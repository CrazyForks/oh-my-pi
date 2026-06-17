/**
 * Tests for secrets regex parsing, compilation, and obfuscation.
 */

import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import type { Context, Message } from "@oh-my-pi/pi-ai";
import {
	getExistingSecretPlaceholderKey,
	getSecretPlaceholderKey,
	loadSecrets,
} from "@oh-my-pi/pi-coding-agent/secrets";
import {
	obfuscateMessages,
	obfuscateProviderContext,
	SecretObfuscator,
	sanitizeSecretFriendlyName,
	stripPendingSecretPlaceholderSuffix,
} from "@oh-my-pi/pi-coding-agent/secrets/obfuscator";
import { compileSecretRegex } from "@oh-my-pi/pi-coding-agent/secrets/regex";
import { getActiveProfile, getConfigRootDir, setProfile } from "@oh-my-pi/pi-utils/dirs";
import { z } from "zod/v4";

describe("compileSecretRegex", () => {
	it("adds global flag when not provided", () => {
		const regex = compileSecretRegex("api[_-]?key\\s*=\\s*\\w+", "i");
		expect(regex.source).toBe("api[_-]?key\\s*=\\s*\\w+");
		expect(regex.flags).toBe("gi");
	});

	it("defaults to global flag when no flags provided", () => {
		const regex = compileSecretRegex("api[_-]?key\\s*=\\s*\\w+");
		expect(regex.source).toBe("api[_-]?key\\s*=\\s*\\w+");
		expect(regex.flags).toBe("g");
	});

	it("rejects invalid regex pattern", () => {
		expect(() => compileSecretRegex("(")).toThrow();
	});
	it("rejects invalid regex flags", () => {
		expect(() => compileSecretRegex("x", "zz")).toThrow();
	});
});

describe("SecretObfuscator regex behavior", () => {
	it("obfuscates and deobfuscates regex matches with flags", () => {
		const obfuscator = new SecretObfuscator([{ type: "regex", content: "api[_-]?key\\s*=\\s*\\w+", flags: "i" }]);
		const original = "API_KEY=abc and api-key=def";
		const obfuscated = obfuscator.obfuscate(original);
		expect(obfuscated).not.toEqual(original);
		expect(obfuscator.deobfuscate(obfuscated)).toEqual(original);
	});

	it("supports bare regex patterns without explicit flags", () => {
		const obfuscator = new SecretObfuscator([{ type: "regex", content: "api[_-]?key\\s*=\\s*\\w+" }]);
		const text = "api_key=abc and API_KEY=def";
		const obfuscated = obfuscator.obfuscate(text);
		expect(obfuscated).not.toEqual(text);
		expect(obfuscator.deobfuscate(obfuscated)).toEqual(text);
	});
	it("deobfuscates placeholders through object payloads", () => {
		const obfuscator = new SecretObfuscator([{ type: "regex", content: "api[_-]?key\\s*=\\s*\\w+", flags: "i" }]);
		const original = {
			cmd: "API_KEY=abc and api-key=def",
			status: "ok",
		};
		const obfuscated = {
			cmd: obfuscator.obfuscate(original.cmd),
			status: original.status,
		};
		expect(obfuscator.deobfuscateObject(obfuscated)).toEqual({
			cmd: original.cmd,
			status: original.status,
		});
	});

	it("obfuscates nested provider request payloads", () => {
		const secret = "SUPER_SECRET_TOKEN_12345";
		const obfuscator = new SecretObfuscator([{ type: "plain", content: secret }]);
		const payload = {
			systemPrompt: [`workspace contains ${secret}`],
			messages: [],
			tools: [
				{
					name: "handoff",
					description: `preserve ${secret}`,
					parameters: {
						type: "object",
						properties: { note: { type: "string", description: `write ${secret}` } },
					},
				},
			],
		};

		const obfuscated = obfuscateProviderContext(obfuscator, payload);
		const serialized = JSON.stringify(obfuscated);

		expect(serialized).not.toContain(secret);
		expect(obfuscator.deobfuscateObject(obfuscated).tools?.[0]?.description).toEqual(payload.tools[0]?.description);
	});

	it("redacts Zod tool schemas without cloning the live schema instance", () => {
		const secret = "SUPER_SECRET_TOKEN_12345";
		const obfuscator = new SecretObfuscator([{ type: "plain", content: secret }]);
		const parameters = z.object({
			note: z.string().describe(`write ${secret}`),
		});
		const context: Context = {
			messages: [],
			tools: [
				{
					name: "extension_tool",
					description: `preserve ${secret}`,
					parameters,
				},
			],
		};

		const obfuscated = obfuscateProviderContext(obfuscator, context);

		expect(obfuscator.obfuscateObject(parameters)).toBe(parameters);
		expect(context.tools?.[0]?.parameters).toBe(parameters);
		expect(obfuscated.tools?.[0]?.parameters).not.toBe(parameters);
		expect(JSON.stringify(obfuscated)).not.toContain(secret);
	});

	it("obfuscates system reminders and assistant tool calls in messages", () => {
		const secret = "SUPER_SECRET_TOKEN_12345";
		const obfuscator = new SecretObfuscator([{ type: "plain", content: secret }]);
		const messages: Message[] = [
			{ role: "developer", content: `system reminder ${secret}`, timestamp: 1 },
			{
				role: "assistant",
				content: [
					{
						type: "toolCall",
						id: "call_1",
						name: "handoff",
						arguments: { note: secret },
						intent: `handoff ${secret}`,
					},
				],
				api: "test",
				provider: "test",
				model: "test",
				usage: {
					input: 0,
					output: 0,
					cacheRead: 0,
					cacheWrite: 0,
					totalTokens: 0,
					cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
				},
				stopReason: "toolUse",
				timestamp: 1,
			},
		];

		const obfuscated = obfuscateMessages(obfuscator, messages);

		expect(JSON.stringify(obfuscated)).not.toContain(secret);
		expect(obfuscator.deobfuscateObject(obfuscated)).toEqual(messages);
	});
});

describe("getSecretPlaceholderKey", () => {
	async function withTempConfigRoot(run: () => Promise<void>): Promise<void> {
		const originalProfile = getActiveProfile();
		const originalConfigDir = process.env.PI_CONFIG_DIR;
		const originalAgentDir = process.env.PI_CODING_AGENT_DIR;
		const configDirName = `.omp-secret-key-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}`;
		const configRoot = path.join(os.homedir(), configDirName);
		try {
			process.env.PI_CONFIG_DIR = configDirName;
			setProfile(undefined);
			await run();
		} finally {
			setProfile(undefined);
			if (originalConfigDir === undefined) {
				delete process.env.PI_CONFIG_DIR;
			} else {
				process.env.PI_CONFIG_DIR = originalConfigDir;
			}
			if (originalAgentDir === undefined) {
				delete process.env.PI_CODING_AGENT_DIR;
			} else {
				process.env.PI_CODING_AGENT_DIR = originalAgentDir;
			}
			setProfile(originalProfile);
			await fs.rm(configRoot, { recursive: true, force: true });
		}
	}

	it("caches placeholder keys per profile config root", async () => {
		await withTempConfigRoot(async () => {
			const alphaKey = "A".repeat(43);
			const betaKey = "B".repeat(43);
			setProfile("alpha");
			await fs.mkdir(getConfigRootDir(), { recursive: true });
			await fs.writeFile(path.join(getConfigRootDir(), "secret-placeholder.key"), alphaKey);
			expect(await getSecretPlaceholderKey()).toBe(alphaKey);

			setProfile("beta");
			await fs.mkdir(getConfigRootDir(), { recursive: true });
			await fs.writeFile(path.join(getConfigRootDir(), "secret-placeholder.key"), betaKey);
			expect(await getSecretPlaceholderKey()).toBe(betaKey);
		});
	});

	it("rejects truncated placeholder key files", async () => {
		await withTempConfigRoot(async () => {
			setProfile("truncated");
			await fs.mkdir(getConfigRootDir(), { recursive: true });
			await fs.writeFile(path.join(getConfigRootDir(), "secret-placeholder.key"), "abc123");

			await expect(getSecretPlaceholderKey()).rejects.toThrow("secret placeholder key");
		});
	});

	it("retries empty existing placeholder key files without creating a new one", async () => {
		await withTempConfigRoot(async () => {
			setProfile("race");
			await fs.mkdir(getConfigRootDir(), { recursive: true });
			const keyPath = path.join(getConfigRootDir(), "secret-placeholder.key");
			await fs.writeFile(keyPath, "");
			const eventualKey = "C".repeat(43);
			const writer = Bun.sleep(25).then(() => fs.writeFile(keyPath, eventualKey));

			await expect(getExistingSecretPlaceholderKey()).resolves.toBe(eventualKey);
			await writer;
		});
	});
});

describe("SecretObfuscator friendlyName placeholders", () => {
	it("prefixes plain secret placeholders with sanitized friendly names", () => {
		const secret = "github_pat_abc123";
		const obfuscator = new SecretObfuscator([{ type: "plain", content: secret, friendlyName: "GitHub Token!" }]);
		const input = `use ${secret} now`;
		const obfuscated = obfuscator.obfuscate(input);

		expect(obfuscated).toMatch(/#GITHUBTOKEN_[A-Z0-9]+:L#/);
		expect(obfuscated).not.toContain(secret);
		expect(obfuscator.deobfuscate(obfuscated)).toBe(input);
	});

	it("uses regex entry friendly names for discovered matches", () => {
		const secret = "tok_abc123";
		const obfuscator = new SecretObfuscator([{ type: "regex", content: "tok_[a-z0-9]+", friendlyName: "API Key" }]);
		const input = `use ${secret} please`;
		const obfuscated = obfuscator.obfuscate(input);

		expect(obfuscated).toMatch(/#APIKEY_[A-Z0-9]+:L#/);
		expect(obfuscated).not.toContain(secret);
		expect(obfuscator.deobfuscate(obfuscated)).toBe(input);
	});

	it("does not replace plain secrets inside generated friendly placeholders", () => {
		const longSecret = "long-secret-token";
		const prefixSecret = "TOKEN";
		const obfuscator = new SecretObfuscator([
			{ type: "plain", content: longSecret, friendlyName: "token" },
			{ type: "plain", content: prefixSecret },
		]);
		const input = `${longSecret} ${prefixSecret}`;
		const obfuscated = obfuscator.obfuscate(input);

		expect(obfuscated).toMatch(/^#TOKEN_[A-Z0-9]+:L# #[A-Z0-9]+:U#$/);
		expect(obfuscated).not.toContain(longSecret);
		expect(obfuscator.deobfuscate(obfuscated)).toBe(input);
	});

	it("redacts configured secrets that already look like placeholders", () => {
		const secret = "#PASSWORD123#";
		const obfuscator = new SecretObfuscator([{ type: "plain", content: secret }]);
		const obfuscated = obfuscator.obfuscate(`value ${secret}`);

		expect(obfuscated).not.toContain(secret);
		expect(obfuscated).toMatch(/^value #[A-Z0-9]+:U#$/);
		expect(obfuscator.deobfuscate(obfuscated)).toBe(`value ${secret}`);
	});

	it("redacts regex matches that span known placeholders", () => {
		const obfuscator = new SecretObfuscator([
			{ type: "plain", content: "abc" },
			{ type: "regex", content: "api_key=\\S+", friendlyName: "api-key" },
		]);

		const obfuscated = obfuscator.obfuscate("api_key=abcXYZ");

		expect(obfuscated).toMatch(/^#APIKEY_[A-Z0-9]+:M#$/);
		expect(obfuscated).not.toContain("XYZ");
		expect(obfuscated).not.toContain("abc");
		expect(obfuscator.deobfuscate(obfuscated)).toBe("api_key=abcXYZ");
	});

	it("ignores regex matches that fall entirely inside known placeholders", () => {
		const obfuscator = new SecretObfuscator([
			{ type: "plain", content: "abc" },
			{ type: "regex", mode: "replace", content: "P+", replacement: "REDACTED" },
		]);

		const obfuscated = obfuscator.obfuscate("abc");

		expect(obfuscated).not.toBe("REDACTED");
		expect(obfuscated).toMatch(/^#[A-Z0-9]+:L#$/);
		expect(obfuscator.deobfuscate(obfuscated)).toBe("abc");
	});

	it("does not recursively rewrite plain secrets that look like placeholders", () => {
		const sharedKey = "D".repeat(43);
		const firstOnly = new SecretObfuscator(
			[{ type: "plain", content: "legacy-secret", friendlyName: "old" }],
			sharedKey,
		);
		const firstPlaceholder = firstOnly.obfuscate("legacy-secret");
		const secondOnly = new SecretObfuscator(
			[{ type: "plain", content: firstPlaceholder, friendlyName: "other" }],
			sharedKey,
		);
		const secondPlaceholder = secondOnly.obfuscate(firstPlaceholder);
		const obfuscator = new SecretObfuscator(
			[
				{ type: "plain", content: "legacy-secret", friendlyName: "old" },
				{ type: "plain", content: firstPlaceholder, friendlyName: "other" },
			],
			sharedKey,
		);

		expect(secondPlaceholder).toMatch(/^#OTHER_[A-Z0-9]+(?::[ULCM])?#$/);
		expect(obfuscator.deobfuscate(secondPlaceholder)).toBe(firstPlaceholder);
	});

	it("keeps no-name placeholders unprefixed but content-derived", () => {
		const first = new SecretObfuscator([
			{ type: "plain", content: "alpha-secret" },
			{ type: "plain", content: "beta-secret" },
		]);
		const second = new SecretObfuscator([
			{ type: "plain", content: "beta-secret" },
			{ type: "plain", content: "alpha-secret" },
		]);

		const firstToken = first.obfuscate("alpha-secret").match(/#[A-Z0-9]+:L#/)?.[0];
		const secondToken = second.obfuscate("alpha-secret").match(/#[A-Z0-9]+:L#/)?.[0];

		expect(firstToken).toBeDefined();
		expect(firstToken).toBe(secondToken);
		expect(firstToken).not.toMatch(/_[A-Z0-9]+/);
		expect(first.deobfuscate(firstToken ?? "")).toBe("alpha-secret");
	});

	it("deobfuscates legacy index-derived placeholders for plain secrets", () => {
		const obfuscator = new SecretObfuscator([{ type: "plain", content: "legacy-secret" }]);

		expect(obfuscator.obfuscate("legacy-secret")).not.toBe("#XRRS#");
		expect(obfuscator.deobfuscate("#XRRS#")).toBe("legacy-secret");
	});

	it("deobfuscates placeholders after friendlyName changes", () => {
		const renamed = new SecretObfuscator([{ type: "plain", content: "renamed-secret", friendlyName: "new name" }]);
		const current = renamed.obfuscate("renamed-secret");
		const oldName = current.replace("#NEWNAME_", "#OLDNAME_");
		const removedName = new SecretObfuscator([{ type: "plain", content: "renamed-secret" }]);

		expect(current).toMatch(/^#NEWNAME_[A-Z0-9]+:L#$/);
		expect(renamed.deobfuscate(oldName)).toBe("renamed-secret");
		expect(removedName.deobfuscate(oldName)).toBe("renamed-secret");
	});

	it("keeps friendly-name-independent aliases unique for same-base same-hint secrets", () => {
		const obfuscator = new SecretObfuscator([
			{ type: "plain", content: "SeCret", friendlyName: "alpha" },
			{ type: "plain", content: "SecRet", friendlyName: "bravo" },
		]);
		const obfuscated = obfuscator.obfuscate("SeCret SecRet");
		const [tokenA, tokenB] = obfuscated.split(" ");
		if (!tokenA || !tokenB) throw new Error("expected two friendly placeholders");

		expect(tokenA).toMatch(/^#ALPHA_[A-Z0-9]+:M#$/);
		expect(tokenB).toMatch(/^#BRAVO_[A-Z0-9]+:M#$/);
		expect(obfuscator.deobfuscate(obfuscated)).toBe("SeCret SecRet");

		const stripPrefix = (token: string) => token.replace(/^#[A-Z0-9]+_/, "#");
		const aliasA = stripPrefix(tokenA);
		const aliasB = stripPrefix(tokenB);
		expect(aliasA).not.toBe(aliasB);
		expect(obfuscator.deobfuscate(aliasA)).toBe("SeCret");
		expect(obfuscator.deobfuscate(aliasB)).toBe("SecRet");
	});

	it("resolves a persisted friendly placeholder to the right same-base secret after a rename", () => {
		const original = new SecretObfuscator([
			{ type: "plain", content: "SeCret", friendlyName: "alpha" },
			{ type: "plain", content: "SecRet", friendlyName: "bravo" },
		]);
		const persistedBravo = original.obfuscate("SeCret SecRet").split(" ")[1];
		if (!persistedBravo) throw new Error("expected a bravo placeholder");

		// bravo renamed to charlie while both same-base secrets still exist.
		const renamed = new SecretObfuscator([
			{ type: "plain", content: "SeCret", friendlyName: "alpha" },
			{ type: "plain", content: "SecRet", friendlyName: "charlie" },
		]);
		expect(renamed.deobfuscate(persistedBravo)).toBe("SecRet");
	});

	it("keeps a mixed-case placeholder stable when a same-normalized secret is added earlier", () => {
		// Session 1: only SecRet is configured; persist its mixed-case token.
		const before = new SecretObfuscator([{ type: "plain", content: "SecRet" }]);
		const persisted = before.obfuscate("SecRet");
		expect(persisted).toMatch(/^#[A-Z0-9]+:M#$/);

		// Session 2: SeCret (same normalized value, also :M) is added EARLIER.
		const after = new SecretObfuscator([
			{ type: "plain", content: "SeCret" },
			{ type: "plain", content: "SecRet" },
		]);

		// SecRet's token must be value-stable, not bumped to a fallback, so the
		// persisted placeholder still round-trips to SecRet rather than SeCret.
		expect(after.obfuscate("SecRet")).toBe(persisted);
		expect(after.deobfuscate(persisted)).toBe("SecRet");
		expect(after.obfuscate("SeCret")).not.toBe(persisted);
	});

	it("derives each placeholder purely from its own secret, independent of load order", () => {
		// A secret persisted alone must keep the same token when unrelated secrets
		// are later added before it, so old session text never aliases to another
		// secret because of config/env ordering.
		const alone = new SecretObfuscator([{ type: "plain", content: "secret397" }]);
		const persisted = alone.obfuscate("secret397");

		const before = new SecretObfuscator([
			{ type: "plain", content: "secret658" },
			{ type: "plain", content: "secret397" },
		]);
		const after = new SecretObfuscator([
			{ type: "plain", content: "secret397" },
			{ type: "plain", content: "secret658" },
		]);

		expect(before.obfuscate("secret397")).toBe(persisted);
		expect(after.obfuscate("secret397")).toBe(persisted);
		expect(before.deobfuscate(persisted)).toBe("secret397");
		expect(before.obfuscate("secret658")).not.toBe(persisted);
	});

	it("keeps Unicode case variants on distinct bases despite a shared ASCII hint", () => {
		// `Äbc` and `äbc` differ only by Unicode case; the ASCII case hint (`:L`)
		// cannot reconstruct Unicode casing, so they must NOT share a base key. A
		// `secret.toLowerCase()` normalization folds `Ä`→`ä` and collapses them,
		// letting a persisted token alias to whichever secret loads first.
		const alone = new SecretObfuscator([{ type: "plain", content: "Äbc" }]);
		const persisted = alone.obfuscate("Äbc");

		// A later session loads `äbc` EARLIER than `Äbc`.
		const reordered = new SecretObfuscator([
			{ type: "plain", content: "äbc" },
			{ type: "plain", content: "Äbc" },
		]);

		expect(reordered.obfuscate("Äbc")).toBe(persisted);
		expect(reordered.obfuscate("äbc")).not.toBe(persisted);
		expect(reordered.deobfuscate(persisted)).toBe("Äbc");
		expect(reordered.deobfuscate(reordered.obfuscate("äbc"))).toBe("äbc");
	});

	it("derives placeholders from a keyed digest, not a public content hash", () => {
		// A provider that sees the placeholder and knows the algorithm must not be
		// able to dictionary low-entropy secrets: the base is keyed by a private
		// per-install secret, so the same secret yields different tokens per key.
		const secret = "hunter2-password";
		const keyA = new SecretObfuscator([{ type: "plain", content: secret }], "install-key-a");
		const keyB = new SecretObfuscator([{ type: "plain", content: secret }], "install-key-b");

		const tokenA = keyA.obfuscate(secret);
		const tokenB = keyB.obfuscate(secret);

		expect(tokenA).not.toBe(secret);
		expect(tokenA).not.toBe(tokenB);

		// Same key + same secret is stable across instances and round-trips.
		const keyAgain = new SecretObfuscator([{ type: "plain", content: secret }], "install-key-a");
		expect(keyAgain.obfuscate(secret)).toBe(tokenA);
		expect(keyA.deobfuscate(tokenA)).toBe(secret);
	});

	it("redacts its own keyed-hash key from obfuscated output", () => {
		// The key can be read from a user-readable config file by a prompt-injected
		// tool; if it reached the provider verbatim, the keyed placeholder bases
		// could be dictionaried, so the obfuscator must never emit its own key.
		const key = "install-key-that-must-never-leak-1234567890";
		const obfuscator = new SecretObfuscator([{ type: "plain", content: "real-secret" }], key);
		const obfuscated = obfuscator.obfuscate(`cat secret-placeholder.key => ${key} (and real-secret)`);

		expect(obfuscated).not.toContain(key);
		expect(obfuscated).not.toContain("real-secret");
	});

	it("withholds pending placeholders while streaming provider text", () => {
		expect(stripPendingSecretPlaceholderSuffix("before #")).toBe("before ");
		expect(stripPendingSecretPlaceholderSuffix("before #AB12:")).toBe("before ");
		expect(stripPendingSecretPlaceholderSuffix("before #TOKEN")).toBe("before ");
		expect(stripPendingSecretPlaceholderSuffix("before #TOKEN_")).toBe("before ");
		expect(stripPendingSecretPlaceholderSuffix("before #TOKEN_AB12:")).toBe("before ");
		expect(stripPendingSecretPlaceholderSuffix("before #TOKEN_AB12:U")).toBe("before ");
		// A lone trailing `#` is buffered even after an alnum/`:` because it can
		// open a new placeholder; emitting it would corrupt the length-sliced draft.
		expect(stripPendingSecretPlaceholderSuffix("before #TOKEN_AB12:U#")).toBe("before #TOKEN_AB12:U");
		expect(stripPendingSecretPlaceholderSuffix("prefix ID#")).toBe("prefix ID");
		expect(stripPendingSecretPlaceholderSuffix("count 42#")).toBe("count 42");
		expect(stripPendingSecretPlaceholderSuffix("before #TOKEN ")).toBe("before #TOKEN ");
	});

	it("shares a base hash across casing variants with distinct hints", () => {
		const obfuscator = new SecretObfuscator([
			{ type: "plain", content: "secret", friendlyName: "token" },
			{ type: "plain", content: "SECRET", friendlyName: "token" },
			{ type: "plain", content: "Secret", friendlyName: "token" },
		]);
		const obfuscated = obfuscator.obfuscate("secret SECRET Secret");
		const tokens = obfuscated.match(/#TOKEN_[A-Z0-9]+:[ULCM]#/g);
		if (!tokens) throw new Error("Expected case-hinted placeholders");
		const bases = tokens.map(token => /^#TOKEN_([A-Z0-9]+):/.exec(token)?.[1]);

		expect(tokens).toHaveLength(3);
		expect(new Set(bases).size).toBe(1);
		expect(tokens[0]?.endsWith(":L#")).toBe(true);
		expect(tokens[1]?.endsWith(":U#")).toBe(true);
		expect(tokens[2]?.endsWith(":C#")).toBe(true);
		expect(obfuscator.deobfuscate(obfuscated)).toBe("secret SECRET Secret");
	});

	it("gives duplicate mixed-case variants distinct placeholders", () => {
		const obfuscator = new SecretObfuscator([
			{ type: "plain", content: "SeCret", friendlyName: "token" },
			{ type: "plain", content: "SecRet", friendlyName: "token" },
		]);
		const repeated = new SecretObfuscator([
			{ type: "plain", content: "SeCret", friendlyName: "token" },
			{ type: "plain", content: "SecRet", friendlyName: "token" },
		]);
		const input = "SeCret SecRet";
		const obfuscated = obfuscator.obfuscate(input);
		const tokens = obfuscated.match(/#TOKEN_[A-Z0-9]+:M#/g);
		if (!tokens) throw new Error("Expected mixed-case placeholders");

		expect(tokens).toHaveLength(2);
		expect(new Set(tokens).size).toBe(2);
		expect(repeated.obfuscate(input)).toBe(obfuscated);
		expect(obfuscator.deobfuscate(obfuscated)).toBe(input);
	});

	it("allows duplicate friendly names because hash suffixes disambiguate them", () => {
		const obfuscator = new SecretObfuscator([
			{ type: "plain", content: "first-token", friendlyName: "api" },
			{ type: "plain", content: "second-token", friendlyName: "api" },
		]);
		const obfuscated = obfuscator.obfuscate("first-token second-token");
		const tokens = obfuscated.match(/#API_[A-Z0-9]+:L#/g);
		if (!tokens) throw new Error("Expected friendly-name placeholders");

		expect(tokens).toHaveLength(2);
		expect(new Set(tokens).size).toBe(2);
		expect(obfuscator.deobfuscate(obfuscated)).toBe("first-token second-token");
	});

	it("sanitizes and caps friendly names", () => {
		expect(sanitizeSecretFriendlyName("git hub-token!!!")).toBe("GITHUBTOKEN");
		expect(sanitizeSecretFriendlyName("0123456789abcdefghijklmnopqrstuvwxyz")).toBe(
			"0123456789ABCDEFGHIJKLMNOPQRSTUV",
		);
		expect(sanitizeSecretFriendlyName("***")).toBeUndefined();
	});

	it("omits invalid friendlyName metadata without dropping the secret", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "omp-secret-friendly-"));
		try {
			const project = path.join(root, "project");
			const agentDir = path.join(root, "agent");
			await fs.mkdir(path.join(project, ".omp"), { recursive: true });
			await fs.mkdir(agentDir, { recursive: true });
			await fs.writeFile(
				path.join(project, ".omp", "secrets.yml"),
				"- type: plain\n  content: invalid-friendly-secret\n  friendlyName: '***'\n",
			);

			const entries = await loadSecrets(project, agentDir);
			const obfuscator = new SecretObfuscator(entries);
			const obfuscated = obfuscator.obfuscate("invalid-friendly-secret");

			expect(entries).toHaveLength(1);
			expect(entries[0]?.friendlyName).toBeUndefined();
			expect(obfuscated).toMatch(/#[A-Z0-9]+:L#/);
			expect(obfuscated).not.toMatch(/_[A-Z0-9]+/);
			expect(obfuscator.deobfuscate(obfuscated)).toBe("invalid-friendly-secret");
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});

	it("omits non-string friendlyName metadata without dropping the secret", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "omp-secret-friendly-"));
		try {
			const project = path.join(root, "project");
			const agentDir = path.join(root, "agent");
			await fs.mkdir(path.join(project, ".omp"), { recursive: true });
			await fs.mkdir(agentDir, { recursive: true });
			await fs.writeFile(
				path.join(project, ".omp", "secrets.yml"),
				"- type: plain\n  content: non-string-friendly-secret\n  friendlyName: 123\n",
			);

			const entries = await loadSecrets(project, agentDir);
			const obfuscator = new SecretObfuscator(entries);
			const obfuscated = obfuscator.obfuscate("non-string-friendly-secret");

			expect(entries).toHaveLength(1);
			expect(entries[0]?.friendlyName).toBeUndefined();
			expect(obfuscated).toMatch(/#[A-Z0-9]+:L#/);
			expect(obfuscated).not.toMatch(/_[A-Z0-9]+/);
			expect(obfuscator.deobfuscate(obfuscated)).toBe("non-string-friendly-secret");
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});
});
