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
	deobfuscateSessionContext,
	obfuscateMessages,
	obfuscateProviderContext,
	SecretObfuscator,
	sanitizeSecretFriendlyName,
	stripPendingSecretPlaceholderSuffix,
} from "@oh-my-pi/pi-coding-agent/secrets/obfuscator";
import { compileSecretRegex } from "@oh-my-pi/pi-coding-agent/secrets/regex";
import { getActiveProfile, getConfigRootDir, setProfile } from "@oh-my-pi/pi-utils/dirs";
import { type } from "arktype";

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

	it("redacts arktype tool schemas without cloning the live schema instance", () => {
		const secret = "SUPER_SECRET_TOKEN_12345";
		const obfuscator = new SecretObfuscator([{ type: "plain", content: secret }]);
		const parameters = type({
			note: "string",
		}).describe(`write ${secret}`);
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

	it("treats an invalid existing placeholder key as absent for redaction", async () => {
		await withTempConfigRoot(async () => {
			setProfile("invalid-existing");
			await fs.mkdir(getConfigRootDir(), { recursive: true });
			await fs.writeFile(path.join(getConfigRootDir(), "secret-placeholder.key"), "abc123");

			// Replace-only/no-secret sessions load the key only to redact it from tool
			// output; a corrupt key must not block startup, so the existing-key probe
			// is best-effort. The obfuscate-mode loader still rejects an invalid key.
			await expect(getExistingSecretPlaceholderKey()).resolves.toBeUndefined();
			await expect(getSecretPlaceholderKey()).rejects.toThrow("secret placeholder key");
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
		expect(obfuscated).not.toContain("abc");
		expect(obfuscator.deobfuscate(obfuscated)).toBe("api_key=abcXYZ");
	});

	it("redacts bounded obfuscate regex spans around generated placeholders", () => {
		const obfuscator = new SecretObfuscator([
			{ type: "plain", content: "abc" },
			{ type: "regex", content: "api_key=[A-Za-z0-9]{6}", friendlyName: "api-key" },
		]);

		const obfuscated = obfuscator.obfuscate("api_key=abcXYZ");

		expect(obfuscated).toMatch(/^#APIKEY_[A-Z0-9]+:M#$/);
		expect(obfuscated).not.toContain("abc");
		expect(obfuscator.deobfuscate(obfuscated)).toBe("api_key=abcXYZ");
	});
	it("obfuscates bounded regex remainders around prior placeholders", () => {
		const obfuscator = new SecretObfuscator([
			{ type: "plain", content: "abc" },
			{ type: "regex", content: "api_key=[A-Za-z0-9]{6}", friendlyName: "api-key" },
		]);
		const token = obfuscator.obfuscate("abc");

		const obfuscated = obfuscator.obfuscate(`api_key=${token}XYZ`);

		expect(obfuscated).not.toContain("api_key=");
		expect(obfuscated).not.toContain("XYZ");
		expect(obfuscated).toContain(token);
		expect(obfuscator.deobfuscate(obfuscated)).toBe("api_key=abcXYZ");
		expect(obfuscator.obfuscate(obfuscated)).toBe(obfuscated);
	});

	it("keeps regex placeholders stable when inner friendly names change", () => {
		const sharedKey = "E".repeat(43);
		const before = new SecretObfuscator(
			[
				{ type: "plain", content: "abc", friendlyName: "old" },
				{ type: "regex", content: "api_key=\\S+", friendlyName: "api-key" },
			],
			sharedKey,
		);
		const persisted = before.obfuscate("api_key=abcXYZ");
		const after = new SecretObfuscator(
			[
				{ type: "plain", content: "abc", friendlyName: "new" },
				{ type: "regex", content: "api_key=\\S+", friendlyName: "api-key" },
			],
			sharedKey,
		);

		expect(after.obfuscate("api_key=abcXYZ")).toBe(persisted);
		expect(after.deobfuscate(persisted)).toBe("api_key=abcXYZ");
	});

	it("does not canonicalize literal placeholder aliases inside regex matches", () => {
		const sharedKey = "F".repeat(43);
		const plain = new SecretObfuscator([{ type: "plain", content: "legacy-secret" }], sharedKey);
		expect(plain.deobfuscateStored("#XRRS#")).toBe("legacy-secret");

		const obfuscator = new SecretObfuscator(
			[
				{ type: "plain", content: "legacy-secret" },
				{ type: "regex", content: "api_key=\\S+", friendlyName: "api-key" },
			],
			sharedKey,
		);

		const obfuscated = obfuscator.obfuscate("api_key=#XRRS#");
		expect(obfuscated).toMatch(/^#APIKEY_[A-Z0-9]+(?::[ULCM])?#$/);
		expect(obfuscator.deobfuscate(obfuscated)).toBe("api_key=#XRRS#");
	});

	it("redacts replace-mode regex spans around generated placeholders", () => {
		const obfuscator = new SecretObfuscator(
			[
				{ type: "plain", content: "SECRET" },
				{ type: "regex", mode: "replace", content: "[A-Z0-9]{8,}", replacement: "REDACTED" },
			],
			"A".repeat(43),
		);

		const obfuscated = obfuscator.obfuscate("SECRETX1");

		expect(obfuscated).toMatch(/^#[A-Z0-9]+:U#REDACTED$/);
		expect(obfuscated).not.toMatch(/X1$/);
		expect(obfuscator.deobfuscate(obfuscated)).toBe("SECRETREDACTED");
	});

	it("redacts bounded replace-mode regex suffixes after generated placeholders", () => {
		const obfuscator = new SecretObfuscator(
			[
				{ type: "plain", content: "SECRET" },
				{ type: "regex", mode: "replace", content: "[A-Z0-9]{8}", replacement: "REDACTED" },
			],
			"B".repeat(43),
		);

		const obfuscated = obfuscator.obfuscate("SECRETX1");

		// The 8-char SECRETX1 redacts to one placeholder + REDACTED; assert the `X1`
		// suffix is gone via end-anchored structure, not substring absence — the
		// random keyed base can itself contain the two chars "X1".
		expect(obfuscated).toMatch(/^#[A-Z0-9]+:U#REDACTED$/);
		expect(obfuscated).not.toMatch(/X1$/);
		expect(obfuscator.deobfuscate(obfuscated)).toBe("SECRETREDACTED");
	});

	it("emits a custom replacement once around a generated placeholder", () => {
		const obfuscator = new SecretObfuscator(
			[
				{ type: "plain", content: "abc" },
				{ type: "regex", mode: "replace", content: "api_key=\\S+", replacement: "REDACTED" },
			],
			"C".repeat(43),
		);

		const obfuscated = obfuscator.obfuscate("api_key=abcXYZ");

		// A custom replacement is a single redaction marker for the whole match, so
		// it must not be duplicated on both sides of the preserved placeholder (the
		// bug produced `REDACTED#…#REDACTED`). Asserted by structure plus an
		// end-anchored guard rather than a base-collidable substring count.
		expect(obfuscated).toMatch(/^REDACTED#[A-Z0-9]+:L#$/);
		expect(obfuscated).not.toMatch(/REDACTED$/);
		expect(obfuscated).not.toContain("api_key=");
		expect(obfuscator.deobfuscate(obfuscated)).toBe("REDACTEDabc");
	});

	it("is idempotent when re-obfuscating already-obfuscated text", () => {
		// The SDK obfuscates messages in both convertToLlm and transformProviderContext,
		// and prior-turn messages re-enter every turn, so obfuscate() must be a fixed
		// point. Re-running it on its own output must not re-redact around an existing
		// placeholder (regression: `#…#REDACTED` -> `#…#REDACTEDDACTED`).
		const replace = new SecretObfuscator(
			[
				{ type: "plain", content: "SECRET" },
				{ type: "regex", mode: "replace", content: "[A-Z0-9]{8}", replacement: "REDACTED" },
			],
			"D".repeat(43),
		);
		const replaceOnce = replace.obfuscate("SECRETX1");
		expect(replaceOnce).toMatch(/^#[A-Z0-9]+:U#REDACTED$/);
		expect(replace.obfuscate(replaceOnce)).toBe(replaceOnce);
		expect(replace.obfuscate(replace.obfuscate(replaceOnce))).toBe(replaceOnce);
		expect(replace.deobfuscate(replaceOnce)).toBe("SECRETREDACTED");

		// Custom replacement spanning a placeholder must also stay a fixed point.
		const custom = new SecretObfuscator(
			[
				{ type: "plain", content: "abc" },
				{ type: "regex", mode: "replace", content: "api_key=\\S+", replacement: "REDACTED" },
			],
			"E".repeat(43),
		);
		const customOnce = custom.obfuscate("api_key=abcXYZ");
		expect(custom.obfuscate(customOnce)).toBe(customOnce);
		expect(custom.deobfuscate(customOnce)).toBe("REDACTEDabc");

		// Obfuscate-mode regex spanning a placeholder is a fixed point too.
		const obf = new SecretObfuscator(
			[
				{ type: "plain", content: "abc" },
				{ type: "regex", content: "api_key=[A-Za-z0-9]{6}", friendlyName: "api-key" },
			],
			"F".repeat(43),
		);
		const obfOnce = obf.obfuscate("api_key=abcXYZ");
		expect(obf.obfuscate(obfOnce)).toBe(obfOnce);
		expect(obf.deobfuscate(obfOnce)).toBe("api_key=abcXYZ");
	});

	it("cross-matches a fresh placeholder whose token already appears in the input", () => {
		const obf = new SecretObfuscator(
			[
				{ type: "plain", content: "abc" },
				{ type: "regex", mode: "replace", content: "api_key=\\S+", replacement: "REDACTED" },
			],
			"G".repeat(43),
		);
		const token = obf.obfuscate("abc");
		expect(token).toMatch(/^#[A-Z0-9]+:L#$/);

		// Input carries the prior token literally AND a fresh api_key=abcXYZ (raw `abc`).
		// The fresh occurrence must still be redacted (XYZ gone) while the prior token is
		// preserved; range-based origin tracking distinguishes the two same-token spans,
		// where a token-value guard would skip both and leak XYZ.
		const out = obf.obfuscate(`${token} api_key=abcXYZ`);
		expect(out).toBe(`${token} REDACTED${token}`);
		expect(obf.deobfuscate(out)).toBe("abc REDACTEDabc");
		expect(obf.obfuscate(out)).toBe(out); // still a fixed point
	});

	it("redacts new surrounding bytes around a prior-call placeholder without re-redacting markers", () => {
		const obf = new SecretObfuscator(
			[
				{ type: "plain", content: "abc" },
				{ type: "regex", mode: "replace", content: "api_key=\\S+", replacement: "REDACTED" },
			],
			"H".repeat(43),
		);
		// Simulate a session where `abc` was obfuscated in an earlier turn (the token
		// is a prior-call/input placeholder) and the regex now re-enters text where
		// `api_key=` + raw `XYZ` still surround that token. The prior placeholder is
		// preserved, but the genuinely-new surrounding bytes (`api_key=`, `XYZ`) must
		// be redacted — not dropped, which would leak `XYZ` to the provider.
		const token = obf.obfuscate("abc");
		const out = obf.obfuscate(`api_key=${token}XYZ`);
		expect(out).toBe(`REDACTED${token}`);
		expect(out).not.toContain("XYZ");
		expect(out).not.toContain("api_key=");
		expect(obf.deobfuscate(out)).toBe("REDACTEDabc");
		// Re-obfuscating the redacted output is a fixed point: the marker `REDACTED`
		// does not independently satisfy `api_key=\S+`, so nothing grows.
		expect(obf.obfuscate(out)).toBe(out);
	});

	it("redacts bounded replace regex remainders around prior placeholders", () => {
		const obf = new SecretObfuscator(
			[
				{ type: "plain", content: "abc" },
				{ type: "regex", mode: "replace", content: "api_key=[A-Za-z0-9]{6}", replacement: "REDACTED" },
			],
			"I".repeat(43),
		);
		const token = obf.obfuscate("abc");

		const out = obf.obfuscate(`api_key=${token}XYZ`);

		expect(out).toBe(`REDACTED${token}`);
		expect(out).not.toContain("XYZ");
		expect(out).not.toContain("api_key=");
		expect(obf.deobfuscate(out)).toBe("REDACTEDabc");
		expect(obf.obfuscate(out)).toBe(out);
	});

	it("redacts custom replacement prefixes that are raw regex remainders", () => {
		const obf = new SecretObfuscator(
			[
				{ type: "plain", content: "SECRET" },
				{ type: "regex", mode: "replace", content: "[A-Z0-9]{7}", replacement: "REDACTED" },
			],
			"K".repeat(43),
		);
		const token = obf.obfuscate("SECRET");

		const out = obf.obfuscate(`${token}R`);

		expect(out).toBe(`${token}REDACTED`);
		expect(obf.deobfuscate(out)).toBe("SECRETREDACTED");
		expect(obf.obfuscate(out)).toBe(out);
	});

	it("redacts trailing bytes after existing custom replacement markers", () => {
		const obf = new SecretObfuscator(
			[
				{ type: "plain", content: "SECRET" },
				{ type: "regex", mode: "replace", content: "[A-Z0-9]{15}", replacement: "REDACTED" },
			],
			"L".repeat(43),
		);
		const token = obf.obfuscate("SECRET");

		const out = obf.obfuscate(`${token}REDACTEDX`);

		expect(out).toBe(`${token}REDACTED`);
		expect(obf.obfuscate(out)).toBe(out);
	});

	it("redacts default replace regex remainders around prior placeholders", () => {
		const obf = new SecretObfuscator(
			[
				{ type: "plain", content: "abc" },
				{ type: "regex", mode: "replace", content: "api_key=[A-Za-z0-9]{6}" },
			],
			"J".repeat(43),
		);
		const token = obf.obfuscate("abc");

		const out = obf.obfuscate(`api_key=${token}XYZ`);

		expect(out).toContain(token);
		expect(out).not.toContain("XYZ");
		expect(out).not.toContain("api_key=");
		expect(obf.obfuscate(out)).toBe(out);
	});

	it("redacts default replace raw suffixes after prior placeholders", () => {
		const obf = new SecretObfuscator(
			[
				{ type: "plain", content: "SECRET" },
				{ type: "regex", mode: "replace", content: "[A-Z0-9]{8}" },
			],
			"N".repeat(43),
		);
		const token = obf.obfuscate("SECRET");

		const out = obf.obfuscate(`${token}X1`);

		expect(out).toContain(token);
		expect(out).not.toContain("X1");
		expect(obf.obfuscate(out)).toBe(out);
	});

	it("keeps default replace regex output idempotent around prior placeholders", () => {
		const obf = new SecretObfuscator(
			[
				{ type: "plain", content: "SECRET" },
				{ type: "regex", mode: "replace", content: "[A-Za-z0-9]{8}" },
			],
			"M".repeat(43),
		);

		const out = obf.obfuscate("SECRETX1");

		expect(obf.obfuscate(out)).toBe(out);
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

	it("ignores obfuscate regex matches that fall entirely inside known placeholders", () => {
		const obfuscator = new SecretObfuscator([
			{ type: "plain", content: "abc" },
			{ type: "regex", content: "P{8}", friendlyName: "inner" },
		]);

		const obfuscated = obfuscator.obfuscate("abc");

		expect(obfuscated).toMatch(/^#[A-Z0-9]+:L#$/);
		expect(obfuscated).not.toMatch(/^#INNER_/);
		expect(obfuscator.deobfuscate(obfuscated)).toBe("abc");
	});

	it("ignores obfuscate regex matches that partially overlap known placeholders", () => {
		const obfuscator = new SecretObfuscator([
			{ type: "plain", content: "secret" },
			{ type: "regex", content: "P{3}X", friendlyName: "partial" },
		]);

		const obfuscated = obfuscator.obfuscate("secretX");

		expect(obfuscated).toMatch(/^#[A-Z0-9]+:L#X$/);
		expect(obfuscated).not.toMatch(/^#PARTIAL_/);
		expect(obfuscator.deobfuscate(obfuscated)).toBe("secretX");
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

	it("honors legacy index-derived aliases only on the stored-replay path", () => {
		const obfuscator = new SecretObfuscator([{ type: "plain", content: "legacy-secret" }]);

		// The generated token is keyed, never the legacy index token.
		expect(obfuscator.obfuscate("legacy-secret")).not.toBe("#XRRS#");

		// Stored session replay/display restores pre-keyed legacy placeholders so
		// older persisted sessions still resume correctly.
		expect(obfuscator.deobfuscateStored("#XRRS#")).toBe("legacy-secret");

		// Live provider output and tool-call arguments MUST NOT honor the legacy
		// alias: it is unkeyed and trivially guessable, so a prompt-injected model
		// could synthesize `#XRRS#` in a bash/read argument and exfiltrate the secret.
		expect(obfuscator.deobfuscate("#XRRS#")).toBe("#XRRS#");
		expect(obfuscator.deobfuscateObject({ cmd: "cat #XRRS#" })).toEqual({ cmd: "cat #XRRS#" });
	});

	it("never restores legacy aliases on agent-feeding replay, only on display transcripts", () => {
		// deobfuscateSessionContext has two kinds of consumers: agent-feeding paths
		// (resume, history rewrite, branch switch) whose output is re-obfuscated and
		// sent to the provider, and a display-only transcript (allowLegacyAliases).
		// Legacy index-derived `#XRRS#` aliases are unkeyed and guessable, so a
		// prompt-injected model can plant one in ANY record it influences — its own
		// assistant output OR a tool result (bash stdout). If a feed path restored
		// it, the next provider turn would re-obfuscate it into a usable keyed
		// placeholder the model could weaponize in a tool argument. So feed paths
		// restore keyed placeholders ONLY; legacy is restored solely for the
		// never-re-sent transcript so pre-keyed sessions still render their secrets.
		const obfuscator = new SecretObfuscator([{ type: "plain", content: "legacy-secret" }]);
		const keyedToken = obfuscator.obfuscate("legacy-secret");
		expect(keyedToken).not.toContain("#XRRS#");

		const assistant: Message = {
			role: "assistant",
			content: [{ type: "text", text: `attacker planted #XRRS# and echoed ${keyedToken}` }],
			api: "anthropic-messages",
			provider: "anthropic",
			model: "test-model",
			usage: {
				input: 1,
				output: 1,
				cacheRead: 0,
				cacheWrite: 0,
				totalTokens: 2,
				cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
			},
			stopReason: "stop",
			timestamp: 1,
		};
		const toolResult: Message = {
			role: "toolResult",
			toolCallId: "call-1",
			toolName: "bash",
			content: [{ type: "text", text: "bash stdout #XRRS#" }],
			isError: false,
			timestamp: 2,
		};
		const ctx = {
			messages: [assistant, toolResult],
			models: {},
			injectedTtsrRules: [],
			selectedMCPToolNames: [],
			hasPersistedMCPToolSelection: false,
			mode: "none",
		};

		// Agent-feeding default: the keyed token resolves, but no legacy `#XRRS#` is
		// restored — neither in assistant output nor in tool results — so nothing can
		// be laundered into a keyed placeholder on the next turn.
		const fed = deobfuscateSessionContext(ctx, obfuscator);
		const fedAssistant = (fed.messages[0] as Extract<Message, { role: "assistant" }>).content[0] as { text: string };
		const fedTool = (fed.messages[1] as Extract<Message, { role: "toolResult" }>).content[0] as { text: string };
		expect(fedAssistant.text).toBe("attacker planted #XRRS# and echoed legacy-secret");
		expect(fedTool.text).toBe("bash stdout #XRRS#");

		// Display-only transcript: legacy aliases ARE restored so a genuinely
		// pre-keyed session renders its secrets. This output is never re-obfuscated.
		const shown = deobfuscateSessionContext(ctx, obfuscator, true);
		const shownAssistant = (shown.messages[0] as Extract<Message, { role: "assistant" }>).content[0] as {
			text: string;
		};
		const shownTool = (shown.messages[1] as Extract<Message, { role: "toolResult" }>).content[0] as { text: string };
		expect(shownAssistant.text).toBe("attacker planted legacy-secret and echoed legacy-secret");
		expect(shownTool.text).toBe("bash stdout legacy-secret");
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

	it("uses independent bases across casing variants with distinct hints", () => {
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
		// Distinct ASCII-case variants must NOT share a base: a shared case-folded
		// base would let a provider synthesize a sibling token by swapping the hint.
		expect(new Set(bases).size).toBe(3);
		expect(tokens[0]?.endsWith(":L#")).toBe(true);
		expect(tokens[1]?.endsWith(":U#")).toBe(true);
		expect(tokens[2]?.endsWith(":C#")).toBe(true);
		expect(obfuscator.deobfuscate(obfuscated)).toBe("secret SECRET Secret");
	});

	it("does not restore a case-variant sibling synthesized by swapping the hint", () => {
		// P1: two obfuscate-mode secrets differing only by ASCII case. Only the
		// lowercase one is ever provider-visible; a prompt-injected model must not
		// recover the uppercase secret (never emitted) by taking the visible
		// token's base and swapping the case hint in a tool-call argument.
		const key = "case-variant-install-key-0000000000000000000";
		const obfuscator = new SecretObfuscator(
			[
				{ type: "plain", content: "abc12345" },
				{ type: "plain", content: "ABC12345" },
			],
			key,
		);

		// Provider sees only the lowercase placeholder.
		const visible = obfuscator.obfuscate("abc12345");
		expect(visible).toMatch(/^#[A-Z0-9]+:L#$/);
		const base = /^#([A-Z0-9]+):L#$/.exec(visible)?.[1];
		if (!base) throw new Error("expected a lowercase placeholder base");

		// The uppercase secret's real token uses an independent base.
		const upperReal = obfuscator.obfuscate("ABC12345");
		expect(upperReal).toMatch(/^#[A-Z0-9]+:U#$/);
		expect(upperReal).not.toBe(`#${base}:U#`);

		// Live deobfuscation of the synthesized sibling token leaves it literal
		// instead of restoring the never-provider-visible uppercase secret.
		const synthesized = `#${base}:U#`;
		expect(obfuscator.deobfuscate(synthesized)).toBe(synthesized);
		expect(obfuscator.deobfuscateObject({ cmd: synthesized })).toEqual({ cmd: synthesized });
		// The legitimate visible token still round-trips.
		expect(obfuscator.deobfuscate(visible)).toBe("abc12345");
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

describe("SecretObfuscator cross-turn cache stability", () => {
	// The provider prompt cache is content-addressed: convertToLlm / transformProviderContext
	// re-run obfuscation over the WHOLE message array every turn, so a non-deterministic
	// placeholder for the same secret would rewrite already-sent prefix bytes and bust the
	// cache (cacheWrite @ $6.25/M vs cacheRead @ $0.50/M on opus). These tests pin the
	// determinism that makes obfuscation cache-safe so a future change cannot silently
	// reintroduce per-turn cache invalidation.
	it("produces byte-identical output when re-obfuscating the same content across turns", () => {
		const secret = "SUPER_SECRET_TOKEN_12345";
		const obfuscator = new SecretObfuscator([
			{ type: "plain", content: secret },
			{ type: "regex", content: "tok_[a-z0-9]+" },
		]);
		const messages: Message[] = [{ role: "user", content: `use ${secret} and tok_abc123`, timestamp: 1 }];

		const turn1 = JSON.stringify(obfuscateMessages(obfuscator, messages));
		const turn2 = JSON.stringify(obfuscateMessages(obfuscator, messages));

		expect(turn1).not.toContain(secret);
		expect(turn1).not.toContain("tok_abc123");
		// Identical bytes on the second pass → the cached prefix stays valid.
		expect(turn2).toEqual(turn1);
	});

	it("keeps earlier message placeholders stable when a later message reveals a new regex secret", () => {
		const obfuscator = new SecretObfuscator([{ type: "regex", content: "tok_[a-z0-9]+" }]);
		const early: Message[] = [{ role: "user", content: "first uses tok_aaa", timestamp: 1 }];

		// Turn N: only the early message exists; tok_aaa mints a fresh placeholder.
		const earlyTurnN = JSON.stringify(obfuscateMessages(obfuscator, early));
		expect(earlyTurnN).not.toContain("tok_aaa");

		// A later turn reveals a brand-new secret. Lazy regex discovery assigns it a fresh
		// index — this MUST NOT shift the placeholder already minted for tok_aaa.
		const later: Message[] = [{ role: "user", content: "later uses tok_bbb", timestamp: 2 }];
		const laterOut = JSON.stringify(obfuscateMessages(obfuscator, later));
		expect(laterOut).not.toContain("tok_bbb");

		// Re-obfuscate the early message after the new discovery: identical bytes → the
		// already-cached prefix for the early message stays valid.
		const earlyTurnNPlus1 = JSON.stringify(obfuscateMessages(obfuscator, early));
		expect(earlyTurnNPlus1).toEqual(earlyTurnN);
	});
});
