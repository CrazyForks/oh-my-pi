/**
 * Tests for secrets regex parsing, compilation, and obfuscation.
 */

import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import type { AgentMessage } from "@oh-my-pi/pi-agent-core";
import type { AssistantMessage, Context, Message } from "@oh-my-pi/pi-ai";
import {
	getExistingSecretPlaceholderKey,
	getSecretPlaceholderKey,
	loadSecrets,
} from "@oh-my-pi/pi-coding-agent/secrets";
import {
	deobfuscateAgentMessages,
	deobfuscateSessionContext,
	deobfuscateToolArguments,
	obfuscateMessages,
	obfuscateProviderContext,
	type SecretEntry,
	SecretObfuscator,
	sanitizeSecretFriendlyName,
	secretEntriesNeedPlaceholderKey,
	secretEntryNeedsPlaceholderKey,
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
	it("deobfuscates placeholders through tool-call arguments", () => {
		const obfuscator = new SecretObfuscator([{ type: "regex", content: "api[_-]?key\\s*=\\s*\\w+", flags: "i" }]);
		const original = { cmd: "API_KEY=abc and api-key=def", status: "ok", nested: { note: "API_KEY=zzz" } };
		const obfuscated = {
			cmd: obfuscator.obfuscate(original.cmd),
			status: original.status,
			nested: { note: obfuscator.obfuscate(original.nested.note) },
		};
		expect(JSON.stringify(obfuscated)).not.toContain("API_KEY=abc");
		expect(deobfuscateToolArguments(obfuscator, obfuscated)).toEqual(original);
	});

	it("obfuscates conversation messages but leaves the system prompt untouched", () => {
		const secret = "SUPER_SECRET_TOKEN_12345";
		const obfuscator = new SecretObfuscator([{ type: "plain", content: secret }]);
		const context: Context = {
			systemPrompt: [`workspace contains ${secret}`],
			messages: [{ role: "user", content: `use ${secret}`, timestamp: 1 }],
		};

		const obfuscated = obfuscateProviderContext(obfuscator, context);

		// Conversation messages are redacted (and round-trip back to the secret)...
		expect(JSON.stringify(obfuscated.messages)).not.toContain(secret);
		expect(obfuscator.deobfuscate(JSON.stringify(obfuscated.messages))).toContain(secret);
		// ...but the author-controlled system prompt passes through by reference.
		expect(obfuscated.systemPrompt).toBe(context.systemPrompt);
	});

	it("leaves tool schemas untouched in provider context (no clone, no redaction)", () => {
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

		expect(obfuscated.tools).toBe(context.tools);
		expect(obfuscated.tools?.[0]?.parameters).toBe(parameters);
	});

	it("redacts only user, tool-result, and user-attributed developer messages", () => {
		const secret = "SUPER_SECRET_TOKEN_12345";
		const obfuscator = new SecretObfuscator([{ type: "plain", content: secret }]);
		const userMsg: Message = { role: "user", content: `user says ${secret}`, timestamp: 1 };
		const systemDeveloperMsg: Message = { role: "developer", content: `system reminder ${secret}`, timestamp: 1 };
		const fileMentionMsg: Message = {
			role: "developer",
			content: `<file>${secret}</file>`,
			attribution: "user",
			timestamp: 1,
		};
		const assistantMsg: Message = {
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
		};
		const toolResultMsg: Message = {
			role: "toolResult",
			toolCallId: "call_1",
			toolName: "read",
			content: [{ type: "text", text: `tool output ${secret}` }],
			isError: false,
			timestamp: 1,
		};

		const obfuscated = obfuscateMessages(obfuscator, [
			userMsg,
			systemDeveloperMsg,
			fileMentionMsg,
			assistantMsg,
			toolResultMsg,
		]);

		// User, user-attributed developer, and tool results are redacted.
		expect(JSON.stringify(obfuscated[0])).not.toContain(secret);
		expect(JSON.stringify(obfuscated[2])).not.toContain(secret);
		expect(JSON.stringify(obfuscated[4])).not.toContain(secret);
		// System developer reminders and assistant output pass through untouched (same reference).
		expect(obfuscated[1]).toBe(systemDeveloperMsg);
		expect(obfuscated[3]).toBe(assistantMsg);
	});

	it("never rewrites inline image bytes", () => {
		const secret = "SUPER_SECRET_TOKEN_12345";
		const obfuscator = new SecretObfuscator([{ type: "plain", content: secret }]);
		// A base64 payload that literally contains the secret substring must survive byte-identical;
		// rewriting it would corrupt the data URL (the Codex "invalid base64" failure).
		const imageData = `iVBORw0KGgo${secret}AAAASUVORK5CYII=`;
		const message: Message = {
			role: "toolResult",
			toolCallId: "call_1",
			toolName: "read",
			content: [
				{ type: "text", text: `read ${secret}` },
				{ type: "image", data: imageData, mimeType: "image/png" },
			],
			isError: false,
			timestamp: 1,
		};

		const [obfuscated] = obfuscateMessages(obfuscator, [message]) as [typeof message];
		const blocks = obfuscated.content;
		const image = blocks[1];
		const text = blocks[0];
		// Image bytes untouched...
		expect(image.type === "image" && image.data).toBe(imageData);
		// ...while the adjacent text is redacted.
		expect(text.type === "text" && text.text.includes(secret)).toBe(false);
	});

	it("ignores configured plain secrets shorter than 8 characters", () => {
		const obfuscator = new SecretObfuscator([{ type: "plain", content: "esp" }]);
		expect(obfuscator.hasSecrets()).toBe(false);
		expect(obfuscator.obfuscate("the response despite whitespace")).toBe("the response despite whitespace");
	});

	it("ignores regex matches shorter than 8 characters", () => {
		const obfuscator = new SecretObfuscator([{ type: "regex", content: "esp" }]);
		expect(obfuscator.obfuscate("the response despite whitespace")).toBe("the response despite whitespace");
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
		const prefixSecret = "TOKENABC";
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
			{ type: "plain", content: "abcdefgh" },
			{ type: "regex", content: "api_key=\\S+", friendlyName: "api-key" },
		]);

		const obfuscated = obfuscator.obfuscate("api_key=abcdefghXYZ");

		expect(obfuscated).toMatch(/^#APIKEY_[A-Z0-9]+:M#$/);
		expect(obfuscated).not.toContain("abcdefgh");
		expect(obfuscator.deobfuscate(obfuscated)).toBe("api_key=abcdefghXYZ");
	});

	it("redacts bounded obfuscate regex spans around generated placeholders", () => {
		const obfuscator = new SecretObfuscator([
			{ type: "plain", content: "abcdefgh" },
			{ type: "regex", content: "api_key=[A-Za-z0-9]{11}", friendlyName: "api-key" },
		]);

		const obfuscated = obfuscator.obfuscate("api_key=abcdefghXYZ");

		expect(obfuscated).toMatch(/^#APIKEY_[A-Z0-9]+:M#$/);
		expect(obfuscated).not.toContain("abcdefgh");
		expect(obfuscator.deobfuscate(obfuscated)).toBe("api_key=abcdefghXYZ");
	});
	it("obfuscates bounded regex remainders around prior placeholders", () => {
		const obfuscator = new SecretObfuscator([
			{ type: "plain", content: "abcdefgh" },
			{ type: "regex", content: "api_key=[A-Za-z0-9]{11}", friendlyName: "api-key" },
		]);
		const token = obfuscator.obfuscate("abcdefgh");

		const obfuscated = obfuscator.obfuscate(`api_key=${token}XYZ`);

		expect(obfuscated).not.toContain("api_key=");
		expect(obfuscated).not.toContain("XYZ");
		expect(obfuscated).toContain(token);
		expect(obfuscator.deobfuscate(obfuscated)).toBe("api_key=abcdefghXYZ");
		expect(obfuscator.obfuscate(obfuscated)).toBe(obfuscated);
	});

	it("skips sub-threshold obfuscate regex matches that straddle a generated placeholder", () => {
		// `[A-Z]{6}` only ever matches 6 chars — below MIN_OBFUSCATE_SECRET_LEN — but
		// when a match overlaps the plain secret's placeholder its range is extended
		// across the whole `#…#` token. Guarding on that rewritten span (instead of
		// the regex's own match length) let the short match re-placeholder across the
		// token and corrupt round-trip deobfuscation (e.g. "XXSECRETUVYY" dropping to
		// "XXSECRETUV"). The plain secret must stay hidden, the surrounding literals
		// must survive, and the round trip must be exact.
		const obfuscator = new SecretObfuscator([
			{ type: "plain", content: "SECRETUV" },
			{ type: "regex", content: "[A-Z]{6}" },
		]);

		const obfuscated = obfuscator.obfuscate("XXSECRETUVYY");

		expect(obfuscated).not.toContain("SECRETUV");
		expect(obfuscated.startsWith("XX")).toBe(true);
		expect(obfuscated.endsWith("YY")).toBe(true);
		expect(obfuscator.deobfuscate(obfuscated)).toBe("XXSECRETUVYY");
		// Re-obfuscation MUST be a fixed point: a sub-threshold match straddling the
		// now-input placeholder must not rewrite the surrounding context into fresh
		// placeholders, or provider-visible history and prompt-cache prefixes drift.
		expect(obfuscator.obfuscate(obfuscated)).toBe(obfuscated);
	});

	it("leaves placeholders intact when a regex match cuts across their expanded value", () => {
		// `[A-Z]{8}` meets MIN_OBFUSCATE_SECRET_LEN, but on "YYBBABCDEFGHSECRETUV"
		// (plain secret `ABCDEFGH`) its greedy 8-char matches start/end inside the
		// secret's placeholder expansion ("YYBBABCD", "EFGHSECR"). Snapping each to
		// the whole `#…#` token mapped them to overlapping ranges that clobbered on
		// apply and dropped the `SECR` bytes (round-trip restored "YYBBABCDEFGHETUV").
		// The scan now resumes past the cut placeholder instead, so the secret stays
		// hidden, no bytes are lost, the trailing 8-char run is obfuscated on its own,
		// and re-obfuscation is a fixed point.
		const obfuscator = new SecretObfuscator([
			{ type: "plain", content: "ABCDEFGH" },
			{ type: "regex", content: "[A-Z]{8}" },
		]);

		const obfuscated = obfuscator.obfuscate("YYBBABCDEFGHSECRETUV");

		expect(obfuscated).not.toContain("ABCDEFGH");
		expect(obfuscated).not.toContain("SECRETUV");
		expect(obfuscator.deobfuscate(obfuscated)).toBe("YYBBABCDEFGHSECRETUV");
		expect(obfuscator.obfuscate(obfuscated)).toBe(obfuscated);
	});

	it("keeps replace regexes from rewriting placeholders their match cuts across", () => {
		// Same partial-placeholder cut as above but in replace mode: `[A-Z]{8}`
		// matches straddle the `ABCDEFGH` placeholder. Redacting only the bytes
		// outside the snapped token was not a fixed point — the deterministic scramble
		// of the prefix drifted across re-obfuscation passes ("ZZgK…" → "ZZgZ…"). The
		// scan now resumes past the cut placeholder, so the cut secret stays hidden as
		// its placeholder, the trailing 8-char run is redacted on its own, and
		// re-obfuscation is stable.
		const obfuscator = new SecretObfuscator([
			{ type: "plain", content: "ABCDEFGH" },
			{ type: "regex", content: "[A-Z]{8}", mode: "replace" },
		]);

		const obfuscated = obfuscator.obfuscate("YYBBABCDEFGHSECRETUV");

		expect(obfuscated).not.toContain("ABCDEFGH");
		expect(obfuscated).not.toContain("SECRETUV");
		expect(obfuscator.obfuscate(obfuscated)).toBe(obfuscated);
	});

	it("replace-mode re-obfuscation is a fixed point when a spillover match straddles a prior-call placeholder whose value satisfies the regex", () => {
		// `[A-Z0-9]{8,12}` in replace mode greedily spans `SECRETUV` into the
		// `ABCDEFGH` placeholder on re-obfuscation — `ABCDEFGH` alone satisfies the
		// regex. Previously the short non-matching spillover bytes abutting the
		// placeholder were fed into the deterministic scramble on every pass
		// (e.g. `…#…#ZZJ5sotJ` → `…#…#ZZpvsotJ`), invalidating provider prompt-cache
		// prefixes despite no new input. The fix: when a replace match straddles a
		// placeholder whose own deobfuscated value satisfies the regex, the surrounding
		// spillover bytes are left verbatim instead of being re-scrambled.
		const obf = new SecretObfuscator(
			[
				{ type: "plain", content: "ABCDEFGH" },
				{ type: "regex", content: "[A-Z0-9]{8,12}", mode: "replace" },
			],
			"Q".repeat(43),
		);
		const first = obf.obfuscate("YYBBABCDEFGHSECRETUV");

		// Core regression: re-obfuscation must be a fixed point.
		expect(obf.obfuscate(first)).toBe(first);
		// Stable across multiple passes.
		expect(obf.obfuscate(obf.obfuscate(first))).toBe(first);
		// Plain secret must not leak into provider-visible output.
		expect(first).not.toContain("ABCDEFGH");
	});

	it("redacts an independently matching prefix before a cut placeholder", () => {
		// A regex match that starts in outside text and ends inside a generated
		// placeholder's expanded value is not rewritten across the token (that drops
		// bytes / drifts the redaction). But when the wholly-outside prefix before the
		// placeholder is itself a complete match it is provider-visible secret-shaped
		// content, not a drift artifact. Regression: `[A-Z0-9]{8,12}` greedily
		// spanning `SECRETUV` into an `ABCDEFGH` placeholder returned `SECRETUV#…#`,
		// leaving `SECRETUV` visible even though it independently satisfies the regex.
		// Obfuscate mode: the prefix gets its own reversible placeholder and the whole
		// input still round-trips.
		const obf = new SecretObfuscator(
			[
				{ type: "plain", content: "ABCDEFGH" },
				{ type: "regex", content: "[A-Z0-9]{8,12}" },
			],
			"Q".repeat(43),
		);
		const out = obf.obfuscate("SECRETUVABCDEFGH");
		expect(out).not.toContain("SECRETUV");
		expect(out).not.toContain("ABCDEFGH");
		expect(obf.deobfuscate(out)).toBe("SECRETUVABCDEFGH");
		expect(obf.obfuscate(out)).toBe(out);

		// Replace mode: the prefix is redacted one-way while the cut secret's
		// placeholder is preserved and still restores.
		const repl = new SecretObfuscator(
			[
				{ type: "plain", content: "ABCDEFGH" },
				{ type: "regex", content: "[A-Z0-9]{8,12}", mode: "replace" },
			],
			"Q".repeat(43),
		);
		const rout = repl.obfuscate("SECRETUVABCDEFGH");
		expect(rout).not.toContain("SECRETUV");
		expect(rout).not.toContain("ABCDEFGH");
		expect(repl.deobfuscate(rout)).toMatch(/ABCDEFGH$/);
		expect(repl.deobfuscate(rout)).not.toContain("SECRETUV");
		expect(repl.obfuscate(rout)).toBe(rout);
	});

	it("re-obfuscation is a fixed point when a greedy regex would spill into a trailing raw chunk around a prior-call placeholder", () => {
		// `[A-Z0-9]{8,12}` greedily matches `SECRETUVA` (9 chars) when the SECRETUV
		// placeholder is followed by the raw literal `A`. Previously the spillover
		// caused that short surrounding chunk to be minted into a fresh placeholder on
		// every subsequent obfuscate() call, drifting provider-visible history and the
		// prompt-cache prefix. The fix: a surrounding raw chunk is only obfuscated when
		// the placeholder's own deobfuscated value does NOT independently satisfy the
		// regex; when it does (greedy spillover), the surrounding bytes stay verbatim.
		const obf = new SecretObfuscator(
			[
				{ type: "plain", content: "ABCDEFGH" },
				{ type: "plain", content: "SECRETUV" },
				{ type: "regex", content: "[A-Z0-9]{8,12}" },
			],
			"Q".repeat(43),
		);
		const first = obf.obfuscate("ZZZZZZZZABCDEFGHSECRETUVA");

		// Core regression: re-obfuscation must be a fixed point.
		expect(obf.obfuscate(first)).toBe(first);
		// Round-trip must restore every byte of the original input.
		expect(obf.deobfuscate(first)).toBe("ZZZZZZZZABCDEFGHSECRETUVA");
		// The trailing `A` must survive the first pass verbatim: SECRETUV alone
		// satisfies [A-Z0-9]{8,12}, so the short tail must not be placeholdered.
		expect(first.endsWith("A")).toBe(true);
		// Plain secrets must not appear in provider-visible output.
		expect(first).not.toContain("SECRETUV");
		expect(first).not.toContain("ABCDEFGH");
	});

	it("redacts a two-sided independently matching chunk instead of leaking it as spillover", () => {
		// `\b[A-Z]{8}\b|[A-Z]{17}` union regex, prior-call placeholder for `SECRETUV`
		// flanked by prefix `ABCDEFGH` (independently matches `\b[A-Z]{8}\b`) and
		// suffix `I` (matches nothing alone). The straddling match is the 17-char
		// run `ABCDEFGH` + `SECRETUV` + `I`, which previously tested the concatenated
		// outside chunks `"ABCDEFGH" + "I"` = `"ABCDEFGHI"` against the regex — that
		// concatenation erases the placeholder-token boundary between the chunks, so
		// neither alternative matches (9 chars, and `H` is no longer at a word
		// boundary), and the whole match was left verbatim, leaking `ABCDEFGH`
		// unredacted. The fix tests each outside chunk in its own real, flanked
		// context: `ABCDEFGH` alone still independently matches `\b[A-Z]{8}\b`, so it
		// is redacted instead of leaked.
		const obf = new SecretObfuscator(
			[
				{ type: "plain", content: "SECRETUV" },
				{ type: "regex", content: "\\b[A-Z]{8}\\b|[A-Z]{17}" },
			],
			"Q".repeat(43),
		);
		const placeholdered = obf.obfuscate("SECRETUV");
		const second = obf.obfuscate(`ABCDEFGH${placeholdered}I`);

		// Core regression: the independently matching prefix must not survive
		// verbatim in provider-visible output.
		expect(second).not.toContain("ABCDEFGH");
		expect(second).not.toContain("SECRETUV");
		// Every byte must still round-trip.
		expect(obf.deobfuscate(second)).toBe("ABCDEFGHSECRETUVI");
		// Redacting the prefix must itself be a fixed point.
		expect(obf.obfuscate(second)).toBe(second);
	});

	it("leaves a genuine one-sided spillover chunk verbatim under the same union regex", () => {
		// Contrast case for the fix above: the trailing chunk `IJKLMNOPQ` (9 chars)
		// does NOT independently match `\b[A-Z]{8}\b|[A-Z]{17}` on its own, and only
		// forms a match by bridging across the `SECRETUV` placeholder (`SECRETUV` +
		// `IJKLMNOPQ` = 17 chars). This is genuine greedy spillover, not independent
		// secret-shaped content, so per-chunk testing must still leave it verbatim
		// and a fixed point — the fix must not turn spillover into a false positive.
		const obf = new SecretObfuscator(
			[
				{ type: "plain", content: "SECRETUV" },
				{ type: "regex", content: "\\b[A-Z]{8}\\b|[A-Z]{17}" },
			],
			"Q".repeat(43),
		);
		const placeholdered = obf.obfuscate("SECRETUV");
		const second = obf.obfuscate(`${placeholdered}IJKLMNOPQ`);

		expect(second.endsWith("IJKLMNOPQ")).toBe(true);
		expect(obf.deobfuscate(second)).toBe("SECRETUVIJKLMNOPQ");
		expect(obf.obfuscate(second)).toBe(second);
	});

	it("redacts a lookbehind-anchored prefix tested in its real source context instead of leaking it", () => {
		// `(?<=api=)[0-9]{8}[A-Z]{8}|(?<=api=)[0-9]{8}|[A-Z]{8}` combined with a
		// prior-call placeholder for `ABCDEFGH` (independently matches the bare
		// `[A-Z]{8}` alternative). Re-obfuscating `api=12345678` + placeholder makes
		// the full match (placeholder expanded) `12345678ABCDEFGH`, preceded by the
		// literal `api=`. The outside chunk is `12345678`. Testing that chunk as an
		// ISOLATED slice (starting a fresh string at index 0) loses the real `api=`
		// bytes immediately before it in the source, so `(?<=api=)[0-9]{8}` never
		// fires, none of the three alternatives match a bare "12345678", and the
		// digits were wrongly left verbatim — a lookbehind-blind leak. The fix tests
		// the chunk against the regex at its REAL position in the full text, where
		// the lookbehind correctly sees the preceding `api=` and the chunk is
		// identified as an independent match, so it is redacted like any other
		// secret-shaped content.
		const obf = new SecretObfuscator(
			[
				{ type: "plain", content: "ABCDEFGH" },
				{ type: "regex", content: "(?<=api=)[0-9]{8}[A-Z]{8}|(?<=api=)[0-9]{8}|[A-Z]{8}" },
			],
			"Q".repeat(43),
		);
		const placeholdered = obf.obfuscate("ABCDEFGH");
		const second = obf.obfuscate(`api=12345678${placeholdered}`);

		// Core regression: the lookbehind-qualified digits must not survive
		// verbatim in provider-visible output.
		expect(second).not.toContain("12345678");
		expect(second).not.toContain("ABCDEFGH");
		// Every byte must still round-trip.
		expect(obf.deobfuscate(second)).toBe("api=12345678ABCDEFGH");
		// Redacting the prefix must itself be a fixed point.
		expect(obf.obfuscate(second)).toBe(second);
	});

	it("redacts a cut prefix using placeholder right context instead of leaking it", () => {
		const obf = new SecretObfuscator(
			[
				{ type: "plain", content: "ABCDEFGH" },
				{ type: "regex", content: "SECRETUVABCD|SECRETUV(?=ABCD)|[A-Z]{8}" },
			],
			"Q".repeat(43),
		);
		const placeholdered = obf.obfuscate("ABCDEFGH");
		const second = obf.obfuscate(`SECRETUV${placeholdered}`);

		// The prefix match depends on lookahead supplied by the expanded placeholder.
		// It must still be redacted while the placeholder's own bytes stay atomic.
		expect(second).not.toContain("SECRETUV");
		expect(second).toContain(placeholdered);
		expect(obf.deobfuscate(second)).toBe("SECRETUVABCDEFGH");
		expect(obf.obfuscate(second)).toBe(second);
	});

	it("redacts a cut suffix using placeholder left context instead of leaking it", () => {
		const key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1n";
		const entries = [
			{ type: "plain" as const, content: "ABCDEFGH" },
			{ type: "regex" as const, mode: "replace" as const, content: "(?<=ABCD)[A-Z]{8}" },
		];
		const obf = new SecretObfuscator(entries, key);
		const placeholdered = obf.obfuscate("ABCDEFGH");
		const second = obf.obfuscate("ABCDEFGHIJKL");

		// The suffix match depends on lookbehind supplied by the expanded placeholder.
		// It must still be redacted while the placeholder's own bytes stay atomic.
		expect(second).not.toContain("IJKL");
		expect(second).toContain(placeholdered);
		expect(obf.obfuscate(second)).toBe(second);

		const restarted = new SecretObfuscator(entries, key);
		expect(restarted.obfuscate(second)).toBe(second);
	});

	it("obfuscates a short cut suffix covered by a full-length placeholder-context match", () => {
		const obf = new SecretObfuscator(
			[
				{ type: "plain", content: "ABCDEFGH" },
				{ type: "regex", content: "(?<=ABCD)[A-Z]{8}" },
			],
			"Q".repeat(43),
		);

		const second = obf.obfuscate("ABCDEFGHIJKL");

		expect(second).not.toContain("IJKL");
		expect(obf.deobfuscate(second)).toBe("ABCDEFGHIJKL");
		expect(obf.obfuscate(second)).toBe(second);
	});

	it("keeps default replace markers stable when a lookbehind match spills into a prior placeholder", () => {
		const key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1n";
		const entries = [
			{ type: "plain" as const, content: "ABCDEFGH" },
			{
				type: "regex" as const,
				mode: "replace" as const,
				content: "(?<=api=)[0-9]{8}[A-Z]{8}|(?<=api=)[0-9]{8}|[A-Z]{8}",
			},
		];
		const obf = new SecretObfuscator(entries, key);
		const placeholdered = obf.obfuscate("ABCDEFGH");
		const persisted = obf.obfuscate(`api=12345678${placeholdered}`);

		expect(persisted).not.toContain("12345678");
		expect(persisted).not.toContain("ABCDEFGH");
		expect(persisted).toContain(placeholdered);
		expect(obf.obfuscate(persisted)).toBe(persisted);

		const restarted = new SecretObfuscator(entries, key);
		expect(restarted.obfuscate(persisted)).toBe(persisted);
	});

	it("keeps regex placeholders stable when inner friendly names change", () => {
		const sharedKey = "E".repeat(43);
		const before = new SecretObfuscator(
			[
				{ type: "plain", content: "abcdefgh", friendlyName: "old" },
				{ type: "regex", content: "api_key=\\S+", friendlyName: "api-key" },
			],
			sharedKey,
		);
		const persisted = before.obfuscate("api_key=abcdefghXYZ");
		const after = new SecretObfuscator(
			[
				{ type: "plain", content: "abcdefgh", friendlyName: "new" },
				{ type: "regex", content: "api_key=\\S+", friendlyName: "api-key" },
			],
			sharedKey,
		);

		expect(after.obfuscate("api_key=abcdefghXYZ")).toBe(persisted);
		expect(after.deobfuscate(persisted)).toBe("api_key=abcdefghXYZ");
	});

	it("keeps default replace markers stable when friendly placeholder aliases advance scan context", () => {
		const sharedKey = "E".repeat(43);
		const regex = "api_key=[a-z]{8}[A-Za-z0-9]{3}|(?<=abcdefgh)[A-Za-z0-9]{3}";
		const before = new SecretObfuscator(
			[
				{ type: "plain", content: "abcdefgh", friendlyName: "old" },
				{ type: "regex", mode: "replace", content: regex },
			],
			sharedKey,
		);
		const oldPlaceholder = before.obfuscate("abcdefgh");
		const after = new SecretObfuscator(
			[
				{ type: "plain", content: "abcdefgh", friendlyName: "new" },
				{ type: "regex", mode: "replace", content: regex },
			],
			sharedKey,
		);

		const persisted = after.obfuscate(`api_key=${oldPlaceholder}XYZ`);

		expect(persisted).toContain(oldPlaceholder);
		expect(persisted).not.toContain("XYZ");
		expect(after.obfuscate(persisted)).toBe(persisted);
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
				{ type: "plain", content: "SECRETUV" },
				{ type: "regex", mode: "replace", content: "[A-Z0-9]{8,}", replacement: "REDACTED" },
			],
			"A".repeat(43),
		);

		const obfuscated = obfuscator.obfuscate("SECRETUVX1");

		expect(obfuscated).toMatch(/^#[A-Z0-9]+:U#REDACTED$/);
		expect(obfuscated).not.toMatch(/X1$/);
		expect(obfuscator.deobfuscate(obfuscated)).toBe("SECRETUVREDACTED");
	});

	it("redacts bounded replace-mode regex suffixes after generated placeholders", () => {
		const obfuscator = new SecretObfuscator(
			[
				{ type: "plain", content: "SECRETUV" },
				{ type: "regex", mode: "replace", content: "[A-Z0-9]{10}", replacement: "REDACTED" },
			],
			"B".repeat(43),
		);

		const obfuscated = obfuscator.obfuscate("SECRETUVX1");

		// The 8-char SECRETUVX1 redacts to one placeholder + REDACTED; assert the `X1`
		// suffix is gone via end-anchored structure, not substring absence — the
		// random keyed base can itself contain the two chars "X1".
		expect(obfuscated).toMatch(/^#[A-Z0-9]+:U#REDACTED$/);
		expect(obfuscated).not.toMatch(/X1$/);
		expect(obfuscator.deobfuscate(obfuscated)).toBe("SECRETUVREDACTED");
	});

	it("emits a custom replacement once around a generated placeholder", () => {
		const obfuscator = new SecretObfuscator(
			[
				{ type: "plain", content: "abcdefgh" },
				{ type: "regex", mode: "replace", content: "api_key=\\S+", replacement: "REDACTED" },
			],
			"C".repeat(43),
		);

		const obfuscated = obfuscator.obfuscate("api_key=abcdefghXYZ");

		// A custom replacement is a single redaction marker for the whole match, so
		// it must not be duplicated on both sides of the preserved placeholder (the
		// bug produced `REDACTED#…#REDACTED`). Asserted by structure plus an
		// end-anchored guard rather than a base-collidable substring count.
		expect(obfuscated).toMatch(/^REDACTED#[A-Z0-9]+:L#$/);
		expect(obfuscated).not.toMatch(/REDACTED$/);
		expect(obfuscated).not.toContain("api_key=");
		expect(obfuscator.deobfuscate(obfuscated)).toBe("REDACTEDabcdefgh");
	});

	it("is idempotent when re-obfuscating already-obfuscated text", () => {
		// The SDK obfuscates messages in both convertToLlm and transformProviderContext,
		// and prior-turn messages re-enter every turn, so obfuscate() must be a fixed
		// point. Re-running it on its own output must not re-redact around an existing
		// placeholder (regression: `#…#REDACTED` -> `#…#REDACTEDDACTED`).
		const replace = new SecretObfuscator(
			[
				{ type: "plain", content: "SECRETUV" },
				{ type: "regex", mode: "replace", content: "[A-Z0-9]{10}", replacement: "REDACTED" },
			],
			"D".repeat(43),
		);
		const replaceOnce = replace.obfuscate("SECRETUVX1");
		expect(replaceOnce).toMatch(/^#[A-Z0-9]+:U#REDACTED$/);
		expect(replace.obfuscate(replaceOnce)).toBe(replaceOnce);
		expect(replace.obfuscate(replace.obfuscate(replaceOnce))).toBe(replaceOnce);
		expect(replace.deobfuscate(replaceOnce)).toBe("SECRETUVREDACTED");

		// Custom replacement spanning a placeholder must also stay a fixed point.
		const custom = new SecretObfuscator(
			[
				{ type: "plain", content: "abcdefgh" },
				{ type: "regex", mode: "replace", content: "api_key=\\S+", replacement: "REDACTED" },
			],
			"E".repeat(43),
		);
		const customOnce = custom.obfuscate("api_key=abcdefghXYZ");
		expect(custom.obfuscate(customOnce)).toBe(customOnce);
		expect(custom.deobfuscate(customOnce)).toBe("REDACTEDabcdefgh");

		// Obfuscate-mode regex spanning a placeholder is a fixed point too.
		const obf = new SecretObfuscator(
			[
				{ type: "plain", content: "abcdefgh" },
				{ type: "regex", content: "api_key=[A-Za-z0-9]{11}", friendlyName: "api-key" },
			],
			"F".repeat(43),
		);
		const obfOnce = obf.obfuscate("api_key=abcdefghXYZ");
		expect(obf.obfuscate(obfOnce)).toBe(obfOnce);
		expect(obf.deobfuscate(obfOnce)).toBe("api_key=abcdefghXYZ");
	});

	it("cross-matches a fresh placeholder whose token already appears in the input", () => {
		const obf = new SecretObfuscator(
			[
				{ type: "plain", content: "abcdefgh" },
				{ type: "regex", mode: "replace", content: "api_key=\\S+", replacement: "REDACTED" },
			],
			"G".repeat(43),
		);
		const token = obf.obfuscate("abcdefgh");
		expect(token).toMatch(/^#[A-Z0-9]+:L#$/);

		// Input carries the prior token literally AND a fresh api_key=abcdefghXYZ (raw `abc`).
		// The fresh occurrence must still be redacted (XYZ gone) while the prior token is
		// preserved; range-based origin tracking distinguishes the two same-token spans,
		// where a token-value guard would skip both and leak XYZ.
		const out = obf.obfuscate(`${token} api_key=abcdefghXYZ`);
		expect(out).toBe(`${token} REDACTED${token}`);
		expect(obf.deobfuscate(out)).toBe("abcdefgh REDACTEDabcdefgh");
		expect(obf.obfuscate(out)).toBe(out); // still a fixed point
	});

	it("redacts new surrounding bytes around a prior-call placeholder without re-redacting markers", () => {
		const obf = new SecretObfuscator(
			[
				{ type: "plain", content: "abcdefgh" },
				{ type: "regex", mode: "replace", content: "api_key=\\S+", replacement: "REDACTED" },
			],
			"H".repeat(43),
		);
		// Simulate a session where `abc` was obfuscated in an earlier turn (the token
		// is a prior-call/input placeholder) and the regex now re-enters text where
		// `api_key=` + raw `XYZ` still surround that token. The prior placeholder is
		// preserved, but the genuinely-new surrounding bytes (`api_key=`, `XYZ`) must
		// be redacted — not dropped, which would leak `XYZ` to the provider.
		const token = obf.obfuscate("abcdefgh");
		const out = obf.obfuscate(`api_key=${token}XYZ`);
		expect(out).toBe(`REDACTED${token}`);
		expect(out).not.toContain("XYZ");
		expect(out).not.toContain("api_key=");
		expect(obf.deobfuscate(out)).toBe("REDACTEDabcdefgh");
		// Re-obfuscating the redacted output is a fixed point: the marker `REDACTED`
		// does not independently satisfy `api_key=\S+`, so nothing grows.
		expect(obf.obfuscate(out)).toBe(out);
	});

	it("redacts bounded replace regex remainders around prior placeholders", () => {
		const obf = new SecretObfuscator(
			[
				{ type: "plain", content: "abcdefgh" },
				{ type: "regex", mode: "replace", content: "api_key=[A-Za-z0-9]{11}", replacement: "REDACTED" },
			],
			"I".repeat(43),
		);
		const token = obf.obfuscate("abcdefgh");

		const out = obf.obfuscate(`api_key=${token}XYZ`);

		expect(out).toBe(`REDACTED${token}`);
		expect(out).not.toContain("XYZ");
		expect(out).not.toContain("api_key=");
		expect(obf.deobfuscate(out)).toBe("REDACTEDabcdefgh");
		expect(obf.obfuscate(out)).toBe(out);
	});

	it("redacts custom replacement prefixes that are raw regex remainders", () => {
		const obf = new SecretObfuscator(
			[
				{ type: "plain", content: "SECRETUV" },
				{ type: "regex", mode: "replace", content: "[A-Z0-9]{9}", replacement: "REDACTED" },
			],
			"K".repeat(43),
		);
		const token = obf.obfuscate("SECRETUV");

		const out = obf.obfuscate(`${token}R`);

		expect(out).toBe(`${token}REDACTED`);
		expect(obf.deobfuscate(out)).toBe("SECRETUVREDACTED");
		expect(obf.obfuscate(out)).toBe(out);
	});

	it("redacts trailing bytes after existing custom replacement markers", () => {
		const obf = new SecretObfuscator(
			[
				{ type: "plain", content: "SECRETUV" },
				{ type: "regex", mode: "replace", content: "[A-Z0-9]{17}", replacement: "REDACTED" },
			],
			"L".repeat(43),
		);
		const token = obf.obfuscate("SECRETUV");

		const out = obf.obfuscate(`${token}REDACTEDX`);

		expect(out).toBe(`${token}REDACTED`);
		expect(obf.obfuscate(out)).toBe(out);
	});

	it("keeps bounded custom replacement matches idempotent around preserved placeholders", () => {
		const obf = new SecretObfuscator(
			[
				{ type: "plain", content: "SECRETUV" },
				{ type: "regex", mode: "replace", content: "[A-Z0-9]{8,12}", replacement: "REDACTED" },
			],
			"M".repeat(43),
		);
		const out = obf.obfuscate("XSECRETUVREDACTED");

		expect(out).toMatch(/^REDACTED#[A-Z0-9]+:U#REDACTED$/);
		expect(obf.obfuscate(out)).toBe(out);
		expect(obf.deobfuscate(out)).toBe("REDACTEDSECRETUVREDACTED");
	});

	it("redacts default replace regex remainders around prior placeholders", () => {
		const obf = new SecretObfuscator(
			[
				{ type: "plain", content: "abcdefgh" },
				{ type: "regex", mode: "replace", content: "api_key=[A-Za-z0-9]{11}" },
			],
			"J".repeat(43),
		);
		const token = obf.obfuscate("abcdefgh");

		const out = obf.obfuscate(`api_key=${token}XYZ`);

		expect(out).toContain(token);
		expect(out).not.toContain("XYZ");
		expect(out).not.toContain("api_key=");
		expect(obf.obfuscate(out)).toBe(out);
	});

	it("redacts bounded regex remainders around renamed friendly placeholders", () => {
		const sharedKey = "J".repeat(43);
		const before = new SecretObfuscator([{ type: "plain", content: "abcdefgh", friendlyName: "old" }], sharedKey);
		const oldToken = before.obfuscate("abcdefgh");
		const after = new SecretObfuscator(
			[
				{ type: "plain", content: "abcdefgh", friendlyName: "new" },
				{ type: "regex", mode: "replace", content: "api_key=[A-Za-z0-9]{11}" },
			],
			sharedKey,
		);

		const out = after.obfuscate(`api_key=${oldToken}XYZ`);

		expect(out).toContain(oldToken);
		expect(out).not.toContain("api_key=");
		expect(out).not.toContain("XYZ");
		expect(after.obfuscate(out)).toBe(out);
	});

	it("redacts default replace raw suffixes after prior placeholders", () => {
		const obf = new SecretObfuscator(
			[
				{ type: "plain", content: "SECRETUV" },
				{ type: "regex", mode: "replace", content: "[A-Z0-9]{10}" },
			],
			"N".repeat(43),
		);
		const token = obf.obfuscate("SECRETUV");

		const out = obf.obfuscate(`${token}X1`);

		expect(out).toContain(token);
		expect(out).not.toContain("X1");
		expect(obf.obfuscate(out)).toBe(out);
	});

	it("redacts raw default replace values that look like generated sentinels", () => {
		const obf = new SecretObfuscator([{ type: "plain", content: "ZZTOPSECRET", mode: "replace" }], "Q".repeat(43));

		const out = obf.obfuscate("ZZTOPSECRET");

		expect(out).not.toBe("ZZTOPSECRET");
		expect(out).toHaveLength("ZZTOPSECRET".length);
	});

	it("does not emit a plain replace secret equal to the Z/ZZ sentinel unchanged", () => {
		for (const content of ["Z", "ZZ"]) {
			const obf = new SecretObfuscator([{ type: "plain", content, mode: "replace" }], "Q".repeat(43));

			const out = obf.obfuscate(content);

			expect(out).not.toBe(content);
			expect(out).toHaveLength(content.length);
			// Replace mode is one-way; re-obfuscating the emitted value is a fixed point.
			expect(obf.obfuscate(out)).toBe(out);
		}
	});

	it("does not emit a default replace regex match equal to the Z/ZZ sentinel unchanged", () => {
		// A literal regex whose match is exactly the sentinel: the perturbed value is
		// not re-matched, so it is emitted distinct AND stays a fixed point.
		for (const content of ["Z", "ZZ"]) {
			const obf = new SecretObfuscator([{ type: "regex", mode: "replace", content }], "Q".repeat(43));

			const out = obf.obfuscate(content);

			expect(out).not.toBe(content);
			expect(out).toHaveLength(content.length);
			expect(obf.obfuscate(out)).toBe(out);
		}
	});

	it("redacts a self-matching sentinel regex to a stable nonmatching value", () => {
		// A regex that also matches the single A/B perturbation still has same-length
		// values it does NOT match (a lowercase pair for [A-Z]{2}, an A/Z-free pair for
		// Z+). The bounded search finds one, so the sentinel is redacted to a value the
		// regex never re-matches: leak-free AND a fixed point under re-obfuscation.
		for (const content of ["Z+", "[A-Z]{2}"]) {
			const obf = new SecretObfuscator([{ type: "regex", mode: "replace", content }], "Q".repeat(43));

			const out = obf.obfuscate("ZZ");

			expect(out).not.toBe("ZZ");
			expect(out).toHaveLength(2);
			expect(obf.obfuscate(out)).toBe(out);
			expect(obf.obfuscate(obf.obfuscate(out))).toBe(out);
		}
	});

	it("searches past the first perturbation when it also matches the regex", () => {
		// Regression for a regex that matches both the sentinel and its single A/B
		// perturbation: `Z|A`/`[AZ]` match `Z` and `A`, so the old guard kept the raw
		// `Z` and shipped it. A nonmatching same-length value (`B`) must be found.
		for (const content of ["Z|A", "[AZ]"]) {
			const obf = new SecretObfuscator([{ type: "regex", mode: "replace", content }], "Q".repeat(43));

			const out = obf.obfuscate("Z");

			expect(out).not.toBe("Z");
			expect(out).toHaveLength(1);
			expect(obf.obfuscate(out)).toBe(out);
		}
	});

	it("falls back to punctuation when a regex matches every alphanumeric sentinel candidate", () => {
		const obf = new SecretObfuscator([{ type: "regex", mode: "replace", content: "[A-Za-z0-9]{2}" }], "Q".repeat(43));

		const out = obf.obfuscate("ZZ");

		expect(out).not.toBe("ZZ");
		expect(out).toHaveLength(2);
		expect(/^[A-Za-z0-9]{2}$/.test(out)).toBe(false);
		expect(obf.obfuscate(out)).toBe(out);
	});

	it("exhausts two-character fallback candidates before keeping the sentinel", () => {
		const obf = new SecretObfuscator([{ type: "regex", mode: "replace", content: "[A-Za-z0-9]." }], "Q".repeat(43));

		const out = obf.obfuscate("ZZ");

		expect(out).not.toBe("ZZ");
		expect(out).toHaveLength(2);
		expect(/[A-Za-z0-9]./.test(out)).toBe(false);
		expect(obf.obfuscate(out)).toBe(out);
	});

	it("samples every leading character class before giving up on three-character collisions", () => {
		const obf = new SecretObfuscator(
			[{ type: "regex", mode: "replace", content: "[A-Za-z0-9].{2}" }],
			"Q".repeat(43),
		);

		const out = obf.obfuscate("ZZc");

		expect(out).not.toBe("ZZc");
		expect(out).toHaveLength(3);
		expect(/[A-Za-z0-9].{2}/.test(out)).toBe(false);
		expect(obf.obfuscate(out)).toBe(out);
	});

	it("exhausts three-character fallback candidates when the nonmatching byte must be last", () => {
		const obf = new SecretObfuscator(
			[{ type: "regex", mode: "replace", content: ".{2}[A-Za-z0-9]" }],
			"Q".repeat(43),
		);

		const out = obf.obfuscate("ZZc");

		expect(out).not.toBe("ZZc");
		expect(out).toHaveLength(3);
		expect(/.{2}[A-Za-z0-9]/.test(out)).toBe(false);
		expect(obf.obfuscate(out)).toBe(out);
	});

	it("exhausts longer fallback candidates when the nonmatching byte must be last", () => {
		const obf = new SecretObfuscator(
			[{ type: "regex", mode: "replace", content: ".{4}[A-Za-z0-9]" }],
			"Q".repeat(43),
		);

		const out = obf.obfuscate("ZZLB6");

		expect(out).not.toBe("ZZLB6");
		expect(out).toHaveLength(5);
		expect(/.{4}[A-Za-z0-9]/.test(out)).toBe(false);
		expect(obf.obfuscate(out)).toBe(out);
	});

	it("tries multi-character fallback replacements when one changed byte is still matchable", () => {
		const obf = new SecretObfuscator([{ type: "regex", mode: "replace", content: "[A-Za-z0-9].*" }], "Q".repeat(43));

		const out = obf.obfuscate("ZZLB6");

		expect(out).not.toBe("ZZLB6");
		expect(out).toHaveLength(5);
		expect(/[A-Za-z0-9].*/.test(out)).toBe(false);
		expect(obf.obfuscate(out)).toBe(out);
	});

	it("redacts a default replace regex that matches every non-whitespace candidate", () => {
		// `\S{5}` matches every non-whitespace value, so the alphanumeric and
		// punctuation candidates are all exhausted. A same-length whitespace run is a
		// stable nonmatching redaction, so the colliding sentinel value is replaced
		// rather than shipped raw to the provider.
		const obf = new SecretObfuscator([{ type: "regex", mode: "replace", content: "\\S{5}" }], "Q".repeat(43));

		const out = obf.obfuscate("ZZLB6");

		expect(out).not.toBe("ZZLB6");
		expect(out).toHaveLength(5);
		expect(/\S{5}/.test(out)).toBe(false);
		expect(obf.obfuscate(out)).toBe(out);
	});

	it("redacts a replace regex that also matches all-space and all-tab runs via a mixed marker", () => {
		// `(?:\S{5}| {5}|\t{5})` matches every non-whitespace run AND a full space or
		// tab run, so neither the punctuation candidates nor a full whitespace run is a
		// stable redaction. A mixed marker (one whitespace byte among filler, e.g.
		// ` AAAA`) breaks every fixed-length run, so the colliding sentinel value is
		// still redacted to a stable nonmatching value instead of shipped raw.
		const obf = new SecretObfuscator(
			[{ type: "regex", mode: "replace", content: "(?:\\S{5}| {5}|\\t{5})" }],
			"Q".repeat(43),
		);

		const out = obf.obfuscate("ZZLB6");

		expect(out).not.toBe("ZZLB6");
		expect(out).toHaveLength(5);
		expect(/(?:\S{5}| {5}|\t{5})/.test(out)).toBe(false);
		expect(obf.obfuscate(out)).toBe(out);
	});

	it("keeps the sentinel only when no same-length value avoids the regex", () => {
		// A match-everything regex has no nonmatching same-length redaction, so the
		// search exhausts and the sentinel is kept as the sole fixed point. Such a
		// config redacts every character and is pathological by construction.
		for (const content of [".", "[\\s\\S]"]) {
			const obf = new SecretObfuscator([{ type: "regex", mode: "replace", content }], "Q".repeat(43));

			const out = obf.obfuscate("Z");

			expect(out).toBe("Z");
			expect(obf.obfuscate(out)).toBe(out);
		}
	});

	it("redacts a context-sensitive replace regex to a value stable in place", () => {
		// A replace-mode regex with lookbehind matches a value only in context, so a
		// candidate tested in isolation can be accepted yet re-match once substituted
		// back. Regression: `(?<=api=)[AZ]` redacting `api=Z` to `api=A` (A does not
		// match a bare `A`) was then re-redacted to `api=Z` on the next pass, shipping
		// the raw matched value on every other turn. The replacement must be a fixed
		// point evaluated in its surrounding context. Both inputs exercise a distinct
		// path: `Z` is the sentinel collision, `A`'s deterministic replacement (`Z`)
		// differs from the value but still re-matches in context.
		for (const input of ["api=Z", "api=A"]) {
			const obf = new SecretObfuscator(
				[{ type: "regex", mode: "replace", content: "(?<=api=)[AZ]" }],
				"Q".repeat(43),
			);

			const out = obf.obfuscate(input);

			expect(out).toHaveLength(input.length);
			expect(out.startsWith("api=")).toBe(true);
			// The matched character must not survive in a position the regex re-matches.
			expect(/(?<=api=)[AZ]/.test(out)).toBe(false);
			// Re-obfuscation is a fixed point, so it never oscillates back to the raw value.
			expect(obf.obfuscate(out)).toBe(out);
			expect(obf.obfuscate(obf.obfuscate(out))).toBe(out);
		}
	});

	it("redacts a wide-lookbehind replace regex to a value stable in place", () => {
		// A lookbehind wider than the re-match back-scan window (512) must still
		// evaluate against the full surrounding text. Regression: truncating the
		// fixed-point probe to a fixed window dropped the 600-char lookbehind, so the
		// check falsely accepted a candidate the regex DOES re-match once the whole
		// prefix is present — the redaction then oscillated back to the raw matched
		// value on alternating obfuscate() passes, leaking it to the provider.
		const prefix = "A".repeat(600);
		const re = new RegExp(`(?<=${prefix})[AZ]`);
		for (const input of [`${prefix}Z`, `${prefix}A`]) {
			const obf = new SecretObfuscator(
				[{ type: "regex", mode: "replace", content: `(?<=${prefix})[AZ]` }],
				"Q".repeat(43),
			);

			const out = obf.obfuscate(input);

			expect(out).toHaveLength(input.length);
			expect(out.startsWith(prefix)).toBe(true);
			// The matched character must not survive where the full-context regex re-matches.
			expect(re.test(out)).toBe(false);
			// Re-obfuscation is a fixed point, so it never oscillates back to the raw value.
			expect(obf.obfuscate(out)).toBe(out);
			expect(obf.obfuscate(obf.obfuscate(out))).toBe(out);
		}
	});

	it("does not require a placeholder key for entries that never produce a placeholder", () => {
		// Short plain obfuscate entries are toned down, so they must not force key
		// creation; regex/long-plain obfuscate entries can placehold and do need it.
		expect(secretEntryNeedsPlaceholderKey({ type: "plain", content: "abc" })).toBe(false);
		expect(secretEntryNeedsPlaceholderKey({ type: "plain", content: "abcdefgh" })).toBe(true);
		expect(secretEntryNeedsPlaceholderKey({ type: "regex", content: "[A-Z]{2}" })).toBe(true);
		expect(secretEntryNeedsPlaceholderKey({ type: "plain", content: "abc", mode: "replace" })).toBe(false);
		expect(secretEntryNeedsPlaceholderKey({ type: "regex", content: "x+", mode: "replace" })).toBe(false);
	});

	it("ignores obfuscate entries shadowed by a same-content replace entry when deciding key need", () => {
		const secret = "ghp_exampletoken1234567890";
		// A same-content plain replace entry runs before the plain obfuscate entry in
		// obfuscate(), so the value is one-way replaced and the obfuscate entry never
		// emits a reversible placeholder. The set must therefore not require the key.
		expect(
			secretEntriesNeedPlaceholderKey([
				{ type: "plain", content: secret, mode: "obfuscate" },
				{ type: "plain", content: secret, mode: "replace" },
			]),
		).toBe(false);
		// Verify the shadowing actually holds: no reversible placeholder is emitted.
		const obf = new SecretObfuscator(
			[
				{ type: "plain", content: secret, mode: "obfuscate" },
				{ type: "plain", content: secret, mode: "replace" },
			],
			"test-placeholder-key",
		);
		const out = obf.obfuscate(`value=${secret}`);
		expect(out).not.toContain(secret);
		expect(out).not.toMatch(/#[A-Z0-9]/);
		// An unshadowed obfuscate entry still requires the key.
		expect(secretEntriesNeedPlaceholderKey([{ type: "plain", content: secret, mode: "obfuscate" }])).toBe(true);
		// A replace entry with DIFFERENT content does not shadow the obfuscate entry.
		expect(
			secretEntriesNeedPlaceholderKey([
				{ type: "plain", content: secret, mode: "obfuscate" },
				{ type: "plain", content: "unrelated-other-secret", mode: "replace" },
			]),
		).toBe(true);
		// A replace entry whose CUSTOM replacement still contains the secret does NOT
		// shadow it: obfuscate()'s later pass re-scans the inserted replacement text and
		// emits a reversible placeholder, which needs the persisted key.
		const reintroEntries: SecretEntry[] = [
			{ type: "plain", content: secret, mode: "obfuscate" },
			{ type: "plain", content: secret, mode: "replace", replacement: `PREFIX_${secret}_SUFFIX` },
		];
		expect(secretEntriesNeedPlaceholderKey(reintroEntries)).toBe(true);
		const reintroOut = new SecretObfuscator(reintroEntries, "test-placeholder-key").obfuscate(`value=${secret}`);
		expect(reintroOut).toMatch(/#[A-Z0-9]/);
		// Among duplicate same-content replace entries the LAST one wins (the
		// obfuscator stores replace mappings in a content-keyed Map), so a safe earlier
		// duplicate must not mask a later reintroducing one: key is still required.
		const dupReintroLast: SecretEntry[] = [
			{ type: "plain", content: secret, mode: "obfuscate" },
			{ type: "plain", content: secret, mode: "replace" },
			{ type: "plain", content: secret, mode: "replace", replacement: secret },
		];
		expect(secretEntriesNeedPlaceholderKey(dupReintroLast)).toBe(true);
		expect(new SecretObfuscator(dupReintroLast, "test-placeholder-key").obfuscate(`value=${secret}`)).toMatch(
			/#[A-Z0-9]/,
		);
		// Reverse order: a later safe replacement overrides an earlier reintroducing
		// one, so the obfuscate entry is shadowed and no key is needed.
		const dupSafeLast: SecretEntry[] = [
			{ type: "plain", content: secret, mode: "obfuscate" },
			{ type: "plain", content: secret, mode: "replace", replacement: `X_${secret}_X` },
			{ type: "plain", content: secret, mode: "replace" },
		];
		expect(secretEntriesNeedPlaceholderKey(dupSafeLast)).toBe(false);
		expect(new SecretObfuscator(dupSafeLast, "test-placeholder-key").obfuscate(`value=${secret}`)).not.toMatch(
			/#[A-Z0-9]/,
		);
		// A transitive replace chain that rewrites a safe alias back into the secret
		// (`SECRET -> ALIAS`, `ALIAS -> SECRET`) reintroduces the value before the
		// plain-obfuscate pass, so the key is still required.
		const alias = "ALIAS_TOKEN_XYZ";
		const chainReintro: SecretEntry[] = [
			{ type: "plain", content: secret, mode: "obfuscate" },
			{ type: "plain", content: secret, mode: "replace", replacement: alias },
			{ type: "plain", content: alias, mode: "replace", replacement: secret },
		];
		expect(secretEntriesNeedPlaceholderKey(chainReintro)).toBe(true);
		expect(new SecretObfuscator(chainReintro, "test-placeholder-key").obfuscate(`value=${secret}`)).toMatch(
			/#[A-Z0-9]/,
		);
		// A replacement fragment that joins with adjacent passthrough bytes to form an
		// obfuscate content (`A -> SEC`, so `ARET12` becomes `SECRET12` during the
		// replace phase) still emits a reversible placeholder, so the key is required
		// even though no single replacement contains the whole content.
		const fragmentJoin: SecretEntry[] = [
			{ type: "plain", content: "SECRET12", mode: "obfuscate" },
			{ type: "plain", content: "SECRET12", mode: "replace", replacement: "SAFE" },
			{ type: "plain", content: "A", mode: "replace", replacement: "SEC" },
		];
		expect(secretEntriesNeedPlaceholderKey(fragmentJoin)).toBe(true);
		expect(new SecretObfuscator(fragmentJoin, "test-placeholder-key").obfuscate("x ARET12 y")).toMatch(/#[A-Z0-9]/);
		// A delete replacement also joins the passthrough bytes on both sides of the
		// removed token, so it can reconstruct the obfuscate content even though its
		// replacement output is empty.
		const deleteJoin: SecretEntry[] = [
			{ type: "plain", content: "SECRET12", mode: "obfuscate" },
			{ type: "plain", content: "SECRET12", mode: "replace", replacement: "SAFE" },
			{ type: "plain", content: "X", mode: "replace", replacement: "" },
		];
		expect(secretEntriesNeedPlaceholderKey(deleteJoin)).toBe(true);
		expect(new SecretObfuscator(deleteJoin, "test-placeholder-key").obfuscate("SECRETX12")).toMatch(/#[A-Z0-9]/);
	});

	it("does not require the key when a later replacement erases a content-forming fragment", () => {
		// `AA -> SEC` could seed `SECRET12`, but the later (shorter-content) `S -> X`
		// rewrites every `SEC` into `XEC`, so the replace phase can never leave
		// `SECRET12` for the plain-obfuscate pass. The key-need check must model that
		// erasure and stay key-free instead of writing secret-placeholder.key for an
		// effectively non-placeholding config.
		const entries: SecretEntry[] = [
			{ type: "plain", content: "SECRET12", mode: "obfuscate" },
			{ type: "plain", content: "SECRET12", mode: "replace", replacement: "SAFE" },
			{ type: "plain", content: "AA", mode: "replace", replacement: "SEC" },
			{ type: "plain", content: "S", mode: "replace", replacement: "X" },
		];
		expect(secretEntriesNeedPlaceholderKey(entries)).toBe(false);
		// And the obfuscator never reconstructs the secret nor emits a reversible
		// placeholder, confirming the config is genuinely non-placeholding.
		const out = new SecretObfuscator(entries, "test-placeholder-key").obfuscate("AARET12 and AART12");
		expect(out).not.toContain("SECRET12");
		expect(out).not.toMatch(/#[A-Z0-9]/);
	});

	it("does not require the key when a later replacement erases the surrounding context bytes", () => {
		// `AA -> SEC` could seed `SECRET12` by tiling its `SEC` output against
		// passthrough `RET12`, but the later `R -> X` rewrites that surrounding `R`,
		// so a freshly formed `SECRET12` becomes `SECXET12` before the obfuscate pass
		// — direct `SECRET12` is also shadowed to `SAFE`. The probe must model that
		// later replacements destroy the required surrounding bytes, not just the
		// fragment itself, and stay key-free for this effectively non-placeholding
		// config (otherwise it writes secret-placeholder.key and fails startup in an
		// unwritable agent config dir).
		const entries: SecretEntry[] = [
			{ type: "plain", content: "SECRET12", mode: "obfuscate" },
			{ type: "plain", content: "SECRET12", mode: "replace", replacement: "SAFE" },
			{ type: "plain", content: "AA", mode: "replace", replacement: "SEC" },
			{ type: "plain", content: "R", mode: "replace", replacement: "X" },
		];
		expect(secretEntriesNeedPlaceholderKey(entries)).toBe(false);
		const out = new SecretObfuscator(entries, "test-placeholder-key").obfuscate("AARET12 and SECRET12");
		expect(out).not.toContain("SECRET12");
		expect(out).not.toMatch(/#[A-Z0-9]/);
	});

	it("redacts a raw sentinel-shaped suffix bridged into a match by a prior placeholder", () => {
		// A prior-call placeholder followed by RAW text that merely looks like a
		// deterministic redaction sentinel (`ZZ…`). The default-replace regex matches
		// only because the deobfuscated placeholder bridges the combined value. The raw
		// suffix was never emitted by this obfuscator, so it must be redacted rather than
		// skipped by shape — both for a fixed-width regex (where the suffix does NOT
		// independently match) and a variable-width one (where it DOES). Either way,
		// leaving it would leak `ZZZZ` to the provider.
		for (const content of ["[A-Z0-9]{12}", "[A-Z0-9]{4,12}"]) {
			const obf = new SecretObfuscator(
				[
					{ type: "plain", content: "SECRETUV" },
					{ type: "regex", mode: "replace", content },
				],
				"R".repeat(43),
			);
			const token = obf.obfuscate("SECRETUV");
			expect(token).toMatch(/^#[A-Z0-9]+:U#$/);

			const out = obf.obfuscate(`${token}ZZZZ`);

			expect(out).toContain(token);
			expect(out).not.toContain("ZZZZ");
		}
	});

	it("keeps default replace regex output idempotent around prior placeholders", () => {
		const obf = new SecretObfuscator(
			[
				{ type: "plain", content: "SECRETUV" },
				{ type: "regex", mode: "replace", content: "[A-Za-z0-9]{10}" },
			],
			"M".repeat(43),
		);

		const out = obf.obfuscate("SECRETUVX1");

		expect(obf.obfuscate(out)).toBe(out);
	});

	it("keeps broad default replace regex output idempotent around prior placeholders", () => {
		const obf = new SecretObfuscator(
			[
				{ type: "plain", content: "SECRETUV" },
				{ type: "regex", mode: "replace", content: "[A-Za-z0-9]+" },
			],
			"O".repeat(43),
		);

		const out = obf.obfuscate("SECRETUVX1");

		expect(obf.obfuscate(out)).toBe(out);
	});

	it("keeps default replace regex output idempotent after restart", () => {
		const key = "P".repeat(43);
		const first = new SecretObfuscator(
			[
				{ type: "plain", content: "SECRETUV" },
				{ type: "regex", mode: "replace", content: "[A-Za-z0-9]+" },
			],
			key,
		);
		const persisted = first.obfuscate("SECRETUVX1");
		const restarted = new SecretObfuscator(
			[
				{ type: "plain", content: "SECRETUV" },
				{ type: "regex", mode: "replace", content: "[A-Za-z0-9]+" },
			],
			key,
		);

		expect(restarted.obfuscate(persisted)).toBe(persisted);
	});

	it("keeps a multi-char default replace remainder stable across restart", () => {
		// Regression: a per-chunk remainder longer than the 2-char `ZZ` sentinel was
		// redacted to a content-derived `ZZ`+hash chunk that was only a fixed point
		// within the generating session (tracked in #generatedReplaceChunks). A fresh
		// obfuscator with the same key re-redacted it to a different value, so persisted
		// obfuscated text — and the provider prompt-cache prefixes it anchors — drifted
		// across restart (`ZZPL#…#` -> `ZZ7f#…#`). The remainder marker now depends only
		// on the key and length, so a fresh instance reproduces it byte-identically.
		const key = "Z".repeat(43);
		const entries = [
			{ type: "plain" as const, content: "ABCDEFGH" },
			{ type: "regex" as const, mode: "replace" as const, content: "[A-Z0-9]{12}" },
		];
		const first = new SecretObfuscator(entries, key);
		const token = first.obfuscate("ABCDEFGH");
		const persisted = first.obfuscate("BBBBABCDEFGH");

		// The 4-char remainder is redacted (raw bytes gone) but the placeholder survives.
		expect(persisted).not.toContain("BBBB");
		expect(persisted).toContain(token);
		expect(first.obfuscate(persisted)).toBe(persisted);

		// A fresh obfuscator (same key) reprocessing the persisted text must not drift.
		const restarted = new SecretObfuscator(entries, key);
		expect(restarted.obfuscate(persisted)).toBe(persisted);
	});

	it("ignores regex matches that fall entirely inside known placeholders", () => {
		const obfuscator = new SecretObfuscator([
			{ type: "plain", content: "abcdefgh" },
			{ type: "regex", mode: "replace", content: "P+", replacement: "REDACTED" },
		]);

		const obfuscated = obfuscator.obfuscate("abcdefgh");

		expect(obfuscated).not.toBe("REDACTED");
		expect(obfuscated).toMatch(/^#[A-Z0-9]+:L#$/);
		expect(obfuscator.deobfuscate(obfuscated)).toBe("abcdefgh");
	});

	it("ignores obfuscate regex matches that fall entirely inside known placeholders", () => {
		const obfuscator = new SecretObfuscator([
			{ type: "plain", content: "abcdefgh" },
			{ type: "regex", content: "P{8}", friendlyName: "inner" },
		]);

		const obfuscated = obfuscator.obfuscate("abcdefgh");

		expect(obfuscated).toMatch(/^#[A-Z0-9]+:L#$/);
		expect(obfuscated).not.toMatch(/^#INNER_/);
		expect(obfuscator.deobfuscate(obfuscated)).toBe("abcdefgh");
	});

	it("ignores obfuscate regex matches that partially overlap known placeholders", () => {
		const obfuscator = new SecretObfuscator([
			{ type: "plain", content: "secretuv" },
			{ type: "regex", content: "P{3}X", friendlyName: "partial" },
		]);

		const obfuscated = obfuscator.obfuscate("secretuvX");

		expect(obfuscated).toMatch(/^#[A-Z0-9]+:L#X$/);
		expect(obfuscated).not.toMatch(/^#PARTIAL_/);
		expect(obfuscator.deobfuscate(obfuscated)).toBe("secretuvX");
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
		expect(shownTool.text).toBe("bash stdout #XRRS#");
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
			{ type: "plain", content: "SeCretuv", friendlyName: "alpha" },
			{ type: "plain", content: "SecRetuv", friendlyName: "bravo" },
		]);
		const obfuscated = obfuscator.obfuscate("SeCretuv SecRetuv");
		const [tokenA, tokenB] = obfuscated.split(" ");
		if (!tokenA || !tokenB) throw new Error("expected two friendly placeholders");

		expect(tokenA).toMatch(/^#ALPHA_[A-Z0-9]+:M#$/);
		expect(tokenB).toMatch(/^#BRAVO_[A-Z0-9]+:M#$/);
		expect(obfuscator.deobfuscate(obfuscated)).toBe("SeCretuv SecRetuv");

		const stripPrefix = (token: string) => token.replace(/^#[A-Z0-9]+_/, "#");
		const aliasA = stripPrefix(tokenA);
		const aliasB = stripPrefix(tokenB);
		expect(aliasA).not.toBe(aliasB);
		expect(obfuscator.deobfuscate(aliasA)).toBe("SeCretuv");
		expect(obfuscator.deobfuscate(aliasB)).toBe("SecRetuv");
	});

	it("resolves a persisted friendly placeholder to the right same-base secret after a rename", () => {
		const original = new SecretObfuscator([
			{ type: "plain", content: "SeCretuv", friendlyName: "alpha" },
			{ type: "plain", content: "SecRetuv", friendlyName: "bravo" },
		]);
		const persistedBravo = original.obfuscate("SeCretuv SecRetuv").split(" ")[1];
		if (!persistedBravo) throw new Error("expected a bravo placeholder");

		// bravo renamed to charlie while both same-base secrets still exist.
		const renamed = new SecretObfuscator([
			{ type: "plain", content: "SeCretuv", friendlyName: "alpha" },
			{ type: "plain", content: "SecRetuv", friendlyName: "charlie" },
		]);
		expect(renamed.deobfuscate(persistedBravo)).toBe("SecRetuv");
	});

	it("keeps a mixed-case placeholder stable when a same-normalized secret is added earlier", () => {
		// Session 1: only SecRet is configured; persist its mixed-case token.
		const before = new SecretObfuscator([{ type: "plain", content: "SecRetuv" }]);
		const persisted = before.obfuscate("SecRetuv");
		expect(persisted).toMatch(/^#[A-Z0-9]+:M#$/);

		// Session 2: SeCret (same normalized value, also :M) is added EARLIER.
		const after = new SecretObfuscator([
			{ type: "plain", content: "SeCretuv" },
			{ type: "plain", content: "SecRetuv" },
		]);

		// SecRet's token must be value-stable, not bumped to a fallback, so the
		// persisted placeholder still round-trips to SecRet rather than SeCret.
		expect(after.obfuscate("SecRetuv")).toBe(persisted);
		expect(after.deobfuscate(persisted)).toBe("SecRetuv");
		expect(after.obfuscate("SeCretuv")).not.toBe(persisted);
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
		const alone = new SecretObfuscator([{ type: "plain", content: "Äbcdefgh" }]);
		const persisted = alone.obfuscate("Äbcdefgh");

		// A later session loads `äbc` EARLIER than `Äbc`.
		const reordered = new SecretObfuscator([
			{ type: "plain", content: "äbcdefgh" },
			{ type: "plain", content: "Äbcdefgh" },
		]);

		expect(reordered.obfuscate("Äbcdefgh")).toBe(persisted);
		expect(reordered.obfuscate("äbcdefgh")).not.toBe(persisted);
		expect(reordered.deobfuscate(persisted)).toBe("Äbcdefgh");
		expect(reordered.deobfuscate(reordered.obfuscate("äbcdefgh"))).toBe("äbcdefgh");
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
			{ type: "plain", content: "secretuv", friendlyName: "token" },
			{ type: "plain", content: "SECRETUV", friendlyName: "token" },
			{ type: "plain", content: "Secretuv", friendlyName: "token" },
		]);
		const obfuscated = obfuscator.obfuscate("secretuv SECRETUV Secretuv");
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
		expect(obfuscator.deobfuscate(obfuscated)).toBe("secretuv SECRETUV Secretuv");
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
			{ type: "plain", content: "SeCretuv", friendlyName: "token" },
			{ type: "plain", content: "SecRetuv", friendlyName: "token" },
		]);
		const repeated = new SecretObfuscator([
			{ type: "plain", content: "SeCretuv", friendlyName: "token" },
			{ type: "plain", content: "SecRetuv", friendlyName: "token" },
		]);
		const input = "SeCretuv SecRetuv";
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
		const early: Message[] = [{ role: "user", content: "first uses tok_aaaa", timestamp: 1 }];

		// Turn N: only the early message exists; tok_aaa mints a fresh placeholder.
		const earlyTurnN = JSON.stringify(obfuscateMessages(obfuscator, early));
		expect(earlyTurnN).not.toContain("tok_aaaa");

		// A later turn reveals a brand-new secret. Lazy regex discovery assigns it a fresh
		// index — this MUST NOT shift the placeholder already minted for tok_aaa.
		const later: Message[] = [{ role: "user", content: "later uses tok_bbbb", timestamp: 2 }];
		const laterOut = JSON.stringify(obfuscateMessages(obfuscator, later));
		expect(laterOut).not.toContain("tok_bbbb");

		// Re-obfuscate the early message after the new discovery: identical bytes → the
		// already-cached prefix for the early message stays valid.
		const earlyTurnNPlus1 = JSON.stringify(obfuscateMessages(obfuscator, early));
		expect(earlyTurnNPlus1).toEqual(earlyTurnN);
	});
});

describe("deobfuscateAgentMessages (display restore)", () => {
	it("restores assistant text and tool calls while leaving raw user text and thinking untouched", () => {
		const secret = "DISPLAY_SECRET_TOKEN_123";
		const obfuscator = new SecretObfuscator([{ type: "plain", content: secret }]);
		const placeholder = obfuscator.obfuscate(secret);
		expect(placeholder).not.toBe(secret);

		const userMsg: AgentMessage = { role: "user", content: `literal ${placeholder} token`, timestamp: 1 };
		const assistantMsg: AgentMessage = {
			role: "assistant",
			content: [
				{ type: "text", text: `answer ${placeholder}` },
				{ type: "thinking", thinking: `reason ${placeholder}` },
				{
					type: "toolCall",
					id: "call_1",
					name: "read",
					arguments: { path: `path ${placeholder}` },
					intent: `intent ${placeholder}`,
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
			timestamp: 2,
		};
		const branchSummary: AgentMessage = {
			role: "branchSummary",
			summary: `branch ${placeholder}`,
			fromId: "x",
			timestamp: 3,
		};
		const compactionSummary: AgentMessage = {
			role: "compactionSummary",
			summary: `compact ${placeholder}`,
			shortSummary: `short ${placeholder}`,
			tokensBefore: 0,
			timestamp: 4,
		};

		const restored = deobfuscateAgentMessages(obfuscator, [userMsg, assistantMsg, branchSummary, compactionSummary]);

		// Assistant text and tool-call args/intent are restored to the real secret.
		const restoredAssistant = restored[1] as AssistantMessage;
		const assistantJson = JSON.stringify(restoredAssistant.content);
		expect(assistantJson).toContain(secret);
		expect(assistantJson).not.toContain(`answer ${placeholder}`);
		expect(assistantJson).not.toContain(`path ${placeholder}`);
		expect(assistantJson).not.toContain(`intent ${placeholder}`);
		// Opaque thinking is never walked: placeholder-shaped bytes survive unchanged.
		expect(assistantJson).toContain(`reason ${placeholder}`);
		expect(assistantJson).not.toContain(`reason ${secret}`);
		// Model-generated summaries are restored.
		expect((restored[2] as { summary: string }).summary).toBe(`branch ${secret}`);
		expect((restored[3] as { summary: string; shortSummary?: string }).summary).toBe(`compact ${secret}`);
		expect((restored[3] as { summary: string; shortSummary?: string }).shortSummary).toBe(`short ${secret}`);
		// The user message is persisted raw and never walked: a literal placeholder-shaped token
		// survives byte-identical (same reference) rather than being turned into the secret.
		expect(restored[0]).toBe(userMsg);
	});

	it("restores compactionSummary block text while leaving snapcompact image bytes intact", () => {
		const secret = "BLOCKS_SECRET_TOKEN_456";
		const obfuscator = new SecretObfuscator([{ type: "plain", content: secret }]);
		const placeholder = obfuscator.obfuscate(secret);
		const imageData = `frame${secret}bytes==`;
		const message: AgentMessage = {
			role: "compactionSummary",
			summary: `summary ${placeholder}`,
			tokensBefore: 0,
			blocks: [
				{ type: "text", text: `archived ${placeholder}` },
				{ type: "image", data: imageData, mimeType: "image/png" },
			],
			timestamp: 1,
		};

		const [restored] = deobfuscateAgentMessages(obfuscator, [message]) as [typeof message];
		const blocks = restored.blocks ?? [];
		const text = blocks[0];
		const image = blocks[1];
		// Archived text is restored to the real secret...
		expect(text.type === "text" && text.text).toBe(`archived ${secret}`);
		// ...while the snapcompact image bytes pass through untouched.
		expect(image.type === "image" && image.data).toBe(imageData);
	});
});
