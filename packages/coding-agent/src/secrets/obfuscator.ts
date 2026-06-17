import * as crypto from "node:crypto";
import type { Context, Message, Tool } from "@oh-my-pi/pi-ai";
import { toolWireSchema } from "@oh-my-pi/pi-ai/utils/schema";
import type { SessionContext } from "../session/session-context";
import { compileSecretRegex } from "./regex";

// ═══════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════

export interface SecretEntry {
	type: "plain" | "regex";
	content: string;
	mode?: "obfuscate" | "replace";
	replacement?: string;
	flags?: string;
	friendlyName?: string;
}

// ═══════════════════════════════════════════════════════════════════════════
// Deterministic replacement generation
// ═══════════════════════════════════════════════════════════════════════════

const REPLACEMENT_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/** Generate a deterministic same-length replacement string from a secret value. */
function generateDeterministicReplacement(secret: string): string {
	// Simple hash: use Bun.hash for speed, seed from the secret bytes
	const hash = BigInt(Bun.hash(secret));
	const chars: string[] = [];
	let h = hash;
	for (let i = 0; i < secret.length; i++) {
		// Mix the hash for each character position
		h = h ^ (BigInt(i + 1) * 0x9e3779b97f4a7c15n);
		const idx = Number((h < 0n ? -h : h) % BigInt(REPLACEMENT_CHARS.length));
		chars.push(REPLACEMENT_CHARS[idx]);
	}
	return chars.join("");
}

// ═══════════════════════════════════════════════════════════════════════════
// Placeholder format
// ═══════════════════════════════════════════════════════════════════════════

const HASH_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
// Base length is sized for ~62 bits of entropy (64 bits of a keyed digest
// rendered as 12 base36 chars) so unrelated secrets do not collide on a shared
// base. A collision would let a persisted placeholder deobfuscate to the wrong
// secret when the configured secret set or its ordering changes across sessions.
const HASH_LEN = 12;
// Pre-friendly-name sessions persisted a 4-char, index-derived token; reproduce
// that exact legacy format so old session text still deobfuscates. The legacy
// token is keyed on the entry index, not the secret value, so it leaks nothing.
const LEGACY_HASH_LEN = 4;
const LEGACY_HASH_SEED = 0x5345_4352;
const MAX_FRIENDLY_NAME_LEN = 32;

// Per-process fallback key used when a caller does not supply a persisted
// per-install key. It is random (never shipped in source), so model-visible
// placeholders cannot be reversed by dictionary-hashing candidate secrets; it
// only forgoes cross-session token stability, which the persisted key provides.
let ephemeralPlaceholderKey: string | undefined;
function defaultPlaceholderKey(): string {
	ephemeralPlaceholderKey ??= crypto.randomBytes(32).toString("base64url");
	return ephemeralPlaceholderKey;
}

type PlaceholderCaseHint = "U" | "L" | "C" | "M";

/** Normalize a friendly name into the model-visible placeholder prefix. */
export function sanitizeSecretFriendlyName(name: string): string | undefined {
	const sanitized = name
		.replace(/[^A-Za-z0-9]/g, "")
		.toUpperCase()
		.slice(0, MAX_FRIENDLY_NAME_LEN);
	return sanitized.length > 0 ? sanitized : undefined;
}

function normalizePlaceholderSecret(secret: string): string {
	// Fold ONLY ASCII A–Z casing — that is exactly what a case hint (U/L/C) can
	// reconstruct. `String.toLowerCase()` also folds Unicode (e.g. `Ä`→`ä`), which
	// no hint encodes, so two Unicode-case-distinct secrets that share an ASCII
	// hint would collapse onto one base key and let a persisted placeholder
	// deobfuscate to the wrong secret when the secret set or its order changes.
	return secret.replace(/[A-Z]/g, ch => ch.toLowerCase());
}

// Derive the model-visible base from a KEYED digest of the secret. xxHash is
// fast and unkeyed, so a fixed-seed content hash of a low-entropy secret could
// be dictionaried from the transcript; HMAC-SHA256 under a private per-install
// key cannot, since the attacker lacks the key.
function buildHashBase(key: string, value: string): string {
	const digest = new Bun.CryptoHasher("sha256", key).update(value).digest();
	let v = 0n;
	for (let i = 0; i < 8; i++) v = (v << 8n) | BigInt(digest[i]);
	const radix = BigInt(HASH_CHARS.length);
	let tag = "";
	for (let i = 0; i < HASH_LEN; i++) {
		tag += HASH_CHARS[Number(v % radix)];
		v /= radix;
	}
	return tag;
}

/** Build the pre-friendly-name index-derived placeholder for session resume compatibility. */
function buildLegacyPlaceholder(index: number): string {
	let v = Bun.hash.xxHash32(String(index), LEGACY_HASH_SEED);
	let tag = "#";
	for (let i = 0; i < LEGACY_HASH_LEN; i++) {
		tag += HASH_CHARS[v % HASH_CHARS.length];
		v = Math.floor(v / HASH_CHARS.length);
	}
	return `${tag}#`;
}

function inferCaseHint(secret: string): PlaceholderCaseHint | undefined {
	let hasCased = false;
	let hasUpper = false;
	let hasLower = false;
	let capitalized = true;
	let seenFirstCased = false;

	for (let i = 0; i < secret.length; i++) {
		const code = secret.charCodeAt(i);
		const isUpper = code >= 65 && code <= 90;
		const isLower = code >= 97 && code <= 122;
		if (!isUpper && !isLower) continue;

		hasCased = true;
		if (isUpper) {
			hasUpper = true;
			if (seenFirstCased) capitalized = false;
		} else {
			hasLower = true;
			if (!seenFirstCased) capitalized = false;
		}
		seenFirstCased = true;
	}

	if (!hasCased) return undefined;
	if (hasUpper && !hasLower) return "U";
	if (hasLower && !hasUpper) return "L";
	if (capitalized) return "C";
	return "M";
}

function buildPlaceholder(hint: PlaceholderCaseHint | undefined, base: string, friendlyName?: string): string {
	const prefix = friendlyName ? `${friendlyName}_` : "";
	return hint ? `#${prefix}${base}:${hint}#` : `#${prefix}${base}#`;
}

/** Regex to match #HASH#, #HASH:U#, and #FRIENDLY_HASH(:hint)# placeholders. */
const PLACEHOLDER_RE = /#(?:[A-Z0-9]+_)?[A-Z0-9]{4,}(?::[ULCM])?#/g;

function placeholderWithoutFriendlyName(placeholder: string): string | undefined {
	const match = /^#[A-Z0-9]+_([A-Z0-9]{4,}(?::[ULCM])?)#$/.exec(placeholder);
	return match ? `#${match[1]}#` : undefined;
}

const PENDING_PLACEHOLDER_SUFFIX_RE = /#(?:[A-Z0-9]+_)?[A-Z0-9]*(?::[ULCM]?)?$/;

// Withhold a trailing run that could be the start of a placeholder from streamed
// deltas, so a partial token is never emitted before deobfuscation can replace
// it. A lone trailing `#` is always buffered, even right after an alnum/`:`
// (e.g. `ID#`), because that `#` can open a placeholder; emitting it would
// corrupt the length-sliced live draft once the token completes. The final
// non-streamed flush re-emits any buffered tail, so nothing is lost.
export function stripPendingSecretPlaceholderSuffix(text: string): string {
	const pendingPlaceholderStart = text.match(PENDING_PLACEHOLDER_SUFFIX_RE);
	if (pendingPlaceholderStart?.index === undefined) return text;
	return text.slice(0, pendingPlaceholderStart.index);
}

// ═══════════════════════════════════════════════════════════════════════════
// SecretObfuscator
// ═══════════════════════════════════════════════════════════════════════════

export class SecretObfuscator {
	/** Plain secrets: secret → index (known at construction) */
	#plainMappings = new Map<string, number>();

	/** Regex entries (patterns compiled at construction) */
	#regexEntries: Array<{ regex: RegExp; mode: "obfuscate" | "replace"; replacement?: string; friendlyName?: string }> =
		[];

	/** All obfuscate-mode mappings: index → { secret, placeholder } */
	#obfuscateMappings = new Map<number, { secret: string; placeholder: string }>();

	/** Replace-mode plain mappings: secret → replacement */
	#replaceMappings = new Map<string, string>();

	/** Reverse lookup for deobfuscation: placeholder → secret plus recursion policy. */
	#deobfuscateMap = new Map<string, { secret: string; recursive: boolean }>();

	/** Placeholder base-key (exact value for :M, case-folded otherwise) → base hash. */
	#placeholderBaseByKey = new Map<string, string>();

	/** Placeholder base hash → owner key, used to avoid ambiguous placeholders. */
	#placeholderBaseOwners = new Map<string, string>();

	/** Next available index for regex match discoveries */
	#nextIndex: number;

	/** Whether any secrets were configured */
	#hasAny: boolean;

	/** Private per-install (or per-process) key for the keyed placeholder digest. */
	readonly #key: string;

	constructor(entries: SecretEntry[], key: string = defaultPlaceholderKey()) {
		this.#key = key;
		// The keyed-hash key makes obfuscate-mode placeholder bases un-dictionaryable,
		// but it can be persisted in a user-readable file (`secret-placeholder.key`).
		// A prompt-injected tool read (read/bash) could otherwise surface it to the
		// provider verbatim and undo that protection, so redact the key itself from
		// obfuscated (provider-visible) output as a one-way secret.
		this.#replaceMappings.set(key, generateDeterministicReplacement(key));
		let index = 0;
		for (const entry of entries) {
			const mode = entry.mode ?? "obfuscate";

			if (entry.type === "plain") {
				if (mode === "obfuscate") {
					const placeholder = this.#createPlaceholder(entry.content, entry.friendlyName);
					this.#registerDeobfuscationAlias(buildLegacyPlaceholder(index), entry.content, false);
					this.#plainMappings.set(entry.content, index);
					this.#obfuscateMappings.set(index, { secret: entry.content, placeholder });
					index++;
				} else {
					// replace mode
					const replacement = entry.replacement ?? generateDeterministicReplacement(entry.content);
					this.#replaceMappings.set(entry.content, replacement);
				}
			} else {
				// regex type — compiled here, matches discovered during obfuscate()
				try {
					const regex = compileSecretRegex(entry.content, entry.flags);
					this.#regexEntries.push({
						regex,
						mode,
						replacement: entry.replacement,
						friendlyName: entry.friendlyName,
					});
				} catch {
					// Invalid regex — skip silently (validation happens at load time)
				}
			}
		}

		this.#nextIndex = index;
		this.#hasAny = entries.length > 0;
	}

	hasSecrets(): boolean {
		return this.#hasAny;
	}

	/** Obfuscate all secrets in text. Bidirectional placeholders for obfuscate mode, one-way for replace. */
	obfuscate(text: string): string {
		if (!this.#hasAny) return text;
		let result = text;

		// 1. Process replace-mode plain secrets
		for (const [secret, replacement] of [...this.#replaceMappings].sort((a, b) => b[0].length - a[0].length)) {
			result = this.#replaceAllOutsideKnownPlaceholders(result, secret, replacement);
		}

		// 2. Process obfuscate-mode plain secrets
		for (const [secret, index] of [...this.#plainMappings].sort((a, b) => b[0].length - a[0].length)) {
			const mapping = this.#obfuscateMappings.get(index)!;
			result = this.#replaceAllOutsideKnownPlaceholders(result, secret, mapping.placeholder);
		}

		// 3. Process regex entries — discover new matches
		for (const entry of this.#regexEntries) {
			entry.regex.lastIndex = 0;
			const matches = this.#collectRegexMatches(result, entry.regex);

			for (const match of matches) {
				if (entry.mode === "replace") {
					const replacement = entry.replacement ?? generateDeterministicReplacement(match.value);
					result = replaceRange(result, match.start, match.end, replacement);
				} else {
					// obfuscate mode — get or create stable index
					let index = this.#findObfuscateIndex(match.value);
					if (index === undefined) {
						index = this.#nextIndex++;
						const placeholder = this.#createPlaceholder(match.value, entry.friendlyName, true);
						this.#obfuscateMappings.set(index, { secret: match.value, placeholder });
					}
					const mapping = this.#obfuscateMappings.get(index)!;
					result = replaceRange(result, match.start, match.end, mapping.placeholder);
				}
			}
		}

		return result;
	}

	/** Deobfuscate obfuscate-mode placeholders back to original secrets. Replace-mode is NOT reversed. */
	deobfuscate(text: string): string {
		if (!this.#hasAny || !text.includes("#")) return text;
		let result = text;
		for (;;) {
			let shouldContinue = false;
			const next = result.replace(PLACEHOLDER_RE, match => {
				const direct = this.#deobfuscateMap.get(match);
				if (direct !== undefined) {
					shouldContinue ||= direct.recursive;
					return direct.secret;
				}
				const unprefixed = placeholderWithoutFriendlyName(match);
				if (unprefixed) {
					const mapped = this.#deobfuscateMap.get(unprefixed);
					if (mapped !== undefined) {
						shouldContinue ||= mapped.recursive;
						return mapped.secret;
					}
				}
				return match;
			});
			if (next === result || !shouldContinue || !next.includes("#")) return next;
			result = next;
		}
	}

	/** Deep-walk an object, deobfuscating all string values. */
	deobfuscateObject<T>(obj: T): T {
		if (!this.#hasAny) return obj;
		return deepWalkStrings(obj, s => this.deobfuscate(s));
	}

	/** Deep-walk an object, obfuscating all string values. */
	obfuscateObject<T>(obj: T): T {
		if (!this.#hasAny) return obj;
		return deepWalkStrings(obj, s => this.obfuscate(s));
	}

	/** Find the obfuscate index for a known secret value. */
	#findObfuscateIndex(secret: string): number | undefined {
		// Check plain mappings first
		const plainIndex = this.#plainMappings.get(secret);
		if (plainIndex !== undefined) return plainIndex;

		// Check regex-discovered mappings
		for (const [index, mapping] of this.#obfuscateMappings) {
			if (mapping.secret === secret) return index;
		}
		return undefined;
	}

	#createPlaceholder(secret: string, friendlyName?: string, recursive: boolean = false): string {
		const hint = inferCaseHint(secret);
		// `:M` does not encode the exact case pattern, so two distinct mixed-case
		// values can share a case-folded base + hint. Key those on the exact value
		// so each token stays stable per value regardless of config/env ordering.
		// U/L/C/none reconstruct casing from the hint, so they safely share the
		// case-folded base across casing variants.
		const baseKey = hint === "M" ? secret : normalizePlaceholderSecret(secret);
		const sanitizedFriendlyName = friendlyName ? sanitizeSecretFriendlyName(friendlyName) : undefined;
		const preferredBase = this.#resolvePreferredPlaceholderBase(baseKey);
		const preferredPlaceholder = buildPlaceholder(hint, preferredBase, sanitizedFriendlyName);
		if (!this.#placeholderConflicts(preferredPlaceholder, secret)) {
			this.#registerDeobfuscationAlias(preferredPlaceholder, secret, recursive);
			return preferredPlaceholder;
		}

		for (let attempt = 1; ; attempt++) {
			const fallbackBase = this.#reserveFallbackPlaceholderBase(baseKey, attempt);
			const placeholder = buildPlaceholder(hint, fallbackBase, sanitizedFriendlyName);
			if (!this.#placeholderConflicts(placeholder, secret)) {
				this.#registerDeobfuscationAlias(placeholder, secret, recursive);
				return placeholder;
			}
		}
	}

	#resolvePreferredPlaceholderBase(baseKey: string): string {
		const existing = this.#placeholderBaseByKey.get(baseKey);
		if (existing !== undefined) return existing;

		for (let attempt = 0; ; attempt++) {
			const base =
				attempt === 0 ? buildHashBase(this.#key, baseKey) : buildHashBase(this.#key, `${baseKey}\0${attempt}`);
			const owner = this.#placeholderBaseOwners.get(base);
			if (owner !== undefined && owner !== baseKey) continue;
			this.#placeholderBaseOwners.set(base, baseKey);
			this.#placeholderBaseByKey.set(baseKey, base);
			return base;
		}
	}

	#reserveFallbackPlaceholderBase(baseKey: string, startAttempt: number): string {
		for (let attempt = startAttempt; ; attempt++) {
			const owner = `${baseKey}\0collision\0${attempt}`;
			const base = buildHashBase(this.#key, `${baseKey}\0collision\0${attempt}`);
			if (this.#placeholderBaseOwners.has(base)) continue;
			this.#placeholderBaseOwners.set(base, owner);
			return base;
		}
	}

	#placeholderCollides(placeholder: string, secret: string): boolean {
		const existing = this.#deobfuscateMap.get(placeholder);
		return existing !== undefined && existing.secret !== secret;
	}

	// A friendly placeholder is only safe if BOTH its full token and its
	// friendly-name-independent alias are free (or already ours). Otherwise a
	// later prefix-stripping deobfuscation of a renamed/removed friendly name
	// would resolve the shared alias to the wrong same-base/same-hint secret.
	#placeholderConflicts(placeholder: string, secret: string): boolean {
		if (this.#placeholderCollides(placeholder, secret)) return true;
		const unprefixed = placeholderWithoutFriendlyName(placeholder);
		return unprefixed !== undefined && this.#placeholderCollides(unprefixed, secret);
	}

	#registerDeobfuscationAlias(placeholder: string, secret: string, recursive: boolean): void {
		const existing = this.#deobfuscateMap.get(placeholder);
		if (existing === undefined || existing.secret === secret) {
			this.#deobfuscateMap.set(placeholder, { secret, recursive });
		}
		const unprefixed = placeholderWithoutFriendlyName(placeholder);
		if (unprefixed !== undefined) {
			const existingUnprefixed = this.#deobfuscateMap.get(unprefixed);
			if (existingUnprefixed === undefined || existingUnprefixed.secret === secret) {
				this.#deobfuscateMap.set(unprefixed, { secret, recursive });
			}
		}
	}

	#isKnownPlaceholder(placeholder: string): boolean {
		if (this.#deobfuscateMap.has(placeholder)) return true;
		const unprefixed = placeholderWithoutFriendlyName(placeholder);
		return unprefixed !== undefined && this.#deobfuscateMap.has(unprefixed);
	}

	#replaceAllOutsideKnownPlaceholders(text: string, search: string, replacement: string): string {
		return transformOutsidePlaceholders(
			text,
			placeholder => this.#isKnownPlaceholder(placeholder),
			chunk => replaceAll(chunk, search, replacement),
		);
	}

	#knownPlaceholderRanges(text: string): Array<{ start: number; end: number }> {
		PLACEHOLDER_RE.lastIndex = 0;
		const ranges: Array<{ start: number; end: number }> = [];
		for (;;) {
			const match = PLACEHOLDER_RE.exec(text);
			if (match === null) break;
			if (this.#isKnownPlaceholder(match[0])) {
				ranges.push({ start: match.index, end: match.index + match[0].length });
			}
		}
		return ranges;
	}

	#collectRegexMatches(text: string, regex: RegExp): Array<{ start: number; end: number; value: string }> {
		const knownPlaceholderRanges = this.#knownPlaceholderRanges(text);
		const scanText = maskKnownPlaceholders(text, placeholder => this.#isKnownPlaceholder(placeholder));
		regex.lastIndex = 0;
		const matches: Array<{ start: number; end: number; value: string }> = [];
		for (;;) {
			const match = regex.exec(scanText);
			if (match === null) break;
			if (match[0].length === 0) {
				regex.lastIndex++;
				continue;
			}
			const start = match.index;
			const end = match.index + match[0].length;
			if (knownPlaceholderRanges.some(range => start >= range.start && end <= range.end)) {
				continue;
			}
			matches.push({
				start,
				end,
				value: text.slice(start, end),
			});
		}
		return matches.reverse();
	}
}

export function deobfuscateSessionContext(
	sessionContext: SessionContext,
	obfuscator: SecretObfuscator | undefined,
): SessionContext {
	if (!obfuscator?.hasSecrets()) return sessionContext;
	const messages = obfuscator.deobfuscateObject(sessionContext.messages);
	return messages === sessionContext.messages ? sessionContext : { ...sessionContext, messages };
}

// ═══════════════════════════════════════════════════════════════════════════
// Message obfuscation (outbound to LLM)
// ═══════════════════════════════════════════════════════════════════════════

/** Obfuscate all string content in LLM messages (for outbound interception). */
export function obfuscateMessages(obfuscator: SecretObfuscator, messages: Message[]): Message[] {
	return obfuscator.obfuscateObject(messages);
}

/** Obfuscate provider request context without walking live tool schema instances. */
export function obfuscateProviderContext(obfuscator: SecretObfuscator | undefined, context: Context): Context {
	if (!obfuscator?.hasSecrets()) return context;
	return {
		...context,
		systemPrompt: obfuscator.obfuscateObject(context.systemPrompt),
		messages: obfuscator.obfuscateObject(context.messages),
		tools: obfuscateProviderTools(obfuscator, context.tools),
	};
}

/** Convert tool schemas to wire JSON Schema before obfuscating provider-visible strings. */
export function obfuscateProviderTools(
	obfuscator: SecretObfuscator | undefined,
	tools: Tool[] | undefined,
): Tool[] | undefined {
	if (!tools || !obfuscator?.hasSecrets()) return tools;
	return tools.map(tool => ({
		...tool,
		description: obfuscator.obfuscate(tool.description),
		parameters: obfuscator.obfuscateObject(toolWireSchema(tool)),
		customFormat: tool.customFormat ? obfuscator.obfuscateObject(tool.customFormat) : undefined,
	}));
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

/** Replace all occurrences of `search` in `text` with `replacement`. */
function replaceAll(text: string, search: string, replacement: string): string {
	if (search.length === 0) return text;
	let result = text;
	let idx = result.indexOf(search);
	while (idx !== -1) {
		result = result.slice(0, idx) + replacement + result.slice(idx + search.length);
		idx = result.indexOf(search, idx + replacement.length);
	}
	return result;
}

function transformOutsidePlaceholders(
	text: string,
	shouldSkipPlaceholder: (placeholder: string) => boolean,
	transform: (chunk: string) => string,
	preservePlaceholder?: (placeholder: string) => string,
): string {
	PLACEHOLDER_RE.lastIndex = 0;
	let result = "";
	let pendingIndex = 0;
	for (;;) {
		const match = PLACEHOLDER_RE.exec(text);
		if (match === null) break;
		if (!shouldSkipPlaceholder(match[0])) continue;
		result += transform(text.slice(pendingIndex, match.index));
		result += preservePlaceholder ? preservePlaceholder(match[0]) : match[0];
		pendingIndex = match.index + match[0].length;
	}
	result += transform(text.slice(pendingIndex));
	return result;
}

function maskKnownPlaceholders(text: string, shouldMaskPlaceholder: (placeholder: string) => boolean): string {
	return transformOutsidePlaceholders(
		text,
		shouldMaskPlaceholder,
		chunk => chunk,
		placeholder => "P".repeat(placeholder.length),
	);
}

function replaceRange(text: string, start: number, end: number, replacement: string): string {
	return text.slice(0, start) + replacement + text.slice(end);
}

/** Deep-walk an object, transforming all string values. */
function deepWalkStrings<T>(obj: T, transform: (s: string) => string): T {
	if (typeof obj === "string") {
		return transform(obj) as unknown as T;
	}
	if (Array.isArray(obj)) {
		let changed = false;
		const result = obj.map(item => {
			const transformed = deepWalkStrings(item, transform);
			if (transformed !== item) changed = true;
			return transformed;
		});
		return (changed ? result : obj) as unknown as T;
	}
	if (obj !== null && typeof obj === "object" && isPlainRecord(obj)) {
		let changed = false;
		const result: Record<string, unknown> = {};
		for (const key of Object.keys(obj)) {
			const value = (obj as Record<string, unknown>)[key];
			const transformed = deepWalkStrings(value, transform);
			if (transformed !== value) changed = true;
			result[key] = transformed;
		}
		return (changed ? result : obj) as T;
	}
	return obj;
}

function isPlainRecord(obj: object): obj is Record<string, unknown> {
	const prototype = Object.getPrototypeOf(obj);
	return prototype === Object.prototype || prototype === null;
}
