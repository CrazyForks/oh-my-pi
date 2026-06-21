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

interface RegexScanSegment {
	scanStart: number;
	scanEnd: number;
	textStart: number;
	textEnd: number;
	generatedPlaceholder: boolean;
	recursive: boolean;
}

interface ReplaceRegexScan {
	text: string;
	segments: RegexScanSegment[];
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

	/** Reverse lookup for LIVE deobfuscation (provider output, tool-call args):
	 *  keyed placeholder → secret plus recursion policy. Only placeholders this
	 *  obfuscator generated under the per-install key (and their friendly-name-
	 *  independent aliases) live here, so a prompt-injected model cannot synthesize
	 *  one without the key. */
	#deobfuscateMap = new Map<string, { secret: string; recursive: boolean }>();

	/** Legacy index-derived aliases (unkeyed `#XRRS#`), honored ONLY when replaying
	 *  stored session content. They are deterministic and trivially guessable, so
	 *  accepting them on live provider/tool-call paths would let a prompt-injected
	 *  model synthesize one to exfiltrate a secret; they exist solely so sessions
	 *  persisted before keyed placeholders still deobfuscate on resume/display. */
	#legacyDeobfuscateMap = new Map<string, { secret: string; recursive: boolean }>();

	/** Exact placeholder tokens generated by this obfuscator revision (no aliases). */
	#generatedPlaceholders = new Set<string>();

	/** Deterministic replace chunks emitted by this obfuscator, used to keep re-obfuscation idempotent. */
	#generatedReplaceChunks = new Set<string>();

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
		this.#replaceMappings.set(key, this.#generateReplacement(key));
		let index = 0;
		for (const entry of entries) {
			const mode = entry.mode ?? "obfuscate";

			if (entry.type === "plain") {
				if (mode === "obfuscate") {
					const placeholder = this.#createPlaceholder(entry.content, entry.friendlyName);
					this.#legacyDeobfuscateMap.set(buildLegacyPlaceholder(index), {
						secret: entry.content,
						recursive: false,
					});
					this.#plainMappings.set(entry.content, index);
					this.#obfuscateMappings.set(index, { secret: entry.content, placeholder });
					this.#generatedPlaceholders.add(placeholder);
					index++;
				} else {
					// replace mode
					const replacement = entry.replacement ?? this.#generateReplacement(entry.content);
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
		// `origin` runs parallel to `result` (one tag char per result char): "I" for
		// bytes carried from the INPUT (placeholders from a PRIOR obfuscate() call)
		// and "F" for bytes this call freshly inserted. The SDK obfuscates messages
		// in both convertToLlm and transformProviderContext, and prior-turn messages
		// re-enter every turn, so obfuscate() must be a fixed point: a regex must not
		// re-redact around a placeholder that arrived in the input (which would
		// corrupt a prior replacement marker, e.g. REDACTED -> REDACTEDDACTED).
		// Tracking by RANGE (not token value) keeps a fresh placeholder that happens
		// to equal a prior one (same secret seen raw again) eligible for cross-match.
		let origin = "I".repeat(text.length);

		// 1. Process replace-mode plain secrets
		for (const [secret, replacement] of [...this.#replaceMappings].sort((a, b) => b[0].length - a[0].length)) {
			({ text: result, origin } = this.#replaceOutsidePlaceholdersTracked(result, origin, secret, replacement, "I"));
		}

		// 2. Process obfuscate-mode plain secrets
		for (const [secret, index] of [...this.#plainMappings].sort((a, b) => b[0].length - a[0].length)) {
			const mapping = this.#obfuscateMappings.get(index)!;
			({ text: result, origin } = this.#replaceOutsidePlaceholdersTracked(
				result,
				origin,
				secret,
				mapping.placeholder,
				"F",
			));
		}

		// 3. Process regex entries — discover new matches
		for (const entry of this.#regexEntries) {
			entry.regex.lastIndex = 0;
			const matches = this.#collectRegexMatches(result, entry.regex, entry.mode, origin, entry.replacement);

			for (const match of matches) {
				if (entry.mode === "replace") {
					if (match.preserveGeneratedPlaceholders) {
						if (
							match.preserveInputPlaceholders &&
							entry.replacement === undefined &&
							match.inputPlaceholderOutsideChunkCount === 1 &&
							this.#generatedReplaceChunks.has(match.inputPlaceholderOutside)
						) {
							continue;
						}
						const span = result.slice(match.start, match.end);
						// A custom replacement is a single redaction marker for the whole
						// match, so emit it once around the preserved placeholder rather
						// than per surrounding chunk (which duplicates it, e.g.
						// `api_key=***#…#api_key=***`). Without one, each surrounding chunk
						// gets its own length-matched deterministic scramble.
						const redacted =
							entry.replacement !== undefined
								? redactWithFixedReplacementOutsidePlaceholders(span, entry.replacement, placeholder =>
										this.#isGeneratedPlaceholder(placeholder),
									)
								: redactOutsideGeneratedPlaceholders(
										span,
										chunk => this.#generateReplacement(chunk),
										placeholder => this.#isGeneratedPlaceholder(placeholder),
									);
						result = replaceRange(result, match.start, match.end, redacted);
						origin = replaceRange(origin, match.start, match.end, "I".repeat(redacted.length));
					} else {
						const replacement = entry.replacement ?? this.#generateReplacement(match.value);
						result = replaceRange(result, match.start, match.end, replacement);
						origin = replaceRange(origin, match.start, match.end, "I".repeat(replacement.length));
					}
				} else {
					if (match.preserveInputPlaceholders) {
						const span = result.slice(match.start, match.end);
						const spanOrigin = origin.slice(match.start, match.end);
						const obfuscated = this.#obfuscateOutsidePlaceholdersTracked(span, spanOrigin, entry.friendlyName);
						result = replaceRange(result, match.start, match.end, obfuscated.text);
						origin = replaceRange(origin, match.start, match.end, obfuscated.origin);
						continue;
					}
					// obfuscate mode — get or create stable index
					let index = this.#findObfuscateIndex(match.canonicalValue);
					if (index === undefined) {
						index = this.#nextIndex++;
						const placeholder = this.#createPlaceholder(
							match.canonicalValue,
							entry.friendlyName,
							match.recursive,
						);
						this.#obfuscateMappings.set(index, { secret: match.canonicalValue, placeholder });
						this.#generatedPlaceholders.add(placeholder);
					}
					const mapping = this.#obfuscateMappings.get(index)!;
					result = replaceRange(result, match.start, match.end, mapping.placeholder);
					origin = replaceRange(origin, match.start, match.end, "F".repeat(mapping.placeholder.length));
				}
			}
		}

		return result;
	}

	/**
	 * Deobfuscate keyed placeholders back to original secrets for LIVE paths
	 * (provider output, tool-call arguments). Replace-mode is NOT reversed, and
	 * legacy index-derived aliases are intentionally ignored so a prompt-injected
	 * model cannot synthesize one to recover a secret.
	 */
	deobfuscate(text: string): string {
		return this.#deobfuscate(text, false);
	}

	/**
	 * Deobfuscate stored session content for replay/display. Identical to
	 * {@link deobfuscate} but additionally honors legacy index-derived aliases so
	 * sessions persisted before keyed placeholders still resume correctly. Use
	 * only for trusted on-disk session content, never for live model output.
	 */
	deobfuscateStored(text: string): string {
		return this.#deobfuscate(text, true);
	}

	#deobfuscate(text: string, allowLegacy: boolean): string {
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
				if (allowLegacy) {
					const legacy = this.#legacyDeobfuscateMap.get(match);
					if (legacy !== undefined) {
						shouldContinue ||= legacy.recursive;
						return legacy.secret;
					}
				}
				return match;
			});
			if (next === result || !shouldContinue || !next.includes("#")) return next;
			result = next;
		}
	}

	/** Deep-walk an object, deobfuscating string values for LIVE paths (keyed placeholders only). */
	deobfuscateObject<T>(obj: T): T {
		if (!this.#hasAny) return obj;
		return deepWalkStrings(obj, s => this.deobfuscate(s));
	}

	/** Deep-walk stored session content, deobfuscating string values incl. legacy aliases. */
	deobfuscateStoredObject<T>(obj: T): T {
		if (!this.#hasAny) return obj;
		return deepWalkStrings(obj, s => this.deobfuscateStored(s));
	}

	/** Deep-walk an object, obfuscating all string values. */
	obfuscateObject<T>(obj: T): T {
		if (!this.#hasAny) return obj;
		return deepWalkStrings(obj, s => this.obfuscate(s));
	}

	#generateReplacement(secret: string): string {
		const replacement = generateDeterministicReplacement(secret);
		this.#generatedReplaceChunks.add(replacement);
		return replacement;
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
		// Key the base on the EXACT secret value, never a case-folded form. The
		// case hint is only a model-visible label. If two distinct secrets that
		// differ solely by ASCII case shared one case-folded base, a provider that
		// saw one placeholder could swap the hint to synthesize the sibling
		// secret's keyed token, and live deobfuscation (provider output / tool-call
		// args) would restore a value that was never provider-visible. Exact-value
		// keying gives every secret an independent base, so a sibling token cannot
		// be derived without the per-install key.
		const baseKey = secret;
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

	#isGeneratedPlaceholder(placeholder: string): boolean {
		return this.#generatedPlaceholders.has(placeholder);
	}

	// Replace `search` with `replacement` outside known generated placeholders while
	// maintaining a parallel `origin` tag string (one char per result char): kept
	// bytes keep their tag, inserted `replacement` bytes get `tag`, and preserved
	// placeholder spans keep their original tags. Lets later passes tell prior-call
	// placeholders ("I") from ones freshly inserted this call ("F") by RANGE.
	#replaceOutsidePlaceholdersTracked(
		text: string,
		origin: string,
		search: string,
		replacement: string,
		tag: string,
	): { text: string; origin: string } {
		if (search.length === 0) return { text, origin };
		PLACEHOLDER_RE.lastIndex = 0;
		let outText = "";
		let outOrigin = "";
		let pending = 0;
		const emitChunk = (from: number, to: number): void => {
			let last = from;
			let idx = text.indexOf(search, from);
			while (idx !== -1 && idx + search.length <= to) {
				outText += text.slice(last, idx) + replacement;
				outOrigin += origin.slice(last, idx) + tag.repeat(replacement.length);
				last = idx + search.length;
				idx = text.indexOf(search, last);
			}
			outText += text.slice(last, to);
			outOrigin += origin.slice(last, to);
		};
		for (;;) {
			const match = PLACEHOLDER_RE.exec(text);
			if (match === null) break;
			if (!(this.#isGeneratedPlaceholder(match[0]) && match[0] !== search)) continue;
			emitChunk(pending, match.index);
			outText += match[0];
			outOrigin += origin.slice(match.index, match.index + match[0].length);
			pending = match.index + match[0].length;
		}
		emitChunk(pending, text.length);
		return { text: outText, origin: outOrigin };
	}

	#placeholderForRegexChunk(secret: string, friendlyName: string | undefined): string {
		let index = this.#findObfuscateIndex(secret);
		if (index === undefined) {
			index = this.#nextIndex++;
			const placeholder = this.#createPlaceholder(secret, friendlyName);
			this.#obfuscateMappings.set(index, { secret, placeholder });
			this.#generatedPlaceholders.add(placeholder);
		}
		return this.#obfuscateMappings.get(index)!.placeholder;
	}

	#obfuscateOutsidePlaceholdersTracked(
		text: string,
		origin: string,
		friendlyName: string | undefined,
	): { text: string; origin: string } {
		PLACEHOLDER_RE.lastIndex = 0;
		let outText = "";
		let outOrigin = "";
		let pending = 0;
		const emitChunk = (from: number, to: number): void => {
			if (from >= to) return;
			const placeholder = this.#placeholderForRegexChunk(text.slice(from, to), friendlyName);
			outText += placeholder;
			outOrigin += "F".repeat(placeholder.length);
		};
		for (;;) {
			const match = PLACEHOLDER_RE.exec(text);
			if (match === null) break;
			if (!this.#isGeneratedPlaceholder(match[0])) continue;
			emitChunk(pending, match.index);
			outText += match[0];
			outOrigin += origin.slice(match.index, match.index + match[0].length);
			pending = match.index + match[0].length;
		}
		emitChunk(pending, text.length);
		return { text: outText, origin: outOrigin };
	}

	#knownPlaceholderRanges(text: string): Array<{ start: number; end: number }> {
		PLACEHOLDER_RE.lastIndex = 0;
		const ranges: Array<{ start: number; end: number }> = [];
		for (;;) {
			const match = PLACEHOLDER_RE.exec(text);
			if (match === null) break;
			if (this.#isGeneratedPlaceholder(match[0])) {
				ranges.push({ start: match.index, end: match.index + match[0].length });
			}
		}
		return ranges;
	}

	#collectRegexMatches(
		text: string,
		regex: RegExp,
		mode: "obfuscate" | "replace",
		origin: string,
		replacement: string | undefined,
	): Array<{
		start: number;
		end: number;
		value: string;
		canonicalValue: string;
		recursive: boolean;
		preserveGeneratedPlaceholders: boolean;
		preserveInputPlaceholders: boolean;
		inputPlaceholderOutside: string;
		inputPlaceholderOutsideIndependentlyMatches: boolean;
		inputPlaceholderOutsideStart: number;
		inputPlaceholderOutsideChunkCount: number;
	}> {
		const knownPlaceholderRanges = this.#knownPlaceholderRanges(text);
		const regexScan = buildReplaceRegexScan(text, knownPlaceholderRanges, this.#deobfuscateMap);
		const scanText = regexScan.text;
		regex.lastIndex = 0;
		const matches: Array<{
			start: number;
			end: number;
			value: string;
			canonicalValue: string;
			recursive: boolean;
			preserveGeneratedPlaceholders: boolean;
			preserveInputPlaceholders: boolean;
			inputPlaceholderOutside: string;
			inputPlaceholderOutsideIndependentlyMatches: boolean;
			inputPlaceholderOutsideStart: number;
			inputPlaceholderOutsideChunkCount: number;
		}> = [];
		for (;;) {
			const match = regex.exec(scanText);
			if (match === null) break;
			if (match[0].length === 0) {
				regex.lastIndex++;
				continue;
			}
			let start = match.index;
			let end = match.index + match[0].length;
			let canonicalValue = "";
			let recursive = false;
			let preserveGeneratedPlaceholders = false;
			let preserveInputPlaceholders = false;
			let inputPlaceholderOutside = "";
			let inputPlaceholderOutsideIndependentlyMatches = false;
			let inputPlaceholderOutsideStart = -1;
			let inputPlaceholderOutsideChunkCount = 0;

			const mapped = mapReplaceRegexMatch(regexScan.segments, start, end);
			start = mapped.start;
			end = mapped.end;
			preserveGeneratedPlaceholders = mapped.preserveGeneratedPlaceholders;
			// A match overlapping a placeholder that arrived in the INPUT (origin tag
			// "I" — generated by a PRIOR obfuscate() call) must preserve that
			// placeholder atomically so repeated obfuscation stays a fixed point. If
			// raw bytes surround it, they still need redaction; branch-specific
			// replacement below keeps prior placeholders while covering the
			// non-placeholder chunks.
			const overlapsInputPlaceholder = knownPlaceholderRanges.some(
				range => start < range.end && end > range.start && origin[range.start] === "I",
			);
			preserveInputPlaceholders = overlapsInputPlaceholder;
			if (overlapsInputPlaceholder) {
				const firstOutside = firstOutsidePlaceholderRange(start, end, knownPlaceholderRanges);
				if (
					mode === "replace" &&
					replacement !== undefined &&
					firstOutside !== undefined &&
					text.slice(firstOutside.start, firstOutside.start + replacement.length) === replacement
				) {
					const expandedEnd = firstOutside.start + replacement.length;
					if (expandedEnd > end) {
						regex.lastIndex = Math.max(regex.lastIndex, match.index + match[0].length + expandedEnd - end);
						end = expandedEnd;
					}
				}
				inputPlaceholderOutside = textOutsidePlaceholderRanges(text, start, end, knownPlaceholderRanges);
				inputPlaceholderOutsideStart =
					firstOutsidePlaceholderRange(start, end, knownPlaceholderRanges)?.start ?? -1;
				inputPlaceholderOutsideChunkCount = countOutsidePlaceholderRanges(start, end, knownPlaceholderRanges);
				if (inputPlaceholderOutside.length === 0) continue;
				const resumeIndex = regex.lastIndex;
				regex.lastIndex = 0;
				inputPlaceholderOutsideIndependentlyMatches = regex.test(inputPlaceholderOutside);
				regex.lastIndex = resumeIndex;
			}
			if (mode === "replace") {
				canonicalValue = match[0];
				recursive = mapped.recursive;
			} else {
				const overlappingRanges = knownPlaceholderRanges.filter(range => start < range.end && end > range.start);
				const containedByPlaceholder = overlappingRanges.some(range => start >= range.start && end <= range.end);
				if (containedByPlaceholder) {
					continue;
				}
				const canonical = deobfuscateGeneratedPlaceholderRanges(
					text,
					start,
					end,
					knownPlaceholderRanges,
					this.#deobfuscateMap,
				);
				canonicalValue = canonical.text;
				recursive = canonical.recursive;
			}

			matches.push({
				start,
				end,
				value: text.slice(start, end),
				canonicalValue,
				recursive,
				preserveGeneratedPlaceholders,
				preserveInputPlaceholders,
				inputPlaceholderOutside,
				inputPlaceholderOutsideIndependentlyMatches,
				inputPlaceholderOutsideStart,
				inputPlaceholderOutsideChunkCount,
			});
		}
		return matches.reverse();
	}
}

export function deobfuscateSessionContext(
	sessionContext: SessionContext,
	obfuscator: SecretObfuscator | undefined,
	allowLegacyAliases = false,
): SessionContext {
	if (!obfuscator?.hasSecrets()) return sessionContext;
	// Legacy index-derived aliases (`#XXXX#`) are unkeyed and trivially guessable,
	// so a prompt-injected model can plant one in ANY stored record it influences
	// (its own assistant output, or tool results such as bash stdout). On a later
	// resume/rebuild this would be restored to the raw secret and then re-obfuscated
	// into a valid keyed placeholder the model can weaponize in a tool argument.
	// Every agent-feeding path (resume, history rewrite, branch switch) therefore
	// deobfuscates keyed placeholders ONLY, leaving any legacy token inert. Legacy
	// aliases are restored solely for display-only transcripts that are never
	// re-obfuscated or sent to a provider (`buildTranscriptSessionContext`).
	const messages = allowLegacyAliases
		? obfuscator.deobfuscateStoredObject(sessionContext.messages)
		: obfuscator.deobfuscateObject(sessionContext.messages);
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

function buildReplaceRegexScan(
	text: string,
	ranges: ReadonlyArray<{ start: number; end: number }>,
	deobfuscateMap: ReadonlyMap<string, { secret: string; recursive: boolean }>,
): ReplaceRegexScan {
	let scanText = "";
	let cursor = 0;
	const segments: RegexScanSegment[] = [];
	const appendSegment = (
		value: string,
		textStart: number,
		textEnd: number,
		generatedPlaceholder: boolean,
		recursive: boolean,
	) => {
		if (value.length === 0) return;
		const scanStart = scanText.length;
		scanText += value;
		segments.push({
			scanStart,
			scanEnd: scanStart + value.length,
			textStart,
			textEnd,
			generatedPlaceholder,
			recursive,
		});
	};

	for (const range of ranges) {
		appendSegment(text.slice(cursor, range.start), cursor, range.start, false, false);
		const placeholder = text.slice(range.start, range.end);
		const mapping = deobfuscateMap.get(placeholder);
		appendSegment(mapping?.secret ?? placeholder, range.start, range.end, true, mapping?.recursive ?? false);
		cursor = range.end;
	}
	appendSegment(text.slice(cursor), cursor, text.length, false, false);

	return { text: scanText, segments };
}

function mapReplaceRegexMatch(
	segments: ReadonlyArray<RegexScanSegment>,
	scanStart: number,
	scanEnd: number,
): { start: number; end: number; recursive: boolean; preserveGeneratedPlaceholders: boolean } {
	const startSegment = findScanSegment(segments, scanStart);
	const endSegment = findScanSegment(segments, scanEnd - 1);
	const start = startSegment.generatedPlaceholder
		? startSegment.textStart
		: startSegment.textStart + (scanStart - startSegment.scanStart);
	const end = endSegment.generatedPlaceholder
		? endSegment.textEnd
		: endSegment.textStart + (scanEnd - endSegment.scanStart);
	let recursive = false;
	let preserveGeneratedPlaceholders = false;
	for (const segment of segments) {
		if (segment.scanStart >= scanEnd || segment.scanEnd <= scanStart) continue;
		recursive ||= segment.recursive;
		preserveGeneratedPlaceholders ||= segment.generatedPlaceholder;
	}
	return { start, end, recursive, preserveGeneratedPlaceholders };
}

function findScanSegment(segments: ReadonlyArray<RegexScanSegment>, scanIndex: number): RegexScanSegment {
	for (const segment of segments) {
		if (scanIndex >= segment.scanStart && scanIndex < segment.scanEnd) return segment;
	}
	throw new Error("regex match did not map to source text");
}

function redactOutsideGeneratedPlaceholders(
	text: string,
	replacementForChunk: (chunk: string) => string,
	shouldPreservePlaceholder: (placeholder: string) => boolean,
): string {
	return transformOutsidePlaceholders(
		text,
		shouldPreservePlaceholder,
		chunk => (chunk.length === 0 ? "" : replacementForChunk(chunk)),
		placeholder => placeholder,
	);
}

// Apply a fixed custom replacement ONCE across a matched span while preserving
// any inner generated placeholders. The replacement is the user's single
// redaction marker for the whole match, so reusing it per surrounding chunk
// would duplicate it around the placeholder; emit it for the first non-empty
// surrounding chunk only and drop the rest (they are redacted into the one
// marker). The reversible placeholder stays intact in its relative position.
function redactWithFixedReplacementOutsidePlaceholders(
	text: string,
	replacement: string,
	shouldPreservePlaceholder: (placeholder: string) => boolean,
): string {
	let emitted = false;
	return transformOutsidePlaceholders(
		text,
		shouldPreservePlaceholder,
		chunk => {
			if (chunk.length === 0 || emitted) return "";
			emitted = true;
			return replacement;
		},
		placeholder => placeholder,
	);
}

function deobfuscateGeneratedPlaceholderRanges(
	text: string,
	start: number,
	end: number,
	ranges: ReadonlyArray<{ start: number; end: number }>,
	deobfuscateMap: ReadonlyMap<string, { secret: string; recursive: boolean }>,
): { text: string; recursive: boolean } {
	let result = "";
	let cursor = start;
	let recursive = false;
	for (const range of ranges) {
		if (range.end <= start || range.start >= end) continue;
		const overlapStart = Math.max(range.start, start);
		const overlapEnd = Math.min(range.end, end);
		result += text.slice(cursor, overlapStart);
		const placeholder = text.slice(overlapStart, overlapEnd);
		const mapping = deobfuscateMap.get(placeholder);
		result += mapping?.secret ?? placeholder;
		recursive ||= mapping?.recursive ?? false;
		cursor = overlapEnd;
	}
	result += text.slice(cursor, end);
	return { text: result, recursive };
}

// Concatenate the bytes of [start, end) that lie OUTSIDE the given (ascending,
// non-overlapping) placeholder ranges. Used to test whether a regex match that
// straddles a prior-call placeholder would still match on its surrounding bytes
// alone — i.e. those bytes are genuinely new content to redact rather than a
// match that only exists because the deobfuscated placeholder bridges them.
function textOutsidePlaceholderRanges(
	text: string,
	start: number,
	end: number,
	ranges: ReadonlyArray<{ start: number; end: number }>,
): string {
	let result = "";
	let cursor = start;
	for (const range of ranges) {
		if (range.end <= start || range.start >= end) continue;
		const overlapStart = Math.max(range.start, start);
		const overlapEnd = Math.min(range.end, end);
		result += text.slice(cursor, overlapStart);
		cursor = overlapEnd;
	}
	result += text.slice(cursor, end);
	return result;
}

function firstOutsidePlaceholderRange(
	start: number,
	end: number,
	ranges: ReadonlyArray<{ start: number; end: number }>,
): { start: number; end: number } | undefined {
	let cursor = start;
	for (const range of ranges) {
		if (range.end <= start || range.start >= end) continue;
		const overlapStart = Math.max(range.start, start);
		const overlapEnd = Math.min(range.end, end);
		if (cursor < overlapStart) return { start: cursor, end: overlapStart };
		cursor = overlapEnd;
	}
	return cursor < end ? { start: cursor, end } : undefined;
}

function countOutsidePlaceholderRanges(
	start: number,
	end: number,
	ranges: ReadonlyArray<{ start: number; end: number }>,
): number {
	let count = 0;
	let cursor = start;
	for (const range of ranges) {
		if (range.end <= start || range.start >= end) continue;
		const overlapStart = Math.max(range.start, start);
		const overlapEnd = Math.min(range.end, end);
		if (cursor < overlapStart) count++;
		cursor = overlapEnd;
	}
	if (cursor < end) count++;
	return count;
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
