import * as crypto from "node:crypto";
import type { AgentMessage } from "@oh-my-pi/pi-agent-core";
import type { AssistantMessage, Context, ImageContent, Message, TextContent } from "@oh-my-pi/pi-ai";
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

export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue | undefined };
export type JsonRecord = { [key: string]: JsonValue | undefined };

// ═══════════════════════════════════════════════════════════════════════════
// Deterministic replacement generation
// ═══════════════════════════════════════════════════════════════════════════

const REPLACEMENT_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/** Generate a deterministic same-length replacement string from a secret value. */
function generateDeterministicReplacement(secret: string): string {
	if (secret.length === 0) return "";
	// Prefix generated chunks with a fixed `ZZ` so re-redacting an already-emitted
	// 1–2 char chunk is a fixed point (the deterministic replacement of a <=2-char
	// value is itself `Z`/`ZZ`), keeping short default-replacement remainders next
	// to a reversible placeholder stable across an obfuscator restart.
	const hash = BigInt(Bun.hash(secret));
	const chars = secret.length === 1 ? ["Z"] : ["Z", "Z"];
	let h = hash;
	for (let i = chars.length; i < secret.length; i++) {
		h = h ^ (BigInt(i + 1) * 0x9e3779b97f4a7c15n);
		const idx = Number((h < 0n ? -h : h) % BigInt(REPLACEMENT_CHARS.length));
		chars.push(REPLACEMENT_CHARS[idx]);
	}
	return chars.join("");
}

/**
 * Force a length-preserving deterministic replacement to differ from the secret
 * it stands in for. `generateDeterministicReplacement` seeds its first 1–2 chars
 * with the `Z`/`ZZ` sentinel, so a whole configured value that is exactly `Z` or
 * `ZZ` (or an astronomically unlikely longer hash collision) would otherwise be
 * emitted unchanged and ship the raw secret to the provider. Flip the first char
 * to a fixed different glyph: same length, still deterministic, guaranteed != the
 * secret. Only safe for a whole CONFIGURED value (a plain secret matches its own
 * literal, so the perturbed output is no longer matched and stays a fixed point);
 * per-chunk remainders must keep the sentinel to remain idempotent across restart.
 */
function ensureDistinctReplacement(replacement: string, secret: string): string {
	if (replacement.length === 0 || replacement !== secret) return replacement;
	const alt = replacement[0] === REPLACEMENT_CHARS[0] ? REPLACEMENT_CHARS[1] : REPLACEMENT_CHARS[0];
	return alt + replacement.slice(1);
}

/**
 * Search same-length replacements for one the regex does NOT match, so a default
 * regex secret whose deterministic replacement collides with its own value (the
 * `Z`/`ZZ` sentinel, or an astronomical hash collision) is still redacted to a
 * STABLE nonmatching value instead of shipping the raw secret. A nonmatching
 * candidate is a fixed point under re-obfuscation — the regex never re-matches it,
 * so it cannot re-leak on a later pass. Candidates are enumerated deterministically
 * over `REPLACEMENT_CHARS` (same value+regex always yields the same redaction); the
 * sweep is bounded so a match-everything regex (`.`/`[\s\S]`) terminates, returning
 * undefined to let the caller keep the sentinel as the only available fixed point.
 */
function findNonMatchingReplacement(value: string, regex: RegExp): string | undefined {
	const len = value.length;
	if (len === 0) return undefined;
	const base = REPLACEMENT_CHARS.length;
	// 62^2 = 3844 candidates cover every 1–2 char value (the only realistic
	// trigger) exhaustively; the cap also bounds longer astronomical collisions.
	const maxAttempts = 4096;
	const chars = new Array<string>(len);
	for (let n = 0; n < maxAttempts; n++) {
		let q = n;
		for (let i = len - 1; i >= 0; i--) {
			chars[i] = REPLACEMENT_CHARS[q % base];
			q = Math.floor(q / base);
		}
		const candidate = chars.join("");
		if (candidate === value) continue;
		regex.lastIndex = 0;
		if (!regex.test(candidate)) return candidate;
	}
	return undefined;
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
// Plain/regex obfuscate matches shorter than this are toned down (never placed
// behind a reversible placeholder) to avoid redacting small words/fragments.
export const MIN_OBFUSCATE_SECRET_LEN = 8;

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

/**
 * Whether an entry can produce a reversible (keyed) obfuscate-mode placeholder
 * and therefore requires the persisted placeholder key. Short plain obfuscate
 * entries are toned down (never placeheld), so they must NOT force key creation:
 * otherwise a `secret-placeholder.key` file is written and persisted for a config
 * that ends up with no active secrets, leaving the key readable via a tool and
 * reusable for later placeholders.
 */
export function secretEntryNeedsPlaceholderKey(entry: SecretEntry): boolean {
	if ((entry.mode ?? "obfuscate") !== "obfuscate") return false;
	if (entry.type === "regex") return true;
	return entry.content.length >= MIN_OBFUSCATE_SECRET_LEN;
}

/**
 * Whether a plain replace-mode replacement string can contribute a fragment that
 * helps the replace phase reconstruct an obfuscate `content`. During obfuscate()'s
 * replace phase the output is a tiling of passthrough bytes (adversary-controlled
 * provider text) and whole replacement outputs; any contiguous occurrence of
 * `content` in that output is covered by interior replacement tiles (each a
 * substring of `content`) bordered by passthrough at the ends, where the border
 * tile may be a suffix of a replacement (forming `content`'s prefix) or a prefix
 * of a replacement (forming `content`'s suffix). An EMPTY replacement deletes its
 * trigger entirely, joining the passthrough on both sides; with adversary-chosen
 * surrounding bytes that can form any non-empty `content` across the deleted gap.
 * So a replacement can help iff it is empty, is a substring of `content`,
 * contains `content`, or shares such a border overlap.
 */
function replacementCanFormContent(replacement: string, content: string): boolean {
	if (replacement.length === 0) return content.length > 0;
	if (content.includes(replacement) || replacement.includes(content)) return true;
	const maxOverlap = Math.min(replacement.length, content.length);
	for (let k = 1; k <= maxOverlap; k++) {
		// A suffix of the replacement forms the prefix of the content (left border),
		// or a prefix of the replacement forms the suffix of the content (right border).
		if (content.startsWith(replacement.slice(replacement.length - k)) || content.endsWith(replacement.slice(0, k))) {
			return true;
		}
	}
	return false;
}

/**
 * Whether a SET of entries needs the persisted placeholder key. `obfuscate()`
 * applies plain replace-mode mappings before the plain-obfuscate pass, so a plain
 * obfuscate entry only emits a reversible (keyed) placeholder when its content can
 * still appear AFTER the replace phase. When no obfuscate entry can ever produce a
 * placeholder, the persisted key must NOT be required/created — otherwise an
 * effectively replace-only secret set still writes `secret-placeholder.key` and
 * fails startup when the agent config dir is unwritable.
 *
 * The decision models the replace phase as the obfuscator actually runs it:
 * replace mappings are content-keyed (later duplicate wins) and applied in
 * descending content-length order; for a fresh probe (no prior placeholders) that
 * phase is plain sequential substring replacement. A plain obfuscate entry needs
 * the key when its content survives that simulated phase (direct typing) OR when
 * any effective replacement can form the content via tiling — a substring,
 * wholesale superstring, or prefix/suffix border that joins with surrounding
 * passthrough bytes (see `replacementCanFormContent`). This covers direct
 * shadowing (`SECRET -> safe`), reintroduction, duplicate ordering, transitive
 * chains, and context-joined fragments uniformly. Default (omitted) replacements
 * are deterministic, length-preserving, and distinct, so a same-content shadow
 * with no other interacting replacement stays key-free.
 */
export function secretEntriesNeedPlaceholderKey(entries: SecretEntry[]): boolean {
	const replaceMap = new Map<string, string>();
	for (const entry of entries) {
		if (entry.type !== "plain" || (entry.mode ?? "obfuscate") !== "replace") continue;
		replaceMap.set(
			entry.content,
			entry.replacement ?? ensureDistinctReplacement(generateDeterministicReplacement(entry.content), entry.content),
		);
	}
	const replacePhase = [...replaceMap].sort((a, b) => b[0].length - a[0].length);
	const replacements = [...replaceMap.values()];
	const applyReplacePhase = (text: string): string => {
		let result = text;
		for (const [secret, replacement] of replacePhase) result = result.split(secret).join(replacement);
		return result;
	};
	return entries.some(entry => {
		if (!secretEntryNeedsPlaceholderKey(entry)) return false;
		// Regex obfuscate entries match dynamically; conservatively require the key.
		if (entry.type !== "plain") return true;
		const content = entry.content;
		return (
			applyReplacePhase(content).includes(content) || replacements.some(r => replacementCanFormContent(r, content))
		);
	});
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
		this.#replaceMappings.set(key, this.#generateSecretReplacement(key));
		let index = 0;
		let hasRealSec = false;
		for (const entry of entries) {
			const mode = entry.mode ?? "obfuscate";

			if (entry.type === "plain") {
				if (mode === "obfuscate") {
					if (entry.content.length < MIN_OBFUSCATE_SECRET_LEN) {
						// Tone down short plain secret obfuscation to avoid false matches on small words like "esp"
						continue;
					}
					const placeholder = this.#createPlaceholder(entry.content, entry.friendlyName);
					this.#legacyDeobfuscateMap.set(buildLegacyPlaceholder(index), {
						secret: entry.content,
						recursive: false,
					});
					this.#plainMappings.set(entry.content, index);
					this.#obfuscateMappings.set(index, { secret: entry.content, placeholder });
					this.#generatedPlaceholders.add(placeholder);
					index++;
					hasRealSec = true;
				} else {
					// replace mode
					const replacement = entry.replacement ?? this.#generateSecretReplacement(entry.content);
					this.#replaceMappings.set(entry.content, replacement);
					hasRealSec = true;
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
					hasRealSec = true;
				} catch {
					// Invalid regex — skip silently (validation happens at load time)
				}
			}
		}

		this.#nextIndex = index;
		this.#hasAny = hasRealSec;
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
							// Preserve an outside chunk as an already-emitted redaction ONLY when this
							// obfuscator emitted it this session; a sentinel-shaped (`ZZ…`) chunk is
							// otherwise indistinguishable from raw content the user wrote, so matching it
							// by shape alone would leak raw bytes the regex covers. Redact anything unknown.
							this.#generatedReplaceChunks.has(match.inputPlaceholderOutside)
						) {
							continue;
						}
						let replaceEnd = match.end;
						let span = result.slice(match.start, replaceEnd);
						if (entry.replacement !== undefined) {
							const trailingChunk = trailingOutsidePreservedPlaceholderChunk(span, placeholder =>
								this.#isGeneratedPlaceholder(placeholder),
							);
							if (trailingChunk.length > 0 && entry.replacement.startsWith(trailingChunk)) {
								const trailingSuffix = entry.replacement.slice(trailingChunk.length);
								if (trailingSuffix.length > 0 && result.slice(replaceEnd).startsWith(trailingSuffix)) {
									replaceEnd += trailingSuffix.length;
									span = result.slice(match.start, replaceEnd);
								}
							}
						}
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
						result = replaceRange(result, match.start, replaceEnd, redacted);
						origin = replaceRange(origin, match.start, replaceEnd, "I".repeat(redacted.length));
					} else {
						const replacement = entry.replacement ?? this.#generateRegexReplacement(match.value, entry.regex);
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
					if (match.value.length < MIN_OBFUSCATE_SECRET_LEN) {
						// Tone down short regex match obfuscation to avoid false matches on small words/fragments
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

	/**
	 * Replacement for a whole CONFIGURED secret value (a plain replace-mode entry
	 * or the redacted key). Unlike a per-chunk remainder redaction, the output
	 * must differ from the input so a value equal to the `Z`/`ZZ` sentinel is not
	 * emitted verbatim. A plain secret only matches its own literal, so the
	 * perturbed output stays a fixed point under re-obfuscation.
	 */
	#generateSecretReplacement(secret: string): string {
		const replacement = ensureDistinctReplacement(generateDeterministicReplacement(secret), secret);
		this.#generatedReplaceChunks.add(replacement);
		return replacement;
	}

	/**
	 * Replacement for a default (no custom replacement) regex match. Like a plain
	 * secret, a value equal to the `Z`/`ZZ` sentinel (or an astronomical hash
	 * collision) must not ship verbatim — but unlike a plain secret a regex can
	 * re-match its own perturbed output. So when the deterministic replacement
	 * collides with the value, search same-length candidates for one the regex does
	 * NOT match: such a value is a STABLE fixed point under re-obfuscation (the regex
	 * never re-matches it) and so cannot re-leak on a later pass. A single
	 * perturbation is not enough — it may also match the regex (e.g. `B` is needed,
	 * not `A`, for `Z|A`), so the search tries further candidates before giving up.
	 * Only when no candidate avoids the regex (a pathological match-everything config
	 * such as `.`/`[\s\S]`) keep the sentinel as the sole available fixed point.
	 */
	#generateRegexReplacement(value: string, regex: RegExp): string {
		let replacement = generateDeterministicReplacement(value);
		if (replacement === value) {
			const stable = findNonMatchingReplacement(value, regex);
			if (stable !== undefined) replacement = stable;
			regex.lastIndex = 0;
		}
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

// ═══════════════════════════════════════════════════════════════════════════
// Display restore (inbound, persisted/provider → local display)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Restore secret placeholders for local display. Only message kinds the model
 * itself authored from obfuscated context carry placeholders — assistant
 * content and the LLM-written branch/compaction summaries. User, developer, and
 * tool-result messages are persisted with their literal text, so a literal
 * `#ABCD#` the operator typed must survive untouched; those roles are never
 * walked.
 *
 * Legacy index-derived aliases (`#XXXX#`) are unkeyed and trivially guessable,
 * so a prompt-injected model can plant one in any record it influences. Every
 * agent-feeding path (resume, history rewrite, branch switch) therefore restores
 * keyed placeholders ONLY (`allowLegacyAliases` false), leaving legacy tokens
 * inert; display-only transcripts that are never re-obfuscated opt in via
 * `allowLegacyAliases`.
 */
export function deobfuscateSessionContext(
	sessionContext: SessionContext,
	obfuscator: SecretObfuscator | undefined,
	allowLegacyAliases = false,
): SessionContext {
	if (!obfuscator?.hasSecrets()) return sessionContext;
	const messages = deobfuscateAgentMessages(obfuscator, sessionContext.messages, allowLegacyAliases);
	return messages === sessionContext.messages ? sessionContext : { ...sessionContext, messages };
}

export function deobfuscateAgentMessages(
	obfuscator: SecretObfuscator,
	messages: AgentMessage[],
	allowLegacyAliases = false,
): AgentMessage[] {
	const deob = (text: string): string =>
		allowLegacyAliases ? obfuscator.deobfuscateStored(text) : obfuscator.deobfuscate(text);
	let changed = false;
	const result = messages.map((message): AgentMessage => {
		switch (message.role) {
			case "assistant": {
				const content = deobfuscateAssistantContent(obfuscator, message.content, allowLegacyAliases);
				if (content === message.content) return message;
				changed = true;
				return { ...message, content };
			}
			case "branchSummary": {
				const summary = deob(message.summary);
				if (summary === message.summary) return message;
				changed = true;
				return { ...message, summary };
			}
			case "compactionSummary": {
				const summary = deob(message.summary);
				const shortSummary = message.shortSummary === undefined ? undefined : deob(message.shortSummary);
				const blocks =
					message.blocks === undefined
						? undefined
						: deobfuscateTextBlocks(obfuscator, message.blocks, allowLegacyAliases);
				if (summary === message.summary && shortSummary === message.shortSummary && blocks === message.blocks) {
					return message;
				}
				changed = true;
				return { ...message, summary, shortSummary, blocks };
			}
			default:
				return message;
		}
	});
	return changed ? result : messages;
}

/**
 * Restore placeholders in assistant content: visible text and tool-call
 * arguments/intent/rawBlock. Thinking and signatures are opaque
 * provider-replay/hidden-reasoning data and pass through byte-identical.
 */
export function deobfuscateAssistantContent(
	obfuscator: SecretObfuscator,
	content: AssistantMessage["content"],
	allowLegacyAliases = false,
): AssistantMessage["content"] {
	if (!obfuscator.hasSecrets()) return content;
	const deob = (text: string): string =>
		allowLegacyAliases ? obfuscator.deobfuscateStored(text) : obfuscator.deobfuscate(text);
	let changed = false;
	const result = content.map((block): AssistantMessage["content"][number] => {
		if (block.type === "text") {
			const text = deob(block.text);
			if (text === block.text) return block;
			changed = true;
			return { ...block, text };
		}

		if (block.type === "toolCall") {
			const args = deobfuscateToolArguments(obfuscator, block.arguments, allowLegacyAliases);
			const intent = block.intent === undefined ? undefined : deob(block.intent);
			const rawBlock = block.rawBlock === undefined ? undefined : deob(block.rawBlock);
			if (args === block.arguments && intent === block.intent && rawBlock === block.rawBlock) return block;
			changed = true;
			return { ...block, arguments: args, intent, rawBlock };
		}
		return block;
	});
	return changed ? result : content;
}

/**
 * Restore placeholders inside a tool call's arguments. Arguments are arbitrary
 * model-authored JSON, so tool-call arguments are the ONLY place a recursive
 * JSON walk runs.
 */
export function deobfuscateToolArguments(
	obfuscator: SecretObfuscator,
	args: Record<string, unknown>,
	allowLegacyAliases = false,
): Record<string, unknown> {
	if (!obfuscator.hasSecrets()) return args;
	const deob = (text: string): string =>
		allowLegacyAliases ? obfuscator.deobfuscateStored(text) : obfuscator.deobfuscate(text);
	return mapJsonStrings(args as JsonValue, deob) as Record<string, unknown>;
}

/** Redact secrets inside a tool call's arguments (same JSON-walk exception as {@link deobfuscateToolArguments}). */
export function obfuscateToolArguments(
	obfuscator: SecretObfuscator,
	args: Record<string, unknown>,
): Record<string, unknown> {
	if (!obfuscator.hasSecrets()) return args;
	return mapJsonStrings(args as JsonValue, s => obfuscator.obfuscate(s)) as Record<string, unknown>;
}

// ═══════════════════════════════════════════════════════════════════════════
// Outbound obfuscation (local → provider)
// ═══════════════════════════════════════════════════════════════════════════

type UserFacingMessage = Extract<Message, { role: "user" | "developer" | "toolResult" }>;

/** Obfuscate `text` blocks of a content array; image and other blocks pass through. */
function obfuscateTextBlocks(
	obfuscator: SecretObfuscator,
	content: (TextContent | ImageContent)[],
): (TextContent | ImageContent)[] {
	let changed = false;
	const result = content.map((block): TextContent | ImageContent => {
		if (block.type !== "text") return block;
		const text = obfuscator.obfuscate(block.text);
		if (text === block.text) return block;
		changed = true;
		return { ...block, text };
	});
	return changed ? result : content;
}

/** Restore placeholders in `text` blocks of a content array; image and other blocks pass through. */
function deobfuscateTextBlocks(
	obfuscator: SecretObfuscator,
	content: (TextContent | ImageContent)[],
	allowLegacyAliases = false,
): (TextContent | ImageContent)[] {
	const deob = (text: string): string =>
		allowLegacyAliases ? obfuscator.deobfuscateStored(text) : obfuscator.deobfuscate(text);
	let changed = false;
	const result = content.map((block): TextContent | ImageContent => {
		if (block.type !== "text") return block;
		const text = deob(block.text);
		if (text === block.text) return block;
		changed = true;
		return { ...block, text };
	});
	return changed ? result : content;
}

/**
 * Redact secrets from outbound messages. Opt-in by origin: only user messages,
 * tool results, and user-authored developer messages (e.g. `@file` mentions)
 * can carry operator secrets. System prompts, tool schemas, and assistant
 * output are author-controlled or model-generated and pass through untouched.
 * Within a targeted message only `text` blocks are rewritten — inline image
 * bytes are never walked.
 */
export function obfuscateMessages(obfuscator: SecretObfuscator, messages: Message[]): Message[] {
	if (!obfuscator.hasSecrets()) return messages;
	let changed = false;
	const result = messages.map((message): Message => {
		if (
			message.role !== "user" &&
			message.role !== "toolResult" &&
			!(message.role === "developer" && message.attribution === "user")
		) {
			return message;
		}
		const target = message as UserFacingMessage;
		if (typeof target.content === "string") {
			const content = obfuscator.obfuscate(target.content);
			if (content === target.content) return message;
			changed = true;
			return { ...target, content } as Message;
		}
		const content = obfuscateTextBlocks(obfuscator, target.content);
		if (content === target.content) return message;
		changed = true;
		return { ...target, content } as Message;
	});
	return changed ? result : messages;
}

/**
 * Redact outbound provider context. Only conversation messages are rewritten;
 * the static system prompt and tool schemas pass through unchanged.
 */
export function obfuscateProviderContext(obfuscator: SecretObfuscator | undefined, context: Context): Context {
	if (!obfuscator?.hasSecrets()) return context;
	const messages = obfuscateMessages(obfuscator, context.messages);
	return messages === context.messages ? context : { ...context, messages };
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

function trailingOutsidePreservedPlaceholderChunk(
	text: string,
	shouldPreservePlaceholder: (placeholder: string) => boolean,
): string {
	PLACEHOLDER_RE.lastIndex = 0;
	let pendingIndex = 0;
	let sawPlaceholder = false;
	for (;;) {
		const match = PLACEHOLDER_RE.exec(text);
		if (match === null) break;
		if (!shouldPreservePlaceholder(match[0])) continue;
		sawPlaceholder = true;
		pendingIndex = match.index + match[0].length;
	}
	return sawPlaceholder ? text.slice(pendingIndex) : "";
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

// Apply a fixed custom replacement across a matched span while preserving any
// inner generated placeholders. Usually the replacement is the user's single
// redaction marker for the whole match, so emit it for the first non-empty
// surrounding chunk and drop later chunks. But bounded regexes can cut through
// an already-emitted marker on the trailing side (`X#…#RED` from
// `XSECRETUVREDACTED`), where dropping the later prefix would leave raw bytes
// (`ACTED`) to be consumed on the next pass. Promote later chunks that are a
// prefix of the replacement to the FULL marker so the first pass is already a
// fixed point. The reversible placeholder stays intact in its relative
// position.
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
			if (chunk.length === 0) return "";
			if (!emitted) {
				emitted = true;
				return replacement;
			}
			return replacement.startsWith(chunk) ? replacement : "";
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

/**
 * Map every string in arbitrary JSON. Used ONLY for tool-call arguments, whose
 * shape is model-authored and not known ahead of time. No other caller may walk
 * untyped data: every message/content path is handled by a typed transformer.
 */
function mapJsonStrings(value: JsonValue, fn: (s: string) => string): JsonValue {
	if (typeof value === "string") return fn(value);
	if (Array.isArray(value)) {
		let changed = false;
		const out = value.map(item => {
			const next = mapJsonStrings(item, fn);
			if (next !== item) changed = true;
			return next;
		});
		return changed ? out : value;
	}
	if (value !== null && typeof value === "object") {
		let changed = false;
		const out: JsonRecord = {};
		for (const key of Object.keys(value)) {
			const item = value[key];
			if (item === undefined) continue;
			const next = mapJsonStrings(item, fn);
			if (next !== item) changed = true;
			out[key] = next;
		}
		return changed ? out : value;
	}
	return value;
}
