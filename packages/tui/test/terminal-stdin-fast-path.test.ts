import { describe, expect, it } from "bun:test";
import { STDIN_ESCAPE_PROBE_PATTERNS } from "@oh-my-pi/pi-tui/terminal";

// The `#setupStdinBuffer` data handler short-circuits plain non-ESC input when
// no reassembly buffer is in flight. That is only safe because every probe
// pattern anchors on `\x1b` — a non-ESC scalar can never satisfy one, so
// skipping the probes is behavior-preserving. This test pins the invariant:
// if a future change adds a probe that does NOT require an ESC prefix, the
// fast path in `terminal.ts` MUST be revisited (issue #4022).

describe("STDIN escape-probe patterns", () => {
	// Sample of common non-ESC bytes: printable ASCII, whitespace, and a
	// couple of high-bit code points that terminals may deliver as raw scalars
	// on legacy (non-UTF-8) encodings. All of these MUST fail every probe.
	const nonEscBytes = [
		"a",
		"Z",
		"0",
		" ",
		"\n",
		"\t",
		"~",
		"\x7f",
		"\u00e9", // é
		"\u4e16", // 世
		"🙂",
	];

	for (const name in STDIN_ESCAPE_PROBE_PATTERNS) {
		const pattern = STDIN_ESCAPE_PROBE_PATTERNS[name as keyof typeof STDIN_ESCAPE_PROBE_PATTERNS];
		it(`${name} requires an ESC-prefixed sequence`, () => {
			// Static invariant: the source anchors on the literal `\x1b`.
			expect(pattern.source).toStartWith("^\\x1b");
			// Dynamic invariant: nothing without an ESC prefix ever matches.
			for (const b of nonEscBytes) {
				expect(pattern.test(b)).toBe(false);
			}
		});
	}
});
