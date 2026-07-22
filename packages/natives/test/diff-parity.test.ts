import { describe, expect, test } from "bun:test";
import { diffLineRuns, diffLines, diffWords, structuredPatchHunks } from "@oh-my-pi/pi-natives";
import * as Diff from "diff";

/** Normalize jsdiff change objects (added/removed may be undefined). */
function jsChanges(changes: Diff.Change[]) {
	return changes.map(c => ({ value: c.value, count: c.count, added: !!c.added, removed: !!c.removed }));
}

function natChanges(changes: { value: string; count: number; added: boolean; removed: boolean }[]) {
	return changes.map(c => ({ value: c.value, count: c.count, added: c.added, removed: c.removed }));
}

function jsHunks(oldText: string, newText: string, context: number) {
	return Diff.structuredPatch("", "", oldText, newText, "", "", { context }).hunks.map(h => ({
		oldStart: h.oldStart,
		oldLines: h.oldLines,
		newStart: h.newStart,
		newLines: h.newLines,
		lines: h.lines,
	}));
}

function assertParity(oldText: string, newText: string) {
	expect(natChanges(diffLines(oldText, newText))).toEqual(jsChanges(Diff.diffLines(oldText, newText)));
	for (const context of [0, 3, 4]) {
		expect(structuredPatchHunks(oldText, newText, context)).toEqual(jsHunks(oldText, newText, context));
	}
	const jsRuns = Diff.diffArrays(oldText.split("\n"), newText.split("\n")).map(c => ({
		count: c.value.length,
		added: !!c.added,
		removed: !!c.removed,
	}));
	expect(diffLineRuns(oldText, newText).map(c => ({ count: c.count, added: c.added, removed: c.removed }))).toEqual(
		jsRuns,
	);
}

/** Deterministic LCG so failures are reproducible. */
function makeRng(seed: number) {
	let state = seed >>> 0;
	return () => {
		state = (state * 1664525 + 1013904223) >>> 0;
		return state / 0x1_0000_0000;
	};
}

function randomText(rng: () => number, lines: number, opts: { crlf?: boolean; unicode?: boolean } = {}) {
	const words = opts.unicode
		? ["alpha", "béta", "γάμμα", "デルタ", "🚀rocket", "ω"]
		: ["alpha", "beta", "gamma", "delta", "epsilon", "zeta"];
	const eol = opts.crlf ? "\r\n" : "\n";
	const out: string[] = [];
	for (let i = 0; i < lines; i++) {
		const n = 1 + Math.floor(rng() * 4);
		const parts: string[] = [];
		for (let j = 0; j < n; j++) parts.push(words[Math.floor(rng() * words.length)]!);
		out.push(parts.join(" "));
	}
	let text = out.join(eol);
	if (rng() > 0.5) text += eol;
	return text;
}

function mutate(rng: () => number, text: string, density: number) {
	const lines = text.split("\n");
	for (let i = 0; i < lines.length; i++) {
		const roll = rng();
		if (roll < density / 3) lines[i] = `${lines[i]} edited`;
		else if (roll < (density * 2) / 3) {
			lines.splice(i, 1);
			i--;
		} else if (roll < density) lines.splice(i, 0, `inserted ${Math.floor(rng() * 1000)}`);
	}
	return lines.join("\n");
}

describe("native diff parity with jsdiff", () => {
	test("fixed edge cases", () => {
		assertParity("", "");
		assertParity("", "a\nb\n");
		assertParity("a\nb\n", "");
		assertParity("same\ntext\n", "same\ntext\n");
		assertParity("a\nb\nc", "a\nx\nc"); // no trailing newline
		assertParity("a\r\nb\r\nc\r\n", "a\r\nx\r\nc\r\n"); // CRLF
		assertParity("a\nb\n", "a\r\nb\r\n"); // mixed EOL rewrite
		assertParity("líne ünicode 🚀\nsecond\n", "líne ünicode 🚀\nsécond\n");
		assertParity("lone\rcarriage\n", "lone\rreturn\n"); // \r is not a line break
	});

	test("word diff parity", () => {
		const cases: [string, string][] = [
			["foo bar baz", "foo qux baz"],
			["  leading space", "leading  space"],
			["tab\tsep", "tab sep"],
			["punct, mark!", "punct; mark?"],
			["ünïcode wörds", "ünïcode words"],
			["", "new words"],
			["same same", "same same"],
		];
		for (const [a, b] of cases) {
			expect(natChanges(diffWords(a, b))).toEqual(jsChanges(Diff.diffWords(a, b)));
		}
	});

	test("seeded random word diffs", () => {
		// Token pool stresses jsdiff's word/whitespace boundary rules: repeated
		// and mixed whitespace, tabs, newlines, punctuation runs, Latin
		// extended, non-Latin scripts, emoji (surrogate pairs), and digits.
		const tokens = [
			"word",
			"Wörter",
			"naïve",
			"λέξη",
			"слово",
			"単語",
			"🚀",
			"👍🏽",
			"can't",
			"co-op",
			"...",
			"!?",
			";",
			"(x)",
			"42",
			"3.14",
			" ",
			"  ",
			"\t",
			" \t ",
			"\n",
			"\n\n",
			" \n ",
		];
		const rng = makeRng(0xd1ff);
		const build = (len: number) => {
			let s = "";
			for (let i = 0; i < len; i++) s += tokens[Math.floor(rng() * tokens.length)];
			return s;
		};
		for (let round = 0; round < 200; round++) {
			const a = build(Math.floor(rng() * 40));
			// Mix related pairs (mutations of `a`) with unrelated pairs.
			let b: string;
			if (round % 2 === 0) {
				b = build(Math.floor(rng() * 40));
			} else {
				const parts = a.split(/(\s+)/).filter(Boolean);
				for (let i = 0; i < parts.length; i++) {
					const roll = rng();
					if (roll < 0.15) parts[i] = tokens[Math.floor(rng() * tokens.length)] ?? "";
					else if (roll < 0.25) parts[i] = "";
				}
				b = parts.join("");
			}
			expect(natChanges(diffWords(a, b))).toEqual(jsChanges(Diff.diffWords(a, b)));
		}
	});

	test("seeded random documents", () => {
		const rng = makeRng(0xc0ffee);
		for (let round = 0; round < 30; round++) {
			const crlf = round % 3 === 1;
			const unicode = round % 4 === 2;
			const base = randomText(rng, 5 + Math.floor(rng() * 120), { crlf, unicode });
			assertParity(base, mutate(rng, base, round % 2 === 0 ? 0.01 : 0.2));
		}
	});

	test("10k-line document", () => {
		const rng = makeRng(0xbeef);
		const base = randomText(rng, 10_000);
		assertParity(base, mutate(rng, base, 0.01));
	});
});
