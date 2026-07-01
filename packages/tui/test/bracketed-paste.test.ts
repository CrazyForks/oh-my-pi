import { describe, expect, it } from "bun:test";
import { BracketedPasteHandler, decodeReencodedPasteControls } from "@oh-my-pi/pi-tui/bracketed-paste";

const PASTE_START = "\x1b[200~";
const PASTE_END = "\x1b[201~";

describe("BracketedPasteHandler", () => {
	it("passes non-paste bytes through untouched", () => {
		const handler = new BracketedPasteHandler();
		expect(handler.process("hello")).toEqual({ handled: false });
	});

	it("assembles a complete paste delivered in one chunk", () => {
		const handler = new BracketedPasteHandler();
		const result = handler.process(`${PASTE_START}hello world${PASTE_END}`);
		expect(result).toEqual({ handled: true, pasteContent: "hello world", remaining: "" });
	});

	it("holds until the end marker arrives when split across chunks", () => {
		const handler = new BracketedPasteHandler();
		expect(handler.process(`${PASTE_START}part 1 `)).toEqual({ handled: true, remaining: "" });
		expect(handler.process("part 2")).toEqual({ handled: true, remaining: "" });
		expect(handler.process(PASTE_END)).toEqual({
			handled: true,
			pasteContent: "part 1 part 2",
			remaining: "",
		});
	});

	it("preserves trailing bytes after the end marker as `remaining`", () => {
		const handler = new BracketedPasteHandler();
		const result = handler.process(`${PASTE_START}payload${PASTE_END}trailing`);
		expect(result).toEqual({ handled: true, pasteContent: "payload", remaining: "trailing" });
	});

	it("delivers the accumulated payload as a completed paste when the byte cap is exceeded", () => {
		// Defense in depth for callers that bypass `StdinBuffer` (which
		// re-wraps paste bodies with both markers). Without this cap, a lost
		// end marker leaks memory forever while input appears dead — see the
		// contrast with `StdinBuffer`'s `#abortPaste` at stdin-buffer.ts:497.
		const handler = new BracketedPasteHandler({ byteLimit: 8 });
		expect(handler.process(`${PASTE_START}0123456789abcdef`)).toEqual({
			handled: true,
			pasteContent: "0123456789abcdef",
			remaining: "",
		});
		// After recovery, ordinary input flows again.
		expect(handler.process("z")).toEqual({ handled: false });
	});

	it("resumes accepting a new paste after a cap-triggered recovery", () => {
		const handler = new BracketedPasteHandler({ byteLimit: 4 });
		handler.process(`${PASTE_START}abcdefgh`);
		const next = handler.process(`${PASTE_START}small${PASTE_END}`);
		expect(next).toEqual({ handled: true, pasteContent: "small", remaining: "" });
	});
});

describe("decodeReencodedPasteControls", () => {
	it("decodes tmux csi-u encoding to the raw control byte", () => {
		expect(decodeReencodedPasteControls("hi\x1b[106;5uworld")).toBe("hi\nworld");
	});

	it("decodes tmux xterm encoding to the raw control byte", () => {
		expect(decodeReencodedPasteControls("a\x1b[27;5;106~b")).toBe("a\nb");
	});

	it("leaves the payload untouched when no re-encoded controls are present", () => {
		expect(decodeReencodedPasteControls("plain text")).toBe("plain text");
	});
});
