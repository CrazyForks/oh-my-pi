/**
 * Issue #4004: `evalToolRenderer.renderResult` mutates the live agent
 * progress tree on nearly every tick — `renderAgentProgressEvents` inserts
 * and removes each subagent's `currentTool` line as tool calls start/stop,
 * and ticks status icons/stats/duration in place — while
 * `options.isPartial === true` for the entire `eval()` cell (progress ticks
 * never carry an `async` completed/failed state). Without the renderer's
 * `provisionalPartialResult: true` opt-out, the block reports commit-stable
 * during that churn: `deriveLiveCommitState` promotes still-mutating agent
 * rows into native scrollback, and the renderer's committed-prefix resync
 * duplicates the frame tail under its "duplication, never loss" contract —
 * the overlapping/duplicated tree rows the user reported. Same bug class as
 * #3177 / #3714 in the SSH renderer. Contract: while a partial eval result
 * is in flight, the block reports commit-unstable so `deriveLiveCommitState`
 * keeps its rows in the live region; once the cell settles it is
 * commit-stable again.
 */
import { afterEach, beforeAll, describe, expect, it, vi } from "bun:test";
import { resetSettingsForTest, Settings } from "@oh-my-pi/pi-coding-agent/config/settings";
import { ToolExecutionComponent } from "@oh-my-pi/pi-coding-agent/modes/components/tool-execution";
import { initTheme } from "@oh-my-pi/pi-coding-agent/modes/theme/theme";
import type { TUI } from "@oh-my-pi/pi-tui";

const uiStub = { requestRender() {} } as unknown as TUI;

function makeEvalComponent() {
	return new ToolExecutionComponent("eval", { language: "py", code: "print('hi')" }, {}, undefined, uiStub);
}

function partialResult(text: string) {
	return { content: [{ type: "text" as const, text }] };
}

describe("eval tool block commit stability", () => {
	beforeAll(async () => {
		resetSettingsForTest();
		await Settings.init({ inMemory: true });
		await initTheme();
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("reports commit-unstable while an eval result is partial", () => {
		const component = makeEvalComponent();
		component.updateResult(partialResult("running…"), true);

		expect(component.isTranscriptBlockFinalized()).toBe(false);
		expect(component.isTranscriptBlockCommitStable()).toBe(false);
	});

	it("flips commit-stable as soon as the eval result settles", () => {
		const component = makeEvalComponent();
		component.updateResult(partialResult("running…"), true);
		expect(component.isTranscriptBlockCommitStable()).toBe(false);

		component.updateResult(partialResult("done\n"), false);
		expect(component.isTranscriptBlockFinalized()).toBe(true);
		expect(component.isTranscriptBlockCommitStable()).toBe(true);
	});

	it("does not opt other foreground tools out of partial-result stream commits", () => {
		// Sanity: bash and friends still get the existing `isPartial`
		// commit-stable behaviour — the eval opt-in must be renderer-scoped.
		const component = new ToolExecutionComponent("bash", { command: "ls" }, {}, undefined, uiStub);
		component.updateResult(partialResult("a\nb\n"), true);

		expect(component.isTranscriptBlockFinalized()).toBe(false);
		expect(component.isTranscriptBlockCommitStable()).toBe(true);
	});
});
