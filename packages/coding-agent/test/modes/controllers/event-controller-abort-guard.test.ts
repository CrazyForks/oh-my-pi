/**
 * Regression tests for `EventController`'s post-turn desktop notifications
 * (`sendCompletionNotification` / `sendErrorNotification`).
 *
 * Both read the settled turn's outcome from the `agent_end` event's own
 * `messages`, not the mutable `viewSession` active context: a classifier-
 * refusal failure ends with `stopReason === "error"` but is pruned from
 * active context before the public `agent_end` fires (see
 * `#removeAssistantMessageFromActiveContext` in `agent-session.ts`), and a
 * user Ctrl+C on the `ask` tool selector similarly leaves `stopReason ===
 * "aborted"` on the terminal message. Reading the mutable context for either
 * check risks a stale/absent lookup — dropping the intended notification, or
 * worse, pairing a misleading "Complete" toast with an error/abort.
 */
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { AssistantMessage } from "@oh-my-pi/pi-ai";
import { resetSettingsForTest, Settings, settings } from "@oh-my-pi/pi-coding-agent/config/settings";
import { SETTINGS_SCHEMA } from "@oh-my-pi/pi-coding-agent/config/settings-schema";
import { EventController } from "@oh-my-pi/pi-coding-agent/modes/controllers/event-controller";
import { initTheme } from "@oh-my-pi/pi-coding-agent/modes/theme/theme";
import type { InteractiveModeContext } from "@oh-my-pi/pi-coding-agent/modes/types";
import type { AgentSessionEvent } from "@oh-my-pi/pi-coding-agent/session/agent-session";
import { TERMINAL } from "@oh-my-pi/pi-tui";

beforeAll(() => {
	initTheme();
});

beforeEach(async () => {
	resetSettingsForTest();
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "omp-abortguard-"));
	await Settings.init({ inMemory: true, cwd: tempDir });
});

afterEach(() => {
	vi.restoreAllMocks();
	resetSettingsForTest();
});

type StopReason = "stop" | "aborted" | "error";

function makeAssistantMessage(stopReason: StopReason): AssistantMessage {
	return {
		role: "assistant",
		content: [{ type: "text", text: "hello" }],
		stopReason,
		usage: { inputTokens: 0, outputTokens: 0 },
		timestamp: Date.now(),
	} as unknown as AssistantMessage;
}

function makeContext(): InteractiveModeContext {
	return {
		sessionManager: {
			getSessionName: () => "test-session",
		},
	} as unknown as InteractiveModeContext;
}

function makeAgentEndEvent(messages: AssistantMessage[]): Extract<AgentSessionEvent, { type: "agent_end" }> {
	return { type: "agent_end", messages } as Extract<AgentSessionEvent, { type: "agent_end" }>;
}

/** Full context needed to drive `#handleAgentEnd` -> `#finishAgentEnd` end to end. */
function makeTurnEndContext(options: { lastAssistantMessage?: AssistantMessage } = {}): InteractiveModeContext {
	const session = {
		isStreaming: false,
		isCompacting: false,
		messages: [] as AssistantMessage[],
		getLastAssistantMessage: () => options.lastAssistantMessage,
		getContextUsage: () => undefined,
	};
	return {
		isInitialized: true,
		loadingAnimation: undefined,
		streamingComponent: undefined,
		streamingMessage: undefined,
		pendingTools: new Map<string, unknown>(),
		flushPendingModelSwitch: async () => {},
		ui: { requestRender: () => {} },
		chatContainer: { removeChild: () => {} },
		statusContainer: { clear: () => {} },
		statusLine: { markActivityEnd: () => {} },
		editor: { getText: () => "" },
		sessionManager: { getSessionName: () => "test-session" },
		session,
		viewSession: session,
	} as unknown as InteractiveModeContext;
}

describe("EventController.sendCompletionNotification — abort guard", () => {
	it("skips notification when the terminal assistant message stopReason === 'aborted'", () => {
		const spy = vi.spyOn(TERMINAL, "sendNotification").mockImplementation(() => {});
		settings.override("completion.notify", "on");
		const controller = new EventController(makeContext());
		controller.sendCompletionNotification(makeAgentEndEvent([makeAssistantMessage("aborted")]));
		expect(spy).toHaveBeenCalledTimes(0);
	});

	it("skips notification when the terminal assistant message stopReason === 'error'", () => {
		const spy = vi.spyOn(TERMINAL, "sendNotification").mockImplementation(() => {});
		settings.override("completion.notify", "on");
		const controller = new EventController(makeContext());
		controller.sendCompletionNotification(makeAgentEndEvent([makeAssistantMessage("error")]));
		expect(spy).toHaveBeenCalledTimes(0);
	});

	it("fires notification when stopReason === 'stop' (normal completion)", () => {
		const spy = vi.spyOn(TERMINAL, "sendNotification").mockImplementation(() => {});
		settings.override("completion.notify", "on");
		const controller = new EventController(makeContext());
		controller.sendCompletionNotification(makeAgentEndEvent([makeAssistantMessage("stop")]));
		expect(spy).toHaveBeenCalledTimes(1);
		// Completion now sends a structured notification (title=session, body="Complete").
		expect(spy).toHaveBeenCalledWith(expect.objectContaining({ body: "Complete", type: "completion" }));
	});

	it("fires notification when agent_end carries no assistant message (e.g. brand-new session)", () => {
		// Defensive: `findLast` returns undefined; treat as 'no abort flag', proceed.
		const spy = vi.spyOn(TERMINAL, "sendNotification").mockImplementation(() => {});
		settings.override("completion.notify", "on");
		const controller = new EventController(makeContext());
		controller.sendCompletionNotification(makeAgentEndEvent([]));
		expect(spy).toHaveBeenCalledTimes(1);
	});

	it("honors the existing completion.notify=off gate", () => {
		const spy = vi.spyOn(TERMINAL, "sendNotification").mockImplementation(() => {});
		settings.override("completion.notify", "off");
		const controller = new EventController(makeContext());
		controller.sendCompletionNotification(makeAgentEndEvent([makeAssistantMessage("stop")]));
		expect(spy).toHaveBeenCalledTimes(0);
	});
});

describe("EventController.sendErrorNotification", () => {
	it("defaults error notifications to opt-in", () => {
		expect(SETTINGS_SCHEMA["error.notify"].default).toBe("off");
	});

	it("fires an error notification when stopReason === 'error'", () => {
		const spy = vi.spyOn(TERMINAL, "sendNotification").mockImplementation(() => {});
		settings.override("error.notify", "on");
		const controller = new EventController(makeContext());
		controller.sendErrorNotification(makeAgentEndEvent([makeAssistantMessage("error")]));
		expect(spy).toHaveBeenCalledTimes(1);
		expect(spy).toHaveBeenCalledWith(
			expect.objectContaining({ body: "Stopped with error", type: "error", title: "test-session" }),
		);
	});

	it("uses the last assistant message when agent_end carries multiple messages", () => {
		const spy = vi.spyOn(TERMINAL, "sendNotification").mockImplementation(() => {});
		settings.override("error.notify", "on");
		const controller = new EventController(makeContext());
		controller.sendErrorNotification(
			makeAgentEndEvent([makeAssistantMessage("stop"), makeAssistantMessage("error")]),
		);
		expect(spy).toHaveBeenCalledTimes(1);
	});

	it("honors error.notify=off without changing completion notifications", () => {
		const spy = vi.spyOn(TERMINAL, "sendNotification").mockImplementation(() => {});
		settings.override("error.notify", "off");
		settings.override("completion.notify", "on");

		const errorController = new EventController(makeContext());
		errorController.sendErrorNotification(makeAgentEndEvent([makeAssistantMessage("error")]));
		expect(spy).toHaveBeenCalledTimes(0);

		const completionController = new EventController(makeContext());
		completionController.sendCompletionNotification(makeAgentEndEvent([makeAssistantMessage("stop")]));
		expect(spy).toHaveBeenCalledTimes(1);
		expect(spy).toHaveBeenCalledWith(expect.objectContaining({ body: "Complete", type: "completion" }));
	});

	it("skips user-aborted turns", () => {
		const spy = vi.spyOn(TERMINAL, "sendNotification").mockImplementation(() => {});
		settings.override("error.notify", "on");
		const controller = new EventController(makeContext());
		controller.sendErrorNotification(makeAgentEndEvent([makeAssistantMessage("aborted")]));
		expect(spy).toHaveBeenCalledTimes(0);
	});

	it("skips normal completion turns", () => {
		const spy = vi.spyOn(TERMINAL, "sendNotification").mockImplementation(() => {});
		settings.override("error.notify", "on");
		const controller = new EventController(makeContext());
		controller.sendErrorNotification(makeAgentEndEvent([makeAssistantMessage("stop")]));
		expect(spy).toHaveBeenCalledTimes(0);
	});
});

describe("EventController — notifications through the real turn-end path (#handleAgentEnd)", () => {
	it("fires the error notification when the dispatched turn settles with stopReason === 'error', even with a stale active-context snapshot", async () => {
		const spy = vi.spyOn(TERMINAL, "sendNotification").mockImplementation(() => {});
		settings.override("error.notify", "on");
		settings.override("completion.notify", "off");
		// viewSession (active context) reports no assistant at all — the shape a
		// classifier-refusal prune leaves behind — while the terminal agent_end
		// event still carries the failed turn.
		const controller = new EventController(makeTurnEndContext({ lastAssistantMessage: undefined }));
		await controller.handleEvent(makeAgentEndEvent([makeAssistantMessage("error")]));
		expect(spy).toHaveBeenCalledTimes(1);
		expect(spy).toHaveBeenCalledWith(expect.objectContaining({ body: "Stopped with error", type: "error" }));
	});

	it("skips the error notification when the dispatched turn settles with stopReason === 'aborted'", async () => {
		const spy = vi.spyOn(TERMINAL, "sendNotification").mockImplementation(() => {});
		settings.override("error.notify", "on");
		settings.override("completion.notify", "off");
		const controller = new EventController(makeTurnEndContext());
		await controller.handleEvent(makeAgentEndEvent([makeAssistantMessage("aborted")]));
		expect(spy).not.toHaveBeenCalled();
	});

	it("fires only the error toast — never a paired 'Complete' toast — for one error-ending turn", async () => {
		// Regression for the exact coupling bug: with both notify settings on,
		// a classifier-refusal turn's stale active context must not let
		// sendCompletionNotification's own stopReason check pass by reading a
		// different (non-error) snapshot than sendErrorNotification just used.
		const spy = vi.spyOn(TERMINAL, "sendNotification").mockImplementation(() => {});
		settings.override("error.notify", "on");
		settings.override("completion.notify", "on");
		const controller = new EventController(makeTurnEndContext({ lastAssistantMessage: undefined }));
		await controller.handleEvent(makeAgentEndEvent([makeAssistantMessage("error")]));
		expect(spy).toHaveBeenCalledTimes(1);
		expect(spy).toHaveBeenCalledWith(expect.objectContaining({ body: "Stopped with error", type: "error" }));
	});
});
