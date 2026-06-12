import {
	type Component,
	Editor,
	type Focusable,
	matchesKey,
	ProcessTerminal,
	replaceTabs,
	ScrollView,
	TUI,
	truncateToWidth,
	wrapTextWithAnsi,
} from "@oh-my-pi/pi-tui";
import { sanitizeText } from "@oh-my-pi/pi-utils";
import { Args, Command } from "@oh-my-pi/pi-utils/cli";
import { AgentPaneHandoffError, consumeAgentPaneHandoff } from "../agent-control/handoff";
import {
	AGENT_CONTROL_PROTOCOL_VERSION,
	type ChildInvalidationDTO,
	type ChildPermissionSet,
	type ChildSnapshotDTO,
	type SendRequestDTO,
	type SendResultDTO,
	type TranscriptEntryDTO,
	type TranscriptPageDTO,
} from "../agent-control/protocol";
import { getEditorTheme, initTheme } from "../modes/theme/theme";

const PERMANENT_LOSS_EXIT_MS = 3_000;
const PARENT_LOSS_TIMEOUT_MS = 8_000;
const RECONNECT_DELAY_MS = 250;
const REQUEST_OPEN_TIMEOUT_MS = 15_000;
const MAX_SSE_BUFFER_CHARS = 64 * 1024;
const MAX_ENTRY_DISPLAY_CHARS = 64 * 1024;
const MAX_NOTICE_CHARS = 1024;

export type AgentPaneConnection =
	| "connecting"
	| "connected"
	| "reconnecting"
	| "revoked"
	| "generation_closed"
	| "protocol_error"
	| "outcome_unknown"
	| "parent_lost"
	| "closed";

export interface AgentPaneState {
	connection: AgentPaneConnection;
	snapshot?: ChildSnapshotDTO;
	entries: readonly TranscriptEntryDTO[];
	notice?: string;
	mutationEnabled?: boolean;
}

export interface AgentPaneClientOptions {
	fetch?: typeof fetch;
	onChange?: (state: AgentPaneState) => void;
	onPermanentLoss?: () => void;
	permanentLossExitMs?: number;
	parentLossTimeoutMs?: number;
	reconnectDelayMs?: number;
}

class AgentPaneProtocolError extends Error {}
class AgentPaneResponseError extends Error {
	readonly status: number;
	constructor(status: number) {
		super(`Agent pane sidecar returned HTTP ${status}.`);
		this.status = status;
	}
}

function sanitizeDisplay(text: string): string {
	return replaceTabs(sanitizeText(text));
}

function samePermission(
	permission: ChildPermissionSet,
	value: { version: number; generation: string; childId: string },
): boolean {
	return (
		value.version === AGENT_CONTROL_PROTOCOL_VERSION &&
		value.generation === permission.generation &&
		value.childId === permission.childId
	);
}

function sameSnapshot(
	permission: ChildPermissionSet,
	value: { version: number; generation: string; id: string },
): boolean {
	return (
		value.version === AGENT_CONTROL_PROTOCOL_VERSION &&
		value.generation === permission.generation &&
		value.id === permission.childId
	);
}

function isTranscriptEntry(value: unknown): value is TranscriptEntryDTO {
	if (!value || typeof value !== "object") return false;
	const entry = value as Partial<TranscriptEntryDTO>;
	return (
		typeof entry.id === "string" &&
		entry.id.length > 0 &&
		typeof entry.text === "string" &&
		(entry.type === "message" ||
			entry.type === "custom_message" ||
			entry.type === "branch_summary" ||
			entry.type === "compaction_summary") &&
		(entry.role === undefined ||
			entry.role === "user" ||
			entry.role === "assistant" ||
			entry.role === "toolResult" ||
			entry.role === "custom") &&
		(entry.toolName === undefined || typeof entry.toolName === "string") &&
		(entry.isError === undefined || typeof entry.isError === "boolean")
	);
}

function isSendResult(value: unknown, commandId: string): value is SendResultDTO {
	if (!value || typeof value !== "object") return false;
	const candidate = value as Partial<SendResultDTO>;
	if (candidate.commandId !== commandId || !candidate.result || typeof candidate.result.ok !== "boolean") return false;
	return candidate.result.ok
		? candidate.result.action === "steered" ||
				candidate.result.action === "prompted" ||
				candidate.result.action === "revived"
		: typeof candidate.result.code === "string" && typeof candidate.result.message === "string";
}

function snapshotAllowsSend(snapshot: ChildSnapshotDTO | undefined): boolean {
	return (
		snapshot?.capability === "send" &&
		(snapshot.availability === "running" || snapshot.availability === "idle" || snapshot.availability === "parked")
	);
}

/** Incremental parser for the narrow single-data-line SSE emitted by the sidecar. */
export class AgentPaneSseParser {
	#buffer = "";

	push(chunk: string): ChildInvalidationDTO[] {
		this.#buffer += chunk;
		if (this.#buffer.length > MAX_SSE_BUFFER_CHARS) throw new AgentPaneProtocolError("SSE frame exceeded its limit.");
		const result: ChildInvalidationDTO[] = [];
		let boundary = this.#buffer.indexOf("\n\n");
		while (boundary >= 0) {
			const frame = this.#buffer.slice(0, boundary);
			this.#buffer = this.#buffer.slice(boundary + 2);
			boundary = this.#buffer.indexOf("\n\n");
			if (frame === "" || frame.startsWith(":")) continue;
			const lines = frame.split("\n");
			if (lines[0] !== "event: invalidation" || lines.length !== 2 || !lines[1]?.startsWith("data: ")) {
				throw new AgentPaneProtocolError("Malformed agent pane stream frame.");
			}
			let value: unknown;
			try {
				value = JSON.parse(lines[1].slice(6));
			} catch {
				throw new AgentPaneProtocolError("Malformed agent pane stream data.");
			}
			if (!value || typeof value !== "object")
				throw new AgentPaneProtocolError("Malformed agent pane invalidation.");
			const candidate = value as Partial<ChildInvalidationDTO>;
			if (
				typeof candidate.version !== "number" ||
				typeof candidate.generation !== "string" ||
				typeof candidate.childId !== "string" ||
				(candidate.kind !== "state" && candidate.kind !== "transcript" && candidate.kind !== "generation_closed")
			) {
				throw new AgentPaneProtocolError("Malformed agent pane invalidation.");
			}
			result.push(candidate as ChildInvalidationDTO);
		}
		return result;
	}
}

/** Sidecar client. It never retries a mutation and owns no child lifecycle operation other than send. */
export class AgentPaneClient {
	readonly permission: ChildPermissionSet;
	readonly done: Promise<void>;
	readonly #fetch: typeof fetch;
	readonly #onChange: (state: AgentPaneState) => void;
	readonly #onPermanentLoss: () => void;
	readonly #permanentLossExitMs: number;
	readonly #parentLossTimeoutMs: number;
	readonly #reconnectDelayMs: number;
	readonly #resolveDone: () => void;
	#connection: AgentPaneConnection = "connecting";
	#snapshot: ChildSnapshotDTO | undefined;
	#entries: TranscriptEntryDTO[] = [];
	#cursor = 0;
	#notice: string | undefined;
	#abort = new AbortController();
	#closed = false;
	#frozen = false;
	#mutationInFlight = false;
	#reconcileQueue: Promise<void> = Promise.resolve();
	#exitTimer: NodeJS.Timeout | undefined;
	#parentLossTimer: NodeJS.Timeout | undefined;

	constructor(permission: ChildPermissionSet, options: AgentPaneClientOptions = {}) {
		this.permission = permission;
		this.#fetch = options.fetch ?? fetch;
		this.#onChange = options.onChange ?? (() => {});
		this.#onPermanentLoss = options.onPermanentLoss ?? (() => {});
		this.#permanentLossExitMs = options.permanentLossExitMs ?? PERMANENT_LOSS_EXIT_MS;
		this.#parentLossTimeoutMs = options.parentLossTimeoutMs ?? PARENT_LOSS_TIMEOUT_MS;
		this.#reconnectDelayMs = options.reconnectDelayMs ?? RECONNECT_DELAY_MS;
		const { promise, resolve } = Promise.withResolvers<void>();
		this.done = promise;
		this.#resolveDone = resolve;
	}

	get state(): AgentPaneState {
		return {
			connection: this.#connection,
			snapshot: this.#snapshot,
			entries: this.#entries,
			notice: this.#notice,
			mutationEnabled: this.canSend,
		};
	}

	get canSend(): boolean {
		return this.#connection === "connected" && !this.#mutationInFlight && snapshotAllowsSend(this.#snapshot);
	}

	async start(): Promise<void> {
		if (this.#closed) return;
		this.#emit("connecting");
		try {
			await this.#reconcile(true);
			this.#emit("connected");
			void this.#streamLoop();
		} catch (error) {
			this.#handleInitialError(error);
		}
	}

	async send(prompt: string): Promise<SendResultDTO | undefined> {
		const text = prompt.trim();
		if (!text || !this.canSend) return undefined;
		this.#mutationInFlight = true;
		this.#notice = "Sending one command…";
		this.#publish();
		const commandId = `${this.permission.generation}:${crypto.randomUUID()}`;
		const body: SendRequestDTO = { version: AGENT_CONTROL_PROTOCOL_VERSION, commandId, prompt: text };
		try {
			const response = await this.#request("/v1/send", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(body),
			});
			if (!response.ok) {
				if (response.status === 401 || response.status === 410) {
					this.#permanent(response.status === 401 ? "revoked" : "generation_closed");
					return undefined;
				}
				if (response.status !== 504) {
					const rejected = await this.#sendRejection(response, commandId);
					if (rejected) {
						const rejectedResult = rejected.result;
						this.#notice = rejectedResult.ok ? "Command rejected." : sanitizeDisplay(rejectedResult.message);
						return rejected;
					}
				}
				// A timeout or untyped transport/server error after dispatch is ambiguous. Never retry it.
				this.#freezeOutcomeUnknown(commandId);
				return undefined;
			}
			const result = await this.#json<SendResultDTO>(response);
			if (!samePermission(this.permission, result) || !isSendResult(result, commandId)) {
				this.#freezeOutcomeUnknown(commandId);
				return undefined;
			}
			this.#notice = result.result.ok
				? `Command accepted: ${result.result.action}.`
				: sanitizeDisplay(result.result.message);
			return result;
		} catch {
			if (!this.#closed) this.#freezeOutcomeUnknown(commandId);
			return undefined;
		} finally {
			this.#mutationInFlight = false;
			this.#publish();
		}
	}

	/** Viewer close is deliberately transport-only: abort reads and send no request. */
	close(): void {
		if (this.#closed) return;
		this.#closed = true;
		this.#connection = "closed";
		this.#abort.abort();
		clearTimeout(this.#exitTimer);
		clearTimeout(this.#parentLossTimer);
		this.#publish();
		this.#resolveDone();
	}

	async #streamLoop(): Promise<void> {
		let disconnectedAt: number | undefined;
		while (!this.#closed && !this.#frozen) {
			try {
				const response = await this.#request("/v1/stream", { headers: { Accept: "text/event-stream" } });
				if (!response.ok || !response.body) {
					if (response.status === 401 || response.status === 410) {
						this.#permanent(response.status === 401 ? "revoked" : "generation_closed");
						return;
					}
					throw new AgentPaneResponseError(response.status);
				}
				if (!response.headers.get("content-type")?.toLowerCase().startsWith("text/event-stream")) {
					throw new AgentPaneProtocolError("Sidecar stream has an invalid content type.");
				}
				const reader = response.body.getReader();
				try {
					await this.#reconcile(true, false);
					disconnectedAt = undefined;
					this.#emit("connected");
					const parser = new AgentPaneSseParser();
					const decoder = new TextDecoder();
					while (!this.#closed) {
						const next = await reader.read();
						if (next.done) break;
						for (const invalidation of parser.push(decoder.decode(next.value, { stream: true }))) {
							this.#acceptInvalidation(invalidation);
						}
					}
				} finally {
					try {
						await reader.cancel();
					} catch {}
					reader.releaseLock();
				}
			} catch (error) {
				if (this.#closed || this.#frozen) return;
				if (error instanceof AgentPaneProtocolError) {
					this.#permanent("protocol_error");
					return;
				}
				if (error instanceof AgentPaneResponseError && (error.status === 401 || error.status === 410)) {
					this.#permanent(error.status === 401 ? "revoked" : "generation_closed");
					return;
				}
			}
			if (this.#closed) return;
			disconnectedAt ??= Date.now();
			this.#emit("reconnecting", "Connection lost; transcript frozen while reconnecting.");
			if (Date.now() - disconnectedAt >= this.#parentLossTimeoutMs) {
				this.#permanent("parent_lost");
				return;
			}
			await Bun.sleep(this.#reconnectDelayMs);
		}
	}

	#acceptInvalidation(invalidation: ChildInvalidationDTO): void {
		if (this.#frozen || this.#closed) return;
		if (!samePermission(this.permission, invalidation)) {
			this.#permanent("protocol_error");
			return;
		}
		if (invalidation.kind === "generation_closed") {
			this.#permanent("generation_closed");
			return;
		}
		this.#reconcileQueue = this.#reconcileQueue
			.then(async () => {
				const reconnecting = this.#connection === "reconnecting";
				await this.#reconcile(invalidation.kind === "state", !reconnecting);
				if (reconnecting) this.#emit("connected");
			})
			.catch(error => {
				if (error instanceof AgentPaneProtocolError) this.#permanent("protocol_error");
				else if (error instanceof AgentPaneResponseError && (error.status === 401 || error.status === 410)) {
					this.#permanent(error.status === 401 ? "revoked" : "generation_closed");
				} else this.#emit("reconnecting", "Connection lost; transcript frozen while reconnecting.");
			});
	}

	async #reconcile(includeSnapshot: boolean, publish = true): Promise<void> {
		if (includeSnapshot) {
			const response = await this.#request("/v1/snapshot");
			if (!response.ok) throw new AgentPaneResponseError(response.status);
			const snapshot = await this.#json<ChildSnapshotDTO>(response);
			if (!sameSnapshot(this.permission, snapshot)) throw new AgentPaneProtocolError("Snapshot identity mismatch.");
			if (
				typeof snapshot.label !== "string" ||
				!Number.isFinite(snapshot.updatedAt) ||
				!["running", "idle", "parked", "aborted", "unavailable"].includes(snapshot.availability) ||
				!["send", "transcript_only"].includes(snapshot.capability) ||
				(snapshot.lastOutcome !== undefined && !["completed", "failed", "aborted"].includes(snapshot.lastOutcome))
			) {
				throw new AgentPaneProtocolError("Malformed snapshot.");
			}
			if (
				(snapshot.availability === "aborted" || snapshot.availability === "unavailable") &&
				snapshot.capability !== "transcript_only"
			) {
				throw new AgentPaneProtocolError("Terminal snapshot unexpectedly permits mutation.");
			}
			this.#snapshot = snapshot;
		}
		let entries = this.#entries;
		let cursor = this.#cursor;
		let pages = 0;
		while (!this.#closed && pages < 256) {
			pages += 1;
			const response = await this.#request(`/v1/transcript?fromByte=${cursor}`);
			if (!response.ok) throw new AgentPaneResponseError(response.status);
			const page = await this.#json<TranscriptPageDTO>(response);
			if (
				!samePermission(this.permission, page) ||
				!Number.isSafeInteger(page.fromByte) ||
				!Number.isSafeInteger(page.nextByte) ||
				page.fromByte < 0 ||
				page.nextByte < page.fromByte ||
				typeof page.reset !== "boolean" ||
				(!page.reset && page.fromByte !== cursor) ||
				!Array.isArray(page.entries) ||
				!page.entries.every(isTranscriptEntry)
			) {
				throw new AgentPaneProtocolError("Malformed transcript page.");
			}
			if (page.reset) entries = [];
			for (const entry of page.entries) {
				if (entries === this.#entries) entries = [...entries];
				entries.push({ ...entry, text: sanitizeDisplay(entry.text) });
			}
			const previous = cursor;
			cursor = page.nextByte;
			if (cursor === previous) break;
			if (pages === 256) throw new AgentPaneProtocolError("Transcript catch-up exceeded its page limit.");
		}
		if (this.#closed || this.#frozen) return;
		this.#entries = entries;
		this.#cursor = cursor;
		if (publish) this.#publish();
	}

	async #request(pathname: string, init: RequestInit = {}): Promise<Response> {
		const headers = new Headers(init.headers);
		headers.set("Authorization", `Bearer ${this.permission.token}`);
		const deadline = new AbortController();
		const timer = setTimeout(() => deadline.abort(), REQUEST_OPEN_TIMEOUT_MS);
		timer.unref?.();
		try {
			return await this.#fetch(new URL(pathname, this.permission.endpoint), {
				...init,
				signal: AbortSignal.any([this.#abort.signal, deadline.signal]),
				headers,
			});
		} finally {
			clearTimeout(timer);
		}
	}

	async #json<T>(response: Response): Promise<T> {
		let value: unknown;
		try {
			value = await response.json();
		} catch {
			throw new AgentPaneProtocolError("Malformed JSON response.");
		}
		if (!value || typeof value !== "object") throw new AgentPaneProtocolError("Malformed JSON response.");
		return value as T;
	}

	#handleInitialError(error: unknown): void {
		if (error instanceof AgentPaneProtocolError) this.#permanent("protocol_error");
		else if (error instanceof AgentPaneResponseError && error.status === 401) this.#permanent("revoked");
		else if (error instanceof AgentPaneResponseError && error.status === 410) this.#permanent("generation_closed");
		else this.#permanent("parent_lost");
	}

	async #sendRejection(response: Response, commandId: string): Promise<SendResultDTO | undefined> {
		let result: SendResultDTO;
		try {
			result = await this.#json<SendResultDTO>(response);
		} catch {
			return undefined;
		}
		if (!samePermission(this.permission, result) || !isSendResult(result, commandId) || result.result.ok) {
			return undefined;
		}
		return result;
	}

	#freezeOutcomeUnknown(commandId: string): void {
		if (this.#closed) return;
		this.#connection = "outcome_unknown";
		this.#frozen = true;
		this.#notice = `Command ${sanitizeDisplay(commandId)} may have been accepted; it will not be retried.`;
		this.#abort.abort();
		this.#publish();
	}

	#permanent(
		connection: Extract<AgentPaneConnection, "revoked" | "generation_closed" | "protocol_error" | "parent_lost">,
	): void {
		if (this.#closed || this.#connection === connection) return;
		clearTimeout(this.#parentLossTimer);
		this.#frozen = true;
		this.#connection = connection;
		this.#notice =
			connection === "revoked"
				? "Capability revoked; transcript frozen. Use Agent Hub in the parent pane."
				: connection === "generation_closed"
					? "Parent generation closed; transcript frozen."
					: connection === "protocol_error"
						? "Protocol mismatch or malformed frame; transcript frozen."
						: "Parent sidecar unavailable; transcript frozen.";
		this.#abort.abort();
		this.#publish();
		this.#exitTimer = setTimeout(() => {
			this.#onPermanentLoss();
			this.close();
		}, this.#permanentLossExitMs);
		this.#exitTimer.unref?.();
	}

	#emit(connection: AgentPaneConnection, notice?: string): void {
		if (this.#closed || this.#frozen) return;
		this.#connection = connection;
		if (notice !== undefined) this.#notice = notice;
		else if (connection === "connected") this.#notice = undefined;
		if (connection === "connected") {
			clearTimeout(this.#parentLossTimer);
			this.#parentLossTimer = undefined;
		} else if (connection === "reconnecting" && !this.#parentLossTimer) {
			this.#parentLossTimer = setTimeout(() => this.#permanent("parent_lost"), this.#parentLossTimeoutMs);
			this.#parentLossTimer.unref?.();
		}
		this.#publish();
	}

	#publish(): void {
		this.#onChange(this.state);
	}
}

interface TranscriptAnchor {
	id: string;
	offset: number;
}

/** Standalone, intentionally narrow transcript + prompt TUI. */
export class AgentPaneComponent implements Component, Focusable {
	focused = false;
	readonly #getRows: () => number;
	readonly #onSend: (prompt: string) => boolean | Promise<boolean>;
	readonly #onClose: () => void;
	readonly #editor: Editor;
	readonly #scroll = new ScrollView([], { height: 1, scrollbar: "auto" });
	#state: AgentPaneState = { connection: "connecting", entries: [] };
	#mode: "prompt" | "transcript" = "prompt";
	#entryStarts: Array<{ id: string; start: number }> = [];
	#layoutWidth = 0;
	#pendingAnchor: TranscriptAnchor | undefined;
	#followBottom = true;
	#newOutput = 0;
	#canSend = false;

	constructor(getRows: () => number, onSend: (prompt: string) => boolean | Promise<boolean>, onClose: () => void) {
		this.#getRows = getRows;
		this.#onSend = onSend;
		this.#onClose = onClose;
		this.#editor = new Editor(getEditorTheme());
		this.#editor.setBorderVisible(false);
		this.#editor.setPromptGutter("> ");
		this.#editor.setMaxHeight(5);
		this.#editor.onSubmit = text => {
			if (!this.#canSend || !text.trim()) {
				this.#editor.setText(text);
				return;
			}
			void Promise.resolve(this.#onSend(text))
				.then(accepted => {
					if (!accepted && !this.#editor.getText()) this.#editor.setText(text);
				})
				.catch(() => {
					if (!this.#editor.getText()) this.#editor.setText(text);
				});
		};
	}

	setState(state: AgentPaneState): void {
		const atBottom = this.#scroll.getScrollOffset() === this.#scroll.getMaxScrollOffset();
		if (!atBottom) this.#pendingAnchor = this.#currentAnchor();
		if (!atBottom && state.entries.length > this.#state.entries.length)
			this.#newOutput += state.entries.length - this.#state.entries.length;
		this.#followBottom = atBottom;
		this.#state = state;
		this.#canSend = state.mutationEnabled ?? (state.connection === "connected" && snapshotAllowsSend(state.snapshot));
		this.#layoutWidth = 0;
	}

	setUseTerminalCursor(useTerminalCursor: boolean): void {
		this.#editor.setUseTerminalCursor?.(useTerminalCursor);
	}

	render(width: number): readonly string[] {
		const safeWidth = Math.max(1, width);
		if (safeWidth !== this.#layoutWidth) this.#rebuildTranscript(safeWidth);
		const snapshot = this.#state.snapshot;
		const connection = this.#state.connection.replaceAll("_", " ");
		const availability = snapshot
			? `${snapshot.availability} / ${snapshot.capability.replaceAll("_", " ")}`
			: "unknown / transcript only";
		const outcome = snapshot?.lastOutcome ?? "none";
		const header = [
			truncateToWidth(`Agent pane: ${sanitizeDisplay(snapshot?.label ?? snapshot?.id ?? "connecting")}`, safeWidth),
			truncateToWidth(`Connection: ${connection}`, safeWidth),
			truncateToWidth(`Availability / capability: ${availability}`, safeWidth),
			truncateToWidth(`Last outcome: ${outcome}`, safeWidth),
		];
		if (this.#state.notice)
			header.push(
				...wrapTextWithAnsi(`Notice: ${sanitizeDisplay(this.#state.notice).slice(0, MAX_NOTICE_CHARS)}`, safeWidth),
			);
		this.#editor.focused = this.focused && this.#mode === "prompt";
		const editorLines = this.#mode === "prompt" ? this.#editor.render(safeWidth) : [];
		const footer = this.#footer();
		const bodyHeight = Math.max(1, this.#getRows() - header.length - editorLines.length - 1);
		this.#scroll.setHeight(bodyHeight);
		if (this.#followBottom) {
			this.#scroll.scrollToBottom();
			this.#newOutput = 0;
			this.#followBottom = false;
		}
		return [...header, ...this.#scroll.render(safeWidth), ...editorLines, truncateToWidth(footer, safeWidth)];
	}

	handleInput(data: string): void {
		if (matchesKey(data, "ctrl+c")) {
			this.#onClose();
			return;
		}
		if (matchesKey(data, "tab")) {
			this.#mode = this.#mode === "prompt" ? "transcript" : "prompt";
			return;
		}
		if (this.#mode === "transcript") {
			if (matchesKey(data, "escape")) {
				this.#mode = "prompt";
				return;
			}
			if (this.#scroll.handleScrollKey(data)) {
				this.#newOutput =
					this.#scroll.getScrollOffset() === this.#scroll.getMaxScrollOffset() ? 0 : this.#newOutput;
				return;
			}
			return;
		}
		if (matchesKey(data, "escape")) {
			if (this.#editor.getText()) this.#editor.setText("");
			else this.#onClose();
			return;
		}
		this.#editor.handleInput(data);
	}

	#rebuildTranscript(width: number): void {
		if (this.#layoutWidth > 0 && this.#scroll.getScrollOffset() !== this.#scroll.getMaxScrollOffset()) {
			this.#pendingAnchor ??= this.#currentAnchor();
		}
		this.#layoutWidth = width;
		const lines: string[] = [];
		const starts: Array<{ id: string; start: number }> = [];
		for (const entry of this.#state.entries) {
			starts.push({ id: entry.id, start: lines.length });
			const role = entry.role ?? entry.type.replaceAll("_", " ");
			const detail = entry.toolName ? ` (${sanitizeDisplay(entry.toolName)})` : "";
			lines.push(truncateToWidth(`${role}${detail}${entry.isError ? " [error]" : ""}:`, width));
			const text = sanitizeDisplay(entry.text);
			const display =
				text.length > MAX_ENTRY_DISPLAY_CHARS
					? `${text.slice(0, MAX_ENTRY_DISPLAY_CHARS)}\n[entry truncated]`
					: text;
			for (const raw of display.split("\n")) lines.push(...wrapTextWithAnsi(`  ${raw}`, width));
		}
		if (lines.length === 0) lines.push("No transcript entries yet.");
		this.#entryStarts = starts;
		this.#scroll.setLines(lines);
		if (this.#pendingAnchor) {
			const start = starts.find(item => item.id === this.#pendingAnchor?.id)?.start;
			if (start !== undefined) this.#scroll.setScrollOffset(start + this.#pendingAnchor.offset);
			this.#pendingAnchor = undefined;
		}
	}

	#currentAnchor(): TranscriptAnchor | undefined {
		const offset = this.#scroll.getScrollOffset();
		let anchor = this.#entryStarts[0];
		for (const candidate of this.#entryStarts) {
			if (candidate.start > offset) break;
			anchor = candidate;
		}
		return anchor ? { id: anchor.id, offset: offset - anchor.start } : undefined;
	}

	#footer(): string {
		const newOutput =
			this.#newOutput > 0 ? `${this.#newOutput} new transcript entr${this.#newOutput === 1 ? "y" : "ies"} | ` : "";
		if (this.#mode === "transcript")
			return `${newOutput}Transcript navigation | Tab/Esc: prompt | Up/Down/PgUp/PgDn/Home/End: scroll | Ctrl+C: close`;
		if (!this.#canSend) {
			const reason =
				this.#state.connection === "connected"
					? `${this.#state.snapshot?.availability ?? "agent"} is transcript only`
					: `while ${this.#state.connection.replaceAll("_", " ")}`;
			return `${newOutput}Prompt disabled: ${reason} | Tab: transcript navigation | Ctrl+C: close`;
		}
		return `${newOutput}Prompt editing | Enter: send | Shift+Enter: newline | Tab: transcript navigation | Esc: clear/close | Ctrl+C: close`;
	}
}

export async function runAgentPane(permission: ChildPermissionSet): Promise<void> {
	await initTheme();
	const ui = new TUI(new ProcessTerminal());
	const { promise: closed, resolve: resolveClosed } = Promise.withResolvers<void>();
	let settled = false;
	const finish = () => {
		if (settled) return;
		settled = true;
		client.close();
		ui.stop();
		resolveClosed();
	};
	const component = new AgentPaneComponent(
		() => ui.terminal.rows,
		async prompt => {
			const result = await client.send(prompt);
			return result === undefined || result.result.ok;
		},
		finish,
	);
	const client = new AgentPaneClient(permission, {
		onChange: state => {
			component.setState(state);
			ui.requestRender();
		},
		onPermanentLoss: finish,
	});
	ui.addChild(component);
	ui.setFocus(component);
	ui.start({ clearScrollback: true });
	await client.start();
	await closed;
}

export default class AgentPane extends Command {
	static hidden = true;
	static args = {
		child: Args.string({ required: true }),
		locator: Args.string({ required: true }),
	};

	async run(): Promise<void> {
		const { args } = await this.parse(AgentPane);
		try {
			if (!args.child || !args.locator) {
				throw new AgentPaneHandoffError(
					"invalid_locator",
					"Agent pane requires a child selector and handoff locator.",
				);
			}
			const permission = await consumeAgentPaneHandoff(args.locator, args.child);
			await runAgentPane(permission);
		} catch (error) {
			const message = error instanceof AgentPaneHandoffError ? error.message : "Agent pane failed to start.";
			process.stderr.write(`Agent pane unavailable: ${message}\n`);
			process.exitCode = 1;
		}
	}
}
