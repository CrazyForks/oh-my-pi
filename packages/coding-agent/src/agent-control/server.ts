import type { AgentLifecycleManager } from "../registry/agent-lifecycle";
import type { AgentRegistry } from "../registry/agent-registry";
import type { AgentSession } from "../session/agent-session";
import type { EventBus } from "../utils/event-bus";
import type { ChildControlErrorCode, DirectChildControlAdmission, DirectChildControlSource } from "./control";
import { DirectChildProjection, type ProjectionListener } from "./projection";
import {
	AGENT_CONTROL_PROTOCOL_VERSION,
	type ChildInvalidationDTO,
	type ChildPermissionSet,
	type ChildSnapshotDTO,
	type SendRequestDTO,
	type SendResultDTO,
} from "./protocol";

const MAX_BODY_BYTES = 64 * 1024;
const MAX_PROMPT_CHARS = 32 * 1024;
const MAX_COMMAND_ID_CHARS = 256;
const MAX_ACTIVE_REQUESTS = 32;
const MAX_STREAMS = 8;
const MAX_QUEUED_SENDS = 16;
const MAX_LEDGER_RESULTS = 256;
const REQUEST_DEADLINE_MS = 15_000;

interface PermissionRecord {
	childId: string;
	generation: string;
	ledger: Map<string, Promise<SendResultDTO>>;
}

interface ProjectionProvider {
	getProjection(): DirectChildProjection | undefined;
}

function secureToken(): string {
	const bytes = crypto.getRandomValues(new Uint8Array(32));
	return Buffer.from(bytes).toString("base64url");
}

function response(status: number, body?: unknown, headers: Record<string, string> = {}): Response {
	return new Response(body === undefined ? null : JSON.stringify(body), {
		status,
		headers: {
			"Cache-Control": "no-store",
			"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
			"X-Content-Type-Options": "nosniff",
			...(body === undefined ? {} : { "Content-Type": "application/json" }),
			...headers,
		},
	});
}

function sendRejection(
	permission: PermissionRecord,
	commandId: string,
	code: ChildControlErrorCode,
	message: string,
): SendResultDTO {
	return {
		version: AGENT_CONTROL_PROTOCOL_VERSION,
		generation: permission.generation,
		childId: permission.childId,
		commandId,
		result: { ok: false, code, message },
	};
}

export interface AgentControlServerHandle {
	readonly endpoint: string;
	grant(childId: string): ChildPermissionSet | undefined;
	revokeAll(): void;
	close(): Promise<void>;
}

/** Ephemeral loopback transport with a permission-set token bound to one child and generation. */
export class AgentControlServer implements AgentControlServerHandle {
	readonly #provider: ProjectionProvider;
	readonly #permissions = new Map<string, PermissionRecord>();
	readonly #tokenByChild = new Map<string, string>();
	readonly #closeStreams = new Set<() => void>();
	readonly #server: Bun.Server<undefined>;
	#exactHost = "";
	#activeRequests = 0;
	#activeStreams = 0;
	#queuedSends = 0;

	constructor(provider: ProjectionProvider) {
		this.#provider = provider;
		this.#server = Bun.serve({
			hostname: "127.0.0.1",
			port: 0,
			idleTimeout: 20,
			fetch: request => this.#fetch(request),
		});
		this.#exactHost = `127.0.0.1:${this.#server.port}`;
	}

	get endpoint(): string {
		return `http://${this.#exactHost}`;
	}

	grant(childId: string): ChildPermissionSet | undefined {
		const projection = this.#provider.getProjection();
		if (!projection?.hasChild(childId)) return undefined;
		let token = this.#tokenByChild.get(childId);
		if (!token) {
			token = secureToken();
			this.#tokenByChild.set(childId, token);
			this.#permissions.set(token, { childId, generation: projection.generation, ledger: new Map() });
		}
		return {
			version: AGENT_CONTROL_PROTOCOL_VERSION,
			generation: projection.generation,
			childId,
			endpoint: this.endpoint,
			token,
		};
	}

	revokeAll(): void {
		for (const close of this.#closeStreams) close();
		this.#closeStreams.clear();
		this.#permissions.clear();
		this.#tokenByChild.clear();
	}

	async close(): Promise<void> {
		this.revokeAll();
		await this.#server.stop(true);
	}

	async #fetch(request: Request): Promise<Response> {
		if (this.#activeRequests >= MAX_ACTIVE_REQUESTS) return response(503, { error: "request_capacity" });
		this.#activeRequests += 1;
		try {
			const url = new URL(request.url);
			if (request.method === "OPTIONS") return response(405, { error: "method_not_allowed" });
			if (request.headers.get("host") !== this.#exactHost) return response(403, { error: "invalid_host" });
			if (request.headers.has("origin")) return response(403, { error: "browser_origin_rejected" });
			const fetchSite = request.headers.get("sec-fetch-site");
			if (fetchSite === "cross-site" || fetchSite === "same-site")
				return response(403, { error: "cross_site_rejected" });
			if (["token", "access_token", "authorization", "api_key"].some(key => url.searchParams.has(key))) {
				return response(400, { error: "query_credentials_rejected" });
			}

			// Authenticate before route dispatch and, critically, before reading a request body.
			const authorization = request.headers.get("authorization");
			const token = authorization?.startsWith("Bearer ") ? authorization.slice(7) : undefined;
			const permission = token ? this.#permissions.get(token) : undefined;
			const projection = this.#provider.getProjection();
			if (
				!permission ||
				!projection ||
				permission.generation !== projection.generation ||
				!projection.hasChild(permission.childId)
			) {
				return response(401, { error: "unauthorized" });
			}

			if (request.method === "GET" && url.pathname === "/v1/snapshot") {
				return response(200, projection.snapshot(permission.childId));
			}
			if (request.method === "GET" && url.pathname === "/v1/transcript") {
				const rawCursor = url.searchParams.get("fromByte");
				const fromByte = rawCursor === null ? 0 : Number(rawCursor);
				if (!Number.isSafeInteger(fromByte) || fromByte < 0) return response(400, { error: "invalid_cursor" });
				const page = await projection.transcript(permission.childId, fromByte);
				return page ? response(200, page) : response(410, { error: "generation_closed" });
			}
			if (request.method === "GET" && url.pathname === "/v1/stream") return this.#stream(projection, permission);
			if (request.method === "POST" && url.pathname === "/v1/send")
				return this.#send(request, projection, permission);
			return response(404, { error: "not_found" });
		} finally {
			this.#activeRequests -= 1;
		}
	}

	#stream(projection: DirectChildProjection, permission: PermissionRecord): Response {
		if (this.#activeStreams >= MAX_STREAMS) return response(503, { error: "stream_capacity" });
		this.#activeStreams += 1;
		const encoder = new TextEncoder();
		let unsubscribe: (() => void) | undefined;
		let keepalive: NodeJS.Timeout | undefined;
		let closed = false;
		let queued: ChildInvalidationDTO | undefined;
		let flushQueued = false;
		let closeStream = () => {};
		const stream = new ReadableStream<Uint8Array>({
			start: controller => {
				closeStream = () => {
					if (closed) return;
					closed = true;
					unsubscribe?.();
					clearInterval(keepalive);
					this.#closeStreams.delete(closeStream);
					this.#activeStreams -= 1;
					try {
						controller.close();
					} catch {}
				};
				this.#closeStreams.add(closeStream);
				const listener: ProjectionListener = invalidation => {
					if (invalidation.childId !== permission.childId) return;
					queued = invalidation;
					if (flushQueued) return;
					flushQueued = true;
					queueMicrotask(() => {
						flushQueued = false;
						if (closed || !queued) return;
						controller.enqueue(encoder.encode(`event: invalidation\ndata: ${JSON.stringify(queued)}\n\n`));
						queued = undefined;
					});
				};
				unsubscribe = projection.onInvalidation(listener);
				keepalive = setInterval(() => controller.enqueue(encoder.encode(": keepalive\n\n")), 15_000);
				keepalive.unref?.();
				listener({
					version: AGENT_CONTROL_PROTOCOL_VERSION,
					generation: projection.generation,
					childId: permission.childId,
					kind: "state",
				});
			},
			cancel: () => closeStream(),
		});
		return new Response(stream, {
			headers: {
				"Content-Type": "text/event-stream",
				"Cache-Control": "no-store",
				Connection: "keep-alive",
				"X-Accel-Buffering": "no",
				"X-Content-Type-Options": "nosniff",
			},
		});
	}

	async #send(request: Request, projection: DirectChildProjection, permission: PermissionRecord): Promise<Response> {
		const contentLength = Number(request.headers.get("content-length") ?? 0);
		if (!Number.isFinite(contentLength) || contentLength > MAX_BODY_BYTES)
			return response(413, { error: "body_too_large" });
		if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) {
			return response(415, { error: "unsupported_media_type" });
		}
		let text: string;
		try {
			text = await request.text();
		} catch {
			return response(400, { error: "invalid_body" });
		}
		if (Buffer.byteLength(text, "utf8") > MAX_BODY_BYTES) return response(413, { error: "body_too_large" });
		let body: unknown;
		try {
			body = JSON.parse(text);
		} catch {
			return response(400, { error: "invalid_json" });
		}
		if (!body || typeof body !== "object") return response(400, { error: "invalid_body" });
		const candidate = body as Partial<SendRequestDTO>;
		if (
			candidate.version !== AGENT_CONTROL_PROTOCOL_VERSION ||
			typeof candidate.commandId !== "string" ||
			typeof candidate.prompt !== "string"
		) {
			return response(400, { error: "invalid_body" });
		}
		const commandId = candidate.commandId;
		const prompt = candidate.prompt;
		if (!commandId.startsWith(`${permission.generation}:`) || commandId.length > MAX_COMMAND_ID_CHARS) {
			return response(400, { error: "invalid_command_id" });
		}
		if (prompt.length === 0 || prompt.length > MAX_PROMPT_CHARS) return response(413, { error: "invalid_prompt" });

		let result = permission.ledger.get(commandId);
		if (!result) {
			if (permission.ledger.size >= MAX_LEDGER_RESULTS) {
				return response(
					503,
					sendRejection(
						permission,
						commandId,
						"unavailable",
						"Agent pane command ledger is full. Reconnect the pane and try again.",
					),
				);
			}
			if (this.#queuedSends >= MAX_QUEUED_SENDS) {
				return response(
					503,
					sendRejection(permission, commandId, "unavailable", "Agent pane send queue is full. Try again."),
				);
			}
			this.#queuedSends += 1;
			result = projection
				.send(permission.childId, prompt)
				.then(sendResult => ({
					version: AGENT_CONTROL_PROTOCOL_VERSION,
					generation: permission.generation,
					childId: permission.childId,
					commandId,
					result: sendResult,
				}))
				.finally(() => {
					this.#queuedSends -= 1;
				});
			permission.ledger.set(commandId, result);
		}
		const deadline = Promise.withResolvers<undefined>();
		const timer = setTimeout(() => deadline.resolve(undefined), REQUEST_DEADLINE_MS);
		timer.unref?.();
		try {
			const settled = await Promise.race([result, deadline.promise]);
			return settled ? response(200, settled) : response(504, { error: "deadline_exceeded", commandId });
		} finally {
			clearTimeout(timer);
		}
	}
}

export interface AgentControlExtensionHost {
	readonly endpoint: string;
	getGeneration(): string;
	getChildren(): ChildSnapshotDTO[];
	onInvalidation(listener: ProjectionListener): () => void;
	createPermissionSet(childId: string): ChildPermissionSet | undefined;
}

/** Lazily acquired top-level host. Merely constructing/binding it allocates no listener or projection subscriptions. */
export class LazyAgentControlHost implements DirectChildControlSource, AgentControlExtensionHost {
	readonly #eventBus: EventBus;
	readonly #registry: AgentRegistry;
	readonly #lifecycle: () => AgentLifecycleManager;
	#projection: DirectChildProjection | undefined;
	#server: AgentControlServer | undefined;
	#sessionUnsubscribe: (() => void) | undefined;
	readonly #listeners = new Set<ProjectionListener>();
	#projectionUnsubscribe: (() => void) | undefined;
	#acquired = false;

	constructor(
		eventBus: EventBus,
		registry: AgentRegistry,
		lifecycle: AgentLifecycleManager | (() => AgentLifecycleManager),
	) {
		this.#eventBus = eventBus;
		this.#registry = registry;
		this.#lifecycle = typeof lifecycle === "function" ? lifecycle : () => lifecycle;
	}

	get endpoint(): string {
		return this.#server?.endpoint ?? "";
	}

	acquire(): AgentControlExtensionHost {
		this.#acquired = true;
		if (!this.#projection) this.#rotate();
		return this;
	}

	bindSession(session: Pick<AgentSession, "onSessionGenerationCommitted">): void {
		this.#sessionUnsubscribe?.();
		this.#sessionUnsubscribe = session.onSessionGenerationCommitted(() => {
			if (this.#acquired) this.#rotate();
		});
	}

	capture(): DirectChildControlAdmission | undefined {
		return this.#projection?.capture();
	}

	getProjection(): DirectChildProjection | undefined {
		return this.#projection;
	}

	getGeneration(): string {
		return this.#projection?.generation ?? "";
	}

	getChildren(): ChildSnapshotDTO[] {
		return this.#projection?.list() ?? [];
	}

	onInvalidation(listener: ProjectionListener): () => void {
		this.#listeners.add(listener);
		return () => this.#listeners.delete(listener);
	}

	createPermissionSet(childId: string): ChildPermissionSet | undefined {
		return this.#server?.grant(childId);
	}

	async close(): Promise<void> {
		this.#sessionUnsubscribe?.();
		this.#sessionUnsubscribe = undefined;
		this.#projectionUnsubscribe?.();
		this.#projectionUnsubscribe = undefined;
		this.#server?.revokeAll();
		this.#projection?.close();
		this.#projection = undefined;
		this.#listeners.clear();
		const server = this.#server;
		this.#server = undefined;
		if (server) await server.close();
	}

	#rotate(): void {
		this.#server?.revokeAll();
		this.#projection?.close();
		this.#projectionUnsubscribe?.();
		this.#projection = new DirectChildProjection(secureToken(), this.#eventBus, this.#registry, this.#lifecycle());
		this.#projectionUnsubscribe = this.#projection.onInvalidation(invalidation => {
			for (const listener of this.#listeners) {
				try {
					listener(invalidation);
				} catch {}
			}
		});
		this.#server ??= new AgentControlServer(this);
	}
}

const HOST_BY_EVENT_BUS = new WeakMap<EventBus, LazyAgentControlHost>();

export function bindAgentControlExtensionHost(eventBus: EventBus, host: LazyAgentControlHost): () => void {
	HOST_BY_EVENT_BUS.set(eventBus, host);
	return () => {
		if (HOST_BY_EVENT_BUS.get(eventBus) === host) HOST_BY_EVENT_BUS.delete(eventBus);
	};
}

export function acquireAgentControlExtensionHost(eventBus: EventBus): AgentControlExtensionHost | undefined {
	return HOST_BY_EVENT_BUS.get(eventBus)?.acquire();
}
