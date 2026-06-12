import { afterEach, describe, expect, test } from "bun:test";
import {
	acquireAgentControlExtensionHost,
	bindAgentControlExtensionHost,
	LazyAgentControlHost,
} from "@oh-my-pi/pi-coding-agent/agent-control/server";
import { AgentLifecycleManager } from "@oh-my-pi/pi-coding-agent/registry/agent-lifecycle";
import { AgentRegistry } from "@oh-my-pi/pi-coding-agent/registry/agent-registry";
import type { AgentSession } from "@oh-my-pi/pi-coding-agent/session/agent-session";
import { TASK_SUBAGENT_LIFECYCLE_CHANNEL } from "@oh-my-pi/pi-coding-agent/task";
import { EventBus } from "@oh-my-pi/pi-coding-agent/utils/event-bus";

const hosts: LazyAgentControlHost[] = [];
afterEach(async () => {
	await Promise.all(hosts.splice(0).map(host => host.close()));
});

function setup() {
	const events = new EventBus();
	const registry = new AgentRegistry();
	const lifecycle = new AgentLifecycleManager(registry);
	const host = new LazyAgentControlHost(events, registry, lifecycle);
	hosts.push(host);
	return { events, registry, host };
}

async function admit(
	events: EventBus,
	registry: AgentRegistry,
	host: LazyAgentControlHost,
	id: string,
	sessionFile: string,
	session: AgentSession,
): Promise<void> {
	registry.register({ id, displayName: id, kind: "sub", parentId: "Main", session, sessionFile, status: "running" });
	events.emit(TASK_SUBAGENT_LIFECYCLE_CHANNEL, {
		id,
		index: 0,
		agent: "task",
		agentSource: "bundled",
		status: "started",
		sessionFile,
		controlGeneration: host.getGeneration(),
	});
	await Promise.resolve();
}

describe("lazy authenticated agent control sidecar", () => {
	test("allocates no endpoint or generation until an explicitly bound extension acquires it", () => {
		const { events, host } = setup();
		expect(host.endpoint).toBe("");
		expect(host.getGeneration()).toBe("");
		expect(acquireAgentControlExtensionHost(events)).toBeUndefined();

		const unbind = bindAgentControlExtensionHost(events, host);
		expect(acquireAgentControlExtensionHost(events)).toBe(host);
		expect(host.endpoint).toStartWith("http://127.0.0.1:");
		unbind();
		expect(acquireAgentControlExtensionHost(events)).toBeUndefined();
	});

	test("binds each token to one child and rejects unauthenticated and browser-shaped traffic", async () => {
		const { events, registry, host } = setup();
		host.acquire();
		const inert = { steer: async () => {} } as unknown as AgentSession;
		await admit(events, registry, host, "A", "/tmp/a.jsonl", inert);
		await admit(events, registry, host, "B", "/tmp/b.jsonl", inert);
		const permissionA = host.createPermissionSet("A")!;
		const permissionB = host.createPermissionSet("B")!;

		const unauthenticated = await fetch(`${host.endpoint}/v1/snapshot`);
		expect(unauthenticated.status).toBe(401);
		const browser = await fetch(`${host.endpoint}/v1/snapshot`, {
			headers: { authorization: `Bearer ${permissionA.token}`, origin: "https://attacker.invalid" },
		});
		expect(browser.status).toBe(403);
		const queryCredential = await fetch(`${host.endpoint}/v1/snapshot?token=${permissionA.token}`, {
			headers: { authorization: `Bearer ${permissionA.token}` },
		});
		expect(queryCredential.status).toBe(400);
		const wrongHost = await fetch(`${host.endpoint}/v1/snapshot`, {
			headers: { authorization: `Bearer ${permissionA.token}`, host: "attacker.invalid" },
		});
		expect(wrongHost.status).toBe(403);
		const crossSite = await fetch(`${host.endpoint}/v1/snapshot`, {
			headers: { authorization: `Bearer ${permissionA.token}`, "sec-fetch-site": "cross-site" },
		});
		expect(crossSite.status).toBe(403);
		const options = await fetch(`${host.endpoint}/v1/snapshot`, { method: "OPTIONS" });
		expect(options.status).toBe(405);
		const unauthenticatedInvalidBody = await fetch(`${host.endpoint}/v1/send`, { method: "POST", body: "{" });
		expect(unauthenticatedInvalidBody.status).toBe(401);
		const invalidBody = await fetch(`${host.endpoint}/v1/send`, {
			method: "POST",
			headers: { authorization: `Bearer ${permissionA.token}`, "content-type": "application/json" },
			body: "{",
		});
		expect(invalidBody.status).toBe(400);
		const oversizedPrompt = await fetch(`${host.endpoint}/v1/send`, {
			method: "POST",
			headers: { authorization: `Bearer ${permissionA.token}`, "content-type": "application/json" },
			body: JSON.stringify({
				version: 1,
				commandId: `${permissionA.generation}:oversized`,
				prompt: "x".repeat(32 * 1024 + 1),
			}),
		});
		expect(oversizedPrompt.status).toBe(413);
		const snapshotA = (await fetch(`${host.endpoint}/v1/snapshot`, {
			headers: { authorization: `Bearer ${permissionA.token}` },
		}).then(response => response.json())) as { id: string };
		const snapshotB = (await fetch(`${host.endpoint}/v1/snapshot`, {
			headers: { authorization: `Bearer ${permissionB.token}` },
		}).then(response => response.json())) as { id: string };
		expect(snapshotA.id).toBe("A");
		expect(snapshotB.id).toBe("B");
	});

	test("rotates after a committed session mutation and revokes the old permission", async () => {
		const { events, registry, host } = setup();
		let observer: (() => void) | undefined;
		host.bindSession({
			onSessionGenerationCommitted: listener => {
				observer = listener;
				return () => {
					observer = undefined;
				};
			},
		});
		host.acquire();
		await admit(events, registry, host, "A", "/tmp/a.jsonl", { steer: async () => {} } as unknown as AgentSession);
		const oldGeneration = host.getGeneration();
		const permission = host.createPermissionSet("A")!;

		observer?.();
		expect(host.getGeneration()).not.toBe(oldGeneration);
		const response = await fetch(`${host.endpoint}/v1/snapshot`, {
			headers: { authorization: `Bearer ${permission.token}` },
		});
		expect(response.status).toBe(401);
	});

	test("deduplicates accepted generation-scoped command IDs", async () => {
		const { events, registry, host } = setup();
		host.acquire();
		let steers = 0;
		await admit(events, registry, host, "A", "/tmp/a.jsonl", {
			steer: async () => {
				steers += 1;
			},
		} as unknown as AgentSession);
		const permission = host.createPermissionSet("A")!;
		const body = JSON.stringify({ version: 1, commandId: `${permission.generation}:command-1`, prompt: "continue" });
		const request = () =>
			fetch(`${host.endpoint}/v1/send`, {
				method: "POST",
				headers: { authorization: `Bearer ${permission.token}`, "content-type": "application/json" },
				body,
			});
		const [first, repeated] = await Promise.all([request(), request()]);
		expect(first.status).toBe(200);
		expect(repeated.status).toBe(200);
		expect(await first.json()).toEqual(await repeated.json());
		expect(steers).toBe(1);
	});

	test("returns typed rejections for send capacity before dispatch", async () => {
		const { events, registry, host } = setup();
		host.acquire();
		const pending = Promise.withResolvers<void>();
		await admit(events, registry, host, "A", "/tmp/a.jsonl", {
			steer: async () => pending.promise,
		} as unknown as AgentSession);
		const permission = host.createPermissionSet("A")!;
		const requests = Array.from({ length: 17 }, (_, index) =>
			fetch(`${host.endpoint}/v1/send`, {
				method: "POST",
				headers: { authorization: `Bearer ${permission.token}`, "content-type": "application/json" },
				body: JSON.stringify({
					version: 1,
					commandId: `${permission.generation}:command-${index}`,
					prompt: `continue ${index}`,
				}),
			}),
		);
		const rejected = await Promise.any(
			requests.map(async request => {
				const response = await request;
				if (response.status !== 503) throw new Error(`unexpected status ${response.status}`);
				return response;
			}),
		);
		const body = await rejected.json();
		if (!body || typeof body !== "object" || !("commandId" in body)) {
			throw new Error("typed send rejection omitted commandId");
		}
		pending.resolve();
		await Promise.all(requests);

		expect(body).toMatchObject({
			version: 1,
			generation: permission.generation,
			childId: permission.childId,
			result: { ok: false, code: "unavailable", message: "Agent pane send queue is full. Try again." },
		});
		expect(String(body.commandId)).toStartWith(`${permission.generation}:command-`);
	});
});
