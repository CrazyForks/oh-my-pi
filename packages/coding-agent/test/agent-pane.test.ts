import { afterEach, beforeAll, describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
	AgentPaneHandoffError,
	consumeAgentPaneHandoff,
	createAgentPaneHandoff,
} from "@oh-my-pi/pi-coding-agent/agent-control/handoff";
import {
	AGENT_CONTROL_PROTOCOL_VERSION,
	type ChildPermissionSet,
	type ChildSnapshotDTO,
	type TranscriptEntryDTO,
} from "@oh-my-pi/pi-coding-agent/agent-control/protocol";
import { commands } from "@oh-my-pi/pi-coding-agent/cli-commands";
import {
	AgentPaneClient,
	AgentPaneComponent,
	AgentPaneSseParser,
	type AgentPaneState,
} from "@oh-my-pi/pi-coding-agent/commands/agent-pane";
import { initTheme } from "@oh-my-pi/pi-coding-agent/modes/theme/theme";

const permission: ChildPermissionSet = {
	version: AGENT_CONTROL_PROTOCOL_VERSION,
	generation: "generation-test",
	childId: "child-test",
	endpoint: "http://127.0.0.1:43210",
	token: "secret-test-capability",
};

const snapshot: ChildSnapshotDTO = {
	version: AGENT_CONTROL_PROTOCOL_VERSION,
	generation: permission.generation,
	id: permission.childId,
	label: "Focused child",
	availability: "idle",
	capability: "send",
	lastOutcome: "failed",
	updatedAt: 1,
};

function transcriptEntry(id: string, text: string): TranscriptEntryDTO {
	return { id, type: "message", role: "assistant", text };
}

function eventStream(): { response: Response; close: () => void } {
	let controller: ReadableStreamDefaultController<Uint8Array> | undefined;
	const body = new ReadableStream<Uint8Array>({
		start: value => {
			controller = value;
		},
	});
	return {
		response: new Response(body, { headers: { "Content-Type": "text/event-stream" } }),
		close: () => controller?.close(),
	};
}
function json(value: unknown, status = 200): Response {
	return Response.json(value, { status });
}

function fixtureFetch(handler: (url: URL, init: RequestInit) => Promise<Response> | Response): typeof fetch {
	return ((input: Parameters<typeof fetch>[0], init: RequestInit = {}) =>
		handler(new URL(String(input)), init)) as typeof fetch;
}

const tempDirs: string[] = [];

beforeAll(async () => {
	await initTheme();
});

afterEach(async () => {
	await Promise.all(tempDirs.splice(0).map(dir => fs.rm(dir, { recursive: true, force: true })));
});

describe("one-shot pane handoff", () => {
	it("publishes an owner-only handoff and consumes it exactly once", async () => {
		if (process.platform === "win32") return;
		const rootDir = await fs.mkdtemp(path.join(os.tmpdir(), "agent-pane-handoff-test-"));
		tempDirs.push(rootDir);
		const locator = await createAgentPaneHandoff(permission, { rootDir });
		const stat = await fs.stat(locator);
		expect(stat.mode & 0o777).toBe(0o600);

		expect(await consumeAgentPaneHandoff(locator, permission.childId, { rootDir })).toEqual(permission);
		await expect(consumeAgentPaneHandoff(locator, permission.childId, { rootDir })).rejects.toMatchObject({
			code: "missing_handoff",
		});
	});

	it("rejects wrong-child, outside, symlink, and permission-invalid locators without disclosing the capability", async () => {
		if (process.platform === "win32") return;
		const rootDir = await fs.mkdtemp(path.join(os.tmpdir(), "agent-pane-handoff-test-"));
		const outsideDir = await fs.mkdtemp(path.join(os.tmpdir(), "agent-pane-outside-test-"));
		tempDirs.push(rootDir, outsideDir);

		const wrongChild = await createAgentPaneHandoff(permission, { rootDir });
		await expect(consumeAgentPaneHandoff(wrongChild, "other-child", { rootDir })).rejects.toBeInstanceOf(
			AgentPaneHandoffError,
		);
		await expect(fs.stat(wrongChild)).rejects.toMatchObject({ code: "ENOENT" });

		const outside = path.join(outsideDir, "handoff-outside.json");
		await fs.writeFile(outside, JSON.stringify(permission), { mode: 0o600 });
		await expect(consumeAgentPaneHandoff(outside, permission.childId, { rootDir })).rejects.toMatchObject({
			code: "invalid_locator",
		});

		const source = path.join(outsideDir, "source.json");
		const symlink = path.join(rootDir, "handoff-00000000-0000-4000-8000-000000000000.json");
		await fs.writeFile(source, JSON.stringify(permission), { mode: 0o600 });
		await fs.symlink(source, symlink);
		await expect(consumeAgentPaneHandoff(symlink, permission.childId, { rootDir })).rejects.toMatchObject({
			code: "missing_handoff",
		});

		const insecure = await createAgentPaneHandoff(permission, { rootDir });
		await fs.chmod(insecure, 0o644);
		let error: unknown;
		try {
			await consumeAgentPaneHandoff(insecure, permission.childId, { rootDir });
		} catch (caught) {
			error = caught;
		}
		expect(error).toMatchObject({ code: "insecure_handoff" });
		expect(String(error)).not.toContain(permission.token);
	});
});

describe("pane protocol and client", () => {
	it("parses fragmented invalidations and rejects malformed frames", () => {
		const parser = new AgentPaneSseParser();
		expect(parser.push('event: invalidation\ndata: {"version":1,')).toEqual([]);
		expect(
			parser.push(`"generation":"${permission.generation}","childId":"${permission.childId}","kind":"state"}\n\n`),
		).toEqual([
			{
				version: AGENT_CONTROL_PROTOCOL_VERSION,
				generation: permission.generation,
				childId: permission.childId,
				kind: "state",
			},
		]);
		expect(() => new AgentPaneSseParser().push("event: invalidation\ndata: nope\n\n")).toThrow();
	});

	it("replays transcript pages from the returned byte cursor and sanitizes display text", async () => {
		const cursors: string[] = [];
		const client = new AgentPaneClient(permission, {
			fetch: fixtureFetch(url => {
				if (url.pathname === "/v1/snapshot") return json(snapshot);
				if (url.pathname === "/v1/transcript") {
					const cursor = url.searchParams.get("fromByte") ?? "";
					cursors.push(cursor);
					return cursor === "0"
						? json({
								version: 1,
								generation: permission.generation,
								childId: permission.childId,
								fromByte: 0,
								nextByte: 10,
								reset: false,
								entries: [transcriptEntry("one", "safe\u001b[31m red\ttext")],
							})
						: json({
								version: 1,
								generation: permission.generation,
								childId: permission.childId,
								fromByte: 10,
								nextByte: 10,
								reset: false,
								entries: [],
							});
				}
				return json({ error: "unauthorized" }, 401);
			}),
		});
		await client.start();
		expect(cursors.slice(0, 2)).toEqual(["0", "10"]);
		expect(client.state.entries[0]?.text).toBe("safe red   text");
		client.close();
	});

	it("cancels an abandoned stream before reconnecting when post-connect reconciliation fails", async () => {
		const events: string[] = [];
		const secondRequested = Promise.withResolvers<void>();
		const firstBody = new ReadableStream<Uint8Array>({
			cancel: () => {
				events.push("first canceled");
			},
		});
		const second = eventStream();
		let snapshots = 0;
		let streams = 0;
		const client = new AgentPaneClient(permission, {
			reconnectDelayMs: 0,
			fetch: fixtureFetch(url => {
				if (url.pathname === "/v1/snapshot") {
					snapshots += 1;
					return snapshots === 2 ? json({ error: "temporarily_unavailable" }, 503) : json(snapshot);
				}
				if (url.pathname === "/v1/transcript")
					return json({
						version: 1,
						generation: permission.generation,
						childId: permission.childId,
						fromByte: 0,
						nextByte: 0,
						reset: false,
						entries: [],
					});
				if (url.pathname === "/v1/stream") {
					streams += 1;
					if (streams === 1) return new Response(firstBody, { headers: { "Content-Type": "text/event-stream" } });
					events.push("second requested");
					secondRequested.resolve();
					return second.response;
				}
				return json({ error: "not_found" }, 404);
			}),
		});

		await client.start();
		await secondRequested.promise;
		expect(events).toEqual(["first canceled", "second requested"]);
		client.close();
		second.close();
	});

	it("uses one generation-scoped command id and never retries an ambiguous mutation", async () => {
		let sends = 0;
		let commandId = "";
		const stream = eventStream();
		const client = new AgentPaneClient(permission, {
			fetch: fixtureFetch(async (url, init) => {
				if (url.pathname === "/v1/snapshot") return json(snapshot);
				if (url.pathname === "/v1/transcript")
					return json({
						version: 1,
						generation: permission.generation,
						childId: permission.childId,
						fromByte: 0,
						nextByte: 0,
						reset: false,
						entries: [],
					});
				if (url.pathname === "/v1/stream") return stream.response;
				if (url.pathname === "/v1/send") {
					sends += 1;
					commandId = (JSON.parse(String(init.body)) as { commandId: string }).commandId;
					throw new Error("lost acknowledgement");
				}
				return json({ error: "not_found" }, 404);
			}),
		});
		await client.start();
		await client.send("continue once");
		expect(sends).toBe(1);
		expect(commandId.startsWith(`${permission.generation}:`)).toBe(true);
		expect(client.state.connection).toBe("outcome_unknown");
		expect(client.canSend).toBe(false);
		client.close();
		stream.close();
	});

	it("keeps the pane usable after a typed pre-dispatch send rejection", async () => {
		const stream = eventStream();
		const client = new AgentPaneClient(permission, {
			fetch: fixtureFetch((url, init) => {
				if (url.pathname === "/v1/snapshot") return json(snapshot);
				if (url.pathname === "/v1/transcript")
					return json({
						version: 1,
						generation: permission.generation,
						childId: permission.childId,
						fromByte: 0,
						nextByte: 0,
						reset: false,
						entries: [],
					});
				if (url.pathname === "/v1/stream") return stream.response;
				if (url.pathname === "/v1/send") {
					const commandId = (JSON.parse(String(init.body)) as { commandId: string }).commandId;
					return json(
						{
							version: AGENT_CONTROL_PROTOCOL_VERSION,
							generation: permission.generation,
							childId: permission.childId,
							commandId,
							result: { ok: false, code: "unavailable", message: "send queue full" },
						},
						503,
					);
				}
				return json({ error: "not_found" }, 404);
			}),
		});

		await client.start();
		const result = await client.send("continue once");
		expect(result?.result).toEqual({ ok: false, code: "unavailable", message: "send queue full" });
		expect(client.state.connection).toBe("connected");
		expect(client.state.notice).toBe("send queue full");
		expect(client.canSend).toBe(true);
		client.close();
		stream.close();
	});

	it("closes the viewer without sending an agent mutation", async () => {
		let sends = 0;
		const stream = eventStream();
		const client = new AgentPaneClient(permission, {
			fetch: fixtureFetch(url => {
				if (url.pathname === "/v1/snapshot") return json(snapshot);
				if (url.pathname === "/v1/transcript")
					return json({
						version: 1,
						generation: permission.generation,
						childId: permission.childId,
						fromByte: 0,
						nextByte: 0,
						reset: false,
						entries: [],
					});
				if (url.pathname === "/v1/stream") return stream.response;
				if (url.pathname === "/v1/send") sends += 1;
				return json({ error: "not_found" }, 404);
			}),
		});
		await client.start();
		client.close();
		stream.close();
		expect(sends).toBe(0);
	});

	it("freezes immediately on unauthorized, malformed, and permanently missing parents", async () => {
		const cases: Array<{ response: () => Promise<Response> | Response; expected: AgentPaneState["connection"] }> = [
			{ response: () => json({ error: "unauthorized" }, 401), expected: "revoked" },
			{ response: () => json({ version: 999, generation: "wrong", childId: "wrong" }), expected: "protocol_error" },
			{ response: () => Promise.reject(new Error("parent gone")), expected: "parent_lost" },
		];
		for (const scenario of cases) {
			const client = new AgentPaneClient(permission, { fetch: fixtureFetch(() => scenario.response()) });
			await client.start();
			expect(client.state.connection).toBe(scenario.expected);
			expect(client.canSend).toBe(false);
			client.close();
		}
	});
});

describe("pane TUI", () => {
	function state(
		connection: AgentPaneState["connection"],
		availability: ChildSnapshotDTO["availability"] = snapshot.availability,
		capability: ChildSnapshotDTO["capability"] = snapshot.capability,
	): AgentPaneState {
		return {
			connection,
			snapshot: { ...snapshot, availability, capability },
			entries: [transcriptEntry("one", "line\u001b]0;hostile\u0007\tvalue")],
		};
	}

	it("renders text-labelled connection, capability, outcome, sanitized transcript, and legal actions", () => {
		const component = new AgentPaneComponent(
			() => 12,
			() => true,
			() => {},
		);
		component.setState(state("connected"));
		const idle = component.render(120).join("\n");
		expect(idle).toContain("Connection: connected");
		expect(idle).toContain("Availability / capability: idle / send");
		expect(idle).toContain("Last outcome: failed");
		expect(idle).toContain("Prompt editing");
		expect(idle).not.toContain("\u001b]0;hostile");

		component.setState(state("connected", "parked", "transcript_only"));
		expect(component.render(120).join("\n")).toContain("parked / transcript only");
		component.setState(state("generation_closed"));
		expect(component.render(120).join("\n")).toContain("Prompt disabled: while generation closed");
	});

	it("keeps prompt and transcript navigation keys separate and reports anchored new output", () => {
		let sent = "";
		const component = new AgentPaneComponent(
			() => 8,
			value => {
				sent = value;
				return true;
			},
			() => {},
		);
		component.setState({
			...state("connected"),
			entries: Array.from({ length: 12 }, (_, index) => transcriptEntry(String(index), `entry ${index}`)),
		});
		component.render(60);
		component.handleInput("draft");
		component.handleInput("\r");
		expect(sent).toBe("draft");

		component.handleInput("\t");
		component.handleInput("\x1b[5~");
		component.setState({
			...state("connected"),
			entries: Array.from({ length: 14 }, (_, index) => transcriptEntry(String(index), `entry ${index}`)),
		});
		const anchored = component.render(60).join("\n");
		expect(anchored).toContain("2 new transcript entries");
		expect(anchored).toContain("Transcript navigation");
	});

	it("distinguishes running, revivable, terminal, reconnecting, unknown-outcome, and parent-loss states in text", () => {
		const component = new AgentPaneComponent(
			() => 12,
			() => true,
			() => {},
		);
		const cases: Array<{ state: AgentPaneState; labels: string[] }> = [
			{
				state: state("connected", "running", "send"),
				labels: ["Connection: connected", "running / send", "Prompt editing"],
			},
			{ state: state("connected", "parked", "send"), labels: ["parked / send", "Prompt editing"] },
			{
				state: state("connected", "aborted", "transcript_only"),
				labels: ["aborted / transcript only", "Prompt disabled"],
			},
			{
				state: state("reconnecting", "running", "send"),
				labels: ["Connection: reconnecting", "Prompt disabled: while reconnecting"],
			},
			{
				state: state("outcome_unknown", "idle", "send"),
				labels: ["Connection: outcome unknown", "Prompt disabled: while outcome unknown"],
			},
			{
				state: state("parent_lost", "idle", "send"),
				labels: ["Connection: parent lost", "Prompt disabled: while parent lost"],
			},
		];
		for (const scenario of cases) {
			component.setState(scenario.state);
			const rendered = component.render(120).join("\n");
			for (const label of scenario.labels) expect(rendered).toContain(label);
		}
	});

	it("preserves a reconnecting draft while preventing submission", () => {
		const sends: string[] = [];
		const component = new AgentPaneComponent(
			() => 10,
			value => {
				sends.push(value);
				return true;
			},
			() => {},
		);
		component.setState(state("reconnecting", "running", "send"));
		component.handleInput("preserved draft");
		component.handleInput("\r");
		expect(sends).toEqual([]);
		component.setState(state("connected", "idle", "send"));
		component.handleInput("\r");
		expect(sends).toEqual(["preserved draft"]);
	});

	it("restores the submitted draft when the sidecar rejects before dispatch", async () => {
		const component = new AgentPaneComponent(
			() => 10,
			() => false,
			() => {},
		);
		component.setState(state("connected", "idle", "send"));
		component.handleInput("retry later");
		component.handleInput("\r");
		await Promise.resolve();

		expect(component.render(60).join("\n")).toContain("retry later");
	});
});

describe("hidden command packaging", () => {
	it("registers the packaged source command as hidden", async () => {
		const entry = commands.find(command => command.name === "__agent-pane");
		expect(entry).toBeDefined();
		const Command = await entry!.load();
		expect(Command.hidden).toBe(true);
	});

	it("ships source and bundles the command-table import graph for npm/Bun", async () => {
		const packageDir = path.resolve(import.meta.dir, "..");
		const manifest = (await Bun.file(path.join(packageDir, "package.json")).json()) as {
			files: string[];
			bin: { omp: string };
		};
		const bundleScript = await Bun.file(path.join(packageDir, "scripts", "bundle-dist.ts")).text();
		expect(manifest.files).toContain("src");
		expect(manifest.bin.omp).toBe("src/cli.ts");
		expect(bundleScript).toContain('"./src/cli.ts"');
	});
});
