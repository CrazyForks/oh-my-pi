import { afterEach, describe, expect, it, vi } from "bun:test";
import * as git from "@oh-my-pi/pi-coding-agent/utils/git";
import type { Subprocess } from "bun";

type SpawnOptions = Bun.SpawnOptions.SpawnOptions<
	Bun.SpawnOptions.Writable,
	Bun.SpawnOptions.Readable,
	Bun.SpawnOptions.Readable
>;

type SpawnCall = {
	cmd: string[];
	options: SpawnOptions;
};

function createTextStream(text: string): ReadableStream<Uint8Array> {
	const body = new Response(text).body;
	if (!body) {
		throw new Error("Failed to create response stream.");
	}
	return body;
}

function createFakeProcess(stdout = "", stderr = "", exitCode: number | Promise<number> = 0): Subprocess {
	return {
		pid: 12345,
		stdout: createTextStream(stdout),
		stderr: createTextStream(stderr),
		exited: typeof exitCode === "number" ? Promise.resolve(exitCode) : exitCode,
		kill: vi.fn(),
	} as unknown as Subprocess;
}

function createSpawnMock(calls: SpawnCall[]) {
	function mockSpawn(options: SpawnOptions & { cmd: string[] }): Subprocess;
	function mockSpawn(cmd: string[], options?: SpawnOptions): Subprocess;
	function mockSpawn(first: string[] | (SpawnOptions & { cmd: string[] }), second?: SpawnOptions): Subprocess {
		if (Array.isArray(first)) {
			calls.push({ cmd: first, options: second ?? ({} as SpawnOptions) });
		} else {
			const { cmd, ...options } = first;
			calls.push({ cmd, options });
		}
		return createFakeProcess();
	}

	return mockSpawn;
}

async function withEnvOverrides<T>(
	overrides: readonly (readonly [key: string, value: string | undefined])[],
	run: () => Promise<T>,
): Promise<T> {
	const previous = new Map<string, string | undefined>();
	for (const [key, value] of overrides) {
		previous.set(key, process.env[key]);
		if (value === undefined) delete process.env[key];
		else process.env[key] = value;
	}
	try {
		return await run();
	} finally {
		for (const [key, value] of previous) {
			if (value === undefined) delete process.env[key];
			else process.env[key] = value;
		}
	}
}

afterEach(() => {
	vi.restoreAllMocks();
});

describe("git subprocess config", () => {
	it("disables fsmonitor and untracked cache for read-only commands", async () => {
		const spawnCalls: SpawnCall[] = [];
		vi.spyOn(Bun, "spawn").mockImplementation(createSpawnMock(spawnCalls));

		expect(await git.status.summary("/work/pi")).toEqual({ staged: 0, unstaged: 0, untracked: 0 });
		expect(spawnCalls).toHaveLength(1);
		expect(spawnCalls[0]?.cmd).toEqual([
			"git",
			"-c",
			"core.fsmonitor=false",
			"-c",
			"core.untrackedCache=false",
			"--no-optional-locks",
			"status",
			"--porcelain",
		]);
	});

	it("disables fsmonitor and untracked cache for mutating commands", async () => {
		const spawnCalls: SpawnCall[] = [];
		vi.spyOn(Bun, "spawn").mockImplementation(createSpawnMock(spawnCalls));

		await git.stage.files("/work/pi", ["tracked.txt"]);

		expect(spawnCalls).toHaveLength(1);
		expect(spawnCalls[0]?.cmd).toEqual([
			"git",
			"-c",
			"core.fsmonitor=false",
			"-c",
			"core.untrackedCache=false",
			"add",
			"--",
			"tracked.txt",
		]);
	});

	it("scopes pushes to the named refspec, never following tags", async () => {
		const spawnCalls: SpawnCall[] = [];
		vi.spyOn(Bun, "spawn").mockImplementation(createSpawnMock(spawnCalls));

		await git.push("/work/pi", { remote: "fork", refspec: "HEAD:refs/heads/feature" });

		// `--no-follow-tags` must override a user's `push.followTags = true`:
		// implicit tag pushes are rejected on remotes the user cannot tag
		// (e.g. PR-head forks) and fail the call after the branch updated.
		expect(spawnCalls).toHaveLength(1);
		expect(spawnCalls[0]?.cmd).toEqual([
			"git",
			"-c",
			"core.fsmonitor=false",
			"-c",
			"core.untrackedCache=false",
			"push",
			"--no-follow-tags",
			"fork",
			"HEAD:refs/heads/feature",
		]);
	});

	it("forces git subprocesses into non-interactive credential mode", async () => {
		const spawnCalls: SpawnCall[] = [];
		vi.spyOn(Bun, "spawn").mockImplementation(createSpawnMock(spawnCalls));

		await withEnvOverrides(
			[
				["GIT_TERMINAL_PROMPT", undefined],
				["GIT_ASKPASS", undefined],
				["SSH_ASKPASS", undefined],
				["GPG_TTY", undefined],
			],
			() => git.push("/work/pi", { remote: "fork", refspec: "HEAD:refs/heads/feature" }),
		);

		expect(spawnCalls[0]?.options.env).toMatchObject({
			GIT_TERMINAL_PROMPT: "0",
			GIT_ASKPASS: "true",
			SSH_ASKPASS: "/usr/bin/false",
			GPG_TTY: "not a tty",
		});
	});

	it("rejects when a git subprocess never exits", async () => {
		const spawnCalls: SpawnCall[] = [];
		const neverExits = Promise.withResolvers<number>();
		vi.spyOn(Bun, "spawn").mockImplementation(() => {
			const process = createFakeProcess("", "", neverExits.promise);
			spawnCalls.push({ cmd: ["git", "push"], options: {} as SpawnOptions });
			return process;
		});

		const result = await withEnvOverrides([["OMP_GIT_SUBPROCESS_TIMEOUT_MS", "1"]], () =>
			Promise.race([
				git.push("/work/pi", { remote: "fork", refspec: "HEAD:refs/heads/feature" }).then(
					() => "resolved",
					error => error,
				),
				Bun.sleep(50).then(() => "still-running"),
			]),
		);

		expect(result).toBeInstanceOf(Error);
		expect(result).not.toBe("still-running");
		expect(result).not.toBe("resolved");
		expect(spawnCalls).toHaveLength(1);
	});

	it("caps captured git subprocess output", async () => {
		vi.spyOn(Bun, "spawn").mockImplementation(() => createFakeProcess("abcdefghijklmnop"));

		const stdout = await withEnvOverrides([["OMP_GIT_SUBPROCESS_MAX_OUTPUT_BYTES", "8"]], () =>
			git.diff.tree("/work/pi", "base", "head", { allowFailure: true }),
		);

		expect(stdout).toContain("abcdefgh");
		expect(stdout).toContain("truncated 8 bytes after 8 byte limit");
		expect(stdout).not.toContain("ijklmnop");
	});
});
