import { describe, expect, it } from "bun:test";
import * as path from "node:path";
import { resetSettingsForTest, Settings } from "@oh-my-pi/pi-coding-agent/config/settings";
import { runRootCommand } from "@oh-my-pi/pi-coding-agent/main";
import { AuthStorage } from "@oh-my-pi/pi-coding-agent/session/auth-storage";
import { TempDir } from "@oh-my-pi/pi-utils";

type HostSettingsSnapshot = {
	todoEnabled: unknown;
	todoReminders: unknown;
	todoEager: unknown;
	taskIsolationMode: unknown;
	taskIsolationMerge: unknown;
	taskIsolationCommits: unknown;
	taskEager: unknown;
	taskBatch: unknown;
	taskMaxConcurrency: unknown;
	taskMaxRecursionDepth: unknown;
	taskDisabledAgents: unknown;
	taskAgentModelOverrides: unknown;
	memoryBackend: unknown;
	memoriesEnabled: unknown;
};

type RpcBackgroundSettingsSnapshot = {
	asyncEnabled: unknown;
	asyncMaxJobs: unknown;
	bashAutoBackground: unknown;
	bashAutoBackgroundThresholdMs: unknown;
};

type ObservedSettingsSnapshot = {
	host: HostSettingsSnapshot;
	rpcBackground: RpcBackgroundSettingsSnapshot;
};

describe("RPC host-defaulted settings", () => {
	const hostConfig = [
		"todo:",
		"  enabled: false",
		"  reminders: false",
		"  eager: always",
		"task:",
		"  isolation:",
		"    mode: auto",
		"    merge: branch",
		"    commits: ai",
		"  eager: always",
		"  batch: false",
		"  maxConcurrency: 2",
		"  maxRecursionDepth: 0",
		"  disabledAgents:",
		"    - explore",
		"    - quick_task",
		"  agentModelOverrides:",
		"    explore: anthropic/claude-test",
		"memory:",
		"  backend: local",
		"memories:",
		"  enabled: true",
		"async:",
		"  enabled: false",
		"  maxJobs: 7",
		"bash:",
		"  autoBackground:",
		"    enabled: true",
		"    thresholdMs: 1234",
		"",
	].join("\n");

	const remindersMaxConfig = ["todo:", "  reminders:", "    max: 5", ""].join("\n");

	function observeHostSettings(settings: Settings): HostSettingsSnapshot {
		return {
			todoEnabled: settings.get("todo.enabled"),
			todoReminders: settings.get("todo.reminders"),
			todoEager: settings.get("todo.eager"),
			taskIsolationMode: settings.get("task.isolation.mode"),
			taskIsolationMerge: settings.get("task.isolation.merge"),
			taskIsolationCommits: settings.get("task.isolation.commits"),
			taskEager: settings.get("task.eager"),
			taskBatch: settings.get("task.batch"),
			taskMaxConcurrency: settings.get("task.maxConcurrency"),
			taskMaxRecursionDepth: settings.get("task.maxRecursionDepth"),
			taskDisabledAgents: settings.get("task.disabledAgents"),
			taskAgentModelOverrides: settings.get("task.agentModelOverrides"),
			memoryBackend: settings.get("memory.backend"),
			memoriesEnabled: settings.get("memories.enabled"),
		};
	}

	function observeRpcBackgroundSettings(settings: Settings): RpcBackgroundSettingsSnapshot {
		return {
			asyncEnabled: settings.get("async.enabled"),
			asyncMaxJobs: settings.get("async.maxJobs"),
			bashAutoBackground: settings.get("bash.autoBackground.enabled"),
			bashAutoBackgroundThresholdMs: settings.get("bash.autoBackground.thresholdMs"),
		};
	}

	async function observeStartupSettings(mode: "rpc" | "acp", configText: string) {
		using tempDir = TempDir.createSync(`@omp-${mode}-host-defaults-`);
		const root = tempDir.path();
		const agentDir = path.join(root, "agent");
		await Bun.write(path.join(agentDir, "config.yml"), configText);
		resetSettingsForTest();
		const settings = await Settings.init({ agentDir, cwd: root });
		const previousNoTitle = Bun.env.PI_NO_TITLE;
		const authStorage = await AuthStorage.create(path.join(root, "auth.db"));
		let observed: ObservedSettingsSnapshot | undefined;
		const stopMessage = "stop after settings observation";
		const capture = (observedSettings: Settings): never => {
			observed = {
				host: observeHostSettings(observedSettings),
				rpcBackground: observeRpcBackgroundSettings(observedSettings),
			};
			throw new Error(stopMessage);
		};

		try {
			await runRootCommand(
				{
					mode,
					messages: [],
					fileArgs: [],
					unknownFlags: new Map(),
					unrecognizedFlags: [],
					noSkills: true,
					noRules: true,
					noTools: true,
					noLsp: true,
					sessionDir: root,
				},
				[],
				{
					discoverAuthStorage: async () => authStorage,
					settings,
					createAgentSession: async (options): Promise<never> => {
						if (!options?.settings) throw new Error("Expected RPC session settings");
						return capture(options.settings);
					},
					runAcpMode: async (): Promise<never> => capture(settings),
				},
			);
		} catch (error) {
			if (!(error instanceof Error) || error.message !== stopMessage) {
				throw error;
			}
		} finally {
			authStorage.close();
			if (previousNoTitle === undefined) {
				delete Bun.env.PI_NO_TITLE;
			} else {
				Bun.env.PI_NO_TITLE = previousNoTitle;
			}
			resetSettingsForTest();
		}

		if (!observed) throw new Error(`Expected ${mode} settings observation`);
		return observed;
	}

	const expectedHostSettings = {
		todoEnabled: false,
		todoReminders: false,
		todoEager: "always",
		taskIsolationMode: "auto",
		taskIsolationMerge: "branch",
		taskIsolationCommits: "ai",
		taskEager: "always",
		taskBatch: false,
		taskMaxConcurrency: 2,
		taskMaxRecursionDepth: 0,
		taskDisabledAgents: ["explore", "quick_task"],
		taskAgentModelOverrides: { explore: "anthropic/claude-test" },
		memoryBackend: "local",
		memoriesEnabled: true,
	};

	it("preserves explicit host-defaulted config values in RPC mode", async () => {
		await expect(observeStartupSettings("rpc", hostConfig)).resolves.toEqual({
			host: expectedHostSettings,
			rpcBackground: {
				asyncEnabled: false,
				asyncMaxJobs: 7,
				bashAutoBackground: true,
				bashAutoBackgroundThresholdMs: 1234,
			},
		});
	});

	it("preserves explicit host-defaulted config values in ACP mode", async () => {
		await expect(observeStartupSettings("acp", hostConfig)).resolves.toMatchObject({
			host: expectedHostSettings,
		});
	});

	it("preserves todo.reminders.max without replacing the reminders object", async () => {
		await expect(observeStartupSettings("rpc", remindersMaxConfig)).resolves.toMatchObject({
			host: {
				todoReminders: { max: 5 },
			},
		});
		await expect(observeStartupSettings("acp", remindersMaxConfig)).resolves.toMatchObject({
			host: {
				todoReminders: { max: 5 },
			},
		});
	});
});
