import * as fs from "node:fs/promises";
import * as path from "node:path";
import { $which, logger } from "@oh-my-pi/pi-utils";

/** Default cap on a single `direnv` invocation. The first export for a devenv
 *  `.envrc` can build a shell; callers may raise this via `bash.direnvLoadTimeoutMs`. */
export const DEFAULT_DIRENV_TIMEOUT_MS = 30_000;

/** Walk up from `startDir` to the nearest directory containing an `.envrc`. */
export async function findEnvrc(startDir: string): Promise<string | null> {
	let dir = path.resolve(startDir);
	for (;;) {
		const candidate = path.join(dir, ".envrc");
		try {
			if ((await fs.stat(candidate)).isFile()) return candidate;
		} catch {
			// no .envrc here — keep walking up
		}
		const parent = path.dirname(dir);
		if (parent === dir) return null;
		dir = parent;
	}
}

export interface DirenvExportDiff {
	/** Variables direnv sets to a concrete value. */
	set: Record<string, string>;
	/** Variables direnv removes (JSON `null`). */
	unset: string[];
}

/** Parse `direnv export json` output (`{VAR: value|null}`) into set/unset halves. */
export function parseDirenvExport(jsonText: string): DirenvExportDiff {
	const trimmed = jsonText.trim();
	if (trimmed.length === 0) return { set: {}, unset: [] };
	let parsed: unknown;
	try {
		parsed = JSON.parse(trimmed);
	} catch {
		return { set: {}, unset: [] };
	}
	const set: Record<string, string> = {};
	const unset: string[] = [];
	if (parsed && typeof parsed === "object") {
		for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
			if (value === null) unset.push(key);
			else if (typeof value === "string") set[key] = value;
		}
	}
	return { set, unset };
}

let direnvLookup: { bin: string | null } | undefined;
function direnvBinary(): string | null {
	if (!direnvLookup) direnvLookup = { bin: $which("direnv") };
	return direnvLookup.bin;
}

/** direnv computes its diff relative to the spawning env; strip any inherited
 *  direnv state so it loads the target `.envrc` from a clean baseline. */
function cleanSpawnEnv(): Record<string, string> {
	const out: Record<string, string> = {};
	for (const [key, value] of Object.entries(Bun.env)) {
		if (value !== undefined && !key.startsWith("DIRENV_")) out[key] = value;
	}
	return out;
}

async function runDirenv(
	bin: string,
	args: string[],
	cwd: string,
	timeoutMs: number,
	env: Record<string, string>,
	signal?: AbortSignal,
): Promise<{ exitCode: number; stdout: string }> {
	// Bail on the caller's cancellation as well as the per-invocation cap so a
	// cold `.envrc` load can't outlive an aborted / short-timeout bash call.
	const abortSignal = signal
		? AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)])
		: AbortSignal.timeout(timeoutMs);
	const proc = Bun.spawn([bin, ...args], {
		cwd,
		env,
		stdout: "pipe",
		stderr: "pipe",
		signal: abortSignal,
	});
	// Drain stdout AND stderr concurrently: a cold `use devenv`/Nix load emits
	// enough diagnostics to fill the stderr pipe and block the child forever if
	// only stdout is read (it would then wait out `timeoutMs`).
	const [stdout] = await Promise.all([
		new Response(proc.stdout as ReadableStream<Uint8Array>).text(),
		new Response(proc.stderr as ReadableStream<Uint8Array>).text(),
	]);
	const exitCode = await proc.exited;
	return { exitCode, stdout };
}

/** Cache the parsed env per resolved `.envrc` + content hash, so the (possibly
 *  slow) first export is paid once and a changed `.envrc` re-loads. */
const exportCache = new Map<string, DirenvExportDiff>();

/**
 * Resolve the nearest `.envrc` from `cwd`, auto-allow it, and return its
 * `direnv export` diff (variables to set, and variables direnv removes).
 * Returns `null` when there is no `.envrc`, `direnv` is not installed, or the
 * export fails/times out.
 *
 * Auto-allow is deliberate: OMP already runs the repository's own code, so its
 * `.envrc` is trusted under the same model rather than forcing a manual
 * `direnv allow`.
 */
export async function loadDirenvEnv(
	cwd: string,
	opts?: { timeoutMs?: number; signal?: AbortSignal },
): Promise<DirenvExportDiff | null> {
	const envrcPath = await findEnvrc(cwd);
	if (!envrcPath) return null;
	const bin = direnvBinary();
	if (!bin) return null;

	let cacheKey: string;
	try {
		const content = await fs.readFile(envrcPath);
		cacheKey = `${envrcPath}\u0000${Bun.hash(content).toString(36)}`;
	} catch {
		return null;
	}
	const cached = exportCache.get(cacheKey);
	if (cached) return cached;

	const dir = path.dirname(envrcPath);
	const timeoutMs = opts?.timeoutMs ?? DEFAULT_DIRENV_TIMEOUT_MS;
	const env = cleanSpawnEnv();
	try {
		await runDirenv(bin, ["allow"], dir, timeoutMs, env, opts?.signal);
		const { exitCode, stdout } = await runDirenv(bin, ["export", "json"], dir, timeoutMs, env, opts?.signal);
		if (exitCode !== 0) {
			logger.warn("direnv export failed", { dir, exitCode });
			return null;
		}
		const diff = parseDirenvExport(stdout);
		exportCache.set(cacheKey, diff);
		return diff;
	} catch (err) {
		logger.warn("direnv load failed", { dir, error: err instanceof Error ? err.message : String(err) });
		return null;
	}
}
