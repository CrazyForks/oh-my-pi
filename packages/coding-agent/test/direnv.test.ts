import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { executeBash } from "@oh-my-pi/pi-coding-agent/exec/bash-executor";
import { findEnvrc, loadDirenvEnv, parseDirenvExport } from "@oh-my-pi/pi-coding-agent/exec/direnv";
import { $which, TempDir } from "@oh-my-pi/pi-utils";

/** Real-direnv cases need the binary on PATH; skip cleanly when it's absent so
 *  the graceful-degradation code path (returns `null`) isn't asserted against. */
const hasDirenv = $which("direnv") !== null;

const tmpDirs: TempDir[] = [];
function tmp(): string {
	const dir = TempDir.createSync("@pi-direnv-");
	tmpDirs.push(dir);
	return dir.path();
}

afterEach(async () => {
	for (const dir of tmpDirs.splice(0)) await dir.remove();
});

describe("findEnvrc", () => {
	it("walks up to the nearest .envrc above the start dir", async () => {
		const root = tmp();
		await Bun.write(path.join(root, ".envrc"), "export A=1\n");
		const nested = path.join(root, "a", "b");
		await fs.mkdir(nested, { recursive: true });

		expect(await findEnvrc(nested)).toBe(path.join(root, ".envrc"));
	});

	it("prefers the nearest .envrc when monorepo dirs nest them", async () => {
		const root = tmp();
		await Bun.write(path.join(root, ".envrc"), "export A=1\n");
		const sub = path.join(root, "pkg");
		await fs.mkdir(sub, { recursive: true });
		await Bun.write(path.join(sub, ".envrc"), "export B=2\n");

		expect(await findEnvrc(sub)).toBe(path.join(sub, ".envrc"));
	});

	it("returns null when no .envrc exists up the tree", async () => {
		const nested = path.join(tmp(), "x", "y");
		await fs.mkdir(nested, { recursive: true });

		expect(await findEnvrc(nested)).toBeNull();
	});
});

describe("parseDirenvExport", () => {
	it("splits set values from null unsets", () => {
		const out = parseDirenvExport('{"FOO":"bar","BAZ":null,"PATH":"/x:/y"}');

		expect(out.set).toEqual({ FOO: "bar", PATH: "/x:/y" });
		expect(out.unset).toEqual(["BAZ"]);
	});

	it("treats empty / whitespace output as no diff", () => {
		expect(parseDirenvExport("")).toEqual({ set: {}, unset: [] });
		expect(parseDirenvExport("  \n")).toEqual({ set: {}, unset: [] });
	});
});

describe.skipIf(!hasDirenv)("loadDirenvEnv (real direnv, auto-allow)", () => {
	// `direnv allow` writes a trust entry into its data dir. Redirect HOME + the
	// XDG dirs to a throwaway tmp so real-direnv cases never leak allow state
	// into the dev/CI user's global direnv store.
	const savedEnv: Record<string, string | undefined> = {};
	beforeEach(() => {
		const home = tmp();
		for (const key of ["HOME", "XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME"]) {
			savedEnv[key] = Bun.env[key];
			Bun.env[key] = path.join(home, key.toLowerCase());
		}
	});
	afterEach(() => {
		for (const [key, value] of Object.entries(savedEnv)) {
			if (value === undefined) delete Bun.env[key];
			else Bun.env[key] = value;
		}
	});

	it("auto-allows an untrusted .envrc and returns its exported vars + PATH additions", async () => {
		const root = tmp();
		await fs.mkdir(path.join(root, "bin"), { recursive: true });
		await Bun.write(path.join(root, ".envrc"), "export DIRENV_FEATURE_TEST=loaded\nPATH_add bin\n");

		const diff = await loadDirenvEnv(root);

		expect(diff?.set.DIRENV_FEATURE_TEST).toBe("loaded");
		expect(diff?.set.PATH).toContain(path.join(root, "bin"));
	});

	it("reports variables a .envrc unsets", async () => {
		const root = tmp();
		await Bun.write(path.join(root, ".envrc"), "unset PI_DIRENV_UNSET_TEST\n");
		// direnv emits a JSON null for a var only when it was present in the
		// spawn env and the `.envrc` removes it, so seed it in the parent env.
		// (Avoid a `DIRENV_`-prefixed name — the loader strips those before spawn.)
		Bun.env.PI_DIRENV_UNSET_TEST = "present";
		try {
			const diff = await loadDirenvEnv(root);
			expect(diff?.set.PI_DIRENV_UNSET_TEST).toBeUndefined();
			expect(diff?.unset).toContain("PI_DIRENV_UNSET_TEST");
		} finally {
			delete Bun.env.PI_DIRENV_UNSET_TEST;
		}
	});

	it("returns null when there is no .envrc to load", async () => {
		expect(await loadDirenvEnv(tmp())).toBeNull();
	});

	it("re-loads when the .envrc content changes (cache keyed by content)", async () => {
		const root = tmp();
		await Bun.write(path.join(root, ".envrc"), "export DIRENV_CACHE_TEST=one\n");
		expect((await loadDirenvEnv(root))?.set.DIRENV_CACHE_TEST).toBe("one");

		await Bun.write(path.join(root, ".envrc"), "export DIRENV_CACHE_TEST=two\n");
		expect((await loadDirenvEnv(root))?.set.DIRENV_CACHE_TEST).toBe("two");
	});
});

describe.skipIf(!hasDirenv)("bash executor direnv wiring (end-to-end)", () => {
	const savedEnv: Record<string, string | undefined> = {};
	beforeEach(() => {
		const home = tmp();
		for (const key of ["HOME", "XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME"]) {
			savedEnv[key] = Bun.env[key];
			Bun.env[key] = path.join(home, key.toLowerCase());
		}
	});
	afterEach(() => {
		for (const [key, value] of Object.entries(savedEnv)) {
			if (value === undefined) delete Bun.env[key];
			else Bun.env[key] = value;
		}
	});

	it("exposes direnv-loaded vars to the command while per-call env still wins", async () => {
		const root = tmp();
		await Bun.write(path.join(root, ".envrc"), "export DIRENV_WIRE_TEST=fromdirenv\nexport OVERRIDE_ME=fromdirenv\n");

		const result = await executeBash('printf "%s|%s" "$DIRENV_WIRE_TEST" "$OVERRIDE_ME"', {
			cwd: root,
			env: { OVERRIDE_ME: "fromcaller" },
		});

		expect(result.output).toContain("fromdirenv|fromcaller");
	});

	it("removes variables the .envrc unsets from the command environment", async () => {
		const root = tmp();
		await Bun.write(path.join(root, ".envrc"), "unset PI_DIRENV_UNSET_E2E\n");
		// Inherited from the process env (as an OMP-provided var would be); the
		// caller does NOT re-supply it, so direnv's unset must strip it. `printenv`
		// exits non-zero and prints nothing when the name is genuinely absent. A
		// unique sessionKey forces a fresh shell that captures the var we just set.
		// (Avoid a `DIRENV_`-prefixed name — the loader strips those before spawn.)
		Bun.env.PI_DIRENV_UNSET_E2E = "leaked";
		try {
			const result = await executeBash('printenv PI_DIRENV_UNSET_E2E; printf "rc=%s" "$?"', {
				cwd: root,
				sessionKey: `direnv-unset-${Date.now()}`,
			});
			expect(result.output).toContain("rc=1");
			expect(result.output).not.toContain("leaked");
		} finally {
			delete Bun.env.PI_DIRENV_UNSET_E2E;
		}
	});
});
