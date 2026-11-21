/**
 * Installs what the benchmarks and the model's training run beside this library, under the data root
 * (eval/data-root.ts): the five scanner binaries eval/baselines.py compares against, in tools/bin, and a Python
 * environment, tools/venv, with the two Python scanners, the model's trainer and the parquet reader the build scripts
 * use (eval/requirements.txt). The versions are the ones the published numbers were measured with.
 *
 *   node scripts/tools.ts [scanners] [python]        (neither named: both)
 *
 * Then: python3 -I eval/baselines.py --bin $REDACT_CORPORA/tools/bin --venv $REDACT_CORPORA/tools/venv …
 *
 * Linux on arm64 or x64, with `tar`, and `python3` for the environment. Each archive is checked against the hash its
 * release published (Nosey Parker's release publishes none: its hashes are of the archives as first downloaded).
 */
import { execFileSync, type ExecFileSyncOptions } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { CORPORA } from "../eval/data-root.ts";

type Arch = "arm64" | "x64";

interface Scanner {
	name: string;
	/** The release archive for an architecture. */
	url(arch: Arch): string;
	/** The binary's path inside the archive. */
	binary: string;
	sha256: Record<Arch, string>;
}

const SCANNERS: Scanner[] = [
	{
		name: "gitleaks",
		url: (arch) =>
			`https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_${arch}.tar.gz`,
		binary: "gitleaks",
		sha256: {
			arm64: "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080",
			x64: "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
		},
	},
	{
		name: "betterleaks",
		url: (arch) =>
			`https://github.com/betterleaks/betterleaks/releases/download/v1.9.0/betterleaks_1.9.0_linux_${arch}.tar.gz`,
		binary: "betterleaks",
		sha256: {
			arm64: "1d39116e0a58dc94574715e2aa12a2dbd5062f193eee3fec011fef6ba06bd13b",
			x64: "f8b185a39ffcece2a1ca82bf3a4e7435cd81963ffd16b7a9128daf75f35f6de7",
		},
	},
	{
		name: "kingfisher",
		url: (arch) => `https://github.com/mongodb/kingfisher/releases/download/v2.11.1/kingfisher-linux-${arch}.tgz`,
		binary: "kingfisher",
		sha256: {
			arm64: "da7508a90ff36337b41d12e63814cca3ac5586abdcf8c194898059c1ed5e1f81",
			x64: "84e4a4c45814f05e80aa8eee768e5170d758736fa116ffaf03565da4d5a77447",
		},
	},
	{
		name: "trufflehog",
		url: (arch) =>
			`https://github.com/trufflesecurity/trufflehog/releases/download/v3.99.2/trufflehog_3.99.2_linux_${arch === "x64" ? "amd64" : arch}.tar.gz`,
		binary: "trufflehog",
		sha256: {
			arm64: "929b81efffca752eafd58bf6f17bf725d354f338636a7bbbee65c086d2f9ddf3",
			x64: "3c7b0d1dc4278294269bfdd7594bca8bb28c78da0a4a06ad202ded37b48deca4",
		},
	},
	{
		name: "noseyparker",
		url: (arch) =>
			`https://github.com/praetorian-inc/noseyparker/releases/download/v0.24.0/noseyparker-v0.24.0-${arch === "x64" ? "x86_64" : "aarch64"}-unknown-linux-gnu.tar.gz`,
		binary: "bin/noseyparker",
		sha256: {
			arm64: "9b7e0294c7a0a49942b459bcfa46d57e7f4a01a675e20c51ab8069ef30088edf",
			x64: "1bd04ea06ce886a7cd1995a814c5570be01b019adacf27fd158cbdfb01da1f3c",
		},
	},
];

const TOOLS = join(CORPORA, "tools");

async function installScanners(): Promise<void> {
	const arch = process.arch;
	if (process.platform !== "linux" || (arch !== "arm64" && arch !== "x64"))
		throw new Error(`the scanner archives listed here are for Linux on arm64 or x64, not ${process.platform} ${arch}`);
	const bin = join(TOOLS, "bin");
	mkdirSync(bin, { recursive: true });
	const tmp = mkdtempSync(join(TOOLS, "unpack-"));
	try {
		for (const scanner of SCANNERS) {
			const res = await fetch(scanner.url(arch));
			if (!res.ok) throw new Error(`${res.status} for ${scanner.url(arch)}`);
			const archive = Buffer.from(await res.arrayBuffer());
			const sha256 = createHash("sha256").update(archive).digest("hex");
			if (sha256 !== scanner.sha256[arch])
				throw new Error(`${scanner.name}: the archive's hash is ${sha256}, not the ${scanner.sha256[arch]} listed`);
			const dir = join(tmp, scanner.name);
			mkdirSync(dir);
			writeFileSync(join(dir, "archive"), archive);
			execFileSync("tar", ["-xzf", join(dir, "archive"), "-C", dir], { stdio: ["ignore", "ignore", "inherit"] });
			copyFileSync(join(dir, scanner.binary), join(bin, scanner.name));
			chmodSync(join(bin, scanner.name), 0o755);
			console.log(`${scanner.name}: ${join(bin, scanner.name)}`);
		}
	} finally {
		rmSync(tmp, { recursive: true, force: true });
	}
}

function installPython(): void {
	const venv = join(TOOLS, "venv");
	const quiet: ExecFileSyncOptions = { stdio: ["ignore", "ignore", "inherit"] };
	if (!existsSync(join(venv, "bin/python"))) execFileSync("python3", ["-m", "venv", venv], quiet);
	const requirements = join(import.meta.dirname, "../eval/requirements.txt");
	execFileSync(join(venv, "bin/python"), ["-m", "pip", "install", "--quiet", "-r", requirements], quiet);
	console.log(`python: ${venv}`);
}

const wanted = process.argv.slice(2);
try {
	if (wanted.some((w) => w !== "scanners" && w !== "python"))
		throw new Error("usage: node scripts/tools.ts [scanners] [python]");
	if (!wanted.length || wanted.includes("scanners")) await installScanners();
	if (!wanted.length || wanted.includes("python")) installPython();
} catch (e) {
	console.error(`tools: ${(e as Error).message}`);
	process.exitCode = 1;
}
