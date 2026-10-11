/**
 * Builds the real-text corpora used to measure false redactions: chunks of public repositories and
 * public coding-agent trajectories, split by source into dev and test so the test split never informs
 * tuning. Everything lives under ~/Downloads/redact-corpora (third-party text, never committed).
 *
 *   node scripts/build-negatives.ts
 */
import {
	createReadStream,
	createWriteStream,
	existsSync,
	mkdirSync,
	readdirSync,
	readFileSync,
	statSync,
} from "node:fs";
import { extname, join, relative } from "node:path";
import { createInterface } from "node:readline";
import { CORPORA } from "../eval/data-root.ts";
import { mulberry32 } from "../eval/random.ts";

const ROOT = CORPORA;
const REPOS = join(ROOT, "repos");
const OUT = join(ROOT, "built");

/** Repositories held out for the final test. Everything else is dev. */
const TEST_REPOS = new Set([
	"grafana_grafana",
	"rails_rails",
	"spring-projects_spring-boot",
	"argoproj_argo-cd",
	"n8n-io_n8n",
	"mastodon_mastodon",
	"discourse_discourse",
	"aws_aws-cli",
	"twilio_twilio-python",
	"hist_pallets_flask",
	"openai_openai-cookbook",
	"Azure_azure-cli",
]);
const TEST_TRAJ = /nebius_SWE-agent-trajectories.*00005|SWE-Gym|Kwai.*00001/;

const TEXT_EXT = new Set([
	".go",
	".py",
	".ts",
	".tsx",
	".js",
	".jsx",
	".mjs",
	".cjs",
	".rb",
	".java",
	".kt",
	".rs",
	".c",
	".h",
	".cc",
	".cpp",
	".cs",
	".php",
	".swift",
	".scala",
	".sh",
	".bash",
	".zsh",
	".ps1",
	".md",
	".rst",
	".txt",
	".yaml",
	".yml",
	".json",
	".toml",
	".ini",
	".cfg",
	".conf",
	".env",
	".properties",
	".xml",
	".html",
	".css",
	".scss",
	".sql",
	".lock",
	".sum",
	".mod",
	".tf",
	".hcl",
	".log",
	".csv",
	".gradle",
	".erb",
	".j2",
	".tpl",
	".dockerfile",
	".ipynb",
	".svg",
	".pem",
	".crt",
	".map",
	"",
]);
const NAMES = new Set([
	"Dockerfile",
	"Makefile",
	"Gemfile",
	"Gemfile.lock",
	"go.sum",
	"Cargo.lock",
	"package-lock.json",
	"yarn.lock",
	"pnpm-lock.yaml",
	"poetry.lock",
	"requirements.txt",
]);

/** Deterministic PRNG, so the corpora rebuild identically. */
const rng = mulberry32;

function* walk(dir: string): Generator<string> {
	let entries;
	try {
		entries = readdirSync(dir, { withFileTypes: true });
	} catch {
		return;
	}
	for (const e of entries) {
		if (e.name === ".git" || e.name === "node_modules") continue;
		const p = join(dir, e.name);
		if (e.isDirectory()) yield* walk(p);
		else if (e.isFile()) yield p;
	}
}

/** Splits text into chunks of about `size` characters at line boundaries. */
function chunks(text: string, size: number): string[] {
	const out: string[] = [];
	let at = 0;
	while (at < text.length) {
		let end = Math.min(text.length, at + size);
		if (end < text.length) {
			const nl = text.indexOf("\n", end);
			end = nl < 0 || nl - at > size * 2 ? end : nl + 1;
		}
		out.push(text.slice(at, end));
		at = end;
	}
	return out;
}

mkdirSync(OUT, { recursive: true });
const writers = { dev: createWriteStream(join(OUT, "dev.jsonl")), test: createWriteStream(join(OUT, "test.jsonl")) };
const sizes = { dev: 0, test: 0 };
function emit(split: "dev" | "test", src: string, text: string, extra: Record<string, unknown> = {}) {
	writers[split].write(
		JSON.stringify({ src, text, ...extra }).replace(
			/[\u2028\u2029\u0085]/g,
			(c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`,
		) + "\n",
	);
	sizes[split] += text.length;
}

/** Up to this many characters per repository, sampled evenly over its text files. */
const PER_REPO = 12_000_000;
for (const repo of readdirSync(REPOS).sort()) {
	const split = TEST_REPOS.has(repo) ? "test" : "dev";
	const files = [...walk(join(REPOS, repo))].filter((p) => {
		const base = p.slice(p.lastIndexOf("/") + 1);
		return NAMES.has(base) || TEXT_EXT.has(extname(p).toLowerCase());
	});
	const rand = rng(repo.length * 7919 + repo.charCodeAt(0));
	files.sort(() => rand() - 0.5);
	let used = 0;
	for (const p of files) {
		if (used >= PER_REPO) break;
		let st;
		try {
			st = statSync(p);
		} catch {
			continue;
		}
		if (st.size > 2_000_000 || st.size < 10) continue;
		const buf = readFileSync(p);
		if (buf.subarray(0, 8000).includes(0)) continue;
		const text = buf.toString("utf8");
		const rel = relative(REPOS, p);
		for (const c of chunks(text, 8000)) emit(split, `repo:${rel}`, c);
		used += text.length;
	}
	console.error(repo, split, used);
}

// Agent trajectories: every tool output and message, deduplicated (system prompts repeat).
const seen = new Set<string>();
const traj = join(ROOT, "text/trajectories.jsonl");
if (existsSync(traj)) {
	const rl = createInterface({ input: createReadStream(traj) });
	for await (const line of rl) {
		const row = JSON.parse(line) as { src: string; role: string; text: string };
		const key = row.text.slice(0, 300);
		if (seen.has(key)) continue;
		seen.add(key);
		const split = TEST_TRAJ.test(row.src) ? "test" : "dev";
		for (const c of chunks(row.text, 8000)) emit(split, `traj:${row.src}:${row.role}`, c);
	}
}
writers.dev.end();
writers.test.end();
console.error(sizes);
