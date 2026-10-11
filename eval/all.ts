/**
 * Every development check in one table: the labelled dev corpora, CredData (dev repositories), adversarial rounds,
 * false redactions per MB of real text, and throughput. The held-out corpus is not included: `node eval/report.ts`
 * scores it (aggregates only) for the README.
 *
 *   node eval/all.ts [--guessing confident]
 */
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { Args } from "./args.ts";
import { CORPORA } from "./data-root.ts";
import { advSets, devSets } from "./sets.ts";
import { join } from "node:path";

const guessing = new Args().opt("guessing", "confident");
const dir = import.meta.dirname;
const run = (script: string, ...args: string[]) =>
	execFileSync(process.execPath, [join(dir, script), "--guessing", guessing, ...args], {
		encoding: "utf8",
		maxBuffer: 1 << 28,
	});

const corpora = [...advSets(), ...devSets()].map((s) => s.file);
for (const line of run("run.ts", "--quiet", ...corpora)
	.trim()
	.split("\n"))
	console.log(line);
// The robustness runner exits non-zero while any case fails; its summary is the last line either way.
let robust: string;
try {
	robust = execFileSync(process.execPath, [join(dir, "adv1-check.ts")], { encoding: "utf8" });
} catch (e) {
	robust = String((e as { stdout?: string }).stdout ?? e);
}
console.log(`robustness: ${robust.trim().split("\n").at(-1)}`);
console.log(run("transcripts.ts", ...corpora.filter((f) => /\/dev/.test(f))).trim());
// (The sets outside the repository, where they are: on a fresh clone, only eval/corpora is scored.)
if (existsSync(join(CORPORA, "CredData"))) console.log(run("creddata.ts", "--split", "dev").trim().split("\n").at(-1));
else console.log(`creddata: skipped (no ${join(CORPORA, "CredData")})`);
if (existsSync(join(CORPORA, "built/dev.jsonl"))) {
	console.log(run("realtext.ts", "--every", "20", "--src", "traj").split("\n")[0]);
	console.log(run("realtext.ts", "--every", "40", "--src", "repo").split("\n")[0]);
} else console.log(`real text: skipped (no ${join(CORPORA, "built/dev.jsonl")})`);
