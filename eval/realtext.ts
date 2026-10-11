/**
 * False redactions on real text: public repositories and public coding-agent trajectories, which hold
 * few real secrets. Reports redactions per MB by rule and by the shape of what was hidden, flags the
 * damaging ones (commit SHAs, digests, UUIDs), and writes samples with context for review.
 *
 *   node eval/realtext.ts [--guessing confident] [--every 10] [--split dev|test|final] [--src traj|repo|gitlog] [--file PATH]
 *
 * `--file` scores any JSONL of {src, text} records (the shared sample eval/baselines.py also scans).
 */
import { createReadStream, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { Redactor, type Guessing } from "../src/index.ts";
import { DAMAGE, shapeOf } from "./shapes.ts";
import { CORPORA } from "./data-root.ts";
import { Args } from "./args.ts";

const args = new Args();
const guessing = args.opt("guessing", "confident") as Guessing;
const every = args.num("every", 10);
const split = args.opt("split", "dev");
const srcFilter = args.opt("src", "");
// `--split final`, `--split final2`, …: fresh sets (new repositories and trajectory shards), each scored
// before any of its output is looked at.
const file = args.opt("file", "");
const corpus = file
	? file
	: /^final\d*$/.test(split)
		? join(CORPORA, `${split}/${split}.jsonl`)
		: join(CORPORA, `built/${split}.jsonl`);

const byRule = new Map<string, number>();
const byShape = new Map<string, number>();
const samples: string[] = [];
let bytes = 0;
let count = 0;
let damage = 0;
let ms = 0;
let n = 0;
const rl = createInterface({ input: createReadStream(corpus) });
for await (const line of rl) {
	if (++n % every) continue;
	const { src, text } = JSON.parse(line) as { src: string; text: string };
	if (srcFilter && !src.startsWith(srcFilter)) continue;
	bytes += text.length;
	// (A Redactor per record: one kept across them would answer a record seen before from its cache.)
	const r = new Redactor({ guessing, fingerprintKey: "eval" });
	const t0 = performance.now();
	const findings = r.detect(text);
	ms += performance.now() - t0;
	for (const f of findings) {
		const v = text.slice(f.start, f.end);
		const shape = shapeOf(v);
		count++;
		byRule.set(f.rule, (byRule.get(f.rule) ?? 0) + 1);
		byShape.set(shape, (byShape.get(shape) ?? 0) + 1);
		if (DAMAGE.has(shape)) damage++;
		const ctx =
			text.slice(Math.max(0, f.start - 100), f.start).replace(/\n/g, "⏎") +
			"«" +
			v.slice(0, 200).replace(/\n/g, "⏎") +
			"»" +
			text.slice(f.end, f.end + 60).replace(/\n/g, "⏎");
		samples.push(`${f.rule}\t${shape}\t${f.confidence.toFixed(2)}\t${src}\t${ctx}`);
	}
}
const mb = bytes / 1e6;
console.log(
	`${split}${srcFilter ? `:${srcFilter}` : ""} [${guessing}]  ${mb.toFixed(1)} MB  ${count} redactions (${(count / mb).toFixed(2)}/MB)  damage ${damage} (${(damage / mb).toFixed(3)}/MB)  ${(mb / (ms / 1000)).toFixed(1)} MB/s`,
);
for (const [k, v] of [...byRule].sort((a, b) => b[1] - a[1]))
	console.log(`  rule  ${k.padEnd(36)} ${String(v).padStart(6)}  ${(v / mb).toFixed(2)}/MB`);
for (const [k, v] of [...byShape].sort((a, b) => b[1] - a[1]))
	console.log(`  shape ${k.padEnd(36)} ${String(v).padStart(6)}`);
mkdirSync(join(import.meta.dirname, "out"), { recursive: true });
writeFileSync(
	join(import.meta.dirname, "out", `realtext.${split}${srcFilter ? `.${srcFilter}` : ""}.${guessing}.tsv`),
	samples.join("\n"),
);
