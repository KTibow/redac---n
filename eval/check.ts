/**
 * The quality gate: scores the labelled sets (dev, adversarial and regression: eval/sets.ts, never a held-out set) and
 * compares what leaks, what is lost and what is slow, case by case, with the committed baseline. Exits 1 on anything
 * new; what is fixed is listed so the baseline can be brought down with `--update`.
 *
 *   node eval/check.ts [--update]
 *
 * eval/baseline.json.gz is `{"leak": ["set:id:value"…], "lost": […], "slow": ["set:id"…]}`, sorted, entries cut as
 * scripts/snap.ts cuts them. It is gzipped, as the corpora are, because the leaked values are fake credentials a secret
 * scanner would flag (GitHub's push protection among them). The regress sets' "secrets" are mostly values the library
 * keeps on purpose, so their leaks are in the baseline: it fences them, it does not call them wrong (see
 * eval/corpora/regress/README.md).
 */
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { gunzipSync, gzipSync } from "node:zlib";
import { Args } from "./args.ts";
import { clip, type Measure, measureSets } from "./measure.ts";
import { labelledSets } from "./sets.ts";

const args = new Args();
const update = args.flag("update");
const KINDS = ["leak", "lost", "slow"] as const;
const baselineFile = join(import.meta.dirname, "baseline.json.gz");

const started = performance.now();
const raw = measureSets(labelledSets());
const now = Object.fromEntries(KINDS.map((k) => [k, [...new Set(raw[k].map(clip))].sort()])) as unknown as Measure;

let old: Measure;
let fresh = false;
try {
	old = JSON.parse(gunzipSync(readFileSync(baselineFile)).toString("utf8"));
} catch {
	if (!update) {
		console.error(`no baseline at ${baselineFile}: run node eval/check.ts --update`);
		process.exit(1);
	}
	old = { leak: [], lost: [], slow: [] };
	fresh = true;
}

let added = 0;
let fixed = 0;
for (const kind of fresh ? [] : KINDS) {
	const a = new Set(old[kind] ?? []);
	const b = new Set(now[kind]);
	for (const x of b) if (!a.has(x)) (added++, console.log(`new ${kind}: ${x}`));
	for (const x of a) if (!b.has(x)) (fixed++, console.log(`fixed ${kind}: ${x}`));
}
const seconds = ((performance.now() - started) / 1000).toFixed(0);
console.log(
	`${KINDS.map((k) => `${now[k].length} ${k}`).join(", ")} (baseline ${KINDS.map((k) => (old[k] ?? []).length).join("/")}); ${added} new, ${fixed} fixed; ${seconds}s`,
);
if (update) {
	writeFileSync(baselineFile, gzipSync(JSON.stringify(now), { level: 9 }));
	console.log(`wrote ${baselineFile}`);
} else if (added) {
	console.log("a new leak, loss or slow case: fix it, or (if it is meant) run node eval/check.ts --update and say why");
	process.exit(1);
} else if (fixed) console.log("fixed entries: run node eval/check.ts --update to lower the baseline");
