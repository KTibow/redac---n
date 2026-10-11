/**
 * Scores the redactor on labeled corpora: recall on `secrets`, loss on `keep`.
 *
 *   node eval/run.ts [--guessing confident] [--fails N] [--by kind|context] [--quiet] <cases.jsonl…>
 *
 * Writes every failure to eval/out/<corpus>.<guessing>.fails.txt for inspection.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { Redactor, type Guessing } from "../src/index.ts";
import { Args } from "./args.ts";
import { isHeldOut } from "./sets.ts";
import { breakdown, type CaseResult, loadCases, scoreCase, summarize } from "./score.ts";

const args = new Args();
const guessing = args.opt("guessing", "confident") as Guessing;
const showFails = args.num("fails", 0);
const by = args.opt("by", "kind");
const quiet = args.flag("quiet");

function pct(x: number) {
	return `${(x * 100).toFixed(1)}%`;
}

mkdirSync(join(import.meta.dirname, "out"), { recursive: true });
for (const file of args.rest) {
	const cases = loadCases(file);
	const results: CaseResult[] = [];
	const fails: string[] = [];
	let ms = 0;
	let bytes = 0;
	for (const c of cases) {
		const r = new Redactor({ guessing, known: c.known, fingerprintKey: "eval" });
		const t0 = performance.now();
		const out = r.redact(c.text, { hint: c.hint }).text;
		const dt = performance.now() - t0;
		ms += dt;
		bytes += c.text.length;
		const res = scoreCase(c, out, dt);
		results.push(res);
		if (res.leaked.length || res.lost.length) {
			fails.push(
				`=== ${c.id} [${c.kind}/${c.context}]${c.hint ? ` hint=${JSON.stringify(c.hint)}` : ""}\n` +
					res.leaked.map((s) => `LEAK ${s}\n`).join("") +
					res.lost.map((s) => `LOST ${s}\n`).join("") +
					`--- in\n${c.text.slice(0, 3000)}\n--- out\n${out.slice(0, 3000)}\n`,
			);
		}
	}
	const s = summarize(results);
	const name = basename(file).replace(/\.\w+$/, "");
	// Held-out failures are never written or shown: looking at them would make the set a dev set.
	const heldOut = isHeldOut(file);
	if (!heldOut) writeFileSync(join(import.meta.dirname, "out", `${name}.${guessing}.fails.txt`), fails.join("\n"));
	console.log(
		`${name} [${guessing}]  recall ${pct(s.recall)} (${s.caught}/${s.secrets})  lost ${pct(s.lossRate)} (${s.lost}/${s.keeps})  ${(bytes / 1e6 / (ms / 1000)).toFixed(1)} MB/s`,
	);
	if (!quiet) {
		for (const [k, v] of breakdown(results, (r) => (by === "context" ? r.context : r.kind))) {
			if (v.secrets + v.keeps === 0) continue;
			console.log(
				`  ${k.padEnd(34)} recall ${v.secrets ? pct(v.recall).padStart(6) : "     -"} (${v.secrets})  lost ${v.keeps ? pct(v.lossRate).padStart(6) : "     -"} (${v.keeps})`,
			);
		}
	}
	if (!heldOut) for (const f of fails.slice(0, showFails)) console.log(f);
}
