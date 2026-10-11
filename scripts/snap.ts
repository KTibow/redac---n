/**
 * Snapshot of what leaks and what's lost per corpus, and of every distinct value hidden in ordinary text
 * (the dev real-text sample: no secrets expected, so each one is a candidate false positive), to diff
 * two versions of the code. A new `real` entry is a redaction no earlier version made: look at it before
 * keeping the change. The labelled sets are eval/corpora's and eval/corpora/regress's (inputs reviewers generated at
 * what a change touched, which the labelled sets don't hold), measured by eval/measure.ts, as eval/check.ts gates
 * them; a case that takes over a second is listed as slow.
 *   node scripts/snap.ts save before   …change code…   node scripts/snap.ts diff before
 */
import { createReadStream, existsSync, readFileSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { join } from "node:path";
import { Redactor } from "../src/index.ts";
import { clip, measureSets } from "../eval/measure.ts";
import { labelledSets } from "../eval/sets.ts";
import { CORPORA } from "../eval/data-root.ts";

const [cmd, name] = process.argv.slice(2);
// (Keyed by the set's `.jsonl` name, gzipped or not, so a snapshot outlives the corpus's storage.)
const snap: Record<string, string[]> = { ...measureSets(labelledSets()) };
for (const kind of ["leak", "lost", "slow"]) if (!snap[kind].length) delete snap[kind];
// Ordinary text: the sample eval/all.ts scores (every 20th trajectory record, every 40th repository file).
const real = join(CORPORA, "built/dev.jsonl");
const context = new Map<string, string>();
if (existsSync(real)) {
	const counters = { traj: 0, repo: 0 };
	const r = new Redactor({ fingerprintKey: "x" });
	for await (const line of createInterface({ input: createReadStream(real) })) {
		if (!line) continue;
		const { src, text } = JSON.parse(line) as { src: string; text: string };
		const kind = src.startsWith("traj:") ? "traj" : src.startsWith("repo:") ? "repo" : "";
		if (!kind || ++counters[kind] % (kind === "traj" ? 20 : 40)) continue;
		for (const f of r.detect(text)) {
			const key = `${f.rule}:${text.slice(f.start, f.end).slice(0, 120)}`;
			(snap.real ??= []).push(key);
			if (!context.has(key)) context.set(key, text.slice(Math.max(0, f.start - 60), f.end + 30).replace(/\n/g, "⏎"));
		}
	}
	snap.real = [...new Set(snap.real ?? [])];
}
const path = join(import.meta.dirname, `../eval/out/snap-${name}.json`);
if (cmd === "save") writeFileSync(path, JSON.stringify(snap));
else if (cmd === "diff") {
	const old = JSON.parse(readFileSync(path, "utf8")) as Record<string, string[]>;
	for (const kind of ["leak", "lost", "real", "slow"]) {
		const a = new Set(old[kind] ?? []);
		const b = new Set(snap[kind] ?? []);
		for (const x of b)
			if (!a.has(x))
				console.log(`new ${kind}: ${clip(x)}${context.has(x) ? `\n    ${context.get(x)!.slice(0, 200)}` : ""}`);
		for (const x of a) if (!b.has(x)) console.log(`fixed ${kind}: ${clip(x)}`);
	}
}
