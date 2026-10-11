/**
 * Runs each imported format rule over real text and reports how often it fires, with samples. A
 * format rule should almost never fire on public code and agent output; one that does is either too
 * loose or matches published example keys, and needs a look before it ships.
 *
 *   node scripts/check-formats.ts eval/out/betterleaks-rules.json [dev.jsonl] [every-nth]
 */
import { createReadStream, readFileSync } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { CORPORA } from "../eval/data-root.ts";

const rulesFile = process.argv[2];
const corpus = process.argv[3] ?? join(CORPORA, "built/dev.jsonl");
const every = Number(process.argv[4] ?? 5);
const { rules } = JSON.parse(readFileSync(rulesFile, "utf8")) as {
	rules: { id: string; regex: string; flags: string; keywords: string[] }[];
};
const compiled = rules.map((r) => ({
	...r,
	re: new RegExp(r.regex, r.flags.replace("g", "") + "g"),
	kw: r.keywords.map((k) => k.toLowerCase()),
	hits: 0,
	ms: 0,
	samples: [] as string[],
}));
let bytes = 0;
let n = 0;
const rl = createInterface({ input: createReadStream(corpus) });
for await (const line of rl) {
	if (++n % every) continue;
	const { src, text } = JSON.parse(line) as { src: string; text: string };
	bytes += text.length;
	const lower = text.toLowerCase();
	for (const r of compiled) {
		if (r.kw.length && !r.kw.some((k) => lower.includes(k))) continue;
		const t0 = performance.now();
		for (const m of text.matchAll(r.re)) {
			r.hits++;
			if (r.samples.length < 4) r.samples.push(`${src.slice(0, 50)} | ${m[0].slice(0, 120).replace(/\n/g, "⏎")}`);
		}
		r.ms += performance.now() - t0;
	}
}
console.log(`MB scanned: ${(bytes / 1e6).toFixed(1)}`);
for (const r of compiled.sort((a, b) => b.hits - a.hits)) {
	if (!r.hits && r.ms < 200) continue;
	console.log(`${String(r.hits).padStart(6)} ${r.ms.toFixed(0).padStart(6)}ms ${r.id}`);
	for (const s of r.samples) console.log(`         ${s}`);
}
