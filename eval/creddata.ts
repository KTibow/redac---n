/**
 * Scores on CredData (Samsung): real lines from ~300 public repositories, each labelled true or false
 * credential, judged with three lines of context either side and the file's path as a hint.
 *
 *   node eval/creddata.ts [--guessing confident] [--split dev|test] [--samples N]
 *
 * Repositories are split dev/test by a hash of their ID, so tuning on dev never sees test repos.
 * Categories that aren't secrets for our purpose (bucket names, app IDs) are left out.
 */
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { Redactor, type Guessing } from "../src/index.ts";
import { leaked } from "./score.ts";
import { CORPORA } from "./data-root.ts";
import { Args } from "./args.ts";

const args = new Args();
const guessing = args.opt("guessing", "confident") as Guessing;
const split = args.opt("split", "dev");
const showSamples = args.num("samples", 0);
const ROOT = join(CORPORA, "CredData");
const NOT_SECRET =
	/AWS S3 Bucket|App ID|Firebase Domain|^Info$|Client ID$|AWS Client ID|^UUID|^Nonce|^Auth:Nonce|^API:UUID/;

const r = new Redactor({ guessing, fingerprintKey: "eval" });
const fileCache = new Map<string, string[]>();
function lines(path: string): string[] | undefined {
	let l = fileCache.get(path);
	if (!l) {
		try {
			l = readFileSync(join(ROOT, path), "utf8").split("\n");
		} catch {
			return undefined;
		}
		if (fileCache.size > 2000) fileCache.clear();
		fileCache.set(path, l);
	}
	return l;
}

interface Tally {
	t: number;
	caught: number;
	f: number;
	falseHit: number;
}
const byCat = new Map<string, Tally>();
const tally = (cat: string) => {
	let t = byCat.get(cat);
	if (!t) byCat.set(cat, (t = { t: 0, caught: 0, f: 0, falseHit: 0 }));
	return t;
};
const missSamples: string[] = [];
const fpSamples: string[] = [];

for (const metaFile of readdirSync(join(ROOT, "meta")).sort()) {
	const repo = metaFile.replace(/\.csv$/, "");
	const inTest = createHash("sha256").update(repo).digest()[0] % 4 === 0;
	if ((split === "test") !== inTest) continue;
	const rows = readFileSync(join(ROOT, "meta", metaFile), "utf8")
		.split("\n")
		.slice(1);
	for (const row of rows) {
		const c = row.split(",");
		if (c.length < 13) continue;
		const [, , , , path, ls, le, gt, vs, ve, , , ...catParts] = c;
		const cat = catParts.join(",");
		if (gt === "X" || NOT_SECRET.test(cat)) continue;
		const L = lines(path);
		if (!L) continue;
		const lineStart = Number(ls) - 1;
		const lineEnd = Number(le) - 1;
		const ctxStart = Math.max(0, lineStart - 3);
		const before = L.slice(ctxStart, lineStart).join("\n");
		const target = L.slice(lineStart, lineEnd + 1).join("\n");
		const after = L.slice(lineEnd + 1, lineEnd + 4).join("\n");
		const text = [before, target, after].filter((x, i) => i === 1 || x).join("\n");
		const offset = before ? before.length + 1 : 0;
		const findings = r.detect(text, { hint: { path } });
		const t = tally(cat.split(":")[0]);
		if (gt === "T") {
			if (vs === "" || ve === "") continue;
			// ValueStart/End index into the first line; ValueEnd may run onto later lines for keys.
			const value = lineStart === lineEnd ? L[lineStart].slice(Number(vs), Number(ve)) : target.slice(Number(vs));
			if (!value || value.length < 4) continue;
			t.t++;
			const out = r.redact(text, { hint: { path } }).text;
			if (!leaked(value, out)) t.caught++;
			else if (missSamples.length < 4000)
				missSamples.push(`${cat}\t${path}\t${value.slice(0, 80)}\t${target.slice(0, 300).replace(/\n/g, "⏎")}`);
		} else {
			t.f++;
			// A false line counts as a false redaction if anything on the labelled line is redacted.
			const lo = offset;
			const hi = offset + target.length;
			const hit = findings.find((f) => f.start < hi && f.end > lo);
			if (hit) {
				t.falseHit++;
				if (fpSamples.length < 4000)
					fpSamples.push(
						`${cat}\t${hit.rule}\t${path}\t${text.slice(hit.start, hit.end).slice(0, 80)}\t${target.slice(0, 300).replace(/\n/g, "⏎")}`,
					);
			}
		}
	}
}

let T = 0;
let C = 0;
let F = 0;
let FH = 0;
for (const [cat, t] of [...byCat].sort((a, b) => b[1].t + b[1].f - a[1].t - a[1].f)) {
	T += t.t;
	C += t.caught;
	F += t.f;
	FH += t.falseHit;
	console.log(
		`  ${cat.padEnd(30)} recall ${t.t ? ((t.caught / t.t) * 100).toFixed(1).padStart(5) : "    -"}% (${t.t})  false hits ${t.f ? ((t.falseHit / t.f) * 100).toFixed(1).padStart(5) : "    -"}% (${t.f})`,
	);
}
console.log(
	`creddata:${split} [${guessing}]  recall ${((C / T) * 100).toFixed(1)}% (${C}/${T})  false lines ${((FH / F) * 100).toFixed(1)}% (${FH}/${F})  precision ${((C / (C + FH)) * 100).toFixed(1)}%`,
);
mkdirSync(join(import.meta.dirname, "out"), { recursive: true });
writeFileSync(join(import.meta.dirname, "out", `creddata.${split}.${guessing}.misses.tsv`), missSamples.join("\n"));
writeFileSync(join(import.meta.dirname, "out", `creddata.${split}.${guessing}.fps.tsv`), fpSamples.join("\n"));
for (const s of missSamples.slice(0, showSamples)) console.log("MISS", s.slice(0, 300));
for (const s of fpSamples.slice(0, showSamples)) console.log("FP  ", s.slice(0, 300));
