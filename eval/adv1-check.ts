/**
 * Runs eval/corpora/adv1-robust.jsonl.gz with the API each case names, which eval/run.ts can't:
 *
 *   node eval/adv1-check.ts [eval/corpora/adv1-robust.jsonl.gz] [-v]
 *
 * Case fields beyond eval/score.ts's `Case`:
 * - `api`: "redact" (default), "stream" (written in `chunk`-sized pieces, optional `holdback`), or
 *   "redactValue" (`text` is the JSON of a message list; the redacted value is re-serialized and scored).
 * - `maxMs`: time budget for one redact() call.
 * `-v` prints each failure's `why` and output. A case whose input parses as JSON must also parse as JSON after redaction.
 */
import { Redactor } from "../src/index.ts";
import { leaked, readCorpus } from "./score.ts";

interface AdvCase {
	id: string;
	kind: string;
	why: string;
	text: string;
	secrets?: string[];
	keep?: string[];
	hint?: { command?: string; path?: string };
	maxMs?: number;
	api?: "redact" | "stream" | "redactValue";
	chunk?: number;
	holdback?: number;
}

const file = process.argv[2] ?? new URL("./corpora/adv1-robust.jsonl.gz", import.meta.url).pathname;
const cases: AdvCase[] = readCorpus(file)
	.split("\n")
	.filter((l) => l.trim())
	.map((l) => JSON.parse(l));
const parses = (s: string) => {
	try {
		JSON.parse(s);
		return true;
	} catch {
		return false;
	}
};

let failed = 0;
for (const c of cases) {
	const r = new Redactor({ fingerprintKey: "adv1" });
	const problems: string[] = [];
	let out = "";
	const t0 = performance.now();
	try {
		if (c.api === "stream") {
			const s = r.stream({ hint: c.hint, holdback: c.holdback });
			const n = c.chunk ?? 512;
			for (let i = 0; i < c.text.length; i += n) out += s.write(c.text.slice(i, i + n));
			out += s.end();
		} else if (c.api === "redactValue") {
			out = JSON.stringify(r.redactValue(JSON.parse(c.text)).value);
		} else out = r.redact(c.text, { hint: c.hint }).text;
	} catch (e) {
		problems.push(`THROWS ${String(e).slice(0, 120)}`);
	}
	const ms = performance.now() - t0;
	if (!problems.length) {
		for (const s of c.secrets ?? []) if (leaked(s, out)) problems.push(`LEAK ${JSON.stringify(s).slice(0, 60)}`);
		for (const k of c.keep ?? []) if (!out.includes(k)) problems.push(`LOST ${JSON.stringify(k).slice(0, 60)}`);
		if (parses(c.text) && !parses(out)) problems.push("output is no longer valid JSON");
		if (c.maxMs !== undefined && ms > c.maxMs) problems.push(`SLOW ${ms.toFixed(0)}ms > ${c.maxMs}ms`);
	}
	if (problems.length) failed++;
	console.log(`${problems.length ? "FAIL" : "pass"} ${c.id.padEnd(40)} ${problems.join("; ")}`);
	if (problems.length && process.argv.includes("-v"))
		console.log(`     why: ${c.why}\n     out: ${JSON.stringify(out).slice(0, 300)}`);
}
console.log(`\n${failed}/${cases.length} cases fail`);
process.exitCode = failed ? 1 : 0;
