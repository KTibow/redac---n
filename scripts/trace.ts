/**
 * How a text is decided: the formats, structure and names layers' proposals with the decision stage's reason to keep them (policy.ts), the
 * unnamed classifier's candidates with their veto or score, and the final redaction.
 *
 *   node scripts/trace.ts '<text>' [--command c] [--path p] [--guessing off|confident|eager]     (or the text on stdin)
 */
import { readFileSync } from "node:fs";
import { findFormats } from "../src/formats.ts";
import { Doc } from "../src/context.ts";
import { type Guessing, Redactor } from "../src/index.ts";
import { findNamed } from "../src/named.ts";
import { keepReason } from "../src/policy.ts";
import { findStructure } from "../src/structure.ts";
import { type Candidate, candidates, features, namedBody, score, vetoes, withGluedName } from "../src/unnamed.ts";

const args = process.argv.slice(2);
const option = (name: string) => {
	const i = args.indexOf(`--${name}`);
	return i >= 0 ? args.splice(i, 2)[1] : undefined;
};
const hint = { command: option("command"), path: option("path") };
const guessing = (option("guessing") ?? "confident") as Guessing;
const text = args[0] ?? readFileSync(0, "utf8");

for (const f of [...findFormats(text), ...findStructure(text), ...findNamed(text)]) {
	console.log(
		`${f.rule.padEnd(28)} ${(f.name ?? "").padEnd(16)} ${JSON.stringify(text.slice(f.start, f.end)).padEnd(40)} ${keepReason(text, f) ?? "hidden"}`,
	);
}
const doc = new Doc(text);
const show = (label: string, c: Candidate, body = false) => {
	const f = body ? withGluedName(features(doc, c, false)) : features(doc, c, false);
	const veto = vetoes(f).join(", ");
	console.log(
		`${label} ${JSON.stringify(c.token).padEnd(40)} ${veto ? `veto ${veto}` : `p=${score(f).toFixed(3)}`}  name=${f.ctx.name || "-"}/${f.ctx.nameClass} syntax=${f.ctx.syntax} natural=${f.natural.toFixed(2)}`,
	);
};
for (const c of candidates(text)) {
	show("unnamed", c);
	// (Judged only where the whole is kept for reading as a name, or scores low: findUnnamed.)
	const b = namedBody(c);
	if (b) show("  body (if the whole is kept)", b, true);
}
console.log("=>", new Redactor({ guessing }).redact(text, { hint }).text);
