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
import { candidates, features, score, vetoes } from "../src/unnamed.ts";

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
for (const c of candidates(text)) {
	const f = features(doc, c, false);
	const veto = vetoes(f).join(", ");
	console.log(
		`unnamed ${JSON.stringify(c.token).padEnd(40)} ${veto ? `veto ${veto}` : `p=${score(f).toFixed(3)}`}  name=${f.ctx.name || "-"}/${f.ctx.nameClass} syntax=${f.ctx.syntax} natural=${f.natural.toFixed(2)}`,
	);
}
console.log("=>", new Redactor({ guessing }).redact(text, { hint }).text);
