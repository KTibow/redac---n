/**
 * Checks scripts/regex-modifiers.ts against the engine's own inline modifiers (Node 23+): every rule of
 * the Betterleaks catalog is rewritten, and both forms run over strings built from the rule's keywords,
 * random casing and random token bodies. Any difference in matches fails.
 *
 *   node scripts/check-modifiers.ts eval/out/betterleaks-rules.json
 */
import { readFileSync } from "node:fs";
import { randomInts } from "../eval/random.ts";
import { withoutModifiers } from "./regex-modifiers.ts";

const { rules } = JSON.parse(readFileSync(process.argv[2], "utf8")) as {
	rules: { id: string; regex: string; flags: string; keywords: string[]; kind: string }[];
};
const rand = randomInts(7);
const ALPHABETS = [
	"0123456789abcdef",
	"0123456789ABCDEF",
	"abcdefghijklmnopqrstuvwxyz0123456789",
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_.=",
];
const body = (n: number) => {
	const a = ALPHABETS[rand(ALPHABETS.length)];
	let s = "";
	for (let i = 0; i < n; i++) s += a[rand(a.length)];
	return s;
};
const casing = (s: string) =>
	[s, s.toUpperCase(), s.replace(/[a-z]/g, (c) => (rand(2) ? c.toUpperCase() : c))][rand(3)];
const LENGTHS = [8, 12, 16, 20, 24, 32, 36, 40, 43, 44, 48, 56, 64, 72, 86, 100, 128];
let changed = 0;
let matched = 0;
let diffs = 0;
for (const r of rules) {
	const regex = r.kind === "keyword" && /^\(\?(?:i)?:/.test(r.regex) ? `(?<![A-Za-z0-9])${r.regex}` : r.regex;
	const [source, flags] = withoutModifiers(regex, r.flags);
	if (source === regex && flags === r.flags) continue;
	changed++;
	const native = new RegExp(regex, `${r.flags}g`);
	const rewritten = new RegExp(source, `${flags}g`);
	let any = false;
	for (const kw of r.keywords.length ? r.keywords : [""]) {
		for (const len of LENGTHS) {
			for (let k = 0; k < 4; k++) {
				const word = casing(kw);
				const t = [
					`${word}_API_KEY="${body(len)}"`,
					`${word} ${body(len)}`,
					`${word}${body(len)}`,
					`${word}: ${body(len)}\n`,
					`${word}-${body(4)}-${body(len)} x`,
					`${word}.${body(len)}.${body(len)}`,
				][rand(6)];
				const a = [...t.matchAll(native)].map((m) => `${m.index}:${m[0]}`).join("|");
				const b = [...t.matchAll(rewritten)].map((m) => `${m.index}:${m[0]}`).join("|");
				if (a) any = true;
				if (a !== b) {
					diffs++;
					if (diffs <= 5) console.log(`DIFF ${r.id}: ${JSON.stringify(t)}\n  native    ${a}\n  rewritten ${b}`);
				}
			}
		}
	}
	if (any) matched++;
}
console.log(`${changed} rules rewritten, ${matched} exercised, ${diffs} differences`);
process.exitCode = diffs ? 1 : 0;
