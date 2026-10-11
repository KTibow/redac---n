/**
 * The random-token layer's funnel on the labelled dev corpora: for each labelled secret the full pipeline leaks, and
 * each keep value the layer hides, the stage of findUnnamed (src/unnamed.ts) that decided it:
 *
 *   no candidate   the value is no candidate run (too short, characters outside the token alphabet)
 *   split          candidates overlap the value but none is it (cut at a separator: `/`, `-`, `.`)
 *   gate           the cheap naturalness gate dropped it (reads as words, no digit)
 *   veto           a hard rule ruled it out, by its first reason (all its reasons are counted too)
 *   model          the boosted trees scored it below the threshold (a histogram of its score)
 *   ids filter     scored at or above the threshold, but findUnnamed drops it: the text shows the same token as an ID
 *   hidden         findUnnamed hides it: the model scored it at or above the threshold, or (`hidden lone-quoted-key`) it is
 *                  a long mixed-case key quoted on its own, which the confident threshold applies to whatever the model says
 *   disagrees      the stages above and findUnnamed's own result disagree: this file has drifted from src/unnamed.ts
 *
 * findUnnamed itself is the judge of hidden or not (`findUnnamed(text, nothing taken, …)`); the stages explain its
 * result from the library's exported parts (candidates, features, vetoes, score, thresholdFor). Only the cheap gate is
 * mirrored here (it is no export), and `disagrees` lists any case where that mirror is wrong. A leak the layer would have caught were it not for another layer's finding beside it shows as `model`/`veto` all
 * the same: the funnel judges the value where it stands, as findUnnamed would with nothing taken.
 *
 *   node eval/funnel.ts [--guessing confident] [--examples 3]
 *
 * The held-out corpora are never read.
 */
import { basename } from "node:path";
import { naturalness } from "../src/charlm.ts";
import { printsSecretFile, isSecretFile } from "../src/commands.ts";
import { Doc } from "../src/context.ts";
import { type Finding, type Guessing, Redactor } from "../src/index.ts";
import { candidates, features, findUnnamed, score, thresholdFor, vetoes } from "../src/unnamed.ts";
import { leaked, loadCases } from "./score.ts";
import { advSets, devSets } from "./sets.ts";
import { Args } from "./args.ts";

const args = new Args();
const guessing = args.opt("guessing", "confident") as Guessing;
const examples = args.num("examples", 3);

const sets = [...advSets(), ...devSets()];

/** Counts by key, with the first few examples of each. */
class Tally {
	readonly counts = new Map<string, { n: number; examples: string[] }>();
	add(key: string, example: string) {
		const e = this.counts.get(key) ?? { n: 0, examples: [] };
		e.n++;
		if (e.examples.length < examples) e.examples.push(example);
		this.counts.set(key, e);
	}
	print(title: string) {
		const total = [...this.counts.values()].reduce((n, e) => n + e.n, 0);
		console.log(`\n${title} (${total})`);
		for (const [key, { n, examples }] of [...this.counts].sort((a, b) => b[1].n - a[1].n)) {
			console.log(
				`  ${String(n).padStart(5)}  ${key.padEnd(28)} ${examples.map((e) => JSON.stringify(e.slice(0, 50))).join("  ")}`,
			);
		}
	}
}

/**
 * Where findUnnamed decides the value at [start, end) of `text`: `found` is what findUnnamed returns for the text with
 * nothing taken, and the stages say why the candidate did or did not come out of it.
 */
function stage(
	doc: Doc,
	found: Finding[],
	start: number,
	end: number,
	secretFile: boolean,
): { stage: string; reasons: string[]; p?: number } {
	const all = candidates(doc.text);
	const exact = all.find((c) => c.start === start && c.end === end);
	if (!exact) return { stage: all.some((c) => c.start < end && c.end > start) ? "split" : "no candidate", reasons: [] };
	const hid = found.some((f) => f.start === start && f.end === end);
	const disagrees = (why: string) => ({ stage: `disagrees: ${why}`, reasons: [] });
	if (naturalness(exact.token) > 1.2 && !/\d/.test(exact.token))
		return hid ? disagrees("hidden past the gate") : { stage: "gate", reasons: [] };
	const f = features(doc, exact, secretFile);
	const reasons = vetoes(f);
	if (reasons.length)
		return hid ? disagrees(`hidden past veto ${reasons[0]}`) : { stage: `veto ${reasons[0]}`, reasons };
	const p = score(f);
	const confident = p >= (thresholdFor(guessing, secretFile) ?? Infinity);
	if (hid) return { stage: confident ? "hidden" : "hidden lone-quoted-key", reasons, p };
	return { stage: confident ? "ids filter" : "model", reasons, p };
}

const bucket = (p: number) => `p ${(Math.floor(p * 10) / 10).toFixed(1)}–${(Math.floor(p * 10) / 10 + 0.1).toFixed(1)}`;
const leaks = new Tally();
const leakVetoes = new Tally();
const leakScores = new Tally();
const losses = new Tally();
const lossScores = new Tally();
const redactor = new Redactor({ guessing, fingerprintKey: "funnel" });
let cases = 0;
for (const { file } of sets) {
	for (const c of loadCases(file)) {
		cases++;
		const result = redactor.redact(c.text, { hint: c.hint });
		const secretFile =
			(c.hint?.path !== undefined && isSecretFile(c.hint.path)) ||
			(c.hint?.command !== undefined && printsSecretFile(c.hint.command));
		let doc: Doc | undefined;
		let found: Finding[] | undefined;
		for (const s of c.secrets ?? []) {
			if (!leaked(s, result.text)) continue;
			const at = c.text.indexOf(s);
			if (at < 0) continue;
			doc ??= Doc.of(c.text);
			found ??= findUnnamed(c.text, () => false, guessing, secretFile);
			const d = stage(doc, found, at, at + s.length, secretFile);
			leaks.add(d.stage.startsWith("veto") ? "veto" : d.stage, s);
			for (const r of d.reasons) leakVetoes.add(r, s);
			if (d.p !== undefined) leakScores.add(bucket(d.p), s);
		}
		// Keeps the random layer hid (or spread: a repeat of its finding).
		for (const k of c.keep ?? []) {
			if (result.text.includes(k)) continue;
			const by = result.findings.find((f) => f.value === k || (f.value.includes(k) && k.length >= 8));
			if (!by || (by.rule !== "unnamed" && by.rule !== "repeat")) continue;
			const at = c.text.indexOf(k);
			if (at < 0) continue;
			doc ??= Doc.of(c.text);
			found ??= findUnnamed(c.text, () => false, guessing, secretFile);
			const d = stage(doc, found, at, at + k.length, secretFile);
			losses.add(`${by.rule}: ${d.stage}`, k);
			if (d.p !== undefined) lossScores.add(bucket(d.p), k);
		}
	}
}
console.log(
	`${cases} cases in ${sets.map((s) => basename(s.file)).join(", ")}; guessing ${guessing}, threshold ${thresholdFor(guessing, false) ?? "none"}`,
);
leaks.print("Leaked secrets, by the random layer's stage that let them through");
leakVetoes.print("…the vetoes that applied to them (every reason)");
leakScores.print("…the model's score of those it scored");
losses.print("Keep values the random layer hid (directly, or spread by repeat), by stage");
lossScores.print("…the model's score of them");
