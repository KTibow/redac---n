/**
 * The README's CredData chart: for each kind of labelled value (eval/shapes.ts redactionKind, the ordinary-text
 * chart's classifier, of the value and the text before it on its line), true and false values alike, secrets caught
 * against false values hit, redac---n's three settings against the other scanners. One chart per split: the test
 * split's goes in the README, the dev split's (what the fixes were made on) beside it.
 *
 *   node eval/creddata.ts --cases eval/out
 *   python3 -I eval/baselines.py … --corpora eval/out/creddata-dev.jsonl,eval/out/creddata-test.jsonl --variants ctx \
 *       --real-mb 0 --json eval/out/baselines-creddata.json
 *   node eval/creddata-chart.ts [--cases eval/out] [--baselines eval/out/baselines-creddata.json]
 *
 * Writes docs/creddata.svg: a column for each kind, the dev split above the test split. CredSweeper is drawn hollow
 * and left out of the unions: CredData's lines come partly from what it finds, and its model is trained on CredData's
 * labels.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Redactor, type Guessing } from "../src/index.ts";
import { leaked } from "./score.ts";
import { REDACTION_KINDS } from "./shapes.ts";
import { esc, scatterPanel, STYLE, type Dot } from "./chart.ts";
import { Args } from "./args.ts";

const args = new Args();
const root = join(import.meta.dirname, "..");
const casesDir = args.opt("cases", join(root, "eval/out"));
const baselines = JSON.parse(
	readFileSync(args.opt("baselines", join(root, "eval/out/baselines-creddata.json")), "utf8"),
);

/** The scanners and unions drawn, by eval/baselines.py's name: none with CredSweeper in it but CredSweeper itself. */
const SCANNERS: Record<string, string> = {
	gitleaks: "gitleaks",
	betterleaks: "Betterleaks",
	kingfisher: "Kingfisher",
	trufflehog: "TruffleHog",
	noseyparker: "Nosey Parker",
	"detect-secrets": "detect-secrets",
	credsweeper: "CredSweeper (tuned on CredData)",
	"gitleaks+betterleaks+kingfisher": "gitleaks + Betterleaks + Kingfisher",
	"union(all but CredSweeper, detect-secrets)": "the other five but detect-secrets",
	"union(all but CredSweeper)": "the other six",
};
/** The line of unions' middle steps go unlabelled: the subtitle says what each adds. */
const STEP: Record<string, null> = {
	"gitleaks+betterleaks+kingfisher": null,
	"union(all but CredSweeper, detect-secrets)": null,
};
/** Unions that hold each other, smallest first: a grey line along them. */
const CHAIN = [
	"gitleaks",
	"gitleaks+betterleaks+kingfisher",
	"union(all but CredSweeper, detect-secrets)",
	"union(all but CredSweeper)",
];
const SETTINGS: Guessing[] = ["off", "confident", "eager"];

interface Case {
	text: string;
	hint: { path: string };
	group: string;
	secrets: string[];
	keep: string[];
}

/** [caught, secrets, lost, keeps] by kind for one setting, scored as eval/baselines.py scores the scanners. */
function ours(cases: Case[], guessing: Guessing): Record<string, number[]> {
	const r = new Redactor({ guessing, fingerprintKey: "eval" });
	const t: Record<string, number[]> = {};
	for (const c of cases) {
		const k = (t[c.group] ??= [0, 0, 0, 0]);
		const out = r.redact(c.text, { hint: c.hint }).text;
		for (const s of c.secrets) {
			k[1]++;
			if (!leaked(s, out)) k[0]++;
		}
		for (const v of c.keep) {
			k[3]++;
			if (!out.includes(v)) k[2]++;
		}
	}
	return t;
}

/** One chart, a row for each kind and a column for each split: dev (what the fixes were made on) and test. */
function chart(): string {
	const SPLITS = ["dev", "test"] as const;
	const data = Object.fromEntries(
		SPLITS.map((split) => {
			const cases: Case[] = readFileSync(join(casesDir, `creddata-${split}.jsonl`), "utf8")
				.split("\n")
				.filter(Boolean)
				.map((l) => JSON.parse(l));
			return [split, Object.fromEntries(SETTINGS.map((g) => [g, ours(cases, g)]))];
		}),
	);
	const theirs = baselines.groups.ctx;
	const PW = 380;
	const PH = 330;
	const GX = 56;
	const GY = 160;
	const L = 56;
	const T = 160;
	const W = L + REDACTION_KINDS.length * (PW + GX) - GX + 30;
	const H = T + SPLITS.length * (PH + GY) - GY + 90;
	const out: string[] = [];
	const title = "CredData by kind of value: secrets caught against false values hit, on its dev and test splits";
	out.push(
		`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-labelledby="t">`,
	);
	out.push(`<title id="t">${esc(title)}</title>`);
	out.push(STYLE);
	out.push(`<rect width="${W}" height="${H}" rx="8" class="bg"/>`);
	out.push(`<text x="16" y="26" class="title">${esc(title)}</text>`);
	for (const [i, s] of [
		"Each labelled value, true or false, sorted by the ordinary-text chart's classifier; a false value is hit only if it is redacted. Top: the dev split, the repositories the fixes were made on.",
		"Bottom: the test split, repositories they never saw. Blue: redac---n (guessing off, confident, eager). Grey: other scanners; a line from gitleaks adds Betterleaks and Kingfisher, then TruffleHog",
		"and Nosey Parker, then detect-secrets (the other six). Hollow: CredSweeper, which CredData's lines partly come from and whose model is trained on its labels. √ scale across; up and left is better.",
	].entries())
		out.push(`<text x="16" y="${44 + i * 16}">${esc(s)}</text>`);
	SPLITS.forEach((split, row) =>
		out.push(
			`<text x="16" y="${T + row * (PH + GY) - 44}" class="title">${split === "dev" ? "Dev split (the fixes were made on it)" : "Test split (never seen by the fixes)"}</text>`,
		),
	);
	SPLITS.forEach((split, row) =>
		REDACTION_KINDS.forEach((kind, col) => {
			const ox = L + col * (PW + GX);
			const oy = T + row * (PH + GY);
			const mine = data[split];
			const dot = (t: number[] | undefined, name: string, look: Dot["look"], label?: string | null): Dot | undefined =>
				t && t[1] && t[3] ? { name, caught: t[0] / t[1], lost: t[2] / t[3], look, label } : undefined;
			const dots = [
				...SETTINGS.map((g) => dot(mine[g][kind], `guessing ${g}`, "ours", g === "confident" ? "redac---n" : null)),
				...Object.entries(SCANNERS).map(([tool, name]) =>
					dot(
						theirs[tool]?.[`creddata-${split}`]?.[kind],
						name,
						tool === "credsweeper" ? "tuned" : "other",
						STEP[tool],
					),
				),
			].filter((d) => d !== undefined);
			const counts = mine.confident[kind];
			out.push(
				`<text x="${ox}" y="${oy - 12}" class="panel">${esc(kind)} <tspan class="tick">${counts[1].toLocaleString("en")} true, ${counts[3].toLocaleString("en")} false</tspan></text>`,
			);
			const { svg, note } = scatterPanel(
				{ x: ox, y: oy, w: PW, h: PH },
				dots,
				[
					{ names: CHAIN.map((c) => SCANNERS[c]), cls: "chain" },
					{ names: SETTINGS.map((g) => `guessing ${g}`), cls: "accent-line" },
				],
				{ margin: 24 },
			);
			out.push(...svg);
			note.forEach((l, i) => out.push(`<text x="${ox}" y="${oy + PH + 34 + i * 14}" class="tick">${esc(l)}</text>`));
		}),
	);
	out.push(`</svg>`);
	return out.join("\n") + "\n";
}

writeFileSync(join(root, "docs/creddata.svg"), chart());
