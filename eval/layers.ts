/**
 * Measures each detection layer separately: every layer alone, every layer left out, each stage around them left out
 * (normalization, the JSON-literal pass, hints, the decision stage, repeats, the random layer's vetoes and its
 * context: STAGES), and the full pipeline, on the labelled dev corpora (recall and loss, as eval/run.ts scores them) and on real text
 * (redactions per million characters). Also, per layer: how many of its findings no other layer makes
 * (unique), and on the labelled sets where its findings land (a labelled secret, a keep value, neither).
 *
 *   node eval/layers.ts [--guessing confident] [--every 10] [--no-real] [--json eval/out/layers.json]
 *
 * Each configuration runs the library's own pipeline with some layers switched off (`RedactorOptions.layers`).
 *
 * Layers:
 *   formats    findFormats (vendor token formats)
 *   structure  findStructure (keys, URL passwords, headers, connection strings, ...; hashes kept)
 *   names      findNamed (values under credential names)
 *   context    hint-driven secret-file and printed-secret passes, and embedded command outputs
 *   encoded    findEncoded and findHexDumps (their "holds a secret" test still uses every finder)
 *   random     findUnnamed (random tokens), given whatever the enabled layers took
 * Known values, wrapping, repeats and the decision stage always run.
 * The held-out corpora are never read.
 */
import { createReadStream, mkdirSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { createInterface } from "node:readline";
import {
	type Finding,
	type Hint,
	type Layer,
	LAYERS,
	type Guessing,
	Redactor,
	type Stage,
	STAGES,
} from "../src/index.ts";
import { type Case, type CaseResult, loadCases, scoreCase, summarize, type Summary } from "./score.ts";
import { CORPORA } from "./data-root.ts";
import { Args } from "./args.ts";
import { devSets } from "./sets.ts";

const args = new Args();
const guessing = args.opt("guessing", "confident") as Guessing;
const every = args.num("every", 10);
const doReal = !args.flag("no-real");
const jsonOut = args.opt("json", join(import.meta.dirname, "out", "layers.json"));
const realFile = args.opt("real", join(CORPORA, "built/dev.jsonl"));
const corpora = devSets().map((s) => s.file);

/** The library's pipeline with only the layers in `on`. */
function detect(
	text: string,
	o: { hint?: Hint; known?: string[]; on: ReadonlySet<Layer>; without?: Stage[] },
): Finding[] {
	return new Redactor({ guessing, known: o.known, fingerprintKey: "eval", layers: o.on, without: o.without }).detect(
		text,
		{ hint: o.hint },
	);
}

// --- Configurations -------------------------------------------------------------------------------------

const CONFIGS: { name: string; on: Set<Layer>; without?: Stage[] }[] = [
	{ name: "full", on: new Set(LAYERS) },
	...LAYERS.map((l) => ({ name: `only ${l}`, on: new Set<Layer>([l]) })),
	...LAYERS.map((l) => ({ name: `without ${l}`, on: new Set<Layer>(LAYERS.filter((x) => x !== l)) })),
	...STAGES.map((stage) => ({ name: `without stage ${stage}`, on: new Set(LAYERS), without: [stage] })),
];

const overlaps = (a: { start: number; end: number }, b: { start: number; end: number }) =>
	a.start < b.end && b.start < a.end;

/** Per layer, from its alone run: findings, those no other layer's alone run overlaps, and where they land. */
interface LayerStats {
	findings: number;
	unique: number;
	secret: number;
	keep: number;
	neither: number;
	uniqueSecret: number;
	uniqueKeep: number;
}
const emptyStats = (): LayerStats => ({
	findings: 0,
	unique: 0,
	secret: 0,
	keep: 0,
	neither: 0,
	uniqueSecret: 0,
	uniqueKeep: 0,
});

function addLayerStats(
	stats: Map<Layer, LayerStats>,
	alone: Map<Layer, Finding[]>,
	secrets: { start: number; end: number }[],
	keeps: { start: number; end: number }[],
) {
	for (const l of LAYERS) {
		const s = stats.get(l)!;
		for (const f of alone.get(l)!) {
			const unique = !LAYERS.some((m) => m !== l && alone.get(m)!.some((g) => overlaps(f, g)));
			const where = secrets.some((x) => overlaps(f, x))
				? "secret"
				: keeps.some((x) => overlaps(f, x))
					? "keep"
					: "neither";
			s.findings++;
			s[where]++;
			if (unique) {
				s.unique++;
				if (where === "secret") s.uniqueSecret++;
				if (where === "keep") s.uniqueKeep++;
			}
		}
	}
}

/** Every occurrence of each value in the text. */
function occurrences(text: string, values: string[] | undefined): { start: number; end: number }[] {
	const out: { start: number; end: number }[] = [];
	for (const v of values ?? []) {
		if (!v) continue;
		for (let at = text.indexOf(v); at >= 0; at = text.indexOf(v, at + 1)) out.push({ start: at, end: at + v.length });
	}
	return out;
}

const pct = (x: number) => `${(x * 100).toFixed(1)}%`;

// --- Labelled corpora -----------------------------------------------------------------------------------

interface LabelledReport {
	corpus: string;
	cases: number;
	configs: Record<string, Summary>;
	layers: Record<string, LayerStats>;
}

function scoreLabelled(file: string): LabelledReport {
	const cases: Case[] = loadCases(file);
	const results = new Map<string, CaseResult[]>(CONFIGS.map((c) => [c.name, []]));
	const stats = new Map<Layer, LayerStats>(LAYERS.map((l) => [l, emptyStats()]));
	const corpus = basename(file).replace(/\.\w+$/, "");
	for (const c of cases) {
		const redactor = new Redactor({ guessing, known: c.known, fingerprintKey: "eval" });
		const alone = new Map<Layer, Finding[]>();
		for (const cfg of CONFIGS) {
			const findings = detect(c.text, { hint: c.hint, known: c.known, on: cfg.on, without: cfg.without });
			if (cfg.on.size === 1 && !cfg.without) alone.set([...cfg.on][0], findings);
			const out = redactor.apply(c.text, findings).text;
			results.get(cfg.name)!.push(scoreCase(c, out, 0));
		}
		addLayerStats(stats, alone, occurrences(c.text, c.secrets), occurrences(c.text, c.keep));
	}
	return {
		corpus,
		cases: cases.length,
		configs: Object.fromEntries([...results].map(([k, v]) => [k, summarize(v)])),
		layers: Object.fromEntries(stats),
	};
}

// --- Real text --------------------------------------------------------------------------------------------

interface RealReport {
	file: string;
	every: number;
	records: number;
	chars: number;
	configs: Record<string, number>;
	layers: Record<string, { findings: number; unique: number }>;
}

async function scoreReal(file: string): Promise<RealReport> {
	const counts = new Map<string, number>(CONFIGS.map((c) => [c.name, 0]));
	const stats = new Map<Layer, LayerStats>(LAYERS.map((l) => [l, emptyStats()]));
	let n = 0;
	let records = 0;
	let chars = 0;
	const rl = createInterface({ input: createReadStream(file) });
	for await (const line of rl) {
		if (++n % every) continue;
		const { text } = JSON.parse(line) as { src: string; text: string };
		records++;
		chars += text.length;
		const alone = new Map<Layer, Finding[]>();
		for (const cfg of CONFIGS) {
			const findings = detect(text, { on: cfg.on, without: cfg.without });
			counts.set(cfg.name, counts.get(cfg.name)! + findings.length);
			if (cfg.on.size === 1 && !cfg.without) alone.set([...cfg.on][0], findings);
		}
		addLayerStats(stats, alone, [], []);
		if (records % 2000 === 0)
			process.stderr.write(`  real text: ${records} records, ${(chars / 1e6).toFixed(1)} M chars\n`);
	}
	return {
		file,
		every,
		records,
		chars,
		configs: Object.fromEntries(counts),
		layers: Object.fromEntries([...stats].map(([l, s]) => [l, { findings: s.findings, unique: s.unique }])),
	};
}

// --- Report -------------------------------------------------------------------------------------------------

function labelledTables(r: LabelledReport): string {
	const full = r.configs.full;
	const rows = CONFIGS.map((c) => {
		const s = r.configs[c.name];
		const d =
			c.name === "full"
				? ""
				: ` | ${((s.recall - full.recall) * 100).toFixed(1)} | ${((s.lossRate - full.lossRate) * 100).toFixed(1)}`;
		return `| ${c.name} | ${pct(s.recall)} (${s.caught}/${s.secrets}) | ${pct(s.lossRate)} (${s.lost}/${s.keeps})${d || " | | "} |`;
	});
	const layerRows = LAYERS.map((l) => {
		const s = r.layers[l];
		const share = (x: number) => (s.findings ? pct(x / s.findings) : "-");
		return `| ${l} | ${s.findings} | ${s.unique} (${s.uniqueSecret} secret, ${s.uniqueKeep} keep) | ${share(s.secret)} | ${share(s.keep)} | ${share(s.neither)} |`;
	});
	return [
		`### ${r.corpus} (${r.cases} cases)`,
		"",
		"| configuration | recall | loss | Δ recall (pts) | Δ loss (pts) |",
		"|---|---:|---:|---:|---:|",
		...rows,
		"",
		"| layer (alone) | findings | unique to it | on a secret | on a keep only | on neither |",
		"|---|---:|---:|---:|---:|---:|",
		...layerRows,
	].join("\n");
}

function realTables(r: RealReport): string {
	const m = r.chars / 1e6;
	const full = r.configs.full;
	const rows = CONFIGS.map(
		(c) =>
			`| ${c.name} | ${r.configs[c.name]} | ${(r.configs[c.name] / m).toFixed(2)} | ${c.name === "full" ? "" : (r.configs[c.name] - full).toString()} |`,
	);
	const layerRows = LAYERS.map(
		(l) =>
			`| ${l} | ${r.layers[l].findings} | ${(r.layers[l].findings / m).toFixed(2)} | ${r.layers[l].unique} | ${(r.layers[l].unique / m).toFixed(2)} |`,
	);
	return [
		`### Real text: ${basename(r.file)}, every ${r.every}th record (${r.records} records, ${m.toFixed(1)} M chars)`,
		"",
		"| configuration | redactions | per M chars | vs full |",
		"|---|---:|---:|---:|",
		...rows,
		"",
		"| layer (alone) | findings | per M chars | unique to it | unique per M chars |",
		"|---|---:|---:|---:|---:|",
		...layerRows,
	].join("\n");
}

const labelled: LabelledReport[] = [];
for (const file of corpora) {
	const t0 = performance.now();
	labelled.push(scoreLabelled(file));
	process.stderr.write(`  ${basename(file)}: ${((performance.now() - t0) / 1000).toFixed(1)} s\n`);
}
// All the dev sets together.
const combined: LabelledReport = { corpus: "all dev sets", cases: 0, configs: {}, layers: {} };
for (const r of labelled) {
	combined.cases += r.cases;
	for (const [k, s] of Object.entries(r.configs)) {
		const c = (combined.configs[k] ??= { secrets: 0, caught: 0, recall: 0, keeps: 0, lost: 0, lossRate: 0 });
		c.secrets += s.secrets;
		c.caught += s.caught;
		c.keeps += s.keeps;
		c.lost += s.lost;
		c.recall = c.secrets ? c.caught / c.secrets : 1;
		c.lossRate = c.keeps ? c.lost / c.keeps : 0;
	}
	for (const [k, s] of Object.entries(r.layers)) {
		const c = (combined.layers[k] ??= emptyStats());
		for (const f of Object.keys(s) as (keyof LayerStats)[]) c[f] += s[f];
	}
}
const real = doReal ? await scoreReal(realFile) : undefined;

const sections = [...labelled, combined].map(labelledTables);
if (real) sections.push(realTables(real));
console.log(`guessing ${guessing}\n`);
console.log(sections.join("\n\n"));
mkdirSync(join(import.meta.dirname, "out"), { recursive: true });
writeFileSync(jsonOut, JSON.stringify({ guessing, labelled, combined, real }, null, "\t"));
