/**
 * Builds the README's results: scores redac---n on the held-out corpus (all three modes) and on a real-text
 * sample, joins the numbers eval/baselines.py wrote for the other scanners on the same data, and draws
 * the two charts as SVG (light and dark, via prefers-color-scheme inside the SVG).
 *
 *   node eval/report.ts [--baselines eval/out/baselines-final.json] [--real FILE] [--cached]
 *
 * `--cached` redraws from eval/out/results.json instead of scoring again. The real-text sample is made by
 * scripts/build-sample.py; the baselines come from
 * `python3 -I eval/baselines.py --corpora holdout --real <sample.jsonl> --real-src "" --real-mb 1000 --json eval/out/baselines-final.json …`.
 *
 * Writes docs/holdout.svg, docs/real-text.svg and eval/out/results.json, and prints markdown tables. It
 * prints aggregates only: held-out failures are never written anywhere.
 */
import { createReadStream, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { Redactor, type Guessing } from "../src/index.ts";
import { DAMAGE, REDACTION_KINDS, redactionKind, shapeOf } from "./shapes.ts";
import { loadCases, scoreCase, summarize, type CaseResult } from "./score.ts";
import { CORPORA } from "./data-root.ts";
import { Args } from "./args.ts";
import { esc, pct, STYLE, textWidth } from "./chart.ts";

const args = new Args();
const root = join(import.meta.dirname, "..");
const baselinesFile = args.opt("baselines", join(root, "eval/out/baselines-final.json"));
const realFile = args.opt("real", join(CORPORA, "final/sample.jsonl"));
/** How the README names a baseline that eval/baselines.py names by its command. */
const DISPLAY: Record<string, string> = {
	betterleaks: "Betterleaks",
	credsweeper: "CredSweeper",
	"detect-secrets": "detect-secrets",
	gitleaks: "gitleaks",
	"gitleaks+betterleaks+kingfisher": "gitleaks + Betterleaks + Kingfisher",
	kingfisher: "Kingfisher",
	noseyparker: "Nosey Parker",
	trufflehog: "TruffleHog",
	"union(all 7)": "all seven combined",
	"union(all but detect-secrets)": "all but detect-secrets",
};
const display = (name: string) => DISPLAY[name] ?? name;
/** A chart's label: redac---n's by its setting of `guessing` alone (a legend says whose they are), another scanner's by its display name. */
const labelOf = (name: string, ours: boolean) =>
	ours ? name.replace(/^redac---n guessing /, "guessing ") : display(name);
/** The two series each chart tells apart. */
const LEGEND = [
	["accent", "redac---n"],
	["other", "other scanners"],
] as const;

/** redac---n is scored at each setting of `guessing`. */
const SETTINGS: Guessing[] = ["off", "confident", "eager"];

interface Point {
	name: string;
	recall: number;
	loss: number;
	ours: boolean;
}
interface Bar {
	name: string;
	perMB: number;
	damagePerMB: number;
	ours: boolean;
	/** Redactions per MB of each kind (shapes.ts REDACTION_KINDS), when the redactions are known. */
	kinds?: number[];
}

/** How many of `redactions` ([value, the text before it on its line]) are of each kind, per MB. */
function kindsPerMB(redactions: [string, string][], mb: number): number[] {
	const n = REDACTION_KINDS.map(() => 0);
	for (const [value, before] of redactions) n[REDACTION_KINDS.indexOf(redactionKind(value, before))]++;
	return n.map((k) => k / mb);
}

// ---------------------------------------------------------------- numbers

const holdout = loadCases(join(root, "eval/corpora/holdout.jsonl.gz"));
const cacheFile = join(root, "eval/out/results.json");
let points: Point[] = [];
let oursHoldout: Record<string, ReturnType<typeof summarize>> = {};
let bars: Bar[] = [];
let oursReal: Record<string, { mb: number; spans: number; damage: number }> = {};
if (args.flag("cached") && existsSync(cacheFile)) {
	// Redraw from the last scoring run, without scoring the held-out corpus again.
	const cached = JSON.parse(readFileSync(cacheFile, "utf8"));
	oursHoldout = cached.holdout;
	oursReal = cached.real;
	points = cached.points.filter((p: Point) => p.ours);
	bars = cached.bars.filter((b: Bar) => b.ours);
} else {
	for (const guessing of SETTINGS) {
		const results: CaseResult[] = [];
		for (const c of holdout) {
			const r = new Redactor({ guessing, known: c.known, fingerprintKey: "eval" });
			results.push(scoreCase(c, r.redact(c.text, { hint: c.hint }).text, 0));
		}
		const s = summarize(results);
		oursHoldout[guessing] = s;
		points.push({ name: `redac---n guessing ${guessing}`, recall: s.recall, loss: s.lossRate, ours: true });
	}
	for (const guessing of SETTINGS) {
		const r = new Redactor({ guessing, fingerprintKey: "eval" });
		let chars = 0;
		let spans = 0;
		let damage = 0;
		const redactions: [string, string][] = [];
		for await (const line of createInterface({ input: createReadStream(realFile) })) {
			const { text } = JSON.parse(line) as { text: string };
			chars += text.length;
			for (const f of r.detect(text)) {
				spans++;
				if (DAMAGE.has(shapeOf(text.slice(f.start, f.end)))) damage++;
				const lineStart = text.lastIndexOf("\n", f.start - 1) + 1;
				redactions.push([text.slice(f.start, f.end), text.slice(Math.max(lineStart, f.start - 200), f.start)]);
			}
		}
		const mb = chars / 1e6;
		oursReal[guessing] = { mb, spans, damage };
		bars.push({
			name: `redac---n guessing ${guessing}`,
			perMB: spans / mb,
			damagePerMB: damage / mb,
			ours: true,
			kinds: kindsPerMB(redactions, mb),
		});
	}
}

interface Baselines {
	corpora: Record<
		string,
		Record<string, Record<string, { caught: number; secrets: number; lost: number; keeps: number }>>
	>;
	real: Record<
		string,
		{ mb: number; findings: number; spans: number; chars: number; damage: number; redactions?: [string, string][] }
	>;
}
const baselines: Baselines | undefined = existsSync(baselinesFile)
	? JSON.parse(readFileSync(baselinesFile, "utf8"))
	: undefined;
const variantRows: string[] = [];
if (baselines) {
	// Each scanner gets its better file-naming variant (all .txt, or an extension from the case's context).
	const names = new Set(Object.values(baselines.corpora).flatMap((v) => Object.keys(v)));
	for (const name of names) {
		const options = Object.entries(baselines.corpora).map(([variant, v]) => ({
			variant,
			s: Object.values(v[name])[0],
		}));
		options.sort((a, b) => b.s.caught / b.s.secrets - a.s.caught / a.s.secrets || a.s.lost - b.s.lost);
		const best = options[0];
		points.push({ name, recall: best.s.caught / best.s.secrets, loss: best.s.lost / best.s.keeps, ours: false });
		variantRows.push(
			`| ${name} | ${options.map((o) => `${o.variant}: ${pct(o.s.caught / o.s.secrets)} / ${pct(o.s.lost / o.s.keeps)}`).join(" · ")} |`,
		);
	}
	for (const [name, v] of Object.entries(baselines.real))
		bars.push({
			name,
			perMB: v.spans / v.mb,
			damagePerMB: v.damage / v.mb,
			ours: false,
			kinds: v.redactions ? kindsPerMB(v.redactions, v.mb) : undefined,
		});
}

// ---------------------------------------------------------------- charts

/** Recall against keep-loss: each scanner as a grey dot, redac---n's three modes in the accent colour. */
function scatter(points: Point[], title: string, sub: string): string {
	const W = 760;
	const H = 460;
	const m = { l: 56, r: 24, t: 64, b: 52 };
	const pw = W - m.l - m.r;
	const ph = H - m.t - m.b;
	// Losses run from under 1% to tens of percent, so x is a square-root scale with labelled ticks.
	const maxLoss = Math.max(0.05, ...points.map((p) => p.loss));
	const xTicks = [0, 0.01, 0.02, 0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.8, 1].filter((t) => t <= maxLoss * 1.05 + 1e-9);
	const xMax = Math.max(maxLoss * 1.05, xTicks[xTicks.length - 1]);
	const x = (v: number) => m.l + (Math.sqrt(v) / Math.sqrt(xMax)) * pw;
	const minRecall = Math.min(...points.map((p) => p.recall));
	const yMin = Math.max(0, Math.floor((minRecall - 0.05) * 10) / 10);
	const y = (v: number) => m.t + ph - ((v - yMin) / (1 - yMin)) * ph;
	const out: string[] = [];
	out.push(
		`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-labelledby="t d">`,
	);
	out.push(
		`<title id="t">${esc(title)}</title><desc id="d">${esc(points.map((p) => `${p.name}: ${pct(p.recall)} of secrets caught, ${pct(p.loss)} of keep values lost`).join("; "))}</desc>`,
	);
	out.push(STYLE);
	out.push(`<rect width="${W}" height="${H}" rx="8" class="bg"/>`);
	out.push(`<text x="${m.l - 40}" y="26" class="title">${esc(title)}</text>`);
	out.push(`<text x="${m.l - 40}" y="44" class="sub">${esc(sub)}</text>`);
	for (let t = yMin; t <= 1 + 1e-9; t += 0.1) {
		out.push(`<line class="grid" x1="${m.l}" x2="${m.l + pw}" y1="${y(t)}" y2="${y(t)}"/>`);
		out.push(`<text class="tick" x="${m.l - 8}" y="${y(t) + 4}" text-anchor="end">${Math.round(t * 100)}%</text>`);
	}
	for (const t of xTicks) {
		out.push(`<line class="grid" x1="${x(t)}" x2="${x(t)}" y1="${m.t}" y2="${m.t + ph}"/>`);
		out.push(`<text class="tick" x="${x(t)}" y="${m.t + ph + 18}" text-anchor="middle">${Math.round(t * 100)}%</text>`);
	}
	out.push(`<line class="axis" x1="${m.l}" x2="${m.l + pw}" y1="${m.t + ph}" y2="${m.t + ph}"/>`);
	out.push(
		`<text x="${m.l + pw}" y="${H - 10}" text-anchor="end">text that must survive but was redacted (lower is better, √ scale) →</text>`,
	);
	out.push(`<text transform="translate(14 ${m.t + ph}) rotate(-90)">secrets caught (higher is better) →</text>`);
	const ours = points.filter((p) => p.ours).sort((a, b) => a.loss - b.loss);
	out.push(
		`<polyline fill="none" class="accent-line" stroke-width="2" points="${ours.map((p) => `${x(p.loss)},${y(p.recall)}`).join(" ")}"/>`,
	);
	// The legend, in the plot's empty corner (high recall at high loss is where no scanner sits).
	const legendW = Math.max(...LEGEND.map(([, n]) => textWidth(n))) + 22;
	LEGEND.forEach(([cls, n], i) => {
		const lx = m.l + pw - legendW;
		const ly = m.t + 14 + i * 20;
		out.push(
			`<circle cx="${lx + 5}" cy="${ly - 4}" r="${cls === "accent" ? 6 : 5}" class="${cls}"/><text x="${lx + 16}" y="${ly}"${cls === "accent" ? ` class="ours"` : ""}>${n}</text>`,
		);
	});
	// Labels: greedy placement around each dot, avoiding dots, redac---n's line, the legend, earlier labels and the
	// plot edge.
	const boxes: [number, number, number, number][] = points.map((p) => [
		x(p.loss) - 6,
		y(p.recall) - 6,
		x(p.loss) + 6,
		y(p.recall) + 6,
	]);
	boxes.push([m.l + pw - legendW - 4, m.t, m.l + pw, m.t + 14 + LEGEND.length * 20]);
	for (let i = 1; i < ours.length; i++) {
		const [x1, y1, x2, y2] = [x(ours[i - 1].loss), y(ours[i - 1].recall), x(ours[i].loss), y(ours[i].recall)];
		const steps = Math.max(1, Math.ceil(Math.hypot(x2 - x1, y2 - y1) / 4));
		for (let k = 0; k <= steps; k++) {
			const [lx, ly] = [x1 + ((x2 - x1) * k) / steps, y1 + ((y2 - y1) * k) / steps];
			boxes.push([lx - 2, ly - 2, lx + 2, ly + 2]);
		}
	}
	const overlaps = (b: [number, number, number, number]) =>
		boxes.some((o) => b[0] < o[2] && b[2] > o[0] && b[1] < o[3] && b[3] > o[1]);
	const labels: string[] = [];
	for (const q of [...points].sort((a, b) => Number(b.ours) - Number(a.ours) || b.recall - a.recall)) {
		const p = { ...q, name: labelOf(q.name, q.ours) };
		const px = x(p.loss);
		const py = y(p.recall);
		const w = textWidth(p.name);
		const tries: [number, number, string][] = [];
		for (const d of [0, 8, 16, 24, 32]) {
			tries.push(
				[px + 10 + d, py + 4, "start"],
				[px - 10 - d, py + 4, "end"],
				[px + 8, py - 10 - d, "start"],
				[px + 8, py + 18 + d, "start"],
				[px - 8, py - 10 - d, "end"],
				[px - 8, py + 18 + d, "end"],
			);
		}
		let placed = false;
		for (const [tx, ty, anchor] of tries) {
			const x0 = anchor === "start" ? tx : tx - w;
			const b: [number, number, number, number] = [x0 - 2, ty - 12, x0 + w + 2, ty + 3];
			if (b[0] < m.l - 30 || b[2] > W - 4 || b[1] < m.t - 14 || b[3] > m.t + ph - 2 || overlaps(b)) continue;
			boxes.push(b);
			const lead =
				Math.hypot(tx - px, ty - 4 - py) > 22
					? `<line x1="${px}" y1="${py}" x2="${anchor === "start" ? x0 - 1 : x0 + w + 1}" y2="${ty - 4}" class="lead"/>`
					: "";
			labels.push(
				`${lead}<text x="${tx}" y="${ty}" text-anchor="${anchor}"${p.ours ? ` class="ours"` : ""}>${esc(p.name)}</text>`,
			);
			placed = true;
			break;
		}
		if (!placed)
			labels.push(`<text x="${px + 10}" y="${py + 4}"${p.ours ? ` class="ours"` : ""}>${esc(p.name)}</text>`);
	}
	for (const p of points.filter((q) => !q.ours)) {
		out.push(
			`<circle cx="${x(p.loss)}" cy="${y(p.recall)}" r="5" class="other ring" stroke-width="2"><title>${esc(`${p.name}: ${pct(p.recall)} caught, ${pct(p.loss)} lost`)}</title></circle>`,
		);
	}
	for (const p of ours) {
		out.push(
			`<circle cx="${x(p.loss)}" cy="${y(p.recall)}" r="6" class="accent ring" stroke-width="2"><title>${esc(`${p.name}: ${pct(p.recall)} caught, ${pct(p.loss)} lost`)}</title></circle>`,
		);
	}
	out.push(...labels);
	out.push(`</svg>`);
	return out.join("\n");
}

/** Redactions per MB on real text, one horizontal bar per scanner, sorted, each split by what it redacted when known. */
function barChart(bars: Bar[], title: string, sub: string): string {
	const sorted = [...bars].sort((a, b) => a.perMB - b.perMB);
	// (Split by kind when every bar's redactions are known.)
	const split = sorted.every((b) => b.kinds);
	const W = 760;
	const rowH = 26;
	const labelW = Math.max(...sorted.map((b) => textWidth(labelOf(b.name, b.ours)))) + 16;
	const m = { l: labelW + 8, r: 72, t: 64, b: 36 };
	const H = m.t + sorted.length * rowH + m.b;
	const pw = W - m.l - m.r;
	const max = Math.max(...sorted.map((b) => b.perMB));
	const step = niceStep(max / 5);
	const top = Math.ceil(max / step) * step;
	const x = (v: number) => m.l + (v / top) * pw;
	const out: string[] = [];
	out.push(
		`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-labelledby="t d">`,
	);
	out.push(
		`<title id="t">${esc(title)}</title><desc id="d">${esc(sorted.map((b) => `${b.name}: ${b.perMB.toFixed(1)} per MB`).join("; "))}</desc>`,
	);
	out.push(STYLE);
	out.push(`<rect width="${W}" height="${H}" rx="8" class="bg"/>`);
	out.push(`<text x="16" y="26" class="title">${esc(title)}</text>`);
	out.push(`<text x="16" y="44" class="sub">${esc(sub)}</text>`);
	for (let t = 0; t <= top + 1e-9; t += step) {
		out.push(`<line class="grid" x1="${x(t)}" x2="${x(t)}" y1="${m.t - 4}" y2="${m.t + sorted.length * rowH}"/>`);
		out.push(
			`<text class="tick" x="${x(t)}" y="${m.t + sorted.length * rowH + 16}" text-anchor="middle">${fmt(t)}</text>`,
		);
	}
	sorted.forEach((b, i) => {
		const cy = m.t + i * rowH + rowH / 2;
		const w = Math.max(1, x(b.perMB) - m.l);
		const fill = b.ours ? "accent" : "other";
		out.push(
			`<text x="${m.l - 10}" y="${cy + 4}" text-anchor="end"${b.ours ? ` class="ours"` : ""}>${esc(labelOf(b.name, b.ours))}</text>`,
		);
		// Bar anchored square on the baseline, 4px rounding on the data end only.
		const h = rowH - 10;
		const r = Math.min(4, w);
		const end = (x0: number, wd: number, cls: string, tip: string) =>
			`<path d="M${x0},${cy - h / 2} h${wd - r} a${r},${r} 0 0 1 ${r},${r} v${h - 2 * r} a${r},${r} 0 0 1 -${r},${r} h-${wd - r} z" class="${cls}"><title>${esc(tip)}</title></path>`;
		if (!split || !b.kinds) out.push(end(m.l, w, fill, `${b.name}: ${b.perMB.toFixed(2)} per MB`));
		else {
			// Each kind a segment, in REDACTION_KINDS's order, a 2px gap of the surface between them.
			let at = 0;
			const last = b.kinds.findLastIndex((k) => k > 0);
			b.kinds.forEach((k, i) => {
				if (k <= 0) return;
				const x0 = x(at);
				const wd = Math.max(1, x(at + k) - x0);
				const tip = `${b.name}: ${REDACTION_KINDS[i]}, ${k.toFixed(2)} per MB`;
				out.push(
					i === last && wd > r
						? end(x0, wd, `k${i} gap`, tip)
						: `<rect x="${x0}" y="${cy - h / 2}" width="${wd}" height="${h}" class="k${i} gap"><title>${esc(tip)}</title></rect>`,
				);
				at += k;
			});
		}
		out.push(
			`<text class="tick" x="${m.l + w + 6}" y="${cy + 4}">${b.perMB < 10 ? b.perMB.toFixed(1) : Math.round(b.perMB)}</text>`,
		);
	});
	out.push(`<line class="axis" x1="${m.l}" x2="${m.l}" y1="${m.t - 4}" y2="${m.t + sorted.length * rowH}"/>`);
	// The legend, top right: the shortest bars come first, so that corner is empty. Split bars: the kinds, and the
	// bold labels for redac---n.
	const legend: readonly (readonly [string, string])[] = split
		? [...REDACTION_KINDS.map((k, i) => [`k${i}`, k] as const), ["", "bold: redac---n"]]
		: LEGEND;
	const legendW = Math.max(...legend.map(([, n]) => textWidth(n))) + 22;
	legend.forEach(([cls, n], i) => {
		const lx = W - m.r - legendW;
		const ly = m.t + 14 + i * 20;
		out.push(
			(cls ? `<rect x="${lx}" y="${ly - 10}" width="12" height="12" rx="3" class="${cls}"/>` : "") +
				`<text x="${lx + 18}" y="${ly}"${cls === "accent" || !cls ? ` class="ours"` : ""}>${n}</text>`,
		);
	});
	out.push(`</svg>`);
	return out.join("\n");
}

function niceStep(raw: number) {
	const p = 10 ** Math.floor(Math.log10(raw));
	for (const k of [1, 2, 2.5, 5, 10]) if (k * p >= raw) return k * p;
	return 10 * p;
}
function fmt(v: number) {
	return Number.isInteger(v) ? String(v) : v.toFixed(1);
}

// ---------------------------------------------------------------- output

const docs = join(root, "docs");
mkdirSync(docs, { recursive: true });
const nSecrets = oursHoldout.confident.secrets;
const nKeeps = oursHoldout.confident.keeps;
writeFileSync(
	join(docs, "holdout.svg"),
	scatter(
		points,
		"Held-out test set: secrets caught vs. look-alikes destroyed",
		`${holdout.length} cases, ${nSecrets} secrets, ${nKeeps} look-alike values that must survive; never used for tuning`,
	) + "\n",
);
const realMB = oursReal.confident.mb;
writeFileSync(
	join(docs, "real-text.svg"),
	barChart(
		bars,
		"Redactions per million characters of ordinary text",
		`${realMB.toFixed(0)} M characters of agent trajectories and source repos never used in development, with few real secrets (lower is better)`,
	) + "\n",
);
writeFileSync(
	join(root, "eval/out/results.json"),
	JSON.stringify({ holdout: oursHoldout, real: oursReal, points, bars }, null, 1),
);

console.log(`## Held-out corpus (${holdout.length} cases, ${nSecrets} secrets, ${nKeeps} keep values)\n`);
console.log(`| scanner | secrets caught | keep values lost |\n|---|---:|---:|`);
for (const p of [...points].sort((a, b) => b.recall - a.recall))
	console.log(`| ${p.ours ? `**${p.name}**` : p.name} | ${pct(p.recall)} | ${pct(p.loss)} |`);
if (variantRows.length)
	console.log(
		`\nfile-naming variants (recall / loss):\n\n| scanner | variants |\n|---|---|\n${variantRows.join("\n")}`,
	);
console.log(`\n## Real text (${realMB.toFixed(1)} MB)\n`);
console.log(`| scanner | redactions per MB | SHAs, digests and UUIDs hidden per MB |\n|---|---:|---:|`);
for (const b of [...bars].sort((a, b) => a.perMB - b.perMB))
	console.log(`| ${b.ours ? `**${b.name}**` : b.name} | ${b.perMB.toFixed(2)} | ${b.damagePerMB.toFixed(3)} |`);
