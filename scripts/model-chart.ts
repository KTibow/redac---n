/**
 * Draws docs/models.svg: the guessing layer's forest against the other models it was compared with, each line one
 * model with its threshold swept, secrets caught against look-alikes destroyed on the development sets.
 *
 *   node scripts/model-chart.ts
 *
 * The points were measured with eval/run.ts in the model comparison (its reports, eval/out/exp-fx.md, exp-x1.md and
 * exp-x3.md, stay out of the repository with the experiments' data); they're written here so the chart can be drawn
 * again without them.
 */
import { writeFileSync } from "node:fs";
import { join } from "node:path";

interface Series {
	name: string;
	/** Its colour, light theme then dark: Okabe and Ito's palette, told apart with colour blindness too. */
	color: [string, string];
	/** [look-alikes destroyed, secrets caught], as fractions, in threshold order. */
	points: [number, number][];
	ours?: boolean;
}

const SERIES: Series[] = [
	{
		name: "the forest with its vetoes",
		color: ["#2a78d6", "#3987e5"],
		ours: true,
		points: [
			[0.0173, 0.9541],
			[0.0162, 0.9531],
			[0.0153, 0.9528],
			[0.0146, 0.95],
			[0.0131, 0.9424],
		],
	},
	{
		name: "one logistic sum, the statistical vetoes on",
		color: ["#c98a00", "#e69f00"],
		points: [
			[0.0189, 0.953],
			[0.0184, 0.9517],
			[0.0176, 0.95],
			[0.0162, 0.9479],
		],
	},
	{
		name: "one logistic sum, with a language model's labels",
		color: ["#c84f00", "#e3712c"],
		points: [
			[0.0206, 0.9522],
			[0.0177, 0.9494],
			[0.0159, 0.9457],
			[0.0141, 0.9408],
			[0.0131, 0.9382],
		],
	},
	{
		name: "one logistic sum, without them",
		color: ["#b4518d", "#d38ab8"],
		points: [
			[0.0198, 0.9488],
			[0.0169, 0.946],
			[0.0152, 0.943],
			[0.014, 0.939],
			[0.0129, 0.934],
			[0.0119, 0.93],
			[0.0109, 0.9209],
		],
	},
	{
		name: "a linear model of the 40 characters before the token",
		color: ["#00876a", "#2fb38f"],
		points: [[0.0154, 0.947]],
	},
	{
		name: "the product P(generated) × P(secret | generated)",
		color: ["#7a7974", "#a3a29c"],
		points: [[0.0127, 0.9326]],
	},
	{
		name: "the forest given the vetoes' context as features",
		color: ["#8c6d1f", "#b8964a"],
		points: [[0.0126, 0.932]],
	},
];

const FONT = `system-ui, -apple-system, "Segoe UI", sans-serif`;
const STYLE = `<style>
.bg { fill: #fcfcfb; } ${SERIES.map((s, i) => `.s${i} { fill: ${s.color[0]}; stroke: ${s.color[0]}; }`).join(" ")}
.ring { stroke: #fcfcfb; } .grid { stroke: #e1e0d9; stroke-width: 1; } .axis { stroke: #c3c2b7; stroke-width: 1; }
text { font-family: ${FONT}; fill: #52514e; font-size: 12px; }
.title { fill: #0b0b0b; font-size: 15px; font-weight: 600; }
.tick { fill: #898781; font-size: 11px; font-variant-numeric: tabular-nums; }
.ours { fill: #0b0b0b; font-weight: 600; }
@media (prefers-color-scheme: dark) {
  .bg { fill: #1a1a19; } ${SERIES.map((s, i) => `.s${i} { fill: ${s.color[1]}; stroke: ${s.color[1]}; }`).join(" ")} .ring { stroke: #1a1a19; }
  .grid { stroke: #2c2c2a; } .axis { stroke: #383835; }
  text { fill: #c3c2b7; } .title, .ours { fill: #ffffff; }
}
</style>`;

const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const pct = (v: number, d = 1) => `${(v * 100).toFixed(d)}%`;

const W = 760;
const H = 480;
const m = { l: 64, r: 24, t: 64, b: 52 };
const pw = W - m.l - m.r;
const ph = H - m.t - m.b;
const [x0, x1] = [0.01, 0.022];
const [y0, y1] = [0.92, 0.96];
const x = (v: number) => m.l + ((v - x0) / (x1 - x0)) * pw;
const y = (v: number) => m.t + ph - ((v - y0) / (y1 - y0)) * ph;

const title = "Why a forest: secrets caught against look-alikes destroyed";
const sub = "Development sets; each line is one model with its threshold swept. Up and to the left is better.";
const out: string[] = [];
out.push(
	`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-labelledby="t d">`,
);
out.push(
	`<title id="t">${esc(title)}</title><desc id="d">${esc(SERIES.map((s) => `${s.name}: ${s.points.map(([l, r]) => `${pct(r, 2)} caught at ${pct(l, 2)} destroyed`).join(", ")}`).join("; "))}</desc>`,
);
out.push(STYLE);
out.push(`<rect width="${W}" height="${H}" rx="8" class="bg"/>`);
out.push(`<text x="16" y="26" class="title">${esc(title)}</text>`);
out.push(`<text x="16" y="44">${esc(sub)}</text>`);
for (let t = y0; t <= y1 + 1e-9; t += 0.01) {
	out.push(`<line class="grid" x1="${m.l}" x2="${m.l + pw}" y1="${y(t)}" y2="${y(t)}"/>`);
	out.push(`<text class="tick" x="${m.l - 8}" y="${y(t) + 4}" text-anchor="end">${Math.round(t * 100)}%</text>`);
}
for (let t = x0; t <= x1 + 1e-9; t += 0.002) {
	out.push(`<line class="grid" x1="${x(t)}" x2="${x(t)}" y1="${m.t}" y2="${m.t + ph}"/>`);
	out.push(`<text class="tick" x="${x(t)}" y="${m.t + ph + 18}" text-anchor="middle">${(t * 100).toFixed(1)}%</text>`);
}
out.push(`<line class="axis" x1="${m.l}" x2="${m.l + pw}" y1="${m.t + ph}" y2="${m.t + ph}"/>`);
out.push(
	`<text x="${m.l + pw}" y="${H - 10}" text-anchor="end">look-alike values destroyed (lower is better) →</text>`,
);
out.push(`<text transform="translate(12 ${m.t + ph}) rotate(-90)">secrets caught (higher is better) →</text>`);
// Lines first, the forest's last so it's on top; then the points.
const order = [...SERIES.keys()].sort((i, j) => Number(!!SERIES[j].ours) - Number(!!SERIES[i].ours)).reverse();
for (const i of order) {
	const s = SERIES[i];
	if (s.points.length > 1)
		out.push(
			`<polyline fill="none" class="s${i}" style="fill:none" stroke-width="${s.ours ? 2.5 : 2}" points="${s.points.map(([l, r]) => `${x(l)},${y(r)}`).join(" ")}"/>`,
		);
}
for (const i of order) {
	const s = SERIES[i];
	for (const [l, r] of s.points)
		out.push(
			`<circle cx="${x(l)}" cy="${y(r)}" r="${s.ours ? 5 : 4}" class="s${i} ring" stroke-width="2"><title>${esc(`${s.name}: ${pct(r, 2)} caught, ${pct(l, 2)} destroyed`)}</title></circle>`,
		);
}
// The legend, in the plot's empty corner: low recall at high loss, where no model sits.
const rowH = 19;
const lx = m.l + pw - 330;
const ly = m.t + ph - SERIES.length * rowH - 6;
SERIES.forEach((s, i) => {
	const cy = ly + i * rowH + rowH / 2;
	out.push(
		`<line x1="${lx}" x2="${lx + 18}" y1="${cy}" y2="${cy}" class="s${i}" stroke-width="2"/><circle cx="${lx + 9}" cy="${cy}" r="4" class="s${i}"/><text x="${lx + 26}" y="${cy + 4}"${s.ours ? ` class="ours"` : ""}>${esc(s.name)}</text>`,
	);
});
out.push(`</svg>`);
writeFileSync(join(import.meta.dirname, "..", "docs", "models.svg"), out.join("\n") + "\n");
