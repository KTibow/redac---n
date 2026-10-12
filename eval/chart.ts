/**
 * What the README's charts share: their style (light and dark, via prefers-color-scheme inside the SVG), text
 * helpers, and the scatter panel of secrets caught against values lost that eval/creddata-chart.ts draws.
 */

export const FONT = `system-ui, -apple-system, "Segoe UI", sans-serif`;
// Plain class rules (no CSS variables, which some SVG renderers ignore); dark mode by media query.
export const STYLE = `<style>
.bg { fill: #fcfcfb; } .accent { fill: #2a78d6; } .accent-line { stroke: #2a78d6; } .other { fill: #898781; }
.hollow { fill: none; stroke: #898781; } .chain { fill: none; stroke: #c3c2b7; stroke-width: 1.5; }
.k0 { fill: #2a78d6; } .k1 { fill: #eb6834; } .k2 { fill: #1baf7a; } .k3 { fill: #b9b8b2; } .gap { stroke: #fcfcfb; stroke-width: 2; }
.ring { stroke: #fcfcfb; } .grid { stroke: #e1e0d9; stroke-width: 1; } .axis, .lead { stroke: #c3c2b7; stroke-width: 1; }
text { font-family: ${FONT}; fill: #52514e; font-size: 12px; }
.title { fill: #0b0b0b; font-size: 15px; font-weight: 600; } .panel { fill: #0b0b0b; font-size: 13px; font-weight: 600; }
.tick { fill: #898781; font-size: 11px; font-variant-numeric: tabular-nums; }
.ours { fill: #0b0b0b; font-weight: 600; }
@media (prefers-color-scheme: dark) {
  .bg { fill: #1a1a19; } .accent { fill: #3987e5; } .accent-line { stroke: #3987e5; } .ring { stroke: #1a1a19; }
  .other { fill: #a3a29c; } .hollow { stroke: #a3a29c; } .chain { stroke: #4a4a47; }
  .k0 { fill: #3987e5; } .k1 { fill: #d95926; } .k2 { fill: #199e70; } .k3 { fill: #5e5d58; } .gap { stroke: #1a1a19; }
  .grid { stroke: #2c2c2a; } .axis, .lead { stroke: #383835; }
  text { fill: #c3c2b7; } .title, .panel, .ours { fill: #ffffff; }
}
</style>`;

export function esc(s: string): string {
	return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
export const textWidth = (s: string, size = 12) => s.length * size * 0.56;
export function pct(x: number, digits = 1): string {
	return `${(x * 100).toFixed(digits)}%`;
}
/** Names run together: `a`, `a and b`, `a, b and c`. */
export function joinNames(names: string[]): string {
	return names.length < 2 ? (names[0] ?? "") : `${names.slice(0, -1).join(", ")} and ${names.at(-1)}`;
}

/** A tool on a scatter: what it caught and lost; drawn in the accent colour (ours), grey (other) or hollow (tuned on the data). */
export interface Dot {
	name: string;
	caught: number;
	lost: number;
	look: "ours" | "other" | "tuned";
	/** Its label, the name if not given; null for none (one of a series the series' label names). */
	label?: string | null;
}

/** A line through dots, by name, in order: redac---n's settings (`accent-line`), or nested unions (`chain`). */
export interface Line {
	names: string[];
	cls: string;
}

/**
 * One scatter panel at (`x`, `y`) of `w` × `h`: recall up, loss across on a square-root scale. Tools that catch
 * under `minCaught` aren't drawn (near the origin they'd crowd the frontier without being on it): they come back as
 * `note`, lines of text giving their numbers, for the caller to place. Dots within 6 pixels of each other share one
 * label (`gitleaks and Betterleaks`). Labels may run `margin` pixels past the panel's right edge.
 */
export function scatterPanel(
	{ x: ox, y: oy, w, h }: { x: number; y: number; w: number; h: number },
	dots: Dot[],
	lines: Line[],
	{ minCaught = 0.01, margin = 8 }: { minCaught?: number; margin?: number } = {},
): { svg: string[]; note: string[] } {
	const drawn = dots.filter((d) => d.look === "ours" || d.caught >= minCaught);
	const rare = dots.filter((d) => d.look !== "ours" && d.caught < minCaught);
	// (Headroom on the right, for the labels of the dots that lose most.)
	const xMax = Math.max(0.02, ...drawn.map((d) => d.lost)) * 1.3;
	const x = (v: number) => ox + (Math.sqrt(v) / Math.sqrt(xMax)) * w;
	const y = (v: number) => oy + h - v * h;
	const svg: string[] = [];
	for (let t = 0; t <= 1.0001; t += 0.25)
		svg.push(
			`<line class="grid" x1="${ox}" x2="${ox + w}" y1="${y(t)}" y2="${y(t)}"/><text class="tick" x="${ox - 6}" y="${y(t) + 4}" text-anchor="end">${pct(t, 0)}</text>`,
		);
	// (Ticks at least 28 pixels apart, the smaller dropped first.)
	const ticks: number[] = [];
	for (const t of [1, 0.8, 0.5, 0.3, 0.2, 0.1, 0.05, 0.02, 0.01, 0.005, 0])
		if (t <= xMax && ticks.every((u) => Math.abs(x(u) - x(t)) >= 28)) ticks.push(t);
	for (const t of ticks)
		svg.push(
			`<line class="grid" x1="${x(t)}" x2="${x(t)}" y1="${oy}" y2="${oy + h}"/><text class="tick" x="${x(t)}" y="${oy + h + 14}" text-anchor="middle">${pct(t, t && t < 0.01 ? 1 : 0)}</text>`,
		);
	const at = new Map(drawn.map((d) => [d.name, d]));
	const boxes: number[][] = drawn.map((d) => [x(d.lost) - 5, y(d.caught) - 5, x(d.lost) + 5, y(d.caught) + 5]);
	for (const l of lines) {
		const ds = l.names.map((n) => at.get(n)).filter((d) => d !== undefined);
		if (ds.length < 2) continue;
		svg.push(
			`<polyline fill="none" class="${l.cls}" stroke-width="2" points="${ds.map((d) => `${x(d.lost)},${y(d.caught)}`).join(" ")}"/>`,
		);
		// (Labels keep off the line.)
		for (let i = 1; i < ds.length; i++) {
			const [x1, y1, x2, y2] = [x(ds[i - 1].lost), y(ds[i - 1].caught), x(ds[i].lost), y(ds[i].caught)];
			const steps = Math.max(1, Math.ceil(Math.hypot(x2 - x1, y2 - y1) / 4));
			for (let k = 0; k <= steps; k++) {
				const [lx, ly] = [x1 + ((x2 - x1) * k) / steps, y1 + ((y2 - y1) * k) / steps];
				boxes.push([lx - 2, ly - 2, lx + 2, ly + 2]);
			}
		}
	}
	const tip = (d: Dot) => `<title>${esc(`${d.name}: ${pct(d.caught)} caught, ${pct(d.lost)} lost`)}</title>`;
	for (const d of drawn.filter((d) => d.look !== "ours"))
		svg.push(
			`<circle cx="${x(d.lost)}" cy="${y(d.caught)}" r="4" class="${d.look === "tuned" ? "hollow" : "other ring"}" stroke-width="1.5">${tip(d)}</circle>`,
		);
	for (const d of drawn.filter((d) => d.look === "ours"))
		svg.push(
			`<circle cx="${x(d.lost)}" cy="${y(d.caught)}" r="5" class="accent ring" stroke-width="1.5">${tip(d)}</circle>`,
		);
	// Labels: ours first, then the rest from the top; dots within 6 pixels share one. Each goes at the first place
	// beside its dot that no dot, line or label takes, with a leader when it's set away.
	const groups: Dot[][] = [];
	for (const d of [...drawn].sort(
		(a, b) => Number(b.look === "ours") - Number(a.look === "ours") || b.caught - a.caught,
	)) {
		if (d.label === null) continue;
		const g = groups.find(
			(g) => g[0].look === d.look && Math.hypot(x(g[0].lost) - x(d.lost), y(g[0].caught) - y(d.caught)) < 6,
		);
		if (g) g.push(d);
		else groups.push([d]);
	}
	for (const g of groups) {
		// (A dot's own label alone; shared, each by its full name.)
		const label = g.length === 1 ? (g[0].label ?? g[0].name) : joinNames(g.map((d) => d.name));
		const px = x(g[0].lost);
		const py = y(g[0].caught);
		const tw = textWidth(label, 11);
		// (Further out step by step, a leader once it's set away; if none is free, where it covers least.)
		const tries: [number, number, "start" | "end"][] = [];
		for (const d of [0, 12, 24, 36, 48, 60, 72, 84, 96])
			tries.push([8, 4 - d, "start"], [-8, 4 - d, "end"], [8, 17 + d, "start"], [-8, 17 + d, "end"]);
		const boxOf = ([dx, dy, anchor]: [number, number, "start" | "end"]) => {
			const x0 = anchor === "start" ? px + dx : px + dx - tw;
			return [x0, py + dy - 10, x0 + tw, py + dy + 3];
		};
		const covered = (b: number[]) =>
			b[0] < ox - 4 || b[2] > ox + w + margin || b[1] < oy - 6 || b[3] > oy + h + 2
				? Infinity
				: boxes.reduce(
						(sum, o) =>
							sum +
							Math.max(0, Math.min(b[2], o[2]) - Math.max(b[0], o[0])) *
								Math.max(0, Math.min(b[3], o[3]) - Math.max(b[1], o[1])),
						0,
					);
		const scored = tries.map((t) => [t, covered(boxOf(t))] as const);
		const [[dx, dy, anchor]] = scored.find(([, c]) => c === 0) ?? scored.reduce((a, b) => (b[1] < a[1] ? b : a));
		boxes.push(boxOf([dx, dy, anchor]));
		if (Math.abs(dy) > 12)
			svg.push(
				`<line class="lead" x1="${px}" y1="${py + (dy < 0 ? -4 : 4)}" x2="${px + dx}" y2="${py + dy + (dy < 0 ? 2 : -10)}"/>`,
			);
		svg.push(
			`<text x="${px + dx}" y="${py + dy}" text-anchor="${anchor}"${g[0].look === "ours" ? ' class="ours"' : ""} font-size="11">${esc(label)}</text>`,
		);
	}
	// The note: what wasn't drawn, wrapped to the panel's width.
	const note: string[] = [];
	if (rare.length) {
		note.push(`Catch under ${pct(minCaught, 0)}, not drawn (caught / lost):`);
		for (const e of rare.map((d) => `${d.name} ${pct(d.caught)} / ${pct(d.lost, 2)}`)) {
			const last = note.at(-1)!;
			if (note.length > 1 && textWidth(`${last}, ${e}`, 11) <= w) note[note.length - 1] = `${last}, ${e}`;
			else note.push(e);
		}
	}
	return { svg, note };
}
