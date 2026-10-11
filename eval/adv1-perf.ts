/**
 * Reproduces the performance and robustness problems found by the adv1 robustness pass.
 *
 *   node eval/adv1-perf.ts [filter-regex] [--max 1000000]
 *
 * Each case is timed at growing sizes (stopping once a step takes over 3s). A case is flagged SLOW if
 * any step runs under 1 MB/s, and SUPERLINEAR if 10x the input costs over 20x the time.
 * The last section checks inputs that make the library throw.
 */
import { Redactor } from "../src/index.ts";
import { Args } from "./args.ts";
import { randomInts } from "./random.ts";

const args = new Args();
const MAX = args.num("max", 1_000_000);
const only = args.rest[0] ? new RegExp(args.rest[0]) : undefined;

const rep = (s: string, n: number) => s.repeat(Math.ceil(n / s.length)).slice(0, n);
const rand = randomInts(7);
const B62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const tokens = (n: number, sep: string, len = 24) => {
	let s = "";
	while (s.length < n) {
		for (let i = 0; i < len; i++) s += B62[rand(62)];
		s += sep;
	}
	return s.slice(0, n);
};

interface PerfCase {
	name: string;
	where: string;
	sizes?: number[];
	run: (n: number) => () => unknown;
}

const r = new Redactor({ fingerprintKey: "perf" });
const redactOf = (gen: (n: number) => string) => (n: number) => {
	const t = gen(n);
	return () => new Redactor({ fingerprintKey: "perf" }).redact(t);
};
const streamOf = (gen: (n: number) => string, chunk: number) => (n: number) => {
	const t = gen(n);
	return () => {
		const s = r.stream();
		for (let i = 0; i < t.length; i += chunk) s.write(t.slice(i, i + chunk));
		s.end();
	};
};
const proseLine = "The quick brown fox jumps over the lazy dog while compiling src/index.ts at line 42.\n";
const secret = (i: number) => `ghp_${"a1B2c3D4e5F6g7H8i9J0".repeat(2).slice(0, 32)}${String(i).padStart(4, "0")}`;

const CASES: PerfCase[] = [
	// Baselines.
	{ name: "baseline: prose", where: "-", run: redactOf((n) => rep(proseLine, n)) },
	{
		name: "baseline: minified-ish JSON",
		where: "-",
		run: redactOf((n) =>
			JSON.stringify(Array.from({ length: n / 60 }, (_, i) => ({ id: i, name: `item${i}`, value: `v${i}` }))),
		),
	},

	// Quadratic regexes.
	{
		name: "run of '-' (no newline)",
		where: "structure.ts flagListItems guard /--?[\\w-]*(?:pass|token|secret|key|auth)/i",
		sizes: [3_000, 10_000, 30_000, 100_000],
		run: redactOf((n) => "-".repeat(n)),
	},
	{
		name: "'sk-' repeated",
		where: "same guard regex",
		sizes: [10_000, 30_000, 100_000],
		run: redactOf((n) => rep("sk-", n)),
	},
	{
		name: "'-a' then long \\w run, no keyword",
		where: "same guard regex",
		sizes: [10_000, 30_000, 100_000],
		run: redactOf((n) => rep("-abcdefghij", n)),
	},

	// Linear but with a very large constant (the ASSIGN loop reads up to 4096 chars of value per match).
	{
		name: "'api_key=' repeated on one line",
		where: "named.ts assignments: readValue(…, 4096) + isNamedSecret per match",
		run: redactOf((n) => rep("api_key=", n)),
	},
	{
		name: "'?sig=' repeated on one line",
		where: "named.ts assignments (name `sig`)",
		run: redactOf((n) => rep("?sig=", n)),
	},
	{
		name: "'aws_secret_access_key=' repeated",
		where: "named.ts assignments",
		run: redactOf((n) => rep("aws_secret_access_key=", n)),
	},
	{
		name: "credential-column table headers",
		where: "named.ts columnTables: each header line scans up to 500 rows",
		sizes: [10_000, 30_000, 100_000],
		run: redactOf((n) => rep("api_key  secret_token\n", n)),
	},

	// Throughput below target on dense random-token text (unnamed layer, ~30µs per candidate).
	{
		name: "random 24-char tokens, space-separated",
		where: "context.ts contextOf per candidate on one long line (its left and right windows, the name regexes)",
		run: redactOf((n) => tokens(n, " ")),
	},
	{
		name: "random 24-char tokens, one per line",
		where: "context.ts columnAbove and pipeColumnAbove (25 and 40 lines above each candidate) + contextOf",
		run: redactOf((n) => tokens(n, "\n")),
	},
	{
		name: "tokens inside an unterminated BEGIN PUBLIC KEY",
		where: "same as space-separated tokens, plus Doc.inPublicArmor",
		run: redactOf((n) => "-----BEGIN PUBLIC KEY-----\n" + tokens(n, " ")),
	},
	{
		name: "CSV rows of random cells",
		where: "context.ts Doc.csvBlockTop: each cell's column header, a block's rows walked once",
		run: redactOf((n) => `id,name,ref,note\n${tokens(n, "\n", 60).replace(/(.{20})(.{20})(.{20})/g, "$1,$2,x,$3")}`),
	},
	{
		name: "long [0-9a-f]/i run (digits, 'aaaa')",
		where: "index.ts findHexDumps /(?:[0-9a-f]{16,200}\\r?\\n){1,100000}…/gi tries 200 chars at every offset",
		run: redactOf((n) => rep("1234567890", n)),
	},
	{
		name: "same secret on 1 line in 27",
		where: "index.ts repeats(): found.some() per occurrence",
		run: redactOf((n) => rep("DB_PASSWORD=Vq8#Lm2!Rz7pKw\n", n)),
	},

	// stream(): every write() after the buffer passes `holdback` re-runs detect() on the whole buffer.
	{
		name: "stream(), 100-byte chunks of prose",
		where: "index.ts stream().flush re-detects ≥16KB per write",
		sizes: [30_000, 100_000, 300_000],
		run: streamOf((n) => rep(proseLine, n), 100),
	},
	{
		name: "stream(), no newline, 1KB chunks",
		where: "index.ts stream(): no `\\n` to cut at, buffer grows, detect() on all of it per write",
		sizes: [50_000, 100_000, 200_000, 400_000],
		run: streamOf((n) => rep("lorem ipsum dolor sit amet ", n), 1000),
	},

	// redactValue(): setAt() copies the whole parent container for every redacted leaf.
	{
		name: "redactValue: array of N strings with a secret",
		where: "transcript.ts setAt: O(N) copy per redacted leaf",
		sizes: [1_000, 4_000, 16_000],
		run: (n) => {
			const v = Array.from({ length: n }, (_, i) => `line ${i} ${secret(i)}`);
			return () => new Redactor().redactValue(v);
		},
	},
	{
		name: "redactValue: object with N keys with a secret",
		where: "known.ts LiteralIndex (learned values sharing their first 16 characters)",
		sizes: [1_000, 4_000, 16_000],
		run: (n) => {
			const v: Record<string, string> = {};
			for (let i = 0; i < n; i++) v[`k${i}`] = `x ${secret(i)}`;
			return () => new Redactor().redactValue(v);
		},
	},

	// Hints.
	{
		name: "hint.command: 'kubectl' + many 'get secret', no -o",
		where: "commands.ts SECRET_TOOLS /kubectl\\b.*\\bget\\s+secrets?\\b.*-o\\s*=?\\s*(?:jsonpath|go-template)/",
		sizes: [10_000, 30_000, 100_000],
		run: (n) => {
			const command = "kubectl " + rep("get secret ", n);
			return () => r.redact("x", { hint: { command } });
		},
	},
];

const fmt = (ms: number) => (ms >= 1000 ? `${(ms / 1000).toFixed(2)}s` : `${ms.toFixed(0)}ms`);
r.redact("warm up sk-proj-abcdefghij1234567890ABCD password=hunter22");
for (const c of CASES) {
	if (only && !only.test(c.name)) continue;
	const sizes = (c.sizes ?? [10_000, 100_000, 1_000_000]).filter((n) => n <= MAX);
	const points: [number, number][] = [];
	for (const n of sizes) {
		const f = c.run(n);
		const t0 = performance.now();
		f();
		const ms = performance.now() - t0;
		points.push([n, ms]);
		if (ms > 3000) break;
	}
	const flags: string[] = [];
	for (let i = 1; i < points.length; i++) {
		const [n0, t0] = points[i - 1];
		const [n1, t1] = points[i];
		if (t0 > 5 && t1 / t0 > 2 * (n1 / n0)) flags.push("SUPERLINEAR");
	}
	const big = points.filter(([n]) => n >= 10_000);
	if (big.some(([n, ms]) => n / 1e6 / (ms / 1000) < 1)) flags.push("SLOW");
	console.log(
		`${c.name}\n  ${points.map(([n, ms]) => `${n >= 1e6 ? `${n / 1e6}M` : `${n / 1e3}K`}: ${fmt(ms)}`).join("  ")}  ${[...new Set(flags)].join(" ")}\n  ${c.where}`,
	);
}

// --- Inputs that throw ---------------------------------------------------------------------------
if (!only || only.test("throws")) {
	console.log("\nthrows:");
	const tryIt = (label: string, f: () => unknown) => {
		try {
			f();
			console.log(`  ok      ${label}`);
		} catch (e) {
			console.log(`  THROWS  ${label}: ${String(e).slice(0, 80)} (${(e as Error).stack?.split("\n")[1]?.trim()})`);
		}
	};
	for (const d of [2_000, 3_000, 5_000]) {
		tryIt(`redact() of a ${d}-deep JSON array beside a "value" key (${d * 2 + 16} chars)`, () =>
			r.redact(`{"value": "x", "a":${"[".repeat(d)}${"]".repeat(d)}}`),
		);
		tryIt(`redact() of a ${d}-deep JSON object beside a "value" key`, () =>
			r.redact(`{"value":"x","a":${'{"a":'.repeat(d)}1${"}".repeat(d)}}`),
		);
	}
	for (const d of [2_000, 5_000, 20_000]) {
		let v: unknown = "password=hunter2xyz";
		for (let i = 0; i < d; i++) v = [v];
		tryIt(`redactValue() of a ${d}-deep array (JSON.parse accepts it)`, () => new Redactor().redactValue(v));
	}
}
