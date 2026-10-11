/**
 * Recall fuzzing: seeded random passwords and keys from several generators, in every context the name and
 * structure layers read (secret files included). Each cell reports how many leaked (score.ts's rule).
 * A shape-based keep that a random value can satisfy shows up here as a leak rate above zero.
 *
 *   node eval/fuzz-secrets.ts [perCell=300] [seed=1]
 */
import { Redactor } from "../src/index.ts";
import { mulberry32 } from "./random.ts";
import { leaked } from "./score.ts";

let rand = mulberry32(1);
/** Restarts the generators' sequence. */
export const seed = (n: number) => {
	rand = mulberry32(n);
};
const pick = (s: string, n: number) => Array.from({ length: n }, () => s[Math.floor(rand() * s.length)]).join("");
const between = (a: number, b: number) => a + Math.floor(rand() * (b - a + 1));
const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const WORDS = [
	"Maple",
	"Orbit",
	"Harbor",
	"Falcon",
	"Cobalt",
	"River",
	"Sierra",
	"Winter",
	"Copper",
	"Island",
	"Tiger",
	"Quartz",
	"Summer",
	"Birch",
	"Ember",
	"Lunar",
];
const PHRASE_WORDS = [
	...WORDS,
	"New",
	"Get",
	"Set",
	"Start",
	"Test",
	"Read",
	"Find",
	"Save",
	"Send",
	"Copy",
	"Join",
	"Open",
	"Var",
	"Local",
	"Data",
	"Self",
	"Config",
	"Env",
	"Path",
	"Await",
	"Import",
	"Lambda",
	"Fn",
];
export const GENERATORS: Record<string, () => string> = {
	symbols: () => pick(ALNUM + "!@#$%^&*()-_=+[]{};:,.<>/?~|", between(12, 24)),
	common: () => pick(ALNUM + "!@#$%^&*", between(14, 24)),
	alnum: () => pick(ALNUM, between(20, 40)),
	base64: () => pick(ALNUM + "+/", 43) + "=",
	long: () => pick(ALNUM + "+/", between(100, 700)),
	hex: () => pick("0123456789abcdef", [32, 40, 64][between(0, 2)]),
	human: () => WORDS[between(0, WORDS.length - 1)] + between(10, 9999) + "!@#$%&*"[between(0, 6)],
	// Words a person strings together, code's words among them: `Get-Lucky#2291`, `New(Falcon)77`, `Self.Orbit!copper`.
	phrase: () => {
		const word = () => PHRASE_WORDS[between(0, PHRASE_WORDS.length - 1)];
		const sep = () => "-_.!@#$&*(:/+?"[between(0, 13)];
		return word() + sep() + word() + sep() + (between(0, 1) ? String(between(0, 9999)) : word().toLowerCase());
	},
	// A person's password in the shape of code: `spring.Boot2024`, `Harbor[2291]`, `Summer(2024)`, `:Cereal7483`, `jaguar.Heavy.aware`.
	codelike: () => {
		const word = () => WORDS[between(0, WORDS.length - 1)];
		const n = between(10, 9999);
		const shapes = [
			() => `${word().toLowerCase()}.${word()}${n}`,
			() => `${word()}[${n}]`,
			() => `${word()}(${n})`,
			() => `:${word()}${n}`,
			() => `${word().toLowerCase()}.${word()}.${word().toLowerCase()}`,
		];
		return shapes[between(0, shapes.length - 1)]();
	},
	// A person's password with what placeholders are made of inside it: `Maple...River3012`, `Fake!Orbit2291`, `Harbor123456789!`.
	marked: () => {
		const word = () => WORDS[between(0, WORDS.length - 1)];
		const mark = ["...", "…", "123456789", "Fake!", "invalid", "_HERE", "-XXXX", "dummy", "abcdefghij"][between(0, 8)];
		return between(0, 1)
			? word() + mark + word() + between(10, 9999)
			: mark + word() + between(10, 9999) + "!@#$%&*"[between(0, 6)];
	},
};
const sq = (v: string) => !/'/.test(v);
/** Contexts that name a key, not a password: a key's name asks for a generator's value, so a person's words aren't tried there. */
const KEY_CONTEXTS = new Set(["js", "shell export"]);
export const CONTEXTS: Record<
	string,
	{ text: (v: string) => string | undefined; hint?: { command?: string; path?: string } }
> = {
	env: { text: (v) => `DB_PASSWORD=${v}` },
	"cat .env": { text: (v) => `NODE_ENV=production\nDB_PASSWORD=${v}\nPORT=8080`, hint: { command: "cat .env" } },
	yaml: { text: (v) => `database:\n  host: db\n  password: ${JSON.stringify(v)}` },
	json: { text: (v) => JSON.stringify({ user: "app", password: v }) },
	python: { text: (v) => (sq(v) && !v.endsWith("\\") ? `password = '${v}'` : undefined) },
	js: { text: (v) => `const apiKey = ${JSON.stringify(v)};` },
	"shell export": { text: (v) => (sq(v) ? `export API_TOKEN='${v}'` : undefined) },
	"mysql -p": { text: (v) => (sq(v) ? `mysql -u root -p'${v}' app` : undefined) },
	url: { text: (v) => `DATABASE_URL=postgres://app:${encodeURIComponent(v)}@db.internal:5432/app` },
	"hcl aligned": { text: (v) => `  user             = "app"\n  password         = ${JSON.stringify(v)}` },
	"curl -u": { text: (v) => (sq(v) ? `curl -u 'admin:${v}' https://api.example.com/v1/me` : undefined) },
	compose: { text: (v) => `    environment:\n      - POSTGRES_PASSWORD=${v}` },
};

export function fuzz(n: number, start = 1, guessing: "off" | "confident" = "confident") {
	seed(start);
	const r = new Redactor({ guessing, fingerprintKey: "fuzz" });
	const cells: { gen: string; ctx: string; leaks: number; total: number; examples: string[] }[] = [];
	for (const [gen, make] of Object.entries(GENERATORS)) {
		for (const [ctx, c] of Object.entries(CONTEXTS)) {
			if ((gen === "phrase" || gen === "marked" || gen === "codelike") && KEY_CONTEXTS.has(ctx)) continue;
			const cell = { gen, ctx, leaks: 0, total: 0, examples: [] as string[] };
			for (let i = 0; i < n; i++) {
				const v = make();
				const text = c.text(v);
				if (text === undefined) continue;
				cell.total++;
				const out = r.redact(text, { hint: c.hint }).text;
				const secret = ctx === "url" ? encodeURIComponent(v) : v;
				if (leaked(secret, out)) {
					cell.leaks++;
					if (cell.examples.length < 3)
						cell.examples.push(text.split("\n").find((l) => l.includes(secret.slice(0, 6))) ?? text);
				}
			}
			cells.push(cell);
		}
	}
	return cells;
}

if (import.meta.main) {
	const cells = fuzz(Number(process.argv[2] ?? 300), Number(process.argv[3] ?? 1));
	let leaks = 0;
	let total = 0;
	for (const c of cells) {
		leaks += c.leaks;
		total += c.total;
		if (c.leaks)
			console.log(
				`${c.gen.padEnd(8)} ${c.ctx.padEnd(13)} ${String(c.leaks).padStart(4)}/${c.total}  ${c.examples.map((e) => JSON.stringify(e)).join("  ")}`,
			);
	}
	console.log(`total: ${leaks}/${total} leaked (${((100 * leaks) / total).toFixed(2)}%)`);
}
