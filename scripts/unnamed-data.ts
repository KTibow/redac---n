/**
 * Training data for the unnamed-token scorer, as feature vectors:
 *
 * - Negatives: every candidate in the real dev corpora that survives the hard vetoes. Public code and
 *   agent trajectories hold very few real keys, so nearly all of these are hashes, IDs, encodings and
 *   identifiers in their natural contexts.
 * - Positives: random keys (CSPRNG, many alphabets and lengths, some with vendor-style prefixes)
 *   placed in the syntactic slots unnamed keys turn up in, with real corpus lines around them.
 *
 * The agent-written corpora under eval/corpora are never used here; they measure the result.
 *
 * Inference differs slightly: it scores candidates in normalized, JSON-decoded text, minus spans the
 * other layers already took; here the raw text is scored with nothing taken. Secret files are left to
 * findInSecretFile, so every example is scored as ordinary text.
 *
 *   node scripts/unnamed-data.ts [--statistical] > ~/Downloads/redact-corpora/built/unnamed-train.jsonl
 *
 * With `--statistical`, the vetoes that judge a token's look (unnamed.ts STATISTICAL_VETOES) don't filter the examples:
 * the model is trained on the tokens they would rule out, and positives run to 200 characters.
 */
const statistical = process.argv.includes("--statistical");
// Seeded, so the training data and the model are reproducible.
let seed = 0x5eed;
function next(): number {
	seed = (seed + 0x6d2b79f5) | 0;
	let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
	t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
	return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}
const randomInt = (n: number) => Math.floor(next() * n);
const randomBytes = (n: number) => {
	const b = Buffer.alloc(n);
	for (let i = 0; i < n; i++) b[i] = randomInt(256);
	return b;
};
import { createReadStream } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { Doc } from "../src/context.ts";
import { naturalness } from "../src/charlm.ts";
import { VENDOR_CLIENTS } from "../src/names.ts";
import { candidates, features, vector, vetoed } from "../src/unnamed.ts";
import { CORPORA } from "../eval/data-root.ts";

const B62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const pick = <T>(xs: readonly T[]): T => xs[randomInt(xs.length)];
function randomFrom(alphabet: string, n: number): string {
	let s = "";
	for (let i = 0; i < n; i++) s += alphabet[randomInt(alphabet.length)];
	return s;
}

/** A random key in one of the shapes services issue. */
function randomKey(): string {
	const n = pick(
		statistical
			? [16, 20, 24, 24, 26, 30, 32, 32, 32, 36, 40, 40, 43, 44, 48, 50, 56, 64, 64, 72, 86, 96, 120, 128, 160, 200]
			: [16, 20, 24, 24, 26, 30, 32, 32, 32, 36, 40, 40, 43, 44, 48, 50, 56, 64, 64, 72, 86],
	);
	switch (randomInt(12)) {
		case 0:
		case 1:
		case 2:
			return randomFrom(B62, n);
		case 3: {
			// (And the lengths `openssl rand -base64 64`, `96` and `128` print: keys longer than other alphabets' run.)
			const m = randomInt(4) ? n : pick([88, 128, 172]);
			return randomBytes(Math.ceil((m * 3) / 4))
				.toString("base64")
				.slice(0, m);
		}
		case 4:
			return randomBytes(Math.ceil((n * 3) / 4))
				.toString("base64url")
				.slice(0, n);
		case 5:
			return randomBytes(Math.ceil(Math.max(32, n) / 2))
				.toString("hex")
				.slice(0, Math.max(32, n));
		case 6:
			return randomFrom("abcdefghijklmnopqrstuvwxyz0123456789", n);
		case 7:
			return randomFrom("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", Math.min(n, 40));
		case 8: {
			// Vendor-style: a short word, a separator, a random body.
			const word = pick([
				"acme",
				"lum",
				"zap",
				"tok",
				"key",
				"api",
				"live",
				"prod",
				"sk",
				"pat",
				"srv",
				"app",
				"orb",
				"nx",
				"qz",
				"hx",
				"dev",
			]);
			return `${word}${pick(["_", "-", "_live_", "_test_", "-v1-"])}${randomFrom(B62, Math.max(20, n - 6))}`;
		}
		case 9:
			// Groups: `xxxx-xxxx-xxxx-xxxx`, `XXXXX-XXXXX-…`.
			return Array.from({ length: pick([4, 5, 6]) }, () =>
				randomFrom(pick([B62, "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"]), pick([4, 5, 6, 8])),
			).join("-");
		case 10:
			return `${randomFrom(B62, 24)}.${randomFrom(B62, 6)}.${randomFrom(B62 + "-_", 27)}`;
		default:
			return randomBytes(32)
				.toString("base64")
				.replace(/=+$/, randomInt(2) ? "=" : "");
	}
}

const NEUTRAL_NAMES = [
	"value",
	"data",
	"x",
	"v",
	"id_val",
	"conf",
	"setting",
	"lumen",
	"X-Lumen",
	"X-Client",
	"X-Partner",
	"X-Upstream",
	"X-Org",
	"upstream",
	"partner",
	"remote",
	"endpoint_auth",
	"license",
	"licence",
	"activation",
	"access",
	"ref",
	"handle",
	"blob",
	"param",
	"arg",
	"opaque",
	"creds",
	"material",
	"signing",
	"webhook",
	"hook",
	"relay",
	"bridge",
	"connector",
	"integration",
	"app",
	"client",
	"dsn_part",
	"magic",
	"nonce_val",
	"code",
	"pass_through",
	"FOO",
	"BAR",
	"DEPLOY_HOOK",
	"CI_VALUE",
	"LUMEN_AUTH",
	"SERVICE",
	"PROVIDER",
	"VENDOR_CONFIG",
	"SDK_INIT",
	"init",
	"seed_value",
	"salt_value",
];
const CALLS = [
	"Client",
	"new Client",
	"configure",
	"sdk.init",
	"init",
	"connect",
	"authenticate",
	"login",
	"Helix",
	"Lumen.setup",
	"api.use",
	"set_api",
	"useKey",
	"setToken",
	"createClient",
	"Stripe",
	"OpenAI",
	"client.auth",
	"with_key",
	"Auth",
];
const HANDOVER = [
	"here's the new key:",
	"use this one:",
	"token:",
	"try with",
	"Key created:",
	"Your API key is",
	"the staging key is",
	"new token ->",
	"creds:",
	"pw:",
	"this should work:",
	"rotated, new one is",
	"copy this:",
	"API key (shown once):",
];

/** The vendors whose client takes a key as its argument (names.ts VENDOR_CLIENTS), as isVendorClient reads them. */
const CLIENT_VENDORS = [...VENDOR_CLIENTS].filter((v) => /^[a-z]{4,}$/.test(v));
/** A vendor's client called with a key, a place hexVeto lets hex through: `algoliasearch("<app>", "<key>")`, `new TwilioClient("<key>")`. */
function vendorCall(k: string): string {
	const vendor = pick(CLIENT_VENDORS);
	const Vendor = vendor[0].toUpperCase() + vendor.slice(1);
	const callee = pick([
		vendor,
		`${vendor}${pick(["search", "sdk", "client", "api"])}`,
		`new ${Vendor}`,
		`new ${Vendor}Client`,
		vendor.toUpperCase(),
	]);
	const q = pick(['"', "'"]);
	return `${pick(["const client = ", "client = ", ""])}${callee}(${pick([`${q}${randomFrom(B62, 10)}${q}, `, ""])}${q}${k}${q})${pick(["", ";"])}`;
}

/** The secret in one of the slots unnamed keys turn up in. */
function slot(k: string): string {
	const name = pick(NEUTRAL_NAMES);
	// (Hex stands only in a key's place, or hexVeto rules it out: most slots below aren't one.)
	if (/^[0-9a-f]{32,}$/.test(k) && randomInt(3) === 0) return vendorCall(k);
	switch (randomInt(18)) {
		case 16:
			return `${pick(["$ ", "+ ", ""])}${pick(["./scripts/notify.sh", "./deploy.sh", "node scripts/sync.js", "python3 tools/push.py", "bin/release", "./run", "ops/rotate.sh"])} ${pick(["production", "staging", "--env prod", "us-east-1", ""])} ${k}`;
		case 17:
			return `${pick(["$ ", ""])}${pick(["vendorcli", "acme", "lumen", "partner-cli", "sdk"])} ${pick(["login", "auth", "configure", "init", "connect"])} ${pick(["", "--profile prod "])}${k}`;
		case 0:
			return `${name} = "${k}"`;
		case 1:
			return `${name}: ${k}`;
		case 2:
			return `"${name}": "${k}",`;
		case 3:
			return `${name.replace(/[^\w]/g, "_").toUpperCase()}=${k}`;
		case 4:
			return `${pick(["-H", "--header"])} "${pick(["X-Lumen", "X-Partner-Auth", "X-Client", "X-Org-Token", "X-Ref"])}: ${k}"`;
		case 5:
			return `${pick(CALLS)}("${k}")`;
		case 6:
			return `${pick(CALLS)}(${pick(['"acme", ', "region='us', ", ""])}"${k}"${pick([", timeout=5", "", ", debug=True"])})`;
		case 7:
			return `https://${pick(["hooks.zapier.com/hooks/catch/94182/", "api.example.com/v1/webhooks/", "relay.acme.io/in/", "example.com/bot", "maker.ifttt.com/trigger/x/with/key/", "chat.example.com/hooks/"])}${k}`;
		case 8:
			return `https://api.${pick(["acme", "lumen", "partner"])}.com/v2/items?${pick(["k", "auth", "access", "appid", "q", "license", "x"])}=${k}&limit=10`;
		case 9:
			return `${pick(HANDOVER)} ${k}`;
		case 10:
			return k; // a bare line
		case 11:
			return `  ${pick(["- ", ""])}${k}`;
		case 12:
			return `${pick(["export ", "set ", ""])}${name.toUpperCase().replace(/[^\w]/g, "_")}="${k}"`;
		case 13:
			return `[${pick(["INFO", "DEBUG", "WARN"])}] ${pick(["calling partner with", "auth header", "using", "retrying with", "upstream responded for"])} ${k}`;
		case 14:
			return `--${pick(["auth", "access", "hook", "relay", "license", "lumen", "partner"])} ${k}`;
		default:
			return `<${pick(["value", "data", "partner", "licence"])}>${k}</${pick(["value", "data", "partner", "licence"])}>`;
	}
}

/** Real lines to surround the slot with, from the corpus. */
const lines: string[] = [];
const rl = createInterface({ input: createReadStream(join(CORPORA, "built/dev.jsonl")) });
let n = 0;
let negatives = 0;
const seenTokens = new Map<string, number>();
const MAX_NEG = 250_000;
const out = (label: number, f: ReturnType<typeof features>, src: string) =>
	process.stdout.write(
		JSON.stringify({ y: label, x: vector(f), t: f.token.slice(0, 80), src, ctx: f.ctx.left.slice(-60) }) + "\n",
	);
for await (const line of rl) {
	n++;
	const { src, text } = JSON.parse(line) as { src: string; text: string };
	if (n % 50 === 0)
		for (const l of text.split("\n")) if (l.length > 5 && l.length < 200 && lines.length < 200_000) lines.push(l);
	if (negatives >= MAX_NEG) continue;
	const doc = new Doc(text);
	for (const c of candidates(text)) {
		// The same cheap gate as findUnnamed, and at most three examples of any one token.
		if (naturalness(c.token) > 1.2 && !/\d/.test(c.token)) continue;
		const seen = seenTokens.get(c.token) ?? 0;
		if (seen >= 3) continue;
		seenTokens.set(c.token, seen + 1);
		const f = features(doc, c, false);
		if (vetoed(f, { statistical: !statistical })) continue;
		// Public text holds some real credentials; ones with credential words around them aren't labelled negatives.
		if (
			f.ctx.lineCredential ||
			f.ctx.handover ||
			f.ctx.nameClass === "credential" ||
			/csrf|verifier|oauth|code=|state=|access|refresh|session|cookie/i.test(f.ctx.left)
		)
			continue;
		out(0, f, src);
		negatives++;
	}
}
console.error(`negatives ${negatives}`);
// As many positives as negatives, each in a window of real lines.
let positives = 0;
while (positives < negatives) {
	const key = randomKey();
	const s = slot(key);
	const before = Array.from({ length: randomInt(4) }, () => pick(lines)).join("\n");
	const after = Array.from({ length: randomInt(4) }, () => pick(lines)).join("\n");
	const text = `${before}${before ? "\n" : ""}${s}${after ? "\n" : ""}${after}`;
	const start = text.indexOf(key);
	// The candidate covering the key; a dotted key splits into candidates, and its longest part counts.
	const c = candidates(text)
		.filter((c) => c.start < start + key.length && c.end > start)
		.sort((a, b) => b.end - b.start - (a.end - a.start))[0];
	if (!c || c.end - c.start < Math.min(key.length - 4, 20)) continue;
	const f = features(new Doc(text), c, false);
	if (vetoed(f, { statistical: !statistical })) continue;
	out(1, f, "synthetic");
	positives++;
}
console.error(`positives ${positives}`);
