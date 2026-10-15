/**
 * Redacts secrets from text before it goes somewhere you don't trust, such as a model provider.
 *
 *   import { Redactor } from "redac---n";
 *   const r = new Redactor({ known: [process.env.STRIPE_KEY] });
 *   r.redact(toolOutput, { hint: { command: "cat .env" } }).text
 *
 * Known values (secrets the caller holds, in every encoding output turns them into: known.ts) are found first; then
 * the layers of LAYERS propose spans, and the decision stage (policy.ts) decides which stay:
 * - formats: vendor token formats (formats.ts);
 * - structure: private keys, URL passwords, Authorization headers, cookies, connection strings, CLI passwords (structure.ts);
 * - names: values under credential names, `password=…`, `"apiKey": "…"`, `--token …` (named.ts);
 * - context: where the text came from, a secret file or a command that prints one, and the secret files inside it, a
 *   pasted session's output, a heredoc or a diff that writes one (commands.ts, secretfile.ts);
 * - encoded: base64 blobs and hex dumps, hidden whole if what they decode to holds a secret (encoded.ts);
 * - random: tokens with no name or format, judged by randomness and context (unnamed.ts).
 * Text is normalized first (normalize.ts); repeats of what was found are hidden too (repeats.ts).
 */
import { isSecretFile, printsSecret, printsSecretFile, printsSecretFileNames } from "./commands.ts";
import { findEncoded, findHexDumps } from "./encoded.ts";
import { jsonLiteralSpans, jsonStringLiterals, mayHoldJsonText, pythonReprLiterals } from "./json.ts";
import { repeats } from "./repeats.ts";
import { RedactionStream } from "./stream.ts";
import {
	covered,
	isLearnable,
	loginPassword,
	toWordEnd,
	trimmedToValue,
	merge,
	overlaps,
	secretValue,
	wrapped,
} from "./spans.ts";
import { isGuess, isVouched, layerOf, needsJudging, PLACEHOLDER_RULE } from "./rules.ts";
import { lowerBound } from "./lines.ts";
import {
	findEmbeddedOutputs,
	findInSecretFile,
	findPrintedSecret,
	firstPrompt,
	secretFileSections,
} from "./secretfile.ts";
import { hmacSha256, randomKey } from "./hmac.ts";
import { needsNormalizing, normalize, withBlanks } from "./normalize.ts";
import { findFormats } from "./formats.ts";
import { KnownValues } from "./known.ts";
import { findNamed } from "./named.ts";
import { findStructure } from "./structure.ts";
import type { DetectOptions, Finding, Guessing, Hint, RedactOptions } from "./types.ts";
import { findUnnamed } from "./unnamed.ts";
import { redactValue, type TranscriptFinding, type TranscriptOptions } from "./transcript.ts";
import { keepReason } from "./policy.ts";
import { percentEncoded } from "./urls.ts";
import { FindingsCache } from "./cache.ts";

export { isSecretFile } from "./commands.ts";
export { fromEnvironment } from "./environment.ts";
export type { DetectOptions, Finding, Guessing, Hint, RedactOptions } from "./types.ts";
export type { TranscriptFinding, TranscriptOptions } from "./transcript.ts";

export interface RedactResult {
	/** The text with every secret replaced by a placeholder. */
	text: string;
	/**
	 * What was replaced; each `value` is the secret as the program reads it (decoded where the text escaped it, as
	 * `detect` gives it, else the text its span covered): strip it before logging.
	 */
	findings: (Finding & { value: string })[];
}

/**
 * Findings kept off the quotes of a JSON text's string literals, so the JSON around them stays valid: one that runs
 * from inside a literal out past its closing quote (a password read through the escaping, `Indigo2027$"}`) ends
 * with the literal, and one that runs into a literal from outside starts with it. One that spans whole literals (a
 * key written across `"…\n" +` lines) is the code's, and stays.
 */
function withinLiterals(text: string, found: Finding[]): Finding[] {
	const spans = jsonLiteralSpans(text);
	const starts = spans.map(([start]) => start);
	const literalAt = (p: number) => {
		const span = spans[lowerBound(starts, p + 1) - 1];
		return span && p < span[1] ? span : undefined;
	};
	return found.flatMap((f) => {
		const first = literalAt(f.start);
		const last = literalAt(f.end - 1);
		if (!first === !last) return [f];
		const [start, end] = first ? [f.start, first[1]] : [last![0], f.end];
		return end > start ? [{ ...f, start, end, value: text.slice(start, end) }] : [];
	});
}

/** A placeholder as placeholderFor writes one: `[REDACTED <kind> #<fingerprint>]`, its kind's characters and length (group 1). */
const PLACEHOLDER = /\[REDACTED ([\w .:/-]{1,60}) #[0-9a-f]{6}\]/g;

/** An entity that spells markup, which decoding turns into the markup itself. */
const MARKUP_ENTITY = /&(?:lt|gt|quot|apos|amp|#0*(?:60|62|34|39|38)|#x0*(?:3c|3e|22|27|26));/i;

/**
 * @internal The stages around the layers, each of which can be left out to measure it (eval/layers.ts): normalization (colours,
 * line prefixes, escapes, entities), the JSON-literal pass (decoded string literals scanned as text), hints (a command
 * or path saying what the text is), the decision stage (policy.ts), repeats of what was found, and in the random layer
 * its hard vetoes and its context (each token then scored on its own characters).
 */
export const STAGES = [
	"normalize",
	"json-literals",
	"percent-encoded",
	"hints",
	"policy",
	"repeats",
	"vetoes",
	"statistical-vetoes",
	"token-context",
] as const;
/** @internal */
export type Stage = (typeof STAGES)[number];

/** @internal Detection layers, in the order they run (see the module comment); each can be left out to measure the rest (eval/layers.ts). */
export const LAYERS = ["formats", "structure", "names", "context", "encoded", "random"] as const;
/** @internal */
export type Layer = (typeof LAYERS)[number];

export interface RedactorOptions extends RedactOptions {
	/**
	 * The HMAC key of placeholders' tags. Random per Redactor by default, so tags differ between Redactors and across
	 * restarts; pass a fixed key to keep them stable (a provider's prompt cache). Keep it secret: with it, a tag can be
	 * checked against guesses.
	 */
	fingerprintKey?: string | Uint8Array;
	/** @internal The layers to run, all by default; known values always run. For measuring each layer's share. */
	layers?: Iterable<Layer>;
	/** @internal The stages to leave out (STAGES), none by default. For measuring what each one buys (eval/layers.ts). */
	without?: Iterable<Stage>;
}

/**
 * The JSON number token around `[start, end)` when it stands as a value (after a key's `:`, or a `[` or `,` inside
 * brackets), with its sign, fraction and exponent; and the quote at the level of escaping around it (`"`, `\"` in
 * JSON inside a JSON string).
 */
function jsonNumberAround(
	text: string,
	start: number,
	end: number,
): { start: number; end: number; quote: string } | undefined {
	let s = start;
	while (s > 0 && start - s < 64 && /[-\d.]/.test(text[s - 1])) s--;
	if (s > 0 && /[-\d.]/.test(text[s - 1])) return undefined; // (a run longer than any number token: not one)
	const e = end + /^\d*(?:\.\d+)?(?:[eE][-+]?\d+)?/.exec(text.slice(end, end + 40))![0].length;
	if (
		!/^-?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?$/.test(text.slice(s, e)) ||
		!/^(?:[ \t\r\n]|\\[nrt])*(?:[,}\]]|$)/.test(text.slice(e, e + 20))
	)
		return undefined;
	const before = text.slice(Math.max(0, s - 400), s);
	const key = /(\\*)"[ \t]*:[ \t]*$/.exec(before);
	if (key) return { start: s, end: e, quote: `${key[1]}"` };
	// (In an array: the escaping of the quote nearest before it, if any.)
	if (!/[[,](?:[ \t\r\n]|\\[nrt])*$/.test(before) || !/[[{]/.test(before)) return undefined;
	return { start: s, end: e, quote: `${/(\\*)"[^"]*$/.exec(before)?.[1] ?? ""}"` };
}

/** One call's options inside the pipeline: what it was told, and how many encodings deep it reads (see the encoded layer). */
type Pass = DetectOptions & { encoded?: number };

export class Redactor {
	/** @internal The values this Redactor hides wherever they appear: given (`known`, `addKnown`) or learned. */
	readonly known = new KnownValues();
	private cache = new FindingsCache();
	private guessing: Guessing;
	private hashes: "keep" | "hide";
	private key: Uint8Array;
	private placeholder?: RedactOptions["placeholder"];
	private layers: ReadonlySet<Layer>;
	private without: ReadonlySet<Stage>;

	constructor(options: RedactorOptions = {}) {
		this.layers = new Set(options.layers ?? LAYERS);
		this.without = new Set(options.without ?? []);
		this.guessing = options.guessing ?? "confident";
		this.hashes = options.hashes ?? "keep";
		this.key =
			typeof options.fingerprintKey === "string"
				? new TextEncoder().encode(options.fingerprintKey)
				: (options.fingerprintKey ?? randomKey());
		this.placeholder = options.placeholder;
		for (const k of options.known ?? []) {
			if (typeof k === "string") this.known.add(k);
			else if (k) this.known.add(k.value, k.label);
		}
	}

	/**
	 * Adds a value that is secret wherever it appears, shown as `label` in its placeholders. False if it's too short or
	 * ordinary to hide everywhere (RedactOptions.known says which), true if it was added or was already held.
	 */
	addKnown(value: string, label?: string): boolean {
		return this.known.add(value, label);
	}

	/** A short keyed fingerprint, so the model can tell two placeholders hide the same value. */
	fingerprint(value: string): string {
		const mac = hmacSha256(this.key, new TextEncoder().encode(value));
		return Array.from(mac.subarray(0, 3), (b) => b.toString(16).padStart(2, "0")).join("");
	}

	/** Every secret in `text`, without changing it. (What was found in a text before, with the same hint and guessing, under the same known values, is returned again.) */
	detect(text: string, options: DetectOptions = {}): Finding[] {
		const context = JSON.stringify([
			options.guessing ?? this.guessing,
			options.hint?.command,
			options.hint?.path,
			options.hint?.secretFile,
		]);
		const version = this.known.version;
		// (Copies out: a caller that changes a finding changes neither the cache nor what the next call returns.)
		const cached = this.cache.get(version, text, context);
		if (cached) return cached.map((f) => ({ ...f }));
		const found = this.detectUncached(text, options);
		this.cache.set(version, text, context, found);
		return found.map((f) => ({ ...f }));
	}

	private detectUncached(text: string, options: Pass): Finding[] {
		// Colour codes, NULs (UTF-16 read as UTF-8), line continuations, HTML entities: detect on the text
		// without them and map positions back.
		// Placeholders of an earlier pass are findings of their own, replaced by themselves, and what overlaps them is
		// dropped: redacting redacted text changes nothing. (Read blank, so their kind words, `token`, `secret`, aren't
		// context for what's next to them.)
		const placeholders: Finding[] = [];
		const scan = text.includes("[REDACTED ") ? this.withoutPlaceholders(text, placeholders) : text;
		try {
			// (Findings run to their token's end can come to overlap: merged again.)
			const found = merge(
				this.detectNormalized(scan, options, 0)
					.map((f) => toWordEnd(scan, trimmedToValue(scan, f)))
					.filter((f) => f.end > f.start),
			);
			return placeholders.length
				? [...found.filter((f) => !overlaps(placeholders, f.start, f.end)), ...placeholders].sort(
						(a, b) => a.start - b.start,
					)
				: found;
		} catch {
			// A detector that fails on some input mustn't let that input through: it is hidden whole (closed, not open), as
			// one finding that is never learned as a secret.
			return text
				? [{ start: 0, end: text.length, kind: "unreadable text", rule: "safety:detector-failed", confidence: 0 }]
				: [];
		}
	}

	/**
	 * `text` with its placeholders read blank (so their kind words, `token`, `secret`, aren't context for what's next to
	 * them), and them added to `found`. Text of a placeholder's shape is one only if its kind holds nothing detection would
	 * hide: `[REDACTED sk_live_… #abcdef]` is a key in a placeholder's shape, and is scanned like any text.
	 */
	private withoutPlaceholders(text: string, found: Finding[]): string {
		const own = new Map<string, boolean>();
		return text.replace(PLACEHOLDER, (m: string, kind: string, at: number) => {
			let ok = own.get(kind);
			if (ok === undefined) own.set(kind, (ok = this.detect(kind).length === 0));
			if (!ok) return m;
			found.push({ start: at, end: at + m.length, kind: "placeholder", rule: "placeholder", confidence: 1 });
			return `[REDACTED${" ".repeat(m.length - 10)}]`;
		});
	}

	private detectNormalized(text: string, options: Pass, depth: number): Finding[] {
		if (needsNormalizing(text) && !this.without.has("normalize")) {
			const n = normalize(text);
			let found = this.detectText(n.text, options, depth);
			// A removed colour code or line continuation can glue a fixed-length key to the next character
			// (`ESC[32mAKIA…ESC[0mdefault`): formats also run with a blank where each separator was. A key found there
			// replaces a span that runs across the separator into the next word.
			if (n.boundaries.length) {
				const separated = withBlanks(n.text, n.boundaries);
				const keys = findFormats(separated.text)
					.map((f) => ({ ...f, start: separated.map[f.start], end: separated.map[f.end - 1] + 1 }))
					.filter((f) => this.judge(n.text, f));
				const across = (f: Finding) => n.boundaries.some((b) => b > f.start && b < f.end);
				found = found.filter(
					(f) => !(across(f) && layerOf(f.rule) !== "format" && keys.some((k) => k.start < f.end && k.end > f.start)),
				);
				found = merge([...found, ...keys.filter((k) => !covered(found, k.start, k.end))]);
			}
			// (Each keeps its value as read here, where a joined literal is whole: `"xoxb-12" "34ab"` is `xoxb-1234ab`.)
			const mapped = found.map((f) => ({
				...f,
				start: n.map[f.start],
				end: f.end > f.start ? n.ends[f.end - 1] : n.map[f.start],
				value: secretValue(n.text, f),
			}));
			// An escaped value in markup (`<password>Vq7m&lt;Zp2</password>`, `value="a&quot;b"`): decoded, its `<` or `"`
			// ends what the XML and attribute readers read, so the names are also read where it's written. (Escaped code in
			// markup, `<pre>DB_PASSWORD=&quot;…&quot;</pre>`, needs the decoding: both readings stand.)
			if (!this.layers.has("names") || !MARKUP_ENTITY.test(text)) return mapped;
			const escaped = findNamed(text).filter(
				(f) => MARKUP_ENTITY.test(text.slice(f.start, f.end)) && this.judge(text, f),
			);
			if (!escaped.length) return mapped;
			const read = merge(mapped);
			return merge([...mapped, ...escaped.filter((f) => !overlaps(read, f.start, f.end))]);
		}
		return this.detectText(text, options, depth);
	}

	private detectText(text: string, options: Pass, depth: number): Finding[] {
		const plain = text.includes('"')
			? withinLiterals(text, this.detectPlain(text, options))
			: this.detectPlain(text, options);
		// A Python repr's strings (`{'stdout': '…\n…'}`) and percent-encoded text (a URL in `redirect=`, JSON in a query):
		// each decoded, scanned, and mapped back.
		const repr = depth >= 3 ? plain : this.withLiterals(plain, [...pythonReprLiterals(text)], options, depth);
		const found =
			depth >= 3 || this.without.has("percent-encoded")
				? repr
				: this.withDecoded(repr, percentEncoded(text), options, depth);
		if (depth >= 3 || !mayHoldJsonText(text) || this.without.has("json-literals")) return found;
		// JSON-escaped text (a serialized request, a log of JSON, a tool result inside a transcript): every
		// string literal holding escapes is decoded, scanned as the text it encodes, and mapped back.
		return this.withLiterals(found, jsonStringLiterals(text), options, depth);
	}

	/**
	 * `found`, with what detection finds in each of a text's decoded string literals (in text order, apart), mapped
	 * back; inside a literal, the decoded pass decides.
	 */
	private withLiterals(
		found: Finding[],
		literals: { decoded: string; map: number[] }[],
		options: Pass,
		depth: number,
	): Finding[] {
		if (!literals.length) return found;
		// (Decoded, a literal may hold colour codes of its own: `\u001b[32m` in a JSON log of terminal output.)
		const extra = this.decodedFindings(literals, options, depth);
		// Inside a decoded literal the decoded pass decides: the raw pass reads the literal through its escapes (`\"`
		// before a value, `\n` for a line break) and can miss what makes a value public (a label on the line above, a
		// quote that closed a string, a name the escapes hide). A raw finding inside one stays only where the decoded
		// pass found something too. (Not secret-file or secret-command findings, nor known values: the hint that makes
		// them is the raw text's; nor another occurrence of a value found elsewhere in it, which no one literal holds.)
		// (Literals come in text order and don't overlap; the decoded findings, merged, neither.)
		// (Nor a finding that is a one-line literal's whole value, read under a name outside it, `"client_secret":"p\/ye…"`:
		// the decoded text has no name to judge it by.)
		const starts = literals.map((l) => l.map[0]);
		const insideLiteral = (f: Finding) => {
			const l = literals[lowerBound(starts, f.start + 1) - 1];
			return (
				!!l &&
				f.end <= l.map[l.map.length - 1] &&
				!(f.name !== undefined && f.start === l.map[0] && !l.decoded.includes("\n"))
			);
		};
		const decoded = merge(extra);
		// (Where both passes read a value from the same place, the decoded one says where it ends: read raw, Go's
		// `client_secret=…\u0026grant_type=…` runs on through the escaped `&`.)
		const decodedStarts = new Set(extra.map((f) => f.start));
		return merge([
			...found.filter(
				(f) =>
					isVouched(f.rule) ||
					layerOf(f.rule) === "repeat" ||
					!insideLiteral(f) ||
					(overlaps(decoded, f.start, f.end) && !decodedStarts.has(f.start)),
			),
			...extra,
		]);
	}

	/** `found`, with what detection finds in each decoded text, mapped back to the text it was decoded from. */
	private withDecoded(
		found: Finding[],
		decodings: Iterable<{ decoded: string; map: number[] }>,
		options: Pass,
		depth: number,
	): Finding[] {
		const extra = this.decodedFindings(decodings, options, depth);
		return extra.length ? merge([...found, ...extra]) : found;
	}

	/** What detection finds in each decoded text, mapped back to the text it was decoded from. */
	private decodedFindings(
		decodings: Iterable<{ decoded: string; map: number[] }>,
		options: Pass,
		depth: number,
	): Finding[] {
		const out: Finding[] = [];
		for (const { decoded, map } of decodings) {
			for (const f of this.detectNormalized(decoded, { ...options, hint: {} }, depth + 1))
				out.push({ ...f, start: map[f.start], end: map[f.end], value: secretValue(decoded, f) });
		}
		return out;
	}

	private detectPlain(text: string, options: Pass): Finding[] {
		const guessing = options.guessing ?? this.guessing;
		// (A command up to 64 KB, read in linear time, and a longer one's both ends: a script written by a heredoc then
		// `&& cat .env` is one command. A long path's end, its file's name.)
		const command = options.hint?.command;
		const hint = this.without.has("hints")
			? {}
			: {
					command:
						command && command.length > 65_536 ? `${command.slice(0, 32_768)}\n${command.slice(-32_768)}` : command,
					path: options.hint?.path?.slice(-4096),
					secretFile: options.hint?.secretFile,
				};
		// (Read whole, a file's text: a command's output only up to the next prompt in it.)
		const wholeFile = hint.secretFile === true || (hint.path !== undefined && isSecretFile(hint.path));
		// (A command that cuts a secret file to its names printed one whole where a `NAME=value` line is in its output.)
		const secretFile =
			wholeFile ||
			(hint.command !== undefined &&
				(printsSecretFile(hint.command) ||
					(printsSecretFileNames(hint.command) && /^[ \t]*(?:export[ \t]+)?[A-Za-z_][\w.]*=\S/m.test(text))));
		const on = this.layers;
		// The layers propose; policy.ts decides, once for all of them, what is public by design or never a secret.
		// Every proposal on a value is judged under the name any layer read for it (a format match on
		// `const NEXT_PUBLIC_MAPS_KEY: string = "AIza…"` under the name the name layer parsed), and without the
		// backslash that, in text encoded twice, is half of the next level's escape.
		const proposals = [
			...this.known.find(text),
			...(on.has("formats") ? findFormats(text) : []),
			...(on.has("structure") ? findStructure(text) : []),
			...(on.has("names") ? findNamed(text) : []),
		];
		const named = proposals.filter((p) => p.name).sort((a, b) => a.start - b.start);
		// (The nearest few named proposals starting before the span's end: spans that overlap rarely nest deeper.)
		const namedStarts = named.map((p) => p.start);
		const nameAt = (f: Finding) => {
			const after = lowerBound(namedStarts, f.end);
			for (let i = after - 1; i >= Math.max(0, after - 8); i--) if (named[i].end > f.start) return named[i].name;
			return undefined;
		};
		const decide = (fs: Finding[]) =>
			fs.filter((f) => {
				let end = f.end;
				while (end > f.start + 1 && text[end - 1] === "\\") end--;
				const name = f.name ?? nameAt(f);
				return this.judge(text, { ...f, end, ...(name ? { name } : {}) });
			});
		let found: Finding[] = decide(proposals);
		// Secret files' contents inside the text (a diff's hunks, a heredoc that writes one): hidden as in the file.
		const secretSections = on.has("context") ? secretFileSections(text) : [];
		if (on.has("context")) {
			// A command's output runs to the next prompt in the text; what follows is another command's.
			const own = hint.command ? text.slice(0, firstPrompt(text)) : text;
			if (hint.command && printsSecret(hint.command)) found.push(...findPrintedSecret(own));
			if (secretFile) found.push(...findInSecretFile(wholeFile ? text : own, { path: hint.path }));
			found.push(...findEmbeddedOutputs(text));
			for (const { start: from, end: to, part } of secretSections)
				for (const f of findInSecretFile(text.slice(from, to), { part }))
					found.push({ ...f, start: f.start + from, end: f.end + from });
			// (A secret file's values under no credential's name are judged like any proposal: see isOpaqueSetting.)
			found = [...found.filter((f) => !needsJudging(f.rule)), ...decide(found.filter((f) => needsJudging(f.rule)))];
		}
		if (on.has("encoded")) {
			// (Decoded text holds a secret when the pipeline finds one there, as it would in the clear: every layer but the
			// random one, whose guess at a random-looking decoding would make every blob a secret (guessing is off, so
			// neither a guess nor its repeats count); the decision stage; the text's own commands and files. Base64 of
			// base64 is read three deep.)
			const encoded = options.encoded ?? 0;
			const inner = (decoded: string) =>
				encoded >= 3
					? this.known.find(decoded).length > 0
					: this.detectNormalized(decoded, { guessing: "off", encoded: encoded + 1 }, 0).some((f) => !isGuess(f.rule));
			found.push(...findEncoded(text, inner), ...findHexDumps(text, inner));
		}
		found = merge(wrapped(text, found), text);
		if (on.has("random")) {
			// (Guessing as asked, but in a secret file, the hint's or one written inside the text, always: there the model
			// isn't guessing whether secrets are present, it tells the file's generated values from its settings.)
			const taken = (start: number, end: number) => overlaps(found, start, end);
			if (guessing !== "off" || secretFile)
				found = merge([...found, ...decide(findUnnamed(text, taken, guessing, secretFile, this.without))]);
			// (A secret file written inside the text, or its diff hunks, is read as that file is.)
			for (const { start: from, end: to } of secretSections) {
				const inner = findUnnamed(
					text.slice(from, to),
					(s, e) => taken(s + from, e + from),
					guessing,
					true,
					this.without,
				).map((f) => ({ ...f, start: f.start + from, end: f.end + from }));
				if (inner.length) found = merge([...found, ...decide(inner)]);
			}
		}
		if (this.without.has("repeats")) return merge(found, text);
		// (Another occurrence of a guess is judged where it stands: `PublicKey = <it>` says what it is.)
		const again = repeats(text, found);
		return merge(
			[...found, ...again.filter((f) => !needsJudging(f.rule)), ...decide(again.filter((f) => needsJudging(f.rule)))],
			text,
		);
	}

	/** The text that replaces a secret: `[REDACTED <kind> #<fingerprint>]` unless a placeholder function was given. */
	placeholderFor(f: Finding, value: string): string {
		if (this.placeholder) return this.placeholder(f, value);
		return `[REDACTED ${f.kind.replace(/[^\w .:/-]/g, "").slice(0, 60)} #${this.fingerprint(value)}]`;
	}

	/**
	 * @internal What replaces a finding in `text`, and the span it replaces: the placeholder; or, for a finding in a
	 * bare JSON number (`{"pin": 1234}`, `[9812773412, 5]`, `-98127.5`), the whole number token replaced by the
	 * placeholder in quotes, so the JSON stays valid.
	 */
	replacement(text: string, f: Finding, value: string): { start: number; end: number; text: string } {
		if (f.rule === PLACEHOLDER_RULE) return { start: f.start, end: f.end, text: text.slice(f.start, f.end) };
		const ph = this.placeholderFor(f, value);
		const number = jsonNumberAround(text, f.start, f.end);
		return number && !/["\\]/.test(ph)
			? { start: number.start, end: number.end, text: `${number.quote}${ph}${number.quote}` }
			: { start: f.start, end: f.end, text: ph };
	}

	/** `text` with every secret replaced by a placeholder. */
	redact(text: string, options: DetectOptions = {}): RedactResult {
		return this.apply(text, this.detect(text, options));
	}

	/** @internal Whether the decision stage keeps `f` hidden in `text`, with this redactor's options (`hashes`). */
	judge(text: string, f: Finding): boolean {
		return this.without.has("policy") || keepReason(text, f, this.hashes) === undefined;
	}

	/** @internal `text` with `findings` (merged: sorted, apart) replaced by placeholders. */
	apply(text: string, findings: Finding[]): RedactResult {
		if (!findings.length) return { text, findings: [] };
		let out = "";
		let at = 0;
		const result: RedactResult["findings"] = [];
		for (const f of findings) {
			const value = secretValue(text, f);
			const r = this.replacement(text, f, value);
			// (A replacement that spans more than its finding can span the next one too: two findings in one JSON number are
			// hidden by the one placeholder.)
			if (r.end > at) {
				out += text.slice(at, Math.max(at, r.start)) + r.text;
				at = Math.max(r.end, f.end);
			}
			if (f.rule !== PLACEHOLDER_RULE) result.push({ ...f, value });
		}
		return { text: out + text.slice(at), findings: result };
	}

	/**
	 * Learns the secrets in `text` as known values, so they're hidden wherever they turn up later, with
	 * or without context: read a `.env` once and its values are hidden in every later output. Returns how many it
	 * hadn't held. `minConfidence` (default 0.9) is the least confidence a finding needs to be learned.
	 */
	learn(text: string, options: DetectOptions & { minConfidence?: number } = {}): number {
		const before = this.known.size;
		for (const f of this.detect(text, options)) {
			const value = secretValue(text, f);
			if (!isLearnable(f, value, options.minConfidence)) continue;
			this.known.add(value, f.kind);
			const password = loginPassword(f, value);
			if (password) this.known.add(password, f.kind);
		}
		return this.known.size - before;
	}

	/**
	 * A copy of any JSON value (a message list, a request body) with every secret in every string and key
	 * replaced, as `JSON.stringify` would send it. Tool results are judged with their tool call's command or path,
	 * and a secret found anywhere is hidden everywhere in it. Options: `learn` (default true: remember what it finds
	 * for later calls too), `thinking` (default "redact").
	 */
	redactValue<T>(value: T, options: TranscriptOptions = {}): { value: T; findings: TranscriptFinding[] } {
		return redactValue(this, value, options);
	}

	/**
	 * A streaming redactor for text that arrives in chunks (a tool's output). Each `write` returns redacted text
	 * ready to pass on: text is released once it's far enough behind the newest chunk that no secret can still be
	 * forming across it, scanned in batches, so nothing comes out until about twice `holdback` characters have
	 * arrived (default 32,768, at least 8,192). `end()` flushes the rest.
	 */
	stream(options: DetectOptions & { holdback?: number } = {}): { write(chunk: string): string; end(): string } {
		return new RedactionStream(this, options);
	}
}

/** Redacts with a one-off Redactor. Prefer a long-lived Redactor so known values and fingerprints carry over. */
export function redact(text: string, options: RedactorOptions & { hint?: Hint } = {}): RedactResult {
	return new Redactor(options).redact(text, { hint: options.hint });
}
