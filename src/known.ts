/**
 * Values that are secret wherever they appear, because the caller says so: the credentials in its
 * environment and config, or values found earlier in the same transcript. Each is also matched in the
 * forms output turns it into: JSON- and URL-escaped, shell- and batch-quoted, hex, and base64 (also inside a
 * longer base64 blob, as in a Basic auth header). A token value of 24 or more characters cut short
 * (`head -c`, a truncated log) is caught by its first or last 16 characters.
 *
 * Values of 16+ characters are found by a rolling hash over 16-character windows, shorter ones by
 * Aho-Corasick: both linear in the text whatever the number of values.
 */
import { naturalness } from "./charlm.ts";
import { KeywordSet } from "./aho.ts";
import { continuesToken } from "./syntax.ts";
import type { Finding } from "./types.ts";

const W = 16;

function base64(bytes: Uint8Array, url = false): string {
	let bin = "";
	for (const b of bytes) bin += String.fromCharCode(b);
	const s = btoa(bin);
	return url ? s.replace(/\+/g, "-").replace(/\//g, "_") : s;
}

/**
 * The value's base64 as it appears inside a longer blob: the value can start at any byte offset mod 3,
 * so each of the three alignments is encoded, and the characters at the edges, which depend on the
 * neighbouring bytes, are dropped.
 */
function base64Shifts(value: string): string[] {
	const bytes = new TextEncoder().encode(value);
	const out: string[] = [];
	for (let shift = 0; shift < 3; shift++) {
		const padded = new Uint8Array(shift + bytes.length);
		padded.set(bytes, shift);
		for (const url of [false, true]) {
			let s = base64(padded, url).replace(/=+$/, "");
			// Leading characters mixing pad bytes and value bits.
			s = s.slice(shift === 0 ? 0 : shift === 1 ? 2 : 3);
			// Trailing characters that depend on what follows the value.
			const tail = (shift + bytes.length) % 3;
			if (tail) s = s.slice(0, -1);
			if (s.length >= 8) out.push(s);
		}
	}
	return out;
}

/** The forms a known value takes in output, besides itself. */
function variants(value: string): string[] {
	const out = new Set([value]);
	const json = JSON.stringify(value).slice(1, -1);
	out.add(json);
	out.add(json.replace(/\//g, "\\/"));
	out.add(json.replace(/[&<>']/g, (c) => `\\u00${c.charCodeAt(0).toString(16).padStart(2, "0")}`));
	out.add(JSON.stringify(json).slice(1, -1)); // twice-escaped: JSON inside a JSON string
	// Every character past ASCII as a code, as Python's json.dumps and PHP's json_encode (with `\/`) write it, and .NET's
	// in capitals.
	const ascii = json.replace(/[^\x00-\x7f]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
	out.add(ascii);
	out.add(ascii.replace(/\//g, "\\/"));
	out.add(ascii.replace(/\\u[0-9a-f]{4}/g, (m) => `\\u${m.slice(2).toUpperCase()}`));
	let uri = value;
	try {
		uri = encodeURIComponent(value);
	} catch {} // lone surrogates
	out.add(uri);
	// RFC 3986's unreserved characters only (Go's QueryEscape, Python's quote_plus with `+`, quote, which also leaves `/`),
	// and a form body's (URLSearchParams, Java's URLEncoder: `*` left, `~` escaped, a space as `+`).
	const strict = uri.replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
	out.add(strict);
	out.add(strict.replace(/%20/g, "+"));
	out.add(strict.replace(/%2F/g, "/"));
	out.add(strict.replace(/%2A/g, "*").replace(/~/g, "%7E").replace(/%20/g, "+"));
	out.add(uri.toLowerCase() === uri ? uri : uri.replace(/%[0-9A-F]{2}/g, (m) => m.toLowerCase()));
	out.add(value.replace(/([^\w\-.,:/@+=%])/g, "\\$1")); // printf %q
	out.add(value.replace(/(["\\$`])/g, "\\$1")); // inside double quotes
	out.add(value.replace(/'/g, "'\\''")); // inside single quotes
	out.add(value.replace(/'/g, `'"'"'`)); // inside single quotes, the other way
	out.add(value.replace(/[\^&|<>()%!]/g, "^$&")); // Windows batch
	out.add(value.replace(/'/g, "''")); // SQL, YAML single quotes
	out.add(value.replace(/\$/g, "$$$$")); // docker compose
	out.add(value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;")); // HTML, XML
	const bytes = new TextEncoder().encode(value);
	let hex = "";
	for (const b of bytes) hex += b.toString(16).padStart(2, "0");
	out.add(hex);
	out.add(hex.toUpperCase());
	if (/^[0-9a-f]+$/i.test(value)) {
		out.add(value.toLowerCase());
		out.add(value.toUpperCase());
	}
	// Standalone `base64(value)`, padded, in both alphabets.
	out.add(base64(bytes));
	out.add(base64(bytes, true));
	// A multi-line value (a key, a certificate bundle) also leaks line by line.
	// (Only lines that read as random: a PEM body's, not a JSON or .env document's boilerplate.)
	if (value.includes("\n")) {
		for (const line of value.split(/\r?\n/)) {
			const t = line.trim();
			if (t.length >= W && !/\s/.test(t) && (/^[A-Za-z0-9+/=_-]+$/.test(t) || naturalness(t) < 0.5)) out.add(t);
		}
	}
	return [...out].filter((v) => v.length >= 6);
}

function hash(s: string, start: number): number {
	let h = 0;
	for (let i = start; i < start + W; i++) h = (Math.imul(h, 31) + s.charCodeAt(i)) | 0;
	return h;
}

/** The polynomial hash, base 31, of `s[start, end)`: the whole-value hash of LiteralIndex. */
function fullHash(s: string, start = 0, end = s.length): number {
	let h = 0;
	for (let i = start; i < end; i++) h = (Math.imul(h, 31) + s.charCodeAt(i)) | 0;
	return h;
}

/**
 * Finds every occurrence of any of many literal strings (16+ characters), in linear time: a rolling hash of a
 * position's first 16 characters picks the values starting with them, kept by length; each length is checked by the
 * candidate's whole hash (from the text's prefix hashes, built on the first hit) before the string itself, so values
 * that share their start (JWTs' header, a vendor's prefix and more) cost a constant per length, not a copy.
 */
class LiteralIndex {
	private buckets = new Map<number, { lengths: number[]; values: Map<number, Map<number, string[]>> }>();
	get size() {
		return this.buckets.size;
	}

	add(value: string) {
		const h = hash(value, 0);
		let bucket = this.buckets.get(h);
		if (!bucket) this.buckets.set(h, (bucket = { lengths: [], values: new Map() }));
		let same = bucket.values.get(value.length);
		if (!same) {
			bucket.values.set(value.length, (same = new Map()));
			bucket.lengths.push(value.length);
			bucket.lengths.sort((a, b) => b - a);
		}
		const full = fullHash(value);
		const list = same.get(full);
		if (!list) same.set(full, [value]);
		else if (!list.includes(value)) list.push(value);
	}

	find(text: string): [number, string][] {
		const found: [number, string][] = [];
		if (text.length < W || !this.buckets.size) return found;
		let pow = 1;
		for (let i = 0; i < W - 1; i++) pow = Math.imul(pow, 31);
		// (The text's prefix hashes and powers of 31, for any substring's hash in O(1).)
		let prefix: Int32Array | undefined;
		let powers: Int32Array | undefined;
		const substringHash = (from: number, to: number) => {
			if (!prefix || !powers) {
				prefix = new Int32Array(text.length + 1);
				powers = new Int32Array(text.length + 1);
				powers[0] = 1;
				for (let k = 0; k < text.length; k++) {
					prefix[k + 1] = (Math.imul(prefix[k], 31) + text.charCodeAt(k)) | 0;
					powers[k + 1] = Math.imul(powers[k], 31);
				}
			}
			return (prefix[to] - Math.imul(prefix[from], powers[to - from])) | 0;
		};
		let h = hash(text, 0);
		for (let i = 0; i + W <= text.length;) {
			const bucket = this.buckets.get(h);
			if (bucket) {
				const length = bucket.lengths.find(
					(n) =>
						i + n <= text.length &&
						bucket.values
							.get(n)!
							.get(substringHash(i, i + n))
							?.includes(text.slice(i, i + n)),
				);
				// Keep rolling after a hit: another value may start inside this one and run past it.
				if (length !== undefined) found.push([i, text.slice(i, i + length)]);
			}
			if (i + W >= text.length) break;
			h = (Math.imul(h - Math.imul(text.charCodeAt(i), pow), 31) + text.charCodeAt(i + W)) | 0;
			i++;
		}
		return found;
	}
}

const TOKEN_CHAR = /[A-Za-z0-9+/_-]/;

/** A short form of a value (under 16 characters), matched as a whole word or anywhere. */
interface ShortForm {
	form: string;
	word: boolean;
}

interface ShortIndex {
	set: KeywordSet;
	forms: ShortForm[];
}

export class KnownValues {
	private long = new LiteralIndex();
	private ends = new LiteralIndex();
	private short = new Map<string, string>();
	/** Short base64 pieces of values, found anywhere: inside a blob they have base64 on both sides. */
	private shortB64 = new Map<string, string>();
	/** Every short form in the order added; `word` if it's matched as a whole word (`short`), else anywhere (`shortB64`). */
	private shortForms: ShortForm[] = [];
	/** The short forms indexed, in indexes of decreasing size (see rebuild), and how many they hold. */
	private levels: ShortIndex[] = [];
	private indexed = 0;
	private labels = new Map<string, string>();
	/** The value each form was made from: a form found is the value written another way, and tagged as the value. */
	private origins = new Map<string, string>();
	/** The values added, as given (trimmed). */
	private values = new Set<string>();
	/** Changes whenever a value not held before is added: what was worked out under an earlier set is told from what holds now. */
	version = 0;

	/** How many values it holds. */
	get size(): number {
		return this.values.size;
	}

	/** Adds a secret value. Values too short or too ordinary to replace everywhere are ignored. (One already held keeps its first label.) */
	add(value: string, label = "known secret"): boolean {
		value = value.trim();
		if (!isReplaceable(value)) return false;
		if (this.values.has(value)) return true;
		this.values.add(value);
		this.version++;
		// The first label given for a form is kept, for full and short forms alike.
		const form = (v: string) => {
			if (!this.labels.has(v)) this.labels.set(v, label);
			if (!this.origins.has(v)) this.origins.set(v, value);
		};
		for (const v of variants(value)) {
			form(v);
			if (v.length >= W) this.long.add(v);
			else if (!this.short.has(v)) {
				this.short.set(v, label);
				this.shortForms.push({ form: v, word: true });
			}
		}
		for (const v of base64Shifts(value)) {
			form(v);
			if (v.length >= W) this.long.add(v);
			// (Also when the same string is a whole-word short form: inside a longer blob it isn't a word.)
			else if (!this.shortB64.has(v)) {
				this.shortB64.set(v, label);
				this.shortForms.push({ form: v, word: false });
			}
		}
		// Only values long enough that a 16-character end is still unmistakably theirs, and ends that would be found in
		// ordinary text no more than the value would: a key's zero bytes, `AAAAAAAAAAAAAAAA`, are in every other blob.
		if (value.length >= 24 && /^[A-Za-z0-9+/=_-]+$/.test(value)) {
			for (const end of [value.slice(0, W), value.slice(-W)].filter(isReplaceable)) {
				this.ends.add(end);
				form(end);
			}
		}
		return true;
	}

	/**
	 * Indexes the short forms added since the last find. They go in an index of their own, merged with the indexes
	 * no bigger than it, so each holds at least twice what the next one holds: a session that learns a value and then
	 * finds, over and over, indexes each form a logarithmic number of times, not every form at every few values, and
	 * a find reads a logarithmic number of indexes.
	 */
	private rebuild() {
		if (this.indexed === this.shortForms.length) return;
		let forms = this.shortForms.slice(this.indexed);
		while (this.levels.length && this.levels[this.levels.length - 1].forms.length <= forms.length)
			forms = [...this.levels.pop()!.forms, ...forms];
		this.levels.push({
			set: new KeywordSet(
				forms.map((f) => f.form),
				true,
			),
			forms,
		});
		this.indexed = this.shortForms.length;
	}

	find(text: string): Finding[] {
		this.rebuild();
		const out: Finding[] = [];
		for (const [start, v] of this.long.find(text))
			out.push({
				start,
				end: start + v.length,
				kind: this.labels.get(v) ?? "known secret",
				rule: "known",
				confidence: 1,
				value: this.origins.get(v),
			});
		// Short values whole only (or straight after a flag like `-p`); short base64 pieces anywhere.
		for (const index of this.levels) {
			for (const [at, k] of index.set.matches(text)) {
				const { form: v, word } = index.forms[k];
				const dash = v.includes("-");
				if (
					word &&
					(continuesToken(text, at + v.length, dash) ||
						(continuesToken(text, at - 1, dash) && !/(?:^|[\s'"])-[A-Za-z]$/.test(text.slice(Math.max(0, at - 3), at))))
				)
					continue;
				out.push({
					start: at,
					end: at + v.length,
					kind: (word ? this.short.get(v) : this.shortB64.get(v)) ?? "known secret",
					rule: "known",
					confidence: 1,
					value: this.origins.get(v),
				});
			}
		}
		// What's left of a value that the output cut short: the whole run of token characters around an end.
		// Hits come in text order; a hit inside a full match, or inside the run just expanded, adds nothing.
		const full = out.slice().sort((a, b) => a.start - b.start);
		let fi = 0;
		let fullEnd = -1;
		let lastEnd = -1;
		for (const [at, v] of this.ends.find(text)) {
			while (fi < full.length && full[fi].start <= at) fullEnd = Math.max(fullEnd, full[fi++].end);
			if (fullEnd >= at + W || at < lastEnd) continue;
			// (Over the characters the value has: a token with no `/` cut short after a path, `…/repos/o/r/ghp_Zq8v…`,
			// takes none of the path with it.)
			const value = this.origins.get(v) ?? "";
			const inValue = (c: string) => TOKEN_CHAR.test(c) && (/[A-Za-z0-9]/.test(c) || value.includes(c));
			let start = at;
			let end = at + W;
			while (start > 0 && inValue(text[start - 1])) start--;
			while (end < text.length && inValue(text[end])) end++;
			lastEnd = end;
			out.push({
				start,
				end,
				kind: `part of ${this.labels.get(v) ?? "known secret"}`,
				rule: "known:partial",
				confidence: 0.95,
			});
		}
		return out;
	}
}

/**
 * Plain words and very short values would match ordinary text everywhere; so would a value with no letter or digit
 * (a rule, `+-----+`; an underline, Python's `~~~~^^^^` under the code a traceback points at) or of one character over
 * and over (`0000000000`, base64's `AAAAAAAAAAAAAAAA`).
 */
export function isReplaceable(value: string): boolean {
	if (value.length < 6 || value.length > 16_384) return false;
	if (!/[\p{L}\p{N}]/u.test(value) || /^(.)\1*$/su.test(value)) return false;
	if (/^\p{L}+$/u.test(value)) return value.length >= 14;
	return !/^\d{1,8}$/.test(value);
}
