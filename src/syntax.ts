/**
 * Pieces of the syntaxes values are written in, shared by the readers of the named layer and the unnamed layer's
 * context, so both read a value's name the same way: quoted strings, spans of matched groups, and name/value pairs
 * written as sibling attributes.
 */
import { lastText } from "./lines.ts";

/** Text and where it is. */
export interface Span {
	value: string;
	start: number;
	end: number;
}

/** A `d`-flag match's group `k` as a span. */
export function group(m: RegExpMatchArray, k: number): Span {
	const [start, end] = m.indices![k]!;
	return { value: m[k], start, end };
}

/**
 * How a string literal escapes its own quote: with a backslash (`"a\"b"`: JSON, C, JavaScript, Python, YAML's double
 * quotes), by doubling it (`'it''s'`: YAML's and SQL's single quotes, C#'s `@"…"`), or not at all (a shell's `'…'`,
 * Rust's `r#"…"#`).
 */
export type Escapes = "backslash" | "doubled" | "none";

/**
 * The longest value a reader reads where its syntax bounds it (a quote, a call's bracket): a guard against a quote
 * that never closes, not a length a secret is expected to stay under.
 */
export const MAX_VALUE = 65_536;

/**
 * How far a reader reads a value that only its characters bound (an unquoted word, `[^\s;]{1,4096}`, the rest of a
 * line): further, a reader that matches from many places on one long line would scan it once from each. A longer value
 * runs on from where its reader stopped to its word's end (spans.ts toWordEnd).
 */
export const UNQUOTED_READ = 4096;

/**
 * An unquoted value as a regex source for a rule that needs `end` (a lookahead: a blank, a quote, the line's end) right
 * after it: one capture group of `chars` (a character class), at least `min` of them, read as far as UNQUOTED_READ. A
 * longer value is cut there without the check, instead of failing the whole match (`end` follows a cut one only by
 * chance, and toWordEnd runs it on to its word's end).
 */
export function unquotedValue(chars: string, min: number, end: string): string {
	return `(${chars}{${min},${UNQUOTED_READ - 1}}?(?=${end})|${chars}{${UNQUOTED_READ}})`;
}

/**
 * The string literal scanner, for readers that walk text (calls.ts, yaml.ts, named.ts's values, attributes; `quoted`
 * is its form for rules that match a whole pattern): where the literal whose opening quote is at `at` closes (the index of
 * its closing quote), or -1 when it doesn't close within `max` characters, or on its line unless `multiline`. `from`
 * starts the scan inside the literal (a value in the middle of `"NAME=value"`).
 */
export function stringEnd(
	text: string,
	at: number,
	{
		escapes = "backslash",
		multiline = false,
		max = MAX_VALUE,
		from = at + 1,
	}: { escapes?: Escapes; multiline?: boolean; max?: number; from?: number } = {},
): number {
	const quote = text[at];
	const end = Math.min(text.length, from + max);
	for (let i = from; i < end; i++) {
		const c = text[i];
		if (c === "\\" && escapes === "backslash") i++;
		else if (c === quote) {
			if (escapes !== "doubled" || text[i + 1] !== quote) return i;
			i++;
		} else if (c === "\n" && !multiline) return -1;
	}
	return -1;
}

/** A quoted item of a flow list and the blanks after it, read from where the last one ended (`y`): its content is group 2. */
const FLOW_ITEM = /[ \t\r\n]*(["'])((?:(?!\1)[^\\\n]|\\.)*)\1[ \t\r\n]*/y;
/** The bracket that closes a flow list, and nothing after it but blanks. */
const FLOW_CLOSE = /[ \t\r\n]*\][ \t\r\n]*$/y;

/**
 * The items of a list of strings that `value` is, each without its quotes (where in `value`, and its text): a flow
 * list on one line or over several, `["a", "b"]`, `['a','b']` (JSON, Python, TOML, YAML), its commas optional as HCL
 * and Vault's listings write it (`["a" "b"]`); or a YAML block list, `- a` lines, plain or quoted. Undefined when it
 * is no such list or anything else is in it: a number, an object, a name (code), a mapping under a `-`.
 */
export function stringListItems(value: string): Span[] | undefined {
	const items: Span[] = [];
	const open = /^[ \t\r\n]*\[/.exec(value);
	if (open) {
		let at = open[0].length;
		for (;;) {
			FLOW_ITEM.lastIndex = at;
			const m = FLOW_ITEM.exec(value);
			if (!m) return undefined;
			const start = m.index + m[0].indexOf(m[1]) + 1;
			items.push({ value: m[2], start, end: start + m[2].length });
			at = m.index + m[0].length;
			if (value[at] === ",") at++;
			FLOW_CLOSE.lastIndex = at;
			if (FLOW_CLOSE.test(value)) return items;
		}
	}
	let at = 0;
	for (const line of value.split("\n")) {
		const m = /^([ \t]*-[ \t]+)(.*?)[ \t]*\r?$/.exec(line);
		if (/^[ \t]*(?:#.*)?\r?$/.test(line)) {
			at += line.length + 1;
			continue;
		}
		if (!m) return undefined;
		let item = m[2];
		let start = at + m[1].length;
		const quote = /^(["'])(.*)\1$/.exec(item);
		if (quote) {
			item = quote[2];
			start++;
		} else {
			item = item.replace(/[ \t]+#.*$/, "");
			// (A mapping, `- name: x`, or a collection, `- [a]`, is no string.)
			if (!item || /:(?:[ \t]|$)|^[[{&*!|>]/.test(item)) return undefined;
		}
		items.push({ value: item, start, end: start + item.length });
		at += line.length + 1;
	}
	return items.length ? items : undefined;
}

/** The opening bracket of each closing one. */
const OPENER: Record<string, string> = { ")": "(", "]": "[", "}": "{" };

/**
 * `value` without the closing brackets at its end that it didn't open (of `closers`, among `)`, `]`, `}`): the end of
 * a call, a link or an object around it (`{user: alice, password: foo}`, `[link](https://x.io/?a=b)`), not a value's
 * own (`Kx7(mQ2)`, `p)q(r)`). One pass, matching each closer to an opener of its kind before it: linear in the value.
 */
export function withoutUnopenedClosers(value: string, closers = ")]}"): string {
	const open: Record<string, number> = { "(": 0, "[": 0, "{": 0 };
	// (Where the run of unopened closers that ends the value so far starts.)
	let run = -1;
	for (let i = 0; i < value.length; i++) {
		const c = value[i];
		const opener = OPENER[c];
		if (opener === undefined) {
			if (c in open) open[c]++;
			run = -1;
		} else if (open[opener] > 0) {
			open[opener]--;
			run = -1;
		} else if (closers.includes(c)) run = run < 0 ? i : run;
		else run = -1;
	}
	return run < 0 ? value : value.slice(0, run);
}

/**
 * Where a value that a reader cut (`start`–`end`) inside a bracket it opened ends: at that bracket's close on the same
 * line, read over the strings and blanks within it (`0x#{key.unpack('H*')[0]}`, `Buffer.from(pw, "base64")`) and a
 * quote that closes nothing (Rust's lifetime, `Option<&'static str>`; a `<` opens a bracket after a name, a generic's).
 * Then the value is judged whole, as the code it is, not as the fragment before the cut; and a password with a
 * bracket, `Xy(z, 9)`, is hidden whole. `end` when the value opened no bracket it didn't close, or nothing closes it on
 * the line.
 */
export function throughBrackets(text: string, start: number, end: number): number {
	const close: Record<string, string> = { "(": ")", "[": "]", "{": "}", "<": ">" };
	const open: string[] = [];
	const lineEnd = text.indexOf("\n", end);
	const stop = Math.min(lineEnd < 0 ? text.length : lineEnd, start + UNQUOTED_READ);
	for (let i = start; i < stop; i++) {
		const c = text[i];
		if (i >= end && open.length === 0) return end;
		if (c in close && (c !== "<" || /\w/.test(text[i - 1] ?? ""))) open.push(close[c]);
		else if (c === open.at(-1) && !(c === ">" && /[-=]/.test(text[i - 1]))) {
			open.pop();
			if (open.length === 0 && i >= end) return i + 1;
		} else if (i >= end && /["'`]/.test(c)) {
			const q = stringEnd(text, i, { max: stop - i });
			if (q >= 0) i = q;
		}
	}
	return end;
}

/**
 * Whether the character at `i` would continue a token beside a value, so the value there is part of a longer one: a
 * letter or a digit of any script, an identifier's `_` and `$`, and a kebab-case name's `-` where the value has one
 * (`set_guest_wifi_password` inside `_async_set_guest_wifi_password` is no whole token). Not the last character of an
 * escape (`\n`, `\t`, `\u0027`, `\x27`): in an escaped string that is where a line or a quote is.
 */
export function continuesToken(text: string, i: number, dash = false): boolean {
	// (A letter outside the basic plane is two UTF-16 units: the pair, whichever half `i` is.)
	const pair = /[\uDC00-\uDFFF]/.test(text[i] ?? "") && /[\uD800-\uDBFF]/.test(text[i - 1] ?? "");
	const c = pair ? text.slice(i - 1, i + 1) : text.slice(i, i + 2);
	if (!(/^[\p{L}\p{N}_$]/u.test(c) || (dash && c[0] === "-"))) return false;
	const escape = /\\(?:[nrtbf]|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2})$/.exec(text.slice(Math.max(0, i - 5), i + 1));
	return !escape || backslashesBefore(text, i + 1 - escape[0].length) % 2 === 1;
}

/**
 * A string literal's prefix: Python's `b r u f` (two of them: `rb`), C#'s `@` and `$`, Rust's `r#`. The readers of
 * calls', assignments' and names' literals find where one opens with it and a quote.
 */
export const STRING_PREFIX = String.raw`r#+|[rRbBuUfF]{1,2}|@\$?|\$@?`;

/** A contraction's apostrophe (`Here's`, `don't`, `you'll`), which prose writes and no quote is: test its source, or replace it. */
export const CONTRACTION = /(?<=[A-Za-z])['’](?=(?:s|t|ll|re|ve|d|m)\b)/gi;

/**
 * Whether the `'` at `i` is a contraction's apostrophe (CONTRACTION) rather than a quote. (Not after a word that is a
 * string's prefix: `r'd+'`, `f'd={d}'`.)
 */
export function isContraction(text: string, i: number): boolean {
	const word = /[A-Za-z]+$/.exec(text.slice(Math.max(0, i - 20), i))?.[0];
	return !!word && !/^[rRbBuUfF]{1,2}$/.test(word) && /^(?:s|t|ll|re|ve|d|m)\b/i.test(text.slice(i + 1, i + 4));
}

/** How many backslashes run right before `at`: an odd count escapes the character at `at`. */
export function backslashesBefore(text: string, at: number): number {
	let n = 0;
	while (at - n - 1 >= 0 && text.charCodeAt(at - n - 1) === 92) n++;
	return n;
}

/** The length of the escape sequence whose backslash is at `at`: `\u0041` 6, `\x41` 4, any other (`\n`, `\"`) 2. */
export function escapeLength(text: string, at: number): number {
	return /^u[0-9a-fA-F]{4}/.test(text.slice(at + 1, at + 6))
		? 6
		: /^x[0-9a-fA-F]{2}/.test(text.slice(at + 1, at + 4))
			? 4
			: 2;
}

/**
 * Whether a `\n` escape starts at `at` (a backslash no other escapes, then `n`) and breaks a line of escaped text: not
 * where a real break follows it, as in a notebook's list of lines (`"…\n",`). (`C:\nginx` reads as one too: there is
 * no telling a path's `\n` from a break.)
 */
export function isEscapedBreak(text: string, at: number): boolean {
	return (
		text.charCodeAt(at) === 92 &&
		text.charCodeAt(at + 1) === 110 &&
		backslashesBefore(text, at) % 2 === 0 &&
		!/^[",\] \t]{0,8}\r?\n/.test(text.slice(at + 2, at + 13))
	);
}

/** Where the line `at` is on starts, counting an escaped break (isEscapedBreak) as one, looking back no further than `from`. */
export function escapedLineStart(text: string, at: number, from = 0): number {
	let floor = at;
	while (floor > from && text.charCodeAt(floor - 1) !== 10) floor--;
	for (let b = at - 2; b >= floor; b--) if (isEscapedBreak(text, b)) return b + 2;
	return floor;
}

/**
 * A quoted string on one line with backslash escapes (stringEnd's default), as a regex source for rules that match
 * a whole pattern: the opening quote (one of `quotes`) is capture group `n`, the content group `n + 1`, at least `min`
 * characters. (Its closing quote bounds the read: no cap on its length.)
 */
export function quoted(n: number, min = 1, quotes = `"'`): string {
	const ref = `\\${n}`;
	return `([${quotes}])((?:(?!${ref})[^\\\\\\n]|\\\\.){${min},})${ref}`;
}

/** The attribute that names a pair's value (`{"name": "API_KEY", "value": …}`, `- name: DB_PASSWORD`), and the one that holds it. */
export const PAIR_NAME =
	/^(?:name|key|keyName|id|label|ParameterKey|ParameterName|OptionName|OutputKey|variable|env|field)$/i;
export const PAIR_VALUE =
	/^(?:value|val|v|data|content|result|secret|secret_value|ParameterValue|OutputValue|SecretString)$/i;

/** An attribute (see `attributes`): its key, its operator, and its value with where it is. */
export interface Attribute {
	/** Where the attribute starts (its key, or the quote around its key) and ends (after its value and blanks). */
	start: number;
	end: number;
	key: string;
	operator: string;
	value: Span;
	quoted: boolean;
}

/** An attribute's key and operator: `name: `, `name = `, `"Name": `, `name=` in a tag. */
const ATTRIBUTE_HEAD = /(?<![\w-])(["']?)([A-Za-z]\w{0,80})\1[ \t]*([:=])[ \t]*/g;

/**
 * The attributes of a text, in any of the syntaxes pairs come in: `name: x`, `name = "x"`, `"Name": "x"`, `name="x"` in
 * a tag. A quoted value runs to its closing quote; a bare one to a `,` `;` `}` or line break, a tag's `>`, or blanks
 * before another word or a comment, and holds no `{`; either is followed by what can follow a value (followsValue).
 * Each value is read from where it starts to the first character that can end it (one table per text), so a long line
 * of keys is read once.
 */
export function* attributes(text: string): Generator<Attribute> {
	const stops = stopsOf(text);
	// (Each read after the one before it: a value's text, `arn:aws:…:secret:x`, holds no attributes.)
	const head = new RegExp(ATTRIBUTE_HEAD.source, "g");
	for (let m = head.exec(text); m; m = head.exec(text)) {
		const at = m.index + m[0].length;
		let value: Span;
		let end: number;
		const quote = text[at];
		if (quote === '"' || quote === "'") {
			const close = stringEnd(text, at);
			if (close < 0) continue;
			value = { value: text.slice(at + 1, close), start: at + 1, end: close };
			end = close + 1;
		} else {
			if (at >= text.length || /[\s,;}{"'<>]/.test(quote)) continue;
			const stop = bareEnd(text, at, stops);
			if (stop < 0) continue;
			value = { value: text.slice(at, stop), start: at, end: stop };
			end = stop;
		}
		const after = end;
		while (text[end] === " " || text[end] === "\t") end++;
		if (!followsValue(text, end, end > after)) continue;
		head.lastIndex = Math.max(head.lastIndex, end);
		yield { start: m.index, end, key: m[2], operator: m[3], value, quoted: quote === '"' || quote === "'" };
	}
}

/**
 * Whether what is at `i` can follow an attribute's value (with `blank`, after blanks): the text's end, a separator, a
 * tag's end, a comment (`"x"// prod`, `"x" # set by CI`), or, after a blank, another word (`name="a" value="b"`). Not an
 * operator: `"abc" + suffix` is no value.
 */
function followsValue(text: string, i: number, blank: boolean): boolean {
	const c = text[i];
	return (
		i >= text.length ||
		/[,;}\r\n>]/.test(c) ||
		(c === "/" && /[/*>]/.test(text[i + 1] ?? "")) ||
		(blank && /[\w"'#]/.test(c))
	);
}

/** For each position of a text, the next one (at or after it) that can end a bare attribute value: `, ; } { \r \n > /` or a blank. */
const stopsOf = lastText((text) => {
	const next = new Int32Array(text.length + 1);
	next[text.length] = text.length;
	for (let i = text.length - 1; i >= 0; i--) next[i] = /[,;}{\r\n>/ \t]/.test(text[i]) ? i : next[i + 1];
	return next;
});

/**
 * Where a bare attribute value that starts at `at` ends (see `attributes`), within 4,097 characters; -1 if it doesn't.
 * (At a `{` too, which can't follow a value: the attribute is none.)
 */
function bareEnd(text: string, at: number, stops: Int32Array): number {
	for (let p = stops[at + 1] ?? text.length; p - at <= 4097; p = stops[p + 1]) {
		const c = text[p];
		// (A path's `/` is the value's.)
		if (c === "/" && text[p + 1] !== ">") continue;
		// (The text's end, where `c` is undefined, too.)
		if (c !== " " && c !== "\t") return p;
		// Blanks end the value before what can follow one; before a symbol (`Kx9 - 2mQ`'s `-`) they don't.
		let q = p;
		while (text[q] === " " || text[q] === "\t") q++;
		if (followsValue(text, q, true)) return p;
		p = q - 1;
	}
	return -1;
}

/**
 * The name a sibling attribute gives a value: in the text before it on its line, the last name attribute with a quoted
 * value and no brace after it (`{"name": "api_key", "value": "`), or, with `alone`, a line that is a name attribute and
 * nothing else but a comment (`- name: API_KEY  # from vault` above `  value: …`). Not a word in a sentence: `Missing environment variable: X`.
 */
export function siblingName(text: string, { alone = false } = {}): string | undefined {
	if (!/(?:name|key|id|label|variable|env|field)["']?[ \t]*[:=]/i.test(text)) return undefined;
	let name: string | undefined;
	let after = 0;
	for (const a of attributes(text)) {
		const value = a.quoted || alone ? a.value.value : "";
		if (!PAIR_NAME.test(a.key) || !/^[\w.-]{1,80}$/.test(value)) continue;
		if (alone && !(/^[ \t-]*$/.test(text.slice(0, a.start)) && /^[ \t,]*(?:#.*)?\r?$/.test(text.slice(a.end))))
			continue;
		name = value;
		after = a.end;
	}
	return name !== undefined && !/[{}]/.test(text.slice(after)) ? name : undefined;
}

/** A table cell's text (trimmed, without the backticks of inline code) and where it is. */
export interface Cell {
	text: string;
	start: number;
	end: number;
}

/**
 * The rule under a `|` table's header or around a MySQL client's table: `|---|:--:|`, `+------+------+`, `===|===`; and
 * the start of one, to look ahead for it. (Each run of blanks belongs to one quantifier, after a separator or after
 * dashes, so a long run of blanks is read once.)
 */
export const PIPE_RULE = /^[ \t]*(?:[|+][ \t]*)?(?::?[-=]+:?[ \t]*[|+][ \t]*)+(?::?[-=]+:?[ \t]*)?\r?$/;
export const PIPE_RULE_START = /^[ \t]*(?:[|+][ \t]*)?(?::?[-=]+:?[ \t]*[|+][ \t]*)+/;

/**
 * A table row's cells between `|` bars, read as GitHub's tables are: `\|` is a pipe inside a cell, and a code span
 * (`` `a|b` ``) isn't split. Each cell's text (trimmed, a code span's backticks off) and where it is (`offset` added).
 */
export function pipeCells(line: string, offset = 0): Cell[] {
	const body = line.replace(/\r$/, "");
	const bounds: number[] = [];
	// (The lengths of the backtick runs with no closing run after them: a long line of backticks is read once.)
	const unclosed = new Set<number>();
	for (let i = 0; i < body.length; i++) {
		const c = body[i];
		if (c === "\\") i++;
		else if (c === "`") {
			// A code span runs to the next run of as many backticks; a run that finds none is text.
			let run = 1;
			while (body[i + run] === "`") run++;
			const close = unclosed.has(run) ? -1 : body.indexOf("`".repeat(run), i + run);
			if (close < 0) unclosed.add(run);
			i = (close < 0 ? i : close) + run - 1;
		} else if (c === "|") bounds.push(i);
	}
	// The cells between the bars; a row may leave out its outer bars.
	const lead = /^[ \t]*$/.test(body.slice(0, bounds[0] ?? 0)) && bounds.length ? bounds.shift()! : -1;
	const trail =
		bounds.length && /^[ \t]*$/.test(body.slice(bounds[bounds.length - 1] + 1)) ? bounds.pop()! : body.length;
	const cells: Cell[] = [];
	for (const [from, to] of [lead, ...bounds].map((b, k, all) => [b + 1, all[k + 1] ?? trail] as const)) {
		const raw = body.slice(from, to);
		let text = raw.trim();
		let start = offset + from + raw.indexOf(text);
		// (A cell is judged as what it holds: a code span's or emphasis' content, `` `x` ``, `**x**`, `_x_`; not of two
		// emphasised words, `**Name** and **Value**`.)
		const wrapped = /^(`+|\*{1,3}|_{1,3})([^`*_](?:(?:(?!\1).)*[^`*_])?)\1$/.exec(text);
		if (wrapped) {
			start += wrapped[1].length;
			text = wrapped[2];
		}
		cells.push({ text, start, end: start + text.length });
	}
	return cells;
}

/**
 * A delimited line's cells (CSV, TSV, `mysql --batch`), as RFC 4180 reads them on one line: a cell in double quotes
 * may hold the delimiter and `""` for a quote (not a line break: a quote still open at the line's end ends there). Each
 * cell's text (unquoted) and where that text starts and ends in the line.
 */
export function delimitedCells(line: string, delim: string, offset = 0): Cell[] {
	const cells: Cell[] = [];
	let i = 0;
	for (;;) {
		if (line[i] === '"') {
			let j = i + 1;
			let text = "";
			for (; j < line.length; j++) {
				if (line[j] !== '"') text += line[j];
				else if (line[j + 1] === '"') text += line[j++];
				else break;
			}
			cells.push({ text, start: offset + i + 1, end: offset + j });
			i = line.indexOf(delim, j);
		} else {
			const next = line.indexOf(delim, i);
			const end = next < 0 ? line.length : next;
			cells.push({ text: line.slice(i, end), start: offset + i, end: offset + end });
			i = next;
		}
		if (i < 0) return cells;
		i += delim.length;
	}
}
