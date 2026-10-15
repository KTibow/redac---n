/**
 * Output rewritten in ways that hide what it says from the detectors, undone before detection, in three passes:
 *
 * 1. What a terminal doesn't show: ANSI escape sequences (raw, or written as escapes in a JSON log), NULs (UTF-16
 *    read as UTF-8), BELs, invisible format characters.
 * 2. What a tool puts in front of lines: a file viewer's line numbers (`     12→`, `cat -n`), `grep -n`'s
 *    `path:12:`, a diff hunk's markers.
 * 3. What spells a character or a string another way: shell line continuations (`--password \` then the value on
 *    the next line), HTML entities (`&quot;`, `&#35;`), full-width punctuation, typographic quotes and spaces of other widths, and a
 *    string literal split in pieces (`"xoxb-12ab" "34cd"`, `'sk-' + '…'`), joined.
 *
 * Each pass sees the lines the one before it leaves (a coloured diff's `ESC[32m+API_TOKEN=…` starts with its `+`;
 * a literal split over numbered lines joins once the numbers are gone). Detection runs on the normalized text;
 * `map` and `ends` turn its positions back into the original's, and `boundaries` says where something that
 * separated two characters was removed.
 */
import { lookup } from "./lookup.ts";
import { lineEnd, lineStart, lowerBound } from "./lines.ts";
import { FILE_EXTENSION } from "./names.ts";

export interface Normalized {
	text: string;
	/** For each position of `text` (and one past its end), the position in the original. */
	map: number[];
	/** For each position of `text`, where its source in the original ends. */
	ends: number[];
	/**
	 * Positions of `text` where a separator was removed before them: a colour code (`AKIA…ESC[0mdefault`) or a line
	 * continuation. Two tokens meet there that the original kept apart. (Not where invisible characters were
	 * dropped from inside a token: `s​k​_…` is one token.)
	 */
	boundaries: number[];
}

/** The named entities that decode (the ASCII punctuation HTML names, and `&nbsp;`), by lower-case name. */
const ENTITIES = lookup<string>({
	quot: '"',
	amp: "&",
	lt: "<",
	gt: ">",
	apos: "'",
	nbsp: " ",
	sol: "/",
	colon: ":",
	equals: "=",
	num: "#",
	excl: "!",
	percnt: "%",
	plus: "+",
	commat: "@",
	dollar: "$",
	lowbar: "_",
	period: ".",
	comma: ",",
	semi: ";",
	quest: "?",
	lpar: "(",
	rpar: ")",
	lsqb: "[",
	lbrack: "[",
	rsqb: "]",
	rbrack: "]",
	lcub: "{",
	lbrace: "{",
	rcub: "}",
	rbrace: "}",
	bsol: "\\",
	verbar: "|",
	vert: "|",
	ast: "*",
	midast: "*",
	grave: "`",
	hat: "^",
});
/** An entity that decodes: a number, or a name of ENTITIES. */
const ENTITY = new RegExp(String.raw`&(?:#\d{1,6}|#x[0-9a-f]{1,5}|${Object.keys(ENTITIES).join("|")});`, "i");
/** An entity's shape, its number (decimal or hex) or its name in a group: entityChar decodes it. */
const ENTITY_SHAPE = String.raw`&(?:#(\d{1,6})|#[xX]([0-9a-fA-F]{1,5})|([a-zA-Z]{2,8}));`;
const ENTITY_AT = new RegExp(`^${ENTITY_SHAPE}`);

/** The character an entity (ENTITY_SHAPE's match) stands for: one UTF-16 unit, and a character, not NUL nor half of a surrogate pair. */
function entityChar(m: RegExpExecArray | string[]): string | undefined {
	const ch = m[1]
		? String.fromCodePoint(Number(m[1]))
		: m[2]
			? String.fromCodePoint(parseInt(m[2], 16))
			: ENTITIES[m[3].toLowerCase()];
	return ch !== undefined && /^[^\0\ud800-\udfff]$/.test(ch) ? ch : undefined;
}

/** A text with its HTML entities decoded as normalize decodes them: `&lt;redacted&gt;` is `<redacted>`. */
export function decodeEntities(text: string): string {
	return text.replace(new RegExp(ENTITY_SHAPE, "g"), (...m: string[]) => entityChar(m) ?? m[0]);
}

/** An ANSI colour code written as an escape in a JSON log or a string literal: `\u001b[32m`, `\x1b[0m`, `\033[1;31m`, `\e[0m`. */
const ESCAPED_CSI = /\\{1,3}(?:u001[bB]|x1[bB]|033|e)\[[0-9;:]{0,20}[A-HJKSTfmsu]/;
const ESCAPED_CSI_AT = new RegExp(ESCAPED_CSI.source, "y");
/**
 * A terminal's capture in caret notation, as `cat -v` and `less` print ESC: a colour or cursor code (`^[[32m`,
 * `^[[0;1m`, `^[[K`), a charset's (`^[(B`) or an OSC's introducer (`^[]0;`). Only where one stands is `^[` an ESC: elsewhere
 * it is a regex's `^[` (`^[\w-]+$`, `^[a-z]`), which no rewrite may touch. (Nor is any other two-byte sequence, `^[7`, read.)
 */
const CARET_ESCAPE = /\^\[(?:\[[0-9;]{0,20}[A-HJKSTfmsu]|\([B0]|\]\d{1,3};)/;
const CARET_ESCAPE_AT = new RegExp(CARET_ESCAPE.source, "y");

/** Lines carrying a tool's prefix: `grep -n`'s `path:12:` and `path-13-`, a diff hunk's markers. */
const PREFIXED = /(?:^|\n)[\w./@+-]{1,200}\.\w{1,10}[:-]\d{1,7}[:-]|(?:^|\n)@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@/;

/**
 * A line number a file viewer prints in front of each line: an agent's Read tool (`     12→`), `cat -n` (`     12\t`).
 * Either is the viewer's on a file of one line too (`     1→Harbor#2291x`).
 */
const LINE_NUMBER = /^(?:[ \t]*\d{1,7}→| +\d{1,7}\t)/gm;
const HAS_LINE_NUMBER = new RegExp(LINE_NUMBER.source, "m");

/**
 * A `.pgpass` line, `host:port:database:user:password` (`*` is a wildcard in the first four). Not a line of bytes in
 * hex pairs, as `openssl x509 -text` prints a certificate's modulus (`f2:36:d0:9e:e7:…`).
 */
export const PGPASS =
	/^(?![ \t]*(?:[0-9A-Fa-f]{2}:){5})[ \t]*[^:\s#][^:\s]*:(?:\d{1,5}|\*):[^:\s]+:[^:\s]+:([^\r\n]+?)\r?$/m;

/** `grep -n` and `rg -n`: `path:12:` before a match, `path-13-` before a context line. */
const GREP_PREFIX = /^([\w./@+-]{1,200}\.[\w]{1,10})[:-](\d{1,7})[:-]/gm;

/**
 * Where one string literal ends and the next begins, when code builds one string from pieces: C and
 * Python juxtapose them (`"ab" "cd"`), most languages add them (`"ab" + "cd"`, PHP `.`, SQL `||`, VB `&`),
 * also across a line break when an operator joins them. The pieces must be token-like (no blanks), so prose in quotes
 * stays apart, and single-quoted pieces need an operator (a CSP source list is `'self' 'nonce-…' 'sha256-…'`). A
 * string starts with a piece of three characters or more; a separator after that may be one (`"SG." + a + "." + b`).
 */
const STRING_PIECE = String.raw`[!#-&(-~]{3,300}`;
const STRING_PART = String.raw`[!#-&(-~]{1,300}`;
const PIECE_JOINT = String.raw`(?:[ \t]*(?:[+.&]|\|\|)[ \t]*(?:\r?\n[ \t]*)?|[ \t]*\r?\n[ \t]*(?:[+.&]|\|\|)[ \t]*|[ \t]*\r?\n[ \t]*|[ \t]+)`;
// (A gate, looser than literalJoints, which decides: it admits single-quoted pieces side by side, for one. The
// second piece as short as literalJoints reads one: `"hunter" + "2" + "xyz"`.)
const JOINT = new RegExp(String.raw`(["'])${STRING_PIECE}\1${PIECE_JOINT}\1${STRING_PART}\1`);

/**
 * What `cat -A`, `-e` and `-vET` print at a line's end: a `$`, after `^M` for a CRLF. A text marked so has them at the end of
 * every line but its last (a file with no final newline), and at least two lines do.
 */
const LINE_END_MARK_TEST = /\$\n[^\n]*\$(?:\n|$)/;

/**
 * Characters pass one drops or turns into a line break: NUL, BEL, ESC and the invisible format characters, the blank
 * fillers some scripts draw as nothing (`\u3164`), and, written as two UTF-16 units, Unicode's tag characters and the
 * supplementary variation selectors, which carry a hidden copy of ASCII text through a copy and paste.
 */
const INVISIBLE =
	/[\x00\x07\x1b\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0]|\udb40[\udc00-\udc7f\udd00-\uddef]/;
const NEEDS_PASS_ONE = (text: string) => INVISIBLE.test(text) || ESCAPED_CSI.test(text) || CARET_ESCAPE.test(text);
const NEEDS_PASS_TWO = (text: string) =>
	HAS_LINE_NUMBER.test(text) || PREFIXED.test(text) || LINE_END_MARK_TEST.test(text);
const NEEDS_PASS_THREE = (text: string) =>
	INLINE_TAG_TEST.test(text) ||
	/[\u00a0\u2000-\u200a\u2018\u2019\u201c-\u201e\u202f\u3000\uff1a\uff1d]|[\u2010-\u2015\u2212][A-Za-z]|\\\r?\n/.test(
		text,
	) ||
	ENTITY.test(text) ||
	JOINT.test(text);

/** Whether a text has anything to normalize, cheaply. (A pass only has work after one that ran if its own gate already fires on the original.) */
export function needsNormalizing(text: string): boolean {
	return NEEDS_PASS_ONE(text) || NEEDS_PASS_TWO(text) || NEEDS_PASS_THREE(text);
}

/**
 * An inline formatting tag, with no attribute but a class, `<b>`, `</strong>`, `<code>`, a syntax highlighter's `<span
 * class="hljs-string">`: what a page shows without it, so a label and its value read as one (`<b>Password:</b> X`,
 * `Password: <code>X</code>`, `<span class="hljs-attr">password</span>: <span class="hljs-string">"X"</span>`).
 */
const INLINE_TAG_TEST =
	/<\/?(?:b|strong|em|i|u|code|tt|kbd|mark|samp|var|span)(?:[ \t]+class=(?:"[^"<>\n]{0,80}"|'[^'<>\n]{0,80}'))?>/i;
const INLINE_TAG = new RegExp(`^${INLINE_TAG_TEST.source}`, "i");

/** Builds one pass's output, recording for each character the span of the input it came from. */
class Rewrite {
	private parts: string[] = [];
	map: number[] = [];
	ends: number[] = [];
	boundaries: number[] = [];
	emit(ch: string, from: number, to: number): void {
		this.parts.push(ch);
		this.map.push(from);
		this.ends.push(to);
	}
	/** Something that separated what comes before from what comes after was dropped here. */
	separate(): void {
		if (this.boundaries.at(-1) !== this.map.length) this.boundaries.push(this.map.length);
	}
	done(inputLength: number): Normalized {
		this.map.push(inputLength);
		return { text: this.parts.join(""), map: this.map, ends: this.ends, boundaries: this.boundaries };
	}
}

/** Pass one: what a terminal doesn't show. */
function stripInvisible(text: string): Normalized {
	const w = new Rewrite();
	let i = 0;
	// Inside an OSC (`ESC ]` or `^[]` begun, not yet ended by BEL, `^G`, a string terminator or the line).
	let inOsc = false;
	while (i < text.length) {
		const c = text.charCodeAt(i);
		// NULs that alternate with characters are UTF-16 read as UTF-8, and dropped; a NUL on its own
		// separates records (`/proc/<pid>/environ`, `find -print0`), and becomes a line break.
		if (c === 0) {
			if (text.charCodeAt(i + 2) !== 0 && text.charCodeAt(i - 2) !== 0) w.emit("\n", i, i + 1);
			i++;
			continue;
		}
		// ESC, or its caret notation `^[` as `cat -v` and `less` show it: one grammar, escapeSequenceEnd's. (In caret
		// notation, an introducer is read where it stands, `^[[32m`, and `^[\` only as the end of an OSC: `^[\w` is a regex's.)
		const esc = c === 0x1b ? 1 : c === 94 && isCaretEscape(text, i, inOsc) ? 2 : 0;
		if (esc) {
			const end = escapeSequenceEnd(text, i, esc);
			if (end > i) {
				// (An OSC's terminator, BEL or `ESC \`, becomes a line break; see escapeSequenceEnd.)
				if (text[i + esc] === "\\") {
					w.emit("\n", i, end);
					inOsc = false;
				} else w.separate();
				if (text[i + esc] === "]") inOsc = true;
				i = end;
				continue;
			}
		}
		// BEL in caret notation, `^G`, ending an OSC: a line break, as BEL is.
		if (inOsc && c === 94 && text[i + 1] === "G") {
			w.emit("\n", i, i + 2);
			inOsc = false;
			i += 2;
			continue;
		}
		if (c === 92) {
			ESCAPED_CSI_AT.lastIndex = i;
			const m = ESCAPED_CSI_AT.exec(text);
			if (m) {
				w.separate();
				i += m[0].length;
				continue;
			}
		}
		// Invisible format characters (zero-width spaces and joiners, the word joiner, a BOM, a soft hyphen) are dropped:
		// placed between every character of a key, they hide it from every rule (`s​k​_​l…`).
		if (c > 0x7f && INVISIBLE.test(text[i])) {
			i++;
			continue;
		}
		if (c === 0xdb40 && INVISIBLE.test(text.slice(i, i + 2))) {
			i += 2;
			continue;
		}
		if (c === 7) {
			w.emit("\n", i, i + 1);
			inOsc = false;
			i++;
			continue;
		}
		if (c === 10) inOsc = false;
		w.emit(text[i], i, i + 1);
		i++;
	}
	return w.done(text.length);
}

/** Whether the `^` at `i` begins an ESC in caret notation (see CARET_ESCAPE), or ends an OSC (`^[\`) when `inOsc`. */
function isCaretEscape(text: string, i: number, inOsc: boolean): boolean {
	CARET_ESCAPE_AT.lastIndex = i;
	return CARET_ESCAPE_AT.test(text) || (inOsc && text.startsWith("^[\\", i));
}

/**
 * Where the escape sequence at `i` ends, or `i` if it isn't one, its ESC `esc` characters long (1, or 2 in caret
 * notation: `^[`): CSI (`ESC [ … letter`), dropped whole; nF character-set designations (`ESC ( B`); two-byte
 * sequences (`ESC 7`, `ESC =`, `ESC M`), among them an OSC's introducer `ESC ]` (only the introducer goes: the
 * payload of `ESC ] … BEL`, a title or a hyperlink's URL, is scanned like any text) and its terminator `ESC \`.
 */
function escapeSequenceEnd(text: string, i: number, esc = 1): number {
	const next = text[i + esc] ?? "";
	if (next === "[") {
		let j = i + esc + 1;
		// Parameters (`:` too, as in 256-colour `38:5:196`), intermediates, then the final byte.
		while (j < text.length && j - i < 40 && /[0-9:;<=>?!]/.test(text[j])) j++;
		while (j < text.length && j - i < 44 && /[ -/]/.test(text[j])) j++;
		return j < text.length && /[@-~]/.test(text[j]) ? j + 1 : i;
	}
	if (/[ -/]/.test(next)) {
		let j = i + esc;
		while (j < text.length && j - i < esc + 3 && /[ -/]/.test(text[j])) j++;
		return /[0-~]/.test(text[j] ?? "") ? j + 1 : i;
	}
	return /[0-~]/.test(next) ? i + esc + 1 : i;
}

/**
 * Line prefixes to drop, by where each starts: a file viewer's line numbers;
 * `grep -n`'s on consecutively numbered lines of one file, or on a match on its own when its path has a directory
 * in it (`/etc/redis/redis.conf:1043:requirepass …`; a bare `host.example.com:8443:` could be a host and a port);
 * a unified diff's markers, walked by its hunk header's line counts.
 */
function linePrefixes(text: string): Map<number, number> {
	const drop = new Map<number, number>();
	for (const m of text.matchAll(LINE_NUMBER)) drop.set(m.index, m[0].length);
	const grep: { at: number; len: number; file: string; n: number; match: boolean }[] = [];
	for (const m of text.matchAll(GREP_PREFIX))
		grep.push({ at: m.index, len: m[0].length, file: m[1], n: Number(m[2]), match: m[0].endsWith(":") });
	for (let k = 0; k < grep.length; k++) {
		const near = (j: number) =>
			j >= 0 && j < grep.length && grep[j].file === grep[k].file && Math.abs(grep[j].n - grep[k].n) === 1;
		// (A file's name: a path, or an extension. `db.example.com:5432:` on two lines of a `.pgpass` is a host and a port,
		// and so is `db.example.sh:5432:` on a whole `.pgpass` line, whatever its top-level domain.)
		if (
			!grep[k].file.includes("/") &&
			((!FILE_EXTENSION.test(grep[k].file) && !/\.(?:env|properties|cnf|pem|key|conf)$/.test(grep[k].file)) ||
				PGPASS.test(text.slice(grep[k].at, lineEnd(text, grep[k].at, 4096))))
		)
			continue;
		if (near(k - 1) || near(k + 1) || (grep[k].match && grep[k].file.includes("/"))) drop.set(grep[k].at, grep[k].len);
	}
	// After `@@ -a,b +c,d @@`: b old lines (context and `-`) and d new ones (context and `+`). A context line whose
	// single space an editor stripped is empty; `\ No newline at end of file` belongs to the line before. Read on each
	// line's text after the prefix dropped above, so a viewer's numbered hunk is walked too (`5→-password=…`).
	if (!text.includes("@@ -")) return drop;
	const hunk = /@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@[^\n]*\n/y;
	for (let line = 0; line < text.length;) {
		hunk.lastIndex = line + (drop.get(line) ?? 0);
		const h = hunk.exec(text);
		if (!h) {
			const nl = text.indexOf("\n", line);
			if (nl < 0) break;
			line = nl + 1;
			continue;
		}
		let old = Number(h[1] ?? 1);
		let fresh = Number(h[2] ?? 1);
		let at = hunk.lastIndex;
		while (at < text.length && (old > 0 || fresh > 0)) {
			const prefix = drop.get(at) ?? 0;
			const c = text[at + prefix];
			if (c === "+") fresh--;
			else if (c === "-") old--;
			else if (c === " " || c === "\n" || c === "\r") {
				old--;
				fresh--;
			} else if (c !== "\\") break;
			if (c === "+" || c === "-" || c === " ") drop.set(at, prefix + 1);
			const nl = text.indexOf("\n", at);
			if (nl < 0) {
				at = text.length;
				break;
			}
			at = nl + 1;
		}
		line = at;
	}
	return drop;
}

/** Where each line-end mark of a text shown by `cat -A` is, and its length (`^M$` is 3, `$` is 1); none if the text isn't marked so. */
function lineEndMarks(text: string): Map<number, number> | undefined {
	const lines = text.split("\n");
	if (lines.length < 3 || !lines.slice(0, -1).every((line) => line.endsWith("$"))) return undefined;
	const marks = new Map<number, number>();
	let at = 0;
	for (const line of lines.slice(0, -1)) {
		const length = line.endsWith("^M$") ? 3 : 1;
		marks.set(at + line.length - length, length);
		at += line.length + 1;
	}
	return marks;
}

/** Pass two: what a tool puts in front of lines, and after them. */
function stripLinePrefixes(text: string): Normalized {
	const w = new Rewrite();
	const prefixes = HAS_LINE_NUMBER.test(text) || PREFIXED.test(text) ? linePrefixes(text) : undefined;
	const marks = LINE_END_MARK_TEST.test(text) ? lineEndMarks(text) : undefined;
	for (let i = 0; i < text.length;) {
		// (Keys are line starts: after `\n`, or `\r` and U+2028 too, as a multiline `^` matches.)
		const skip = prefixes?.get(i) ?? marks?.get(i);
		if (skip) {
			i += skip;
			continue;
		}
		w.emit(text[i], i, i + 1);
		i++;
	}
	return w.done(text.length);
}

/** For each joint, its start (the closing quote of a piece) and its end (after the next piece's opening quote). */
function literalJoints(text: string): Map<number, number> {
	const joints = new Map<number, number>();
	const piece = new RegExp(String.raw`(["'])(${STRING_PART})\1`, "g");
	const sep = new RegExp(PIECE_JOINT, "y");
	const doubleQuoted = new RegExp(`"${STRING_PART}"`, "y");
	const singleQuoted = new RegExp(`'${STRING_PART}'`, "y");
	let continues = -1; // where a piece joined to the one before starts
	for (let m = piece.exec(text); m; m = piece.exec(text)) {
		// (A piece that joins nothing may be the gap between two literals, `"a;"+"b"` read as `"+"`: the next search
		// starts inside it, at its closing quote.)
		piece.lastIndex = m.index + 1;
		const chained = m.index === continues;
		if (m[2].length < 3 && !chained) continue;
		const close = m.index + m[0].length - 1;
		sep.lastIndex = close + 1;
		const s = sep.exec(text);
		if (!s) continue;
		// The next piece: in the same quotes, and token-like too (`"Hello" + " world"` is two strings).
		const next = m[1] === '"' ? doubleQuoted : singleQuoted;
		next.lastIndex = sep.lastIndex;
		if (!next.test(text)) continue;
		const start = lineStart(text, m.index);
		const before = text.slice(start, m.index);
		// (Or a line of its own after one: `parse(\n    "postgres://u:" "pw" "@host"`, Black's wrapping.)
		const above = /^[ \t]*$/.test(before) && start > 0 ? text.slice(lineStart(text, start - 1), start - 1) : "";
		// Juxtaposition (blanks alone) is code only after `=`, `(`, `,`, `:`, `[` or `return`, in either quotes (Python and
		// Ruby join single-quoted pieces too): shell, nginx and log lines put separate arguments and fields side by side.
		// A format string starts no join, nor a CSP source list (`'self' 'nonce-…'`).
		if (!/[+.&|]/.test(s[0]) && !chained) {
			if (!/(?:[=(,:[]|\breturn)[ \t]*$/.test(before) && !/[=(,[][ \t]*\r?$/.test(above)) continue;
			// (A command line with options passes its quoted words as separate arguments: `curl -u u:"$PW" "https://…"`.)
			if (/(?:^|\s)--?[A-Za-z][\w-]*(?:[ \t=]|$)/.test(before)) continue;
			if (/%[-+ #0-9.]*[sdvqf]|\{\d*\}/.test(m[2])) continue;
			if (m[1] === "'" && /content-security-policy|-src\b/i.test(text.slice(start, lineEnd(text, m.index)))) continue;
			// Across a line break with no operator: inside parentheses (Python), or a C initializer after `=`, whose next
			// piece is indented under it (a shell line's quoted value ends its line: `export PW="…"` then `"$DIR/run.sh"`).
			if (/\n/.test(s[0]) && !/[(=][ \t]*$/.test(before) && !/[(=,][ \t]*\r?$/.test(above)) continue;
			if (/\n/.test(s[0]) && !/\n[ \t]+$/.test(s[0]) && !/\([ \t]*$/.test(before)) continue;
		}
		// The next piece is more of the string, not a name: `"…"="…"` lines (a .reg file, an INI) don't join.
		if (/^[ \t]*[=:]/.test(text.slice(next.lastIndex, next.lastIndex + 20))) continue;
		joints.set(close, sep.lastIndex + 1);
		continues = sep.lastIndex;
		piece.lastIndex = sep.lastIndex; // the next piece starts a literal of its own
	}
	return joints;
}

/** Pass three: what spells a character or a string another way. */
function unspell(text: string): Normalized {
	const w = new Rewrite();
	const joints = JOINT.test(text) ? literalJoints(text) : undefined;
	let i = 0;
	while (i < text.length) {
		const c = text.charCodeAt(i);
		// Between two pieces of one string literal: the quotes and the operator vanish.
		const joint = joints?.get(i);
		if (joint !== undefined) {
			i = joint;
			continue;
		}
		// A line continuation: the backslash and newline vanish, joining the lines as a shell, a C macro or a string
		// does (`--password \`, `TOKEN=AbCd\` then `EfGh`). Not a Windows path's last backslash (`DATA_DIR=C:\data\`,
		// `C:\Program Files\App\`, `\\server\share\`, `%ProgramData%\app\`: a word with another backslash in it), nor a
		// Markdown hard break (`**Host:** db\` then `**Password:** …`): a line that begins with no token there. Nor a
		// setting's line before another's, `NAME=…` on both (a .env's value ending in a backslash).
		if (c === 92 && (text[i + 1] === "\n" || (text[i + 1] === "\r" && text[i + 2] === "\n"))) {
			const next = text[i + 1] === "\r" ? i + 3 : i + 2;
			const line = text.slice(lineStart(text, i), i);
			const windowsPath = /(?:^|[\s=:"'])[A-Za-z]:\\[^\s]*$|\\[^\s]*$/.test(line);
			const hardBreak = !/[ \t]$/.test(line) && !/^[\w"'$\s-]/.test(text[next] ?? "");
			const assignment = /^(?:export[ \t]+)?[A-Za-z_][\w.]*=/;
			const setting = assignment.test(line) && assignment.test(text.slice(next, next + 80));
			if (!windowsPath && !hardBreak && !setting) {
				w.separate();
				i = next;
				continue;
			}
		}
		if (c === 60) {
			const tag = INLINE_TAG.exec(text.slice(i, i + 100));
			if (tag) {
				w.separate();
				i += tag[0].length;
				continue;
			}
		}
		if (c === 38) {
			const m = ENTITY_AT.exec(text.slice(i, i + 12));
			let ch = m ? entityChar(m) : undefined;
			if (m && ch !== undefined) {
				// (An entity escaped again, `&amp;quot;` in an attribute escaped twice, is the character it stands for.)
				let end = i + m[0].length;
				for (let depth = 0; ch === "&" && depth < 3; depth++) {
					const inner = ENTITY_AT.exec(`&${text.slice(end, end + 11)}`);
					const innerChar = inner ? entityChar(inner) : undefined;
					if (!inner || innerChar === undefined) break;
					ch = innerChar;
					end += inner[0].length - 1;
				}
				w.emit(ch, i, end);
				i = end;
				continue;
			}
		}
		// A space of another width or one that doesn't break (`Password:\u00a0V`, `&nbsp;`'s character, CJK's ideographic
		// space): a blank, as `&nbsp;` decodes to.
		if (c === 0xa0 || c === 0x202f || c === 0x3000 || (c >= 0x2000 && c <= 0x200a)) {
			w.emit(" ", i, i + 1);
			i++;
			continue;
		}
		// A dash a word processor typed for a command line's (`mysql –u root –pV`, `—password V`): after a blank, before a
		// letter. An em dash stands for two, as `--` turns into one.
		if (
			((c >= 0x2010 && c <= 0x2015) || c === 0x2212) &&
			/^\s?$/.test(text[i - 1] ?? "") &&
			/[A-Za-z]/.test(text[i + 1] ?? "")
		) {
			w.emit("-", i, i + 1);
			if (c === 0x2014) w.emit("-", i, i + 1);
			i++;
			continue;
		}
		// Full-width colon and equals sign.
		if (c === 0xff1a || c === 0xff1d) {
			w.emit(c === 0xff1a ? ":" : "=", i, i + 1);
			i++;
			continue;
		}
		// Typographic quotes, as a word processor's or a chat app's autocorrect writes them in pasted JSON and config
		// (`“password”: “…”`, German `„…“`): the straight quotes the syntax means.
		if (c === 0x2018 || c === 0x2019 || (c >= 0x201c && c <= 0x201e)) {
			w.emit(c <= 0x2019 ? "'" : '"', i, i + 1);
			i++;
			continue;
		}
		w.emit(text[i], i, i + 1);
		i++;
	}
	return w.done(text.length);
}

/** Pass `b` run over pass `a`'s output, as one pass over `a`'s input. */
function compose(a: Normalized, b: Normalized): Normalized {
	return {
		text: b.text,
		map: b.map.map((p) => a.map[p]),
		// (A character's source ends where the last character of `a`'s output it came from ends.)
		ends: b.ends.map((e) => a.ends[e - 1]),
		// (`a`'s boundaries carried into `b`'s output: the first position of `b` at or after each.)
		boundaries: [...new Set([...a.boundaries.map((p) => lowerBound(b.map, p)), ...b.boundaries])].sort((x, y) => x - y),
	};
}

export function normalize(text: string): Normalized {
	let done: Normalized | undefined;
	for (const [needs, pass] of [
		[NEEDS_PASS_ONE, stripInvisible],
		[NEEDS_PASS_TWO, stripLinePrefixes],
		[NEEDS_PASS_THREE, unspell],
	] as const) {
		const input = done?.text ?? text;
		if (!needs(input)) continue;
		const next = pass(input);
		done = done ? compose(done, next) : next;
	}
	if (done) return done;
	const map = Array.from({ length: text.length + 1 }, (_, k) => k);
	return { text, map, ends: map.slice(1), boundaries: [] };
}

/** A text with a blank put in at each of `at` (sorted), and for each of its positions the position in the text it came from. */
export function withBlanks(text: string, at: number[]): { text: string; map: number[] } {
	const parts: string[] = [];
	const map: number[] = [];
	let from = 0;
	for (const b of at) {
		parts.push(text.slice(from, b), " ");
		for (let i = from; i < b; i++) map.push(i);
		map.push(b);
		from = b;
	}
	parts.push(text.slice(from));
	for (let i = from; i < text.length; i++) map.push(i);
	map.push(text.length);
	return { text: parts.join(""), map };
}
