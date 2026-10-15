/**
 * Calls in source code, read the way most languages read them: arguments are separated by commas outside strings,
 * comments and brackets, and a call may span lines. An argument that is a string literal is read with the prefixes
 * and wrappers languages put around one (`b"…"`, `@"…"`, `Some("…")`, `"…".to_string()`), and a keyword argument
 * with its keyword (`password="…"`, `password: "…"`).
 */

import { lastText, lineEnd } from "./lines.ts";
import { type Escapes, isContraction, MAX_VALUE, type Span, STRING_PREFIX, stringEnd } from "./syntax.ts";

/** A string literal's content and where it is (quotes excluded). */
export interface Literal extends Span {
	quote: string;
}

export interface Argument {
	/** The argument as written, without the blanks and comments around it. */
	text: string;
	start: number;
	end: number;
	/** A keyword argument's keyword: `password` in `password="…"` or `password: "…"`. */
	keyword?: string;
	/** The string literal the argument is (after its keyword), if it is one. */
	literal?: Literal;
}

/** The brackets an argument list may open with, and the one that closes each. */
const CLOSER: Record<string, string> = { "(": ")", "[": "]", "{": "}" };

/** How far a call's arguments may run, in characters. */
const MAX_CALL = MAX_VALUE;

/**
 * The arguments of the call (or the list or object) whose opening bracket is just before `at`, up to its matching
 * closing bracket; undefined when the call isn't closed within MAX_CALL characters, a string doesn't close on its
 * line, or a bracket closes that didn't open. A `//` is a comment unless reading it as one leaves the call unclosed:
 * then it's Python's floor division (`port=total // 2)`).
 */
export function callArguments(text: string, at: number): Argument[] | undefined {
	for (const slashComments of [true, false]) {
		const close = closeOf(text, at - 1, slashComments);
		if (close >= 0) return splitArguments(text, at, close, slashComments);
	}
	return undefined;
}

/** Where the bracket opened just before `at` closes (its index), strings and comments skipped as callArguments skips them; -1 if not found. */
export function closingBracket(text: string, at: number): number {
	const close = closeOf(text, at - 1, true);
	return close >= 0 ? close : closeOf(text, at - 1, false);
}

/**
 * The tables `matchBrackets` makes for a text, with and without `//` comments. Kept for the last text read: the rules of
 * one text share them.
 */
const bracketTables = lastText(() => new Map<boolean, Int32Array>());

/** Where the opening bracket at `open` closes (see `matchBrackets`); -1 for none, and for a bracket the pass read inside a string or a comment. */
function closeOf(text: string, open: number, slashComments: boolean): number {
	const tables = bracketTables(text);
	let table = tables.get(slashComments);
	if (!table) tables.set(slashComments, (table = matchBrackets(text, slashComments)));
	const close = table[open] ?? -1;
	return close > open && close - open <= MAX_CALL ? close : -1;
}

/**
 * For each opening bracket of a text, the index of the bracket that closes it (0 if none does: a string on the way
 * doesn't close, or a bracket closes that didn't open), read in one pass with strings and comments skipped.
 */
function matchBrackets(text: string, slashComments: boolean): Int32Array {
	const close = new Int32Array(text.length);
	const open: number[] = [];
	// (A `/*` that never closes is no comment but text, a glob's `src/*.py` or a regex's `a/*b`, and so is every later one.)
	let unclosed = Infinity;
	for (let i = 0; i < text.length; i++) {
		const c = text[i];
		if ((c === "/" && text[i + 1] === "/" && slashComments) || (c === "#" && /[\s(,]/.test(text[i - 1] ?? " "))) {
			i = lineEnd(text, i, Infinity) - 1;
		} else if (c === "/" && text[i + 1] === "*" && i < unclosed) {
			const stop = text.indexOf("*/", i + 2);
			if (stop < 0) unclosed = i;
			else i = stop + 1;
		} else if (c === "'" && isContraction(text, i)) {
			// (Prose's apostrophe, `don't connect(…) doesn't`, opens nothing.)
		} else if (c === "`" && text.startsWith("``", i + 1)) {
			i = fenceEnd(text, i);
		} else if (c === '"' || c === "'" || c === "`") {
			// (A string that doesn't close ends every call around it: none of them is closed.)
			const stop = literalEnd(text, i, { max: MAX_CALL });
			if (stop < 0) open.length = 0;
			else i = stop;
		} else if (c === "(" || c === "[" || c === "{") open.push(i);
		else if (c === ")" || c === "]" || c === "}") {
			const at = open.pop();
			if (at !== undefined && CLOSER[text[at]] === c) close[at] = i;
			// (A bracket that closes what didn't open ends every call around it.)
			else open.length = 0;
		}
	}
	return close;
}

/**
 * The last backtick of the run of three or more that starts at `at`: a Markdown code fence (or inline code's), which opens
 * no template literal. Read as one, a fence would hide everything up to the next one, the code it shows included.
 */
function fenceEnd(text: string, at: number): number {
	let i = at;
	while (text[i + 1] === "`") i++;
	return i;
}

/** The arguments between `at` and the bracket at `close` that closes the call: separated by commas outside brackets and strings. */
function splitArguments(text: string, at: number, close: number, slashComments: boolean): Argument[] {
	const args: Argument[] = [];
	// Where the current argument's text starts and ends: its first and last characters outside blanks and comments.
	let first = -1;
	let last = -1;
	let inner: { text: string; at: number; stop: number } | undefined;
	const finish = () => {
		if (first >= 0) args.push(argument(text, first, last));
		first = last = -1;
	};
	for (let i = at; i < close; i++) {
		const c = text[i];
		if (c === " " || c === "\t" || c === "\n" || c === "\r") continue;
		if ((c === "/" && text[i + 1] === "/" && slashComments) || (c === "#" && /[\s(,]/.test(text[i - 1] ?? " "))) {
			i = Math.min(close, lineEnd(text, i, MAX_CALL)) - 1;
			continue;
		}
		if (c === "/" && text[i + 1] === "*") {
			// (As the bracket pass reads it: a comment that closes inside the call, or text. The next `*/` is looked for
			// once, not from each `/*`: a call of globs, `src/*/*.py`, would read its length once for each.)
			inner ??= { text: text.slice(i + 2, close), at: i + 2, stop: -2 };
			if (inner.stop !== -1 && inner.stop < i + 2 - inner.at) inner.stop = inner.text.indexOf("*/", i + 2 - inner.at);
			if (inner.stop >= 0) {
				i = inner.at + inner.stop + 1;
				continue;
			}
		}
		if (c === ",") {
			finish();
			continue;
		}
		if (first < 0) first = i;
		// (Each closes before `close`: the pass that matched `close` read them.)
		const stop =
			c === "`" && text.startsWith("``", i + 1)
				? fenceEnd(text, i)
				: c === '"' || c === "'" || c === "`"
					? literalEnd(text, i, { max: close - i })
					: c === "(" || c === "[" || c === "{"
						? closeOf(text, i, slashComments)
						: i;
		if (stop < 0) break;
		i = stop;
		last = i + 1;
	}
	finish();
	return args;
}

/**
 * How the string literal whose quote is at `quoteAt` escapes, told by the prefix before the quote: C#'s verbatim
 * `@"…"` doubles its quotes and may span lines, Rust's raw `r#"…"#` has no escapes, a backtick template spans lines.
 */
function dialect(text: string, quoteAt: number): { escapes: Escapes; multiline: boolean } | undefined {
	const before = text.slice(Math.max(0, quoteAt - 3), quoteAt);
	if (/(?<![\w$])(?:@\$?|\$@)$/.test(before)) return { escapes: "doubled", multiline: true };
	if (/(?<!\w)r#+$/.test(before)) return { escapes: "none", multiline: true };
	return undefined;
}

/**
 * What may follow a string literal that ends a value: a separator, a closing bracket, a comment, the line's end, an
 * operator or a SQL keyword (`… = 'a''b' WHERE …`, `AND`, `||`).
 */
const AFTER_LITERAL =
	/^[ \t]*(?:[,;)\]}|+&]|#|\/\/|--|\r?\n|$|(?:WHERE|AND|OR|LIMIT|ORDER|GROUP|ON|FROM|SET|VALUES|RETURNING|IS|NOT|ELSE|THEN|END)\b)/i;

/** What ends a shell word's bare characters: a blank, an operator, a bracket that closes what's around the word, a list's comma. */
const SHELL_WORD_END = /[\s;&|<>()`}\],#]/;

/**
 * Where the value of the shell word whose single-quoted first piece opens at `at` ends, its pieces run together the
 * way a shell joins them (`'it'\''s'`, `'Kx9''Qv2'`, `'Kx9'"Qv2"`, a `\` line continuation between two): at its last
 * piece's closing quote, or after its last bare character. -1 if a single quote is left open on its line, which makes
 * the line no shell's: `'Kx9\'Qv2 Lp7'` is another language's escape (a single quote escapes nothing in a shell).
 */
function shellWordEnd(text: string, at: number, max: number): number {
	let end = -1;
	let i = at;
	while (i < text.length && i - at <= max) {
		const c = text[i];
		if (c === "'" || c === '"') {
			const close = stringEnd(text, i, { escapes: c === "'" ? "none" : "backslash", max: max - (i - at) });
			if (close < 0) break;
			end = close;
			i = close + 1;
		} else if (c === "\\" && i + 1 < text.length) {
			// (An escaped character is the word's, `'Kx9'\!`, and an escaped line break joins the next line's pieces on.)
			end = i += 2;
		} else if (SHELL_WORD_END.test(c)) break;
		else end = ++i;
	}
	return (text.slice(i, lineEnd(text, i)).match(/'/g)?.length ?? 0) % 2 ? -1 : end;
}

/**
 * Where the string literal whose opening quote is at `at` closes, read with its syntax's escapes: C#'s `@"…"` doubles
 * a quote, Rust's `r#"…"#` has none, a shell's single quotes have none and run on into the rest of their word
 * (shellWordEnd), a template literal has a backslash, and any other is read both ways a language writes one, a
 * backslash (`'Kx9\'Qv2'`, `"Kx9\"Qv2"`: Python, JS, Ruby, PHP) and a doubled quote (`'Kx9''Qv2'`: YAML, SQL,
 * PowerShell; `"Kx9""Qv2"`: PowerShell, VB, CSV), whichever leaves the line well-formed after it (the longer when both
 * do); otherwise a backslash. (A raw string closes at its first quote, as the doubled reading reads it: Rust's
 * `r"C:\keys\"`. Python's `r"\""`, which keeps its escape, leaves the line well-formed only read with a backslash.)
 */
export function literalEnd(text: string, at: number, { max = MAX_VALUE, shell = false } = {}): number {
	const special = dialect(text, at);
	if (special) return stringEnd(text, at, { ...special, max });
	const quote = text[at];
	if (quote === "'" && shell) {
		const word = shellWordEnd(text, at, max);
		if (word >= 0) return word;
	}
	const backslash = stringEnd(text, at, { escapes: "backslash", multiline: quote === "`", max });
	if (quote === "`") return backslash;
	const doubled = stringEnd(text, at, { escapes: "doubled", max });
	const fits = (close: number) => close >= 0 && AFTER_LITERAL.test(text.slice(close + 1, close + 41));
	if (fits(backslash) && fits(doubled)) return Math.max(backslash, doubled);
	return fits(doubled) ? doubled : backslash;
}

/**
 * The head of a string literal, up to its opening quote: a keyword (`password=`, `password: `), a wrapper (`Some(`,
 * `String::from(`, `SecretStr(`), and a prefix (Python's `b r u f`, C#'s `@` and `$`, Rust's `r#`): how the readers
 * of calls' and assignments' literals find where one starts.
 */
const LITERAL_HEAD = new RegExp(
	String.raw`^(?:([A-Za-z_$][\w$]*)[ \t]*(?:=(?![=>])|:(?!:))[ \t]*)?((?:Some|String::from|SecretStr|Secret)\([ \t]*)?(${STRING_PREFIX})?(["'\x60])`,
);
/**
 * What may follow a literal and leave it the value: a Rust raw string's closing `#`s, the wrapper's `)`, a conversion
 * (`.to_string()`, `.encode()`).
 */
const LITERAL_TAIL = /^#*(?:[ \t]*\))?(?:\.(?:to_string|into|to_owned|encode|strip)\(\))?[ \t]*$/;
const KEYWORD = /^([A-Za-z_$][\w$]*)[ \t]*(?:=(?![=>])|:(?!:))/;

export interface LiteralHead {
	/** The keyword before it, when `keyword` was asked for. */
	keyword?: string;
	/** The literal's prefix: `f` makes its `{…}` holes code, `b` makes it bytes. */
	prefix: string;
	/** Where the opening quote is. */
	open: number;
}

/** The literal head starting at `at`, or undefined. With `keyword`, a keyword before it is read too. */
export function literalHead(text: string, at: number, { keyword = false } = {}): LiteralHead | undefined {
	const m = LITERAL_HEAD.exec(text.slice(at, at + 140));
	if (!m || (m[1] !== undefined && !keyword)) return undefined;
	return { keyword: m[1], prefix: m[3] ?? "", open: at + m[0].length - 1 };
}

/** The string literal that opens at `head`: its content and where it is, or undefined if it doesn't close. */
function literalOf(text: string, head: LiteralHead): Literal | undefined {
	const close = literalEnd(text, head.open, { max: MAX_CALL });
	return close < 0
		? undefined
		: { value: text.slice(head.open + 1, close), start: head.open + 1, end: close, quote: text[head.open] };
}

function argument(text: string, start: number, end: number): Argument {
	const arg: Argument = { text: text.slice(start, end), start, end };
	const keyword = KEYWORD.exec(arg.text);
	if (keyword) arg.keyword = keyword[1];
	const head = literalHead(text, start, { keyword: true });
	const lit = head && literalOf(text, head);
	if (lit && LITERAL_TAIL.test(text.slice(lit.end + 1, end))) arg.literal = lit;
	return arg;
}

/** The string literal starting at `at` (after blanks), read as an argument would be: `"…"`, `b'…'`, `Some("…")`. */
export function literalAt(text: string, at: number): Literal | undefined {
	const start = at + /^[ \t]*/.exec(text.slice(at, at + 200))![0].length;
	const head = literalHead(text, start);
	return head && literalOf(text, head);
}

export interface Call {
	/** The callee pattern's match, ending at the call's `(`. */
	match: RegExpExecArray;
	args: Argument[];
}

/** The calls whose callee `pattern` (global, ending with the opening bracket) matches, with their arguments. */
export function* calls(text: string, pattern: RegExp): Generator<Call> {
	pattern.lastIndex = 0;
	for (let m = pattern.exec(text); m; m = pattern.exec(text)) {
		const args = callArguments(text, m.index + m[0].length);
		if (args) yield { match: m, args };
	}
}
