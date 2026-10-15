/**
 * A shell command line's commands and words, read by one lexer (lexWord) the way bash reads them: blanks separate words outside
 * quotes; `'…'` quotes everything, `"…"` and a bare backslash escape a character, `$'…'` decodes bash's escapes, and a
 * backslash before a line break removes both; pieces next to each other are one word (`--password='x y'`); expansions
 * (`$(…)`, backticks, `${…}`, `<(…)`) stay in the word as written, and the commands they run are noted; `#` starting a
 * word comments out the rest of the line. `|`, `|&`, `||`, `&&`, `;`, `&` and line breaks end a command; redirections
 * (`>`, `>>`, `2>&1`, `&>`, `<`, `<<EOF`, `<<-`, `<<<`) are read with their targets, a heredoc's body off the lines after
 * its command; and a group (`{ …; }`, `( … )`, a loop, an `if` or a `case`) passes its redirections and its pipe on
 * to the commands inside it. Not read: arithmetic (`$((1 + 2))` stays in its word as written), functions, and a `case`
 * pattern (`x)` is dropped, not run). A quote that doesn't close runs to the end of the text, into the word it opened in:
 * bash rejects such a line, and what follows it is not a command of its own.
 */
import { lookup } from "./lookup.ts";
import { lastText, lineEnd, lowerBound } from "./lines.ts";
import { UNQUOTED_READ } from "./syntax.ts";

export interface ShellWord {
	/** The word with its quotes and escapes removed. */
	text: string;
	/** Where it was written: its start and end, and what is there (offset added). */
	start: number;
	end: number;
	raw: string;
	/** Whether any of it was quoted. */
	quoted: boolean;
	/** Whether its last part sat in single quotes (`'…'`, `$'…'`), where a shell expands nothing: `'$mIWy…'` is a literal. */
	literalEnd: boolean;
	/** Where each character of `text` was written (offset added): a value's span is read off it, never searched for. */
	map: number[];
	/** Where each character's source ends (offset added): an escape, `\x63` in `$'…'`, is several characters of the line. */
	ends: number[];
	/** Where the commands its substitutions run are written (offset added): `$(…)`, backticks, `<(…)`, `>(…)`. */
	substitutions: { start: number; end: number }[];
}

/**
 * The redirection operators, in the order the lexer tries them (one before the operator it starts with), and what each
 * sends to its target: standard output (`>`), standard output and error (`&>`, and `>&` onto a file), or no output.
 */
const REDIRECT_OPERATORS = lookup<"stdout" | "both" | "none">({
	"<<<": "none",
	"<<-": "none",
	"<<": "none",
	"<>": "none",
	"<&": "none",
	">&": "both",
	">>": "stdout",
	">|": "stdout",
	"&>>": "both",
	"&>": "both",
	"<": "none",
	">": "stdout",
});

/** A redirection, at the start of a text, as the lexer reads it: its file descriptor (group 1 is the operator after it). `<(` and `>(` are process substitutions, words. */
const REDIRECT = new RegExp(
	String.raw`^\d*(${Object.keys(REDIRECT_OPERATORS)
		.map((op) => op.replace("|", String.raw`\|`) + (op.length === 1 ? String.raw`(?!\()` : ""))
		.join("|")})`,
);

export interface ShellRedirect {
	/** The operator, without its file descriptor: `>`, `>>`, `>|`, `&>`, `&>>`, `<`, `<>`, `>&`, `<&`, `<<`, `<<-`, `<<<`. */
	op: string;
	/** The file descriptor written before it, if one was: `2` of `2>/dev/null`. */
	fd?: number;
	/** Its target: a file, a descriptor (`2>&1`'s `1`), a heredoc's delimiter, a here-string. */
	target?: ShellWord;
	/** Where the redirection is written, its target included (offset added). */
	start: number;
	end: number;
}

export interface Heredoc {
	/** The delimiter, unquoted, and whether it was quoted (`<<'EOF'`, `<<\EOF`: the body isn't expanded). */
	delimiter: string;
	quoted: boolean;
	/** `<<-`: the body's and the terminator's leading tabs are stripped. */
	strip: boolean;
	/** The body: the lines after the command's line, up to the delimiter's line, or the end (offset added). */
	start: number;
	end: number;
	terminated: boolean;
}

/** A compound command around simple ones: its redirections and the operator after it apply to all of them. */
export interface ShellGroup {
	kind: string;
	redirects: ShellRedirect[];
	/** The operator after the group: `|` pipes what every command in it prints (`{ cat .env; echo; } | sha256sum`). */
	then?: ShellOperator;
}

type ShellOperator = "|" | "|&" | "||" | "&&" | ";" | "&" | "\n" | "";

export interface ShellCommand {
	/** The command as written, and where it starts and ends (offset added). */
	text: string;
	start: number;
	end: number;
	/** Its words, redirections aside. */
	words: ShellWord[];
	redirects: ShellRedirect[];
	heredocs: Heredoc[];
	/** The groups it is inside, innermost first. */
	groups: ShellGroup[];
	/** The operator after it, or after the group it ends: `|` and `|&` pipe its output into the next command. */
	then: ShellOperator;
}

/** bash's one-character escapes in `$'…'`. */
const ANSI_C: Record<string, string> = {
	n: "\n",
	t: "\t",
	r: "\r",
	a: "\x07",
	b: "\b",
	e: "\x1b",
	E: "\x1b",
	f: "\f",
	v: "\v",
	"\\": "\\",
	"'": "'",
	'"': '"',
	"?": "?",
};

/** The escape whose backslash is at `at` in `$'…'`, which ends at `end`: what it decodes to and how long it is (`\n`, `\x41`, `\101`, `\u00e9`, `\cA`). */
function ansiEscape(text: string, at: number, end: number): [decoded: string, length: number] {
	const rest = text.slice(at + 1, Math.min(at + 10, end));
	const m = /^(?:x([0-9a-fA-F]{1,2})|u([0-9a-fA-F]{1,4})|U([0-9a-fA-F]{1,8})|([0-7]{1,3}))/.exec(rest);
	if (m) {
		const code = parseInt(m[1] ?? m[2] ?? m[3] ?? m[4], m[4] !== undefined ? 8 : 16);
		return [code <= 0x10ffff ? String.fromCodePoint(code) : "", 1 + m[0].length];
	}
	if (rest[0] === "c" && rest[1] !== undefined) return [String.fromCharCode(rest.charCodeAt(1) & 0x1f), 3];
	const simple = ANSI_C[rest[0]];
	return simple === undefined ? [`\\${rest[0] ?? ""}`, 2] : [simple, 2];
}

/** Words that open a group, and the word or operator that closes each. */
const GROUP_CLOSER = lookup<string>({
	"(": ")",
	"{": "}",
	if: "fi",
	for: "done",
	while: "done",
	until: "done",
	select: "done",
	case: "esac",
});

/**
 * Where each short line of a text starts, by its content (and by its content without leading tabs): a heredoc's
 * terminator is then a lookup, so many heredoc lines in a text cost each body once.
 */
export class LineIndex {
	private readonly exact = new Map<string, number[]>();
	private readonly stripped = new Map<string, number[]>();

	constructor(text: string) {
		for (let start = 0; start < text.length;) {
			const nl = text.indexOf("\n", start);
			const end = nl < 0 ? text.length : nl;
			if (end - start <= 200) {
				const line = text.slice(start, text[end - 1] === "\r" ? end - 1 : end);
				for (const [map, key] of [
					[this.exact, line],
					[this.stripped, line.replace(/^\t+/, "")],
				] as const) {
					const starts = map.get(key);
					if (starts) starts.push(start);
					else map.set(key, [start]);
				}
			}
			start = end + 1;
		}
	}

	/** The first line at or after `from` that is `line` (with `strip`, after its leading tabs), or -1. */
	next(line: string, strip: boolean, from: number): number {
		const starts = (strip ? this.stripped : this.exact).get(line);
		return starts?.[lowerBound(starts, from)] ?? -1;
	}
}

/**
 * The line index of the last text asked about, for a heredoc search whose caller gave none: many lines of one text then
 * cost the text once.
 */
const lineIndex = lastText((text: string) => new LineIndex(text));

/** What the lexer reads: the text, where to stop, whether a backslash escapes (not on Windows), and the offset added to positions. */
interface Lexing {
	text: string;
	limit: number;
	backslash: boolean;
	offset: number;
}

/** Whether an expansion opens at `at`: `$(`, `${` or a backtick. */
const opensExpansion = (text: string, at: number) =>
	text[at] === "`" || (text[at] === "$" && (text[at + 1] === "(" || text[at + 1] === "{"));

/** Where the expansion opened at `at` (see opensExpansion) closes, or -1. */
function expansionEnd(lx: Lexing, at: number, depth: number): number {
	if (lx.text[at] === "`") return closing(lx, at + 1, "`", depth + 1);
	return closing(lx, at + 2, lx.text[at + 1] === "(" ? ")" : "}", depth + 1);
}

/**
 * Where the quote of the given kind (`'`, `"` or `$'`) whose content starts at `from` closes: the index of its closing
 * quote, past what the quote reads whole (the escapes in `"…"` and `$'…'`, the expansions in `"…"`); -1 if it doesn't close
 * within the limit. The one place the quotes' grammar is written: lexWord reads a quote's content up to it, and `closing`
 * steps over a quote with it.
 */
function quoteEnd(lx: Lexing, from: number, quote: "'" | '"' | "$'", depth = 0): number {
	const { text, limit } = lx;
	if (quote === "'") {
		const close = text.indexOf("'", from);
		return close < 0 || close >= limit ? -1 : close;
	}
	const closer = quote === '"' ? '"' : "'";
	for (let j = from; j < limit; j++) {
		const ch = text[j];
		if (ch === "\\" && (lx.backslash || quote === "$'")) j++;
		else if (ch === closer) return j;
		else if (quote === '"' && opensExpansion(text, j)) {
			j = expansionEnd(lx, j, depth);
			if (j < 0) return -1;
		}
	}
	return -1;
}

/**
 * `case` or `esac` where a command starts at `at` (first in the text from `from`, or after a blank run that follows `;`, `&`,
 * `|`, `(` or a line break): `echo case` and `showcase` are not it.
 */
function caseWord(text: string, at: number, from: number): "case" | "esac" | undefined {
	const word = text.startsWith("case", at) ? "case" : text.startsWith("esac", at) ? "esac" : undefined;
	if (!word || /[\w.-]/.test(text[at + 4] ?? "")) return undefined;
	let k = at;
	while (k > from && (text[k - 1] === " " || text[k - 1] === "\t")) k--;
	return k === from || ";&|(\n".includes(text[k - 1]) ? word : undefined;
}

/**
 * Where what an expansion opened at `from` (after its opener) closes: the index of `close`, through nested expansions,
 * quotes and escapes, as the shell reads them; -1 if it doesn't within the limit. In a `$(…)`, the `)` that ends a `case`
 * pattern (`$(case x in x) cat .env;; esac)`) is not its end.
 */
function closing(lx: Lexing, from: number, close: ")" | "}" | "`", depth = 0): number {
	if (depth > 32) return -1;
	const { text, limit } = lx;
	let parens = 0;
	let cases = 0;
	// Heredocs opened on the current line: their bodies, from the next line, are text, not code (`$(cat <<'EOF'` with a
	// `don't` in the body).
	let heredocs: { delimiter: string; strip: boolean }[] = [];
	for (let j = from; j < limit; j++) {
		const ch = text[j];
		if (ch === "\\" && lx.backslash) j++;
		else if (close === "`") {
			if (ch === "`") return j;
		} else if (close === ")" && ch === "<" && text[j - 1] !== "<") {
			// (Not a here-string, `<<<`, at its second `<`; at its first, no delimiter follows the `<<`. A delimiter quoted,
			// `<<'EOF'`, `<<"EOF"`, or escaped, `<<\EOF`.)
			const h = /^<<(-?)[ \t]*(?:\\|(["']?))([\w.-]{1,80})\2/.exec(text.slice(j, j + 100));
			if (h) {
				heredocs.push({ delimiter: h[3], strip: h[1] === "-" });
				j += h[0].length - 1;
			}
		} else if (ch === "\n" && heredocs.length) {
			for (const h of heredocs) {
				// (Each body runs to its delimiter's line; one that never ends runs past the limit, and nothing closes.)
				let line = j + 1;
				for (;;) {
					if (line >= limit) return -1;
					const nl = text.indexOf("\n", line);
					const body = text.slice(line, nl < 0 ? limit : nl).replace(/\r$/, "");
					line = nl < 0 ? limit : nl + 1;
					if ((h.strip ? body.replace(/^\t+/, "") : body) === h.delimiter) break;
				}
				j = line - 1;
			}
			heredocs = [];
		} else if (close === ")" && ch === "#" && (j === from || /[ \t\n;&|(]/.test(text[j - 1]))) {
			// A comment runs to the line's end; its quotes are prose.
			const nl = text.indexOf("\n", j);
			if (nl < 0 || nl >= limit) return -1;
			j = nl - 1;
		} else if (ch === "'" || ch === '"' || (ch === "$" && text[j + 1] === "'")) {
			j = quoteEnd(lx, j + (ch === "$" ? 2 : 1), ch === "$" ? "$'" : ch, depth);
			if (j < 0) return -1;
		} else if (opensExpansion(text, j)) {
			j = expansionEnd(lx, j, depth);
			if (j < 0) return -1;
		} else if (close === ")" && (ch === "c" || ch === "e") && caseWord(text, j, from)) {
			cases = Math.max(0, cases + (ch === "c" ? 1 : -1));
			j += 3;
		} else if (close === ")" && ch === ")" && parens === 0 && cases > 0) continue;
		else if (close === ")" && ch === "(") parens++;
		else if (ch === close && parens-- === 0) return j;
	}
	return -1;
}

/** Whether the `$(` at `at` opens arithmetic, `$((1 + 2))`, and not a subshell in a substitution, `$((cat .env) | head)`: the second `(` closes right before the first. */
function isArithmetic(lx: Lexing, at: number): boolean {
	if (!lx.text.startsWith("$((", at)) return false;
	const inner = closing(lx, at + 3, ")");
	return inner >= 0 && lx.text[inner + 1] === ")";
}

/**
 * The word at `from`, to a blank, a line break or an operator outside quotes; its `end` is where the next thing starts.
 * Each quote is read to its end (`quoteEnd`), an expansion as written; one that doesn't close runs to the limit.
 */
function lexWord(lx: Lexing, from: number): ShellWord {
	const { text, limit, backslash, offset } = lx;
	let i = from;
	let s = "";
	const map: number[] = [];
	const ends: number[] = [];
	const substitutions: { start: number; end: number }[] = [];
	let quoted = false;
	let literalEnd = false;
	/** A character of the word, written at `[at, to)`. */
	const put = (ch: string, at: number, to = at + 1) => {
		s += ch;
		map.push(offset + at);
		ends.push(offset + to);
	};
	// An expansion is copied as written; the command a substitution runs is noted. (Unclosed, it runs to the limit.)
	const expansion = (openLength: number, close: ")" | "}" | "`", command: boolean) => {
		const begin = i;
		const closed = closing(lx, i + openLength, close);
		const stop = closed < 0 ? limit : closed + 1;
		if (command && !isArithmetic(lx, begin))
			substitutions.push({ start: offset + begin + openLength, end: offset + (closed < 0 ? limit : closed) });
		for (let k = begin; k < stop; k++) put(text[k], k);
		i = stop;
	};
	while (i < limit) {
		const ch = text[i];
		if (ch === " " || ch === "\t" || ch === "\n" || ch === "\r") break;
		if ((ch === "<" || ch === ">") && text[i + 1] === "(") {
			expansion(2, ")", true);
			continue;
		}
		if (/[|;&()<>]/.test(ch)) break;
		literalEnd = false;
		if (ch === "\\" && backslash) {
			if (text[i + 1] === "\n") i += 2;
			else if (i + 1 < limit) {
				put(text[i + 1], i + 1);
				i += 2;
			} else i++;
			continue;
		}
		if (ch === "'") {
			quoted = literalEnd = true;
			const close = quoteEnd(lx, i + 1, "'");
			const stop = close < 0 ? limit : close;
			for (let k = i + 1; k < stop; k++) put(text[k], k);
			i = close < 0 ? stop : stop + 1;
			continue;
		}
		if (ch === "$" && text[i + 1] === "'") {
			quoted = literalEnd = true;
			i += 2;
			const close = quoteEnd(lx, i, "$'");
			const stop = close < 0 ? limit : close;
			while (i < stop) {
				if (text[i] === "\\" && i + 1 < stop) {
					// (Every character it decodes to was written as the whole escape.)
					const [decoded, length] = ansiEscape(text, i, stop);
					for (let u = 0; u < decoded.length; u++) put(decoded[u], i, i + length);
					i += length;
				} else put(text[i], i++);
			}
			i = close < 0 ? stop : stop + 1;
			continue;
		}
		if (ch === '"' || (ch === "$" && text[i + 1] === '"')) {
			quoted = true;
			i += ch === "$" ? 2 : 1;
			const close = quoteEnd(lx, i, '"');
			const stop = close < 0 ? limit : close;
			while (i < stop) {
				if (text[i] === "\\" && backslash && text[i + 1] === "\n") i += 2;
				else if (text[i] === "\\" && backslash && /["\\$`]/.test(text[i + 1] ?? "")) {
					put(text[i + 1], i + 1);
					i += 2;
				} else if (text[i] === "$" && text[i + 1] === "(") expansion(2, ")", true);
				else if (text[i] === "$" && text[i + 1] === "{") expansion(2, "}", false);
				else if (text[i] === "`") expansion(1, "`", true);
				else put(text[i], i++);
			}
			i = close < 0 ? stop : stop + 1;
			continue;
		}
		if (ch === "$" && text[i + 1] === "(") expansion(2, ")", true);
		else if (ch === "$" && text[i + 1] === "{") expansion(2, "}", false);
		else if (ch === "`") expansion(1, "`", true);
		else put(ch, i++);
	}
	return {
		text: s,
		start: offset + from,
		end: offset + i,
		raw: text.slice(from, i),
		quoted,
		literalEnd,
		map,
		ends,
		substitutions,
	};
}

/**
 * The commands of a command line (or several: a line break ends a command), read from `at` to the end of `text`. With
 * `oneLine`, through the logical line at `at` (continued by `\`-newlines, and by a quote that closes within a few lines)
 * and its heredocs' bodies, as out of other text. With `backslash` false a backslash is a character like any other, as
 * on Windows (`.\.env`, `\\srv\share`). A `lines` index of `text` finds heredocs' terminators by lookup.
 */
export function shellCommands(
	text: string,
	offset = 0,
	{
		backslash = true,
		oneLine = false,
		at = 0,
		lines,
	}: { backslash?: boolean; oneLine?: boolean; at?: number; lines?: LineIndex } = {},
): ShellCommand[] {
	const out: ShellCommand[] = [];
	let i = at;
	let start = i;
	let words: ShellWord[] = [];
	let redirects: ShellRedirect[] = [];
	let heredocs: Heredoc[] = [];
	let pending: Heredoc[] = [];
	/** Open groups, outermost first, each with where its commands start in `out`; a group just closed takes the redirections after it. */
	const groups: { group: ShellGroup; from: number; patterns?: boolean }[] = [];
	let closed: { group: ShellGroup; from: number } | undefined;
	// (One line read out of other text: a quote may run on for up to four more lines, and no further.)
	let limit = text.length;
	if (oneLine) {
		limit = Math.min(text.length, at + UNQUOTED_READ);
		for (let k = 0, nl = at; k < 5 && nl >= 0 && nl < limit; k++) {
			nl = text.indexOf("\n", nl + 1);
			if (k === 4 && nl >= 0) limit = Math.min(limit, nl);
		}
	}
	const lx: Lexing = { text, limit, backslash, offset };
	const readWord = () => {
		const word = lexWord(lx, i);
		i = word.end - offset;
		return word;
	};
	const end = (then: ShellOperator, to: number) => {
		if (closed && !words.length) {
			// The redirections and the operator after a group's closer are the group's.
			closed.group.redirects.push(...redirects);
			closed.group.then = then;
			const last = out.at(-1);
			if (last && out.length > closed.from) last.then = then;
		} else if (words.length || redirects.length) {
			out.push({
				text: text.slice(start, to),
				start: offset + start,
				end: offset + to,
				words,
				redirects,
				heredocs,
				groups: groups.map((g) => g.group).reverse(),
				then,
			});
		}
		closed = undefined;
		words = [];
		redirects = [];
		heredocs = [];
	};
	const open = (kind: string) => groups.push({ group: { kind, redirects: [] }, from: out.length });
	const close = (kind: string) => {
		const k = groups.findLastIndex((g) => GROUP_CLOSER[g.group.kind] === kind);
		if (k < 0) return false;
		closed = groups[k];
		groups.length = k;
		return true;
	};
	while (i < limit) {
		const c = text[i];
		if (c === " " || c === "\t" || c === "\r") {
			i++;
			continue;
		}
		if (c === "\\" && backslash && text[i + 1] === "\n") {
			i += 2;
			continue;
		}
		// (Here a word would start: `#` comments out the rest of the line; inside a word, `a#b`, it's a character.)
		if (c === "#") {
			while (i < limit && text[i] !== "\n") i++;
			continue;
		}
		if (c === "\n") {
			// (A line that ends in `|`, `&&` or `||` goes on to the next: `echo "$PW" |` then `  docker login --password-stdin`.)
			const continued = !words.length && !redirects.length && /^(?:\||\|&|&&|\|\|)$/.test(out.at(-1)?.then ?? "");
			end("\n", i);
			i = heredocBodies(i + 1);
			start = i;
			if (oneLine && !continued) break;
			continue;
		}
		// `<(…)` and `>(…)` are words: process substitutions.
		const op = /^(?:\|\||\|&|&&|[|;&()])/.exec(text.slice(i, i + 2))?.[0];
		if (op && !/^&>/.test(text.slice(i, i + 2))) {
			const inCase = groups.at(-1)?.group.kind === "case" ? groups.at(-1) : undefined;
			if (op === "|" && inCase?.patterns) {
				// (A `case` pattern's alternative, `a|b) …`: no pipe.)
			} else if (op === ")" && inCase) {
				// (A `case` pattern's `)`, `x) cat .env;;`: what came before it, the pattern, is no command.)
				words = [];
				redirects = [];
				inCase.patterns = false;
			} else {
				if (op === ";" && text[i - 1] === ";" && inCase) inCase.patterns = true;
				end(op === "(" || op === ")" ? ";" : (op as ShellOperator), i);
				if (op === "(") open("(");
				else if (op === ")") close(")");
			}
			i += op.length;
			start = i;
			continue;
		}
		const redirect = REDIRECT.exec(text.slice(i, i + 12));
		if (redirect) {
			const from = i;
			i += redirect[0].length;
			while (text[i] === " " || text[i] === "\t") i++;
			// (A process substitution is a target too, a file its command writes or reads: `tee out.log < <(cat .env)`.)
			const target =
				i < limit && (!/[\r\n;&|()<>]/.test(text[i]) || /^[<>]\(/.test(text.slice(i, i + 2))) ? readWord() : undefined;
			const fd = /^\d+/.exec(redirect[0])?.[0];
			redirects.push({
				op: redirect[1],
				...(fd ? { fd: Number(fd) } : {}),
				target,
				start: offset + from,
				end: offset + i,
			});
			if (target && (redirect[1] === "<<" || redirect[1] === "<<-")) {
				const heredoc: Heredoc = {
					delimiter: target.text,
					quoted: target.quoted || target.raw.includes("\\"),
					strip: redirect[1] === "<<-",
					start: -1,
					end: -1,
					terminated: false,
				};
				heredocs.push(heredoc);
				pending.push(heredoc);
			}
			continue;
		}
		const before = i;
		const word = readWord();
		// (A character no branch above reads is skipped: whatever the lexer stops at, every pass of this loop moves on.)
		if (i === before) {
			i++;
			continue;
		}
		// A reserved word in a command's first place (after `!`, `then`, `else`, `do`) opens or closes a group.
		if (words.every((w) => RESERVED.has(w.text) && !w.quoted) && !word.quoted && !redirects.length) {
			if (
				word.text === "{" ||
				word.text === "}" ||
				word.text === "fi" ||
				word.text === "done" ||
				word.text === "esac"
			) {
				if (word.text === "{") {
					open("{");
					continue;
				}
				if (close(word.text)) continue;
			} else if (Object.hasOwn(GROUP_CLOSER, word.text)) open(word.text);
		}
		// (`case x in`: the patterns of the first arm follow.)
		if (word.text === "in" && !word.quoted && words.at(-2)?.text === "case" && groups.at(-1)?.group.kind === "case")
			groups.at(-1)!.patterns = true;
		words.push(word);
	}
	end("", i);
	// A heredoc whose body never came (the text ended on its line) is empty.
	for (const h of pending) h.start = h.end = offset + text.length;
	return out;

	/** Reads the bodies of the line's heredocs from `from`, in order; returns where the next line starts. */
	function heredocBodies(from: number): number {
		let at = from;
		for (const h of pending) {
			h.start = offset + at;
			const line = (lines ?? lineIndex(text)).next(h.delimiter, h.strip, at);
			if (line < 0) {
				h.end = offset + text.length;
				at = text.length;
				continue;
			}
			h.end = offset + line;
			h.terminated = true;
			const nl = text.indexOf("\n", line);
			at = nl < 0 ? text.length : nl + 1;
		}
		pending = [];
		return at;
	}
}

/** The shell word written at `at`, read to its line's end at most: `'it'\''s'` is one word, `it's`. */
export function shellWordAt(text: string, at: number): ShellWord {
	return lexWord({ text, limit: lineEnd(text, at, UNQUOTED_READ), backslash: true, offset: 0 }, at);
}

/** The words of a command line, redirections aside (see shellCommands). */
export function shellWords(command: string, offset = 0, { backslash = true } = {}): ShellWord[] {
	return shellCommands(command, offset, { backslash }).flatMap((c) => c.words);
}

/** A command's redirections and those of the groups it is inside. */
export function allRedirects(c: ShellCommand): ShellRedirect[] {
	return [...c.redirects, ...c.groups.flatMap((g) => g.redirects)];
}

/**
 * Whether a redirection sends the command's standard output to a file: `>`, `>>`, `>|`, `&>`, `&>>`, and `>&` onto a
 * file (`>& out`; `>&2` and `2>&1` copy a descriptor), with no descriptor written before it or standard output's
 * (`1> out`, `1>& out`; `2> out` sends another's).
 */
export function redirectsStdout(r: ShellRedirect): boolean {
	const sends = REDIRECT_OPERATORS[r.op];
	if (sends === "none" || (r.fd !== undefined && r.fd !== 1)) return false;
	return sends === "stdout" || !/^(?:\d+|-)$/.test(r.target?.text ?? "");
}

/**
 * Where `text.slice(from)` of a word was written: the characters themselves when they were written together, or,
 * when quotes or escapes sit among them (`'Xk9'"mQ2"`, `'a'\''b'`, `a\ b`), the whole stretch with the quotes around it,
 * so what replaces it leaves the line's quoting whole.
 */
export function wordSpan(word: ShellWord, from = 0): { start: number; end: number } {
	if (word.text.length <= from) return { start: word.end, end: word.end };
	let start = word.map[from];
	let end = word.ends.at(-1)!;
	const raw = (k: number) => word.raw[k - word.start];
	// (A span that starts and ends in the same quotes, or outside any, keeps the word's quotes about it as they were: the
	// `'\''` a single-quoted password writes its quote with, `'admin:pa'\''ss'`, leaves the closing quote out.)
	if (
		word.raw.slice(start - word.start, end - word.start) !== word.text.slice(from) &&
		quoteAt(word.raw, start - word.start) !== quoteAt(word.raw, end - word.start)
	) {
		while (start > word.start && /["'$]/.test(raw(start - 1))) start--;
		while (end < word.end && /["']/.test(raw(end))) end++;
	}
	return { start, end };
}

/** The quote a shell word's raw text is inside at `at`: `'`, `"`, or "" outside quotes. */
function quoteAt(raw: string, at: number): string {
	let quote = "";
	for (let k = 0; k < at; k++) {
		const c = raw[k];
		if (c === "\\" && quote !== "'") k++;
		else if (quote ? c === quote : c === "'" || c === '"') quote = quote ? "" : c;
	}
	return quote;
}

/** The command line an argument vector stands for, each word quoted as a shell needs it: `["bash", "-lc", "cat .env"]` → `bash -lc 'cat .env'`. */
export function shellLine(argv: string[]): string {
	return argv.map((w) => (/^[\w@%+=:,./-]+$/.test(w) ? w : `'${w.replace(/'/g, "'\\''")}'`)).join(" ");
}

/**
 * A terminal prompt at the start of a line, before a command. Group 1 is the command. A POSIX shell's, after a
 * virtualenv's or conda's `(venv) `: `$ `, `user@host:~/app$ `, `root@3f2a9c1d:/app# `, RHEL's `[ec2-user@ip-10-0-1-5
 * app]$ `, macOS zsh's `user@host app % `, a bare shell's `bash-5.1$ ` and `sh-4.2# `, busybox's `/app # `. PowerShell's
 * `PS C:\> ` and `PS> `, cmd's `C:\app>` (no blank after it), a notebook's `In [3]: !` or a cell's bare `!` before a
 * command. (Not root's bare `# `: a comment or a Markdown heading is written so.)
 */
export const PROMPT =
	/^[ \t]*(?:(?:\([\w.-]{1,40}\)[ \t]+)?(?:\$ |[\w.-]+@[\w.-]+:[^\n$#]{0,200}[$#] |\[[\w.-]+@[\w.-]+(?:[ \t][^\]\n]{0,200})?\][$#] |[\w.-]+@[\w.-]+[ \t]\S{1,200}[ \t][%$#] |[a-z]+-\d+(?:\.\d+)*[$#] |[~/][\w./~-]{0,200}[ \t]#[ \t])|In \[\d*\]:[ \t]*!|PS(?: [^>\n]{0,200})?> |[A-Za-z]:\\[^<>|"\n]{0,200}>|!(?=[a-z]))[ \t]*(\S[^\n]{0,2000})/;

/** Words before a simple command's own (`!` negates it); `then`, `do`, `else` open a group's commands. */
const RESERVED = new Set(["!", "if", "then", "else", "elif", "do", "while", "until"]);

/**
 * Commands that run the command after them: the options of theirs that take a value (letters, getopt's way:
 * `sudo -iu app` and `-uapp`; and long options), and how many operands come before the command (`timeout`'s duration).
 */
const WRAPPERS = new Map<string, { values?: string; long?: RegExp; operands?: number }>([
	[
		"sudo",
		{ values: "ugCDhprtTUR", long: /^--(?:user|group|chdir|host|prompt|role|type|close-from|other-user|chroot)$/ },
	],
	["doas", { values: "uC" }],
	// (`runuser -u app cmd`; with no `-u` it is su's twin, `runuser -l app -c 'cmd'`, and its `-l` is `--login`.)
	["runuser", { values: "ug", long: /^--(?:user|group)$/ }],
	["env", { values: "uCS", long: /^--(?:unset|chdir|split-string)$/ }],
	["timeout", { values: "sk", long: /^--(?:signal|kill-after)$/, operands: 1 }],
	["nice", { values: "n", long: /^--adjustment$/ }],
	["ionice", { values: "cnp" }],
	["stdbuf", { values: "ioe" }],
	[
		"xargs",
		{ values: "InPLdEsa", long: /^--(?:replace|max-args|max-procs|max-lines|delimiter|eof|max-chars|arg-file)$/ },
	],
	["exec", { values: "a" }],
	["watch", { values: "n", long: /^--interval$/ }],
	["time", { values: "fo", long: /^--(?:format|output)$/ }],
	["nohup", {}],
	["command", {}],
	["builtin", {}],
	["unbuffer", {}],
	["caffeinate", {}],
	["chronic", {}],
]);

/** Whether a word names a wrapper, a command that runs the command after it. */
export function isWrapper(word: string): boolean {
	return WRAPPERS.has(word);
}

/**
 * A program's name without its directory and Windows' `.exe`: `/usr/bin/grep` → `grep`, `.\\steamcmd.exe` → `steamcmd`.
 * PowerShell's and cmd's commands in the case the readers know them by, as both shells take any case (`get-content`,
 * `TYPE`, `Select-string`).
 */
export function programName(word: ShellWord | undefined): string {
	const name = (word?.text ?? "").replace(/^.*[/\\]/, "").replace(/\.exe$/i, "");
	return WINDOWS_COMMANDS.get(name.toLowerCase()) ?? name;
}

/** PowerShell's cmdlets and aliases and cmd's builtins that the readers name, by their names in lower case. */
const WINDOWS_COMMANDS = new Map(
	[
		"Get-Content",
		"Select-String",
		"Write-Output",
		"Write-Host",
		"Get-Item",
		"Get-ChildItem",
		"Get-Secret",
		"gc",
		"sls",
		"gci",
		"gi",
		"type",
		"findstr",
		"pwsh",
		"powershell",
		"cmd",
	].map((name) => [name.toLowerCase(), name]),
);

/**
 * A simple command's words from the program it runs: past assignments (`FOO=1`), reserved words (`!`, `then`, `do`)
 * and wrappers with their options and operands (`sudo -iu app`, `env -i`, `timeout 5`, `nice -n 10`, `xargs -I{}`).
 * A wrapper that runs nothing (`env -0`, `sudo -l`) is the program itself.
 */
export function simpleCommand(words: ShellWord[]): ShellWord[] {
	let k = 0;
	for (;;) {
		while (
			k < words.length &&
			((RESERVED.has(words[k].text) && !words[k].quoted) || /^[A-Za-z_]\w*=/.test(words[k].text))
		)
			k++;
		const wrapper = WRAPPERS.get(programName(words[k]));
		if (!wrapper) return words.slice(k);
		const at = k++;
		for (; k < words.length && words[k].text.startsWith("-"); k++) {
			const w = words[k].text;
			if (w === "--") {
				k++;
				break;
			}
			if (w.startsWith("--")) {
				if (!w.includes("=") && wrapper.long?.test(w)) k++;
				continue;
			}
			// (In a cluster, the first letter that takes a value takes the rest of the word, or the next word.)
			const takes = [...w.slice(1)].findIndex((letter) => wrapper.values?.includes(letter));
			if (takes >= 0 && takes === w.length - 2) k++;
		}
		k += wrapper.operands ?? 0;
		if (k >= words.length) return words.slice(at);
	}
}
