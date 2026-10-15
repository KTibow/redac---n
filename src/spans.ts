/**
 * Spans of findings: merging overlapping ones, keeping them off escape sequences, extending a token a terminal
 * wrapped, and what a finding's value is.
 */
import { lastText, lineEnd, lineStart, lowerBound } from "./lines.ts";
import { naturalness } from "./charlm.ts";
import type { Finding } from "./types.ts";
import { backslashesBefore, escapeLength, UNQUOTED_READ } from "./syntax.ts";
import { leadingUrl } from "./urls.ts";
import { isPath } from "./values.ts";
import { isReplaceable } from "./known.ts";
import { namesLogin } from "./names.ts";
import { continuesAcrossWraps, isGuess, isWholeLine, layerOf, PLACEHOLDER_RULE } from "./rules.ts";

/** An Amazon Resource Name: `arn:aws:iam::483920176654:role/deploy`, in any partition. */
const ARN = /^arn:[a-z][a-z0-9-]*:[a-z0-9-]+:[a-z0-9-]*:\d*:[\w:/.@+=,*-]+$/;
/** A host name: dotted lowercase labels ending in a TLD, with a port maybe (`db-main.cluster-cx8k2.us-west-2.rds.amazonaws.com:5432`). */
const HOST_NAME = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?::\d{1,5})?$/;
/** A URL path segment this long may be a generated token (a webhook's), not a name. */
const TOKEN_SEGMENT = 20;

/**
 * Whether a value is never a secret by its shape alone: an ARN, a host name, a file path, a URL with no password (an
 * http(s) one only when it has no query and no segment long enough for a webhook's token). Learning one would hide it
 * everywhere after, and a text that says `API_TOKEN=<an ARN>` can be written by anyone the tool output comes from.
 * (Hex stays learnable: real keys are hex, and a commit SHA taught as one is over-redaction only.)
 */
export function isNeverSecretShape(value: string): boolean {
	if (ARN.test(value) || HOST_NAME.test(value) || isPath(value)) return true;
	const url = leadingUrl(value);
	if (!url || url.end !== value.length || url.password) return false;
	return (
		!/^https?$/i.test(url.scheme) || (!/[?#]/.test(value) && url.segments.every((s) => s.end - s.start < TOKEN_SEGMENT))
	);
}

/**
 * The password of a finding that is a login: a username and a password in one value, `user:password` or
 * `user/password`, under a name that says it holds one (names.ts namesLogin: `NEO4J_AUTH=neo4j/…`, Bundler's
 * `BUNDLE_<HOST>: "user:…"`). Learned and repeated on its own too, as a client takes it (`cypher-shell -u neo4j -p
 * <it>`). Not a `:` or `/` inside another secret (a signature's `abc:<id>`), nor a URL's (its password is read in the
 * URL); before a `/`, only a user's lower-case name (`neo4j/…`, not a base64 key's `wJalrXUtnFEMI/K7MDENG…`).
 */
export function loginPassword(f: Finding, value: string): string | undefined {
	if (!f.name || !namesLogin(f.name) || value.includes("://")) return undefined;
	const pair = /^(?:[\w.@+-]{1,64}:|[a-z][a-z0-9._-]{0,31}\/)([^\s/:]\S*)$/.exec(value);
	return pair && isReplaceable(pair[1]) ? pair[1] : undefined;
}

/**
 * Whether a finding is sure enough, and long enough, to be learned as a known value and hidden wherever it appears: one
 * a rule read by a name, a format, a structure or a file, not the unnamed layer's guess about one place; and whose
 * `value` (secretValue) isn't of a shape no secret has (isNeverSecretShape).
 */
export function isLearnable(f: Finding, value: string, minConfidence = 0.9): boolean {
	return (
		f.confidence >= minConfidence &&
		f.end - f.start >= 8 &&
		!isGuess(f.rule) &&
		f.rule !== PLACEHOLDER_RULE &&
		!isNeverSecretShape(value)
	);
}

/**
 * The secret a finding covers, as the program reads it, so one secret written two ways gets one tag and is learned
 * once: its recorded value (a known value whichever way it was written, a literal split in pieces joined, a JSON
 * escape decoded); or the text it spans, read through a URL's percent-encoding (a userinfo's `Harbor2291%21x`, a
 * query's `%26`, `+` a blank), a double-quoted string's escapes (`"Ab\"cd9"`, `\u0041`), or a shell's backslashes
 * outside quotes (`Harbor2291\!x`). (Not a single-quoted string's: a shell's has no escapes, a SQL one doubles its
 * quote, and `'a''b'` is `ab` to a shell.)
 */
export function secretValue(text: string, f: { start: number; end: number; value?: string }): string {
	if (f.value !== undefined) return f.value;
	const raw = text.slice(f.start, f.end);
	const before = text.slice(Math.max(0, f.start - 200), f.start);
	if (/%[0-9A-Fa-f]{2}/.test(raw)) {
		const query = /[?&][\w.[\]-]{1,60}=$/.test(before);
		if (query || /:\/\/[^\s/@]*$/.test(before)) {
			try {
				return decodeURIComponent(query ? raw.replace(/\+/g, " ") : raw);
			} catch {} // an escape that isn't UTF-8: the text as it is
		}
	}
	if (raw.includes("\\") && /"$/.test(before)) {
		try {
			return JSON.parse(`"${raw}"`);
		} catch {} // not JSON's escapes: the text as it is
	}
	if (/\\[^\w\s]/.test(raw) && !/["'`]$/.test(before)) return raw.replace(/\\([^\w\s])/g, "$1");
	return raw;
}

/** The escape sequence covering position `i` (after its backslash), as [backslash, end), if `i` is inside one. */
function escapeAt(text: string, i: number): [number, number] | undefined {
	for (let b = i - 1; b >= Math.max(0, i - 6); b--) {
		if (text[b] !== "\\" || backslashesBefore(text, b) % 2) continue;
		const end = b + escapeLength(text, b);
		return end > i ? [b, end] : undefined;
	}
	return undefined;
}

/** An escape spelling a letter or a digit: `\x63`, `\u0063`. */
const SPELLED_CHAR = /\\(?:x|u00)(?:3[0-9]|[46][1-9a-fA-F]|[57][0-9aA])/y;
/** How many of them a token goes on through. */
const MAX_SPELLED = 64;

/**
 * A span kept off escape sequences, so replacing it never breaks an escape or, inside JSON, the document. One that
 * starts or ends inside an escape (`\n<token>`, `<token>\`, `\u0020`) was read through it by mistake, and leaves it
 * out. In text encoded twice, `\\n` is the next level's escape, or an escaped backslash and a letter of the
 * secret (`C:\\nKx82…`): there is no telling, so a span right after an escaped backslash takes the pair in, and an
 * error over-redacts rather than leaks.
 */
function onEscapes(text: string, f: Finding): Finding {
	let { start, end } = f;
	const s = escapeAt(text, start);
	if (s) start = Math.min(end, s[1]);
	else if (
		text[start - 1] === "\\" &&
		text[start - 2] === "\\" &&
		!escapeAt(text, start - 2) &&
		/[nrtbfu"/]/.test(text[start] ?? "")
	)
		start -= 2;
	const e = escapeAt(text, end);
	if (e) end = Math.max(start, e[0]);
	// A token goes on through an escape that spells one of its characters (`…zdp7d\x63` in a shell's `$'…'`).
	for (let n = 0; n < MAX_SPELLED && end > start && /[\w-]/.test(text[end - 1]); n++) {
		SPELLED_CHAR.lastIndex = end;
		if (backslashesBefore(text, end) % 2 || !SPELLED_CHAR.test(text)) break;
		end = SPELLED_CHAR.lastIndex;
	}
	return start === f.start && end === f.end ? f : { ...f, start, end, value: undefined };
}

/**
 * A whole line taken as a secret (a one-line secret file, a command's printed line) that holds a confident
 * finding of another rule (`export TOKEN="ghp_…"`, a URL with a token) gives way to it: the name and URL stay, and the
 * placeholder's tag is the secret's own, the same as wherever else it appears.
 */
function preferNarrower(findings: Finding[]): Finding[] {
	if (!findings.some((f) => isWholeLine(f.rule))) return findings;
	const narrow = findings
		.filter((f) => !isWholeLine(f.rule) && f.confidence >= 0.9 && !isGuess(f.rule) && layerOf(f.rule) !== "repeat")
		.sort((a, b) => a.start - b.start);
	const starts = narrow.map((f) => f.start);
	return findings.filter((w) => {
		if (!isWholeLine(w.rule)) return true;
		// (The narrow findings starting inside the line, by binary search; one that ends inside it too. One that is the
		// whole line names it better: `cat .vault_pass` printing a GitHub token.)
		for (let i = lowerBound(starts, w.start); i < narrow.length && narrow[i].start < w.end; i++) {
			if (narrow[i].end <= w.end) return false;
		}
		return true;
	});
}

/**
 * A token's character, where a format that stops before it may have been cut and its tail is still secret: a
 * percent-encoded one too (a session token's `%2B` in a URL); a dot only inside a token (`hvs.…`), not a sentence's
 * full stop.
 */
const TOKEN_CHAR = /^(?:[\w+/=~-]|\.\w|%[0-9A-Fa-f])/;

/**
 * Whether `f`, starting with or inside a format's token `token`, runs past it only by reading on into what follows it
 * (`ghp_…;git push`, `ghp_…&q=foo`, `ghp_…#top`): an unquoted value read to the next blank. The format's regex bounds
 * the token, so the rest is the text after it, not more of the secret. (A finding that starts before the token, a
 * quote or a prefix, or a token that stops before a token character, may have been cut: those widen.)
 */
function runsPastToken(text: string | undefined, token: Finding, f: Finding): boolean {
	return (
		text !== undefined &&
		layerOf(token.rule) === "format" &&
		token.confidence > f.confidence &&
		f.start >= token.start &&
		f.end > token.end &&
		!TOKEN_CHAR.test(text.slice(token.end, token.end + 3))
	);
}

/** Overlapping findings as one span each, every field but the span the most confident one's. */
function union(findings: Finding[], text?: string): Finding[] {
	const sorted = [...findings].sort((a, b) => a.start - b.start || b.end - a.end);
	const out: Finding[] = [];
	for (const f of sorted) {
		if (f.end <= f.start) continue;
		const last = out.at(-1);
		if (!last || f.start >= last.end) {
			out.push({ ...f });
			continue;
		}
		if (runsPastToken(text, last, f)) continue;
		if (runsPastToken(text, f, last) && f.start === last.start) {
			out[out.length - 1] = { ...f };
			continue;
		}
		const end = Math.max(last.end, f.end);
		const winner = f.confidence > last.confidence ? f : last;
		// (A value goes with its own span only: `last` may start earlier or `f` end later than the winner.)
		const widened = last.start !== winner.start || end !== winner.end;
		out[out.length - 1] = { ...winner, start: last.start, end, value: widened ? undefined : winner.value };
	}
	return out;
}

/** A character that may go on a value cut short: not a blank or a quote. */
const VALUE_CHAR = /[^\s"'`]/;

/**
 * How long a finding is that a read bound may have cut: half of UNQUOTED_READ, as a reader's bound counts from where it
 * started reading (a command's first word, a line's start), not from the value.
 */
const MAY_BE_CUT = UNQUOTED_READ / 2;

/**
 * A finding that may have been cut by a read bound (MAY_BE_CUT) and stops inside a word runs to the word's end, a blank
 * or a quote: a longer secret must not leave its tail. A shorter one ends where its reader meant it to (a URL's
 * password at its `@`). (A finding whose recorded value differs from its span, decoded or joined, is left as it is.)
 */
export function toWordEnd(text: string, f: Finding): Finding {
	if (f.end - f.start < MAY_BE_CUT || f.value !== undefined || !VALUE_CHAR.test(text[f.end - 1])) return f;
	const end = wordEnds(text)[f.end];
	return end === f.end ? f : { ...f, end };
}

/**
 * For each position of a text, where the word (of VALUE_CHAR) it is in ends, an escape (`\n`, `\"`) ending one: built
 * once a text, so many findings in one long word cost one scan.
 */
const wordEnds = lastText((text) => {
	const ends = new Int32Array(text.length + 1);
	ends[text.length] = text.length;
	for (let i = text.length - 1; i >= 0; i--)
		ends[i] = VALUE_CHAR.test(text[i]) && !(text[i] === "\\" && /[nrt"]/.test(text[i + 1] ?? "")) ? ends[i + 1] : i;
	return ends;
});

/**
 * A finding trimmed to its value, of what is syntax beyond doubt: blanks, an `=` or `:` with a blank or a quote after it,
 * and a pair of quotes around the value (`= "CANYxh7686!"`); a comma or a semicolon before the next `name=` of a list
 * (`passwort=COBAlyrxgo%, knownHosts=…`). A password's own first or last character (`:Kx9…`, `Kx9…)`, `Kx9…;`) stays.
 * A placeholder then replaces the value only, so the syntax around it stays; and the value is what's fingerprinted and
 * learned. (A finding that records its value, decoded or joined, is that value already.)
 */
export function trimmedToValue(text: string, f: Finding): Finding {
	if (f.value !== undefined) return f;
	let { start, end } = f;
	const lead = /^[ \t]*(?:[=:](?:[ \t]+|(?=["'`])))?/.exec(text.slice(start, Math.min(end, start + 40)))![0].length;
	start += lead;
	const q = text[start];
	if (/["'`]/.test(q ?? "") && end - start > 2 && text[end - 1] === q && !text.slice(start + 1, end - 1).includes(q)) {
		start++;
		end--;
	}
	if (end - start > 1 && /[,;]/.test(text[end - 1]) && /^[ \t]+[A-Za-z_][\w.-]*=/.test(text.slice(end, end + 80)))
		end--;
	else if (layerOf(f.rule) === "named" && !/["'`]/.test(q ?? "")) end = start + nextSetting(text.slice(start, end));
	return start === f.start && end === f.end ? f : { ...f, start, end };
}

/**
 * Settings that end an unquoted value read to the next blank: `;`, `,` or `&`, a name of a word's shape (lower case,
 * upper case or camel case, at least two letters), `=` and a plain value, to the end (`;username=bob`,
 * `,DB_HOST=db,DB_PORT=5432`, `&page=2&sort=desc`). A password's own punctuation seldom reads that way to its end
 * (`86)68/C{,C=wyhJH9`, `Nakp&nDiqWJ-K=nW`).
 */
const SETTINGS_AFTER =
	/[;,&](?=[\w.-]*[A-Za-z][\w.-]*[A-Za-z])(?:[a-z][a-z0-9]*(?:[_.-][a-z0-9]+)*|[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*|[a-z]+(?:[A-Z][a-z0-9]+)+)=[\w.:/@+-]*(?=[;,&]|$)/y;

/**
 * Where an unquoted value read to the next blank ends at the settings after it of a list it is in, with no blank
 * between (`password=Kx9…;username=bob`, `A=…,B=db`): the value's length up to there, or all of it. Not in a value that
 * is itself a list of settings or a URL (an `=` or `?` before), whose own separators these are (`DSN=host=db;password=…`),
 * and not after a value too short to be one.
 */
function nextSetting(value: string): number {
	const list = value.search(/=+[^=;,&]|\?|:\/\//);
	const separators = /[;,&]/g;
	for (let m; (m = separators.exec(value)) && (list < 0 || m.index < list);) {
		if (m.index < 6) continue;
		let at = m.index;
		SETTINGS_AFTER.lastIndex = at;
		while (at < value.length && SETTINGS_AFTER.test(value)) at = SETTINGS_AFTER.lastIndex;
		if (at === value.length) return m.index;
	}
	return value.length;
}

/** Findings merged into one span each, sorted; with `text`, kept off escape sequences. (The inputs aren't changed.) */
export function merge(findings: Finding[], text?: string): Finding[] {
	return union(preferNarrower(text ? findings.map((f) => onEscapes(text, f)) : findings), text);
}

/** The first of `sorted` (merged, sorted by start) that ends after `start`, by binary search. */
function firstEndingAfter(sorted: Finding[], start: number): number {
	let lo = 0;
	let hi = sorted.length;
	while (lo < hi) {
		const mid = (lo + hi) >> 1;
		if (sorted[mid].end <= start) lo = mid + 1;
		else hi = mid;
	}
	return lo;
}

/** Whether [start, end) lies inside one of `sorted` (merged, sorted by start). */
export function covered(sorted: Finding[], start: number, end: number): boolean {
	const f = sorted[firstEndingAfter(sorted, start)];
	return !!f && f.start <= start && f.end >= end;
}

/** Whether [start, end) overlaps one of `sorted` (merged, sorted by start). */
export function overlaps(sorted: Finding[], start: number, end: number): boolean {
	const f = sorted[firstEndingAfter(sorted, start)];
	return !!f && f.start < end;
}

/** Terminal widths output is commonly wrapped at. */
const WRAP_WIDTHS = new Set([64, 76, 79, 80, 100, 120, 132]);

/**
 * A token cut by a terminal or log viewer wrapping at a fixed width (`Authorization: Bearer eyJ…` at
 * column 80): a finding that ends exactly at the end of a line of a common wrap width continues on
 * the following lines while they are bare token characters, up to the first shorter line.
 */
export function wrapped(text: string, found: Finding[]): Finding[] {
	return found.map((f) => {
		if (!continuesAcrossWraps(f.rule)) return f;
		let end = f.end;
		const width = end - lineStart(text, end, 400);
		if (!WRAP_WIDTHS.has(width)) return f;
		for (let n = 0; n < 100 && (text[end] === "\n" || (text[end] === "\r" && text[end + 1] === "\n")); n++) {
			const from = end + (text[end] === "\r" ? 2 : 1);
			const to = lineEnd(text, from, width + 1);
			const line = text.slice(from, to).replace(/\r$/, "");
			if (
				line.length < 8 ||
				line.length > width ||
				!/^[A-Za-z0-9._~+/-]+={0,2}$/.test(line) ||
				!/\d/.test(line) ||
				!/[A-Za-z]/.test(line) ||
				naturalness(line) > 0.5
			)
				break;
			end = from + line.length;
			if (line.length < width) break;
		}
		return end === f.end ? f : { ...f, end };
	});
}
