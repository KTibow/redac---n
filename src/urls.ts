/**
 * URLs read into their parts, each with where it is: user and password, host, path segments; and the query
 * parameters (`?name=value&…`) anywhere in a text, in a URL or a form body. One definition of where a URL and a
 * parameter's value end, for every rule that reads them.
 */
import { lastText, lowerBound } from "./lines.ts";
import { MAX_VALUE, type Span, withoutUnopenedClosers } from "./syntax.ts";

export interface Url {
	start: number;
	end: number;
	/** `https`, `postgres`, …; "" for a path (`/reset/<token>`). */
	scheme: string;
	user?: Span;
	password?: Span;
	host?: Span;
	/** The path's segments, without the slashes. */
	segments: Span[];
}

/**
 * A URL's scheme, as a regex source for use inside other patterns: `https`, `postgres`, `mongodb+srv`, SQLAlchemy's
 * dialect and driver (`redshift+redshift_connector`, `oracle+cx_oracle`, whose drivers' names hold `_`). Two characters
 * at least: a drive letter (`C://Users`) is none.
 */
const SCHEME_LENGTH = 41;
export const URL_SCHEME = String.raw`[A-Za-z][\w+.-]{1,${SCHEME_LENGTH - 1}}`;

/** A scheme and its `://` that starts a text. */
const SCHEME = new RegExp(String.raw`^${URL_SCHEME}:\/\/`);

/** A scheme, its `://` and the user information after it, to its first `/` or `@`. */
const USERINFO = new RegExp(String.raw`${URL_SCHEME}:\/\/[^\s/@]*`, "y");

/**
 * Where a URL that starts at `at` ends: at a blank, a quote, an angle bracket, a backtick, a backslash (a JSON
 * string's escaped quote), or a closing bracket it didn't open (a Markdown link's `)`); sentence punctuation at its
 * end isn't part of it (`…/reset/<token>.`). A password's brackets are (`app:p)dgbs@db`, `admin:<Harbor2291x>@host`).
 * However long the password: each look-ahead for its `@` is remembered to where it stopped (`reachesAt`). With `enough`,
 * it stops once it has read past that point (the answer is then only known to be past it): urlAround asks whether a
 * URL reaches a position, and a line with no blank in it (a comma-separated list of hosts) reads, as one URL, to its end.
 */
export function urlEnd(text: string, at: number, enough = Infinity): number {
	const open = { ")": 0, "]": 0 };
	const closerIsPassword = reachesAt(text, /[^\s"'<>`\\/@]*(@)?/y);
	const quoteIsPassword = reachesAt(text, /[^\s"<>`\\/@,;]*(@)?/y);
	// A quote is a password's only in `scheme://user:password` (no `/` or `@` yet), not after a port (`host:5432'`).
	USERINFO.lastIndex = at;
	const userinfoEnd = USERINFO.exec(text) ? USERINFO.lastIndex : -1;
	const colon = userinfoEnd < 0 ? -1 : text.indexOf(":", text.indexOf("://", at) + 3);
	const bracketed = /<[^\s<>@"'`]+>@/y;
	let end = at;
	for (; end < text.length && end - at < MAX_VALUE; end++) {
		// (Sentence punctuation read last could still be trimmed off below.)
		if (end > enough && !/[.,;:!?]/.test(text[end - 1])) return end;
		const c = text[end];
		if (c === "(") open[")"]++;
		else if (c === "[") open["]"]++;
		else if (c === ")" || c === "]") {
			// (Before the `@` that ends a user and password, it's the password's: `postgres://app:p)dgbs@db`.)
			if (open[c] === 0 && !closerIsPassword(end + 1)) break;
			open[c] = Math.max(0, open[c] - 1);
		} else if (c === "<" && text[end - 1] === ":") {
			bracketed.lastIndex = end;
			if (!bracketed.test(text)) break;
			end = bracketed.lastIndex - 1;
		} else if (
			/["'<>`\\]/.test(c) &&
			quoteIsPassword(end + 1) &&
			colon >= 0 &&
			colon < end &&
			end <= userinfoEnd &&
			!endsInPort(text, end)
		) {
			// (In a password, before the `@` that ends it: `postgres://app:Kx9m'Qv2@db`, `postgres://app:Kx9m"Qv2@db`,
			// `postgres://app:Qv2>Kx9m@db`; a JSON string's escape too, `app:Kx9m\u0026Qv2@db`.)
		} else if (/[\s"'<>`\\]/.test(c)) break;
	}
	while (end > at && /[.,;:!?]/.test(text[end - 1])) end--;
	return end;
}

/**
 * Whether the characters from `from` on, up to the first one `stop` doesn't take, are followed by an `@` (`stop` is a
 * sticky pattern with the `@` as its one group). The answer holds for every `from` up to where that run stopped, so a
 * URL of many brackets looks ahead once per run, not once per bracket.
 */
function reachesAt(text: string, stop: RegExp): (from: number) => boolean {
	let runEnd = -1;
	let found = false;
	return (from) => {
		if (from > runEnd) {
			stop.lastIndex = from;
			found = stop.exec(text)![1] !== undefined;
			runEnd = stop.lastIndex - (found ? 1 : 0);
		}
		return found;
	};
}

/** Whether the text before `end` ends in a port (`:5432`, digits after a colon). */
function endsInPort(text: string, end: number): boolean {
	let digits = end;
	while (digits > 0 && text[digits - 1] >= "0" && text[digits - 1] <= "9") digits--;
	return digits < end && text[digits - 1] === ":";
}

/** Whether `value` starts with a URL with a scheme. */
export const isUrl = (value: string) => SCHEME.test(value);

/** The URL with a scheme that `value` starts with, read to where urlEnd ends it; undefined if it starts with none. */
export function leadingUrl(value: string): Url | undefined {
	return isUrl(value) ? parseUrl(value, 0, urlEnd(value, 0)) : undefined;
}

/** Whether `value` is, whole, one URL with a scheme and no password: an endpoint, a setting. */
export function isPasswordlessUrl(value: string): boolean {
	const url = leadingUrl(value);
	return !!url && url.end === value.length && !url.password;
}

/** The URLs in `text` with a scheme (`https://…`, `postgres://…`), and with `paths`, paths that start with a segment and a slash (`/reset/<token>`). */
export function* urls(text: string, { paths = false } = {}): Generator<Url> {
	const start = paths
		? new RegExp(String.raw`\b${URL_SCHEME}:\/\/|(?<![\w.:/])\/[\w.-]{1,80}\/`, "g")
		: new RegExp(String.raw`\b${URL_SCHEME}:\/\/`, "g");
	// (exec, not matchAll, which iterates a copy: the next URL is looked for after this one ends.)
	for (let m = start.exec(text); m; m = start.exec(text)) {
		const end = urlEnd(text, m.index);
		yield parseUrl(text, m.index, end);
		start.lastIndex = Math.max(start.lastIndex, end);
	}
}

/** Where each `://` of a text is, in order: found once a text, so the URL around a position is a binary search away. */
const schemeSeparators = lastText((text) => {
	const out: number[] = [];
	for (let i = text.indexOf("://"); i >= 0; i = text.indexOf("://", i + 1)) out.push(i);
	return out;
});

/** A scheme that ends a text, as a whole word. */
const SCHEME_BEFORE = new RegExp(String.raw`(?<![\w+.-])${URL_SCHEME}$`);

/**
 * Where the URL with a scheme that holds `text[at, end)` starts, looking back no further than `from`; -1 if that
 * stretch isn't inside one. (The innermost: `?next=https://…/<token>` is inside the `next` URL.)
 */
export function urlAround(text: string, at: number, end = at, from = Math.max(0, at - 4096)): number {
	// (A stretch may start at the `//` itself: `https:` then `//<host>`.)
	const seps = schemeSeparators(text);
	const sep = seps[lowerBound(seps, at) - 1] ?? -1;
	if (sep < from) return -1;
	// (A scheme's characters and the one before it.)
	const scheme = SCHEME_BEFORE.exec(text.slice(Math.max(from, sep - SCHEME_LENGTH - 1), sep));
	if (!scheme) return -1;
	const start = sep - scheme[0].length;
	return urlEnd(text, start, end) >= end ? start : -1;
}

/**
 * A URL's parts. The authority's user information, as clients read it: a user with no `/?#@:` (or an email address
 * before a `:`, `writer@proj.iam.gserviceaccount.com:pw@host`), then `@`, or `:` and a password that runs to the first
 * `@` whose host runs to a `/`, `?`, `#` or the end with no other `@`, so a generated password may hold `@` and `/`
 * (`app:Xk9/mQ@2pL@host`). An `@` in the path or the query (`?email=bob@example.com`, `react@18.3.1`) is not a user's.
 */
function parseUrl(text: string, start: number, end: number): Url {
	const url = text.slice(start, end);
	// (A scheme starts the URL: a path's `?next=https://…` is its query's.)
	const sep = isUrl(url) ? url.indexOf("://") : -1;
	const scheme = sep > 0 ? url.slice(0, sep) : "";
	let at = sep > 0 ? sep + 3 : 0;
	const span = (from: number, to: number): Span => ({
		value: url.slice(from, to),
		start: start + from,
		end: start + to,
	});
	const out: Url = { start, end, scheme, segments: [] };
	if (scheme) {
		const userinfo = readUserinfo(url, at);
		if (userinfo) {
			out.user = span(at, userinfo.userEnd);
			if (userinfo.passwordStart >= 0) out.password = span(userinfo.passwordStart, userinfo.end);
			at = userinfo.end + 1;
		}
		const hostEnd = url.slice(at).search(/[/?#]|$/) + at;
		out.host = span(at, hostEnd);
		at = hostEnd;
	}
	const pathEnd = url.slice(at).search(/[?#]|$/) + at;
	for (let s = at; s < pathEnd;) {
		const slash = url.indexOf("/", s + 1);
		const segEnd = slash < 0 || slash > pathEnd ? pathEnd : slash;
		if (url[s] === "/") s++;
		if (segEnd > s) out.segments.push(span(s, segEnd));
		s = segEnd;
	}
	return out;
}

/**
 * The user information starting at `at` in `url` (after `scheme://`, or a DSN's start): where the user ends, where the
 * password starts (-1 for none), and where the `@` that ends it is; undefined if there is none. The password may hold
 * `/`, `@`, `?` and `#` (`Sparrow2024?`, `Vq8#Lm2!`), but not a blank, nor a `?` or `#` after a `/` (that's a path's
 * query: `host:443/docs?contact=ops@x`), nor a port and a path (`localhost:4873/@babel/core`); it ends at the first `@` whose host reaches `hostEnd` with no other `@`. An
 * IPv6 host (`[::1]`) has none.
 */
export function readUserinfo(
	url: string,
	at: number,
	hostEnd = /[/?#]/,
): { userEnd: number; passwordStart: number; end: number } | undefined {
	if (url[at] === "[") return undefined;
	// A service account's email as the user, if a password follows it.
	const email = /^[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,8}(?=:)/.exec(url.slice(at, at + 200));
	const withEmail = email && password(url, at, at + email[0].length, hostEnd);
	if (withEmail) return withEmail;
	const userEnd = at + url.slice(at).search(/[/?#@:\s]|$/);
	return url[userEnd] === "@" ? { userEnd, passwordStart: -1, end: userEnd } : password(url, at, userEnd, hostEnd);
}

/** A `:` at `userEnd` and the password after it, to its `@`. */
function password(url: string, userStart: number, userEnd: number, hostEnd: RegExp) {
	// (`host:5432/path@ref`: a port, not a password.)
	if (url[userEnd] !== ":" || /^\d{1,5}(?:[/?#]|$)/.test(url.slice(userEnd + 1, userEnd + 8))) return undefined;
	let a = -1;
	let slash = false;
	for (let i = userEnd + 1; i < url.length && !/\s/.test(url[i]!) && !(slash && a < 0 && /[?#]/.test(url[i]!)); i++) {
		if (url[i] === "/" && a < 0) slash = true;
		if (url[i] === "@") a = i;
		// The host after the last `@` ended with no `@` in it.
		else if (a >= 0 && hostEnd.test(url[i]!)) break;
	}
	if (a < 0) return undefined;
	// `git.example.com:org/repo@v1.2`: a host, a path and a ref (no host after the `@`), not a user and a password.
	const after = url.slice(a + 1).split(/[/?#]/)[0];
	if (slash && /^[\w-]+(?:\.[\w-]+)+$/.test(url.slice(userStart, userEnd)) && !isHost(after)) return undefined;
	return { userEnd, passwordStart: userEnd + 1, end: a };
}

/** A host as a URL names one: a domain with a TLD (`db.internal`, `example.com`), an IPv4 address, a name and a port. */
const isHost = (h: string) =>
	/^(?:[\w-]+\.)+[A-Za-z][\w-]*(?::\d{1,5})?$|^\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?$|^[\w-]+:\d{1,5}$/.test(h);

export interface Param {
	name: string;
	value: Span;
}

/**
 * A parameter's start and name: after `?`, `&` (or HTML's `&amp;`, or the `\u0026` and `\x26` that JSON encoders and JS
 * write for it: Go's encoding/json escapes every `&`) or `#`, a name with PHP's `[]` allowed.
 */
export const PARAM_START = String.raw`(?:&amp;|\\u0026|\\x26|[?&#])`;
export const PARAM_NAME = String.raw`[\w.\[\]-]{1,60}`;

/**
 * The `name=value` pairs in `text`: a URL's query and fragment (`#access_token=…`), a form body. A value ends at `&`,
 * `#`, a blank, a quote, an angle bracket, a backtick or a backslash (JSON's `&` escape); closing parentheses it didn't
 * open end it only at its end (`(see https://x.io/?k=abc)` is `abc`; a Markdown link's): `?key=Xk9(mP2)vQ7` is one value.
 */
export function* queryParams(text: string, names = PARAM_NAME): Generator<Param> {
	for (const m of text.matchAll(new RegExp(String.raw`${PARAM_START}(${names})=([^&#\s"'<>\`\\]+)`, "dgi"))) {
		const value = withoutUnopenedClosers(m[2], ")");
		if (!value) continue;
		const start = m.indices![2]![0];
		yield { name: m[1], value: { value, start, end: start + value.length } };
	}
}

const UTF8 = new TextEncoder();

/**
 * A run of what percent-encoding leaves as it is and `%XX` escapes, matched whole (each run once: linear), and kept
 * when it holds an escape: an encoded URL, query or JSON.
 */
const PERCENT_RUN = /(?:[A-Za-z0-9_.~+-]|%[0-9A-Fa-f]{2})+/g;

/**
 * The percent-encoded text in `text` that encodes text of its own (a URL in `redirect=`, JSON in a query, a sentence,
 * in a log): each run decoded, `+` as a blank as forms write one, with the position in `text` of each decoded
 * character (and one past the last). A run that encodes a single token is the random layer's (unnamed.ts
 * `candidates`); one that isn't UTF-8 is left alone.
 */
export function* percentEncoded(text: string): Generator<{ decoded: string; map: number[] }> {
	if (!text.includes("%")) return;
	const utf8 = new TextDecoder("utf-8", { fatal: true });
	for (const m of text.matchAll(PERCENT_RUN)) {
		const run = m[0];
		if (!run.includes("%")) continue;
		let decoded = "";
		const map: number[] = [];
		let ok = true;
		for (let i = 0; i < run.length && ok;) {
			if (run[i] !== "%") {
				decoded += run[i] === "+" ? " " : run[i];
				map.push(m.index + i++);
				continue;
			}
			// (A run of escapes is decoded as UTF-8 together, each character mapped to its first byte's escape.)
			const bytes: number[] = [];
			const at: number[] = [];
			while (run[i] === "%") {
				bytes.push(parseInt(run.slice(i + 1, i + 3), 16));
				at.push(m.index + i);
				i += 3;
			}
			let chars = "";
			try {
				chars = utf8.decode(new Uint8Array(bytes));
			} catch {
				ok = false;
			}
			let byte = 0;
			for (const c of chars) {
				decoded += c;
				for (let k = 0; k < c.length; k++) map.push(at[byte]);
				byte += UTF8.encode(c).length;
			}
		}
		// (Text of its own: a URL, a path, pairs, JSON, words. A token with a `:`, a `/` or base64's padding in it is a
		// token: `<id>:<time>`, `+TGFu…3M=`.)
		if (!ok || decoded.length < 12 || !/[?&{"@ ]|:\/\/|^\/\w|=(?!=*$)/.test(decoded)) continue;
		map.push(m.index + run.length);
		yield { decoded, map };
	}
}
