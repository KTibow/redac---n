/**
 * PEM blocks (RFC 7468, with RFC 1421's headers) as text carries them: a BEGIN line; headers, then a blank line,
 * before the material; lines of base64; an END line. The lines may be escaped in a string (`\n`, `\\n`, `\r\n`), and
 * the string written a line at a time in source (`"…\n" +`, Python's `"…\n"` juxtaposed); carry a line number or a
 * grep path read off the BEGIN line; or have become blanks (`echo $KEY`). A block cut short ends with its material
 * (`head -3 cert.pem`); one whose BEGIN was cut off (`tail -5 server.key`) is read up from its END. Both readers take
 * each line once, so a scan of a text's blocks is linear.
 */
import { lastText, lineEnd, lineStart } from "./lines.ts";

/** Characters of base64 material. */
function isArmorChar(c: number): boolean {
	return (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || (c >= 48 && c <= 57) || c === 43 || c === 47 || c === 61;
}

/**
 * A BEGIN or END line, in PEM's armor (`-----BEGIN RSA PRIVATE KEY-----`) or RFC 4716's (`---- BEGIN SSH2 ENCRYPTED
 * PRIVATE KEY ----`, ssh.com's and PuTTYgen's export). Its label: capitals, or OpenVPN's `OpenVPN Static key V1`.
 */
const ARMOR = (word: string) => String.raw`-{4,5} ?${word} ([A-Za-z0-9][A-Za-z0-9 ]{0,59}?) ?-{4,5}`;
const END_LINE = new RegExp(ARMOR("END"), "y");
/** Where an END line may start. */
const END_START = /-{4,5} ?END /y;

/** The BEGIN lines of a text, each with its label, in order. */
export function* beginLines(text: string): Generator<{ start: number; end: number; label: string }> {
	for (const m of text.matchAll(new RegExp(ARMOR("BEGIN"), "g")))
		yield { start: m.index, end: m.index + m[0].length, label: m[1] };
}

/** An armored block as pemBody reads it: its BEGIN line (`start`, `labelEnd`), its label, and its body. */
export interface ArmoredBlock extends PemBody {
	start: number;
	labelEnd: number;
	label: string;
}

/**
 * Every armored block of a text, read once a text, in order. (A BEGIN line inside an earlier block's body is that
 * body's text, not a block of its own.)
 */
export const armoredBlocks = lastText((text: string): ArmoredBlock[] => {
	const out: ArmoredBlock[] = [];
	for (const begin of beginLines(text)) {
		if (out.length && begin.start < out[out.length - 1].end) continue;
		out.push({ start: begin.start, labelEnd: begin.end, label: begin.label, ...pemBody(text, begin.start, begin.end) });
	}
	return out;
});

/** Whether an END line starts at `at`. */
function endsAt(text: string, at: number): boolean {
	END_START.lastIndex = at;
	return END_START.test(text);
}

/**
 * The prefix every line of an output carries, read off one line's text before its armor: a line number (`cat -n`,
 * `nl`, an agent's Read tool `     1→`), a `grep -r` path (`key.pem:12:` on a match, `key.pem-13-` on context), a log's
 * timestamp, syslog header, level tag or compose service bar. Digit runs and blank runs vary from line to line; the
 * rest is the same on each. None when the armor starts its line.
 */
function linePrefix(before: string): RegExp | undefined {
	if (!before.trim()) return undefined;
	const grep = /^([\w./~-]{1,200}?)[:-](?:\d{1,7}[:-])?$/.exec(before);
	if (grep) return new RegExp(`${escape(grep[1])}[:-](?:\\d{1,7}[:-])?`, "y");
	return new RegExp(
		escape(before)
			.replace(/\d+/g, "\\d+")
			.replace(/[ \t]+/g, "[ \\t]+"),
		"y",
	);
}

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** What a block's body is: where it ends (its END line's end, or its last material's), and how much material it has. */
export interface PemBody {
	end: number;
	material: number;
}

/**
 * The body after a BEGIN line (`begin` its start, `from` its end): headers and a blank line before the material, then
 * material lines up to END. Anything else ends a block cut short, a blank line or a `Name: value` line after material
 * has begun among them (the HTTP headers after `head -3 cert.pem`).
 */
function pemBody(text: string, begin: number, from: number): PemBody {
	const prefix = linePrefix(text.slice(lineStart(text, begin, 300), begin));
	let i = from;
	let material = 0;
	let end = i;
	let lines = 0;
	let lastRun = 0;
	// (A line's width with the `+` that may start its material, which the leading markers' skip takes as a `+"` or a
	// diff's.)
	let lastWidth = 0;
	while (i < text.length && lines < 2000) {
		// A line break, real or escaped inside a string, after any trailing blanks.
		for (let n = 0; n < 40 && (text[i] === " " || text[i] === "\t"); n++) i++;
		const brk = breakAt(text, i);
		// A key whose line breaks became spaces (`echo $KEY`): material after a blank, right after BEGIN or after a
		// full line of material. One whose breaks were stripped (`-----BEGIN OPENSSH PRIVATE KEY-----b3Bl…`): its
		// material right after BEGIN, its END right after a full line of it.
		const blank = text[i - 1] === " " || text[i - 1] === "\t";
		const glued = (lines === 0 && isArmorChar(text.charCodeAt(i))) || (lastRun >= 40 && endsAt(text, i));
		if (
			!brk &&
			!glued &&
			!(blank && (endsAt(text, i) || ((lines === 0 || lastRun >= 40) && isArmorChar(text.charCodeAt(i)))))
		)
			break;
		let j = i + brk;
		lines++;
		if (prefix) {
			prefix.lastIndex = j;
			if (prefix.exec(text)) j = prefix.lastIndex;
		}
		// Leading indentation, quotes, comment markers, diff markers, `+"` concatenations.
		while (j < text.length && " \t\"'+#>|-".includes(text[j]) && j - (i + brk) < 40) {
			if (text[j] === "-" && text.startsWith("----", j)) break;
			if (text[j] === "+" && isArmorChar(text.charCodeAt(j + 1)) && !brk) break; // (material's own `+`, after a blank)
			j++;
		}
		if (endsAt(text, j)) {
			END_LINE.lastIndex = j;
			const e = END_LINE.exec(text);
			return { end: e ? j + e[0].length : end, material };
		}
		const lineFrom = j;
		let run = 0;
		if (material === 0 && /^[A-Za-z][A-Za-z0-9-]{0,40}: /.test(text.slice(lineFrom, lineFrom + 44))) {
			// Headers, before the material only: `Proc-Type: 4,ENCRYPTED`, `Version: GnuPG v2`, `Comment: …`.
			j = lineEnd(text, lineFrom, 300);
			// (A header ends at an escaped break too, in whichever form: `Comment: x\n`, `\\n`.)
			for (let k = lineFrom + 1; k < j; k++) {
				if (escapedBreakAt(text, k)) {
					j = k;
					break;
				}
			}
		} else {
			while (j < text.length && isArmorChar(text.charCodeAt(j))) j++;
			run = j - lineFrom;
			// (Base64 has `=` only as its padding, at the end: `password=Zq7m…` after a cut certificate, or on its BEGIN
			// line in a log, is a setting.)
			if (/=[^=]/.test(text.slice(lineFrom, j))) break;
			// (A blank line separates the headers from the material; once material has begun, it ends the block, unless
			// every line is followed by one, as by a tool that doubled the breaks: the next line is the next full line
			// of material, or the END line.)
			if (run === 0 && material > 0 && doubledBreak(text, j, lastWidth)) {
				i = j;
				continue;
			}
			if (run === 0 && (material > 0 || !breakAt(text, j))) break;
		}
		// The line's ending: blanks, a closing quote, a comma. (Not a `+`: before the line's break, breakAt reads it as an
		// operator, `"…" +⏎`; after a blank, it starts the next line's material in a key joined by blanks.)
		const runEnd = j;
		// (Not into the next string of a compact array of lines, whose `","` is the break.)
		while (j < text.length && " \t\"',;".includes(text[j]) && !(text[j] === '"' && breakAt(text, j) > 0)) j++;
		// A line of material is all armor: what follows is the line's end, the END line, or (in a key whose line breaks
		// became blanks) more material after a full run. A word that only starts like it (`hello world`) ends the block;
		// a full run that something else follows is the last material, cut where output was shortened (`…AB…`,
		// `…AB... [truncated]`).
		if (run > 0) {
			const lineEnds = j >= text.length || breakAt(text, j) > 0 || endsAt(text, j);
			// (Under four characters only as the material's last line, the END line next however the line ends, past the
			// prefix every line carries: `Q==`, `"Q==\n" +⏎    "-----END`, `Q== -----END`, `<timestamp> -----END`.)
			const lastLine = lineEnds && endLineNext(text, j, prefix);
			if (run < 4 && !lastLine) break;
			// (Past full lines, a shorter line is the block's only before its END line: a commit after
			// `head -n 4 server.key; git rev-parse HEAD` is the next command's. Read either way where a `+` starts the
			// line: material's own, or a diff's marker.)
			const width = run + (text[lineFrom - 1] === "+" ? 1 : 0);
			const shorter = Math.max(run, width) < Math.min(lastRun, lastWidth);
			if (lastRun >= 40 && shorter && lineEnds && !lastLine && !endLineAfterBlank(text, runEnd, prefix)) break;
			if (!(lineEnds || (run >= 40 && j > runEnd && isArmorChar(text.charCodeAt(j))))) {
				if (run >= 40) return { end: Math.max(end, lineFrom + run), material: material + run };
				break;
			}
			material += run;
		}
		lastRun = run;
		lastWidth = run + (run && text[lineFrom - 1] === "+" ? 1 : 0);
		end = Math.max(end, lineFrom + run);
		i = j;
	}
	return { end, material };
}

/**
 * Whether the empty line at `at` (after a line of material `width` long) is a doubled break: the line after it is
 * a full line of material (as wide as the one before), or a shorter last line or the END line, each after the same
 * kind of empty line.
 */
function doubledBreak(text: string, at: number, width: number): boolean {
	const brk = breakAt(text, at);
	if (width < 40 || !brk) return false;
	let j = at + brk;
	while (j < text.length && j - at < 40 && (text[j] === " " || text[j] === "\t")) j++;
	if (endsAt(text, j)) return true;
	let k = j;
	while (k < text.length && isArmorChar(text.charCodeAt(k))) k++;
	const run = k - j;
	if (run === 0 || !breakAt(text, k)) return false;
	return run >= width || (run >= 4 && endLineAfterBlank(text, k, undefined));
}

/** Whether an END line follows `at` on the next line, or past one empty line. */
function endLineAfterBlank(text: string, at: number, prefix: RegExp | undefined): boolean {
	if (endLineNext(text, at, prefix)) return true;
	const brk = breakAt(text, at);
	return brk > 0 && breakAt(text, at + brk) > 0 && endLineNext(text, at + brk, prefix);
}

/**
 * Whether an END line follows `at`, where a line's material ends: on the next line, past `prefix` and the quotes and
 * blanks pemBody skips, or on the same line.
 */
function endLineNext(text: string, at: number, prefix: RegExp | undefined): boolean {
	const brk = breakAt(text, at);
	let j = at + brk;
	if (brk && prefix) {
		prefix.lastIndex = j;
		if (prefix.exec(text)) j = prefix.lastIndex;
	}
	while (j < text.length && j - at < 40 && " \t\"'".includes(text[j])) j++;
	return text.startsWith("-----END ", j);
}

/**
 * The material above an END line at `end` whose BEGIN was cut off: the lines of base64 up from it, each with the
 * prefix and the endings pemBody reads (a line number, quotes, a `\n` escape), of any length (a key stored unwrapped),
 * up to the first line that isn't one; that line's own trailing material too, where the cut fell inside it (`out=…`,
 * `"private_key": "…`).
 */
export function pemTail(text: string, end: number): { start: number; material: number } {
	let start = end;
	let material = 0;
	let above = lineAbove(text, end);
	// (The END line's prefix is every line's: a log's timestamp, a line number.)
	const prefix = linePrefix(text.slice(above.start, end));
	for (let n = 0; n < 2000 && above.breakAt >= 0; n++) {
		const line = lineAbove(text, above.breakAt);
		let afterPrefix = line.start;
		if (prefix) {
			prefix.lastIndex = afterPrefix;
			if (prefix.exec(text) && prefix.lastIndex <= above.breakAt) afterPrefix = prefix.lastIndex;
		}
		let rawEnd = above.breakAt;
		while (rawEnd > afterPrefix && CONTINUATION.includes(text[rawEnd - 1])) rawEnd--;
		const raw = text.slice(afterPrefix, rawEnd);
		let from = raw.length;
		while (from > 0 && isArmorChar(raw.charCodeAt(from - 1))) from--;
		const head = raw.slice(0, from);
		const whole = /^[ \t]*(?:\d{1,7}(?:[\t→:|]|[ \t]{1,4}))?[ \t"'+#>|]*$/.test(head);
		if (raw.length - from < (whole ? 4 : 16)) break;
		material += raw.length - from;
		start = afterPrefix + from;
		if (!whole) break;
		above = line;
	}
	return { start, material };
}

/** Between a string's line and the source's own break after it: the string's closing quote, an operator, a comma. */
const CONTINUATION = ` \t"',;+`;

/**
 * The length of the line break at `i`, or 0: a real one, after what may end a string written a line at a time in
 * source (`"-----BEGIN PRIVATE KEY-----",⏎`, a key as an array of lines); or one escaped in a string (`\n`, `\r\n`,
 * `\\n`, `\r\n` escaped), together with that before the source's own break (`…\n" +⏎`, `…\n"⏎`).
 */
function breakAt(text: string, i: number): number {
	const escaped = escapedBreakAt(text, i);
	let j = i + escaped;
	while (j < text.length && j - i < 40 && CONTINUATION.includes(text[j])) j++;
	// (CRs before the LF: `\r\n`, and a terminal's `\r\r\n` from output captured through a pty, `docker exec -t`, `ssh -t`.)
	let k = j;
	while (k < text.length && k - j < 4 && text[k] === "\r") k++;
	if (text[k] === "\n") return k + 1 - i;
	// One line of a compact JSON array of lines (`["-----BEGIN …-----","MIIE…","…"]`): a quote, a comma, a quote.
	const item = /^"[ \t]*,[ \t]*"/.exec(text.slice(i + escaped, i + escaped + 24));
	return item ? escaped + item[0].length : escaped;
}

/** The length of an escaped line break at `i` (`\n`, `\\n`, `\r\n` escaped), or 0. */
function escapedBreakAt(text: string, i: number): number {
	if (text[i] !== "\\") return 0;
	if (text[i + 1] === "n") return 2;
	if (text[i + 1] === "\\" && text[i + 2] === "n") return 3;
	if (text[i + 1] === "r" && text[i + 2] === "\\" && text[i + 3] === "n") return 4;
	return 0;
}

/**
 * The line that ends at `at`: where it starts, after the break above it, and where that break starts (-1 when the
 * text starts the line, or the line is longer than 16,384 characters, an 8192-bit key's base64 on one line). breakAt read backwards: base64 has no
 * backslash, so an `n` after one is an escaped break's; a real break after an escaped one and its closing quote is
 * the same break.
 */
function lineAbove(text: string, at: number): { start: number; breakAt: number } {
	for (let k = at - 1; k >= 0 && k >= at - 16_384; k--) {
		if (text[k] === "\n") {
			let e = text[k - 1] === "\r" ? k - 1 : k;
			for (let n = 0; n < 40 && e > 0 && CONTINUATION.includes(text[e - 1]); n++) e--;
			const escaped = escapedBreakEnding(text, e);
			return { start: k + 1, breakAt: escaped >= 0 ? escaped : text[k - 1] === "\r" ? k - 1 : k };
		}
		if (text[k] === "n" && text[k - 1] === "\\") return { start: k + 1, breakAt: escapedBreakEnding(text, k + 1) };
	}
	return { start: Math.max(0, at - 16_384), breakAt: -1 };
}

/** Where an escaped line break that ends at `end` starts (`\n`, `\\n`, `\r\n` escaped), or -1. */
function escapedBreakEnding(text: string, end: number): number {
	if (text[end - 1] !== "n" || text[end - 2] !== "\\") return -1;
	let b = text[end - 3] === "\\" ? end - 3 : end - 2;
	if (text[b - 1] === "r" && text[b - 2] === "\\") b -= 2;
	return b;
}
