/**
 * Encodings that hold a secret, decoded and judged by what they hold: base64 blobs (`base64 .env`, a Kubernetes
 * Secret's data, a docker config `auth`, a Basic header built by hand), base64 wrapped over lines, and hex dumps.
 * The whole encoding is the secret.
 */
import { base64Prefix } from "./base64.ts";
import { naturalness } from "./charlm.ts";
import { lineEnd, lineStart } from "./lines.ts";
import { asciiSet, longRuns } from "./runs.ts";
import { keepReason } from "./policy.ts";
import type { Finding } from "./types.ts";
import { hasThreeClasses } from "./values.ts";

const UTF8 = new TextDecoder("utf-8");
/** The share of characters that must be printable for bytes to count as text, and of zero bytes for UTF-16. */
const TEXT_SHARE = 0.95;

/**
 * The text some bytes hold, if they hold text: UTF-8 (UTF-16 when every other byte is zero, as
 * `powershell -EncodedCommand`'s is, with or without a byte-order mark), 95% of it printable (ASCII, tabs and line
 * breaks, and every character from U+00A0 on but U+FFFD, which marks bytes that aren't UTF-8), and at least `min`
 * characters long. Binary data, keys and hashes aren't text.
 */
function textOfBytes(bytes: Uint8Array | undefined, min = 8): string | undefined {
	if (!bytes) return undefined;
	let b = bytes;
	if ((b[0] === 0xff && b[1] === 0xfe) || (b[0] === 0xfe && b[1] === 0xff)) b = b.subarray(2);
	let text: string | undefined;
	for (const parity of [1, 0]) {
		if (b.length < 16 || b[parity] !== 0) continue;
		let zeros = 0;
		for (let i = parity; i < b.length; i += 2) if (b[i] === 0) zeros++;
		if (zeros >= (b.length >> 1) * TEXT_SHARE) {
			text = new TextDecoder(parity ? "utf-16le" : "utf-16be").decode(b);
			break;
		}
	}
	text ??= UTF8.decode(b);
	if (text.length < min) return undefined;
	let printable = 0;
	for (const ch of text) {
		const c = ch.codePointAt(0)!;
		if ((c >= 32 && c < 127) || c === 9 || c === 10 || c === 13 || (c >= 0xa0 && c !== 0xfffd)) printable++;
	}
	return printable >= [...text].length * TEXT_SHARE ? text : undefined;
}

/** Hex digits as bytes, or undefined for an odd count. */
function hexBytes(hex: string): Uint8Array | undefined {
	if (hex.length % 2) return undefined;
	const out = new Uint8Array(hex.length / 2);
	for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	return out;
}

const BASE64_SET = asciiSet("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/_-");
/** The fewest characters of a base64 value worth decoding (12 bytes). */
const MIN_BASE64_RUN = 16;
const WRAPPED_SET = asciiSet("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
const HEX_SET = asciiSet("0123456789abcdefABCDEF");
/** The fewest hex digits of a run read as a hex-encoded value (12 bytes), and the most. */
const MIN_HEX_RUN = 24;
const MAX_HEX_RUN = 100000;

/** The base64 values in `text`, whole: a run of the alphabet (base64 or base64url) with up to two `=` of padding, bounded by other characters. */
function* base64Runs(text: string): Generator<[start: number, end: number]> {
	for (const [start, runEnd] of longRuns(text, BASE64_SET, MIN_BASE64_RUN)) {
		let end = runEnd;
		while (end < runEnd + 2 && text[end] === "=") end++;
		if (/[A-Za-z0-9+/=_-]/.test(text[end] ?? "")) continue;
		yield [start, end];
	}
}

/**
 * Base64 blobs whose decoded text holds a secret (`inner` decides), on one line or wrapped over several; and a line
 * that is only base64 of one generated-looking token (`echo "$KEY" | base64`).
 */
export function findEncoded(text: string, inner: (decoded: string) => boolean): Finding[] {
	const out: Finding[] = [];
	const wrapped = wrappedBase64(text);
	// (A line of a blob wrapped over lines is no token of its own, however random its piece of the blob reads. Runs and
	// blobs both come in text order: one pass over each.)
	let w = 0;
	const inBlob = (start: number) => {
		while (w < wrapped.length && wrapped[w].end <= start) w++;
		return w < wrapped.length && wrapped[w].start <= start;
	};
	for (const [start, end] of base64Runs(text)) {
		const value = text.slice(start, end);
		const decoded = textOfBytes(base64Prefix(value));
		if (decoded === undefined) continue;
		if (inner(decoded)) out.push({ start, end, kind: "base64 of a secret", rule: "encoded:base64", confidence: 0.95 });
		else if (
			/^[!-~]{8,200}\n?$/.test(decoded) &&
			/[=]$|^[A-Za-z0-9+/]+$/.test(value) &&
			isLineAlone(text, start, end) &&
			!inBlob(start) &&
			isGeneratedToken(decoded.trim())
		) {
			out.push({ start, end, kind: "base64 of a secret", rule: "encoded:base64-token", confidence: 0.8 });
		}
	}
	for (const run of wrapped) {
		const decoded = textOfBytes(base64Prefix(run.text));
		if (decoded !== undefined && inner(decoded))
			out.push({
				start: run.start,
				end: run.end,
				kind: "base64 of a secret",
				rule: "encoded:base64-wrapped",
				confidence: 0.95,
			});
	}
	return out;
}

/**
 * A token a generator made, or a password a person made with symbols in it; not one public by design or never a key
 * (which the decision stage keeps: `pk_live_…`), a UUID, hex, an email or a URL.
 */
function isGeneratedToken(token: string): boolean {
	if (
		/\s/.test(token) ||
		/^[0-9a-f]+$/i.test(token) ||
		/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(token) ||
		/^[\w.-]+@[\w.-]+$|^https?:/.test(token)
	)
		return false;
	if (
		keepReason(token, { start: 0, end: token.length, kind: "random token", rule: "unnamed", confidence: 0.8 }) !==
		undefined
	)
		return false;
	return naturalness(token) < 0.2 || (hasThreeClasses(token) && /[^A-Za-z0-9]/.test(token));
}

/** Base64 wrapped over lines, joined: its characters, and the span from the first line's to the last's. */
interface WrappedRun {
	text: string;
	start: number;
	end: number;
	/** The length of its first line, which the lines after it fill. */
	width: number;
	lines: number;
}

const isBase64Char = (ch: string) => /[A-Za-z0-9+/]/.test(ch);

/** Where the base64 (and `=` padding) at the end of `line` starts. */
function base64Start(line: string): number {
	let k = line.length;
	while (k > 0 && line[k - 1] === "=" && line.length - k < 2) k--;
	while (k > 0 && isBase64Char(line[k - 1])) k--;
	return k;
}

/** Where the base64 (and `=` padding) at the start of `line` ends. */
function base64End(line: string): number {
	let k = 0;
	while (k < line.length && isBase64Char(line[k])) k++;
	for (let padding = 0; k < line.length && line[k] === "=" && padding < 2; padding++) k++;
	return k;
}

/**
 * Base64 wrapped over lines (`base64 .env`, `base64 -w 76`, PEM-like bodies, JSON with `\n`): full-width lines of
 * 16 to 200 base64 characters, then one shorter last line or a line ending in `=`. Their characters joined, and
 * the span from the first to the last. The first line may have text before its base64 (`data: `, `"d":"`) and the
 * last text after it (`"}`, `")`): of two lines or more, a line's base64 at its end opens a run, and a line's
 * base64 at its start, followed by a quote or a closing bracket, ends it.
 */
function wrappedBase64(text: string): { text: string; start: number; end: number }[] {
	// (A run has a line of 16 base64 characters at least.)
	if (longRuns(text, WRAPPED_SET, MIN_BASE64_RUN).next().done) return [];
	const out: WrappedRun[] = [];
	let run: WrappedRun | undefined;
	const close = () => {
		// (One line alone is base64Runs' to judge.)
		if (run && run.text.length >= 24 && run.lines > 1) out.push(run);
		run = undefined;
	};
	let offset = 0;
	const parts = text.split(/(\\n|\r?\n)/);
	for (let i = 0; i < parts.length; offset += parts[i].length, i++) {
		if (i % 2) continue;
		// (No run is open, and a line this short opens none: a run's first line has 16 base64 characters.)
		if (!run && parts[i].length < MIN_BASE64_RUN) continue;
		const body = parts[i].trim();
		const at = offset + parts[i].indexOf(body);
		// (Any other line, a blank one too, ends a run; one with base64 at its end opens the next.)
		if (!/^[A-Za-z0-9+/]+={0,2}$/.test(body)) {
			const head = base64End(body);
			if (run && head > 0 && head <= run.width && /["'`)\]}>]/.test(body[head])) {
				run.text += body.slice(0, head);
				run.end = at + head;
				run.lines++;
				close();
				continue;
			}
			close();
			const tail = base64Start(body);
			const length = body.length - tail;
			if (tail > 0 && length >= 16 && length <= 200 && /[\s"'`:=(\[>,]/.test(body[tail - 1]))
				run = { text: body.slice(tail), start: at + tail, end: at + body.length, width: length, lines: 1 };
			continue;
		}
		if (run && body.length <= run.width) {
			run.text += body;
			run.end = at + body.length;
			run.lines++;
			// (A shorter line, or padding, is the last.)
			if (body.length < run.width || body.endsWith("=")) close();
			continue;
		}
		close();
		if (body.length >= 16 && body.length <= 200) {
			run = { text: body, start: at, end: at + body.length, width: body.length, lines: 1 };
			if (body.endsWith("=")) close();
		}
	}
	close();
	return out;
}

/** Whether [start, end) is all that's on its line, apart from a log timestamp or prompt prefix. */
function isLineAlone(text: string, start: number, end: number): boolean {
	const ls = lineStart(text, start, 200);
	const le = lineEnd(text, end, 200);
	const before = text.slice(ls, start);
	const after = text.slice(end, le);
	return /^\s*$/.test(after) && /^(?:\s*|\d{4}-\d\d-\d\dT[\d:.]+Z?\s+|[$>+#]\s+)$/.test(before);
}

/**
 * Hex dumps (`xxd`, `xxd -p`, `hexdump -C`, `od -A x -t x1`): the bytes are decoded, and a dump whose
 * contents hold a secret is redacted whole.
 */
export function findHexDumps(text: string, inner: (decoded: string) => boolean): Finding[] {
	const out: Finding[] = [];
	if (!/[0-9a-f]{4}/i.test(text)) return out;
	// Offset-prefixed dumps: runs of lines `<offset>[:] <hex groups> [ascii]`.
	for (const m of text.matchAll(
		/(?:^[0-9a-f]{6,8}:?(?:[ \t]{1,4}[0-9a-f]{2,4}){1,16}[^\n]{0,80}(?:\n|$)){1,100000}/gim,
	)) {
		const words: string[] = [];
		let bytes = "";
		const lines = m[0].split("\n").filter((l) => l);
		// Bytes per line from the offset step (16 for xxd and `hexdump -C`), so an ASCII column that
		// starts with hex letters (`cafe.txt`, `DEBUG=1.`) isn't read as more bytes.
		const offsets = lines.slice(0, 2).map((l) => parseInt(l.slice(0, 8), 16));
		const step =
			offsets.length === 2 && offsets[1] > offsets[0] && offsets[1] - offsets[0] <= 64 ? offsets[1] - offsets[0] : 16;
		for (const line of lines) {
			const body = line.replace(/^[0-9a-f]{6,8}:?[ \t]+/i, "");
			let digits = 0;
			for (const t of body.split(/[ \t]+/)) {
				if (!/^(?:[0-9a-f]{2}|[0-9a-f]{4}|[0-9a-f]{8})$/i.test(t) || digits + t.length > step * 2) break;
				if (t.length === 4) words.push(t.slice(2) + t.slice(0, 2));
				bytes += t;
				digits += t.length;
			}
		}
		for (const hex of [bytes, words.join("")]) {
			if (hex.length < 12) continue;
			const decoded = textOfBytes(hexBytes(hex), 0);
			if (decoded !== undefined && inner(decoded)) {
				out.push({
					start: m.index,
					end: m.index + m[0].replace(/\n$/, "").length,
					kind: "hex dump of a secret",
					rule: "encoded:hexdump",
					confidence: 0.95,
				});
				break;
			}
		}
	}
	// Plain hex (`xxd -p`): runs of whole lines of hex, or one long run, that decode to text holding a secret.
	const runs: { index: number; text: string }[] = [];
	for (const [start, end] of longRuns(text, HEX_SET, MIN_HEX_RUN)) {
		// (A hex run that a letter or digit touches is part of a longer word; one past the most is no value but a dump. A
		// literal's prefix is no word: `0x…` (mysqldump's --hex-blob, SQL Server), `\x…` (psql's bytea).)
		const prefixed = /(?:^|[^0-9a-z])0x$|\\x$/i.test(text.slice(Math.max(0, start - 3), start));
		if (
			end - start <= MAX_HEX_RUN &&
			(prefixed || !/[0-9a-z]/i.test(text[start - 1] ?? "")) &&
			!/[0-9a-z]/i.test(text[end] ?? "")
		)
			runs.push({ index: start, text: text.slice(start, end) });
	}
	// (Lines are read together, a dump's last line as short as it is: a secret read line by line leaves its tail on the
	// next line. A list of hashes, one a line, decodes to no text.)
	let runStart = -1;
	let runEnd = -1;
	let lines = 0;
	const flush = () => {
		if (lines > 1) runs.push({ index: runStart, text: text.slice(runStart, runEnd) });
		runStart = -1;
		lines = 0;
	};
	for (const m of text.matchAll(/^(?:[0-9a-f]{2}){1,100}\r?$/gim)) {
		if (runStart >= 0 && m.index === runEnd + 1) {
			runEnd = m.index + m[0].length;
			lines++;
		} else {
			flush();
			if (m[0].trimEnd().length < 16) continue;
			runStart = m.index;
			runEnd = m.index + m[0].length;
			lines = 1;
		}
	}
	flush();
	for (const m of runs) {
		const decoded = textOfBytes(hexBytes(m.text.replace(/\s+/g, "")));
		if (decoded !== undefined && inner(decoded))
			out.push({
				start: m.index,
				end: m.index + m.text.replace(/\s+$/, "").length,
				kind: "hex of a secret",
				rule: "encoded:hex",
				confidence: 0.95,
			});
	}
	return out;
}
