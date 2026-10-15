/**
 * The context of a token: the name it's assigned to, the syntax it sits in, and the words around it.
 * A random token under `api_key=`, in an `X-Api-Key:` header or after `Client(` is likely a key; the
 * same token after `sha256:`, under `"integrity":` or after `commit ` is a hash.
 */
import { lastText, lowerBound } from "./lines.ts";
import { isGenericName, mentionsCredential, nameClass, type NameClass, phraseBefore, readPhrase } from "./names.ts";
import { inJwk } from "./json.ts";
import { publicBlocks } from "./publickeys.ts";
import { sqlCells, type SqlCell } from "./sql.ts";
import {
	backslashesBefore,
	delimitedCells,
	isEscapedBreak,
	PAIR_VALUE,
	PIPE_RULE,
	pipeCells,
	siblingName,
	STRING_PREFIX,
} from "./syntax.ts";
import { PARAM_NAME, PARAM_START, urlAround } from "./urls.ts";

/** How far a line is read either side of a token, and the longest line read whole for its structure (tables, blobs). */
const LEFT = 400;
const RIGHT = 200;
const LONG_LINE = 4000;

/**
 * A text read once for the context of its tokens: its logical lines (a line break ends one, and so does an escaped one,
 * syntax.ts isEscapedBreak: escaped text has no telling a JSON string's `\n` from a path's `C:\nginx`), the extents
 * of its public armored blocks, and the first lines of its comma-separated blocks as they're found.
 */
export class Doc {
	readonly text: string;
	/** Where each line starts, and where it ends (before its break). */
	private readonly starts: number[] = [0];
	private readonly ends: number[] = [];
	/** Public armored blocks: where each BEGIN is, in order, and where its block ends. */
	private armor?: { begins: number[]; ends: number[] };
	/** Whether the text has a JSON Web Key in it, so a token's enclosing object is worth reading. */
	readonly hasJwk: boolean;
	/** The first line of the comma-separated block each line walked is in, by line and cell count (`line:cells`). */
	private readonly csvTops = new Map<string, number>();
	/** The cells of the text's SQL rows, by where their values start. */
	private cells?: SqlCell[];
	private cellStarts?: number[];

	/** The last text read, so the rules that judge one text's spans one by one (policy.ts) read it once. */
	static readonly of = lastText((text) => new Doc(text));

	constructor(text: string) {
		this.text = text;
		this.hasJwk = /\bkty\b/.test(text);
		for (let i = 0; i < text.length; i++) {
			const c = text.charCodeAt(i);
			// (A line ends before the `\r` of a CRLF, real or escaped.)
			if (c === 10) this.lineBreak(text.charCodeAt(i - 1) === 13 ? i - 1 : i, i + 1);
			else if (c === 92) {
				// (A run of backslashes: only its last can start a `\n`.)
				let j = i;
				while (text.charCodeAt(j + 1) === 92) j++;
				if (isEscapedBreak(text, j)) {
					this.lineBreak(text.startsWith("\\r", j - 2) && backslashesBefore(text, j - 2) % 2 === 0 ? j - 2 : j, j + 2);
					i = j + 1;
				} else i = j;
			}
		}
		this.ends.push(text.length);
	}

	private lineBreak(end: number, next: number) {
		this.ends.push(end);
		this.starts.push(next);
	}

	/** The index of the line `at` is on. */
	lineOf(at: number): number {
		return lowerBound(this.starts, at + 1) - 1;
	}

	start(line: number): number {
		return this.starts[line];
	}

	end(line: number): number {
		return this.ends[line];
	}

	/** A line's text; empty for a line longer than LONG_LINE, which is no table row, blob line or sibling. */
	line(i: number): string {
		if (i < 0 || i >= this.starts.length || this.ends[i] - this.starts[i] > LONG_LINE) return "";
		return this.text.slice(this.starts[i], this.ends[i]);
	}

	/**
	 * Whether `at` is inside a public armored block: a certificate, a public key, a PGP public block or signature, read
	 * as pem.ts reads a block (to its END, or where its material stops when output is cut short: `head -3 cert.pem`).
	 */
	inPublicArmor(at: number): boolean {
		if (!this.armor) {
			const blocks = publicBlocks(this.text);
			this.armor = { begins: blocks.map((b) => b.start), ends: blocks.map((b) => b.end) };
		}
		const k = lowerBound(this.armor.begins, at + 1) - 1;
		return k >= 0 && at < this.armor.ends[k];
	}

	/** The cell of an SQL row (`INSERT`, `COPY`) whose value holds `[start, end)`, read as sql.ts reads rows. */
	sqlCell(start: number, end: number): SqlCell | undefined {
		if (!this.cells) {
			// (Values in the order they appear, so their starts are sorted.)
			this.cells = [...sqlCells(this.text)].sort((a, b) => a.value.start - b.value.start);
			this.cellStarts = this.cells.map((c) => c.value.start);
		}
		const cell = this.cells[lowerBound(this.cellStarts!, start + 1) - 1];
		return cell && end <= cell.value.end ? cell : undefined;
	}

	/**
	 * The first line of the comma-separated block that line `i` is in: the lines above it with as many cells, up to
	 * 2,000. Remembered for every line walked, so a block's rows cost one walk between them.
	 */
	csvBlockTop(i: number, cells: number): number {
		const walked: number[] = [];
		let top = i;
		for (let n = 0; n < 2000 && top > 0; n++) {
			const known = this.csvTops.get(`${top}:${cells}`);
			if (known !== undefined) {
				top = known;
				break;
			}
			walked.push(top);
			if (delimitedCells(this.line(top - 1), ",").length !== cells) break;
			top--;
		}
		for (const line of walked) this.csvTops.set(`${line}:${cells}`, top);
		return top;
	}
}

type Syntax =
	| "assign" // NAME=value, NAME: value, "name": "value", name => value
	| "flag" // --name value, -p value
	| "header" // Name: value at line start, HTTP style
	| "query" // ?name=value, &name=value
	| "path" // /segment/value in a URL or path
	| "call" // fn("value"), new Client("value")
	| "xml" // <name>value</name>, name="value" attribute
	| "prose" // "the key is value", "here's your token: value"
	| "bare" // the token is the whole line
	| "list" // an item of an array or list
	| "other";

export interface Context {
	/** The name the token is assigned to, if any. */
	name: string;
	nameClass: NameClass;
	syntax: Syntax;
	/** The token is inside quotes. */
	quoted: boolean;
	/** A hash or content-address prefix right before: `sha256:`, `sha512-`, `h1:`, `@sha256:`, `md5=`. */
	hashPrefix: boolean;
	/** A filename extension or path continues after: `main.3f9a2c.js`, `abc123.png`. */
	fileish: boolean;
	/** Credential words before the token on its line or on the line above (weaker than a name). */
	lineCredential: boolean;
	/** Hash or ID words before the token on its line, on the line above, or just after the token. */
	lineHash: boolean;
	/**
	 * A hash or ID word heads the phrase the token belongs to: last before it (`commit <t>`, `sha256: <t>`, `Resolved
	 * <t>`, on the line above for a token that starts its line) or first after it (`<t> (sha256)`). Not one elsewhere
	 * on the line: "your new API key for the git server: <t>".
	 */
	hashPhrase: boolean;
	/**
	 * The previous URL path segment, for `/hooks/<token>`, `/webhook/<token>`; in a URL, or a request's target after its
	 * method (`POST /hooks/<token> HTTP/1.1`).
	 */
	pathParent: string;
	/** A phrase that hands over a value: "here's your key", "Token created:", "use this one". */
	handover: boolean;
	/** The token sits in a URL (host, path, query or fragment). */
	inUrl: boolean;
	/** The token is a segment of a filesystem path (`/tmp/tmpab12…`, `/var/lib/docker/overlay2/l/…`). */
	fsPath: boolean;
	/**
	 * The token is the whole value of a `name=value` or `name: value` line and a PEM block opens on the next line: the
	 * block's label (OpenSSL's test files, `PrivateKey=ALICE_cf_c2pnb163v1` above `-----BEGIN PRIVATE KEY-----`).
	 */
	labelsBlock: boolean;
	/** The token sits inside a PEM PUBLIC KEY or CERTIFICATE block, or an SSH public key line. */
	armored: boolean;
	/** The token fills its line, and a neighbouring line is base64 of similar length: a wrapped blob. */
	blobLine: boolean;
	/** The SQL row's cell the token is the value of, or in. */
	sqlCell: SqlCell | undefined;
	/** The token is a member of a JSON Web Key: its innermost object has a `kty`. */
	jwk: boolean;
	/** The token is an argument on a shell command line (`$ ./notify.sh prod <token>`, `+ curl … <token>`). */
	shellArg: boolean;
	/** The left context of the line, for features. */
	left: string;
	/** The rest of the line after the token. */
	right: string;
	/** A few lines around the token. */
	near: string;
}

/**
 * Text with the words of its identifiers apart (`SMOKE_TOKEN` → `SMOKE TOKEN`, `stagingAdminToken` → `staging Admin
 * Token`, `IDToken` → `ID Token`), so the `\b` in the line patterns below finds a word inside a name.
 */
function identifierWords(text: string): string {
	return text.replace(/_|(?<=[a-z\d])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])/g, " ");
}

/** Line patterns, tested on identifierWords. */
const LINE_CREDENTIAL =
	/(?:api[-_ ]?key|apikey|\bsecret|\btoken|passw(?:or)?d|passphrase|credential|bearer|auth(?:orization)?\b|private[-_ ]key|access[-_ ]key|client[-_ ]secret|signing[-_ ]key|webhook|sk[_ ]live|\bpat\b|\bpwd\b)/i;
const LINE_HASH =
	/(?:\bsha(?:1|224|256|384|512)?\b|\bmd5\b|\bhash(?:es)?\b|\bdigest\b|checksum|integrity|\betag\b|\brevision\b|\brev\b|fingerprint|\bnonce\b|cursor|resource ?version|\btrace[-_ ]?id\b|\bspan[-_ ]?id\b|request[-_ ]?id|correlation[-_ ]?id|\bblob\b|\btree\b|\bparent\b|\buuid\b|\bguid\b|object[-_ ]?id|\bcid\b|\bsum\b|\bh1:|\bgo\.sum\b|lockfile|resolved|\btx(?:id|hash)?\b|block[-_ ]?hash|\baddress\b|\bkid\b|thumbprint|\bpublic[-_ ]key\b|\bpubkey\b|\bcommit(?:ted)?\b|\bmerge\b|\bcherry-pick\b|\bgit\b)/i;
/** Git's `HEAD`, as git writes it: "head" is a word (`head -c 16 /dev/urandom`). */
const LINE_HASH_CASED = /\bHEAD\b/;
/** The line patterns' hash words as the last before a token, and as the first after it (each pattern with its own case). */
const HASH_HEADS = [LINE_HASH, LINE_HASH_CASED].map((re) => ({
	before: new RegExp(String.raw`(?:${re.source})[ \t:="'()#-]*$`, re.flags),
	after: new RegExp(String.raw`^[ \t:="'(),-]*(?:${re.source})`, re.flags),
}));
const HANDOVER =
	/(?:\bhere(?:'s| is| are| you go| ya go| it is)|\b(?:token|key|secret|password|credentials?)(?: \w+){0,2} (?:is|was|created|generated|issued|:)|use (?:this|that)(?: one)?|(?:new|your|my|the) (?:api[- ]?)?(?:key|token|secret|password|pat)\b|copy (?:it|this)|paste (?:it|this)|save (?:it|this)|won'?t be shown again|only (?:be )?(?:shown|displayed) once|try (?:this|with))/i;

/** A name: identifier characters, dots, dashes, starting a word. */
const NAME_TAIL = String.raw`(?<![\p{L}\p{N}_.$@-])([\p{L}_$@][\p{L}\p{N}_.$@-]{0,80}?)`;

/**
 * `name = "`, `name: `, `cfg["api_key"] = "`, `self.secret_key: str = "`, `key => '`, `Authorization: Bearer `: a name,
 * its closing quote or subscript bracket, a type annotation, the operator, a scheme or keyword word, and the value's
 * opening quote or bracket.
 */
const ASSIGN = new RegExp(
	String.raw`${NAME_TAIL}(?:["'\x60]?\]|["'\x60])?(?:[ \t]*:[ \t]*[&*]?(?:'\w+[ \t]+)?[A-Za-z_][\w.<>\[\]|?, ]{0,40}?(?=[ \t]*=[^=>]))?[ \t]{0,40}(?:=|:=|:|=>|->|<-|\?\?=|\|\|=)[ \t]{0,40}(?:[!&*]?\w{0,10}[ \t]{1,4})?(?:(?:${STRING_PREFIX})?["'\x60]|\[[ \t]*["']?|\{[ \t]*["']?)?$`,
	"u",
);
const FLAG = /(?:^|[\s"'])(--?[A-Za-z][\w-]{0,60})(?:[ \t]{1,4}|=)["']?$/;
const QUERY = new RegExp(String.raw`${PARAM_START}(${PARAM_NAME})=$`);
const XML_TEXT = /<([\w:.-]{1,80})(?:\s[^<>]{0,200})?>$/;
const XML_ATTR = /\b([\w:.-]{1,80})=["']$/;
const CALL = new RegExp(
	String.raw`(?<![\w$.])([A-Za-z_$][\w$]{0,60}(?:\.[A-Za-z_$][\w$]{0,60}){0,4})[ \t]{0,2}\((?:[^()]{0,200}?,)?[ \t]{0,4}(?:[A-Za-z_]\w{0,30}[ \t]{0,2}=[ \t]{0,2})?(?:(?:${STRING_PREFIX})?["'\x60])?$`,
);
const PROSE =
	/\b([A-Za-z][\w-]{0,30})(?:[ \t]{1,3}(?:is|was|=|:)[ \t]{0,3}|:[ \t]{1,3}|[ \t]{1,3}(?:of|for)[ \t][^:]{0,40}:[ \t]{0,3})["'`*]{0,2}$/;
const TABLE = /^[ \t│|]{0,10}([A-Za-z_][\w.-]{0,80})(?:[ \t]{2,80}|[ \t]{0,80}[│|][ \t]{0,10})$/;
/** A hash algorithm's name: `sha256`, `sha-256` (HTTP's), `md5`, `blake3`. */
const HASH_ALGORITHM = String.raw`(?:sha-?(?:1|224|256|384|512)|md5|blake2b?|blake3|crc32|xxh\d*)`;
/**
 * A hash's or a digest's name right before the token. (HTTP's digest fields, RFC 9530, write the digest as a structured
 * field's byte sequence, `Content-Digest: sha-256=:<base64>:`; tools write the algorithm or the encoding in brackets
 * after a label, `Hash (sha256): `, `Checksum (base64): `; BSD's checksum tools the file's name after the algorithm,
 * `SHA256 (app.tar.gz) = `.)
 */
const HASH_PREFIX = new RegExp(
	String.raw`(?:^|[\s;])bh=$|pin-sha256="?$|(?<![A-Za-z0-9])(?:${HASH_ALGORITHM}|h1|integrity)[:=\-]:?[ \t]?$|(?<![A-Za-z0-9])(?:hash|checksum|digest|${HASH_ALGORITHM})[ \t]*\([^()\n]{1,100}\)[ \t]?[:=][ \t]?$|@sha256:$|\bsha(?:1|256|512)sum\b.{0,40}$|\b(?:commit|tree|parent|object|blob|merge)[ \t]$|\bcherry picked from commit $|\bindex $|(?:^|\n)Index: [^\s=:]{1,100}$`,
	"i",
);

/** The text before the last `name` in `left` (none when the name came from elsewhere, a sibling or a header). */
function textBefore(left: string, name: string): string {
	const at = left.lastIndexOf(name);
	return at < 0 ? "" : left.slice(0, at);
}

/**
 * A line of wrapped base64, its material the only token on it: `MIIBIjANBgkq…`, `"…\n"` in a JSON string, `+…` in a
 * diff, the first and last lines of an element's body (`<X509Certificate>MIIC…`, `…</X509Certificate>`).
 */
const BLOB_LINE =
	/^(?:[ \t"'>+-]{0,20}|[ \t]*(<)[\w:.-]{1,40}(?:[ \t][^<>]{0,200})?>)([A-Za-z0-9+/=]{16,120})(?:\\n)?(?:[ \t"',+]{0,4}|(<)\/[\w:.-]{1,40}>[ \t]*)$/;
/** The line widths base64 encoders wrap at. */
const ENCODER_WIDTHS = new Set([60, 64, 70, 72, 76, 80, 100, 120]);

/** Whether the token fills line `i`, a line of wrapped base64, with another such line above or below. */
function isBlobLine(doc: Doc, start: number, end: number, i: number): boolean {
	const line = doc.line(i);
	// (The material's length; -1 for a line that isn't one. An element on one line, `<key>…</key>`, holds a value.)
	const width = (l: string) => {
		const m = BLOB_LINE.exec(l);
		return m && !(m[1] && m[3]) ? m[2].length : -1;
	};
	const [w, pw, nw] = [width(line), width(doc.line(i - 1)), width(doc.line(i + 1))];
	if (end - start < 40 || w < 40) return false;
	// A body's lines share an encoder's width (64, 76…), or three in a row share one; only the last is shorter.
	// Keys listed one per line (`kubectl get secret … | base64 -d` per key, a handover) have their own lengths.
	// (Three in a row: this line and two neighbours above, below or around it.)
	const run =
		(pw === w && nw === w) || (pw === w && width(doc.line(i - 2)) === w) || (nw === w && width(doc.line(i + 2)) === w);
	if (!((ENCODER_WIDTHS.has(w) && (pw === w || nw === w)) || (pw > 0 && ENCODER_WIDTHS.has(pw) && w < pw) || run))
		return false;
	// Items of a list under a credential's name (`api_keys:` then `- …` lines, `"keys": [` then `"…",`) are keys, not a body.
	if (/^[ \t]*(?:- |["'])/.test(line)) {
		const parent = listName(doc, i);
		if (parent && nameClass(parent) === "credential") return false;
	}
	return true;
}

/** A line holding one token alone, or as a list's item: `- Kx9mQ2…`. */
const LONE_TOKEN_LINE = /^[ \t]*(?:[-*•][ \t]+)?["'`]?[A-Za-z0-9+/=_.-]{16,}["'`]?[ \t]*\r?$/;

/**
 * The line above line `i`, or above the lines of lone tokens line `i` ends (keys handed over one per line: "Here are
 * your new API keys:" over three of them).
 */
function listHead(doc: Doc, i: number, above: string): string {
	let k = i - 1;
	while (k > 0 && k >= i - 20 && LONE_TOKEN_LINE.test(doc.line(k))) k--;
	return k < i - 1 ? doc.line(k) : above;
}

/**
 * The name the list that line `i` is an item of sits under (`api_keys:` above `- …` lines, `"keys": [` above `"…",`
 * lines), read over its other items, blank lines and comments; undefined if none. (A line that only names: `Your API
 * key:` above a token hands it over, which the handover rules read.)
 */
function listName(doc: Doc, i: number): string | undefined {
	for (let k = i - 1; k >= 0 && k >= i - 200; k--) {
		const above = doc.line(k);
		if (/^[ \t]*(?:- |["'][A-Za-z0-9+/=_-]{16,}["'],?[ \t]*$|#|\/\/|$)/.test(above)) continue;
		return /^[ \t]*(?:- |[{[][ \t]*)?["']?([\w.-]{1,80})["']?[ \t]*[:=][ \t]*\[?[ \t]*$/.exec(above)?.[1];
	}
	return undefined;
}

/**
 * The cell of `header`, a `|` table's header row, over the cell `start` sits in on line `i`: by place, as a Markdown
 * table's cells needn't line up under their headers. None for a token with no bar before it on its line.
 */
function headerOver(header: string, doc: Doc, start: number, i: number): string | undefined {
	const row = doc.line(i);
	if (!/\|/.test(row.slice(0, start - doc.start(i)))) return undefined;
	return pipeCells(header)[pipeCells(row, doc.start(i)).findIndex((c) => c.end >= start)]?.text;
}

/** The header of the `|` table column `start` sits in on line `i`: `| Test name | Commit |` then `|---|---|` above its row. */
function pipeColumnAbove(doc: Doc, start: number, i: number): string | undefined {
	if (!/\|/.test(doc.line(i).slice(0, start - doc.start(i))) || start - doc.start(i) > 600) return undefined;
	for (let k = i - 1; k > 0 && k >= i - 40; k--) {
		const line = doc.line(k);
		if (PIPE_RULE.test(line)) return headerOver(doc.line(k - 1), doc, start, i)?.replace(/[*`]/g, "");
		if (!/\|/.test(line)) return undefined;
	}
	return undefined;
}

/** The header of the column `start` sits in, if the lines above line `i` are a whitespace-aligned or bar-separated table. */
function columnAbove(doc: Doc, start: number, end: number, i: number): string | undefined {
	const col = start - doc.start(i);
	for (let k = i - 1; k >= 0 && k >= i - 25; k--) {
		const line = doc.line(k);
		if (!line.trim()) return undefined;
		// A header: names (one or two words each) separated by two or more spaces.
		if (
			/^[ \t]*[A-Z][A-Z0-9_]*(?: [A-Z][A-Z0-9_]*)?(?:[ \t]{2,}[A-Z][A-Z0-9_]*(?: [A-Z][A-Z0-9_]*)?)+[ \t]*$/.test(line)
		) {
			for (const m of line.matchAll(/[A-Z][A-Z0-9_]*(?: [A-Z][A-Z0-9_]*)?/g))
				if (m.index <= col && col < m.index + Math.max(m[0].length, 4)) return m[0];
			return undefined;
		}
		// Lower-case headers of four or more columns (`curl …/_cat/indices?v`): values sit under their header.
		if (/^[ \t]*[a-z][a-z0-9_.]*(?:[ \t]+[a-z][a-z0-9_.]*){3,}[ \t]*$/.test(line)) {
			for (const m of line.matchAll(/[a-z][a-z0-9_.]*/g))
				if (m.index <= col && col < m.index + Math.max(m[0].length, 4)) return m[0];
			return undefined;
		}
		// A pandas or R frame: the header sits flush with its column's right (or left) edge, `   id  score` over `0  q3J9…=  0.91`.
		if (/^[ \t]*[A-Za-z_][\w.]*(?:[ \t]{2,}[A-Za-z_][\w.]*)+[ \t]*$/.test(line)) {
			for (const m of line.matchAll(/[A-Za-z_][\w.]*/g))
				if (m.index === col || m.index + m[0].length === end - doc.start(i)) return m[0];
			return undefined;
		}
		// A bar-separated header with no rule under it (`aws … --output table`): `|  ClientId  |  ClientName  |`. (The
		// table's first row: a row of words under another row is data.)
		if (
			/^[ \t]*\|(?:[ \t]*[A-Za-z][\w.-]{0,60}[ \t]*\|){2,}[ \t]*$/.test(line) &&
			!(k > 0 && /^[ \t]*\|.*\|[ \t]*$/.test(doc.line(k - 1)) && !/^[ \t]*[+|][-+=|: ]*$/.test(doc.line(k - 1)))
		)
			return headerOver(line, doc, start, i);
	}
	return undefined;
}

/** Whether `at` is inside a PEM block of public material, or on an SSH public key line. */
function armoredAt(doc: Doc, at: number, left: string): boolean {
	return (
		doc.inPublicArmor(at) ||
		/(?:^|\s|["'])(?:ssh-(?:rsa|dss|ed25519|ed448)|ecdsa-sha2-nistp\d{3}|sk-(?:ssh|ecdsa)[\w@.-]*)[ \t]+$/.test(
			left.slice(-200),
		)
	);
}

/** The nearest line above line `i` that isn't blank, over up to two blank lines: a label's line ("Your token:" then a blank line). */
function lineAbove(doc: Doc, i: number): string {
	for (let k = i - 1; k >= 0 && k >= i - 3; k--) {
		const end = doc.end(k);
		const line = doc.text.slice(Math.max(doc.start(k), end - LEFT), end);
		if (line.trim()) return line;
	}
	return "";
}

/**
 * The name and syntax the text left of a token gives it: `api_key="`, `--token `, `?key=`, `<secret>`,
 * `Client(`, a table column, `the key is `.
 */
function nameFromLeft(left: string, url: string | undefined): { name: string; syntax: Syntax } {
	let m: RegExpMatchArray | null;
	if (url !== undefined) {
		if ((m = QUERY.exec(url))) return { name: m[1], syntax: "query" };
		if (/\/$/.test(url)) return { name: "", syntax: "path" };
		// (Outside a URL, a form body: `#key=` is a comment's assignment.)
	} else if ((m = QUERY.exec(left)) && m[0][0] !== "#") return { name: m[1], syntax: "query" };
	const trimmed = left.trimStart();
	if (trimmed === "" || /^[-*•>+][ \t]*["'`]?$/.test(trimmed) || /^["'`]$/.test(trimmed))
		return { name: "", syntax: /^[-*•]/.test(trimmed) ? "list" : "bare" };
	// `Authorization: Bearer <token>`: the scheme word sits between name and value; or parameters and version tags do,
	// `webhook-signature: v1,<sig>`, `Stripe-Signature: t=…,v1=<sig>`.
	if (
		(m =
			/^[ \t]{0,8}([A-Za-z][\w-]{1,60}):[ \t]{1,4}(?:[A-Za-z][\w-]{0,20}[ \t]{1,3}|(?:[\w-]{1,20}(?:=[^\s,;]{0,40})?[,;][ \t]*)+(?:[\w-]{1,20}=)?)?$/.exec(
				left,
			))
	)
		return { name: m[1], syntax: /^[A-Z]/.test(m[1]) || /-/.test(m[1]) ? "header" : "assign" };
	if ((m = FLAG.exec(left))) return { name: m[1].replace(/^-+/, ""), syntax: "flag" };
	if ((m = XML_TEXT.exec(left))) return { name: m[1], syntax: "xml" };
	if ((m = XML_ATTR.exec(left)) && /<[\w:.-]+\s[^<>]*$/.test(left)) return { name: m[1], syntax: "xml" };
	if ((m = ASSIGN.exec(left))) return { name: m[1].replace(/^[$@]/, ""), syntax: "assign" };
	// A pair as a tuple or a list, its name first: `('oauth_signature', '…')`, `["api_key", "…"]`. (Not a call's
	// arguments: `algoliasearch('<app id>', '…')`.)
	if ((m = /(?<![\w$.\])][ \t]*)[([][ \t]*["']([\w.-]{1,60})["'][ \t]*,[ \t]*["'`]$/.exec(left)))
		return { name: m[1], syntax: "assign" };
	// (SQL's `VALUES (` is no call: an INSERT's cell is named by its column, Doc.sqlCell.)
	if ((m = CALL.exec(left)) && !/^values$/i.test(m[1])) return { name: m[1], syntax: "call" };
	if ((m = TABLE.exec(left))) return { name: m[1], syntax: "assign" };
	if ((m = PROSE.exec(left))) return { name: m[1], syntax: "prose" };
	// "(token 075d…)", "the key abc…": a credential word right before the value.
	if (
		(m = /\b((?:api[ _-]?)?(?:key|token|secret|password|passwd|credential)s?)[ \t]{0,3}[(:]?[ \t]{0,3}["'`]?$/i.exec(
			left,
		))
	)
		return { name: m[1].replace(/[ -]/g, "_"), syntax: "prose" };
	if (/(?:^|[\s(])["'`]$|,[ \t]*["'`]?$|\[[ \t]*["'`]?$/.test(left)) return { name: "", syntax: "list" };
	return { name: "", syntax: "other" };
}

export function contextOf(doc: Doc, start: number, end: number): Context {
	const text = doc.text;
	const i = doc.lineOf(start);
	const ls = Math.max(doc.start(i), start - LEFT);
	const le = Math.min(doc.end(i), end + RIGHT);
	const left = text.slice(ls, start);
	const right = text.slice(end, le);
	// The line above: for `- name: X` / `value:` pairs, and handover lines ("Your token:\n<token>").
	const above = lineAbove(doc, i);

	const quoted = /["'`]$/.test(left) || /^["'`]/.test(right);
	// The URL the token is in, from its scheme on.
	const urlStart = left.includes("://") ? urlAround(text, start, end, ls) : -1;
	const inUrl = urlStart >= 0;
	// (Its longest prefix, a line break and `Index: <path>`, is 108 characters.)
	const tail = left.slice(-120);
	const hashPrefix =
		HASH_PREFIX.test(tail) ||
		HASH_PREFIX.test(tail.replace(/[+/=]+$/, "")) ||
		/\bbase64,$/.test(tail) ||
		/digest=["'][^"'\n]{0,20}["'][^>\n]{0,40}>$/.test(tail);
	const fileish =
		/^\.(?:[a-z][a-z0-9]{0,5})(?:[^\w]|$)/i.test(right) && !/^\.(?:com|org|net|io|dev|app|co|ai)\b/i.test(right);
	let { name, syntax } = nameFromLeft(left, inUrl ? text.slice(urlStart, start) : undefined);

	// `{"name": "api_key", "value": "<token>"}`, and `env:` → `- name: API_KEY` → `value: <token>` with the name on the
	// line above: a sibling attribute names the value. (The line above only for a value attribute's line or a token alone
	// on its own: `id: get_token` over `uses: actions/create-github-app-token@<sha>` names no pin.)
	if (!name || PAIR_VALUE.test(name))
		name = siblingName(left) ?? (name || !left.trim() ? siblingName(above, { alone: true }) : undefined) ?? name;
	// An item of a list under a name (`api_keys:` then `- <key>` lines): the list's name.
	if (!name && /^[ \t]*(?:[-*•][ \t]*["'`]?|["'`])$/.test(left)) name = listName(doc, i) ?? "";

	// A request's target after its method, as access logs and HTTP dumps print it (`"POST /hooks/<token> HTTP/1.1"`): a
	// URL's path, not a file's.
	const requestPath = !inUrl && /\b(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)[ \t]+\/[^\s"]*$/.test(left);
	const fsPath =
		!inUrl &&
		(/(?:^|[\s"'`=:(,\[])(?:~|\.{1,2}|[A-Za-z]:)?(?:[\\/][\w.@+-]{1,80}){1,30}[\\/]$/.test(left) ||
			(/[\\/]$/.test(left) && /^[\\/][\w.-]/.test(right)));
	// A wrapped line of a long string value (RFC examples, wrapped JSON): `"n": "0vx7…` above, the rest of it here.
	// It belongs to that name, so the name's rules apply (a JWK's public member, a JWE's ciphertext).
	if (!name && /^[ \t]*\\?$/.test(left)) {
		for (let k = i - 1; k >= 0 && k >= i - 40; k--) {
			const prev = doc.line(k);
			// (A line ending in `=` padding has ended its value: the next line holds another.)
			if (/=[ \t]*\\?[ \t]*$/.test(prev)) break;
			const open = /"([\w-]{1,40})"[ \t]*:[ \t]*"[A-Za-z0-9_\-+/=.]{16,}\\?[ \t]*$/.exec(prev);
			if (open) {
				name = open[1];
				syntax = "assign";
				break;
			}
			if (!/^[ \t]*[A-Za-z0-9_\-+/=.]{8,}\\?[ \t]*$/.test(prev)) break;
		}
	}
	// Prose naming what an ID is: "Created document …", "job …", "Instance …", "run …".
	if (!name) {
		const noun =
			/\b(document|doc|job|task|run|build|instance|record|row|object|entity|item|order|post|comment|file|image|deployment|release|version|commit|request|trace|span|event|message|prediction|experiment|workflow|pipeline|execution|invocation|batch|upload|attachment|asset|node|pod|container|volume|snapshot|backup|ticket|issue|case|session|account|user|customer|project|workspace|org|organization|team|tenant|app|application|client|device|sign-in|signin)[ \t:#]{1,3}["'`]?$/i.exec(
				left,
			)?.[1];
		if (noun) {
			name = `${noun} id`; // (a space: `session id` here is a label, not a session's ID field)
			syntax = "prose";
		}
	}
	// A cell under a column header: `NAME  DIGEST  CREATED AT` above `DB_PASSWORD  e17e…  2 days ago`. A Markdown
	// table's header (over its rule) first: the table's rows above the token's would read as a bar-separated header.
	const column =
		pipeColumnAbove(doc, start, i) ||
		(/[ \t]{2,}\S*$|^\S*$|[│|][ \t]*$/.test(left) && start - ls < 300 ? columnAbove(doc, start, end, i) : undefined);
	if (
		column &&
		/^(?:digest|hash|sha|sha256|checksum|etag|id|uuid|guid|version|revision|commit|fingerprint|client[ _-]?id|app[ _-]?id|created|updated|name|[a-z]{1,8}[ _-]?id|[a-z]{0,8}uuid)$/i.test(
			column,
		)
	)
		name = column.replace(/\s+/g, "_");
	// A CSV cell: its column's header, from the first line of the block (`$id,name` above `xb6bxg56lral1qy9,Alyssa`).
	const row = text.slice(ls, le);
	// (The cells of the whole line, not of the window around the token.)
	if (
		!name &&
		!column &&
		/,/.test(row) &&
		/(?:^|,)[ \t]*["']?$/.test(left) &&
		/^["']?[ \t]*(?:,|$)/.test(right) &&
		doc.line(i)
	) {
		const cells = delimitedCells(doc.line(i), ",", doc.start(i));
		const index = cells.findIndex((c) => c.end >= start);
		const top = doc.csvBlockTop(i, cells.length);
		const header =
			top < i
				? delimitedCells(doc.line(top), ",")
						[index]?.text.trim()
						.replace(/^["'$]+|["']+$/g, "")
				: undefined;
		// (Not a run of digits, a first row of values read as the header; but a digest's name, `sha256`, `sha3_512`.)
		if (header && /^[A-Za-z_][\w ]{0,40}$/.test(header) && (!/\d{3}/.test(header) || /^sha(?:3_)?\d{3}$/i.test(header)))
			name = header.replace(/\s+/g, "_");
	}
	// A value in an SQL row: its column (`INSERT INTO uploads (id, name) VALUES ('<id>', …)`), over what the row's own
	// text reads as a name (`VALUES (` as a call, the cell before as a pair). A token inside a value keeps a name the
	// value gives it (`'{"api_key": "…"}'`).
	const sqlCell = doc.sqlCell(start, end);
	if (sqlCell) {
		const value = sqlCell.value.literal ?? sqlCell.value;
		if (!name || (start <= value.start && end >= value.end)) name = sqlCell.column;
	}
	// `checksum/secret:`, `annotations.checksum/config:`: the path before a name is part of it.
	if (name) {
		const path = /([\w.-]{1,60})\/$/.exec(textBefore(left, name))?.[1];
		if (path) name = `${path}/${name}`;
	}
	let cls = nameClass(name);
	// "public key: …", "next page token: …", "the search-only key (…)", "cache warm key=": the words before a bare
	// generic name can change what it means (names.ts readPhrase).
	if (name && (isGenericName(name) || /^(?:id|hash)$/i.test(name))) {
		const before = phraseBefore(textBefore(left, name), 4);
		({ name, class: cls } = readPhrase(before, name));
	}
	const pathParent = inUrl || requestPath ? (/\/([^/\s?#]{1,60})\/$/.exec(left)?.[1] ?? "") : "";
	// (A query parameter's credential words are its own name's: `?api_key=…&profile=<id>` says nothing of the profile.)
	const ownLeft = syntax === "query" && name ? left.replace(/[?&][^?&\s"'=]+=[^&\s"']*(?=&[^&]*$)/g, "") : left;
	const leftAndAbove = identifierWords(`${above}\n${ownLeft}`);
	return {
		name,
		nameClass: cls,
		syntax,
		quoted,
		hashPrefix,
		fileish,
		lineCredential: LINE_CREDENTIAL.test(leftAndAbove) || (name !== "" && mentionsCredential(name)),
		lineHash: [leftAndAbove, identifierWords(right.slice(0, 60))].some(
			(t) => LINE_HASH.test(t) || LINE_HASH_CASED.test(t),
		),
		hashPhrase: HASH_HEADS.some(
			({ before, after }) =>
				before.test(identifierWords((left.trim() ? left : above).slice(-80))) ||
				after.test(identifierWords(right.slice(0, 40))),
		),
		pathParent,
		sqlCell,
		handover:
			HANDOVER.test(identifierWords(left.slice(-200))) ||
			(left.trim() === "" && HANDOVER.test(identifierWords(listHead(doc, i, above).slice(-200)))),
		inUrl,
		fsPath,
		armored: armoredAt(doc, start, left),
		labelsBlock:
			/^[ \t]*[\w.-]{1,60}[ \t]*[=:][ \t]*["']?$/.test(left) &&
			/^["']?[ \t]*\r?$/.test(text.slice(end, doc.end(i))) &&
			/^\r?\n?-----BEGIN [A-Z0-9 ]{3,40}-----/.test(text.slice(doc.end(i), doc.end(i) + 60)),
		blobLine: isBlobLine(doc, start, end, i),
		jwk: doc.hasJwk && inJwk(text, start, end),
		shellArg:
			/^[ \t]*(?:\d{4}-\d\d-\d\dT[\d:.]+Z?[ \t]+)?(?:[$#>+][ \t]+|(?:sudo[ \t]+)?(?:\.{0,2}\/[\w.-][\w./-]*|[a-z][\w-]*(?:\.(?:sh|py|js|rb|ts|pl))?)[ \t]+)(?:[^\s"'|;&]+[ \t]+){0,12}["']?$/.test(
				left,
			),
		left: left.slice(-120),
		right: right.slice(0, 120),
		near: text.slice(Math.max(0, start - 300), Math.min(text.length, end + 100)),
	};
}
