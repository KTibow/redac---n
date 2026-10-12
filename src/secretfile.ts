/**
 * What a secret file holds, read as that file: every value under a credential's name, a file that is one token, a
 * `.pgpass` line's password, a value no setting has under a vendor's name; a credential command's output; the
 * output under a prompt in a pasted session; and the places a secret file's content sits inside other text (a
 * diff's hunks, a heredoc that writes one, `echo … > ~/.vault_pass`).
 */
import {
	type CommandRun,
	commandsRun,
	holdsOnlySecrets,
	isConfigFileName,
	isSecretFile,
	printsSecret,
	printsSecretFile,
} from "./commands.ts";
import { allRedirects, type Heredoc, LineIndex, programName, PROMPT, simpleCommand, wordSpan } from "./shell.ts";
import { naturalness } from "./charlm.ts";
import { isPlaceholder } from "./public.ts";
import { hasCredentialWord, isCredentialName, isSettingName, namesPasswordOrPin, words } from "./names.ts";
import { lowerBound } from "./lines.ts";
import type { Finding } from "./types.ts";
import {
	COMMON_WORDS,
	isBenignValue,
	isCode,
	isGeneratedSegment,
	isIdentifierShaped,
	isInert,
	isPath,
	isPodName,
	isRandomToken,
	isWordy,
	readsAsWords,
} from "./values.ts";
import { isSentenceWord } from "./named.ts";
import { isPasswordlessUrl, leadingUrl } from "./urls.ts";
import { publicBlocks } from "./publickeys.ts";
import { isSessionCookie } from "./structure.ts";

/**
 * Under a name the name rules didn't take, in a secret file: a value no setting has, under a vendor's bare word
 * (`STRIPE=<uuid>`, `OPENAI=Tiger1103#x`) or a name with a credential word that the in-text classifier reads otherwise
 * (`BASIC_AUTH=Harbor2291!`, `MY_SECRET_THING=…`): the file says its values are secrets. Not under a name a setting
 * has (`APP_URL`, `SSH_AUTH_SOCK`), nor a value that reads as a setting: words, numbers, versions, paths, hosts and URLs
 * (`DEBUG=true`, `REGION=us-east-1`). These findings still pass the decision stage (policy.ts), which keeps publishable
 * keys and other public values.
 */
function isOpaqueSetting(name: string, v: string, tokenUnderAnyName: boolean): boolean {
	if (isSettingName(name) || isPodName(v)) return false;
	// (Under a name that says nothing, `admin:` in `config/secrets.staging.yml`, only a generated token is one, and only in
	// a file that holds nothing else: `.env` has settings and public IDs (`GPG_KEY=<fingerprint>`). Not one a word and a
	// hyphen lead, `gradle-<hash>`: a cache's key.)
	if (!(isBareVendorWord(name) || hasCredentialWord(name)))
		return tokenUnderAnyName && isRandomToken(v, MIN_UNNAMED_TOKEN) && !isSettingShaped(v) && !/^[a-z]{2,}-/i.test(v);
	if (/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(v)) return true;
	return !isSettingShaped(v) && /[A-Za-z]/.test(v) && /[\d\W]/.test(v.replace(/[-_.]/g, ""));
}

/** The shortest generated token taken as a secret under a name that says nothing of one: a 128-bit hex ID is 32; a 96-bit one, 24. */
const MIN_UNNAMED_TOKEN = 24;

/** One upper-case word: `STRIPE`, `OPENAI`. */
function isBareVendorWord(name: string): boolean {
	return /^[A-Z][A-Z0-9]{2,30}$/.test(name);
}

/** What settings hold: words, numbers, versions, paths, hosts, emails and URLs without credentials. */
function isSettingShaped(v: string): boolean {
	return (
		v.length < 8 ||
		v.length > 1000 ||
		/\s/.test(v) ||
		isPasswordlessUrl(v) ||
		isPath(v) ||
		/^[\w.+-]+@[\w-]+(?:\.[\w-]+)+$/.test(v) ||
		/^v?\d+(?:[.:-]\d+)*$/.test(v) ||
		/^[\w-]+(?:\.[a-z][\w-]*)+(?::\d+)?$/.test(v) ||
		isWordy(v) ||
		isIdentifierShaped(v) ||
		isBenignValue(v)
	);
}

/** Words in sentence punctuation, no digits or symbols: `The PORT key is duplicated`, `ASCII text, with CRLF line terminators`. */
const PROSE_WORD = /^[\p{L}][\p{L}_'’.,:;!?()-]*$/u;

/** The fewest words of a sentence. (Two are a name and its qualifier, `Admin password`; a passphrase has none of a sentence's words.) */
const MIN_SENTENCE_WORDS = 3;

/** A sentence: a message or a report line, not a passphrase, which is words with none of a sentence's (`correct horse battery staple`). */
function isProse(value: string): boolean {
	const words = value.trim().split(/\s+/);
	return (
		words.length >= MIN_SENTENCE_WORDS &&
		words.length <= MAX_SENTENCE_WORDS &&
		words.every((w) => PROSE_WORD.test(w)) &&
		words.some(isSentenceWord)
	);
}
const MAX_SENTENCE_WORDS = 40;

/** A URL with a scheme that carries no credential: no password, no query or fragment, and no path segment a generator made (`https://packages.microsoft.com/keys/microsoft.asc`). */
function isPlainUrl(value: string): boolean {
	const url = leadingUrl(value);
	if (!url || url.end !== value.length || url.password || /[?#]/.test(value)) return false;
	return url.segments.every((s) => {
		const segment = value.slice(s.start, s.end);
		return !isGeneratedSegment(segment) && (segment.length < MIN_UNNAMED_TOKEN || readsAsWords(segment));
	});
}

/** A duration (`24h`, `90s`, `1h30m`) or a list of words (`["ci" "default"]`): a setting a secret manager's listing shows. */
function isSettingList(value: string): boolean {
	return (
		/^(?:\d+(?:\.\d+)?(?:ns|us|ms|s|m|h|d|w))+$/.test(value) ||
		(/^\[(?:[ \t,]*(["'])[a-z][\w-]{0,30}\1)+[ \t]*\]$/.test(value) &&
			[...value.matchAll(/[a-z][\w-]*/g)].every((m) => readsAsWords(m[0])))
	);
}

/** A value a secret file holds that is no secret: an inert one (values.ts), a plain URL, a sentence, a file's name, a setting. */
function isNotSecret(value: string): boolean {
	return isInert(value) || isPlainUrl(value) || isProse(value) || isConfigFileName(value) || isSettingList(value);
}

/** Where group `g` of a match made with the `d` flag starts and ends. */
function at(m: RegExpExecArray | RegExpMatchArray, g: number): [number, number] {
	return m.indices![g] as [number, number];
}

/** A number that is a setting (a port, a timeout), unless the name says password or PIN (or, for 4 digits or more, secret). */
function isSettingNumber(name: string, value: string): boolean {
	if (!/^\d{1,19}$/.test(value)) return false;
	// (By the name's words: `spinner_delay` and `shipping_days` hold no PIN.)
	return value.length <= 3 ? !namesPasswordOrPin(name) : !(namesPasswordOrPin(name) || words(name).includes("SECRET"));
}

/**
 * A file that is one line with no name in it is its value: a password file, a passphrase with spaces; or
 * `user:password`, as a credentials file holds it. (Not a `NAME=value` line, a diff's or an `export`'s
 * included, nor a URL: those are read by their parts. A comment is `#` and a blank, a section `[…]`, an object
 * `{…}`, markup `<…>`. A name before `=` or `:` is a name when it reads as one: `db_password=`, `API_KEY:`,
 * `dbPassword=`; `Hx7m=Q2pL` and `kX9:mQ2#pLw7` are one value. Brackets around one token are part of it:
 * `{Kd8pQ2zX9mL}`.)
 */
function wholeFile(text: string, out: Finding[]) {
	const only = text.trim();
	if (!only || only.includes("\n")) return;
	const start = text.indexOf(only); // (the first non-blank character: `only` is `text` trimmed)
	if (isOneValueLine(only)) {
		out.push({ start, end: start + only.length, kind: "secret", rule: "file:whole", confidence: 0.95 });
		return;
	}
	const pair = /^[\w.@-]{1,64}:(\S{4,4096})$/d.exec(only);
	if (
		pair &&
		!/:\/\//.test(only) &&
		!PGPASS.test(only) &&
		!isInert(pair[1]) &&
		!isPlaceholder(pair[1]) &&
		!/^\d{1,5}$/.test(pair[1])
	) {
		out.push({
			start: start + at(pair, 1)[0],
			end: start + at(pair, 1)[1],
			kind: "password",
			rule: "file:whole",
			confidence: 0.95,
		});
	}
}

/** A line that is one value: not `NAME=value` or `NAME: value`, a URL, a comment, a section, a document or a reference. */
function isOneValueLine(line: string): boolean {
	const named = /^[+ -]?(?:export[ \t]+)?([\w.-]+)[=:]/.exec(line)?.[1];
	const nameShaped =
		named !== undefined && /^(?:[a-z_][a-z0-9_.-]*|[A-Z_][A-Z0-9_.-]*|[a-z]+(?:[A-Z][a-z]+)+)$/.test(named);
	if (line.length > 1000 || /[=:]\s|:\/\//.test(line) || nameShaped) return false;
	// One token in brackets is the value, brackets and all: `{Kd8pQ2zX9mL}`.
	if (/^(?:\[[^\s\]]*\]|\{[^\s}]*\}|<[^\s>]*>)$/.test(line) && !/[:,=]/.test(line)) return true;
	const structured = /^#[ \t!#]|^\[[^\]]*\]$|^\{[\s\S]*\}$|^<[\s\S]*>$|^["{[][\s\S]*[:,]/.test(line);
	// (Nor a keyword and a reference: `requirepass ${REDIS_PASSWORD}`, its value read elsewhere.)
	const keywordReference = /^[\w.-]+[ \t]+(?:\$\{[^{}\n]+\}|\$[A-Za-z_]\w*)$/.test(line);
	return (
		!structured &&
		!keywordReference &&
		!isNotSecret(line) &&
		!(line.includes("=") && isInert(line.slice(line.lastIndexOf("=") + 1)))
	);
}

/** A `.pgpass` line, `host:port:database:user:password` (`*` is a wildcard in the first four). */
const PGPASS = /^[ \t]*[^:\s#][^:\s]*:(?:\d{1,5}|\*):[^:\s]+:[^:\s]+:([^\r\n]+?)\r?$/m;

/** `.pgpass` lines: the last field. */
function pgpassLines(text: string, out: Finding[]) {
	for (const m of text.matchAll(new RegExp(PGPASS.source, "gmd")))
		out.push({ start: at(m, 1)[0], end: at(m, 1)[1], kind: "password", rule: "file:named", confidence: 1 });
}

/**
 * `NAME=value`, `name: value`, `"name": "value",` lines, and `+` lines of a patch that adds the file: the value under
 * a credential's name, or an opaque one under any name that says nothing of a secret (isOpaqueSetting). (Published examples, `AKIAIOSFODNN7EXAMPLE`,
 * are placeholders even in a secret file. Rails' Active Record encryption keys are named `primary_key`,
 * `deterministic_key` and `key_derivation_salt`.)
 */
function assignments(text: string, out: Finding[], tokenUnderAnyName: boolean) {
	for (const m of text.matchAll(
		/^([ \t]{0,40}(?:\d{1,7}(?:[\t→:|]|[ \t]{1,4})[ \t]*)?(?:export[ \t]+|-[ \t]+|\+[ \t]*)?["']?)([\w.\-/@]{1,200})(["']?[ \t]{0,20}(?:=|:(?!\/\/))[ \t]{0,20})([^\r\n]{1,4000})\r?$/dgm,
	)) {
		if (PGPASS.test(m[0])) continue;
		const name = m[2];
		// Trailing blanks and a ` # comment` are cut in code: a regex for them backtracks on long blank runs.
		const raw = m[4].trimEnd();
		// A quoted value keeps its quotes, a JSON line its trailing comma, a `.env` line its ` # comment`; a line of
		// several JSON pairs is left to jsonPairs.
		// (Its quote inside written as YAML and SQL write it, doubled, `'it''s'`, or as a shell does, `'it'\''s'`.)
		const quoted = raw.match(
			/^(["'`])((?:\1\\\1\1|\1\1|\\.|(?!\1|\\).|\\(?=\1(?:[,;]|[ \t]+#.*)?$))*)\1(?:[,;]|[ \t]+#.*)?$/,
		);
		if (!quoted && /^["'`]/.test(raw)) continue;
		let value = quoted ? quoted[2] : raw;
		// An unquoted JSON value (`"token": true, "x": 1`) ends at its delimiter.
		if (!quoted && m[1].endsWith('"')) value = value.replace(/[ \t]*[,}\]][\s\S]*$/, "");
		const comment = quoted ? -1 : value.search(/[ \t]#/);
		if (comment >= 0) value = value.slice(0, comment).trimEnd();
		// (A reference in code, `password: process.env.DB_PASSWORD,` in a line `grep` found in source.)
		if (
			!value ||
			isNotSecret(value) ||
			isCode(value, true) ||
			(value.length >= 8 && !/^\d+$/.test(value) && isPlaceholder(value)) ||
			/^[|>][-+]?$|^[{[]$|^(true|false|null)$/i.test(value) ||
			isSettingNumber(name, value)
		)
			continue;
		const credential =
			isCredentialName(name) ||
			/^pass$/i.test(name) ||
			(/^(?:primary_key|deterministic_key|key_derivation_salt)$/.test(name) &&
				text.includes("active_record_encryption"));
		if (!credential && !isOpaqueSetting(name, value, tokenUnderAnyName)) continue;
		const start = at(m, 4)[0] + (quoted ? 1 : 0);
		out.push({
			start,
			end: start + value.length,
			kind: "secret",
			rule: credential ? "file:named" : "file:opaque",
			name,
			confidence: credential ? 1 : 0.9,
		});
	}
}

/** Table rows, as secret managers print them: `client_secret    abc123` (vault kv get), `│ KEY │ value │` (doppler). */
function tableRows(text: string, out: Finding[]) {
	for (const m of text.matchAll(
		/^(?:[ \t]*[│|┃║][ \t]*|[ \t]*)([\w.\-/@]{1,200})(?:[ \t]{2,}|[ \t]*[│|┃║][ \t]*)([^\s│|┃║](?:[^│|┃║\r\n]{0,4000}?[^\s│|┃║])?)[ \t]*(?:[│|┃║][^\r\n]*)?\r?$/dgm,
	)) {
		const [, name, value] = m;
		if (
			!isCredentialName(name) ||
			isNotSecret(value) ||
			isPlaceholder(value) ||
			/^(true|false|null|n\/a|-+|values?|data|type|description)$/i.test(value) ||
			isSettingNumber(name, value)
		)
			continue;
		out.push({ start: at(m, 2)[0], end: at(m, 2)[1], kind: "secret", rule: "file:table", confidence: 1 });
	}
}

/**
 * JSON pairs anywhere, minified files included: `{"client_secret":"…","refresh_token":"…"}`, `"pin":4821`. Read as pairs,
 * not parsed: a secret file shown by a viewer has its line numbers in front (`     3→  "token": "…",`), and one cut
 * short (`head -c`) isn't a whole document.
 */
function jsonPairs(text: string, out: Finding[]) {
	for (const m of text.matchAll(
		/"([\w.\-]{1,100})"[ \t]*:[ \t]*(?:"((?:[^"\\\n]|\\.){1,4096})"|(-?\d[\d.]{0,40})(?=[ \t]*(?:[,}\]\r\n]|$)))/dg,
	)) {
		const name = m[1];
		const g = m[2] !== undefined ? 2 : 3;
		const value = m[g];
		if (
			!isCredentialName(name) ||
			isNotSecret(value) ||
			(value.length >= 8 && !/^\d+$/.test(value) && isPlaceholder(value)) ||
			/^(true|false|null)$/i.test(value) ||
			isSettingNumber(name, value)
		)
			continue;
		out.push({ start: at(m, g)[0], end: at(m, g)[1], kind: "secret", rule: "file:json", confidence: 1 });
	}
}

/**
 * netrc and space-separated configs: `machine h login u password p`, `requirepass p`. The keyword starts a line or
 * follows another `keyword value` pair; comments and prose (`# the secret is rotated monthly`) are skipped. A shell
 * expansion is read whole, blanks and all (`requirepass ${REDIS_PASSWORD:?set it first}`: a reference, kept).
 */
function spacedKeywords(text: string, out: Finding[]) {
	for (const m of text.matchAll(
		/(?:^[ \t]*|(?:^|[ \t])(?:machine|login|default|account)[ \t]+\S{1,200}[ \t]+)(?:password|passwd|account|secret|token|requirepass|masterauth|rootpw|adminpass)[ \t]+(?:"([^"\n]+)"|'([^'\n]+)'|(\$\{[^{}\n]+\}|[^\s"',;]{1,4096}))/dgim,
	)) {
		const g = m[1] !== undefined ? 1 : m[2] !== undefined ? 2 : 3;
		const v = m[g];
		if (v.length < 4 || isInert(v) || COMMON_WORDS.has(v.toLowerCase())) continue;
		out.push({ start: at(m, g)[0], end: at(m, g)[1], kind: "password", rule: "file:spaced", confidence: 0.95 });
	}
}

/** pgbouncer's userlist: `"user" "password"`. */
function userlist(text: string, out: Finding[]) {
	for (const m of text.matchAll(/^"[^"\n]{1,100}"[ \t]+"([^"\n]{4,500})"/dgm))
		out.push({ start: at(m, 1)[0], end: at(m, 1)[1], kind: "password", rule: "file:userlist", confidence: 0.9 });
}

/** Netscape cookies.txt: the value is the seventh tab-separated field, judged as structure.ts judges a cookie jar's (a session's, not a preference's). */
function cookiesTxt(text: string, out: Finding[]) {
	for (const m of text.matchAll(
		/^(?:#HttpOnly_)?[^\s#][^\t\n]*\t(?:TRUE|FALSE)\t[^\t\n]*\t(?:TRUE|FALSE)\t\d+\t([^\t\n]+)\t([^\t\n]{4,4096})$/dgm,
	)) {
		if (isSessionCookie(m[1], m[2]))
			out.push({ start: at(m, 2)[0], end: at(m, 2)[1], kind: "cookie", rule: "file:cookies", confidence: 0.95 });
	}
}

/** htpasswd: `user:<hash>`. */
function htpasswd(text: string, out: Finding[]) {
	for (const m of text.matchAll(/^[\w.@-]{1,100}:(\$[\w$./+=-]{10,300}|\{SSHA\}[\w+/=]{10,200})[ \t]*$/dgm))
		out.push({ start: at(m, 1)[0], end: at(m, 1)[1], kind: "password hash", rule: "file:hash", confidence: 1 });
}

/**
 * Lines that are one token (a bare token file, `cut -d= -f2` output), after any line number a file viewer puts in
 * front (`cat -n`, an agent's Read tool `     3→`). Not a NAME, an assignment, a comment, a section or a rule, nor
 * a line inside a certificate or public-key block stored next to a private key: those are public.
 */
function bareTokens(text: string, out: Finding[]) {
	const publicBlocks = certificateBlocks(text);
	let block = 0;
	for (const m of text.matchAll(/^[ \t]*(?:\d{1,7}[\t→][ \t]*)?([A-Za-z0-9+/=_.~!@#$%^&*-]{8,})[ \t]*\r?$/dgm)) {
		while (block < publicBlocks.length && publicBlocks[block][1] <= m.index) block++;
		if (block < publicBlocks.length && m.index >= publicBlocks[block][0]) continue;
		const t = m[1];
		if (
			/^[A-Za-z_][A-Za-z0-9_]*$/.test(t) &&
			t === t.toUpperCase() &&
			t
				.split("_")
				.filter(Boolean)
				.every((w) => readsAsWords(w.toLowerCase()) || /^\d+$/.test(w))
		)
			continue;
		// (A name and `=` or `:`; not padded base64, whose `=` pads: `Zm9vYmFyYg==`.)
		if (/^[A-Za-z_][\w.-]{0,80}[ \t]*(?::|=(?!=$))/.test(t) || /^#|^\[|^-{3}/.test(t)) continue;
		if (isInert(t) || (isWordy(t) && naturalness(t) > 0.5) || /^-+$|^=+$|^#|^[+|][-+=|]+$/.test(t)) continue;
		out.push({ start: at(m, 1)[0], end: at(m, 1)[1], kind: "secret", rule: "file:bare", confidence: 0.9 });
	}
}

/** The shapes of line a secret file holds, each read where it is. */
const SECRET_FILE_READERS: ((text: string, out: Finding[], tokenUnderAnyName: boolean) => void)[] = [
	wholeFile,
	pgpassLines,
	assignments,
	tableRows,
	jsonPairs,
	spacedKeywords,
	userlist,
	cookiesTxt,
	htpasswd,
	bareTokens,
];

/**
 * In a secret file, every value under a credential name is hidden whatever it looks like, and so is a
 * line that is a single token (a bare token file, `cut -d= -f2` output); see isOpaqueSetting for other names.
 * `path` is the file's, when known: a file that holds only secrets (`secrets.yml`) hides a generated token under any name.
 */
export function findInSecretFile(text: string, { part = false, path = "" } = {}): Finding[] {
	const out: Finding[] = [];
	const secretsOnly = holdsOnlySecrets(path);
	// (`part`: lines added to a file, `echo x >> .env`, aren't the whole file.)
	for (const read of SECRET_FILE_READERS) if (!(part && read === wholeFile)) read(text, out, secretsOnly);
	return out;
}

/** Spans of public armored blocks (certificates, public keys, parameters, signatures), in order. */
const certificateBlocks = (text: string): [number, number][] => publicBlocks(text).map((b) => [b.start, b.end]);

/**
 * The first line with something on it, its blanks trimmed (`start`, `value`), and where the line ends (`end`). Scanned,
 * not matched: a regex for the trailing blanks backtracks quadratically on a long run of them.
 */
function firstLine(text: string): { start: number; value: string; end: number } {
	let start = 0;
	while (start < text.length && " \t\r\n".includes(text[start])) start++;
	let end = start;
	while (end < text.length && !"\r\n\u2028\u2029".includes(text[end])) end++;
	let stop = end;
	while (stop > start && (text[stop - 1] === " " || text[stop - 1] === "\t")) stop--;
	return {
		start,
		value: text.slice(start, stop),
		end: end + (text[end] === "\r" && (end + 1 === text.length || "\r\n\u2028\u2029".includes(text[end + 1])) ? 1 : 0),
	};
}

/**
 * The credential in the output of a command that prints one: its first line, whole (a passphrase of words, a PIN, a
 * password that starts with `[`), unless the line is a message (`Error: …`), a record's field (`ID:  …`), a reference a
 * variable holds instead (`op://vault/item/field`), a plain URL or address, or a JSON document whole (its pairs'
 * readers judge it); and later
 * lines that are one token, as `pass show` prints its metadata under the password. `--output text` rows of AWS's.
 */
export function findPrintedSecret(text: string): Finding[] {
	const out: Finding[] = [];
	const add = (start: number, end: number) =>
		out.push({ start, end, kind: "credential", rule: "command:prints-secret", confidence: 1 });
	// `--output text` rows: SSM's value follows its type, Secrets Manager's is the fourth field.
	for (const m of text.matchAll(
		/^(?:PARAMETER\t[^\n]*?\t(?:SecureString|String|StringList)\t([^\t\n]+)\t\d+|arn:aws:secretsmanager:[^\t\n]+\t[^\t\n]*\t[^\t\n]*\t([^\t\n]+)(?:\t[^\n]*)?)\r?$/dgm,
	)) {
		const [start, end] = at(m, m[1] !== undefined ? 1 : 2);
		add(start, end);
	}
	if (out.length) return out;
	// (A `Name: value` line is a record's field, `op item get`'s `ID:  …`: its fields are read by name.)
	// (A path is where a credential is, not one: `GOOGLE_APPLICATION_CREDENTIALS=/workspace/secrets/sa.json`.)
	const notSecret = (line: string) =>
		isInert(line) ||
		isPath(line.replace(/^[A-Za-z_][\w.-]*=/, "")) ||
		/^[A-Za-z][\w .-]{0,30}:[ \t]/.test(line) ||
		/^(?:error|warning|usage|fatal|note|hint)\b/i.test(line) ||
		/^[\w.+-]+@[\w-]+(?:\.[\w-]+)+$/.test(line) ||
		isPasswordlessUrl(line) ||
		isJsonDocument(line);
	const first = firstLine(text);
	const firstEnd = first.end;
	// (A value printed as a JSON string is judged as what it holds, and hidden inside its quotes.)
	const firstValue = jsonString(first.value) ?? first.value;
	const quote = firstValue === first.value ? 0 : 1;
	if (firstValue && !notSecret(firstValue) && !/^[{[]$/.test(firstValue) && readsAsValue(firstValue))
		add(first.start + quote, first.start + first.value.length - quote);
	for (const m of text.slice(firstEnd).matchAll(/^[ \t]*(\S{6,})[ \t]*\r?$/dgm)) {
		const value = jsonString(m[1]) ?? m[1];
		const q = value === m[1] ? 0 : 1;
		// (A message's tokens are not values; `[`/`{` start a JSON document's lines.)
		if (isMessageToken(value) || /^[{[]/.test(value) || notSecret(value)) continue;
		add(firstEnd + at(m, 1)[0] + q, firstEnd + at(m, 1)[1] - q);
	}
	return out;
}

/**
 * The shape of a CLI's message rather than a value: it opens with a message's word (`no oauth token found`, `Error …`,
 * `Please run …`), says something isn't (`You are not logged into …`, `token does not exist`), or ends on what
 * happened (`Permission denied`, `An error occurred`). A message word elsewhere in the line is just a word:
 * `correct horse no battery staple` is a passphrase.
 */
const MESSAGE_SHAPE =
	/^(?:no|not|error|errors|failed|failure|invalid|unable|cannot|can't|couldn't|please|run|missing|unauthorized|forbidden)\b|\b(?:is|are|was|were|do|does|did|has|have|can|could|will|must)(?:n't| not)\b|\b(?:found|denied|expired|occurred|exists?|failed)$/i;

/**
 * One token that is a message's, not a value: a label (`Error:`), a status word with its stop (`Done.`, `Saved!`), or
 * a word with a message's shape (`Unauthorized`, `expired`). A letters-only word otherwise is a value, with a password's
 * own stop too (`monkeykingdom`, `sunshine!`, `letmein.`).
 */
const isMessageToken = (token: string): boolean =>
	/^\p{L}+:$/u.test(token) ||
	/^(?:done|ok|okay|success|succeeded|saved|copied|deleted|removed|updated|created|finished|complete|completed|ready|aborted|cancell?ed|warning)[.!]$/i.test(
		token,
	) ||
	MESSAGE_SHAPE.test(token);

/**
 * Whether a credential command's first line reads as the value it prints, not a sentence about it: one token, or a
 * passphrase's words (up to 24, no sentence punctuation, not a message's shape).
 */
function readsAsValue(line: string): boolean {
	if (!/\s/.test(line)) return !isMessageToken(line);
	const words = line.split(/\s+/);
	return words.length <= 24 && words.every((w) => /^[\p{L}\p{N}-]+$/u.test(w)) && !MESSAGE_SHAPE.test(line);
}

/**
 * Whether a line is a JSON document whole: an object, an array, or a string that holds one (output encoded once more,
 * `--query SecretString`'s `"{\"password\": …}"`). A string that holds anything else is a value (jsonString).
 */
function isJsonDocument(line: string): boolean {
	if (!/^(?:[{[].*[}\]]|".*")$/.test(line)) return false;
	try {
		const v = JSON.parse(line);
		return typeof v !== "string" || isJsonDocument(v.trim());
	} catch {
		return false;
	}
}

/** What a line that is one JSON string holds (`az … --query value` prints its value so, `"…"`), or undefined. */
function jsonString(line: string): string | undefined {
	if (!/^".+"$/.test(line)) return undefined;
	try {
		const v = JSON.parse(line);
		return typeof v === "string" ? v : undefined;
	} catch {
		return undefined;
	}
}

/** Prompt lines: a terminal prompt (shell.ts PROMPT) at a line's start, before a command. */
const PROMPT_LINES = new RegExp(PROMPT.source, "gm");
/** In a document, a code fence closes the session it shows: what follows isn't the last command's output. */
const FENCE = /^[ \t]*(?:```|~~~)/m;
/**
 * The commands a notebook cell runs with a bare `!` (`!cat .env`, `!pip install …`): a `!` line is a prompt only before
 * one of them, as a value (`!qaz2wsx`) or a MySQL option file's `!include` isn't.
 */
const NOTEBOOK_COMMAND =
	/^!(?:cat|head|tail|less|more|grep|ls|echo|printf|env|printenv|export|pip3?|python3?|conda|git|curl|wget|cd|sudo|bash|sh|source|type|sops|op|docker|kubectl|gcloud|aws|az|npm|apt(?:-get)?|which|find|wc|unzip|mkdir|rm|cp|mv)\b/;

/** The prompt lines of a text: where each starts and ends, and its command. */
function promptLines(text: string): { start: number; end: number; command: string }[] {
	return [...text.matchAll(PROMPT_LINES)]
		.filter((m) => !/^[ \t]*!/.test(m[0]) || NOTEBOOK_COMMAND.test(m[0].trimStart()))
		.map((m) => ({ start: m.index, end: m.index + m[0].length, command: m[1] }));
}

/**
 * Where the first prompt line inside a command's output starts (a later command), or its length if none. (Not a `!`
 * line: in a command's output that is a value or an option file's directive, not a notebook's command.)
 */
export function firstPrompt(text: string): number {
	return (
		promptLines(text).find((p) => p.start > 0 && !/^[ \t]*!/.test(text.slice(p.start, p.end)))?.start ?? text.length
	);
}

/**
 * Command transcripts inside a text (a notebook's `!cat .env`, a pasted terminal session's
 * `$ cat ~/.aws/credentials`): the output under a prompt that prints a secret file, up to the next
 * prompt or a closing fence, is treated as that file.
 */
export function findEmbeddedOutputs(text: string): Finding[] {
	const out: Finding[] = [];
	for (const { command, start, end } of commandOutputs(text)) {
		const credential = printsSecret(command);
		if (!credential && !printsSecretFile(command)) continue;
		const body = text.slice(start, end);
		for (const f of credential ? findPrintedSecret(body) : findInSecretFile(body))
			out.push({ ...f, start: f.start + start, end: f.end + start });
	}
	return out;
}

/** Each prompt's command and its output: the lines after it, up to the next prompt or a code fence. */
function commandOutputs(text: string): { command: string; prompt: number; start: number; end: number }[] {
	const prompts = promptLines(text);
	return prompts.map((p, i) => {
		const start = Math.min(text.length, p.end + 1);
		let end = i + 1 < prompts.length ? prompts[i + 1].start : text.length;
		const fence = text.slice(start, end).search(FENCE);
		if (fence >= 0) end = start + fence;
		return { command: p.command.slice(0, 2000), prompt: p.start, start, end: Math.max(start, end) };
	});
}

export interface FileSection {
	start: number;
	end: number;
	/** Lines added to a file (`>>`, `tee -a`, one of a group's writes) are part of it, not all of it. */
	part: boolean;
}

/**
 * Where a secret file's content sits inside a text, as [start, end) spans, in order and apart:
 * - a diff of one (`git diff` of `.env.production`): its hunks, once normalization has removed their markers;
 * - what a command line writes into one (commands.ts commandsRun reads it, through `sudo sh -c`, `ssh`, a prompt): a
 *   heredoc's body (`cat > .env <<'EOF'`, `sudo tee .env > /dev/null <<EOF`, `cat <<EOF | tee .env`), a here-string
 *   (`tee .env <<< "…"`), or `echo`'s and `printf`'s operands (`echo 'Harbor#2291x' > ~/.vault_pass`,
 *   `{ echo A=1; echo B=2; } > .env`).
 * Not a SOPS file, encrypted by design. A command line inside an earlier heredoc's body is that body's text.
 */
export function secretFileSections(text: string): FileSection[] {
	return readWrites(text).sections;
}

/** A heredoc still open at the end of a text, and the secret file it writes, if it writes one. */
interface OpenHeredoc {
	heredoc: Heredoc;
	file?: string;
}

/** The secret files' sections of a text (secretFileSections), and the heredocs open at its end that write one. */
function readWrites(text: string): { sections: FileSection[]; open: OpenHeredoc[]; diff?: string } {
	const sections: FileSection[] = [];
	// (Where a `sops:` line starts, found once: a heredoc that never ends reaches the text's end, and slicing to it per line is quadratic.)
	let sops: number[] | undefined;
	const holdsSops = ({ start, end }: FileSection) => {
		sops ??= [...text.matchAll(/^sops:/gm)].map((m) => m.index);
		return text.startsWith("sops:", start) || sops[lowerBound(sops, start)] < end;
	};
	const add = (section: FileSection) => {
		if (section.end > section.start && !holdsSops(section)) sections.push(section);
	};
	let diff: string | undefined;
	if (/^\+\+\+ /m.test(text)) {
		// A diff's file headers and the lines that end a file's hunks, in order: each section is read once. The file is
		// named on either side: `+++ b/.env`, or `--- a/.env` above `+++ /dev/null` when the diff deletes it.
		const marks = [...text.matchAll(/^(?:\+\+\+ (?:b\/)?(\S+)[^\n]*\n|diff --git |--- (?:a\/)?(\S+)|Index: )/gm)];
		marks.forEach((h, k) => {
			const file = h[1] === "/dev/null" ? marks[k - 1]?.[2] : h[1];
			if (file === undefined || !isSecretFile(file)) return;
			const from = h.index + h[0].length;
			const to = marks[k + 1]?.index ?? text.length;
			// (Only once its markers are gone.)
			if (!/^[+-]/m.test(text.slice(from, to).replace(/^@@[^\n]*\n/gm, ""))) add({ start: from, end: to, part: false });
			if (to === text.length) diff = file;
		});
	}
	let open: OpenHeredoc[] = [];
	if (/<<|\b(?:echo|printf|tee)\b/.test(text)) {
		const lines = /<</.test(text) ? new LineIndex(text) : undefined;
		let body = 0;
		for (const line of text.matchAll(/^[^\n]*(?:<<|\b(?:echo|printf|tee)\b)[^\n]*$/gm)) {
			if (line.index < body) continue;
			const commands = commandsRun(text, { at: line.index, oneLine: true, lines });
			const writes = writtenToSecretFile(commands);
			for (const w of writes.sections) add(w);
			const heredocs = commands.flatMap((c) => c.heredocs);
			// (A finished heredoc's body is text, whatever the heredoc writes to; one that never ends is read as text.)
			for (const h of heredocs) if (h.terminated) body = Math.max(body, h.end);
			if (heredocs.some((h) => !h.terminated && writes.files.has(h)))
				open = heredocs.filter((h) => !h.terminated).map((h) => ({ heredoc: h, file: writes.files.get(h) }));
		}
	}
	// (In order and apart: a section inside or overlapping the one kept before it is dropped.)
	const apart: FileSection[] = [];
	for (const section of sections.sort((a, b) => a.start - b.start))
		if (section.start >= (apart.at(-1)?.end ?? 0)) apart.push(section);
	return { sections: apart, open, diff };
}

/**
 * The scopes still open at the end of a text, as the lines that open them, in order: a secret file's diff that runs to
 * the end (its `+++` line and a hunk header), heredocs that write one and haven't ended (their command lines, made minimal, with any
 * heredoc before them that is open too), or else the last prompt's command line, while no code fence has closed its
 * output. Text that continues this one (a stream's next chunk) is read as it would be with these lines in front of it.
 */
export function openScopes(text: string): string[] {
	const { open, diff } = readWrites(text);
	const out: string[] = [];
	// (With a hunk header that runs on, so normalization takes the markers off the hunk lines that follow.)
	if (diff) out.push(`+++ b/${diff}\n@@ -1,1000000 +1,1000000 @@\n`);
	if (open.length) {
		const last = open.findLastIndex((o) => o.file !== undefined);
		out.push(
			`${open
				.slice(0, last + 1)
				.map(({ heredoc: h, file }) => `cat${file ? ` > '${file}'` : ""} <<${h.strip ? "-" : ""}'${h.delimiter}'`)
				.join("; ")}\n`,
		);
	} else {
		const last = commandOutputs(text).at(-1);
		if (last && last.end === text.length) out.push(`$ ${last.command}\n`);
	}
	return out;
}

/** Descriptor targets of a redirection (`2>&1`, `>&-`): not files. */
const DESCRIPTOR = /^(?:\d+|-)$/;

/**
 * What the pipelines of a command line write into a secret file: their heredocs' bodies and here-strings, or what
 * they echo; and the file each heredoc writes.
 */
function writtenToSecretFile(commands: CommandRun[]): { sections: FileSection[]; files: Map<Heredoc, string> } {
	const sections: FileSection[] = [];
	const files = new Map<Heredoc, string>();
	let pipeline: CommandRun[] = [];
	for (let k = 0; k < commands.length; k++) {
		const c = commands[k];
		pipeline.push(c);
		if ((c.then === "|" || c.then === "|&") && commands[k + 1]?.host === c.host) continue;
		// Where it writes: a redirection's file (`>`, `>>`, `>|`, `&>`, `>&`), its groups' included, and `tee`'s.
		const targets = pipeline.flatMap((p) => {
			const words = simpleCommand(p.words);
			const tee = programName(words[0]) === "tee" ? words.slice(1) : [];
			const append = tee.some((w) => /^-\w*a|^--append$/.test(w.text));
			const redirected = allRedirects(p).filter(
				(r) => r.target && (/^(?:>|>>|>\||&>|&>>)$/.test(r.op) || (r.op === ">&" && !DESCRIPTOR.test(r.target.text))),
			);
			return [
				...redirected.map((r) => ({ file: r.target!.text, append: r.op.endsWith(">>") })),
				...tee.filter((w) => !w.text.startsWith("-")).map((w) => ({ file: w.text, append })),
			];
		});
		const written = targets.filter(({ file }) => isSecretFile(file.replace(/^~[/\\]/, "")));
		if (written.length) {
			// (One of a group's several writes is part of the file: `{ echo A=1; echo B=2; } > .env`.)
			const grouped = pipeline[0].groups.some(
				(g) => g.redirects.length && commands.filter((x) => x.groups.includes(g)).length > 1,
			);
			const part = grouped || written.every((f) => f.append);
			// What: the pipeline's heredocs and here-strings, or the first stage's echo or printf operands (printf's after its format).
			for (const p of pipeline) {
				for (const h of p.heredocs) {
					sections.push({ start: h.start, end: h.end, part });
					files.set(h, written[0].file);
				}
				for (const r of p.redirects) if (r.op === "<<<" && r.target) sections.push({ ...wordSpan(r.target), part });
			}
			const first = simpleCommand(pipeline[0].words);
			const program = programName(first[0]);
			if (program === "echo" || program === "printf") {
				const args = first.slice(1).filter((w) => !/^-[neE]+$/.test(w.text));
				const operands = program === "printf" && args.length > 1 ? args.slice(1) : args;
				for (const w of operands) if (w.text) sections.push({ ...wordSpan(w), part });
			}
		}
		pipeline = [];
	}
	return { sections, files };
}
