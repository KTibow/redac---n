/**
 * Secrets recognizable by the structure around them rather than their own format: private key
 * blocks, passwords in URLs, Authorization headers, cookies, passwords in connection strings, and
 * signatures in signed URLs. Each is a secret wherever it appears.
 */
import { base64Binary } from "./base64.ts";
import { isDerPrivateKey, isPublicPem } from "./publickeys.ts";
import { sha256 } from "./hmac.ts";
import { lineEnd, lineStart } from "./lines.ts";
import { armoredBlocks, pemTail } from "./pem.ts";
import { inJwk, jsonDocuments, type JsonNode } from "./json.ts";
import { blockLines, siblingValue, yamlLines } from "./yaml.ts";
import { isUrl, queryParams, readUserinfo, URL_SCHEME, urls } from "./urls.ts";
import { naturalness } from "./charlm.ts";
import { bip39, isNamedSecret } from "./named.ts";
import { FILE_EXTENSION, isCredentialName, isSettingName, nameClass, namesPasswordOrPin } from "./names.ts";
import {
	ANALYTICS_COOKIE,
	COMMON_WORDS,
	isCode,
	isIdentifierShaped,
	isInert,
	isNameLike,
	isRandomToken,
	isTestValue,
	isWordsValue,
	PASSWORD_HASH_IN_TEXT,
	readsAsWords,
} from "./values.ts";
import { isPlaceholder } from "./public.ts";
import {
	isWrapper,
	programName,
	type ShellCommand,
	type ShellWord,
	shellWords,
	simpleCommand,
	wordSpan,
} from "./shell.ts";
import { commandAt, commandsRun, passwordOptions, SHELL } from "./commands.ts";
import { type Span, stringEnd } from "./syntax.ts";
import type { Finding } from "./types.ts";

/** The labels of private key blocks, and of the OpenVPN static key. */
const PRIVATE_LABEL = /^(?:[A-Z0-9]+ ){0,4}PRIVATE KEY(?: BLOCK)?$|^OpenVPN Static key V1$/;
/** An END line of a private key's armor, PEM's or RFC 4716's. */
const PRIVATE_END = /-{4,5} ?END (?:[A-Z0-9]+ ){0,4}PRIVATE KEY(?: BLOCK)? ?-{4,5}/g;

/**
 * Private key blocks (pem.ts reads them): from BEGIN to END, or to the last line of material when output stops early,
 * and from the material above END when it starts late. A BEGIN with no material after it (a string constant in code)
 * is not a key.
 */
function privateKeys(text: string, out: Finding[]) {
	if (!text.includes("PRIVATE KEY") && !text.includes("BEGIN ")) return;
	// (A private key's DER under another label, `PUBLIC KEY` or `CERTIFICATE`, is a private key: its body says so.)
	const blocks = armoredBlocks(text)
		.filter(
			(b) =>
				b.material >= 64 &&
				(PRIVATE_LABEL.test(b.label) || isDerPrivateKey(armoredBase64(text.slice(b.labelEnd, b.end)))),
		)
		.map(({ start, end }) => ({ start, end }));
	// The end of a key whose BEGIN line was cut off (`tail -5 server.key`), in order with the blocks read whole.
	let k = 0;
	for (const m of text.matchAll(PRIVATE_END)) {
		while (k < blocks.length && blocks[k].end < m.index) k++;
		if (k < blocks.length && blocks[k].start <= m.index) continue;
		const { start, material } = pemTail(text, m.index);
		if (material >= 64) blocks.splice(k, 0, { start, end: m.index + m[0].length });
	}
	for (const b of blocks) out.push({ ...b, kind: "private key", rule: "structure:private-key", confidence: 1 });
}

/** The base64 of an armored block's body: its material lines' characters, past any `Name: value` headers. */
function armoredBase64(body: string): string {
	return body
		.split(/\r?\n|\\r\\{1,2}n|\\{1,2}n/)
		.filter((line) => !line.includes(":"))
		.join("")
		.replace(/[^A-Za-z0-9+/=]/g, "");
}

/** PuTTY private keys: the `Private-Lines:` section. OpenSSL `-text` dumps: `priv:` and prime sections. */
function otherPrivateKeys(text: string, out: Finding[]) {
	if (text.includes("Private-Lines:")) {
		for (const m of text.matchAll(/Private-Lines: \d{1,3}\r?\n((?:[A-Za-z0-9+/=]{4,80}(?:\r?\n|$)){1,200})/g)) {
			const start = m.index + m[0].length - m[1].length;
			out.push({
				start,
				end: start + m[1].trimEnd().length,
				kind: "private key",
				rule: "structure:putty-key",
				confidence: 1,
			});
		}
	}
	if (/priv(?:ate)?|prime|exponent|coefficient/i.test(text)) {
		for (const m of text.matchAll(
			/^[ \t]{0,20}(?:priv(?:ate)?(?:[- ]?key)?|privateExponent|prime[12]|exponent[12]|coefficient|d)[ \t]{0,20}:[ \t]{0,20}\r?\n((?:[ \t]{1,20}(?:[0-9a-f]{2}:){1,40}[0-9a-f]{0,2}[ \t]{0,20}(?:\r?\n|$)){1,200})/gim,
		)) {
			const start = m.index + m[0].length - m[1].length;
			out.push({
				start,
				end: start + m[1].trimEnd().length,
				kind: "private key",
				rule: "structure:key-dump",
				confidence: 1,
			});
		}
	}
	// A JWK private key: `"d": "<base64url>"` in an object with a `kty`, in JSON or a JS or Python literal
	// (`{ kty: "OKP", d: "…" }`): key material by its place, unless it is words (a docs' `"d": "private-exponent"`).
	if (/\bkty["']?[ \t]*:/.test(text)) {
		for (const m of text.matchAll(
			/(?<![\w$])["']?(?:d|p|q|dp|dq|qi|k)["']?[ \t]*:[ \t]*["']([A-Za-z0-9_-]{16,})["']/dg,
		)) {
			const [start, end] = m.indices![1]!;
			if (!inJwk(text, start, end) || isWordsValue(m[1])) continue;
			out.push({ start, end, kind: "private key", rule: "structure:jwk", confidence: 0.95 });
		}
	}
}

/** A name in docs' brackets: `<password>`, `[YOUR_PASSWORD]`, `{db pass}`; not a password left in them, `<Harbor2291x>`. */
function isBracketedName(value: string): boolean {
	const inner = /^[[{(<]+([\w -]{1,40})[\]})>]+$/.exec(value)?.[1];
	return (
		inner !== undefined &&
		inner
			.split(/[ -]+/)
			.filter(Boolean)
			.every((w) => isNameLike(w))
	);
}

/** A password the way docs write one: `password`, `[password]`, `<password>`, `thepassword`, `password_test`. */
function isDocsPassword(value: string): boolean {
	// (Every word a password word or a docs' word: `thepassword`, `my_secret`, `password_test`; not a passphrase that
	// ends in one, `Lunar-Tiger-Velvet-Pass`, `FluffyBunnyPassword`.)
	if (isBracketedName(value) || /^(?:pass|password|passwd|pwd|secret|changeme|test|foo|bar)$/i.test(value)) return true;
	const words = value.split(/[_-]|(?<=[a-z])(?=[A-Z])/).map((w) => w.toLowerCase());
	const PW = /^(?:the|my|your|our|some|other|test|real|really|dummy|fake|super)?(?:pass(?:word|wd)?|pwd|secret)$/;
	return (
		words.some((w) => PW.test(w)) &&
		words.every(
			(w) =>
				PW.test(w) ||
				/^(?:the|my|your|some|other|test|tests|real|really|dummy|fake|super|secret|user|admin|example|sample|db|database|app|api|root)$/.test(
					w,
				),
		)
	);
}

/**
 * Whether a URL's password field (or a command line's password) holds a password rather than a variable, format
 * specifier or placeholder. `quoted`: the value sat in single quotes, where a shell expands nothing (`-p'$mIWy…'`
 * is a literal).
 */
export function isLiteralPassword(value: string, quoted = false): boolean {
	if (!value || value.length < 3 || (!quoted && isInert(value)) || isPlaceholder(value) || isUrl(value)) return false;
	// A hole of an interpolated string, whole: `{quote_plus(password)}`, Swift's `\(password)`, `{Uri.EscapeDataString(pw)}`.
	if (/^\{[^{}\n]{1,200}\}$|^\\\([^()\n]{1,200}\)$/.test(value) && /[A-Za-z_]/.test(value)) return false;
	// `$DB_PASSWORD`-style names, a letter in each part, not all-caps passwords like `WINTER2024PASS`, `SUMMER_2024`
	// or `WINTERPASS` (a placeholder word in capitals is read below). (Templates with holes, `${DB_PASS}`, `{{ pw }}`,
	// `<password>`, are placeholders above when nothing secret is around their holes.) A `$(…)` even in single quotes:
	// a Makefile's `-p'$(DB_PASSWORD)'` is make's variable, expanded before the shell runs.
	if (
		/^[A-Z]+(?:_[A-Z0-9]*[A-Z][A-Z0-9]*)+$|^_[A-Z0-9_]+$/.test(value) ||
		(!quoted && /^\$[A-Za-z_]\w*$/.test(value)) ||
		/^\$\(.*\)$/.test(value) ||
		(/^[a-z_][A-Za-z_]{2,}\(.*\)$/.test(value) && readsAsWords(value.slice(0, value.indexOf("("))))
	)
		return false;
	// Default credentials docs and images use (`postgres`, `guest`, `rabbitmq`), and docs' placeholders (isDocsPassword).
	if (
		/^(?:user|username|token|credentials|pw|example|postgres|root|admin|guest|mysql|redis|rabbitmq|baz|qux)$/i.test(
			value,
		)
	)
		return false;
	return !isDocsPassword(value);
}

/** A Go MySQL DSN's user and its `:`, after a scheme or not (`mysql://root:`, `root:`). */
const DSN_USER = new RegExp(String.raw`(?<![\w/:@.-])(?:${URL_SCHEME}:\/\/)?([\w.-]{1,64}):(?!\/\/)`);

function urlCredentials(text: string, out: Finding[]) {
	// Go's MySQL DSN: `root:pw@tcp(127.0.0.1:3306)/db`, `user:pw@unix(/tmp/mysql.sock)/db`, after a scheme or not
	// (`mysql://root:@tcp(…)`, whose password is empty). The userinfo reads as a URL's, with `tcp(` as the host.
	// (From the start of the word, or the end of the DSN before it in the word: its userinfo is read whole, however long,
	// and each stretch once.)
	let previous = 0;
	for (const m of text.matchAll(/@(?:tcp|unix)\(/g)) {
		let from = m.index;
		while (from > previous && !/[\s'"`]/.test(text[from - 1])) from--;
		previous = m.index + m[0].length;
		const user = DSN_USER.exec(text.slice(from, m.index));
		if (!user) continue;
		const at = from + user.index + user[0].length - user[1].length - 1;
		const info = readUserinfo(text.slice(at, m.index + 4), 0, /\(/);
		if (!info || info.passwordStart < 0 || at + info.end !== m.index) continue;
		const pw = text.slice(at + info.passwordStart, m.index);
		if (pw.length >= 3 && isLiteralPassword(pw))
			out.push({
				start: at + info.passwordStart,
				end: m.index,
				kind: "password",
				rule: "structure:url-password",
				confidence: 0.98,
			});
	}
	if (!text.includes("://")) return;
	for (const url of urls(text)) {
		const { user, password: pw, host } = url;
		if (!user || !host) continue;
		// A token as the whole user part: `https://<token>@github.com`, Azure DevOps PATs, `https://x-access-token:<token>@`,
		// whatever the host (`@${GIT_HOST}`). (With a password, the user is a name unless the password is empty, as curl's
		// `-u <token>:` writes it, or a fixed word: `<token>:x-oauth-basic@`.)
		if (
			/^[A-Za-z0-9_-]{20,}$/.test(user.value) &&
			(!pw?.value || pw.value === user.value || FIXED_PASSWORD.test(pw.value))
		) {
			// Sentry DSNs carry a public key by design (`<key>@o123.ingest.sentry.io`).
			const hostname = /^[\w.-]{0,200}/.exec(host.value)![0];
			const sentry = /(?:^|\.)(?:sentry\.io|ingest\.[\w.]+|sentry\.[\w.]+)$/.test(hostname);
			if (!sentry && isRandomToken(user.value, 20) && !isIdentifierShaped(user.value))
				out.push({
					start: user.start,
					end: user.end,
					kind: "token",
					rule: "structure:url-user-token",
					confidence: 0.9,
				});
		}
		// A password (urls.ts reads where it ends: it may hold `@` and `/`, the user may be a service account's email), and
		// the host may be empty (`snowflake://USER:pw@/DB?account=…`), the password a docs' `<password>` filled in
		// (`mongodb+srv://admin:<Harbor2291x>@…`).
		if (!pw) continue;
		// (A password that is the user name, `tally:tally@`, tells nothing the name doesn't, unless both are a token.)
		if (
			!isLiteralPassword(pw.value) ||
			FIXED_PASSWORD.test(pw.value) ||
			(pw.value === user.value && !isRandomToken(pw.value))
		)
			continue;
		out.push({ start: pw.start, end: pw.end, kind: "password", rule: "structure:url-password", confidence: 0.98 });
	}
}

/** Passwords that forges and registries take beside a token in the user part: `<token>:x-oauth-basic@github.com`. */
const FIXED_PASSWORD = /^(?:x-oauth-basic|x-access-token|oauth2|x-token-auth|token)$/i;

/** Authorization schemes whose name says what the credential is, for its placeholder. */
const AUTH_SCHEMES =
	/^(?:Bearer|Basic|Token|Bot|Digest|ApiKey|Api-Key|SSWS|OAuth|JWT|DPoP|Splunk|GenieKey|Klaviyo-API-Key|Key|sso-key|Negotiate|NTLM|SharedKey|Client-ID)$/i;

/**
 * What an Authorization header holds in code, configs and docs rather than a credential, by what it is. (Quotes,
 * brackets and sentence punctuation around the value aside.)
 */
const NOT_AN_AUTHORIZATION: [what: string, test: (v: string) => boolean][] = [
	// `authorization: "https://…/authorize"` in an OAuth provider's config.
	["an endpoint", (v) => /^https?:\/\//.test(v)],
	// `authorization: config.authHeader`, Swift's `authorization: Mastodon.API.OAuth.Authorization`.
	["a member or type path", (v) => /^[A-Za-z_$][\w$]{0,40}(?:\.[A-Za-z_$][\w$]{0,40}){1,6}$/.test(v) && isNameLike(v)],
	["too short", (v) => v.length < 6],
	["inert", isInert],
	["a test value", isTestValue],
	["identifier-shaped", isIdentifierShaped],
	["code", (v) => /[[\]()<>{}]/.test(v)],
	["a placeholder", isPlaceholder],
	["a constant's name", (v) => /^[A-Z][A-Z_]{2,}$|^[A-Z][A-Z0-9]*_[A-Z0-9_]+$/.test(v)],
	["a template's hole", (v) => /^\$[A-Za-z_]\w*$|\$\{\w[\w:-]*\}|\{\{[^{}]*\}\}|^%[sdv]$|^<[^<>]*>$/.test(v)],
	// `"Bearer " + token`: a name and the `+` that joins it (not base64's own last `+`).
	["a concatenation", (v) => /^[A-Za-z_$][\w$.]*\+$/.test(v) && isNameLike(v.slice(0, -1))],
	// `Authorization: required`, `Bearer realm`.
	["words", isWordsValue],
];

function isAuthorizationLiteral(raw: string): boolean {
	const value = raw.replace(/^[`'"(\[]+|[`'")\].,;:]+$/g, "");
	return !NOT_AN_AUTHORIZATION.some(([, test]) => test(value));
}

/** The value after a scheme in an Authorization header or a bare `Bearer`/`Basic` token. */
function authorization(text: string, out: Finding[]) {
	if (!/auth|bearer|basic|token |bot |apikey|ssws|Signature=/i.test(text)) return;
	// `Authorization: Bearer x`, `"authorization": "Token x"`, `-H 'Authorization: Basic x'`, `Proxy-Authorization:`: as RFC 7235
	// has it, a scheme (any token: `Negotiate`, `NTLM`, `Zoho-oauthtoken`, `SharedKey`) and its credential, or a
	// credential alone (`authorization: <token>` in a config).
	// (A path's `::` is no separator: `windows_sys::Win32::Security::Authorization::GetNamedSecurityInfoW`.)
	for (const m of text.matchAll(
		/(?:\b|(?<=\\[nrt]))(?<!::)(?:Proxy-)?Authorization["']?[ \t]{0,10}(?:=|,|:(?!:))[ \t]{0,10}["']?([!#$%&'*+.^_`|~0-9A-Za-z-]{1,40}[ \t]{1,10}(?=[^\s"',;\\]))?([^\s"',;\\]{1,4096})/dgi,
	)) {
		const scheme = m[1]?.trim();
		const end = m.index + m[0].length;
		// OAuth 1 and MAC headers are `k="v"` and `k=v` lists (`k=\"v\"` inside a JSON string); their secret parts are
		// named and caught by name: a `k=` is theirs when a quoted value follows it. Base64 ending in `=` padding is a
		// credential, the quote after it the string's end (`-H 'Authorization: Basic ZGV2OlhrOWYycFE='`).
		if (
			/^[\w-]+=[^=]/.test(m[2]) ||
			(/^[\w-]+=$/.test(m[2]) && /^\\?["'][^\s"'\\,;)\]}]/.test(text.slice(end, end + 3))) ||
			!isAuthorizationLiteral(m[2])
		)
			continue;
		if (/^aws4-hmac/i.test(scheme ?? "")) continue; // handled by the Signature= rule
		// Closing quotes, brackets and sentence punctuation aren't part of the value.
		let value = m[2].replace(/[`'")\].,;:]+$/, "");
		let start = m.indices![2]![0];
		if (/^basic$/i.test(scheme ?? "") && isPlaceholderBasic(value)) continue;
		// Azure's `SharedKey <account>:<signature>`: the account is a name.
		const account = /^SharedKey(?:Lite)?$/i.test(scheme ?? "") ? /^[\w-]{1,64}:/.exec(value)?.[0] : undefined;
		if (account) {
			start += account.length;
			value = value.slice(account.length);
		}
		out.push({
			start,
			end: start + value.length,
			kind: scheme && AUTH_SCHEMES.test(scheme) ? `${scheme.toLowerCase()} credential` : "authorization",
			rule: "structure:authorization",
			confidence: 0.97,
		});
	}
	for (const m of text.matchAll(/\b(Bearer|Basic|Token|Bot)[ \t]{1,10}([A-Za-z0-9._~+/-]{16,4096}={0,2})/g)) {
		if (!isAuthorizationLiteral(m[2]) || naturalness(m[2]) > 0.8) continue;
		if (m[1] === "Basic" && isPlaceholderBasic(m[2])) continue;
		const start = m.index + m[0].length - m[2].length;
		out.push({
			start,
			end: start + m[2].length,
			kind: `${m[1].toLowerCase()} token`,
			rule: "structure:bearer",
			confidence: m[1] === "Token" || m[1] === "Bot" ? 0.8 : 0.95,
		});
	}
	// AWS SigV4's request signature, in the header and the query. (The credential scope's key ID is an AKIA… format.)
	for (const m of text.matchAll(/(?<![\w-])Signature=([a-f0-9]{64})\b/g)) {
		const start = m.index + m[0].length - m[1].length;
		out.push({ start, end: start + m[1].length, kind: "request signature", rule: "structure:sigv4", confidence: 0.9 });
	}
}

/** SMTP `AUTH PLAIN <base64>` and the base64 lines after `AUTH LOGIN`, as a mail client's debug output shows them. */
function smtpAuth(text: string, out: Finding[]) {
	// (Or the password's prompt alone: a log excerpt that starts there, `grep -A1 '334 UGFzc3dvcmQ6' maillog`.)
	if (!/AUTH[ \t]+(?:PLAIN|LOGIN)|334[ \t]+UGFzc3dvcmQ6/i.test(text)) return;
	for (const m of text.matchAll(/AUTH[ \t]+PLAIN[ \t]+([A-Za-z0-9+/]{8,4096}={0,2})/gi)) {
		const start = m.index + m[0].length - m[1].length;
		out.push({
			start,
			end: start + m[1].length,
			kind: "SMTP credentials",
			rule: "structure:smtp-auth",
			confidence: 0.95,
		});
	}
	// The base64 line answering `334 UGFzc3dvcmQ6` ("Password:"), or `334` after a bare `AUTH PLAIN`, with any
	// `C: `, `-> ` or timestamp prefix (swaks, a client's debug log).
	for (const m of text.matchAll(
		/(?:334[ \t]+UGFzc3dvcmQ6|AUTH[ \t]+PLAIN[ \t]*\r?\n[^\n]{0,40}334[ \t]*)[^\n]{0,400}\r?\n[^\n]{0,40}?(?:->|C:|>)?[ \t]*([A-Za-z0-9+/]{4,4096}={0,2})[ \t]*\r?$/gim,
	)) {
		const start = m.index + m[0].lastIndexOf(m[1]);
		out.push({
			start,
			end: start + m[1].length,
			kind: "SMTP credentials",
			rule: "structure:smtp-auth",
			confidence: 0.95,
		});
	}
}

/** What `vault operator init` prints: unseal and recovery keys, and the initial root token. */
function vaultInit(text: string, out: Finding[]) {
	if (!/Unseal Key|Recovery Key|Initial Root Token/.test(text)) return;
	for (const m of text.matchAll(
		/^[ \t]*(?:Unseal Key \d+|Recovery Key \d+|Initial Root Token):[ \t]*(\S{8,})[ \t]*\r?$/gm,
	)) {
		const start = m.index + m[0].indexOf(m[1], m[0].indexOf(":"));
		out.push({ start, end: start + m[1].length, kind: "Vault key", rule: "structure:vault-init", confidence: 1 });
	}
}

/** HTTP Basic credentials whose password is a docs placeholder (`user:password`, `username:[password]`). */
export function isPlaceholderBasic(b64: string): boolean {
	const decoded = base64Binary(b64);
	if (decoded === undefined) return false;
	const colon = decoded.indexOf(":");
	// (`dGVzdA==` is `test`: a test word with no password at all.)
	if (colon < 0) return /^(?:test|user|admin|foo|bar|example|demo|username|password)$/i.test(decoded);
	return /^[\x20-\x7e]+$/.test(decoded) && isDocsPassword(decoded.slice(colon + 1));
}

/** Signatures and tokens in signed URLs (S3/GCS presigned, Azure SAS, CloudFront) and credentials in query strings and form bodies. */
function signedUrls(text: string, out: Finding[]) {
	const NAMES = String.raw`X-Amz-Signature|X-Amz-Security-Token|X-Goog-Signature|X-Goog-Credential|sig|Signature|access_token|id_token|refresh_token|auth_token|token|apikey|api_key|key|client_secret|password|code|appid|app_key|private_token|access_key|sasl_password|db_password|secret|passwd|pwd`;
	if (!new RegExp(String.raw`[?&](?:${NAMES})=`, "i").test(text)) return;
	for (const { name: n, value } of queryParams(text, NAMES)) {
		const name = n.toLowerCase();
		const v = value.value;
		// (Judged decoded: `%24%7BAPI_KEY%7D` is `${API_KEY}`. `refresh_token=refresh_token`,
		// `client_secret=my_client_secret`: placeholders made of words.)
		const decoded = decodeURIComponentSafe(v);
		if (v.length < 8 || isInert(decoded) || isPlaceholder(decoded) || isWordsValue(v)) continue;
		// `key=`, `code=`, `token=` and `appid=` are often not secrets (`?key=value`, `?code=200`, a page's
		// `?token=next-page-2`, `?appid=WeatherDashboard`): require randomness.
		if ((name === "key" || name === "code" || name === "token" || name === "appid") && !isRandomToken(v)) continue;
		out.push({
			start: value.start,
			end: value.end,
			kind: "URL credential",
			rule: "structure:url-param",
			confidence: 0.9,
		});
	}
}

function decodeURIComponentSafe(v: string): string {
	try {
		return decodeURIComponent(v);
	} catch {
		return v;
	}
}

/** Whether a cookie holds something worth hiding: not an attribute, a flag, a number, or an analytics or preference cookie. */
export function isSessionCookie(name: string, value: string): boolean {
	if (/^(domain|path|expires|max-age|samesite|secure|httponly|priority|partitioned|version|comment)$/i.test(name))
		return false;
	if (value.length < 8 || isInert(value) || isWordsValue(value)) return false;
	// Analytics and preference cookies: `_ga=GA1.1.35…`, `_gid`, `_fbp`, consent, locale.
	return !(ANALYTICS_COOKIE.test(name) || /^(?:GA|GS)\d\.\d\.|^fb\.\d\.|^-?[\d.]+$/.test(value));
}

/** Google's app passwords, as Google writes them: `Your app password for your device: qwhz kfmt vbnr xplo`. */
function appPasswords(text: string, out: Finding[]) {
	if (!/app[ -]?password/i.test(text)) return;
	for (const m of text.matchAll(
		/app[ -]?password\b[^\n:]{0,60}:[ \t]*["'`*]{0,2}([a-z]{4} [a-z]{4} [a-z]{4} [a-z]{4})\b/gi,
	)) {
		const start = m.index + m[0].length - m[1].length;
		out.push({ start, end: start + m[1].length, kind: "password", rule: "structure:app-password", confidence: 0.95 });
	}
}

/**
 * The session cookies' values in a cookie string (`a=1; session="…"`), placed at `base`. A value is quoted or bare, with
 * no blank, quote, `;` or backslash (none is a cookie's: a log line's escaped `\r\n` ends it).
 */
function* cookiePairs(s: string, base: number): Generator<{ start: number; end: number }> {
	for (const c of s.matchAll(/(?:^|;[ \t]{0,5})([^=;\s]{1,100})=("?)([^;"'\s\\]{1,4096})\2/dg)) {
		if (isSessionCookie(c[1], c[3])) yield { start: base + c.indices![3]![0], end: base + c.indices![3]![1] };
	}
}

/** Cookie values in Cookie and Set-Cookie headers (bare, quoted, or in a headers object), and in Netscape cookie jars. */
function cookies(text: string, out: Finding[]) {
	// A cookie written as a Set-Cookie line outside a header: `user_session=…; Path=/; HttpOnly` (its attributes say so).
	if (/;\s*(?:Path|Domain|Expires|Max-Age|HttpOnly|Secure|SameSite)\b/i.test(text)) {
		for (const m of text.matchAll(
			/(?<![\w.-])([A-Za-z_][\w.-]{1,60})=([^;\s"'|]{6,4096});[ \t]*(?:Path|Domain|Expires|Max-Age|HttpOnly|Secure|SameSite)\b/gi,
		)) {
			// (A session's cookie by its name, as isSessionCookie judges one; not a CSRF token, nor an email.)
			if (
				!/sess|sid$|token|auth|jwt|remember|login/i.test(m[1]) ||
				/csrf|xsrf/i.test(m[1]) ||
				!isSessionCookie(m[1], m[2]) ||
				/@/.test(m[2])
			)
				continue;
			const start = m.index + m[1].length + 1;
			out.push({ start, end: start + m[2].length, kind: "cookie", rule: "structure:cookie", confidence: 0.9 });
		}
	}
	if (/cookie/i.test(text)) {
		// (Real Cookie headers run past 8 KB.)
		// (Also a request-headers table copied from devtools: `cookie` then a tab or a run of spaces.)
		for (const m of text.matchAll(
			/^((?:[^\n]{0,200}?[ \t'"{(,])?[ \t]{0,10}(?:[<>*] )?(?:set-)?cookie["']?[ \t]{0,3}[:=][ \t]{0,10}["']?|[ \t]*(?:set-)?cookie(?:\t|[ \t]{2,})[ \t]*)([^\n]+)/gim,
		)) {
			for (const c of cookiePairs(m[2], m.index + m[1].length))
				out.push({ ...c, kind: "cookie", rule: "structure:cookie", confidence: 0.9 });
		}
	}
	// `curl -b 'a=1; session=…'`, `--cookie "…"`: curl's options (ldapsearch's `-b` is a base DN).
	if (/(?:^|\s)(?:-b|--cookie)[ \t]/.test(text)) {
		for (const m of text.matchAll(/(?:^|\s)(?:-b|--cookie)[ \t]+(['"])([^'"\n]{3,})\1/g)) {
			const program = commandAt(text, m.index + m[0].search(/-/))?.command[0];
			if (!program || programName(program) !== "curl") continue;
			for (const c of cookiePairs(m[2], m.index + m[0].length - 1 - m[2].length))
				out.push({ ...c, kind: "cookie", rule: "structure:cookie", confidence: 0.9 });
		}
	}
	// `domain  TRUE  /  FALSE  expiry  name  value`, tab-separated (`curl -c`, `wget --save-cookies`, browser exports).
	if (/\t(?:TRUE|FALSE)\t/.test(text)) {
		for (const m of text.matchAll(
			/^(?:#HttpOnly_)?[^\s#][^\t\n]*\t(?:TRUE|FALSE)\t[^\t\n]*\t(?:TRUE|FALSE)\t\d+\t([^\t\n]+)\t([^\t\n\r]{1,4096})/gm,
		)) {
			if (!isSessionCookie(m[1], m[2])) continue;
			const start = m.index + m[0].length - m[2].length;
			out.push({ start, end: start + m[2].length, kind: "cookie", rule: "structure:cookie-jar", confidence: 0.9 });
		}
	}
}

/** `Password=…;` in ADO.NET and ODBC connection strings, `AccountKey=`, `SharedAccessKey=`, JDBC `password=`. */
function connectionStrings(text: string, out: Finding[]) {
	if (!/pass|pwd|accountkey|sharedaccess|secret/i.test(text)) return;
	for (const m of text.matchAll(
		/(?:^|[;"'\s?&{])((?:User )?Password|Pwd|AccountKey|SharedAccessKey|SharedAccessSignature|SharedSecret|ClientSecret|Client Secret)[ \t]{0,3}=[ \t]{0,3}(?:\{(?!\{)([^}\n]+)\}|'([^'\n]+)'|"([^"\n]+)"|([^;"'\s](?:[^;"'\n]{0,4096}[^;"'\s])?))/dgi,
	)) {
		// (The value inside its braces or quotes, or bare.)
		const g = m[2] !== undefined ? 2 : m[3] !== undefined ? 3 : m[4] !== undefined ? 4 : 5;
		const bare = g === 5;
		let value = m[g];
		const start = m.indices![g]![0];
		// In a URL query (`?password=x&y=z`) `&` ends the value; in `Password=Wi&nter;` it's part of it.
		if (/^[?&]/.test(m[0]) && value.includes("&")) value = value.slice(0, value.indexOf("&"));
		// The `Key=Value;` shape is a literal context; a `{…}` or quoted value is a literal whatever it holds.
		if (value.length < 4 || isInert(value) || isPlaceholder(value) || (bare && isCode(value, true))) continue;
		// Only in something shaped like a connection string: two other `Key=Value` pairs separated by `;` on the line. (A
		// value may hold `=`: base64's padding, `Pwd=Xk9fPq2LmZ=`.)
		const line = text.slice(lineStart(text, m.index), lineEnd(text, m.index + m[0].length));
		if ((line.match(/(?:^|;)[ \t]{0,3}["']?[A-Za-z][\w .-]{0,40}=[^;\n]{0,300}(?=;|["']|$)/g) ?? []).length < 3)
			continue;
		out.push({
			start,
			end: start + value.length,
			kind: "password",
			rule: "structure:connection-string",
			confidence: 0.95,
		});
	}
}

/**
 * Base64 that decodes to something public or trivial: a certificate, a public key; a word, a boolean, a number or a
 * URL without credentials, unless the key says password or PIN (`admin-pin: NDgyMTc3MzA=`).
 */
function harmlessBase64(v: string, key = ""): boolean {
	const d = /^[A-Za-z0-9+/]+={0,2}$/.test(v) && v.length % 4 === 0 ? base64Binary(v) : undefined;
	if (d === undefined) return false;
	if (isPublicPem(d) || /^ssh-(?:rsa|ed25519) /.test(d)) return true;
	const t = d.trim();
	return (
		!namesPasswordOrPin(key) &&
		((d.length < 40 && (isWordsValue(t) || /^(?:true|false|\d+)$/.test(t) || HOST_NAME.test(t))) || isPlainUrl(t, key))
	);
}

/**
 * A URL that carries no credential: no password, no path segment or parameter value that a generator made, and no
 * key that says the URL is a secret itself (`webhook-secret: https://hooks.zapier.com/hooks/catch/23808906/7c06jvh/`).
 */
function isPlainUrl(t: string, key: string): boolean {
	if (isCredentialName(key)) return false;
	const [url] = urls(t);
	if (!url || url.start !== 0 || url.end !== t.length || url.password) return false;
	return (
		url.segments.every((s) => !isRandomToken(s.value)) &&
		[...queryParams(t)].every((p) => !isRandomToken(p.value.value))
	);
}

/**
 * Every value under `data:`/`stringData:` of a Kubernetes Secret, whatever its key is called, in YAML or in JSON. The
 * Secret is the mapping the `data` key is in, by its own `kind` (`kubectl get cm,secret -o yaml` lists ConfigMaps too).
 */
function kubeSecrets(text: string, out: Finding[]) {
	for (const { key, value } of secretDataEntries(text)) {
		if (isKubeSecretKey(key) && isKubeSecretValue(value.value, key))
			out.push({
				start: value.start,
				end: value.end,
				kind: "Kubernetes secret",
				rule: "structure:kube-secret",
				confidence: 0.95,
			});
	}
}

/**
 * A manifest's `data:` or `stringData:` mapping still open at the end of a text (no line has come back to its column),
 * by the lines that open it: its own and its `kind` (a Secret's, or a ConfigMap's), at its column. `pending`: its
 * `kind` hasn't come yet (kubectl prints `data:` first), so what follows can't be judged until it does.
 */
export function openManifestData(text: string): { lines: string[]; pending: boolean } | undefined {
	if (!/^[ \t-]*(?:data|stringData):[ \t]*$/m.test(text)) return undefined;
	const lines = yamlLines(text);
	for (let i = lines.length - 1; i >= 0; i--) {
		const data = lines[i];
		if (data.blank) continue;
		if ((data.key !== "data" && data.key !== "stringData") || data.value || data.block) {
			// (A line inside the mapping: keep looking up for its `data:`.)
			if (data.indent > 0) continue;
			return undefined;
		}
		if (lines.slice(i + 1).some((l) => !l.blank && l.indent <= data.indent)) return undefined;
		const kind = siblingValue(lines, i, "kind");
		const line = text.slice(data.start, data.end);
		return {
			lines: [`${kind === undefined ? "" : `${" ".repeat(data.indent)}kind: ${kind}\n`}${line}\n`],
			pending: kind === undefined,
		};
	}
	return undefined;
}

/** The entries of every Kubernetes Secret's `data` and `stringData`: each key, and its value where it is. */
function* secretDataEntries(text: string): Generator<{ key: string; value: Span }> {
	// (Gated on the word alone: the readers decide on the parsed `kind`, quoted or not, `kind: "Secret"`.)
	if (!/\bSecret\b/.test(text)) return;
	const lines = yamlLines(text);
	for (let i = 0; i < lines.length; i++) {
		const data = lines[i];
		if (
			(data.key !== "data" && data.key !== "stringData") ||
			data.value ||
			data.block ||
			siblingValue(lines, i, "kind") !== "Secret"
		)
			continue;
		// The mapping's own entries, at its first entry's indent: a line deeper is a block scalar's or a flow
		// collection's (the config file under `config.yaml: |`), and a line without a key (`- item`) is none.
		let indent = -1;
		for (let j = i + 1; j < lines.length && (lines[j].blank || lines[j].indent > data.indent); j++) {
			const { key, value, block, blank } = lines[j];
			if (blank) continue;
			if (indent < 0) indent = lines[j].indent;
			if (lines[j].indent !== indent || !key) continue;
			// A `key: |` block scalar: one line is a value like any other; several (a config file) are scanned as text
			// by the other detectors.
			const body = block ? blockLines(text, lines[j].start) : [];
			if (body.length === 1) yield { key, value: body[0] };
			else if (value) yield { key, value };
		}
	}
	// JSON: `"data": { "k": "v", … }` in an object whose `"kind"` is `"Secret"` (`kubectl -o json` puts `data` before `kind`).
	if (!text.includes('"kind"')) return;
	const entries: { key: string; value: Span }[] = [];
	const walk = (v: JsonNode) => {
		if (v.kind === "array") v.items.forEach(walk);
		if (v.kind !== "object") return;
		const secret = v.entries.some(([k, x]) => k === "kind" && x.kind === "string" && x.value === "Secret");
		for (const [k, x] of v.entries) {
			if (secret && (k === "data" || k === "stringData") && x.kind === "object") {
				for (const [key, value] of x.entries) if (value.kind === "string") entries.push({ key, value });
			} else walk(x);
		}
	};
	for (const doc of jsonDocuments(text)) walk(doc);
	yield* entries;
}

/**
 * Every value of a Secret is sensitive, except ones whose key says they locate something or are public. (A URL is
 * judged by its value and its key, isPlainUrl's: one in a Secret is often there because it carries a token.)
 */
function isKubeSecretKey(key: string): boolean {
	// Certificates and public keys stored next to the key: `tls.crt`, `ca.crt`, `ca-bundle.pem`.
	if (/\.(?:crt|cer|pub)$|^(?:ca|ca[-_.]bundle(?:\.pem)?|tls\.crt|cert|certificate)$/i.test(key)) return false;
	// (A file's name is judged by its stem: what the file holds is mounted as the key, `password.txt`; `checksums.txt` is
	// still a hash's.)
	const stem = key.replace(FILE_EXTENSION, "");
	const cls = nameClass(stem);
	return !(
		/^(?:user(?:name)?|login|host(?:name)?|port|database|db|dbname|region|namespace|email|bucket|cluster|server|address|account)$/i.test(
			stem,
		) ||
		cls === "public" ||
		cls === "hash"
	);
}

function isKubeSecretValue(value: string, key = ""): boolean {
	// (A flow collection written over several lines, `config.json: {`, leaves its key's line the bracket alone.)
	return (
		!isInert(value) &&
		!/^[{[]$/.test(value) &&
		!isPlainUrl(value, key) &&
		!harmlessBase64(value, key) &&
		!isHarmlessText(value, key)
	);
}

/**
 * A host as a setting gives one (`mycluster.example.com`, `db.internal:5432`): lowercase labels, then a short TLD or an
 * internal zone's name; not a dotted token (`AbCdEf123456.zzSecret`, `qwerty.secretkeyvalue`).
 */
// (Its top-level domain a country's or a common generic one, or a cluster's: `hunter2.mypass` is no host.)
const HOST_NAME =
	/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2}|com|net|org|edu|gov|mil|int|info|biz|dev|app|cloud|tech|site|online|xyz|internal|local|localdomain|lan|corp|home|svc|cluster|example)(?::\d{1,5})?$/;

/**
 * A Secret's field written as text that holds nothing secret, under a key that names no credential: a word under a
 * setting's key, a boolean or a number (a JSON line's, with its comma), a host, an API version, a Helm template's expression (`type: git`,
 * `"insecure": false,`, `server: mycluster.example.com`, `apiVersion: client.authentication.k8s.io/v1beta1`).
 */
function isHarmlessText(value: string, key: string): boolean {
	const t = value.trim().replace(/^"|",?$|,$/g, "");
	if (isCredentialName(key)) return false;
	// (A word only under a setting's key, `type: git`: under `value` or `key1` a word is as likely a weak password.)
	return (
		/^\{\{.*\}\}$/.test(t) ||
		/^(?:true|false|null|-?\d+(?:\.\d+)?)$/.test(t) ||
		HOST_NAME.test(t) ||
		/^[a-z0-9.-]+\/v\d\w*$/.test(t) ||
		(t.length < 40 && isWordsValue(t) && isSettingName(key))
	);
}

/** PowerShell: `ConvertTo-SecureString "p@ss" -AsPlainText`, the plain password itself. */
function powershellSecureStrings(text: string, out: Finding[]) {
	if (!/ConvertTo-SecureString/i.test(text)) return;
	// `ConvertTo-SecureString "pw" -AsPlainText`, flags in any order before `-String "pw"`, and `"pw" | ConvertTo-SecureString -AsPlainText`.
	// (A PowerShell string: double-quoted, escaped by a backtick or a doubled quote; single-quoted, by a doubled quote.)
	const literal = String.raw`(?:"((?:""|\x60[^\n]|[^"\x60\n])+)"|'((?:''|[^'\n])+)')`;
	const forms = [
		new RegExp(
			String.raw`ConvertTo-SecureString[ \t]+(?:-(?:AsPlainText|Force)[ \t]+){0,2}(?:-String[ \t]+)?${literal}(?=[^\n]{0,80}-AsPlainText|(?<=AsPlainText[^\n]{0,80}))`,
			"gid",
		),
		new RegExp(String.raw`${literal}[ \t]*\|[ \t]*ConvertTo-SecureString\b(?=[^\n]{0,80}-AsPlainText)`, "gid"),
	];
	for (const m of forms.flatMap((re) => [...text.matchAll(re)])) {
		const group = m[1] === undefined ? 2 : 1;
		if (isInert(m[group])) continue;
		const [start, end] = m.indices![group]!;
		out.push({ start, end, kind: "password", rule: "structure:securestring", confidence: 0.95 });
	}
}

/**
 * The passwords one command's words give its tool (commands.ts passwordOptions): `docker login -p pw`, `redis-cli -apw`,
 * `mysql --password=pw`, HTTPie's `-a user:pw` (or the whole `-a` with `-A bearer`), smbclient's `-U user%pw`,
 * `rabbitmqctl add_user name pw`, `htpasswd -b file user pw`. A wrapper's own options are read with its spec, and
 * the command it runs with that command's.
 */
function commandPasswords(words: ShellWord[], add: AddPassword) {
	// (A wrapper's command is read in turn, in a loop: `sshpass -p x sshpass -p y …` nests as deep as it's written.)
	for (let next: ShellWord[] | undefined = words; next;) next = toolPasswords(next, add);
}

/** The passwords one command gives its tool (see commandPasswords); the words of the command it wraps, if it wraps one. */
function toolPasswords(words: ShellWord[], add: AddPassword): ShellWord[] | undefined {
	// The command starts at its first word that names a tool or a wrapper: past a prompt, a timestamp or a CI log's
	// prefix (`$ `, `2025-…Z ##[group]Run`, `xcrun`); a path names one only as the first word (`find /var/lib/mysql`
	// runs find). Then past wrappers and assignments (shell.ts simpleCommand).
	const names = (w: ShellWord, i: number) =>
		(i === 0 || !/[/\\]/.test(w.text)) &&
		(isWrapper(w.text) ||
			/^(?:rabbitmqctl|htpasswd|https?|httpie|steamcmd|vault|lftp|pulumi|openssl)$/.test(programName(w)) ||
			USER_PASSWORD.test(programName(w)) ||
			!!passwordOptions(programName(w)));
	const k = words.findIndex(names);
	if (k < 0) return;
	// (A wrapper alone, `sudo`, runs nothing: its name and its words are empty.)
	const command = simpleCommand(words.slice(k));
	const name = programName(command[0]);
	const rest = command.slice(1);
	// (`value` is the end of the word's text: `pw` of `--password='pw'`.)
	const addWord = (w: ShellWord, value: string) => addTail(add, w, value, w.literalEnd);
	// `steamcmd +login <user> <password>`.
	if (name === "steamcmd") {
		const at = rest.findIndex((w) => w.text === "+login");
		if (at >= 0 && at + 2 < rest.length && !rest[at + 2].text.startsWith("+")) addWord(rest[at + 2], rest[at + 2].text);
		return;
	}
	// `vault login <token>`, `vault login -method=userpass username=u password=pw`.
	if (name === "vault" && rest[0]?.text === "login") {
		for (const w of rest.slice(1)) {
			const pair = /^(?:token|password)=(.+)$/.exec(w.text);
			if (pair) addWord(w, pair[1]);
			else if (!w.text.startsWith("-") && !w.text.includes("=")) addWord(w, w.text);
		}
		return;
	}
	// lftp: `-u user,password`.
	if (name === "lftp") {
		const at = rest.findIndex((w) => w.text === "-u" || w.text === "--user");
		const pair = rest[at + 1];
		if (at >= 0 && pair?.text.includes(",")) addWord(pair, pair.text.slice(pair.text.indexOf(",") + 1));
		return;
	}
	// `pulumi config set --secret <key> <value>`, the value the flag makes a secret (without one, it's read at a prompt
	// or from stdin), past `--path` and options with a value: `-s dev`, `--config-file f`.
	if (name === "pulumi") {
		const set = rest.findIndex((w, i) => w.text === "set" && rest[i - 1]?.text === "config");
		if (set < 0 || !rest.some((w) => w.text === "--secret")) return;
		const operands = rest
			.slice(set + 1)
			.filter(
				(w, i, after) =>
					!w.text.startsWith("-") && !/^(?:-s|--stack|--config-file|--type)$/.test(after[i - 1]?.text ?? ""),
			);
		if (operands[1]) addWord(operands[1], operands[1].text);
		return;
	}
	// `openssl passwd -6 <password>…`, which hashes the passwords it's given (`-salt` and `-in` take a value).
	if (name === "openssl") {
		if (rest[0]?.text !== "passwd") return;
		for (const [i, w] of rest.entries())
			if (i > 0 && !w.text.startsWith("-") && !/^-(?:salt|in)$/.test(rest[i - 1].text)) addWord(w, w.text);
		return;
	}
	if (name === "rabbitmqctl") {
		const at = rest.findIndex((w) => w.text === "add_user" || w.text === "change_password");
		if (at >= 0 && at + 2 < rest.length) addWord(rest[at + 2], rest[at + 2].text);
		return;
	}
	if (name === "htpasswd") {
		// `htpasswd -b[c] <file> <user> <password>`; with -n there is no file. (`-C <cost>` and `-r <rounds>` take a value.)
		const flags = rest
			.filter((w) => /^-[a-zA-Z]+$/.test(w.text))
			.map((w) => w.text.slice(1))
			.join("");
		const positional = rest.filter(
			(w, i) => !/^-[a-zA-Z]+$/.test(w.text) && !/^-[a-zA-Z]*[Cr]$/.test(rest[i - 1]?.text ?? ""),
		);
		const pw = positional[flags.includes("n") ? 1 : 2];
		if (flags.includes("b") && pw) addWord(pw, pw.text);
		return;
	}
	if (/^(?:http|https|httpie)$/.test(name)) {
		// HTTPie: `-a user:password` (the part after the colon, unless it's the docs' `username:password`; `-a user`
		// alone prompts), or with `-A bearer` the whole `-a` argument.
		const bearer =
			rest.some((w, i) => /^(?:-A|--auth-type)$/.test(w.text) && /^bearer$/i.test(rest[i + 1]?.text ?? "")) ||
			rest.some((w) => /^--auth-type=bearer$/i.test(w.text));
		for (let i = 0; i < rest.length; i++) {
			const eq = /^--auth=/.exec(rest[i].text);
			const word = eq ? rest[i] : /^(?:-a|--auth)$/.test(rest[i].text) ? rest[i + 1] : undefined;
			const arg = word && (eq ? word.text.slice(eq[0].length) : word.text);
			if (!word || !arg) continue;
			if (bearer) addWord(word, arg);
			else if (arg.includes(":") && isLiteralPassword(arg.slice(arg.indexOf(":") + 1)))
				addWord(word, arg.slice(arg.indexOf(":") + 1));
		}
		return;
	}
	// `gh secret set <NAME> --body <value>`: a secret, unless its name says it's an ID (`AZURE_TENANT_ID`, `CLOUDFLARE_ACCOUNT_ID`).
	if (name === "gh" && rest[0]?.text === "secret" && rest[1]?.text === "set") {
		const secret = rest.slice(2).find((w) => !w.text.startsWith("-"))?.text ?? "";
		if (["identifier", "public"].includes(nameClass(secret))) return;
	}
	// curl and its kin: `-u user:password`, `--user=user:password`, `--proxy-user …` (the part after the first colon).
	if (USER_PASSWORD.test(name)) {
		for (let i = 0; i < rest.length; i++) {
			const eq = /^--(?:proxy-)?user=/.exec(rest[i].text);
			const word = eq ? rest[i] : /^(?:-u|-U|--user|--proxy-user)$/.test(rest[i].text) ? rest[i + 1] : undefined;
			const pair = word && (eq ? word.text.slice(eq[0].length) : word.text);
			if (pair?.includes(":")) addWord(word!, pair.slice(pair.indexOf(":") + 1));
		}
	}
	const spec = passwordOptions(name);
	if (!spec || (spec.subcommand && !rest.slice(0, 3).some((w) => w.text === spec.subcommand))) return;
	for (let i = 0; i < rest.length; i++) {
		const w = rest[i].text;
		// A wrapper's command starts at its first word that isn't an option or an option's value.
		if (spec.wraps && !w.startsWith("-") && !spec.flags.has(rest[i - 1]?.text ?? "")) return rest.slice(i);
		const eq = w.indexOf("=");
		if (eq > 0 && spec.flags.has(w.slice(0, eq))) addWord(rest[i], w.slice(eq + 1));
		else if (
			spec.flags.has(w) &&
			i + 1 < rest.length &&
			(spec.next === "always" || (spec.next === "unless an option" && !rest[i + 1].raw.startsWith("-")))
		)
			addWord(rest[i + 1], rest[i + 1].text);
		// A one-letter option with its value attached: `sshpass -pPW`, `redis-cli -aPW`, `mysql -pPW`.
		else if (
			spec.attached &&
			/^-[A-Za-z]./.test(w) &&
			(spec.flags.has(w.slice(0, 2)) || (w[1] === "p" && /^mysql|^mariadb/.test(name)))
		)
			addWord(rest[i], w.slice(2));
		// smbclient, net, rpcclient: `-U user%password`, and attached, `-Uuser%password`, `--user=user%password`.
		else if (w === "-U" && /^(?:smbclient|net|rpcclient)$/.test(name) && rest[i + 1]?.text.includes("%"))
			addWord(rest[i + 1], rest[i + 1].text.slice(rest[i + 1].text.indexOf("%") + 1));
		else if (/^(?:-U|--user=)[^%]*%/.test(w) && /^(?:smbclient|net|rpcclient)$/.test(name))
			addWord(rest[i], w.slice(w.indexOf("%") + 1));
	}
}

/**
 * Adds a password a command-line rule found: where it starts, its text, the rule, whether it sat in single quotes, and
 * where it ends when that isn't `start` plus its length (quotes or escapes inside it: wordSpan).
 */
type AddPassword = (start: number, value: string, rule: string, quoted?: boolean, end?: number) => void;

/** Adds `value`, the end of a shell word's text, as a command-line password, at the span the word wrote it in. */
function addTail(add: AddPassword, word: ShellWord, value: string, quoted: boolean, rule = "structure:cli-password") {
	const { start, end } = wordSpan(word, word.text.length - value.length);
	add(start, value, rule, quoted, end);
}

/**
 * What a command line feeds a command on stdin: `echo`'s or `printf`'s one operand piped into it (printf's after its
 * format: `printf '%s' pw | …`), or a here-string (`… <<< "pw"`). Each value's word, and the command that reads it.
 */
function stdinFeeds(text: string): { value: ShellWord; reader: ShellCommand }[] {
	const out: { value: ShellWord; reader: ShellCommand }[] = [];
	if (!/\||<<</.test(text)) return out;
	for (const line of text.matchAll(/^[^\n]*$/gm)) {
		// (A here-string, or an echo or printf before a pipe: found with one indexOf, not a pattern that backtracks along the line.)
		const echo = /\b(?:echo|printf)\b/.exec(line[0]);
		if (!line[0].includes("<<<") && !(echo && line[0].includes("|", echo.index))) continue;
		const commands = commandsRun(text, { at: line.index, oneLine: true });
		commands.forEach((c, k) => {
			const herestring = c.redirects.find((r) => r.op === "<<<")?.target;
			if (herestring) out.push({ value: herestring, reader: c });
			const words = simpleCommand(c.words);
			const program = programName(words[0]);
			if (c.then !== "|" || !/^(?:echo|printf)$/.test(program) || !commands[k + 1]) return;
			// (A format alone with `%s` in it prints no value. Nor its options: echo's `-n`, printf's `--` before its format.)
			const args = words
				.slice(1)
				.filter((w) => !/^-[neE]+$/.test(w.text) && !(program === "printf" && w.text === "--"));
			const operands =
				program === "printf" ? (args.length > 1 ? args.slice(1) : args.filter((w) => !/%[sd]/.test(w.text))) : args;
			if (operands.length === 1) out.push({ value: operands[0], reader: commands[k + 1] });
		});
	}
	return out;
}

/** Commands that read a password or a token from stdin, by their words (and `sudo`'s options before them). */
const STDIN_SECRET =
	/^(?:sudo(?:\s+-[A-Za-z]*S[A-Za-z]*)(?:\s|$)|(?:sudo(?:\s+-\S+)*\s+)?(?:(?:docker|podman|nerdctl|helm|oras|crane|skopeo|buildah)\s+(?:registry\s+)?login\b.*--password-stdin|gh\s+auth\s+login\b.*--with-token|gh\s+secret\s+set\b|(?:podman|docker)\s+secret\s+create\b|(?:npx\s+)?wrangler\s+secret\s+put\b|vercel\s+env\s+add\b|kubectl\s+create\s+secret\b|fly(?:ctl)?\s+secrets\s+(?:set|import)\b|netlify\s+env:set\b|pulumi\s+config\s+set\b.*--secret\b|vault\s+(?:login|kv\s+put|write)\b|chpasswd\b|passwd\b|openssl\b.*-pass(?:in|out)?\s+stdin))/;

/**
 * Windows commands' passwords: switches (`cmdkey /pass:pw`, `wmic /password:pw`, `winrs -p:pw`, `schtasks /rp pw`,
 * `psexec -p pw`, `osql -P pw`) and positional ones (`net use Z: \\srv\share pw /user:CORP\alice`, `net user svc pw /add`).
 * (`*` asks for the password at a prompt: passwordAdder adds no run of `*`.)
 */
function windowsPasswords(text: string, add: AddPassword) {
	if (!/\b(?:cmdkey|schtasks|psexec|net|wmic|winrs|osql|sqlcmd|runas)\b|\/(?:pass|password|pwd):/i.test(text)) return;
	for (const m of text.matchAll(/^[^\n]*$/gm)) {
		const ws = shellWords(m[0], m.index, { backslash: false });
		const command = ws.findIndex((w) =>
			/^(?:cmdkey|schtasks|psexec(?:64)?|net|wmic|winrs|osql|sqlcmd)(?:\.exe)?$/i.test(w.text),
		);
		for (let k = 0; k < ws.length; k++) {
			const w = ws[k];
			// `/pass:pw`, `/password:pw`, `/pwd:pw` on any command; `-p:pw` (winrs).
			const glued = /^(?:\/(?:pass|password|pwd)|-p):(.+)$/i.exec(w.text);
			if (glued && (w.text[0] === "/" || /^winrs/i.test(ws[command]?.text ?? ""))) addTail(add, w, glued[1], w.quoted);
		}
		if (command < 0) continue;
		const tool = ws[command].text.toLowerCase().replace(/\.exe$/, "");
		const rest = ws.slice(command + 1);
		// A switch followed by its value: `/rp pw` (schtasks), `-p pw` (psexec), `-P pw` (osql, sqlcmd).
		const flag =
			tool === "schtasks"
				? /^\/rp$/i
				: /^psexec/.test(tool)
					? /^-p$/
					: /^(?:osql|sqlcmd)$/.test(tool)
						? /^-P$/
						: undefined;
		for (let k = 0; flag && k + 1 < rest.length; k++)
			if (flag.test(rest[k].text)) addTail(add, rest[k + 1], rest[k + 1].text, rest[k + 1].quoted);
		// `net use [drive] \\share [password] /user:…` and `net user name [password] /add`: the positional word after the share or the name.
		if (tool === "net" && /^(?:use|user)$/i.test(rest[0]?.text ?? "")) {
			const positional = rest.slice(1).filter((w) => !/^\//.test(w.text));
			const skip = rest[0].text.toLowerCase() === "use" ? positional.findIndex((w) => /^\\\\/.test(w.text)) + 1 : 1;
			const pw = skip > 0 ? positional[skip] : undefined;
			if (pw && !/^[A-Za-z]:$/.test(pw.text)) addTail(add, pw, pw.text, pw.quoted);
		}
	}
}

/**
 * Network devices' configuration lines that end in a key: Cisco IOS (`enable secret pw`, `username u privilege 15 secret 0 pw`,
 * `crypto isakmp key pw address 0.0.0.0`, `tacacs-server key pw`, `ip ospf authentication-key pw`,
 * `ip ospf message-digest-key 1 md5 pw`, `snmp-server community s RW`) and Junos (`… authentication-key "pw"`,
 * `plain-text-password-value pw`). The keyword may carry an encryption type: 0 and 7 are readable, 5, 8 and 9 are
 * hashes, kept as hashes are.
 */
function networkConfigKeys(text: string, add: AddPassword) {
	if (!/\b(?:secret|password|key|key-string|community|plain-text-password-value|psk)\b/.test(text)) return;
	const IOS =
		/^[ \t]*(?:set[ \t]+)?(?:(?:enable|username|crypto|tacacs-server|radius-server|ip|ipv6|ntp|key-string|neighbor|ppp|standby|vrrp|router|aaa|snmp-server|system|protocols|security|interfaces)\b[^\n]*?[ \t](?:secret|password|key|key-string|pre-shared-key|authentication-key|md5|community|plain-text-password-value|psk)|wpa-psk|key-string)[ \t]+(?:(?:ascii-text|hexadecimal|ascii|hex)[ \t]+)?(?:(\d)[ \t]+)?(?:"([^"\n]{3,200})"|(\S{3,200}))((?:[ \t]+(?:address|level|RO|RW|ro|rw)\b[^\n]*)?)[ \t]*;?\r?$/gm;
	for (const m of text.matchAll(IOS)) {
		if (m[1] && /[589]/.test(m[1])) continue;
		const pw = m[2] ?? m[3];
		if (/^(?:public|private|\d+)$/i.test(pw) && !m[2]) continue;
		const end = m.index + m[0].replace(/[ \t]*;?\r?$/, "").length - m[4].length - (m[2] ? 1 : 0);
		add(end - pw.length, pw, "structure:cli-password", !!m[2]);
	}
}

/**
 * Oracle's `user/password@db` logins: `jdbc:oracle:thin:admin/pw@host:1521:SID`, `expdp system/pw@ORCL`,
 * `rman target sys/pw@db`, `sqlldr userid=u/pw@db`, `SQL> connect scott/pw@orcl`, `CONN u/pw`, quoted `"system/pw@ORCL"`.
 * (`sqlplus user/pw` is read with the other command lines.) The last `@` ends the password: `scott/pa@ss@orcl`.
 */
function oracleLogins(text: string, add: AddPassword) {
	if (!/oracle|expdp|impdp|\bexp\b|\bimp\b|rman|sqlldr|dgmgrl|tkprof|\bconn(?:ect)?\b/i.test(text)) return;
	// (Oracle's tools as a command, at a line's start or after a prompt or an operator: `dvc exp run` runs dvc.)
	const LOGIN =
		/(?:jdbc:oracle:(?:thin|oci):|(?:^|[;&|(]|\$ )[ \t]*(?:sudo[ \t]+)?(?:expdp|impdp|exp|imp|rman|sqlldr|dgmgrl|tkprof)\b[^\n]{0,400}?[ \t](?:(?:target|auxiliary|userid|catalog)[ \t=]+)?["']?|^[ \t]*(?:SQL>[ \t]*)?conn(?:ect)?[ \t]+["']?)([A-Za-z_][\w$#]{0,30})\/((?:[^\s\/@'"]|@(?=[^\s\/@'"]*@)){3,})(?=@|["']?[ \t]*(?:as[ \t]+sys\w*)?[ \t]*;?\r?$)/gim;
	for (const m of text.matchAll(LOGIN)) add(m.index + m[0].length - m[2].length, m[2], "structure:cli-password");
}

/**
 * How command-line and config rules add a password: unless it's a reference (`$PASS`, `${PASS}`, `{{ pw }}`, a
 * `<placeholder>`, `%VAR%`), a docs' placeholder or a prompt's `*`. `quoted`: inside single quotes, where a shell
 * expands nothing: `-u 'admin:$q…'` is a literal. (In a shell, `$name` unquoted is expanded whatever the name.)
 */
function passwordAdder(out: Finding[]): AddPassword {
	return (start, value, rule, quoted = false, end = start + value.length) => {
		if (/^\*+$/.test(value) || !isLiteralPassword(value, quoted)) return;
		out.push({
			start,
			end,
			kind: "password",
			rule,
			confidence: 0.92,
			literal: true,
			...(end - start !== value.length ? { value } : {}),
		});
	};
}

/** Programs whose `-u`, `--user` or `--proxy-user` is `user:password`: curl and its kin, HTTP clients, wget's `--user`. */
const USER_PASSWORD = /^(?:curl|curlie|xh|xhs|http|https|httpie|wget|grpcurl|hey|siege)$/;

/**
 * Passwords given to command-line clients: `curl -u user:pass`, `mysql -pPASS` / `-p'PASS'`,
 * `docker login -p PASS`, `sshpass -p PASS`, `redis-cli -a PASS`, `ldapsearch -w PASS`, `htpasswd -b file user PASS`.
 */
function cliPasswords(text: string, out: Finding[]) {
	if (
		!/[\s"']-[upaPwUbN]|--(?:user|pass|auth|pw|body)|\/p:|password[ \t]|sshpass|htpasswd|rabbitmqctl|steamcmd|sqlplus|poetry|wandb|beeline|keytool|vault[ \t]+login|pulumi|openssl[ \t]+passwd|-a |\||<<</i.test(
			text,
		)
	)
		return;
	const add = passwordAdder(out);
	// The password options of programs outside the tool table: `hydra -p`, `xfreerdp /p:`, `unrar x -p…`, `ssh-keygen -N`,
	// and a `password <v>` word pair on any command line (`nmcli … password <v>`, `mysqladmin … password <v>`). (`-p` is
	// a port, a path or a profile to most programs: only these say it is a password.)
	// (Bare, or quoted as a shell quotes it: `-p 'Password123!'`, `/p:"Summer2024!"`; in a line's inline code too,
	// `` Run `hydra -p pw` ``.)
	for (const m of text.matchAll(
		/(?:^|[ \t])(-[pNA]|\/p:|password[ \t]+)([ \t]?)(?:'([^'\n]{6,64})'|"([^"\n]{6,64})"|([^\s'"`]{6,64}))(?=[\s;|&)`]|$)/g,
	)) {
		const [, option, blank] = m;
		const pw = m[3] ?? m[4] ?? m[5];
		const bare = m[5] !== undefined;
		const at = m.index + m[0].length - pw.length - (bare ? 0 : 1);
		const program = commandAt(text, at)?.command[0];
		// (A word list is no password: `nxc smb hosts -u users.txt -p passwords.txt`.)
		if (pw.startsWith("-") || !program || /\.(?:txt|lst|list|dic|csv)$/i.test(pw)) continue;
		const name = programName(program);
		const word = /^password/.test(option);
		// (rar's `-p` takes its password attached, `-pPW`; alone it asks for one, and the archive's name follows,
		// `rar a -p backup.rar`. A password written apart anyway, `-p Summer2024`, is still the one its writer meant.)
		const takes =
			word ||
			(option === "/p:" && /^(?:(?:x|w|s)?freerdp3?|rdesktop)$/.test(name)) ||
			(option === "-p" &&
				(/^(?:hydra|medusa|twine|evil-winrm|crackmapexec|netexec|nxc|rpcclient|smbmap|enum4linux(?:-ng)?|useradd|usermod)$|^impacket-/.test(
					name,
				) ||
					(/^(?:unrar|rar)$/.test(name) && !(blank && /\.(?:rar|r\d\d|zip|7z|exe|sfx)$/i.test(pw))))) ||
			(option === "-N" && name === "ssh-keygen") ||
			(option === "-A" && /^snmp/.test(name));
		if (!takes) continue;
		// A program's own password option or word takes any value, and quoted, all its quotes hold: `-p 'Xk9(mP2/vQ7'`.
		// Otherwise a path or a call is no password (`-p /tmp/pwlist`, `password hash(pw1)`), and a sentence's
		// punctuation is none of one (`hydra -p Winter2024.`); after a `password` word on any other command, only a
		// password's shape is one: letters with a digit, or of both cases with a symbol, `Zebra-Lamp-Cloud`; not prose,
		// `authentication`, `re-use`, nor code that holds one, `os.environ.PW1`.
		const own = !word || /^(?:nmcli|mysqladmin)$/.test(name);
		const whole = own && !bare;
		if (!whole && /[()/]/.test(pw)) continue;
		const value = whole ? pw : pw.replace(/[.,;:]+$/, "");
		if (
			!own &&
			(isCode(value, true) ||
				!(
					(/[A-Za-z]/.test(value) && /\d/.test(value)) ||
					(/[a-z]/.test(value) && /[A-Z]/.test(value) && /[\W_]/.test(value))
				))
		)
			continue;
		add(at, value, "structure:cli-password");
	}
	// `wandb login <key>`: a key as a command's argument.
	for (const m of text.matchAll(/\bwandb[ \t]+login(?:[ \t]+--?[\w-]+)*[ \t]+([0-9a-f]{40}|local-[0-9a-f]{40,})\b/g))
		add(m.index + m[0].length - m[1].length, m[1], "structure:cli-key");
	// curl -u user:password, --user user:password: only the part after the first colon.
	for (const m of text.matchAll(
		new RegExp(
			String.raw`(?:^|\s)(?:-u|--user|--proxy-user|-U)(?:[ \t]{1,4}|=|(?=[\w.@+-]{1,100}:))` +
				String.raw`(?:'([^':\n]{0,100}):([^'\n]+)'|"([^":\n]{0,100}):([^"\n]+)"|([^\s:'"]{0,100}):(?:'([^'\n]+)'|"([^"\n]+)"|([^\s'"]{1,4096})))`,
			"g",
		),
	)) {
		// `user:pass`, `'user:pass'`, or `user:'pass'` with only the password quoted.
		const pw = m[2] ?? m[4] ?? m[6] ?? m[7] ?? m[8];
		// The tools that document `user:password` say so (USER_PASSWORD); for any other program, or a sentence, both halves
		// must read as a pair: a user's name, and no name or number (`docker run -u www-data:www-data`, `chown 1000:1000`,
		// `date -u +%Y-%m-%dT%H:%M:%SZ` aren't). (The command the option is in: an earlier `chown app:app … &&` says
		// nothing about a later `curl -u`.)
		const user = m[1] ?? m[3] ?? m[5] ?? "";
		// (A URL, `redis-cli -u redis://:pw@host:6379/2`, is the URL reader's: its scheme is no user.)
		if (pw.startsWith("//")) continue;
		const program = commandAt(text, m.index + m[0].search(/-/))?.command[0];
		if (
			!(program && USER_PASSWORD.test(programName(program))) &&
			(!/^[\w.@-]{1,100}$/.test(user) || /^(?:[a-z_][a-z0-9_.-]{0,31}|\d{1,10})$/.test(pw))
		)
			continue;
		add(
			m.index + m[0].length - pw.length - (m[8] === undefined ? 1 : 0),
			pw,
			"structure:cli-user-pass",
			m[2] !== undefined || m[6] !== undefined,
		);
	}
	// A password piped into a command that reads it from stdin: `echo pw | docker login --password-stdin`, or given it as
	// a here-string: `vault login - <<< "pw"`.
	for (const { value, reader } of stdinFeeds(text)) {
		if (STDIN_SECRET.test(reader.words.map((w) => w.text).join(" ")))
			addTail(add, value, value.text, value.literalEnd, "structure:piped-password");
	}
	// `poetry config http-basic.<repo> <user> <password>`.
	for (const m of text.matchAll(
		/\bpoetry[ \t]+config[ \t]+http-basic\.[\w.-]+[ \t]+["']?[^\s'"]{1,100}["']?[ \t]+(["']?)([^\s'"]{3,4096})\1/g,
	)) {
		add(m.index + m[0].length - m[1].length - m[2].length, m[2], "structure:cli-password");
	}
	// `sqlplus user/password@db` (the last `@` ends a password that has one, `scott/pa@ss@orcl`).
	for (const m of text.matchAll(
		/(?:^|[;&|(\s]|\$ )sqlplus[ \t]+(?:-\w+[ \t]+)*["']?[\w.$#-]{1,60}\/((?:[^\s@'"]|@(?=[^\s@'"]*@)){3,4096})(?=@|[ \t]+as[ \t]+sys|["']?[ \t]*$|["']?[ \t]*[;&|\n])/gm,
	)) {
		const pw = m[1] ?? m[2];
		add(m.index + m[0].length - pw.length, pw, "structure:cli-password");
	}
	// A password written unquoted with a shell's operators in it (`-pXk9(mP2&vQ7`) runs to the next blank, as the person
	// who wrote it reads it; the shell would have cut it at the operator. (Not past a quote: `"$(… pw)"` closes there.)
	const toBlank: AddPassword = (start, value, rule, quoted, end = start + value.length) => {
		const rest = /^[()&|;<>]+[^\s()&|;<>"'`]\S*/.exec(text.slice(end, end + 4096))?.[0] ?? "";
		add(start, value + rest, rule, quoted, end + rest.length);
	};
	for (const line of text.matchAll(/^[^\n]*$/gm)) {
		if (!/-|rabbitmqctl|steamcmd|vault[ \t]+login/.test(line[0])) continue;
		// (Read as the commands it runs: past a prompt, through wrappers, in PowerShell's dialect where it's written in it.)
		for (const c of commandsRun(text, { at: line.index, oneLine: true })) commandPasswords(c.words, toBlank);
	}
	// The same commands written as lists of words; a shell's `-c` script in one, as the command line it is.
	if (/\[[ \t\r\n]*["']/.test(text))
		for (const m of text.matchAll(/\[[ \t\r\n]*(?=["'])/g)) {
			const words = listWords(text, m.index + m[0].length);
			if (!words || words.length < 2) continue;
			commandPasswords(words, add);
			const flag = SHELL.test(programName(words[0])) ? words.findIndex((w) => /^-\w*c\w*$/.test(w.text)) : -1;
			const script = flag > 0 ? words[flag + 1] : undefined;
			if (script)
				for (const c of commandsRun(script.text))
					commandPasswords(
						c.words.map((w) => inWord(script, w)),
						add,
					);
		}
}

/** A word of a command read out of `outer`'s text, with its positions where `outer`'s map puts them. */
function inWord(outer: ShellWord, w: ShellWord): ShellWord {
	const at = (p: number) => (p < outer.map.length ? outer.map[p] : outer.map[outer.map.length - 1] + 1);
	return {
		...w,
		start: at(w.start),
		end: at(w.end - 1) + 1,
		map: w.map.map(at),
		ends: w.ends.map((e) => at(e - 1) + 1),
	};
}

/**
 * An exec array's words, from the first item at `at` to its `]`: a command written as a list (`["docker", "login", "-p",
 * "pw"]` in JSON, a Dockerfile's `CMD`, compose's `command:`, Python's `subprocess.run([…])`, Node's `spawn(…, […])`),
 * read as a command line's words are (commandPasswords), each literal's text mapped to where it's written. An item
 * that isn't a literal (`pw`, `os.environ["PW"]`) is a reference, a `$` word no password rule takes.
 */
function listWords(text: string, at: number): ShellWord[] | undefined {
	const words: ShellWord[] = [];
	let i = at;
	while (words.length < 200) {
		const q = text[i];
		const start = i;
		if (q === '"' || q === "'") {
			const close = stringEnd(text, i);
			if (close < 0) return undefined;
			// (An escaped character is written as its whole escape, `\"`. The word is what its quotes hold: a value's span
			// is never widened over them, so `"-a", "pa\"ss"` keeps its quotes.)
			let value = "";
			const map: number[] = [];
			const ends: number[] = [];
			for (let j = i + 1; j < close; j++) {
				map.push(j);
				if (text[j] === "\\") j++;
				value += text[j];
				ends.push(j + 1);
			}
			words.push({
				text: value,
				start: start + 1,
				end: close,
				raw: text.slice(start + 1, close),
				quoted: true,
				literalEnd: q === "'",
				map,
				ends,
				substitutions: [],
			});
			i = close + 1;
		} else {
			const item = /^[^,\]\n]{1,200}/.exec(text.slice(i, i + 201))?.[0].trimEnd();
			if (!item) return undefined;
			const end = start + item.length;
			words.push({
				text: "$ref",
				start,
				end,
				raw: item,
				quoted: false,
				literalEnd: false,
				map: [start, start, start, start],
				ends: [end, end, end, end],
				substitutions: [],
			});
			i += item.length;
		}
		while (text[i] === " " || text[i] === "\t" || text[i] === "\r" || text[i] === "\n") i++;
		if (text[i] === "]") return words;
		if (text[i] !== ",") return undefined;
		i++;
		while (text[i] === " " || text[i] === "\t" || text[i] === "\r" || text[i] === "\n") i++;
	}
	return undefined;
}

/**
 * Values a CI system was told to mask: GitHub Actions `::add-mask::<value>`, Azure `##vso[task.setsecret]<value>`,
 * Buildkite `buildkite-agent redactor add` (fed on stdin).
 */
function ciMasks(text: string, out: Finding[]) {
	// Buildkite's `buildkite-agent redactor add`, fed on stdin.
	if (text.includes("redactor add")) {
		for (const { value, reader } of stdinFeeds(text)) {
			if (
				!/^buildkite-agent\s+redactor\s+add\b/.test(
					simpleCommand(reader.words)
						.map((w) => w.text)
						.join(" "),
				) ||
				value.text.length < 4 ||
				isInert(value.text)
			)
				continue;
			out.push({
				...wordSpan(value),
				kind: "masked CI value",
				rule: "structure:ci-mask",
				confidence: 1,
				...(wordSpan(value).end - wordSpan(value).start !== value.text.length ? { value: value.text } : {}),
			});
		}
	}
	if (!/::add-mask::|##vso\[task\.setsecret\]|##vso\[task\.setvariable[^\]\n]{0,200}issecret=true/i.test(text)) return;
	// The value is the rest of the line (a passphrase has spaces), up to the quote that opened an `echo "…"`,
	// or a JSON escape when the line sits inside a JSON string.
	for (const m of text.matchAll(
		/(?:::add-mask::|##vso\[task\.setsecret\]|##vso\[task\.setvariable[^\]\n]{0,200}issecret=true[^\]\n]{0,100}\])([^\n]{1,4096})/gi,
	)) {
		let value = m[1].replace(/\\[nrt"][\s\S]*$/, "");
		const quote = /(["'])[^"'\n]*$/.exec(text.slice(Math.max(0, m.index - 200), m.index))?.[1];
		if (quote && value.includes(quote)) value = value.slice(0, value.indexOf(quote));
		value = value.replace(/[ \t\r]+$/, "");
		if (!value || isInert(value)) continue;
		const start = m.index + m[0].length - m[1].length;
		out.push({ start, end: start + value.length, kind: "masked CI value", rule: "structure:ci-mask", confidence: 1 });
	}
}

/** Path segments of one-time links: `/reset/<token>`, `/auth/magic-link/<token>`, `/verify-email/<token>`. */
const SIGN_IN_SEGMENT =
	/^(?:(?:password|email|account|user|magic)[-_]?)?(?:reset|verify|verification|confirm|confirmation|magic|login|signin|sign[-_]in|activate|activation|invite|invitation|unlock|recover|recovery|otp|claim|passwordless|onetime|one[-_]time)(?:[-_]?(?:password|email|account|links?|tokens?|login))?$/i;
/** A bundler's content-hashed asset: `app-Kx81kP0qLm2Vb7Rt.js`, `chunk.3f9a2c1e.css`, `Inter-Bold-Zk3mP9qL.woff2`. Named for its hash, served to everyone. */
const HASHED_ASSET =
	/^[A-Za-z_][\w]*[-.][\w-]{6,}\.(?:m?js|cjs|css|map|json|woff2?|ttf|otf|eot|png|jpe?g|gif|webp|avif|svg|ico|mp[34]|webm|wasm)$/i;
/** A path segment that is a one-time token: random, and not a UUID (a record's id as often as a token) or an asset's name. */
function isSignInToken(v: string): boolean {
	return isRandomToken(v) && !/^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(v) && !HASHED_ASSET.test(v);
}

/** Query parameters that carry a one-time login or an access grant. */
const SIGN_IN_PARAM =
	/^(?:magic|otp|ticket|oobcode|login_token|reset_token|invite_token|verification_token|confirmation_token|reset_password_token|unlock_token|invitation_token|access_token|id_token|refresh_token|auth|sso_token)$/i;

/**
 * Reset, magic sign-in and verification links, which log in whoever opens them: a random token in the
 * path after `/reset/`, `/magic-link/`, `/verify/`, or in a query parameter like `?magic=`.
 */
function signInLinks(text: string, out: Finding[]) {
	if (
		!/https?:\/\/|\/(?:reset|verify|magic|confirm|invite|activate|login|unlock)|[?&](?:magic|otp|ticket|oobcode|[a-z]+_token|auth)=/i.test(
			text,
		)
	)
		return;
	for (const { scheme, segments } of urls(text, { paths: true })) {
		if (scheme && !/^https?$/i.test(scheme)) continue;
		// The token follows the sign-in segment (and a second word that qualifies it: `/password/reset/<token>`), right
		// after it or after an id (Django's `/reset/<uidb64>/<token>/`). Laravel's reset tokens are 64 hex; under a
		// repository named `login`, `/login/commit/<sha>` has a word there.
		let at = segments.findIndex((seg) => SIGN_IN_SEGMENT.test(seg.value));
		if (at < 0) continue;
		const next = segments[at + 1]?.value ?? "";
		if (SIGN_IN_SEGMENT.test(next) || /^(?:password|email|account|user)s?$/i.test(next)) at++;
		// (A token right after it is taken first, read as an id or not.)
		const id =
			segments[at + 1] &&
			/^[A-Za-z0-9_=-]{1,24}$/.test(segments[at + 1].value) &&
			!readsAsWords(segments[at + 1].value);
		const token = segments.slice(at + 1, at + (id ? 3 : 2)).find((seg) => isSignInToken(seg.value));
		if (token)
			out.push({
				start: token.start,
				end: token.end,
				kind: "sign-in link token",
				rule: "structure:sign-in-link",
				confidence: 0.9,
			});
	}
	for (const { name, value } of queryParams(text)) {
		if (!SIGN_IN_PARAM.test(name) || !isRandomToken(value.value) || isInert(value.value)) continue;
		out.push({
			start: value.start,
			end: value.end,
			kind: "sign-in link token",
			rule: "structure:sign-in-link",
			confidence: 0.9,
		});
	}
}

/**
 * A credential flag and its value as separate items of a list: `- "--requirepass"` then `- "value"` in a
 * compose `command:`, `["--password", "value"]` in an exec array or a JSON args list.
 */
function flagListItems(text: string, out: Finding[]) {
	if (!/(?:pass|token|secret|key|auth)/i.test(text) || !/["'\s]-{1,2}[A-Za-z]/.test(text)) return;
	// `["--password", "x"]`, `- "--requirepass"` then `- "x"`, and unquoted YAML list items `- --password` / `- x`.
	for (const m of text.matchAll(
		// (A flag starts a word: not `-password` inside `/run/secrets/db-password`.)
		/(?<![\w/.=-])(["']?)(--?[A-Za-z][\w-]{0,60})\1[ \t]*(?:,[ \t\r\n]{0,80}(["'])([^"'\n]{3,})\3|\r?\n[ \t]*-[ \t]+(?:(["'])([^"'\n]{3,})\5|([^\s"'#-][^\n#]{2,4095}?))[ \t]*(?=\r?\n|$))/g,
	)) {
		const flag = m[2].replace(/^-+/, "");
		const value = m[4] ?? m[6] ?? m[7];
		// (Judged as every name rule judges a value: `--partition-key` names an identifier, `--auth oidc-device-flow` a mode.)
		if (!isCredentialName(flag) || /^-/.test(value) || !isNamedSecret(flag, `"${value}"`, true)) continue;
		const start = m.index + m[0].lastIndexOf(value);
		out.push({ start, end: start + value.length, kind: "credential", rule: "structure:flag-list", confidence: 0.9 });
	}
}

/** `machine host login user password value` (netrc), also inside JSON strings and logs. */
function netrcLike(text: string, out: Finding[]) {
	if (!/\bpassword\b/.test(text) || !/\b(?:login|machine)\b/.test(text)) return;
	// `machine <host> login <user> password <pw>` (or `default …`, or `login <user> password <pw>`): the
	// tokens follow one another, as netrc writes them; prose that mentions a login and a password doesn't.
	// Between tokens: blanks, a line break, a `\n` escape, or the end of one string of a JSON lines array and the next.
	const SEP = String.raw`(?:[ \t]+|[ \t]*(?:\\n|\r?\n)(?:["'],?[ \t\r\n]{0,40}["'])?[ \t]*)`;
	// (Or `machine <host> password <pw> login <user>`: netrc tokens may come in any order. A word that joins the two is
	// no user: `"login or password incorrect"`.)
	for (const m of text.matchAll(
		new RegExp(
			String.raw`(?:\b(?:machine${SEP}[^\s,;:]{1,200}|default)${SEP}|(?:^|\\n|["'])[ \t]*)(?:login${SEP}(?!(?:and|or|with|via|using|by|&)${SEP})[^\s,;:]{1,200}${SEP}(?:account${SEP}\S{1,200}${SEP})?)?password[ \t]+([^\s"'\\]{3,500})`,
			"gm",
		),
	)) {
		// Without a login before it, a password must follow `machine`/`default` and be followed by `login`.
		if (
			!/\blogin\b/.test(m[0]) &&
			!/^(?:[ \t]+|[ \t]*(?:\\n|\r?\n)(?:["'],?[ \t\r\n]{0,40}["'])?[ \t]*)login\b/.test(
				text.slice(m.index + m[0].length, m.index + m[0].length + 60),
			)
		)
			continue;
		if (!/\b(?:machine|default)\b/.test(m[0]) && !/\blogin\b/.test(m[0])) continue;
		if (isInert(m[1]) || COMMON_WORDS.has(m[1].toLowerCase())) continue;
		const start = m.index + m[0].length - m[1].length;
		out.push({ start, end: start + m[1].length, kind: "password", rule: "structure:netrc", confidence: 0.9 });
	}
}

/**
 * Passwords in SQL statements: MySQL/Oracle `IDENTIFIED [WITH plugin] BY '…'`, `SET PASSWORD [FOR u] = '…'`,
 * Postgres `[WITH] PASSWORD '…'`, T-SQL `WITH PASSWORD = '…'`.
 */
function sqlPasswords(text: string, out: Finding[]) {
	if (!/IDENTIFIED|PASSWORD/i.test(text)) return;
	const forms = [
		/\bIDENTIFIED\s+(?:WITH\s+['"`]?\w+['"`]?\s+)?BY\s+(?!PASSWORD\b)(?:'((?:[^'\n]|'')+)'|"([^"\n]+)")/gi,
		// Unquoted (Oracle) only in a statement that creates or changes a user: prose says "identified by" too. (Up to a
		// statement's end, or a quote that closes the string a program holds it in: `"CREATE USER app IDENTIFIED BY …"`.
		// Not MySQL's `IDENTIFIED BY RANDOM PASSWORD`, which makes one.)
		/\b(?:CREATE|ALTER)\s+(?:USER|ROLE)\b[^;\n]{0,200}?\bIDENTIFIED\s+BY\s+(?!PASSWORD\b|VALUES\b|RANDOM\s+PASSWORD\b)([A-Za-z0-9_$#!@%^&*+=.-]{4,128})(?=\s*(?:[;"'`]|$|\s))/gim,
		/\bSET\s+PASSWORD\s+(?:FOR\s+\S+\s*)?=\s*(?:PASSWORD\s*\(\s*)?'((?:[^'\n]|'')+)'/gi,
		/\b(?:CREATE|ALTER)\s+(?:USER|ROLE|LOGIN)\b[^;\n]{0,200}?\bPASSWORD\s*=?\s*'((?:[^'\n]|'')+)'/gi,
		// MySQL's current password, which a password change authenticates with: `IDENTIFIED BY 'new' REPLACE 'old'`.
		/\bIDENTIFIED\s+BY\s+'(?:[^'\n]|'')+'\s+REPLACE\s+'((?:[^'\n]|'')+)'/gi,
	];
	for (const re of forms) {
		for (const m of text.matchAll(re)) {
			const pw = m[1] ?? m[2];
			// (A bind parameter, `:pw` or `?`, is never quoted and can't start the unquoted form: these are all literals.
			// MySQL's `*<40 hex>` is a hash, passwordHashes's.)
			if (pw.length < 3 || isInert(pw) || isPlaceholder(pw) || /^\*[0-9A-F]{40}$/.test(pw)) continue;
			const start = m.index + m[0].lastIndexOf(pw);
			out.push({ start, end: start + pw.length, kind: "password", rule: "structure:sql-password", confidence: 0.95 });
		}
	}
}

/**
 * Redis sessions: `AUTH [user] pw`, `CONFIG SET requirepass pw`, and replies that pair a credential name
 * with its value (`1) "requirepass"` / `2) "pw"`, `GET api_token` then `"pw"`).
 */
function redisSessions(text: string, out: Finding[]) {
	if (!/\bAUTH\b|requirepass|masterauth|\d\) "|> ?GET /i.test(text)) return;
	const add = (start: number, value: string, rule: string) => {
		if (value.length < 4 || isInert(value)) return;
		out.push({ start, end: start + value.length, kind: "password", rule, confidence: 0.9 });
	};
	const value = String.raw`(?:"((?:[^"\\\n]|\\.)+)"|'([^'\n]+)'|([^\s"']{1,4096}))`;
	// `127.0.0.1:6379> AUTH pw`, `redis-cli … AUTH user pw`, `> CONFIG SET requirepass "pw"`.
	for (const m of text.matchAll(
		new RegExp(
			String.raw`(?:(?:^|\s)[\w.-]*:\d{2,5}(?:\[\d+\])?>[ \t]*|\bredis-cli\b[^\n]{0,400}?[ \t])(?:AUTH|auth)[ \t]+(?:[^\s"']{1,100}[ \t]+)?` +
				value +
				String.raw`[ \t]*$`,
			"gm",
		),
	)) {
		const v = m[1] ?? m[2] ?? m[3];
		add(m.index + m[0].trimEnd().length - v.length - (m[3] === undefined ? 1 : 0), v, "structure:redis-auth");
	}
	for (const m of text.matchAll(
		new RegExp(String.raw`\bCONFIG[ \t]+SET[ \t]+(?:requirepass|masterauth|masteruser)[ \t]+` + value, "gi"),
	)) {
		const v = m[1] ?? m[2] ?? m[3];
		add(m.index + m[0].length - v.length - (m[3] === undefined ? 1 : 0), v, "structure:redis-auth");
	}
	// Array replies: a credential-named element followed by its value.
	for (const m of text.matchAll(
		/^[ \t]*\d{1,4}\) "([\w.:-]{1,80})"[ \t]*\r?\n[ \t]*\d{1,4}\) "((?:[^"\\\n]|\\.)+)"/gm,
	)) {
		if (!isCredentialName(m[1])) continue;
		add(m.index + m[0].length - 1 - m[2].length, m[2], "structure:redis-reply");
	}
	// `GET <credential key>` and its bulk-string reply on the next line.
	for (const m of text.matchAll(/>[ \t]*GET[ \t]+([\w.:-]{1,120})[ \t]*\r?\n[ \t]*"((?:[^"\\\n]|\\.)+)"/gi)) {
		if (!isCredentialName(m[1].split(/[:.]/).at(-1)!)) continue;
		add(m.index + m[0].length - 1 - m[2].length, m[2], "structure:redis-reply");
	}
}

/** IPsec `ipsec.secrets` (`: PSK "…"`) and OpenVPN inline `<auth-user-pass>` blocks (user, then password). */
function vpnSecrets(text: string, out: Finding[]) {
	if (text.includes("PSK") || text.includes("XAUTH") || text.includes("EAP")) {
		// Selectors (IPs, `%any`, hostnames, `@ids`) before the colon; an unquoted value ends the line.
		for (const m of text.matchAll(
			/^[ \t]*(?:[\w.:%@/-]{1,100}[ \t]+){0,4}[\w.:%@/-]{0,100}[ \t]*:[ \t]*(?:PSK|XAUTH|EAP)[ \t]+(?:"([^"\n]+)"|'([^'\n]+)'|(\S{4,4096})[ \t]*$)/gm,
		)) {
			if (/^[ \t]*[A-Z][a-z]+(?:[ \t]+[a-z]+)*[ \t]*:/.test(m[0])) continue; // `Mode: PSK x`, `Authentication method: PSK …`: prose
			const v = m[1] ?? m[2] ?? m[3];
			if (isInert(v)) continue;
			const start = m.index + m[0].length - v.length - (m[3] === undefined ? 1 : 0);
			out.push({ start, end: start + v.length, kind: "pre-shared key", rule: "structure:ipsec", confidence: 0.95 });
		}
	}
	if (text.includes("<auth-user-pass>")) {
		for (const m of text.matchAll(
			/<auth-user-pass>[ \t]*\r?\n[^\n]*\r?\n[ \t]*([^\s<][^\n]{0,4096}?)[ \t]*\r?\n[ \t]*<\/auth-user-pass>/g,
		)) {
			if (isInert(m[1])) continue;
			const start = m.index + m[0].indexOf(m[1], m[0].indexOf("\n", m[0].indexOf("\n") + 1));
			out.push({ start, end: start + m[1].length, kind: "password", rule: "structure:openvpn", confidence: 0.95 });
		}
	}
}

/**
 * Password hashes: by their format (values.ts PASSWORD_HASHES: bcrypt, argon2, crypt(3) and its `$$`-escaped Compose
 * form, Django and passlib, SCRAM, LDAP `{SSHA}`, Postgres `md5…`, MySQL `*…`), and by their place: MySQL's and Redis
 * ACL's hex where a password is talked about, values under hash-named password fields. Not a usable password, but
 * crackable offline, so not for an untrusted provider either.
 */
function passwordHashes(text: string, out: Finding[]) {
	if (
		!/\$|\{S?S?HA|\{MD5|\{CRYPT|\{PBKDF2|\{ARGON2|\{BCRYPT|md5[0-9a-f]|\*[0-9A-F]{40}|#[0-9a-f]{64}|SCRAM-|storedKey|serverKey|password[_-]?(?:hash|sha|double|digest)|hashed_?password/i.test(
			text,
		)
	)
		return;
	const add = (start: number, value: string, rule: string) =>
		out.push({ start, end: start + value.length, kind: "password hash", rule, confidence: 0.95 });
	for (const m of text.matchAll(PASSWORD_HASH_IN_TEXT)) add(m.index, m[0], "structure:password-hash");
	// MySQL `*<40 hex>` and Redis ACL `#<64 hex>` only where a password is being talked about.
	for (const m of text.matchAll(/^[^\n]*(?:password|passwd|authentication_string|\buser\s+\S+\s+on\b)[^\n]*$/gim)) {
		for (const h of m[0].matchAll(/(?<![\w*#])(?:\*[0-9A-F]{40}|#[0-9a-f]{64})\b/g))
			add(m.index + h.index + 1, h[0].slice(1), "structure:hash-field");
	}
	// Hash-named fields: `"password_hash": "…"`, `<password_sha256_hex>…</…>`, SCRAM `storedKey`/`serverKey`.
	for (const m of text.matchAll(
		/(?:["'<]|\b)(password[_-]?(?:hash|sha\d+(?:_hex)?|double_sha1_hex|digest)|passwordHash|hashed_?password|storedKey|serverKey)["'>]?[ \t]*(?:[:=]>?[ \t]*["']?|(?<=>))([A-Za-z0-9+/=$.:_-]{16,512})/gi,
	)) {
		if (isInert(m[2])) continue;
		add(m.index + m[0].length - m[2].length, m[2], "structure:hash-field");
	}
}

/** VPN and server configs: HAProxy `stats auth user:pw`, `user u insecure-password pw`; OpenSSL `-passout pass:pw`. */
function configPasswords(text: string, out: Finding[]) {
	const add = (start: number, value: string, rule: string) => {
		if (value.length < 3 || isInert(value)) return;
		out.push({ start, end: start + value.length, kind: "password", rule, confidence: 0.92, literal: true });
	};
	for (const m of text.matchAll(
		/\bstats[ \t]+auth[ \t]+[^:\s]{1,100}:(\S{1,4096})|\buser[ \t]+\S{1,100}[ \t]+insecure-password[ \t]+(\S{1,4096})/g,
	)) {
		const v = m[1] ?? m[2];
		add(m.index + m[0].length - v.length, v, "structure:haproxy");
	}
	for (const m of text.matchAll(
		// (Quoted, the value may hold blanks: `-passout "pass:correct horse"`.)
		/(?:^|\s)-(?:pass(?:in|out|word)?|password|passphrase|storepass|keypass|srcstorepass|deststorepass)[ \t]+(?:(['"])pass:([^'"\n]{1,4096})\1|pass:([^\s'"]{1,4096}))/gm,
	)) {
		const pw = m[2] ?? m[3];
		add(m.index + m[0].length - pw.length - (m[1] ? 1 : 0), pw, "structure:openssl-pass");
	}
}

/** Everything in this module. */
export function findStructure(text: string): Finding[] {
	const out: Finding[] = [];
	privateKeys(text, out);
	otherPrivateKeys(text, out);
	urlCredentials(text, out);
	mnemonics(text, out);
	appPasswords(text, out);
	authorization(text, out);
	signedUrls(text, out);
	cookies(text, out);
	connectionStrings(text, out);
	kubeSecrets(text, out);
	powershellSecureStrings(text, out);
	cliPasswords(text, out);
	windowsPasswords(text, passwordAdder(out));
	networkConfigKeys(text, passwordAdder(out));
	oracleLogins(text, passwordAdder(out));
	ciMasks(text, out);
	smtpAuth(text, out);
	vaultInit(text, out);
	signInLinks(text, out);
	flagListItems(text, out);
	netrcLike(text, out);
	sqlPasswords(text, out);
	redisSessions(text, out);
	vpnSecrets(text, out);
	passwordHashes(text, out);
	configPasswords(text, out);
	return out;
}

/**
 * A BIP-39 seed phrase: 12 to 24 words of the English list whose checksum verifies (1 in 16 to 1 in 256 for
 * words drawn at random), on one line or numbered one per line, with or without a name. A wallet's whole
 * key; never kept for its context (policy.ts). Published phrases are (isPublishedPhrase).
 */
function mnemonics(text: string, out: Finding[]) {
	if (!/[A-Za-z]{3,8}[^A-Za-z]+[A-Za-z]{3,8}/.test(text)) return;
	const list = bip39();
	// Runs of list words in any case, separated by anything without letters: blanks, commas, quotes, numbering
	// (`1. slow 2. core`), bullets, line breaks (`['slow', 'core', …]`, `Slow Core Trial`, one word per line).
	const words: { word: string; start: number; end: number; lineBreakBefore: boolean }[] = [];
	const flush = () => {
		if (words.length >= 12) findPhrases(words, list, out);
		words.length = 0;
	};
	let last = -1;
	const isLetter = (i: number) => {
		const folded = text.charCodeAt(i) | 32;
		return folded >= 97 && folded <= 122;
	};
	for (let at = 0; at < text.length;) {
		if (!isLetter(at)) {
			at++;
			continue;
		}
		let end = at + 1;
		while (end < text.length && isLetter(end)) end++;
		// (Only a word of the list's lengths is looked up; any other, and a gap too long, ends the run.)
		const w =
			end - at >= BIP39_WORD_LENGTHS[0] && end - at <= BIP39_WORD_LENGTHS[1] ? text.slice(at, end).toLowerCase() : "";
		if (list.has(w)) {
			const gap = last < 0 ? "" : text.slice(last, at);
			// (A line's indentation is one separator, not twelve. Code's joints and operators separate no phrase's words:
			// `chunk.item.type == "…"`, `model_dump`, `ignore_index=True`.)
			if (gap.replace(/\s+/g, " ").length > MAX_PHRASE_GAP || /[_=()]|\.(?=[A-Za-z])/.test(gap)) flush();
			words.push({ word: w, start: at, end, lineBreakBefore: /\n/.test(gap) });
		} else flush();
		last = end;
		at = end;
	}
	flush();
}

/** The shortest and longest word of BIP-39's English list. */
const BIP39_WORD_LENGTHS = [3, 8];

/** The most characters between two words of a phrase, blanks counted once. */
const MAX_PHRASE_GAP = 12;

/** List words a label before a phrase is made of: `Seed phrase:`, `secret key:`, `private key words:`. */
const LABEL_WORDS = new Set(["seed", "phrase", "secret", "key", "word", "list", "private"]);

/**
 * Windows of 12–24 words with a valid checksum (published phrases aside), longest first, each word in one at most.
 * A window starts a run or a line, or follows a label of list words on its line (`Seed phrase: slow core …`).
 * In a run longer than 48 words (a word list, or several phrases on their own lines) only whole lines count.
 */
function findPhrases(
	words: { word: string; start: number; end: number; lineBreakBefore: boolean }[],
	list: Map<string, number>,
	out: Finding[],
) {
	const long = words.length > 48;
	for (let i = 0; i < words.length; i++) {
		const startsLine = i === 0 || words[i].lineBreakBefore;
		// (A label may follow other list words on its line: `Copy this seed phrase: slow core …`.)
		if (!startsLine && (long || !LABEL_WORDS.has(words[i - 1].word))) continue;
		for (const n of [24, 21, 18, 15, 12]) {
			if (i + n > words.length) continue;
			const endsLine = i + n === words.length || words[i + n].lineBreakBefore;
			if (long && !(startsLine && endsLine && words.slice(i + 1, i + n).every((w) => !w.lineBreakBefore))) continue;
			// (Ending at the run's end or a line's, unless the run is short: a 13th word after a phrase is allowed.)
			if (!endsLine && words.length > 30) continue;
			const run = words.slice(i, i + n).map((w) => w.word);
			// (A phrase's words are mostly different; markup repeating its tag names isn't one.)
			if (new Set(run).size < n * 0.75) continue;
			const entropy = phraseEntropy(run.map((w) => list.get(w)!));
			if (!entropy) continue;
			if (isPublishedPhrase(run, entropy)) break;
			out.push({
				start: words[i].start,
				end: words[i + n - 1].end,
				kind: "seed phrase",
				rule: "structure:mnemonic",
				confidence: 0.99,
			});
			i += n - 1;
			break;
		}
	}
}

/** The entropy bytes 11-bit word indices encode, if their BIP-39 checksum (the first ENT/32 bits of SHA-256(entropy)) verifies. */
function phraseEntropy(indices: number[]): Uint8Array | undefined {
	const bits = indices.map((x) => x.toString(2).padStart(11, "0")).join("");
	const cs = bits.length / 33;
	const ent = bits.slice(0, bits.length - cs);
	const bytes = new Uint8Array(ent.length / 8);
	for (let k = 0; k < bytes.length; k++) bytes[k] = parseInt(ent.slice(k * 8, k * 8 + 8), 2);
	const hashBits = sha256(bytes)[0].toString(2).padStart(8, "0");
	return hashBits.slice(0, cs) === bits.slice(bits.length - cs) ? bytes : undefined;
}

/** Whether a text is a published BIP-39 phrase (see isPublishedPhrase): 12 to 24 list words whose checksum verifies. */
export function isPublishedMnemonic(text: string): boolean {
	const list = bip39();
	const words = text
		.toLowerCase()
		.split(/[^a-z]+/)
		.filter(Boolean);
	if (words.length < 12 || words.length > 24 || words.length % 3 || !words.every((w) => list.has(w))) return false;
	const entropy = phraseEntropy(words.map((w) => list.get(w)!));
	return !!entropy && isPublishedPhrase(words, entropy);
}

/** The first words of development wallets' published phrases: Truffle's, Ganache's, ethers' docs', Osmosis' localnet, Hardhat's. */
const PUBLISHED_PHRASES = [
	"candy maple cake sugar",
	"myth like bonus scare",
	"announce room limb pattern",
	"notice oak worry limit",
	"test test test test",
];

/**
 * A phrase published on purpose: a test vector, whose entropy is one or two repeated bytes (BIP-39's `abandon … about`,
 * `legal winner … yellow`, `letter advice … above`, `zoo … wrong`), or a development wallet's (`candy maple cake
 * sugar …`). A random phrase starts like one with odds below 2^-40.
 */
function isPublishedPhrase(words: string[], entropy: Uint8Array): boolean {
	return new Set(entropy).size <= 2 || PUBLISHED_PHRASES.some((p) => words.join(" ").startsWith(p));
}
