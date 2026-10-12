/**
 * Values under a credential name, in the syntaxes tools print them: `NAME=value` (env, shell, ini,
 * properties), `name: value` (YAML, headers), `"name": "value"` (JSON), `name = "value"` and
 * `name: str = "value"` (code), `name => 'value'`, `--name value`, `<name>value</name>`,
 * `name="value"` attributes, `NAME value` (redis.conf, Dockerfile ENV, tables), Kubernetes
 * `- name:`/`value:` pairs, YAML block scalars and prose (`the password is …`).
 *
 * A value is hidden only if it's a literal secret: not a type, placeholder, reference or code (see
 * values.ts). Generic names (`key`, `token`, `auth`) also need a value that looks generated, since
 * `"key": "user.name"` and `token: bearer` are everywhere.
 */
import {
	type Argument,
	callArguments,
	calls,
	closingBracket,
	type Literal,
	literalEnd,
	literalAt,
	literalHead,
} from "./calls.ts";
import {
	attributes,
	type Cell,
	delimitedCells,
	group,
	isEscapedBreak,
	MAX_VALUE,
	PAIR_NAME,
	UNQUOTED_READ,
	PAIR_VALUE,
	PIPE_RULE,
	PIPE_RULE_START,
	pipeCells,
	quoted,
	type Span,
	stringEnd,
	unquotedValue,
	withoutUnopenedClosers,
} from "./syntax.ts";
import { lineEnd as lineEndAt, lineStart as lineStartAt, lowerBound, splitLines } from "./lines.ts";
import { BIP39_WORDS } from "./bip39-data.ts";
import { insertCells } from "./sql.ts";
import { isUrl, queryParams, urls } from "./urls.ts";
import { blockExtent, isBlockIndicator, yamlLines } from "./yaml.ts";
import { naturalness } from "./charlm.ts";
import { clientSdkAt, isPlaceholder } from "./public.ts";
import { jsonDocuments, type JsonNode } from "./json.ts";
import { PROMPT } from "./shell.ts";
import { promptsForValue } from "./commands.ts";
import {
	CREDENTIAL_QUALIFIERS,
	CREDENTIAL_WORD,
	phraseBefore,
	FOREIGN_PASSWORD_SPELLINGS,
	isCredentialName,
	PHRASE_STOP,
	isGenericName,
	readPhrase,
	isPasswordName,
	isPinName,
	nameClass,
	PASSWORD_SPELLINGS,
	readName,
	takesAnyWord,
} from "./names.ts";
import type { Finding } from "./types.ts";
import {
	ALGORITHM,
	CJK_COUNT,
	isBenignValue,
	isForeignText,
	characterClasses,
	isRandomToken,
	COMMON_WORDS,
	cleanValue,
	isBalanced,
	isCode,
	isTestValue,
	isGeneratedSegment,
	isPasswordLabel,
	isPath,
	isGroupedDigits,
	isIdentifierShaped,
	isInert,
	hasThreeClasses,
	isNameLike,
	isWordy,
	looksSecret,
	readsAsWords,
} from "./values.ts";

/** A name that could be a credential's: cheap lookahead so other names never start a match. */
const NAME = String.raw`((?=[\p{L}\p{N}_.$@-]{0,80}?(?:${CREDENTIAL_WORD}))[\p{L}_$@][\p{L}\p{N}_.$@-]{0,80})`;
// A name doesn't start inside a word or right after a backslash, except an escape before it in a JSON string (`\n`,
// `\r`, `\t`: a line of an encoded file).
// (`keystore/release_password="…"` in a Godot preset: a `section/name` key at the start of a line.)
const ASSIGN = new RegExp(
	String.raw`(?:(?<=\\[nrt])|(?<=(?:^|\n)[ \t]*[\w.-]{1,60}\/)|(?<![\p{L}\p{N}_.$@/-]|\$\{|\\))(\\?["'${"`"}]?)${NAME}\1(?:\[\])?\]?[ \t]{0,40}(=>|:=|\?=|\|\|=|===?|=|:(?!:))[ \t]{0,40}`,
	"dgiu",
);
const FLAG = /(?:^|[\s"'`(]|(?<=\\[nrt]))(--?[A-Za-z][\w-]{0,60})(?:[ \t]{1,4}|=)(?=[^\s-])/g;
/**
 * An XML element's text, plain or in a CDATA section (Jenkins `credentials.xml`, Maven `settings.xml`, Android
 * resources), as two groups from `n`: the section's content, or the plain text. elementText picks the one that matched.
 */
const XML_TEXT = (min: number) =>
	String.raw`(?:<!\[CDATA\[([^\n]{${min},${MAX_VALUE}}?)\]\]>|([^<\n]{${min},${MAX_VALUE}}?))`;
const elementText = (m: RegExpMatchArray, n: number) => group(m, m[n] !== undefined ? n : n + 1);
const XML_ELEMENT = new RegExp(String.raw`<([\w:.-]{1,80})(?:\s[^<>]{0,200})?>${XML_TEXT(1)}<\/\1>`, "dg");
const SPACED =
	/^([ \t║┃│|]{0,20}"?(?:ENV[ \t]+|set[ \t]+|setenv[ \t]+|SetEnv[ \t]+|config set[ \t]+|ARG[ \t]+)?)([A-Za-z_][\w.-]{1,80})([ \t]*[│|┃║][ \t]*|[ \t]+)(?=[^\s=:│|┃║])/gm;

/** Prefixes tools put before a line: diff `+`/`-`, grep `path:12:`, `cat -n`/`nl` numbers, log timestamps. */
const LP = String.raw`(?:[+-](?=[ \t\w])|\d{1,7}[:|\t→-]|[\w./-]{1,200}:\d{1,7}[:-]|\d{4}-\d\d-\d\dT[\d:.]+Z?[ \t])?[ \t]*`;
/** What may come before `NAME=` on an env line, and before `key:` on a YAML line. */
const ENV_LINE_START = new RegExp(
	String.raw`^[ \t]*${LP}(?:export[ \t]+|declare[ \t]+-x[ \t]+|set[ \t]+-gx[ \t]+|\+|-[ \t]+|#[ \t]*|ENV[ \t]+|ARG[ \t]+)?$`,
);
const YAML_LINE_START = new RegExp(String.raw`^[ \t]*${LP}(?:-[ \t]+)?["']?$`);

/** Keywords that declare a variable rather than qualify its name: `export TOKEN=…`, `let key = …`. */
const DECLARATION =
	/^(?:export|declare|local|readonly|typeset|const|let|var|val|final|static|private|protected|String|string|str|ENV|ARG|set|setenv)$/;

/** The last meaningful word of a name, for deciding how strict to be about its value. */
const lastWord = (name: string): string => readName(name).last;

/** A UI label or message rather than a password: a sentence, Title Case, or the name repeated. */
function isLabel(value: string, name: string): boolean {
	// Title Case words. (One capitalised word is a password as much as a label, `Sunshine`, `Großmutter`: a label of one
	// word is "password" in some language, isPasswordLabel's. Words with no sentence's word among them are a passphrase:
	// `Correct horse battery staple`.)
	// (Or with another language's grammar among them, a translated label: `Bevestig mijn account`.)
	if (
		/^\p{Lu}\p{Ll}+(?: \p{L}\p{Ll}*)+[.:!?]?$/u.test(value) &&
		(!isPassphrase(value.split(" ")) || value.split(" ").some((w) => FOREIGN_FUNCTION_WORDS.has(w.toLowerCase())))
	)
		return true;
	if (/[^\x00-\x7f]/.test(value) && /^[\p{L}\p{M}\d .,!?'’()-]+$/u.test(value) && / \p{L}/u.test(value)) return true;
	// A sentence; but a passphrase is words by design, and only its UI text says "enter" or "your".
	const phrase = /PHRASE|MNEMONIC|SEED/.test(lastWord(name));
	if (
		value.split(/\s+/).length >= 3 &&
		(phrase
			? /\b(enter|please|your|must|at least|invalid|incorrect|required|characters?)\b/i
			: /\b(the|your|is|are|be|to|for|of|and|enter|please|must|at least|invalid|incorrect|required|characters?)\b/i
		).test(value)
	)
		return true;
	const flat = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, "");
	// (Or the name's own end, as docs fill each option with its name: `--user user --key key --passphrase phrase`.)
	return (
		flat(value) === flat(name) ||
		(/^[\p{L} _.-]+$/u.test(value) &&
			(flat(value).endsWith(flat(lastWord(name))) || (flat(value).length >= 4 && flat(name).endsWith(flat(value)))))
	);
}

/** Names about how a credential is handled, not the credential: `update_password`, `password_mechanism`, `pin_mode`. */
const SETTING_OF_CREDENTIAL =
	/(?:^|[^a-z])(?:update|change|check|rotate|lock|expire|expiry|mechanism|method|mode|strategy|policy|type|format)(?:$|[^a-z])|(?:password|passwd)[_-]?(?:encryption|hash(?:ing)?[_-]?algorithm|algorithm|scheme)(?:$|[^a-z])/i;

/** Words near a PIN that make it a postal code. */
const POSTAL = /\b(?:city|state|address|street|road|district|postal|zip|country|landmark|locality)\b/i;

/**
 * Whether `label` is the ID half of a `label:secret` value under credential name `name` (Dagster's `user:<token>`,
 * a catalog's `<client id>:<secret>`): a name, a number, an email, a UUID, a hex ID or a short ID. Under a password's name the
 * whole value is the password, and a label as random as its secret is part of it (`pR7kQ2mX9vL4nB8w:Ht6J…`).
 */
export function isPairLabel(name: string, label: string): boolean {
	if (takesAnyWord(name)) return false;
	return (
		label.length <= 12 ||
		readsAsWords(label) ||
		/^\d+$|^[\w.+-]+@[\w-]+(?:\.[\w-]+)+$/.test(label) ||
		/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$|^[0-9a-f]{8,40}$/i.test(label)
	);
}

/** Where the secret starts in a `label:token` value under a credential's name, or -1. */
function credentialPair(name: string, value: string): number {
	const m = /^([\w.@-]{1,64}):([A-Za-z0-9+/_~-]{16,4096}={0,2})$/.exec(value);
	// (Not a digest's name, `sha256:<b64>`, as names.ts reads one, nor an encoding's or a version's: `hex:`, `v2:`.)
	if (
		!m ||
		isGenericName(name.replace(/^[-$@]+/, "")) ||
		nameClass(m[1]) === "hash" ||
		/^(?:sha3-\d+|xxh\d*|sri|v\d+|\d+|hex\w*|b64\w*|base64\w*|raw\w*|str\w*|utf-?8\w*)$/i.test(m[1]) ||
		naturalness(m[2]) >= 0.5 ||
		!isPairLabel(name, m[1])
	)
		return -1;
	return m[1].length + 1;
}

/**
 * Cache keys, object keys, content addresses: a hash with words or paths around it (`linux-deps-<sha>`,
 * `objects/<sha>`, `sha256:<hex>`, `v2-cache-<sha>`). Not a vendor's key, one short prefix and the hex (Firecrawl's
 * `fc-<hex>`), nor a token with a hash beside it (a Rails cookie, `<base64>--<hmac>`): every other part is a number, a
 * short word or one that reads as a name (`fabrikam`, `PaymentApiKey`; random letters score far lower).
 */
function isHashWithWords(value: string): boolean {
	if (!/[0-9a-f]{16,}/i.test(value) || !/[-_/.:|+~]/.test(value) || /^[a-z]{2,4}[-_][0-9a-f]{24,}$/i.test(value))
		return false;
	return value
		.replace(/[0-9a-f]{16,}/gi, "")
		.split(/[-_/.:@()=;?&|+~]+/)
		.every(
			(part) =>
				part === "" ||
				/^v?\d{1,8}$/i.test(part) ||
				(part.length <= 24 &&
					/^[A-Za-z]+\d{0,4}$/.test(part) &&
					(part.length <= 4 || naturalness(part.toLowerCase()) > -0.5)),
		);
}

/**
 * Whether `pass` after the word `before` is the verb or the noun: after what a test run counts or an ordinal (`All tests
 * pass:`, `First pass:`, `each pass`). After a thing it is a password's label (`wifi pass:`, `Redis pass:`, `His pass:`),
 * after a type a variable (`char pass[]`).
 */
function isPassInEnglish(before: string): boolean {
	return /^(?:tests|cases|checks|builds|specs|assertions|suites|jobs|steps|runs|lints|linters|examples|scenarios|validations|benchmarks|things|all|first|second|third|final|last|next|one|two|three|each|every|both|single|double|another|initial|this|that)$/i.test(
		before,
	);
}

/** Under a bare `pass`, a snake_case identifier: a test's or a rule's name in a verdict list (`- pass: expired_command`), not a password. */
function isVerdictUnderPass(name: string, value: string): boolean {
	return /^pass$/i.test(name) && /^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$/.test(value);
}

/** An entity key: `ORDER#2026-09-30#o_4411`, `USER#42`. */
const ENTITY_KEY = /^[A-Z][A-Z0-9_]{1,30}(?:#[\w.:@-]{1,60}){1,4}$/;
/** A partition key's name in a pair: `PK: 'CUSTOMER#c_8812'`, `"pk": …`, `partitionKey=`. */
const PARTITION_KEY = /(?:^|[\s{,"'])(?:PK|pk|partitionKey|hashKey)["']?[ \t]*[:=]/;

/**
 * A value its name says is no credential's: a setting of how one is handled, a word or two in lower case (Ansible's
 * `update_password: always`, `password_mechanism: sshpass`, `password_lock: false`) or a hashing scheme's name
 * (PostgreSQL's `password_encryption = 'scram-sha-256'`); or a placeholder that names its own variable, with markup
 * around it (`POSTGRES_PASSWORD=!!!SET POSTGRES_PASSWORD!!!`, `ELASTIC_PASSWORD=$ELASTIC_PASSWORD <1>`; not a token
 * that starts with its name, `API_TOKEN_9fQ2mL…`, nor a password made of it, `DB_PASSWORD1`).
 */
function isSettingOrSelfName(name: string, value: string): boolean {
	if (
		SETTING_OF_CREDENTIAL.test(name) &&
		(/^[a-z]+(?:[_-][a-z]+)*$/.test(value) ||
			/^(?:scram|sha|md5|argon2|bcrypt|scrypt|pbkdf2|crypt|ssha|hmac|plain)(?:[_-]?[a-z0-9]+)*$/i.test(value))
	)
		return true;
	// (Not the name assigned again, its own value after it: `s/# DBPassword=/a\DBPassword=<value>/`.)
	const rest =
		name.length >= 8 && value.includes(name) && !value.includes(`${name}=`) && !value.includes(`${name}:`)
			? value.split(name).join("")
			: undefined;
	return rest !== undefined && /[^\w]/.test(rest) && (rest.match(/[A-Za-z0-9]/g)?.length ?? 0) < 8;
}

/**
 * Whether `value` under credential name `name` is a secret. Password-like names accept any literal
 * that isn't a common word or label; key-like names need something that isn't a word or identifier.
 */
export function isNamedSecret(name: string, raw: string, literal = false): boolean {
	const value = cleanValue(raw);
	// A shell's backticks run a command: `PASSWORD=\`openssl rand -hex 16\``.
	if (/^`[a-z][\w.-]*\s[^`]*`$/.test(raw.trim())) return false;
	if (isVerdictUnderPass(name, value)) return false;
	// "Password" in another language: a form's label, not a password (i18n files, string resources).
	if (isPasswordLabel(value)) return false;
	// A JSON object or array as a string (`"SecretString": "{\"username\": …}"`): its own pairs are judged by name.
	// (Starting as JSON does: `{"`, `{key:`, `[1`, `["`, `[{`; `[bZ0{6tfzE&n2q:]` is a password in brackets.)
	if (
		/^\s*(?:\{.*\}|\[.*\])\s*$/s.test(value) &&
		/[:,]/.test(value) &&
		/^\s*(?:\{\s*(?:["'][^"']*["']|[A-Za-z_$][\w$-]*)\s*:|\[\s*(?:["'{[\d-]|true\b|false\b|null\b))/.test(value)
	)
		return false;
	const last = lastWord(name);
	// A PIN is a few digits (`pin: GPIO21` is a hardware pin; a postal PIN code has an address around it).
	// (Grouped digits too: `4821-7730`.)
	// (A passcode of letters is a password: judged as one below.)
	if (isPinName(name) && (/^\d/.test(value) || !isPasswordName(name)))
		return /^\d{4,8}$|^\d{2,8}(?:[- ]\d{2,8}){1,3}$/.test(value) && !/^[$%{<]/.test(value);
	// (Under a password's name, `PurpleRain1984` unquoted in an INI file is a password, not a class name.)
	const passwordName = takesAnyWord(name);
	if (isSettingOrSelfName(name, value)) return false;
	// (And digits with separators, a date or a phone number, are one: `DB_PASSWORD=21.05.1987`; an ISO date is a date, isGroupedDigits.)
	if (passwordName && isGroupedDigits(value)) return true;
	if (
		!(
			looksSecret(raw, literal) ||
			(passwordName && /^[A-Z][A-Za-z0-9]{2,40}$/.test(value) && /\d/.test(value) && looksSecret(raw, true))
		) ||
		isLabel(value, name)
	)
		return false;
	if (/^(SEED|SALT)$/.test(last) && /^[\d.]+$/.test(value)) return false;
	// A value under a signature's name is a signature (a payment callback's, a webhook delivery's, an RSA, ECDSA or
	// Ed25519 one), public once sent; the secret that makes one is named a secret or a key. A `…Sig` constant of 32–64
	// characters, a signing key's length, is more often an HMAC key. (Signed URLs are judged by their own rule.)
	if (last === "SIGNATURE" || (last === "SIG" && value.length > 64)) return false;
	if (/^(PREFIX|HINT|LAST4|SUFFIX)$/.test(last)) return false;
	// A constant's name under a dictionary key (`brandKey=KSBrandID` in a plist log): letters in a name's case, in
	// words (`zvCadApKxYVYHo` isn't).
	if (
		!passwordName &&
		/[a-z]Key$/.test(name) &&
		/^[A-Za-z]{4,40}$/.test(value) &&
		/[A-Z].*[A-Z]/.test(value) &&
		readsAsWords(value) &&
		naturalness(value.replace(/([a-z])([A-Z])/g, "$1 $2")) > 0
	)
		return false;
	// Seeds, mnemonics and phrases worth hiding are wallet phrases (12+ words) or long random values;
	// `level-seed=…`, `mnemonic: "MOVZX"`, `"phrase": "machine learning"` are not.
	if (
		/^(SEED|MNEMONIC|PHRASE)$/.test(last) &&
		/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)
	)
		return false; // a seed node's ID
	if (/^(SEED|MNEMONIC|PHRASE)$/.test(last)) {
		const n = value.trim().split(/\s+/).length;
		return n >= 12 || (n === 1 && value.length >= 32 && naturalness(value) < 0.5);
	}
	if (passwordName) {
		// A bare `pass` is also a verb and a test counter (`tests pass: AGPL`, `PASS  =/2 binds variable`,
		// `pass | 41/41`): one word with a digit or a symbol, and not a count.
		if (
			/^[-$@]*pass$/i.test(name) &&
			!/^\s*["'`]/.test(raw) &&
			(/\s/.test(value) || /^[A-Z]{2,}$/.test(value) || /^\d+(?:[/.,]\d+)*%?$/.test(value))
		)
			return false;
		// A test runner's status, not a password: `PASS: tests/test_auth.py::test_login`, `PASS  src/a.test.ts`.
		if (
			/^PASS(?:ED)?$/.test(name) &&
			/^[\w./:\[\]-]+$/.test(value) &&
			(/test|spec|::|\//i.test(value) || !(/[A-Z]/.test(value) && /[a-z]/.test(value) && /\d/.test(value)))
		)
			return false;
		// A compound adjective about the password, not one: `case-sensitive`, `write-only`, `per-user`.
		if (/^[a-z]{2,12}-[a-z]{2,12}$/.test(value) && value.split("-").every((p) => naturalness(p) > 0)) return false;
		if (
			COMMON_WORDS.has(value.toLowerCase()) ||
			(!/PHRASE/.test(last) && COMMON_WORDS.has(value.trim().split(/\s+/)[0].toLowerCase()))
		)
			return false;
		// Lower-case words holding a sentence's word say where the password is or what it's like (`see vault entry`,
		// `ask devops team`, `case sensitive`, `randomly generated`), as isPassphrase reads them. (A wallet's seed
		// phrase, twelve words or more, is any words.)
		if (/^[a-z]+(?:[ \t]+[a-z]+){1,10}[.!]?$/.test(value.trim()) && value.trim().split(/\s+/).some(isSentenceWord))
			return false;
		const maxWords = /PHRASE/.test(last) ? 24 : 6;
		if (/\s/.test(value) && value.split(/\s+/).length > maxWords) return false;
		return true;
	}
	// A URL under a credential name is a secret when its path carries a generated token (a webhook).
	// (Its password is the URL reader's: structure.ts.)
	if (isUrl(value))
		return [...urls(value)].some((u) =>
			[...u.segments, ...[...queryParams(value)].map((p) => p.value)].some((p) => isRandomToken(p.value)),
		);
	// `label:token` under a credential's name (Dagster's `user:<token>`, a catalog's `<client id>:<secret>`): a pair,
	// not a cache key or a digest (`sha256:…`). The caller hides the part after the colon (credentialPair).
	if (credentialPair(name, value) > 0) return true;
	if (isHashWithWords(value) && !/^[A-Za-z0-9+/]+=*$/.test(value)) return false;
	if (/^[-+]?\d*\.?\d+(?:e[-+]?\d+)?$/i.test(value)) return false; // numbers: ports, counts, floats, numeric session ids
	// Keys and tokens: generated values, not identifiers, words or sentences.
	if (/\s/.test(value) && !/^(Bearer|Basic|Token) /.test(value)) return false;
	if (value.length < 8) return false;
	// A UUID under a credential name is a key (Heroku and others issue them), unless the name says ID.
	// (A session's ID as a UUID or an object ID names a session, as Claude Code's `sessionId` does; a random one is its cookie.)
	if (
		/session[_-]?id$|sessionId$|sess[_-]?id$/i.test(name) &&
		(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value) ||
			/^[a-z]{1,8}_[A-Za-z0-9]{8,}$/.test(value))
	)
		return false;
	if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value))
		return !/ID$/.test(last) || /(?:^|[-_ ])secret[-_ ]?id$/i.test(name);
	if (isIdentifierShaped(value)) return false;
	// Words, and code made of them: `my-signing-config`, `env(DATABASE_URL)`, `CORP\svc_deploy`.
	// (Mostly letters: on a value mostly of symbols the model reads nothing. And each word one: the model reads
	// camel-case breaks and symbols as likely word ends, so `JujvAIngWfOqw` and `)AM{?NfoSuFiMi.s` would score as words.)
	if (
		naturalness(value) > 1.0 &&
		(value.match(/[A-Za-z]/g)?.length ?? 0) >= value.length * 0.6 &&
		readsAsWords(value) &&
		(/[^A-Za-z0-9]/.test(value) || isNameLike(value))
	)
		return false;
	// (Letters alone can still be generated: `WnDKpEQCbOciskIKhAfdQxFmY` reads as no words.)
	if (
		isWordy(value) &&
		!hasThreeClasses(value) &&
		value.length < 40 &&
		!(/^[A-Za-z]{16,}$/.test(value) && naturalness(value) < 1.2)
	)
		return false;
	// dotted.config.keys, kebab-names, a word in any script (`--rpc-secret bayrağını kullanın`, Turkish for "use the flag").
	if (/^\p{Ll}+(?:[._-]\p{Ll}+)*$/u.test(value)) return false;
	if (isGenericName(name.replace(/^[-$@]+/, ""))) {
		// Cache keys, object keys, content addresses: hashes with words or paths around them.
		// (Line-shaped base64 passes the test above; under a generic name a hex run with `/` is still a key path.)
		// (Pure hex of 32 or 40 under a bare `secret` or `token` is one: Facebook app secrets, webhook secrets;
		// 64 is a SHA-256, as Laravel Sanctum stores its tokens.)
		if (
			/[0-9a-f]{16,}/i.test(value) &&
			(/[-_/.:]/.test(value) ||
				(/^[0-9a-f]+$/i.test(value) &&
					!(
						/^(?:secret|token|tokens)$/i.test(name.replace(/^[-$@]+/, "")) &&
						(value.length === 32 || value.length === 40)
					)))
		)
			return false;
		// A path or an object key: a path's characters only, with a `.`, `_` or `-` base64 never has (`uploads/<id>.png`,
		// `_pending/<id>/transit`), or segments that are all words (`config/keys`). Not a key in base64 with a word-like
		// piece, nor a password with symbols.
		if (
			/\//.test(value) &&
			(isPath(value) ||
				(/^[\w./-]+$/.test(value) &&
					(/[._-]/.test(value) ||
						value
							.split("/")
							.filter(Boolean)
							.every((seg) => !isGeneratedSegment(seg) && naturalness(seg.toLowerCase()) > 0.5))))
		)
			return false;
		// `"key": "user.name"`, `token: refresh`: a bare generic name needs a generated-looking value.
		// (Or a made password: three character classes, a symbol among them, `CANYpfso8s%` as an express-session secret.)
		return (
			(value.length >= 12 && naturalness(value) < 0.6 && /\d/.test(value)) ||
			(value.length >= 20 && naturalness(value) < 0.2) ||
			(value.length >= 8 &&
				characterClasses(value) >= 3 &&
				/[^A-Za-z0-9._-]/.test(value) &&
				!isCode(value, true) &&
				naturalness(value) < 1)
		);
	}
	return true;
}

/** What ends a bare value in code (`,` `;` `)` `]` `}` quotes, blanks, a table's bar) and in a shell word (blanks, quotes, operators). */
const CODE_VALUE_END = /[ \t,;&)\]}"'`<|│┃║]/;
const SHELL_WORD_END = /[ \t;&|<>()"'`]/;

/** The word after a quote that never closes, to its line's end. */
const UNCLOSED_WORD = new RegExp(`^${unquotedValue(String.raw`[^\s"'\x60]`, 4, String.raw`[ \t]*\r?$`)}`, "m");

/** Reads the value starting at `at`: quoted, JSON-escaped-quoted, or bare up to a delimiter. */
function readValue(
	text: string,
	at: number,
	{ toEol = false, shell = false, toBlank = false } = {},
): [number, number] | undefined {
	const c = text[at];
	// A triple-quoted string (Python, Kotlin and Swift raw strings, Java text blocks): to its closing triple.
	if ((c === '"' || c === "'") && text.startsWith(c.repeat(3), at)) {
		const close = text.slice(at + 3, at + 3 + MAX_VALUE).indexOf(c.repeat(3));
		return close < 0 ? undefined : [at + 3, at + 3 + close];
	}
	if (c === '"' || c === "'" || c === "`") {
		const close = literalEnd(text, at, { shell });
		if (close >= 0) return [at + 1, close];
		// (A quote that never closes on its line opens no string: the value is the one word after it, `DB_PASSWORD='Kx9…`.)
		const rest = UNCLOSED_WORD.exec(text.slice(at + 1, lineEndAt(text, at + 1, UNQUOTED_READ + 1) + 1));
		return rest ? [at + 1, at + 1 + rest[0].length] : undefined;
	}
	// `\"value\"` inside a JSON string (a transcript holding code).
	if (c === "\\" && (text[at + 1] === '"' || text[at + 1] === "'")) {
		const q = `\\${text[at + 1]}`;
		const end = text.indexOf(q, at + 2);
		if (end < 0 || end - at > MAX_VALUE) return undefined;
		return [at + 2, end];
	}
	// Inside a JSON string (an odd count of unescaped quotes before it on its line), a run of backslashes before a quote,
	// `n`, `r` or `t` ends the value: a quote, a line break or a tab at some level of encoding (`\"`, `\n`, `\\n` in text
	// encoded twice). Another run is the value's own backslash (`Vq7m\\2Lx`). Elsewhere a backslash is part of it
	// (`x9#Lq\tR2!` in a .env), except an escaped line break, which ends a line of escaped text (isEscapedBreak).
	// (Counted when a backslash first needs it.)
	let inStringAt: boolean | undefined;
	const inString = () =>
		(inStringAt ??=
			(text
				.slice(lineStartAt(text, at, 4000), at)
				.replace(/\\./g, "")
				.match(/"/g)?.length ?? 0) %
				2 ===
			1);
	let i = at;
	// (A bracket the value opened is its own: `%{K8S_TOKEN}`, `${DB_PASS}`, `Wint(er)2024`; another ends it. Inside a
	// shell expansion the value starts with, a blank is its own too: `${REDIS_PASSWORD:?set it first}`.)
	let open = 0;
	const expansion = text.startsWith("${", at);
	while (i < text.length && i - at < UNQUOTED_READ) {
		const ch = text[i];
		if (ch === "\n" || ch === "\r") break;
		if (ch === "\\" && inString()) {
			let run = 1;
			while (text[i + run] === "\\") run++;
			if (/["'nrt]/.test(text[i + run] ?? "")) break;
			i += run;
			continue;
		}
		if (ch === "\\" && isEscapedBreak(text, i)) break;
		if (ch === "(" || ch === "[" || ch === "{") open++;
		else if ((ch === ")" || ch === "]" || ch === "}") && open > 0) open--;
		else if (
			!toEol &&
			!(expansion && open > 0 && (ch === " " || ch === "\t")) &&
			(toBlank ? /[ \t]/ : shell ? SHELL_WORD_END : CODE_VALUE_END).test(ch)
		)
			break;
		i++;
	}
	// Trailing spaces and a trailing comment of a whole-line value.
	let end = i;
	if (toEol) {
		const comment = text.slice(at, end).search(/(?<![ \t])[ \t]+#/);
		if (comment >= 0) end = at + comment;
		while (end > at && /[ \t]/.test(text[end - 1])) end--;
	}
	return end > at ? [at, end] : undefined;
}

/** The opening of a heredoc: `<<EOF`, `<<-EOT`, `<<~SQL`, `<<'EOF'`. */
const HEREDOC = /^<<[-~]?[ \t]*(["']?)([A-Za-z_]\w*)\1[ \t]*\r?\n/;

/** Adds the value at `start`–`end` under credential name `name`, its kind read from the name. */
function namedFinding(out: Finding[], start: number, end: number, name: string, rule: string, confidence = 0.95) {
	const w = lastWord(name);
	const kind = isPasswordName(name)
		? "password"
		: /TOKEN/.test(w)
			? "token"
			: /SECRET/.test(w)
				? "secret"
				: /KEY/.test(w)
					? "key"
					: "credential";
	out.push({ start, end, kind, rule, confidence, name });
}

/**
 * Adds a string literal's content under `name` when the name it is judged under (`judgedAs`, by default the name
 * itself) is a credential's and the value is a secret under it.
 */
function namedValue(
	out: Finding[],
	name: string,
	value: Span,
	rule: string,
	{ judgedAs = name, confidence = 0.95 } = {},
) {
	if (!isCredentialName(judgedAs) || !isNamedSecret(judgedAs, `"${value.value}"`, true)) return;
	namedFinding(out, value.start, value.end, name, rule, confidence);
}

/** An encoding's name, which a converter takes beside the value it converts: `Buffer.from(key, "base64")`. */
const ENCODING = /^(?:utf-?8|utf-?16(?:le|be)?|latin-?1|ascii|iso-?8859-?\d+|cp\d+|base64|hex|binary|ucs-?2)$/i;

/** The rules, each a reader of one syntax; findNamed runs them all. */
const RULES: ((text: string, out: Finding[]) => void)[] = [
	assignments,
	flags,
	xmlElements,
	spacedPairs,
	configList,
	cDefines,
	referenceDefaults,
	envFallbacks,
	conditionalBranches,
	xmlNamedValues,
	dotLeaders,
	setterCalls,
	positionalCalls,
	pairCalls,
	comparisons,
	formFills,
	terraformVariables,
	diffArrows,
	pipeTables,
	replEchoes,
	jsonValues,
	userPassProse,
	dslCalls,
	declarations,
	substitutions,
	secretArguments,
	htmlPairs,
	foreignLabels,
	wrappedValues,
	columnTables,
	javaProperties,
	siblingPairs,
	userInfo,
	sqlRows,
	prose,
	labelledProse,
	passwordShaped,
];

/** Values under a credential name. (Values public by design, client-side Google keys and DocSearch keys among them, are policy.ts's.) */
export function findNamed(text: string): Finding[] {
	const out: Finding[] = [];
	for (const rule of RULES) rule(text, out);
	return out.filter((f) => !explainedByNeighbours(text, f)).flatMap((f) => urlTokens(text, f));
}

/**
 * Whether the text around a finding says its value is no secret, whichever reader found it (isNamedSecret judges the
 * value under its name; this, what stands near them, within 200 characters before and 100 after).
 */
function explainedByNeighbours(text: string, f: Finding): boolean {
	const near = text.slice(Math.max(0, f.start - 200), f.end + 100);
	const value = cleanValue(text.slice(f.start, f.end));
	const name = f.name ?? "";
	// A single-table database's key: an entity's name, then its parts (`ORDER#2026-09-30#o_4411`), beside the partition
	// key it sorts under (`PK: 'CUSTOMER#c_8812'`). (`sk` alone can name a secret key: the shape and the `PK` decide.)
	if (ENTITY_KEY.test(value) && PARTITION_KEY.test(near)) return true;
	// A postal PIN code, with an address around it.
	if (isPinName(name) && POSTAL.test(near)) return true;
	// A translation file: several neighbouring values are phrases (`password: facal-faire` among
	// `otp: aplacaid dearbhaidh dhà-cheumnaich`, `sign_in_token: cuir còd …`).
	if (
		/[\s-]/.test(value) &&
		/^[\p{L}\p{M}'’ -]+$/u.test(value) &&
		(near.match(/^[ \t]*[\w.-]{1,60}:[ \t]+["']?\p{L}[\p{L}\p{M}'’,.-]*(?:[ \t]+[\p{L}\p{M}'’,.-]+){2,}["']?[ \t]*$/gmu)
			?.length ?? 0) >= 3
	)
		return true;
	// A default: the password is the user's or the database's name (`POSTGRES_USER=app` / `POSTGRES_PASSWORD=app`).
	// (In the other pairs near it, under a whole name: `INFLUXDB=<value>` isn't a database named <value>.)
	if (value && value.length <= 32) {
		const esc = value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
		const others = near.replace(
			new RegExp(String.raw`[\w.-]*${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}["']?[ \t]*[:=][^\n]*`, "g"),
			"",
		);
		if (
			new RegExp(
				String.raw`(?<![\w.-])(?:[\w.-]*[_.-])?(?:user(?:name)?|login|db|database|dbname|name|account)["']?[ \t]*[:=][ \t]*["'\`]?${esc}["'\`]?(?:[\s,;]|$)`,
				"i",
			).test(others)
		)
			return true;
	}
	return false;
}

/**
 * A URL a name says is a secret (`password: https://…/reset/<token>`, `SLACK_WEBHOOK=https://hooks…/<token>`) is one by
 * the tokens in it (isNamedSecret): those are hidden, the URL around them is kept.
 */
function urlTokens(text: string, f: Finding): Finding[] {
	const value = text.slice(f.start, f.end);
	if (!isUrl(value)) return [f];
	const [url] = urls(value);
	if (!url || url.end !== value.length) return [f];
	const parts = [url.password, ...url.segments, ...[...queryParams(value)].map((p) => p.value)].filter(
		(p) => p && isRandomToken(p.value),
	) as Span[];
	return parts.length ? parts.map((p) => ({ ...f, start: f.start + p.start, end: f.start + p.end })) : [f];
}

/**
 * SQL rows, each value under its column's name: `INSERT INTO users (email, password) VALUES ('ann@x.io', 'V'), (…)`.
 * (`UPDATE … SET password = 'V'` is an assignment; a psql grid, a table.)
 */
function sqlRows(text: string, out: Finding[]) {
	for (const { column, value } of insertCells(text, (_, columns) => columns.some(isCredentialName))) {
		if (value.literal && isCredentialName(column) && isNamedSecret(column, `'${value.literal.value}'`, true))
			namedFinding(out, value.literal.start, value.literal.end, column, "named:sql-row");
	}
}

/** An INI or TOML section header line: `[database]`, `[profile "prod"]`. */
const INI_SECTION = /(?:^|\n)[ \t]*\[[\w. "'-]{1,80}\][ \t]*\r?(?=\n)/g;
/** A flag that sets an environment variable or a property, before `NAME=value`: `-e`, `--env`, `--build-arg`, `-D`, `--set`. */
const ENV_FLAG = /(?:^|\s)(?:-e|--env|--build-arg|-D|--set|--set-string|--var|-var|env)[ \t]+["']?$/;

/**
 * `name = value` in the syntaxes ASSIGN reads. The value is a string literal (with its prefix or wrapper, in
 * parentheses, or passed to a converter), a bare word, the rest of an env, YAML or INI line, a YAML block scalar or
 * a heredoc.
 */
function assignments(text: string, out: Finding[]) {
	let sections: number[] | undefined;
	// Whether a section header is within 4,000 characters above `at`.
	const underSection = (at: number) => {
		sections ??= [...text.matchAll(INI_SECTION)].map((m) => m.index);
		const i = lowerBound(sections, at) - 1;
		return i >= 0 && at - sections[i] <= 4000;
	};
	ASSIGN.lastIndex = 0;
	for (let m = ASSIGN.exec(text); m; m = ASSIGN.exec(text)) {
		const name = m[2].replace(/^[$@]+/, "");
		if (!isAssignedName(text, m, name)) continue;
		const [opStart, opEnd] = m.indices![3]!;
		let op = m[3];
		let at = m.index + m[0].length;
		const lineStart = lineStartAt(text, m.index);
		const before = text.slice(lineStart, m.index);
		// `DB_PASSWORD==x…`, `- POSTGRES_PASSWORD=>>y…`: an env-shaped name glued to its operator on an env line, or after
		// an env flag, takes the first `=` as the operator; the value starts with whatever follows it. Any other
		// operator followed by `=` or `>` isn't one.
		// (So does any unquoted name that starts a line, as `.properties` and INI lines are read: `spring.datasource.password==x`.)
		// (Not a pinned requirement, `django-secrets==0.1.dev3`: there `==` pins a version.)
		const envGlued =
			m[1] === "" &&
			opEnd === at &&
			text[opStart] === "=" &&
			((/^[A-Z][A-Z0-9_]*$/.test(name) && (ENV_LINE_START.test(before) || ENV_FLAG.test(before))) ||
				/^[ \t]*$/.test(before)) &&
			!isBenignValue(/^\S*/.exec(text.slice(opEnd))![0]);
		if (/[=>]/.test(text[opEnd] ?? "") || (/^(?:==|===|=>)$/.test(op) && envGlued)) {
			if (!envGlued) continue;
			at = opStart + 1;
			op = "=";
		}
		// (No blank after the operator: `NAME=value`, not `name = value`.)
		const tight = at === opEnd || op !== m[3];
		// `password: str = "x"`, `apiKey: string = "x"`: skip a type annotation. (Unspaced, `password: str='x'`, only a
		// built-in type's: `start='…'` and `MAC id="…"` aren't annotations.)
		const typed =
			op === ":"
				? /^(?:[A-Za-z_&*][\w.<>\[\]|?, &'*]{0,60}?[ \t]+=(?!=)[ \t]*|(?:str|bytes|int|float|bool|string|number|boolean|SecretStr|(?:Optional|Union|list|dict)\[[\w., |]{1,40}\])(?:[ \t]*\|[ \t]*None)?=(?=["']))/.exec(
						text.slice(at, at + 80),
					)
				: null;
		if (typed) at += typed[0].length;
		// Aligned columns: `SecretID:          <value>`.
		while (text[at] === " " || text[at] === "\t") at++;
		// `MYSQL_USER=root MYSQL_PASSWORD= FILTER=x npm test`: an empty variable, the next one's pair after it.
		if (
			op === "=" &&
			at > opEnd &&
			/^[A-Z][A-Z0-9_]*$/.test(name) &&
			/^[A-Za-z_]\w*=(?!=)/.test(text.slice(at, at + 80))
		)
			continue;
		// `password: |` YAML block scalar, `password = <<EOT` heredoc: the lines below.
		// (The indicator, and a comment after it however long: yaml.ts reads the line.)
		const eol = lineEndAt(text, at);
		if (op === ":" && /^[|>]/.test(text[at] ?? "") && isBlockIndicator(text.slice(at, eol)) && text[eol] === "\n") {
			multiLineValue(out, name, blockExtent(text, lineStart), "named:block");
			continue;
		}
		if (HEREDOC.test(text.slice(at, at + 100))) {
			multiLineValue(out, name, heredoc(text, at), "named:heredoc");
			continue;
		}
		// A string literal's prefix or wrapper: Python `b'…'`, `r'…'`, `f"…"`, C# `@"…"` and `$"…"`, Rust `r#"…"#`,
		// `Some("…")`, `String::from("…")`.
		const head = literalHead(text, at);
		if (head && text[head.open] !== "`") at = head.open;
		const prefix = head?.prefix ?? "";
		const unquoted = !/["'`]/.test(text[at] ?? "");
		// (Not an object literal's entry: code before its `,`, a name, a constant or a bracketed expression, its brackets
		// balanced as a random password's rarely are: `  password: userPassword,`, `Keys: []string{"a"},`, an interface's
		// generic type, `password: Secret<String>;`.)
		const entry = /^(.*?)[ \t]*[,;{][ \t]*\r?$/.exec(text.slice(at, lineEndAt(text, at)))?.[1];
		// `"NAME=value with spaces"` (docker inspect, compose lists): the value runs to the quote that opened the pair,
		// escaped as it was (`\"NAME=value\"` inside a JSON string).
		const pairQuote = m[1] === "" && op === "=" && /["']/.test(text[m.index - 1] ?? "") ? m.index - 1 : -1;
		// An entry of a call or a literal written over several lines, the line before opening a bracket or ending an entry
		// (`login(\n  password=user_input[CONF_PASSWORD],`, `{\n  'password': None},`), or its last entry (isLastEntry):
		// code, its value read as code is, not a whole-line env, YAML or INI value nor a log's pair. (Its value may open a
		// call of its own, its arguments on the lines below: `),\n  MasterUserPassword=Join(`; a callee in words, as a
		// password ending in `(` is not.)
		const opensCall = /^([A-Za-z_$][\w$.]*)\([ \t]*\r?$/.exec(text.slice(at, lineEndAt(text, at)))?.[1];
		const continued =
			pairQuote < 0 &&
			(((entry !== undefined || (opensCall !== undefined && readsAsWords(opensCall))) &&
				/[,([{][ \t]*\r?\n$/.test(text.slice(Math.max(0, lineStart - 400), lineStart))) ||
				isLastEntry(text, at));
		// A whole-line `NAME=value` (env, export) or YAML `key: value` runs to the end of the line, spaces included.
		// (A sigil makes the name code's variable, not an environment's or an INI file's: Perl's `@key=map(…);`.)
		const sigil = /^[$@]/.test(m[2]);
		const envLine = op === "=" && m[1] === "" && tight && !continued && !sigil && ENV_LINE_START.test(before);
		const yamlLine =
			op === ":" &&
			!continued &&
			YAML_LINE_START.test(before) &&
			!(
				entry !== undefined &&
				(/^(?:[A-Za-z_$][\w$.]*|\d+|true|false|null)$/.test(entry) ||
					(/^[\w$.&*[\]<>]*[([{<]/.test(entry) && /[)\]}>]$/.test(entry) && isBalanced(entry)))
			);
		// An INI or TOML line under a `[section]` header: `password = c@I|wr=vsY6h[`, `admin_passwd = correct horse battery 42`.
		// (Not a call, `password = input("…")`; a number in parentheses is the value's own, `Planet(685)`.)
		const iniLine =
			op === "=" &&
			m[1] === "" &&
			!continued &&
			!sigil &&
			/^[ \t]*$/.test(before) &&
			unquoted &&
			!/^[A-Za-z_][\w.]*\((?![ \t]*-?\d+[ \t]*\))[^()\n]*\)[ \t]*\r?$/.test(text.slice(at, lineEndAt(text, at))) &&
			underSection(m.index);
		// `key: # a comment`: YAML has no value there.
		if (yamlLine && text[at] === "#") continue;
		const wholeLine = (envLine || yamlLine || iniLine) && unquoted;
		// Outside a call's parentheses (`env=dict(os.environ, PGPASSWORD=quote(pw))` passes an expression):
		const inLiteral = (before.replace(/\\./g, "").match(/"/g)?.length ?? 0) % 2 === 1;
		const openParens = inLiteral ? 0 : (before.match(/\(/g)?.length ?? 0) - (before.match(/\)/g)?.length ?? 0);
		// `SMTP_PASSWORD=x` anywhere (`heroku config:set …`, `API_KEY=x npm start`) is an env var, so a literal; and
		// `user=root password=x` in a log line, a query string or a CLI is data.
		const envName = op === "=" && /^[A-Z][A-Z0-9_]*$/.test(name) && !sigil && tight && openParens <= 0;
		const logPair = op === "=" && m[1] === "" && tight && /[ \t]$/.test(before) && openParens <= 0;
		const shellTest = /^===?$/.test(op) && /(?:^|\s)(?:\[\[?|test)\s/.test(before);
		const literal =
			!typed &&
			!continued &&
			(envLine ||
				yamlLine ||
				iniLine ||
				envName ||
				logPair ||
				shellTest ||
				pairQuote >= 0 ||
				(op === "=" && m[1] === "" && ENV_FLAG.test(before)));
		// (A logfmt line, `level=info … password=V host=db`: its pairs are separated by blanks, a value runs to one.)
		const logfmt =
			logPair && (text.slice(lineStart, lineEndAt(text, at)).match(/(?:^|[ \t])[\w.-]+=[^\s=]/g)?.length ?? 0) >= 3;
		let span = assignedValue(text, at, {
			wholeLine,
			envLine,
			shell: envLine || envName || pairQuote >= 0 || ENV_FLAG.test(before),
			pairQuote,
			logfmt,
		});
		if (!span) continue;
		// In a sed or perl substitution, `s/^DB_PASSWORD=.*/DB_PASSWORD=<value>/`, a value ends at the script's delimiter.
		const sed = /(?:^|[\s'"])s([/|#,:@])(?:[^\n]*)$/.exec(before);
		if (sed) {
			const stop = text.slice(span[0], span[1]).search(new RegExp(`(?<!\\\\)\\${sed[1]}`));
			if (stop >= 0) span = [span[0], span[0] + stop];
		}
		// `Authorization: Bearer x`: the value is the token, not the scheme (so it's learned and fingerprinted alone).
		if (/^(?:proxy-)?authorization$/i.test(name)) {
			const scheme =
				/^(?:Bearer|Basic|Token|Bot|Digest|ApiKey|Api-Key|SSWS|OAuth|JWT|DPoP|Splunk|GenieKey|Key)[ \t]+/i.exec(
					text.slice(span[0], span[1]),
				);
			if (scheme) span = [span[0] + scheme[0].length, span[1]];
		}
		// Inside a flow mapping an unquoted value runs to `,` or `}`, not to `&` (`{password: Tr0ub4dor&3x}`).
		if (
			span[0] === at &&
			text[span[1]] === "&" &&
			/[{,][ \t]*$/.test(before) &&
			(before.match(/\{/g)?.length ?? 0) > (before.match(/\}/g)?.length ?? 0)
		) {
			span = [span[0], span[1] + /^[^\s,}]*/.exec(text.slice(span[1], span[1] + 4096))![0].length];
		}
		const raw = text.slice(span[0], span[1]);
		// A quoted value was read without its quotes; let the value tests see them.
		const quoted = span[0] > at;
		// Inside a call's or a signature's parentheses, an unquoted name before `)`, `,`, `|` or `=` is a parameter's type
		// or a variable: `decode(secret: Base32SecretKey): …`, Swift's and Kotlin's `login(password: pw)`.
		if (
			!quoted &&
			op === ":" &&
			openParens > 0 &&
			/^[A-Za-z_$][\w$.]*$/.test(raw) &&
			/^[ \t]*[),|=]/.test(text.slice(span[1], span[1] + 3))
		)
			continue;
		// `readPassword("password: ")).thenReturn(…)`: the name was inside a string, and what follows its
		// closing quote is code.
		if (quoted && m[1] === "" && /["'`]/.test(text[m.index - 1] ?? "") && /^\)[).;]/.test(raw)) continue;
		// A parameter's description in a comment, a sentence to the line's end that names what the parameter holds:
		// `#   keystore_password: Keystore password.`, `// db_password: Primary password of the database.` (Not a password
		// that opens a sentence, `# password: Sunshine is the default.`: the sentence names no credential.)
		if (!quoted && op === ":" && /^[ \t]*(?:#+|\/\/+|\*|--|;+)[ \t]*$/.test(before) && /^\p{Lu}\p{Ll}+$/u.test(raw)) {
			const rest = /^(?:[ \t]+[\p{L}'’(),-]+)+\.[ \t]*\r?$/u.exec(text.slice(span[1], lineEndAt(text, span[1])))?.[0];
			const sentence = `${raw}${rest}`.trim();
			const credential = lastWord(name).toLowerCase();
			if (
				rest &&
				isLabel(sentence, name) &&
				sentence
					.toLowerCase()
					.split(/[^\p{L}]+/u)
					.includes(credential)
			)
				continue;
		}
		// Resume after this value: a value isn't also the start of the next pair (`a=b=c…` stays linear). An
		// object or a list is read inside instead: its pairs are values of their own (`auth: { user, pass: '…' }`).
		ASSIGN.lastIndex = Math.max(ASSIGN.lastIndex, /^[{[]/.test(raw) ? span[0] + 1 : span[1]);
		// (With its own quote: a shell's backticks run a command.)
		const q = quoted && text[span[0] - 1] === "`" ? "`" : '"';
		if (!isNamedSecret(name, quoted ? `${q}${raw}${q}` : raw, literal)) continue;
		// In an interpolated string (`f'user_id={cookie}'`, `$"Pwd={pw}"`) the holes are code: the literal part must hold the secret.
		if (
			/[fF$]/.test(prefix) &&
			/\{[^{}]*\}/.test(raw) &&
			!isNamedSecret(name, `"${raw.replace(/\{[^{}]*\}/g, "")}"`, literal)
		)
			continue;
		// (Basic auth's user info is a credential in both halves: Confluent's `basic.auth.user.info=<key>:<secret>`.)
		const colon = /user[._-]?info|basic/i.test(name) ? -1 : credentialPair(name, raw);
		namedFinding(out, colon > 0 ? span[0] + colon : span[0], span[1], name, "named:assign");
		if (literal) out[out.length - 1].literal = true;
	}
}

/**
 * Whether the line `at` is on is the last entry of a literal or a call written over several lines: the entry before it
 * ends with a comma, and the next line closes the bracket (`  email: user.email,` / `  password: hash` / `},`). There a
 * bare word is a variable, as before a comma. (A config file's braces, `authorization {` / `  password: hunter2` /
 * `}`, separate no entries with commas.)
 */
function isLastEntry(text: string, at: number): boolean {
	const start = lineStartAt(text, at);
	const end = lineEndAt(text, at);
	return (
		/,[ \t]*\r?\n$/.test(text.slice(Math.max(0, start - 400), start)) &&
		/^\r?\n[ \t]*[)\]}]/.test(text.slice(end, end + 202))
	);
}

/** JavaScript's `typeof` before a name and its object's path: `typeof this.`. */
const TYPEOF_BEFORE = /\btypeof[ \t]+[\w$.]*$/;

/** Whether ASSIGN's match names a credential's value, and not a namespace, a string compared, or a header read elsewhere. */
function isAssignedName(text: string, m: RegExpExecArray, name: string): boolean {
	const [, quote, , op] = m;
	// (A name a generator made is none: `sha1-IpnwLG3tMNSllhsLn3RSShj2NPw= sha512-…` is two hashes, its `=` base64's.)
	if ((!isCredentialName(name) && !(name === "PASS" && op === "=")) || isRandomToken(name)) return false;
	if (
		/^pass$/i.test(name) &&
		isPassInEnglish(
			/(\p{L}+)[ \t]*["']?$/u.exec(text.slice(Math.max(0, m.index - 30), m.index + m[1].length))?.[1] ?? "",
		)
	)
		return false;
	// A `section/name` key is judged whole: `keystore/release_password` is a password, `checksum/secrets` a digest.
	const section =
		text[m.index - 1] === "/"
			? /([\w.-]{1,60})\/$/.exec(text.slice(Math.max(0, m.index - 61), m.index))?.[1]
			: undefined;
	if (section && nameClass(`${section}/${name}`) !== "credential") return false;
	// `pw:api`, `key:value`, `redis:6379`: an unquoted name with a colon and no space is a namespace, not YAML.
	// (Except a password in a comma list of fields: `Logon ID: 0x1a2b, Password:Rmtq@1234!`.)
	const end = m.index + m[0].length;
	if (
		op === ":" &&
		quote === "" &&
		!/[ \t]/.test(text[end - 1]) &&
		!/["'`]/.test(text[end] ?? "") &&
		!(/,[ \t]+$/.test(text.slice(Math.max(0, m.index - 4), m.index)) && isPasswordName(name))
	)
		return false;
	// `prop="password" :class=…`: a quoted attribute value, not a key.
	if (quote && text[m.index - 1] === "=") return false;
	// `` `pwd`:/workspace ``: a command substitution, not a name.
	if (quote === "`") return false;
	// `typeof this.password === 'function'`: the value's type compared, not the value.
	if (/^===?$/.test(op) && TYPEOF_BEFORE.test(text.slice(Math.max(0, m.index - 60), m.index))) return false;
	// `"password" === e.type`: a string compared, not a variable (`$auth['password'] === 'x'` is one).
	if (quote && /^===?$/.test(op) && !m[0].includes("]")) return false;
	// `Cookie:` and `Set-Cookie:` headers are read pair by pair (structure.ts), with analytics cookies kept.
	if (/^(?:set-)?cookies?$/i.test(name) && op === ":") return false;
	// `$expected ? 'pass' : 'cancel'`, `type={shown ? 'text' : 'password'}`: a ternary's strings, not a key and its value.
	if (quote && op === ":" && /\?[ \t]*$/.test(text.slice(Math.max(0, m.index - 4), m.index))) return false;
	// A country's ISO code among others, `{"SK": "Slovakia", "PW": "Palau", …}`: a map of countries, not a secret key.
	if (
		/^[A-Z]{2}$/.test(name) &&
		(text.slice(Math.max(0, m.index - 300), m.index + 300).match(/["'][A-Z]{2}["'][ \t]*:/g)?.length ?? 0) >= 5
	)
		return false;
	// XAML's own attributes, `x:Key="Minus10Converter"`, `x:Name`: a resource's or an element's name.
	if (text[m.index - 1] === ":" && /(?:^|[\s<])x$/.test(text.slice(Math.max(0, m.index - 3), m.index - 1)))
		return false;
	// Windows `SET /P NAME=prompt`: what follows the `=` is the prompt the value is read with.
	if (op === "=" && /(?:^|[\s(&])set[ \t]+\/p[ \t]+$/i.test(text.slice(Math.max(0, m.index - 20), m.index)))
		return false;
	// `PublicKey(key_id=…, key="…")`: a public key's constructor takes its key.
	if (isGenericName(name) && /public[_-]?key|pub[_-]?key/i.test(enclosingCall(text, m.index) ?? "")) return false;
	// `cache key=…`, `next page token: …`, `public key: …`: the word before a bare generic name decides.
	// (Read as context.ts reads the same words: names.ts readPhrase. A declaration's keyword is no part of the phrase.)
	if (isGenericName(name)) {
		const before = phraseBefore(text.slice(Math.max(0, m.index - 64), m.index), 2).filter((w) => !DECLARATION.test(w));
		if (before.length && readPhrase(before, name).class !== "credential") return false;
	}
	return true;
}

/** The name of the call whose arguments `at` is among, on its line: `PublicKey` in `PublicKey(key_id=1, key="…")`. */
function enclosingCall(text: string, at: number): string | undefined {
	let depth = 0;
	for (let i = at - 1; i >= Math.max(0, at - 300); i--) {
		const c = text[i];
		if (c === "\n") return undefined;
		if (c === ")") depth++;
		else if (c === "(") {
			if (depth === 0) return /([A-Za-z_$][\w$.]*)$/.exec(text.slice(Math.max(0, i - 80), i))?.[1];
			depth--;
		}
	}
	return undefined;
}

/** Reads an assignment's value at `at` (after its operator, blanks and a literal's prefix). */
function assignedValue(
	text: string,
	at: number,
	{
		wholeLine,
		envLine,
		shell,
		pairQuote,
		logfmt = false,
	}: { wholeLine: boolean; envLine: boolean; shell: boolean; pairQuote: number; logfmt?: boolean },
): [number, number] | undefined {
	// `"NAME=value with spaces"`: to the pair's own closing quote, or a `\n` escape inside a JSON string. (Not a value
	// quoted itself, `\"…\"` in a JSON string included.)
	if (pairQuote >= 0 && !/["'`]/.test(text[at] ?? "") && !(text[at] === "\\" && /["']/.test(text[at + 1] ?? ""))) {
		// (Escaped itself inside a JSON string, `\"NAME=value\"`, the pair closes at the same escape.)
		const close =
			text[pairQuote - 1] === "\\"
				? escapedClose(text, at, `\\${text[pairQuote]}`)
				: stringEnd(text, pairQuote, { from: at });
		if (close > at) {
			const esc = text.slice(at, close).search(/\\[nrt]/);
			const end = esc >= 0 ? at + esc : close;
			// A query string in quotes (`'a=1&b=2'`): each value ends at the next `&name=`.
			const amp = text.slice(at, end).search(/&[\w.-]{1,60}=/);
			// (A shell command in quotes: `'PGPASSWORD=x psql -h db'`, the value is its first word.)
			return amp >= 0 ? [at, at + amp] : shellWordValue(text, [at, end]);
		}
	}
	// A string in parentheses, as Black wraps a long one: `DATABASES_PASSWORD = (\n    "…"\n)`.
	if (text[at] === "(") {
		const inner = callArguments(text, at + 1);
		if (inner?.length === 1 && inner[0].literal && !inner[0].keyword)
			return [inner[0].literal.start, inner[0].literal.end];
	}
	// `key = hexStringToUint8Array("…")`, `SecretStr("…")`, `bytes.fromhex("…")`: a literal in a converter.
	const converter =
		/^[\w.]{0,60}(?:hex|Hex|b64|base64|Base64|decode|Decode|fromhex|unhexlify|Buffer\.from|SecretStr|Secret|SecureString|getBytes|encode|bytes|String|str|Uint8Array|parse|Parse)[\w.]{0,40}\(/.exec(
			text.slice(at, at + 120),
		);
	// (Not a lookup, whose argument is a secret's name: Prefect's `Secret.load("db-password")`, `SecretStr.get(…)`.)
	const lookup = converter && /\.(?:load|get|fetch|read|lookup|retrieve|resolve|access)\w*\($/i.test(converter[0]);
	const converted = converter && !lookup ? callArguments(text, at + converter[0].length)?.[0]?.literal : undefined;
	if (converted && converted.value.length >= 4 && !ENCODING.test(converted.value))
		return [converted.start, converted.end];
	// Any other call that is the whole value is code, whose value isn't in the text: `getpass("Password: ")`, Ansible's
	// `password_expire_warn=dict(type='int', no_log=False)` (which, cut at its comma, would read as `dict(type='int'`).
	// (A function's name, and the call ending the value: a password with brackets in it, `Pa(ss)w0rd`, goes on.)
	const call = /^([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\(/.exec(text.slice(at, at + 64));
	if (call && (/[._]/.test(call[1]) || (call[1].length >= 4 && naturalness(call[1].toLowerCase()) > 0.3))) {
		const close = closingBracket(text, at + call[0].length);
		// (Code's arguments, not a number alone: `Tiger(6859)`, `Summer(2024)` are passwords.)
		const args = close > 0 ? text.slice(at + call[0].length, close).trim() : "";
		if (close > 0 && !/^[\d.]+$/.test(args) && /^[ \t]*(?:[,;)\]}\r\n#]|$)/.test(text.slice(close + 1, close + 3)))
			return undefined;
	}
	const span = readValue(text, at, { toEol: wholeLine, shell, toBlank: logfmt });
	// A pair in helm's list of them, `--set a.password=x,b.c=d`: the value ends at the list's next unescaped comma. (A
	// quoted one was written whole: `--set adminPassword='p-NK,fX…'`.)
	if (span && !/["']/.test(text[span[0] - 1] ?? "") && SET_LIST.test(text.slice(lineStartAt(text, at, 4000), at))) {
		const comma = /(?<!\\),/.exec(text.slice(span[0], span[1]));
		if (comma) return [span[0], span[0] + comma.index];
	}
	// An unquoted env value runs to the end of the line only as words (a dotenv passphrase); on a shell line it is one
	// shell word (`PGPASSWORD=… psql -h db`, `export MYSQL_PWD=… && mysql`). A query string's value ends at its next
	// pair, every `&` starting one (`oauth_consumer_key=…&oauth_nonce=…`, a percent-encoded one decoded; a password's
	// own `&` starts none, `Tr0ub4dor&3horse`).
	if (span && envLine && wholeLine) {
		const value = text.slice(span[0], span[1]);
		if (/^[^&\s]+(?:&[A-Za-z_][\w.-]{1,60}=[^&\s]*)+$/.test(value)) return [span[0], span[0] + value.indexOf("&")];
		return shellWordValue(text, span);
	}
	return span;
}

/** Inside a `--set` argument (helm, helmfile), after a key and its `=`: the pairs before it, then this one's key. */
const SET_LIST = /--set(?:-string|-file|-json|-literal)?[ \t=]+["']?(?:[^\s"',]*,)*[^\s"',=]+=$/;

/** Commands an environment variable is set for (`PGPASSWORD=x psql …`): what tells a command line from a passphrase. */
const COMMAND_WORDS =
	/^(?:sudo|env|exec|time|nohup|psql|pg_dump|pg_restore|mysql|mysqldump|mongo|mongosh|redis-cli|sqlcmd|sqlplus|python[\d.]*|pip\d?|node|npm|npx|yarn|pnpm|bun|deno|ruby|bundle|rails|rake|php|java|go|cargo|dotnet|make|bash|sh|zsh|curl|wget|docker|docker-compose|kubectl|helm|terraform|ansible-playbook|aws|gcloud|az|git|ssh|scp|rsync|uv|poetry|pytest|uvicorn|gunicorn|flask|celery|manage\.py)$/;

/**
 * The value of an unquoted `NAME=value` that starts an env line, when a command follows it on the line: its first word,
 * up to a blank (read as a line, a password may hold `&`, `;` and `<` themselves: `Tr0ub4dor&3horse`). A command follows when the next word is an operator
 * (`&&`, `;`, `|`) or the first ends with `;`, a command or a path comes next, or later words are flags, `NAME=`s or
 * tokens. Otherwise the line's words are the value (a dotenv passphrase, `correct horse battery staple`).
 */
function shellWordValue(text: string, span: [number, number]): [number, number] {
	const words = [...text.slice(span[0], span[1]).matchAll(/\S+/g)];
	if (words.length < 2) return span;
	const first = words[0][0];
	const [next, ...later] = words.slice(1).map((w) => w[0]);
	// (Or any program's name, `gh`, `vercel`, `mvn`, on a line of its own: not an env file's next line, nor a passphrase
	// of plain words, `correct horse battery staple`.)
	const lineAt = lineStartAt(text, span[0]);
	// (The next line from its `\n`: a CRLF line's value ends before its `\r`.)
	const nextAt = text.indexOf("\n", span[1]) + 1;
	const envFile = [
		text.slice(lineStartAt(text, Math.max(0, lineAt - 1)), Math.max(0, lineAt - 1)),
		nextAt > 0 ? text.slice(nextAt, lineEndAt(text, nextAt)) : "",
	].some((l) => /^[ \t]*(?:export[ \t]+)?[A-Z_][A-Z0-9_]*=/.test(l));
	const program =
		/^[a-z][a-z0-9.+_-]{0,30}$/.test(next) && !FUNCTION_WORDS.has(next) && !envFile && !/^[A-Za-z][a-z]*$/.test(first);
	const command =
		/;$/.test(first) ||
		/^(?:&&?|\|\|?|;)$/.test(next) ||
		COMMAND_WORDS.test(next) ||
		program ||
		/^(?:\.{0,2}\/|~\/)\S|\.(?:sh|py|js|ts|rb|pl)$/.test(next) ||
		[next, ...later].some(
			(w) => /^--?[A-Za-z]/.test(w) || /^[A-Za-z_]\w*=/.test(w) || /^(?=\S*\d)(?=\S*[A-Za-z])\S{12,}$/.test(w),
		);
	return command ? [span[0], span[0] + first.replace(/;$/, "").length] : span;
}

/** Where `\"` (or `\'`) closes a string that opened with it, inside a JSON string: on the same line, within 4,096 characters. */
function escapedClose(text: string, at: number, quote: string): number {
	const close = text.indexOf(quote, at);
	return close >= 0 && close - at < 4096 && !text.slice(at, close).includes("\n") ? close : -1;
}

/**
 * A value of several lines under `name`: one line is judged like any value; several (a key, a certificate bundle)
 * are hidden whole.
 */
function multiLineValue(out: Finding[], name: string, body: Span | undefined, rule: string) {
	// (Judged by its first 8 KB, a key's or a certificate chain's size: past that, a block holds more than a value.)
	const head = body?.value.slice(0, 8192) ?? "";
	if (!body || isInert(head) || isCode(head, true) || (!head.includes("\n") && !isNamedSecret(name, head, true)))
		return;
	namedFinding(out, body.start, body.end, name, rule);
}

/** The body of a heredoc whose `<<` is at `at` (`<<EOF`, `<<-EOT`, `<<~SQL`, `<<'EOF'`), up to its delimiter line, trimmed. */
function heredoc(text: string, at: number): Span | undefined {
	const open = HEREDOC.exec(text.slice(at, at + 100));
	if (!open) return undefined;
	const start = at + open[0].length;
	const close = new RegExp(String.raw`^[ \t]*${open[2]}[ \t]*\r?$`, "m").exec(text.slice(start, start + 100_000));
	if (!close) return undefined;
	const body = text.slice(start, start + close.index).replace(/\r?\n$/, "");
	return trimmed({ value: body, start, end: start + body.length });
}

/** A span without the blanks at either end. */
function trimmed(span: Span): Span | undefined {
	const value = span.value.trim();
	if (!value) return undefined;
	const start = span.start + span.value.indexOf(value);
	return { value, start, end: start + value.length };
}

/** `--password value`, `--api-key=value`, `-p value` style flags on a command line. */
function flags(text: string, out: Finding[]) {
	for (const m of text.matchAll(FLAG)) {
		const name = m[1].replace(/^-+/, "");
		if (name.length < 2 || !isCredentialName(name)) continue;
		const at = m.index + m[0].length;
		const span = readValue(text, at, { shell: true });
		if (!span) continue;
		let raw = text.slice(span[0], span[1]);
		const skip = (n: number) => {
			span[0] += n;
			raw = raw.slice(n);
		};
		// `--cookie "sessionid=…"`, `-b name=…`: the cookie's name stays, its value is the secret.
		if (/^(?:cookie|b)$/i.test(name) && /^[\w.-]{1,100}=/.test(raw)) skip(raw.indexOf("=") + 1);
		// `--auth user:password`, `--user name:pw`: the user stays, the part after the colon is the secret.
		if (/^(?:auth|user|u|basic|credentials?)$/i.test(name) && /^[\w.@+-]{1,100}:[^\s:]+$/.test(raw))
			skip(raw.indexOf(":") + 1);
		// OpenSSL's pass phrase arguments say where it comes from: `pass:<pw>` is the phrase; `env:`, `file:`, `fd:`
		// and `stdin` name a place, not a secret.
		if (/^pass(?:in|out|word)?$|^passphrase$/i.test(name)) {
			if (/^(?:env|file|fd):\S|^stdin$/.test(raw)) continue;
			if (/^pass:/.test(raw)) skip(5);
		}
		// (`use the -user and -passwd options`: the flag named in a sentence.)
		if (span[0] === at && /^(?:options?|flags?|arguments?|args|parameters?|params|switch(?:es)?)$/i.test(raw)) continue;
		// (An option its tool takes a value for only attached: the next word is the command's next argument, `mysql
		// --password mydb`, unless it looks like the password typed in the wrong place.)
		if (!m[0].endsWith("=") && promptsForValue(text, m.index + m[0].indexOf(m[1])) && !looksSecret(raw)) continue;
		if (!isNamedSecret(name, span[0] > at ? `"${raw}"` : raw, true)) continue;
		namedFinding(out, span[0], span[1], name, "named:flag");
		out[out.length - 1].literal = true;
	}
}

/** `<password>value</password>`, `<ns:apiKey>value</ns:apiKey>`. */
function xmlElements(text: string, out: Finding[]) {
	if (!text.includes("</")) return;
	for (const m of text.matchAll(XML_ELEMENT)) {
		const value = trimmed(elementText(m, 2));
		if (!value || !isCredentialName(m[1].replace(/^\w+:/, "")) || !isNamedSecret(m[1], `"${value.value}"`)) continue;
		namedFinding(out, value.start, value.end, m[1], "named:xml");
		out[out.length - 1].literal = true;
	}
}

/** Words that start a sentence about a credential after its name, not a value: `password reset link`, `Passwort wurde …`. */
const PROSE_START =
	/^(is|was|for|of|and|to|the|a|an|reset|change|changed|updated|rotated|set|required|must|should|will|can|field|policy|manager|hash|length|expired|expires|expiry|last|not|has|have|had|ist|est|es|é|è|är|jest|je|это|lautet|wurde|wird|muss|doit|debe|deve)$/i;

/** `NAME value` with blanks between: redis.conf's `requirepass`, Dockerfile `ENV`, `set`, tables with column bars. */
function spacedPairs(text: string, out: Finding[]) {
	for (const m of text.matchAll(SPACED)) {
		const name = m[2];
		if (!isCredentialName(name)) continue;
		if (isListingLine(text.slice(lineStartAt(text, m.index), lineEndAt(text, m.index)))) continue;
		const at = m.index + m[0].length;
		let span = readValue(text, at, { toEol: !/^["'`]/.test(text[at]) });
		if (!span) continue;
		// A table's cell (the name's own cell ended at a bar) ends at a bar; a column's at two blanks. Elsewhere a bar is the
		// value's (`requirepass a|b`).
		const barred = /[│|┃║]/.test(m[3]);
		const cell = text.slice(span[0], span[1]).search(barred ? /[ \t]*[│|┃║]|[ \t]{2,}/ : /[ \t]{2,}/);
		if (cell > 0) span = [span[0], span[0] + cell];
		// A line that is a JSON string of its own (a notebook's output, `"NAME value\n",`) ends at its escape or quote.
		const jsonLine = m[1].endsWith('"');
		if (jsonLine && !/^[ \t]+$/.test(m[3])) continue;
		if (jsonLine) {
			const stop = text.slice(span[0], span[1]).search(/\\[nrt]|"/);
			if (stop > 0) span = [span[0], span[0] + stop];
			if (!/^(?:\\[nrt])*"[ \t]*[,\]]?[ \t]*\r?$/.test(text.slice(span[1], lineEndAt(text, span[1])))) continue;
		}
		const raw = text.slice(span[0], span[1]);
		if (/^[\w-]+:\s/.test(raw)) continue; // `PSK identity: None`: a label, then its own value
		if (/^--?[A-Za-z]|^(?:&&|\|\||[|;>&])/.test(raw)) continue; // `htpasswd -nb admin pw`, `pwd && ls`: a command line
		if (/^(?:->|=>|::|\?\.|<-)/.test(raw)) continue; // `LoginField.PASSWORD -> input.text`: a `when` arm, an operator
		// A note or a type in brackets first (`password (optional)`, `token [required]`, a docstring's `password (str|None):`),
		// a member (`.field`), code in braces (`{ get; set; }`).
		const note = /^[([{]([^)\]}\n]{0,60})[)\]}]/.exec(raw);
		if ((note && readsAsWords(note[1] || "x")) || /^\.[A-Za-z_]|^\{[ \t]/.test(raw)) continue;
		// More words after the cell (and its closing quote) on a line that isn't a table: a directive (`password requisite
		// pam_pwquality.so`). (Not when the cell was read as far as a value is, UNQUOTED_READ: the rest is its own.)
		const after = span[0] > at ? span[1] + 1 : span[1];
		if (
			!jsonLine &&
			!barred &&
			span[1] - span[0] < UNQUOTED_READ &&
			/\S/.test(text.slice(after, lineEndAt(text, after)))
		)
			continue;
		// `requirepass value`, `ENV API_KEY value`, `│ password │ value │`: but not prose (`password reset link`).
		if (PROSE_START.test(raw) || (!barred && PROSE_START.test(raw.split(/[ \t]/)[0]) && /[ \t]/.test(raw))) continue;
		if (
			/^\S+(?: \S+){2,}$/.test(raw) &&
			!barred &&
			!/\d/.test(raw) &&
			!(/^[a-z]+(?: [a-z]+)+$/.test(raw) && isPassphrase(raw.split(" ")))
		)
			continue; // words: a sentence, not a value
		if (/^passwd$/i.test(name) && /^[a-z_][a-z0-9_-]{0,31}$/.test(raw)) continue; // `passwd ubuntu`: a user whose password changes
		// A title, `Password Store`, `Password Manager`; and `pass init`, `pass insert`: the password store's commands.
		if (
			((/^[A-Z][a-z]+$/.test(name) && /^[A-Z][a-z]{2,}$/.test(raw)) || (name === "pass" && /^[a-z]{2,}$/.test(raw))) &&
			naturalness(raw.toLowerCase()) > 1
		)
			continue;
		if (isSentenceWord(raw)) continue; // `can't fake a pass either.`: the sentence goes on
		// A call, its result read: Gradle's `storePassword file('keystore.pass').text.trim()`, `password System.getenv("PW")`.
		if (/^[A-Za-z_$][\w$.]*\([^()]*\)(?:\.[A-Za-z_$][\w$]*(?:\([^()]*\))?)*$/.test(raw)) continue;
		if (!isNamedSecret(name, span[0] > at ? `"${raw}"` : raw, true)) continue;
		namedFinding(out, span[0], span[1], name, "named:spaced", 0.85);
		out[out.length - 1].literal = true;
	}
}

/** Meltano's `config list`: `password [env: TARGET_SNOWFLAKE_PASSWORD] current value: 'pw' (from \`.env\`)`. */
function configList(text: string, out: Finding[]) {
	if (!text.includes("current value:")) return;
	for (const m of text.matchAll(
		new RegExp(
			String.raw`^[ \t]*([\w.-]{1,80})[ \t]+\[env: [A-Z0-9_]{1,120}\][ \t]+current value:[ \t]+${quoted(2)}`,
			"dgm",
		),
	))
		namedValue(out, m[1], group(m, 3), "named:config-list");
}

/** C and Arduino: `#define SECRET_PASS "…"`. */
function cDefines(text: string, out: Finding[]) {
	if (!text.includes("#define")) return;
	for (const m of text.matchAll(
		new RegExp(String.raw`^[ \t]*#define[ \t]+([A-Za-z_]\w{1,80})[ \t]+${quoted(2, 1, '"')}`, "dgm"),
	))
		namedValue(out, m[1], group(m, 3), "named:define");
}

/**
 * A default inside a reference: Spring `${DB_PASSWORD:claims_dev_2024}`, shell `${DB_PASSWORD:-hunter2}` and
 * `${DB_PASSWORD:=hunter2}` (assigned when unset), and the same without the colon. (`:?message` is the error when
 * unset, `:+word` the value when set: neither is a default.)
 */
function referenceDefaults(text: string, out: Finding[]) {
	if (!text.includes("${")) return;
	for (const m of text.matchAll(/\$\{([A-Za-z_][\w.-]{0,80})(?::[-=]|:(?![-=?+])|[-=])([^}\s$]{4,4096})\}/dg)) {
		// (A generic name needs a value with letters and digits: `${TOKEN_TTL:3600}` is a number.)
		if (
			!takesAnyWord(m[1]) &&
			readName(m[1]).last !== "SECRET" &&
			(m[2].length < 8 || !/\d/.test(m[2]) || !/[A-Za-z]/.test(m[2]))
		)
			continue;
		namedValue(out, m[1], group(m, 2), "named:env-default");
	}
}

/** JavaScript and Ruby fallbacks: `process.env.JWT_SECRET ?? "…"`, `ENV["X"] || "…"`, `ENV.fetch("X") { "…" }`. */
function envFallbacks(text: string, out: Finding[]) {
	if (!/process\.env|ENV[[.]/.test(text)) return;
	const lookup = String.raw`process\.env\.([A-Za-z_]\w{0,80})|process\.env\[["']([\w.-]{1,80})["']\]|ENV\[["']([\w.-]{1,80})["']\]`;
	for (const m of text.matchAll(
		new RegExp(
			String.raw`(?:(?:${lookup})[ \t]*(?:\?\?|\|\||\bor\b)|ENV\.fetch\(["']([\w.-]{1,80})["']\)[ \t]*\{)[ \t]*${quoted(5, 4, "\"'`")}`,
			"dg",
		),
	)) {
		namedValue(out, m[1] ?? m[2] ?? m[3] ?? m[4], group(m, 6), "named:env-default");
	}
}

/** A ternary's `?`: not a query string's (`?schema=public`), optional chaining's `?.` nor a fallback's `??`. */
const TERNARY = String.raw`(?<!\?)\?(?![?.=]|[\w-]+=)`;
/** A ternary, a Python conditional, or a fallback. */
const CONDITIONAL = new RegExp(String.raw`${TERNARY}[^\n]*:|[ \t]if[ \t][^\n]*[ \t]else[ \t]|\|\||\?\?|[ \t]or[ \t]`);
/** A credential's name and what gives it a value: `pw =`, `password:`, `setPassword(`. */
const CONDITIONAL_HEAD = /(?<![\w$])([A-Za-z_$][\w$.]{0,80}?)(?:["']?[ \t]*(?:=|:)(?![=:])|[ \t]*\()[ \t]*/dg;
/** What may follow a branch that ends the expression: its statement's or bracket's end, or a comment. */
const BRANCH_END = String.raw`(?:[;,)\]}]|#|//|$)`;
/** Where a literal branch stands in the expression after it. */
const BRANCHES = [
	// A ternary's: `? "…" :` and, after its `?`, `: "…"` closing the expression.
	new RegExp(String.raw`${TERNARY}[ \t]*${quoted(1, 1, "\"'`")}[ \t]*:`, "dg"),
	new RegExp(String.raw`${TERNARY}[^\n]*?:[ \t]*${quoted(1, 1, "\"'`")}[ \t]*${BRANCH_END}`, "dg"),
	// A fallback's, after `or`, `||` or `??`: `os.getenv("PW") or "…"`.
	new RegExp(String.raw`(?:\|\||\?\?|[ \t]or)[ \t]+${quoted(1, 1, "\"'`")}[ \t]*${BRANCH_END}`, "dg"),
	// Python's: `"…" if … else …` and `… if … else "…"`.
	new RegExp(String.raw`^${quoted(1, 1, "\"'")}[ \t]+if[ \t]`, "dg"),
	new RegExp(String.raw`[ \t]if[ \t][^\n]*?[ \t]else[ \t]+${quoted(1, 1, "\"'")}[ \t]*${BRANCH_END}`, "dg"),
];
/**
 * A conditional's string branches under a credential's name, assigned or passed: `pw = cfg == null ? "…" : cfg.pw;`,
 * `setPassword(p == null ? "…" : p)`, Python's `password = os.environ.get("PW") if env else "…"`, a fallback's
 * `token = os.getenv("T") or "…"`. (The expression is code, which the readers of a value leave whole; a literal branch
 * is a value all the same.)
 */
function conditionalBranches(text: string, out: Finding[]) {
	// (A cheap gate on the whole text; CONDITIONAL itself only on an expression, at most 300 characters.)
	if (!/[?|]|[ \t](?:or|if)[ \t]/.test(text)) return;
	CONDITIONAL_HEAD.lastIndex = 0;
	for (const m of text.matchAll(CONDITIONAL_HEAD)) {
		const name = m[1].split(".").at(-1)!;
		if (!isCredentialName(name)) continue;
		// The expression: the rest of its line, up to a statement's `;`.
		const from = m.index + m[0].length;
		const line = text.slice(from, lineEndAt(text, from));
		const expr = line.slice(0, Math.min(300, /;/.exec(line)?.index ?? line.length));
		// (Quotes escaped are a string's inside a string, a level the JSON pass decodes and reads again.)
		if (!CONDITIONAL.test(expr) || /\\["']/.test(expr)) continue;
		for (const branch of BRANCHES) {
			branch.lastIndex = 0;
			for (const b of expr.matchAll(branch)) {
				const [start, end] = b.indices![2]!;
				namedValue(out, name, { value: b[2], start: from + start, end: from + end }, "named:conditional");
			}
		}
	}
}

/** Android resources and similar: `<string name="api_secret">…</string>`, `<setting name="X"><value>…</value>`. */
function xmlNamedValues(text: string, out: Finding[]) {
	if (!text.includes('name="')) return;
	for (const m of text.matchAll(
		new RegExp(
			String.raw`<(string|item|setting|entry|add)\b[^>\n]{0,100}?\bname="([\w.-]{1,80})"[^>\n]{0,200}>[ \t\r\n]{0,40}(?:<value>)?${XML_TEXT(4)}(?:<\/value>)?[ \t\r\n]{0,40}<\/\1>`,
			"dg",
		),
	)) {
		const value = trimmed(elementText(m, 3));
		if (value) namedValue(out, m[2], value, "named:xml-name");
	}
}

/** A dot-leader row: the label (group 1), then the rest of the line (group 2). */
const DOT_LEADER = new RegExp(
	String.raw`^(?![ \t]*test[ \t]).{0,300}?(?<![\w:./-])([A-Za-z_][\w-]{0,80})[ \t]\.{3,300}[ \t]{1,5}(?=\S)${unquotedValue("[^\\n]", 1, String.raw`[ \t]*\r?$`)}`,
	"dgm",
);

/** Dot-leader rows (`artisan config:show`, `wp config list`): `password ........ value`. */
function dotLeaders(text: string, out: Finding[]) {
	if (!text.includes("...")) return;
	// (The label is words of its own, not a path's last segment or a test runner's `test <path> ... ok`.)
	for (const m of text.matchAll(DOT_LEADER)) {
		if (isCredentialName(m[1]) && isNamedSecret(m[1], m[2], true))
			namedFinding(out, m.indices![2]![0], m.indices![2]![1], m[1], "named:dot-leader");
	}
}

const USER_INFO = new RegExp(
	String.raw`(?:^|[\s"'])((?:[\w.-]*[._-])?user[._-]?info|[\w.-]*basic[\w.-]*credentials?)[ \t]*[=:][ \t]*["']?[\w.@+-]{1,100}:${unquotedValue(String.raw`[^\s"']`, 6, String.raw`["']|\s|$`)}`,
	"dgim",
);

/** `user:secret` under a name that says it's a user's credentials (`basic.auth.user.info`, `userinfo`): the part after the colon. */
function userInfo(text: string, out: Finding[]) {
	if (!/user[._-]?info|basic/i.test(text)) return;
	for (const m of text.matchAll(USER_INFO)) {
		if (looksSecret(`"${m[2]}"`, true) && !isInert(m[2]))
			namedFinding(out, m.indices![2]![0], m.indices![2]![1], m[1], "named:userinfo");
	}
}

/**
 * Terraform variables and outputs: `variable "db_password" {` … `default = "…"` (or a heredoc) among the block's own
 * attributes, not a nested block's (`validation { … }`). `sensitive = true` says the value is secret whatever it's named;
 * an `output` block's value is judged only then.
 */
function terraformVariables(text: string, out: Finding[]) {
	if (!/\b(?:variable|output)\b/.test(text)) return;
	// (Where the block last read ends: a block holds no other, so a run of unclosed `variable "a" {` costs each character once.)
	let readTo = 0;
	for (const m of text.matchAll(/\b(variable|output)[ \t]+"([\w-]{1,80})"[ \t]*\{/g)) {
		if (m.index < readTo) continue;
		const open = m.index + m[0].length;
		// (A heredoc can hold what the bracket matcher reads as an unclosed string: then the block ends at a `}` line.)
		const bracket = closingBracket(text, open);
		const line = text.indexOf("\n}", open);
		const block = topLevel(text, open, Math.min(bracket >= 0 ? bracket : line >= 0 ? line : text.length, open + 8000));
		readTo = open + block.length;
		const sensitive = /(?<![\w.-])sensitive[ \t]*=[ \t]*true\b/.test(block);
		const name = m[2];
		if (m[1] === "output" && !sensitive) continue;
		// (An attribute starts its line, or the block: not one in a comment, `# default = "changeme"`, `description = "…" # value = …`.)
		const attribute = /(?:^|\n)[ \t]*(default|value)[ \t]*=(?!=)[ \t]*/.exec(block);
		if (!attribute) continue;
		const at = open + attribute.index + attribute[0].length;
		if (HEREDOC.test(text.slice(at, at + 100))) {
			if (sensitive || isCredentialName(name))
				multiLineValue(out, sensitive ? "password" : name, heredoc(text, at), "named:tf-variable");
			continue;
		}
		const value = text[at] === '"' ? literalAt(text, at) : undefined;
		if (value) namedValue(out, name, value, "named:tf-variable", { judgedAs: sensitive ? "password" : name });
	}
}

/**
 * The text of a block, `text[start, end)`, with its nested blocks and its strings' contents blanked out (the same
 * length, so positions hold): its own attributes only, never words inside a `description`.
 */
function topLevel(text: string, start: number, end: number): string {
	const out: string[] = [];
	for (let i = start; i < end; i++) {
		const close = text[i] === '"' ? stringEnd(text, i) : text[i] === "{" ? closingBracket(text, i + 1) : -1;
		if (close < 0 || close >= end) {
			out.push(text[i]);
			continue;
		}
		out.push(text[i], " ".repeat(close - i - 1), text[close]);
		i = close;
	}
	return out.join("");
}

/** Plan diffs: `"CLIENT_SECRET" = "old" -> "new"`, `password: "old" => "new"`. */
function diffArrows(text: string, out: Finding[]) {
	if (!/->|=>/.test(text)) return;
	for (const m of text.matchAll(
		new RegExp(
			String.raw`["']?([A-Za-z_][\w.-]{0,80})["']?[ \t]*[=:][ \t]*(["'])[^"'\n]{0,${MAX_VALUE}}\2[ \t]*(?:->|=>)[ \t]*${quoted(3)}`,
			"dg",
		),
	))
		namedValue(out, m[1], group(m, 4), "named:diff-arrow");
}

/** A value key in JSON, quoted: what jsonValues needs in a text to have anything to read. */
const PAIR_VALUE_KEY = new RegExp(`"${PAIR_VALUE.source.slice(1, -1)}"`, "i");

/**
 * JSON documents in the text (API responses, `terraform output -json`, `aws … --output json`), walked
 * for values whose name is a sibling field (`{"name": "DB_PASSWORD", "value": …}`, `{"keyName": "key1",
 * "value": …}`) or which are marked sensitive (`{"sensitive": true, "value": …}`). Values directly under
 * a credential name are left to the assignment rule. Each value is where the parser read it, however the
 * source escaped it (`\/`, `é`).
 */
function jsonValues(text: string, out: Finding[]) {
	if (!PAIR_VALUE_KEY.test(text)) return;
	for (const doc of jsonDocuments(text)) {
		const walk = (v: JsonNode, sensitive: boolean) => {
			if (v.kind === "array") for (const x of v.items) walk(x, sensitive);
			if (v.kind !== "object") return;
			const field = (k: string) => v.entries.find(([key]) => key === k)?.[1];
			const type = field("type");
			const sens = field("sensitive");
			const marked =
				sensitive ||
				(sens?.kind === "literal" && sens.value === true) ||
				(type?.kind === "string" &&
					/^(random_password|tls_private_key|random_string|aws_iam_access_key)$/.test(type.value));
			const sibling = v.entries.find(([key, x]) => PAIR_NAME.test(key) && x.kind === "string")?.[1] as
				{ value: string } | undefined;
			for (const [k, x] of v.entries) {
				if (x.kind === "string" && PAIR_VALUE.test(k) && !/^\s*\{/.test(x.value)) {
					const quoted = JSON.stringify(x.value);
					if (
						(sibling && isCredentialName(sibling.value) && isNamedSecret(sibling.value, quoted, true)) ||
						(marked && looksSecret(quoted, true))
					)
						namedFinding(out, x.start, x.end, sibling?.value ?? "secret", "named:json-sibling", 0.95);
				} else walk(x, marked && /^(value|outputs|resources|instances|attributes|values)$/.test(k));
			}
		};
		walk(doc, false);
	}
}

/** Callees that look a key up, so their literal argument is the key, not a secret: `getToken("github")`. */
const LOOKUP =
	/^(?:find|get|delete|remove|has|fetch|load|read|lookup|clear|forgot|show|list|describe|generate|create|new|is)(?:_|[A-Z])/;

/**
 * A call named for a credential that is given one: `cfg.setPassword("…")`, `builder.apiKey("…")`,
 * `withToken("…")`, `u.check_password("…")`, `keyring.set_password(service, user, "…")`. The secret is the
 * last string literal among the arguments, or with keyword arguments the one named for a credential. A lookup
 * takes the key it looks up instead (`findPassword(service)`, `getToken("github")`); its literal fallback is the
 * secret itself (`get_secret("prod/db", default="…")`).
 */
const SETTER_CALL = new RegExp(
	String.raw`(?<![\w$])((?:[A-Za-z_$][\w$]{0,60}?)?(?:${CREDENTIAL_WORD})[\w$]{0,60})[ \t]{0,2}\(`,
	"gi",
);
function setterCalls(text: string, out: Finding[]) {
	// (Any callee that holds a credential word, `set_db_password`, `withApiKey`; isCredentialName decides.)
	for (const { match, args } of calls(text, SETTER_CALL)) {
		const callee = match[1];
		const hasher = HASHER.exec(callee.split(".").at(-1)!);
		if (!hasher && LOOKUP.test(callee)) {
			for (const a of args)
				if (a.literal && a.keyword && /^(?:default|fallback|default_value|defaultValue)$/.test(a.keyword))
					namedValue(out, callee, a.literal, "named:fallback", { judgedAs: "password" });
			continue;
		}
		// (`pass` alone is the verb: picobox's `@box.pass_("database_session")`. A hasher's name says what it's given, though
		// it reads as a hash's: `password_hash`.)
		if (!hasher && (!isCredentialName(callee) || /^pass_*$/i.test(callee))) continue;
		// (With keyword arguments the call names its slots: only one named for a credential, `password="…"`, is read; and a
		// hasher's first argument, whatever follows it, `generate_password_hash("…", method="scrypt")`.)
		if (args.some((a) => a.keyword)) {
			for (const a of args)
				if (a.keyword && a.literal && isCredentialName(a.keyword))
					namedValue(out, hasher ? "password" : callee, a.literal, "named:setter");
			if (!hasher?.[1]) continue;
		}
		// The secret is the last argument, after a service and a user (`keyring.set_password("pgcli", key, passwd)` passes
		// a variable); flags after it don't count (`setPassword("…", true)`). A credentials call takes a user, then the
		// secret: `setCredentials("admin", "…", "realm")`.
		const positional = args.filter(
			(a) => !a.keyword && !/^(?:true|false|True|False|None|null|nil|undefined|-?\d+(?:\.\d+)?)$/.test(a.text),
		);
		// A hasher or a checker takes the password first, its salt or its hash after; werkzeug's checker, last (HASHER).
		let secret = positional.at(-1);
		if (hasher?.[1]) secret = positional[0];
		else if (!hasher && /credentials?$/i.test(callee) && positional.length >= 2) secret = positional[1];
		// (Judged as the password a hasher is given, whatever its name reads as.)
		if (secret?.literal) namedValue(out, hasher ? "password" : callee, secret.literal, "named:setter");
	}
}

/**
 * Calls that hash or check a password. Given first (the group): Django's `make_password("…", salt, hasher)` and
 * `check_password("…", encoded)`, bcrypt's `hashpw(b"…", salt)` and `checkpw`, PHP's `password_hash("…",
 * PASSWORD_DEFAULT)` and `password_verify`, werkzeug's `generate_password_hash`; given last, werkzeug's
 * `check_password_hash(hash, "…")`.
 */
const HASHER =
	/^((?:make|hash|check|verify)_?password|generate_password_hash|(?:hash|check)pw|password_(?:hash|verify))$|^check_password_hash$/i;

/**
 * Positional credentials of connect and credential calls: `mysqli_connect(host, user, pw, db)`,
 * `DBI->connect(dsn, user, pw)`, `new NetworkCredential(user, pw)`, `DirectoryEntry(path, user, pw)`,
 * `smtp.login(user, pw)`, `pymysql.connect(host, user, pw, db)`, `ldap.simple_bind_s(dn, pw)`, `auth=(user, pw)`.
 */
function positionalCalls(text: string, out: Finding[]) {
	for (const { match, args } of calls(
		text,
		/\b(mysqli?_connect|mysqli|DBI->connect|NetworkCredential(?:\]::new)?|DirectoryEntry|(?:pymysql|MySQLdb)\.connect|(?:\.|->)login|simple_bind(?:_s)?|bind_s|new PDO|PDO|getConnection|FTP(?:_TLS)?|WiFi\.begin|HTTPBasicAuth|HTTPDigestAuth|BasicAuth|PasswordAuthentication|UsernamePasswordCredentials)[ \t]*\(|\bauth[ \t]*=[ \t]*\(/g,
	)) {
		const callee = match[1] ?? "auth";
		// (The password is the third argument after a host or a DSN, the second after a user.)
		const at =
			/^(?:mysqli?_connect|mysqli|DBI->connect|DirectoryEntry|(?:pymysql|MySQLdb)\.connect|new PDO|PDO|getConnection|FTP(?:_TLS)?)$/.test(
				callee,
			)
				? 2
				: 1;
		if (args.length <= at || ((/login$/.test(callee) || callee === "auth") && args.length !== 2)) continue;
		// (`login(provider, mode)` signs in with an identity provider: `auth.login("github", "popup")`.)
		if (
			/login$/.test(callee) &&
			/^(?:github|google|facebook|twitter|apple|microsoft|azure|gitlab|bitbucket|discord|slack|okta|auth0|linkedin|oidc|saml|oauth2?|email|anonymous|guest)$/i.test(
				args[0].literal?.value ?? "",
			)
		)
			continue;
		const lit = args[at].literal;
		if (lit && !args[at].keyword) namedValue(out, "password", lit, "named:positional");
	}
}

/** The verbs of calls whose first argument names their second (case-insensitive in the first letter). */
const PAIR_VERBS = [
	"set",
	"put",
	"add",
	"append",
	"insert",
	"store",
	"define",
	"with",
	"header",
	"option",
	"config",
	"cookie",
	"get",
	"fetch",
];
/**
 * A call whose first argument names its second: a setter (`os.Setenv("API_KEY", "…")`, `localStorage.setItem("token",
 * "…")`, `req.Header.Set("Authorization", "…")`, PHP's `define('DB_PASSWORD', '…')`, a session builder's
 * `.config("spark.…key", "…")`) or a lookup whose second is the default (`os.getenv("X", "…")`, `ENV.fetch("X", "…")`,
 * Laravel's `env('X', '…')`). Not any call: `__('Password', 'my-theme')` translates a label.
 */
const PAIR_CALL = new RegExp(
	String.raw`(?<![\w$])(?:(?:${PAIR_VERBS.map((v) => `[${v[0]}${v[0].toUpperCase()}]${v.slice(1)}`).join("|")})(?:[A-Z_][\w$]*)?|[sS]etenv|getenv|setdefault|env)[ \t]*\((?=\s*[fFbBrRuU@$]?["'\x60])`,
	"g",
);

/** A Spark or Hadoop setting that holds a key: `fs.azure.account.key.<account>.dfs.core.windows.net`, `fs.s3a.secret.key`. */
const KEY_SETTING =
	/^[\w.{}$-]{0,200}(?:account\.key|secret\.key|access\.key|sas\.token|sas|password|secret|token|credential)(?:\.[\w.{}$-]{0,200})?$/;

function pairCalls(text: string, out: Finding[]) {
	for (const { match, args } of calls(text, PAIR_CALL)) {
		const name = args[0]?.literal?.value ?? "";
		const value = args[1]?.literal;
		if (!value || !/^[A-Za-z_][\w.{}$-]{1,200}$/.test(name)) continue;
		// A cookie set by name, `res.append('Set-Cookie', 'theme=dark')`, holds a secret only as a session's cookie,
		// which the structure layer reads as cookies are read.
		if (/^(?:set-)?cookie$/i.test(name)) continue;
		// WordPress's keys and salts: 64 generated characters, spaces among them (`define('AUTH_SALT', 'k%Y …')`).
		if (/^define/.test(match[0]) && (isCredentialName(name) || /_SALT$/.test(name)) && isWordpressKey(value.value)) {
			namedFinding(out, value.start, value.end, name, "named:define");
			continue;
		}
		if (!isCredentialName(name) && KEY_SETTING.test(name) && !/\.id$|access\.key\.id/i.test(name))
			namedValue(out, name, value, "named:call-pair", { judgedAs: "key" });
		else namedValue(out, name, value, /^define/.test(match[0]) ? "named:define" : "named:call-pair");
	}
}

/** A WordPress key or salt as its generator makes them: 32+ characters of three or more classes, not the sample text. */
function isWordpressKey(value: string): boolean {
	return (
		value.length >= 32 &&
		[/[a-z]/, /[A-Z]/, /\d/, /[^\w\s]/].filter((r) => r.test(value)).length >= 3 &&
		!/put your unique phrase here/i.test(value)
	);
}

/**
 * A credential compared with a literal: `secure_compare(password, "…")`, `hmac.compare_digest(token, "…")`,
 * `password.equals("…")`, `"…".equals(password)`, `if password == "…"`, a shell's `[ "$DB_PASSWORD" = "…" ]`.
 */
function comparisons(text: string, out: Finding[]) {
	if (!/[cC]ompare|[!=]=|equals|cmp|Equal|\[\[?[ \t]+"?\$/.test(text)) return;
	const variable = (a?: Argument) =>
		a && !a.literal ? /^(?:[\w.]*\.)?([A-Za-z_]\w{1,60})$/.exec(a.text)?.[1] : undefined;
	for (const { match, args } of calls(
		text,
		/(?<![\w$])(?:([A-Za-z_][\w$]{0,60})\.)?(secure_compare|compare_digest|timingSafeEqual|constant_time_compare|ConstantTimeCompare|safe_str_cmp|equals(?:IgnoreCase)?)[ \t]*\(/g,
	)) {
		// (Two arguments compare each other, a variable and a literal in either order; one argument, with the receiver:
		// `password.equals("…")`.)
		let name: string | undefined;
		let lit: Literal | undefined;
		if (args.length === 2) {
			const first = variable(args[0]) !== undefined;
			name = variable(args[first ? 0 : 1]);
			lit = args[first ? 1 : 0].literal;
		} else if (args.length === 1 && match[1]) [name, lit] = [match[1], args[0].literal];
		if (name && lit) namedValue(out, name, lit, "named:compare");
	}
	// `name == "…"`, `"…" === name`, `"…".equals(name)`, `assertEquals("…", cfg.getPassword())`, and `[ "$NAME" = "…" ]` in a shell test.
	for (const m of text.matchAll(
		new RegExp(
			String.raw`(?<![\w.'"])\$?([A-Za-z_]\w{1,60})[ \t]*(?:===?|!==?)[ \t]*${quoted(2, 4, "\"'`")}|${quoted(4, 4, "\"'`")}(?:[ \t]*(?:===?|!==?)[ \t]*|\.equals(?:IgnoreCase)?\([ \t]*|[ \t]*,[ \t]*(?=[\w.]*get))(?:[\w.]*\.)?(?:get)?([A-Za-z_]\w{1,60})\b(?![.[])|\[\[?[ \t]+"?\$\{?([A-Za-z_]\w{1,60})\}?"?[ \t]+!?==?[ \t]+${quoted(8, 4)}`,
			"dg",
		),
	)) {
		const name = m[1] ?? m[6] ?? m[7];
		// (`typeof password === 'function'` compares the value's type.)
		if (m[1] !== undefined && TYPEOF_BEFORE.test(text.slice(Math.max(0, m.index - 60), m.index))) continue;
		const k = m[3] !== undefined ? 3 : m[5] !== undefined ? 5 : 9;
		namedValue(out, name, group(m, k), "named:compare");
	}
}

/**
 * Browser automation filling a password field: `page.fill('#password', '…')`, `getByLabel('Password').fill('…')`,
 * `cy.get('input[name=password]').type('…')`, `find_element(By.ID, "password").send_keys("…")`.
 */
function formFills(text: string, out: Finding[]) {
	if (!/\.(?:fill|type|send_keys|sendKeys|setValue|pressSequentially)\(/.test(text)) return;
	const fill = (selector: string | undefined, value: Literal | undefined) => {
		const name = selector === undefined ? undefined : fieldName(selector);
		// (Cypress's key sequences, `{selectall}{backspace}`, are keystrokes, not text.)
		const typed = value?.value.replace(/\{[a-z]+\}/gi, "");
		if (!name || !value || !typed || !isCredentialName(name) || !isNamedSecret(name, `"${typed}"`, true)) return;
		namedFinding(out, value.start, value.end, name, "named:form-fill");
	};
	for (const { args } of calls(text, /\.(?:fill|type)\(/g))
		if (args.length === 2) fill(args[0].literal?.value, args[1].literal);
	// The selector of the call the value is chained to: its last argument, `getByLabel('Password')`, `find_element(By.ID, "password")`.
	for (const { match, args } of calls(
		text,
		new RegExp(
			String.raw`${quoted(1, 0)}[ \t]*\)[ \t]*\.(?:fill|type|send_keys|sendKeys|setValue|pressSequentially)\(`,
			"g",
		),
	)) {
		if (args.length === 1) fill(match[2], args[0].literal);
	}
}

/**
 * The name of the field a selector or label points at: `#password`, `[name=api_key]` and `[type=password]` name it; a
 * label's words do (`Password`, `API token`); `#token-name` and `#password-hint` name a token's name and a password's hint.
 */
function fieldName(selector: string): string | undefined {
	const attribute =
		/\[(?:name|id|data-testid|data-test|data-cy|placeholder|aria-label)[*^$]?=["']?([^"'\]]{1,80})["']?\]/i.exec(
			selector,
		)?.[1];
	const id = /#([\w-]{1,80})(?![\w-])/.exec(selector)?.[1];
	// (A password input names its field whatever else the selector says: `input[type=password]`, `[name=pw][type="password"]`.)
	if (/\[type=\\?["']?password\\?["']?\]/i.test(selector)) return "password";
	const name =
		attribute ??
		id ??
		(/^[\p{L} _-]{1,60}$/u.test(selector.trim())
			? selector.trim()
			: /^[\w-]{1,80}$/.test(selector)
				? selector
				: undefined);
	return name?.replace(/[\s-]+/g, "_");
}

/**
 * Tables with `|` bars: Markdown, psql, `aws … --output table`. Rows are split at the bars, so cells match their
 * header by index whatever the alignment. A cell is a secret under a credential column's header
 * (`| User | Password |`), or after a cell that is a credential's name (`| api_key | abc… |`,
 * `| Postgres | DB_PASSWORD | Harbor#2291x |`), unless the next column describes rather than holds values
 * (`| auth.password | Redis password | "" |`: name, description, value).
 */
function pipeTables(text: string, out: Finding[]) {
	if (!text.includes("|")) return;
	const { lines, starts } = splitLines(text);
	let header: string[] | undefined;
	// Where the rule under the header puts the bars, when the header's own bars stand there: psql's and mysql's
	// aligned columns, which a `|` inside a value can't move.
	let bars: number[] | undefined;
	for (let i = 0; i < lines.length; i++) {
		const line = lines[i];
		// (A row starts with a bar, or sits under a header ruled off below it: psql's ` name | value`. A sentence
		// with a `|` in it, `grep -Ev 'token|password'`, is neither.)
		if (PIPE_RULE.test(line)) continue; // a rule under the header, or a MySQL table's `+----+` rules
		if (
			!line.includes("|") ||
			line.length > MAX_VALUE ||
			!(/^[ \t]*\|/.test(line) || header || PIPE_RULE_START.test(lines[i + 1] ?? ""))
		) {
			header = bars = undefined;
			continue;
		}
		let cells = pipeCells(line, starts[i]);
		if (cells.length < 2) continue;
		// A table starts at a row a rule follows: its header. Its rows run to a line without a bar, whatever their
		// cell count (a value may hold a `|`). (In a table with a header, a rule with no row after it closes the table:
		// mysql's last `+----+`.)
		const rule = lines[i + 1] ?? "";
		if (PIPE_RULE_START.test(rule) && (!header || (lines[i + 2] ?? "").includes("|"))) {
			header = cells.map((c) => c.text);
			const at = [...rule.matchAll(/[|+]/g)].map((m) => m.index);
			bars = at.length && at.every((p) => line[p] === "|" || p === 0 || p >= line.length) ? at : undefined;
			continue;
		}
		if (header && cells.length > header.length)
			cells = bars ? alignedCells(line, starts[i], bars) : joinedCells(text, cells, header);
		for (let k = 0; k < cells.length; k++) {
			const cell = cells[k];
			if (cell.text.length < 4) continue;
			const column = header?.[k];
			const before = cells[k - 1]?.text;
			// (A description column holds sentences about the value, not the value.)
			const describes = (n?: string) =>
				!!n && /^(?:description|desc|purpose|notes?|meaning|usage|used for|details|comment|explanation)$/i.test(n);
			// The name is the column's header, or a credential's name in the cell before, unless the column describes the
			// value or (with no header) a sentence sits there with more cells after it.
			const prose = /\s/.test(cell.text) && cells.length > k + 1 && !header;
			const rowName =
				before !== undefined &&
				/^[A-Za-z_][\w.-]{1,80}$/.test(before) &&
				isCredentialName(before) &&
				!describes(column) &&
				!prose;
			const name = column && isCredentialName(column) ? column : rowName ? before : undefined;
			// (A bare `key` or `secret` naming a row of settings is the setting's name, not a cache's or an object's key:
			// its value is judged as a credential's, `| key | <64 hex> |`.)
			const judgedAs = name === before && isGenericName(name ?? "") ? `api_${name}` : name;
			if (!name || !isNamedSecret(judgedAs!, `"${cell.text}"`, true)) continue;
			namedFinding(out, cell.start, cell.end, name, "named:table-cell");
		}
	}
}

/** A row of an aligned table read by its rule's bars, not its own: ` 2 | bob | Kx9|mQv2 ` is three cells. */
function alignedCells(line: string, offset: number, bars: number[]): Cell[] {
	const cells: Cell[] = [];
	const edges = [-1, ...bars, line.length];
	for (let k = 0; k + 1 < edges.length; k++) {
		const raw = line.slice(edges[k] + 1, edges[k + 1]);
		// (Outside the outer bars of a `+----+` table there is nothing.)
		if ((k === 0 && edges[1] === 0) || (k === edges.length - 2 && edges[k] >= line.length - 1 && !raw.trim())) continue;
		const value = raw.trim();
		const start = offset + edges[k] + 1 + raw.indexOf(value);
		cells.push({ text: value, start, end: start + value.length });
	}
	return cells;
}

/**
 * A Markdown row with more cells than its header (a `|` its writer didn't escape): the extra bars are taken to be
 * inside the first credential column's value, whose cells are joined back into one.
 */
function joinedCells(text: string, cells: Cell[], header: string[]): Cell[] {
	const extra = cells.length - header.length;
	const k = header.findIndex((h) => isCredentialName(h));
	if (k < 0) return cells;
	const joined = {
		text: text.slice(cells[k].start, cells[k + extra].end),
		start: cells[k].start,
		end: cells[k + extra].end,
	};
	return [...cells.slice(0, k), joined, ...cells.slice(k + extra + 1)];
}

/**
 * A REPL or notebook echoing a credential: `os.environ['SESSION_SECRET']` (or `settings.API_KEY`,
 * `process.env.TOKEN`) on one line and its value on the next: `Out[29]: '…'`, `'…'`, `=> "…"`.
 */
function replEchoes(text: string, out: Finding[]) {
	if (!/environ|getenv|process\.env|settings\.|config\.|ENV\[|\$env:/.test(text)) return;
	for (const m of text.matchAll(
		new RegExp(
			String.raw`(?:environ(?:\.get)?[\[(][ \t]*["']|getenv\([ \t]*["']|process\.env\.|settings\.|config\.|ENV\[["']|\$env:)([A-Za-z_][\w]{0,80})["']?[\])]?[^\n]{0,40}\r?\n(?:Out\[\d+\]:[ \t]*|=>[ \t]*|>[ \t]*)?${quoted(2, 4)}[ \t]*\r?$`,
			"dgm",
		),
	))
		namedValue(out, m[1], group(m, 3), "named:repl-echo");
}

const HTML_PAIR = new RegExp(
	String.raw`<(th|td|dt)\b[^>]{0,200}>[ \t]*([^<\n]{1,80}?)[ \t]*<\/\1>[ \t\r\n]{0,40}<(td|dd)\b[^>]{0,200}>[ \t]*([^<\n]{1,${MAX_VALUE}}?)[ \t]*<\/\3>`,
	"dgi",
);

/** HTML tables and definition lists: `<th>password</th><td>…</td>`, `<dt>API key</dt><dd>…</dd>`. */
function htmlPairs(text: string, out: Finding[]) {
	if (!/<t[hd]|<dt/i.test(text)) return;
	for (const m of text.matchAll(HTML_PAIR))
		namedValue(out, m[2].replace(/[\s:]+$/, "").replace(/\s+/g, "_"), group(m, 4), "named:html-pair");
}

/** The verbs that give a value in a sentence, after the name (`le mot de passe est …`, `der Key lautet …`), and CJK's particles (`密码是 …`, `パスワードは …`). */
const COPULAS = ["lautet", "ist", "est", "es", "é", "è", "är", "jest", "je", "это", "is", "on"].join("|");
const CJK_COPULAS = ["是", "为", "為", "は", "는", "은"].join("|");

/** "Key" and "token" in other languages, as labels: 密钥, 令牌, トークン, ключ, токен, clave. */
const FOREIGN_KEY_WORDS = ["密钥", "令牌", "トークン", "ключ", "токен", "clave"];
/** The labels a copula sentence names (FOREIGN_COPULA), each with its first letter in either case: `[Mm]ot de passe`. */
const COPULA_LABELS = ["password", ...FOREIGN_PASSWORD_SPELLINGS, "ключ", "токен", "clave"]
	.filter((w) => /^[\p{Script=Latin}\p{Script=Cyrillic}]/u.test(w))
	.map((w) => `[${w[0].toUpperCase()}${w[0].toLowerCase()}]${w.slice(1)}`)
	.join("|");

/** The scripts a sentence in another language runs on into without a blank: a value ends at one. */
const CJK_SCRIPTS = String.raw`[\p{sc=Han}\p{sc=Hiragana}\p{sc=Katakana}\p{sc=Hangul}]`;

/** Credential labels in other languages: 密码, パスワード, 비밀번호, пароль, contraseña, mot de passe, Passwort, … */
// Labels in alphabets written with spaces start a word (`enclave` isn't `clave`); CJK labels follow other characters directly.
const FOREIGN = new RegExp(
	String.raw`(?<![\p{Script=Latin}\p{Script=Cyrillic}\p{Script=Greek}\p{N}_])(${[...FOREIGN_PASSWORD_SPELLINGS, ...FOREIGN_KEY_WORDS].join("|")})[ \t]*[:：=][ \t]*["'「]?${unquotedValue(String.raw`[^\s"'」，。、；！？）]`, 4, String.raw`[\s"'」，。、；！？）]|${CJK_SCRIPTS}|$`)}`,
	"dgiu",
);
/**
 * The same in a sentence, with the language's copula: `le mot de passe du service est …`, `a senha dele é …`,
 * `der DATADOG_API_KEY lautet …`, `пароль сервиса — …`, `パスワードは … です`, `他的密码是 …`. Up to three words
 * may stand between the name and the verb (`du service`, `für den Dienst`, `actuel`).
 */
const FOREIGN_COPULA = new RegExp(
	String.raw`(?:(?<![\p{Script=Latin}\p{Script=Cyrillic}\p{Script=Greek}\p{N}_])(${COPULA_LABELS}|[A-Za-z][A-Za-z0-9]*[_-][\w.-]{1,60}|[A-Z][A-Z0-9]{2,60})((?:[ \t]+(?!(?:${COPULAS})[ \t])[\p{L}][\p{L}'-]{0,20}){0,3})(?:[ \t]+(?:${COPULAS}|—|–)|[ \t]*(?:${CJK_COPULAS}))|(密码|口令|密碼|密钥|令牌|パスワード|トークン|비밀번호|암호)()[ \t]*(?:是|为|為|は|는|은|이|가))[ \t]*[:：]?[ \t]*(["'「『*\x60]{0,2})${unquotedValue(String.raw`[^\s"'」』，。、；！？）*\x60]`, 4, String.raw`\5?(?:[\s"'」』，。、；！？）*\x60]|[.,;!?](?:\s|$)|${CJK_SCRIPTS}|$)`)}\5?`,
	"dgu",
);
const FOREIGN_WORDS = new RegExp(
	`^(?:password|${[...FOREIGN_PASSWORD_SPELLINGS, ...FOREIGN_KEY_WORDS].join("|")})$`,
	"iu",
);
/** What FOREIGN and FOREIGN_COPULA need to match at all: a label's word, a copula, or a dash. */
const FOREIGN_PREFILTER = new RegExp(
	`${[...FOREIGN_PASSWORD_SPELLINGS, ...FOREIGN_KEY_WORDS, "키", "秘钥", "キー", "clé", "schlüssel", "chave", CJK_COPULAS, "이", "가"].join("|")}|(?<!\\p{L})(?:${COPULAS})(?!\\p{L})|[—–]`,
	"iu",
);
function foreignLabels(text: string, out: Finding[]) {
	// (The labels' words, or a copula after an English name: what FOREIGN and FOREIGN_COPULA need to match at all.)
	if (!FOREIGN_PREFILTER.test(text)) return;
	for (const m of text.matchAll(FOREIGN)) {
		const value = withoutUnopenedClosers(m[2]);
		// (A value running on into a counter's word is the sentence's: `パスワード：英数字8文字以上`; `春天4698@です` is a password.)
		const end = m.indices![2]![0] + value.length;
		if (
			!isProseValue(value) ||
			isCode(value, true) ||
			/^\d+(?:-\d+)?$/.test(value) ||
			CJK_COUNT.test(value + text.slice(end, end + 4))
		)
			continue;
		namedFinding(out, m.indices![2]![0], m.indices![2]![0] + value.length, "password", "named:foreign-label", 0.9);
	}
	// A key's row in a table labelled in another language: `| REST API 키 | … |`, `| 密钥 | … |`.
	for (const m of text.matchAll(
		new RegExp(
			String.raw`[│|][ \t]*([^│|\n]{0,40}?(?:키|密钥|秘钥|キー|ключ|clé|schlüssel|chave|clave))[ \t]*[│|][ \t]*([^\s│|]{8,${MAX_VALUE}})[ \t]*[│|]`,
			"dgi",
		),
	)) {
		if (
			/p[uú]blic|공개|公开|公開|öffentlich|публичн|javascript|js\b|native|네이티브|client/i.test(m[1]) ||
			!isNamedSecret("api_key", `"${m[2]}"`, true)
		)
			continue;
		namedFinding(out, m.indices![2]![0], m.indices![2]![1], "key", "named:foreign-label", 0.85);
	}
	for (const m of text.matchAll(FOREIGN_COPULA)) {
		const name = m[1] ?? m[3];
		const value = withoutUnopenedClosers(m[6]);
		// An English-looking name must be a credential's (`DATADOG_API_KEY`, `access_token`), and a sentence in English is prose's.
		const foreign = m[3] !== undefined || FOREIGN_WORDS.test(name);
		const copula = m[0]
			.slice((m[1] ?? m[3]).length + (m[2] ?? "").length)
			.trim()
			.split(/[ \t]/)[0];
		if (!foreign && (!isCredentialName(name) || /^(?:is|on)$/i.test(copula))) continue;
		// (Dutch `is` and Finnish `on` only after their own labels.)
		if (/^(?:is|on)$/i.test(copula) && !/^(?:wachtwoord|salasana)$/i.test(name)) continue;
		// A dash after an English name documents the variable: `- SMTP_PASSWORD — app-specific password`.
		if (
			!foreign &&
			/^[—–]$/.test(copula) &&
			(/^[a-z]+(?:-[a-z]+)+$/.test(value) || !(/\d/.test(value) || /[^\w-]/.test(value)))
		)
			continue;
		if (!isProseValue(value) || isCode(value, true)) continue;
		// Judged as a password (or, under a word that also means "key" in general, as a generated key), and
		// not when a word for "public" stands beside the name (`la clave pública es …`, `публичный ключ — …`),
		// nor a URL, a version, or a value in the sentence's own language (`8-stellig`, `2FA-geschützt`, `英数字8`); a
		// password in another script is one (`さくら3594@`, isForeignText).
		const start = m.indices![6]![0];
		const end = start + value.length;
		const around = text.slice(Math.max(0, m.index - 20), start);
		const nonLatin = /(?!\p{Script=Latin})\p{L}/u.test(value);
		if (
			/p[uú]blic|öffentlich|публичн|открыт|公开|公開|공개|pubblic/i.test(around) ||
			/^https?:\/\//.test(value) ||
			(/[^\x00-\x7f]/.test(value) && (!nonLatin || isForeignText(value))) ||
			CJK_COUNT.test(value + text.slice(end, end + 4)) ||
			/^v?\d+(?:\.\d+)+$/.test(value)
		)
			continue;
		const generic = /^(?:clave|ключ|токен|密钥|令牌|トークン)$/i.test(name);
		const accepted = foreign
			? looksSecret(value) &&
				/\d/.test(value) &&
				/\p{L}/u.test(value) &&
				isNamedSecret(generic ? "api_key" : "password", `"${value}"`, true)
			: isNamedSecret(name, `"${value}"`, true);
		if (!accepted) continue;
		namedFinding(out, start, end, name, "named:foreign-label", 0.85);
	}
}

/**
 * A value wrapped onto the next line, as terminals and log viewers do at 80 columns: `DB_PASSWORD=`
 * ending one line, the value alone on the next.
 */
function wrappedValues(text: string, out: Finding[]) {
	for (const m of text.matchAll(
		new RegExp(
			String.raw`(?<![\w.$@-])([A-Za-z_][\w.-]{1,80})[ \t]*[=:][ \t]*\r?\n[ \t]*${unquotedValue(String.raw`[^\s=:]`, 4, String.raw`[ \t]*\r?$`)}`,
			"dgm",
		),
	)) {
		if (isCredentialName(m[1]) && isNamedSecret(m[1], m[2], true))
			namedFinding(out, m.indices![2]![0], m.indices![2]![1], m[1], "named:wrapped");
	}
}

/**
 * Declarations and assignments in the syntaxes ASSIGN's operators don't cover, each a name then a string literal: VB's
 * `Dim password As String = "…"` (and `Private Shared …`), T-SQL's `DECLARE @password NVARCHAR(100) = N'…'`, C++'s
 * `std::string password{"…"}` and `auto password = std::string{"…"}`, CMake's `set(DB_PASSWORD "…")`, AppleScript's
 * `set thePassword to "…"`, R's `password <- "…"`; and a name and its value as two words of a command that sets one
 * (`setx DB_PASSWORD …`, fish's `set -gx`, `launchctl setenv`, `npm config set`, `dotnet user-secrets set`, `wp config
 * set`, `aws configure set`, `reg add … /v Password /d …`).
 */
const DECLARATION_FORMS: [gate: RegExp, form: string][] = [
	[
		/\bAs\b/i,
		String.raw`\b(?:Dim|Private|Public|Protected|Friend|Const|Static)(?:[ \t]+(?:Shared|ReadOnly|Const|Static))*[ \t]+(\w+)[ \t]+As[ \t]+[\w.]+(?:\(\))?[ \t]*=[ \t]*`,
	],
	[
		/string[ \t]*[{(][ \t]*["']/i,
		String.raw`\b(\w+)[ \t]*=[ \t]*(?:std::)?(?:string|String|wstring)[ \t]*[{(][ \t]*(?=["'])`,
	],
	[/DECLARE[ \t]+@/i, String.raw`\bDECLARE[ \t]+@(\w+)[ \t]+\w+(?:\([^)\n]*\))?[ \t]*=[ \t]*N?(?=')`],
	[/\w[ \t]*\{[ \t]*["']/, String.raw`\b(\w+)[ \t]*\{[ \t]*(?=["'])`],
	[/\bset\(/i, String.raw`\bset\([ \t]*(\w+)[ \t]+`],
	[/\bset[ \t]+\w+[ \t]+to[ \t]/i, String.raw`\bset[ \t]+(\w+)[ \t]+to[ \t]+`],
	[/<<?-[ \t]*["']/, String.raw`\b(\w+)[ \t]*<<?-[ \t]*(?=["'])`],
	[
		/\bset(?:x|env)?\b/i,
		String.raw`(?:^|[;&|][ \t]*|\$[ \t]+)(?:setx|set(?:[ \t]+-[a-zA-Z]+)+|launchctl[ \t]+setenv|aws[ \t]+configure[ \t]+set|(?:npm|yarn|pnpm|git|wp|dotnet[ \t]+user-secrets|heroku)[ \t]+(?:config[ \t]+)?set)[ \t]+["']?([\w.:/@-]+?)["']?[ \t]+(?=\S)`,
	],
	[
		/\breg(?:\.exe)?[ \t]+add[ \t]/i,
		String.raw`\breg(?:\.exe)?[ \t]+add[ \t][^\n]*?\/v[ \t]+["']?([\w.-]+)["']?[ \t][^\n]*?\/d[ \t]+`,
	],
];

/**
 * The forms of DECLARATION_FORMS whose gate the text passes, as one regex (built once for each set of them): the
 * forms that open with a bare name (`\b(\w+)…`) would otherwise be tried at every word of every text.
 */
const declarationForms = new Map<string, RegExp>();
function declarationRegex(text: string): RegExp | undefined {
	const forms = DECLARATION_FORMS.filter(([gate]) => gate.test(text)).map(([, form]) => form);
	if (!forms.length) return undefined;
	const key = forms.join("|");
	let re = declarationForms.get(key);
	if (!re) declarationForms.set(key, (re = new RegExp(key, "gim")));
	return re;
}
/**
 * Calls whose signature takes a secret, with no credential word in the callee: the argument at its place, judged as
 * what it is. Basic auth's password (Go's `req.SetBasicAuth(user, pw)`, Ruby's and Rust's `basic_auth(user, pw)`,
 * OkHttp's `Credentials.basic(user, pw)`, Python's `HTTPBasicAuth(user, pw)`), a JWT's signing secret
 * (`jwt.sign(payload, secret)`, `jwt.encode(payload, key, …)`), an HMAC's key (`hmac.new(key, …)`,
 * `crypto.createHmac("sha256", key)`, `OpenSSL::HMAC.hexdigest("SHA256", key, data)`).
 */
const SECRET_ARGUMENTS: [callee: RegExp, key: number, judgedAs: string][] = [
	[/(?:SetBasicAuth|basic_auth|BasicAuth|HTTPBasicAuth|HttpBasicAuth|Credentials\.basic|basicAuth)$/, 1, "password"],
	[/\bjwt\.(?:sign|encode|verify|decode)$|\bJWT\.(?:encode|decode)$|\bJwts?\.(?:sign|encode)$/i, 1, "secret_key"],
	[/\bsignWith$/, 0, "secret_key"],
	// (An HMAC's key: first in Python's `hmac.new(key, msg, sha256)` and `hmac.digest(key, msg, "sha256")`, pycryptodome's
	// `HMAC.new(key, msg)` and Ruby's `OpenSSL::HMAC.new(key, digest)`; second after the algorithm in `createHmac(alg, key)`
	// and Ruby's `HMAC.hexdigest(alg, key, data)`.)
	[/\bhmac\.(?:new|digest|HMAC)$|\bHMAC\.new$/, 0, "secret_key"],
	[/\bcreateHmac$|\bHMAC\.(?:hexdigest|digest)$/, 1, "secret_key"],
];
const SECRET_ARGUMENT_CALL =
	/(?<![\w$])((?:[A-Za-z_$][\w$]*\.){0,3}(?:SetBasicAuth|basic_auth|BasicAuth|HTTPBasicAuth|HttpBasicAuth|basic|basicAuth|sign|signWith|encode|decode|verify|new|createHmac|hexdigest|digest|HMAC))[ \t]*\(/g;
function secretArguments(text: string, out: Finding[]) {
	if (!/basic|jwt|hmac|signWith/i.test(text)) return;
	for (const { match, args } of calls(text, SECRET_ARGUMENT_CALL)) {
		const callee = match[1];
		const rule = SECRET_ARGUMENTS.find(([pattern]) => pattern.test(callee));
		if (!rule) continue;
		const literal = args[rule[1]]?.literal;
		if (literal) namedValue(out, rule[2], literal, "named:secret-argument", { judgedAs: rule[2] });
	}
}

/**
 * A sed or perl substitution's replacement, `s|^DB_PASSWORD=.*|DB_PASSWORD=<value>|`: a `NAME=value` the script
 * writes into a file, the value to the script's delimiter.
 */
function substitutions(text: string, out: Finding[]) {
	if (!/(?:^|[\s'"])s[/|#,:@]/.test(text)) return;
	for (const m of text.matchAll(/(?:^|[\s'"])s([/|#,:@])((?:\\.|(?!\1)[^\n\\])*)\1((?:\\.|(?!\1)[^\n\\])*)\1/dg)) {
		const [from] = m.indices![3]!;
		// (A replacement that starts with the pattern's group holding the name, `s/^\(API_KEY=\).*/\1<value>/`, `-E 's/(KEY=).*/\1v/'`.)
		const group = /^\\1/.test(m[3]) ? /\\?\((?:\^)?([A-Za-z_][\w.-]{1,80})[ \t]*[=:][ \t]*\\?\)/.exec(m[2]) : null;
		if (group) {
			const value = /^\\1["']?((?:\\.|[^\s"'\\]){3,4096})/.exec(m[3]);
			if (value)
				namedValue(
					out,
					group[1],
					{ value: value[1], start: from + value[0].length - value[1].length, end: from + value[0].length },
					"named:substitution",
				);
		}
		// (A replacement may begin with a back-reference, `\1API_KEY=…`, and a value hold an escaped delimiter, `a\/b`.)
		for (const pair of m[3].matchAll(
			/(?:^|[^\w.-]|\\\d)([A-Za-z_][\w.-]{1,80})[ \t]*[=:][ \t]*["']?((?:\\.|[^\s"'\\]){3,4096})/dg,
		)) {
			namedValue(
				out,
				pair[1],
				{ value: pair[2], start: from + pair.indices![2]![0], end: from + pair.indices![2]![1] },
				"named:substitution",
			);
		}
	}
}

function declarations(text: string, out: Finding[]) {
	const forms = declarationRegex(text);
	if (!forms) return;
	for (const m of text.matchAll(forms)) {
		const name = m.slice(1).find((g) => g !== undefined)!;
		if (!isCredentialName(name)) continue;
		const at = m.index + m[0].length;
		if (text[at] === '"' || text[at] === "'") {
			const close = literalEnd(text, at);
			if (close > at)
				namedValue(out, name, { value: text.slice(at + 1, close), start: at + 1, end: close }, "named:declaration");
			continue;
		}
		// (A command's value word, unquoted: to a blank, and CMake's to its call's `)`. VB's `Dim … As … =` takes an
		// expression, code, `txtPassword.Text`: only its literal is a value.)
		if (/\bAs\b[^=]*=[ \t]*$/i.test(m[0])) continue;
		const word = (/^set\(/i.test(m[0]) ? /^[^\s'"`;&|)]{3,4096}/ : /^[^\s'"`;&|]{3,4096}/).exec(
			text.slice(at, at + 4096),
		);
		if (word) namedValue(out, name, { value: word[0], start: at, end: at + word[0].length }, "named:declaration");
	}
}

/**
 * A line that is a name and one string literal, the call syntax of Groovy's and Ruby's DSLs: Gradle's `storePassword
 * 'x'`, Chef's and Rails' `bind_password "x"`, `api_key 'x'`.
 */
function dslCalls(text: string, out: Finding[]) {
	for (const m of text.matchAll(/^[ \t]*([A-Za-z_][\w]{1,60})[ \t]+(?=["'])/gm)) {
		const at = m.index + m[0].length;
		const close = literalEnd(text, at);
		if (close < 0 || !/^[ \t]*[,;]?[ \t]*(?:\/\/.*|#.*)?\r?$/.test(text.slice(close + 1, lineEndAt(text, close + 1))))
			continue;
		if (inGoImports(text, m.index)) continue;
		namedValue(out, m[1], { value: text.slice(at + 1, close), start: at + 1, end: close }, "named:dsl-call");
	}
}

/** Whether `at` is in a Go `import ( … )` block, where a name before a string is a package's alias: `pwd "…/password"`. */
function inGoImports(text: string, at: number): boolean {
	const open = text.lastIndexOf("import (", at);
	return open >= 0 && (open === 0 || text[open - 1] === "\n") && !/\n[ \t]*\)/.test(text.slice(open, at));
}

/** Credentials given as a pair in prose: `wifi: guest / Cherry-Jade-57*`, `user \`ro\` pass \`p@ss\``, `login admin/hunter22`. */
function userPassProse(text: string, out: Finding[]) {
	if (!/pass|pw|creds?|login|wifi|wi-fi|account|u\/p/i.test(text)) return;
	for (const m of text.matchAll(
		new RegExp(
			String.raw`(?:\b(?:password|passwd|pw|pwd|passcode|passphrase)|\buser(?:name)?[ \t]{1,3}[\x60'"]?[\w.@-]{1,60}[\x60'"]?,?[ \t]{1,3}pass)[ \t]{1,3}(?:is[ \t]{1,3})?([\x60'"])([^\x60'"\s]{4,${MAX_VALUE}})\1`,
			"dgi",
		),
	)) {
		if (isProseValue(m[2]))
			namedFinding(out, m.indices![2]![0], m.indices![2]![1], "password", "named:prose-pair", 0.85);
	}
	for (const m of text.matchAll(
		new RegExp(
			String.raw`(?<![/\w-])(?:creds?|credentials|login|logins|wifi|wi-fi|account|user\/pass|u\/p)[ \t]{0,3}[:=-]?[ \t]{1,3}[\x60'"]?([\w.@+-]{1,60})[\x60'"]?[ \t]{0,3}\/[ \t]{0,3}[\x60'"]?${unquotedValue(String.raw`[^\s\x60'"/]`, 4, String.raw`[\x60'"]?(?=[.,;!)]*(?:\s|$))`)}[\x60'"]?`,
			"dgi",
		),
	)) {
		const pw = m[2];
		// (A module path's segment and its version, go.sum's `…/credentials v1.20.6/go.mod`, are no user and password.)
		if (!isProseValue(pw) || /^\d+$/.test(pw) || /^(?:https?|www)\b/.test(pw) || /^v?\d+(?:\.\d+)+/.test(m[1]))
			continue;
		// `login page / dashboard`, `account settings/billing`: words, not a password.
		if (/^\p{L}+$/u.test(pw) && naturalness(pw) > 0) continue;
		namedFinding(out, m.indices![2]![0], m.indices![2]![1], "password", "named:prose-pair", 0.85);
	}
}

/**
 * A line of an `ls` listing: file names in columns (`cron.daily  passwd-  sudo.conf`). A file named `passwd`
 * or `gpg-preset-passphrase` isn't a column of passwords, nor a name with its value beside it.
 */
function isListingLine(line: string): boolean {
	const cells = line
		.trim()
		.split(/[ \t]{2,}|\t/)
		.filter(Boolean);
	if (cells.length < 2 || !cells.every((c) => /^[\w.@+-]{1,80}[/*@=|]?$/.test(c))) return false;
	// (A bin directory's commands, `chage  gpasswd  passwd  su`: lower-case words, one a password tool's name.)
	if (
		cells.every((c) => /^[a-z][a-z0-9_.+-]*$/.test(c)) &&
		cells.some((c) => /^(?:g|ch|ht|smb|vnc|yp)?passwd$/.test(c))
	)
		return true;
	const marked = cells.filter((c) => /[.-]/.test(c)).length;
	return cells.length >= 3 ? marked >= 1 : marked === cells.length;
}

/** What columnTables needs in a text to have a column to read: a credential word (names.ts), or a cookie table's `remember_me`. */
const CREDENTIAL_COLUMN = new RegExp(`${CREDENTIAL_WORD}|remember`, "i");

/** What prose needs in a text to have a credential's name to read: any of names.ts's words (`psk`, `salt`, `unseal`), or `code` (`PIN code`). */
const CREDENTIAL_SENTENCE = new RegExp(`${CREDENTIAL_WORD}|code`, "i");

/** A header of a fixed-width table: column names apart by two or more blanks or a box-drawing bar (`NAME  DIGEST  CREATED`). */
const FIXED_WIDTH_HEADER = /^[ \t|│]*[A-Za-z_][\w.-]*(?:(?:[ \t]{2,}|[ \t]*[|│][ \t]*)[A-Za-z_][\w.-]*)+[ \t|│]*\r?$/;

/**
 * Tables with a credential column: `psql` output, pandas DataFrames, `docker ps`-style listings. The
 * header names the column; each row's cell under it is the value.
 */
function columnTables(text: string, out: Finding[]) {
	if (!CREDENTIAL_COLUMN.test(text)) return;
	const { lines, starts: offsets } = splitLines(text);
	for (let i = 0; i < lines.length - 1; i++) {
		const header = lines[i];
		// Delimited tables (CSV, TSV, `mysql --batch`): split by the delimiter, match cells by index.
		// A header: every cell a name (not a number, not empty, not indented code).
		// (Its cells read as the rows' are, quotes and all: `"name, full",password`; a blank after the delimiter is allowed.)
		const delim = header.length < 2000 ? (/[\t,;]/.exec(header)?.[0] ?? "") : "";
		const names = delim ? delimitedCells(header.replace(/\r$/, ""), delim).map((c) => c.text.trim()) : [];
		// (Names of a few words each: a wrapped sentence, `password, the authorization server MUST protect the
		// endpoint`, or a line of code, `from picobox import Stack, pass_`, has commas but no columns. Nor names inside a
		// bracket the line above opens, a parameter list or a destructuring: `({` / `  email, password` / `}: {…}) => {`.)
		if (
			names.length >= 2 &&
			names.every((n) => /^[\p{L}_][\p{L}\w ./,-]{0,60}$/u.test(n) && (n.match(/\p{L}+/gu)?.length ?? 0) <= 4) &&
			!/^[ \t]*(?:from|import|def|class|return|if|for|while|let|const|var|use)\b/.test(header) &&
			!/[([{][ \t]*\r?$/.test(lines[i - 1] ?? "")
		) {
			const credIdx = names.map((n, k) => (isCredentialName(n) ? k : -1)).filter((k) => k >= 0);
			// A name column and a value column (DevTools cookie tables, exports of settings): each row names its value.
			const nameIdx = names.findIndex((n) => /^(?:name|key|cookie|nombre|nom)$/i.test(n));
			const valueIdx = names.findIndex((n) => /^(?:value|wert|valeur|valor|值)$/i.test(n));
			if (!credIdx.length && nameIdx >= 0 && valueIdx >= 0) {
				let j = i + 1;
				for (; j < lines.length && lines[j].trim(); j++) {
					const cells = delimitedCells(lines[j].replace(/\r$/, ""), delim, offsets[j]);
					if (cells.length <= Math.max(nameIdx, valueIdx)) continue;
					const name = cells[nameIdx].text.trim();
					const cell = cells[valueIdx];
					const value = cell.text.trim();
					// (A cookie named for a session, `connect.sid`, `PHPSESSID`, is judged as a session token.)
					const session = /sess|sid$/i.test(name) && !isCredentialName(name);
					if (
						!(isCredentialName(name) || /sess|sid$|token|auth|jwt|remember/i.test(name)) ||
						!isNamedSecret(session ? "session_token" : name, `"${value}"`, true)
					)
						continue;
					const st = cell.start + cell.text.indexOf(value);
					namedFinding(out, st, st + value.length, name, "named:table-pairs", 0.85);
				}
				i = j - 1;
				continue;
			}
			if (credIdx.length) {
				let j = i + 1;
				// (A row of another width is skipped, not the end of the table; a blank line ends it.)
				for (; j < lines.length && lines[j].trim(); j++) {
					const cells = delimitedCells(lines[j].replace(/\r$/, ""), delim, offsets[j]);
					if (cells.length !== names.length) continue;
					for (const k of credIdx) {
						const cell = cells[k];
						const value = cell.text.trim();
						if (!value || !isNamedSecret(names[k], `"${value}"`, true)) continue;
						const st = cell.start + cell.text.indexOf(value);
						namedFinding(out, st, st + value.length, names[k], "named:table-delimited", 0.85);
					}
				}
				i = j - 1;
				continue;
			}
		}
		// A header is only column names, separated by two or more spaces or by box-drawing bars (`|` tables are pipeTables').
		if (header.length > 2000 || header.includes("|") || !FIXED_WIDTH_HEADER.test(header)) continue;
		if (isListingLine(header) && !/^[ \t]*[A-Z][A-Z_ ]+$/.test(header)) continue;
		const cols: [number, number, string][] = [];
		for (const c of header.matchAll(/[A-Za-z_][\w.-]{0,60}/g)) cols.push([c.index, c.index + c[0].length, c[0]]);
		// A declaration, not a header: a struct's field and its type (`Password       string`, gofmt's alignment).
		if (cols.length >= 2 && cols.slice(1).every(([, , n]) => DECLARED_TYPE.test(n))) continue;
		const credCols = cols.filter(([, , n]) => isCredentialName(n));
		// A name/value table (`SELECT name, value FROM settings`, `vault kv get`'s `Key  Value`): each row names its own value.
		const pairs =
			cols.length === 2 &&
			/^(?:name|key|setting|variable|var|parameter|param|option|field|property)$/i.test(cols[0][2]) &&
			/^(?:value|val|setting)$/i.test(cols[1][2]);
		if (pairs || !credCols.length) {
			// Its rows aren't headers of their own: skip past them.
			let j = i + 1;
			for (; j < lines.length && lines[j].trim(); j++) {
				// A header of its own with a credential column starts the next table.
				if (
					!pairs &&
					FIXED_WIDTH_HEADER.test(lines[j]) &&
					[...lines[j].matchAll(/[A-Za-z_][\w.-]{0,60}/g)].some((c) => isCredentialName(c[0]))
				)
					break;
				if (!pairs) continue;
				const cells = [...lines[j].matchAll(/[^\s|│]+(?:[ \t][^\s|│]+)*/g)];
				if (cells.length !== 2 || /^[-+=─━┼]+$/.test(cells[0][0])) continue;
				const [name, value] = [cells[0][0], cells[1][0]];
				if (!isCredentialName(name) || !isNamedSecret(name, `"${value}"`, true)) continue;
				namedFinding(
					out,
					offsets[j] + cells[1].index,
					offsets[j] + cells[1].index + value.length,
					name,
					"named:table-pairs",
					0.85,
				);
			}
			i = j - 1;
			continue;
		}
		let j = i + 1;
		const column: { finding: Finding; cell: string }[] = [];
		for (; j < lines.length; j++) {
			const row = lines[j];
			// (A blank line or a prompt ends the table: the next command's output is another's.)
			if (!row.trim() || PROMPT.test(row)) break;
			if (/^[ \t]*[-+=|─━┼]+[ \t]*$/.test(row) || /^[-+|=─ ]+$/.test(row)) continue; // separator
			if ((row.match(/[^\s|│]+/g) ?? []).length < 2) break;
			// A row with a cell for each column (cells apart by two or more blanks) is read by index: a cell wider than its
			// header (`doctl`'s URI) shifts the others off their headers' columns.
			const cells = [...row.matchAll(/[^\s|│]+(?:[ \t][^\s|│]+)*/g)];
			if (cells.length === cols.length) {
				for (const [hs, , name] of credCols) {
					const cell = cells[cols.findIndex(([s]) => s === hs)];
					if (/[ \t]/.test(cell[0]) || !isNamedSecret(name, `"${cell[0]}"`, true)) continue;
					const found: Finding[] = [];
					namedFinding(
						found,
						offsets[j] + cell.index,
						offsets[j] + cell.index + cell[0].length,
						name,
						"named:table-column",
						0.85,
					);
					column.push({ finding: found[0], cell: cell[0] });
				}
				continue;
			}
			for (const [hs, he, name] of credCols) {
				// The cell is the run of non-space characters overlapping the header's columns.
				for (const cell of row.matchAll(/[^\s|│]+/g)) {
					const cs = cell.index;
					const ce = cs + cell[0].length;
					if (ce <= hs - 2 || cs >= he + 2) continue;
					if (!isNamedSecret(name, `"${cell[0]}"`, true)) continue;
					const found: Finding[] = [];
					namedFinding(found, offsets[j] + cs, offsets[j] + ce, name, "named:table-column", 0.85);
					column.push({ finding: found[0], cell: cell[0] });
					break;
				}
			}
		}
		// (Identifiers all down the column are a listing's file names or a struct's fields under a name that only looks
		// like a header: `ls /usr/bin` under `kpasswd`, gofmt's `clientSecret  string` above `tokenURL  string`. A header
		// that is a column's name, `PASSWORD`, `passwd`, heads a table of passwords, however plain they are.)
		const headed = credCols.every(([, , n]) =>
			/^(?:pass(?:word|wd)?|pwd|pin|secrets?|tokens?|keys?|api[_-]?keys?|credentials?)$/i.test(n),
		);
		if (
			headed ||
			!(
				column.length >= 2 && column.every(({ cell }) => /^[a-z_][a-z0-9_.+-]*$|^[a-z]+(?:[A-Z][a-z0-9]*)+$/.test(cell))
			)
		)
			out.push(...column.map(({ finding }) => finding));
		// The rows just read aren't headers of their own: continue after them.
		i = Math.max(i, j - 1);
	}
}

/** A type as a declaration writes it after a field's name (Go's built-in types, a package's type: `time.Duration`). */
const DECLARED_TYPE =
	/^(?:string|bool|byte|rune|error|any|int(?:8|16|32|64)?|uint(?:8|16|32|64|ptr)?|float(?:32|64)|complex(?:64|128)|func|map|chan|interface|struct|[a-z][a-z0-9]*\.[A-Z]\w*)$/;

/** Java system properties on a command line: `-Dspring.datasource.password=…`, `-Djavax.net.ssl.keyStorePassword=…`. */
function javaProperties(text: string, out: Finding[]) {
	if (!text.includes("-D") && !text.includes("-P")) return;
	// (Gradle takes project properties the same way: `-PKEYSTORE_PASSWORD=…`.)
	for (const m of text.matchAll(
		/(?:^|[\s"'=])-[DP]([A-Za-z_][\w.-]{0,120})=(?:"([^"\n]+)"|'([^'\n]+)'|([^\s"']{1,4096}))/dg,
	)) {
		const k = m[2] !== undefined ? 2 : m[3] !== undefined ? 3 : 4;
		if (isCredentialName(m[1]) && isNamedSecret(m[1], k < 4 ? `"${m[k]}"` : m[k], true))
			namedFinding(out, m.indices![k]![0], m.indices![k]![1], m[1], "named:java-property");
	}
}

/**
 * Pairs whose name is a sibling attribute of the value, not its key: Kubernetes env (`- name: DB_PASSWORD` /
 * `value: …`), HCL (`name = "/prod/db/password"` … `value = "…"`), JSON and CloudFormation (`{"Name": "API_KEY",
 * "Value": "…"}`), HTML (`<input name="password" value="…">`). Siblings sit on one line, or in one block: later lines
 * indented at least as far, with nothing between them that closes the block. A name that is a path or a dotted key
 * names its value by its last part (`/prod/db/password`). (One reader for every syntax, so a value's name is found
 * the same way wherever it is written.)
 */
function siblingPairs(text: string, out: Finding[]) {
	if (!/value|SecretString/i.test(text)) return;
	type Attr = { key: string; value: string; start: number; quoted: boolean; line: number; indent: number };
	const attrs: Attr[] = [];
	let line = 0;
	let lineAt = 0;
	// (The next line break, and a line's indent, its blanks and list markers, each found once.)
	let next = text.indexOf("\n");
	let indent = -1;
	// YAML mapping lines as yaml.ts reads them (a plain value runs to the line's end or a comment, `,` `{` and blanks
	// included); other syntaxes' attributes as syntax.ts reads them.
	const yaml = /^[ \t-]*["']?[A-Za-z]\w*["']?[ \t]*:/m.test(text) ? yamlLines(text) : [];
	const mapping = new Set<number>();
	yaml.forEach((l, i) => {
		if (!l.key || !l.value || (!PAIR_NAME.test(l.key) && !PAIR_VALUE.test(l.key))) return;
		mapping.add(l.start);
		attrs.push({ key: l.key, value: l.value.value, start: l.value.start, quoted: l.quoted, line: i, indent: l.indent });
	});
	for (const a of attributes(text)) {
		if (
			!PAIR_NAME.test(a.key) &&
			!PAIR_VALUE.test(a.key) &&
			!(/^type$/i.test(a.key) && /^password$/i.test(a.value.value))
		)
			continue;
		for (; next >= 0 && next < a.start; next = text.indexOf("\n", next + 1)) {
			line++;
			lineAt = next + 1;
			indent = -1;
		}
		if (indent < 0) for (indent = 0; lineAt + indent < a.start && /[ \t-]/.test(text[lineAt + indent]); indent++);
		if (lineAt + indent === a.start && mapping.has(lineAt)) continue;
		attrs.push({ key: a.key, value: a.value.value, start: a.value.start, quoted: a.quoted, line, indent });
	}
	attrs.sort((a, b) => a.start - b.start);
	for (let i = 0; i < attrs.length; i++) {
		const named = attrs[i];
		// (An HTML input's `type="password"` names its value as `name=` does: `<input type="password" value="…">`.)
		const passwordInput = /^type$/i.test(named.key) && /^password$/i.test(named.value);
		if (!PAIR_NAME.test(named.key) && !passwordInput) continue;
		const credential = passwordInput
			? "password"
			: [named.value, named.value.split(/[/.:]/).filter(Boolean).at(-1) ?? ""].find(
					(n) => /^[A-Za-z_][\w.\/:-]{0,100}$/.test(n) && isCredentialName(n),
				);
		if (!credential) continue;
		// The value attribute nearest it, before or after, in the same block.
		for (const j of [i + 1, i - 1, i + 2, i - 2, i + 3]) {
			const v = attrs[j];
			if (!v || !PAIR_VALUE.test(v.key) || Math.abs(v.line - named.line) > 6) continue;
			const [first, second] = v.start > named.start ? [named, v] : [v, named];
			const between = text.slice(first.start, second.start);
			// (A brace or a new list item between them starts another block: `- name: A` / `value: …` / `- name: B`.)
			if (
				/[{}]|\n[ \t]*- /.test(between.slice(first.value.length)) ||
				(second.line > first.line && second.indent < first.indent)
			)
				continue;
			if (!v.value || !isNamedSecret(credential, v.quoted ? `"${v.value}"` : v.value, true)) break;
			namedFinding(out, v.start, v.start + v.value.length, credential, "named:sibling-pair");
			break;
		}
	}
}

/** Words that follow `password is` in sentences about passwords rather than ones that give one. */
const PROSE_WORDS = new Set([
	"required",
	"incorrect",
	"invalid",
	"wrong",
	"correct",
	"missing",
	"empty",
	"blank",
	"set",
	"unset",
	"stored",
	"hashed",
	"encrypted",
	"saved",
	"changed",
	"reset",
	"expired",
	"too",
	"not",
	"the",
	"a",
	"an",
	"your",
	"my",
	"our",
	"their",
	"his",
	"her",
	"its",
	"this",
	"that",
	"same",
	"different",
	"still",
	"now",
	"also",
	"being",
	"been",
	"case",
	"sensitive",
	"mandatory",
	"weak",
	"strong",
	"long",
	"short",
	"okay",
	"fine",
	"good",
	"bad",
	"there",
	"here",
	"generated",
	"random",
	"provided",
	"given",
	"sent",
	"shown",
	"hidden",
	"visible",
	"used",
	"needed",
	"protected",
	"secure",
	"insecure",
	"valid",
	"unique",
	"only",
	"just",
	"always",
	"never",
	"usually",
	"probably",
	"somewhere",
	"written",
	"printed",
	"rotated",
	"revoked",
	"compromised",
	"leaked",
	"known",
	"unknown",
	"fake",
	"real",
	"temporary",
	"new",
	"old",
	"updated",
	"string",
	"number",
	"int",
	"boolean",
	"text",
	"bytes",
	"object",
	"any",
	"nullable",
	"ignored",
	"configured",
	"supported",
	"accepted",
	"rejected",
	"disabled",
	"enabled",
	"displayed",
	"masked",
	"redacted",
	"what",
	"which",
	"where",
	"when",
	"why",
	"how",
	"something",
	"anything",
	"nothing",
	"everything",
	"easy",
	"hard",
	"simple",
	"complex",
	"safe",
	"unsafe",
	"secret",
	"private",
	"public",
	"important",
	"bcrypt",
	"scrypt",
	"argon2",
	"argon2id",
	"pbkdf2",
	"md5",
	"sha1",
	"sha256",
	"plaintext",
	"salted",
	"optional",
	"immutable",
	"readonly",
	"in",
	"on",
	"at",
	"for",
	"of",
	"to",
	"from",
	"by",
	"with",
	"and",
	"or",
	"but",
	"if",
	"then",
	"so",
	"because",
	"available",
	"expiring",
	"defined",
	"specified",
	"read",
	"loaded",
	"passed",
	"included",
	"attached",
	"present",
	"absent",
	"null",
	"none",
	"undefined",
	"false",
	"true",
]);
const PROSE = new RegExp(
	String.raw`(?<![/.])\b([A-Za-z][\w-]{0,40}(?:[ \t][A-Za-z][\w-]{0,40})?)('s[ \t]{1,3}|[ \t]{1,3}(?:is|was|=|got (?:reset|changed|rotated|set) to|(?:has been |was )?(?:reset|changed|rotated|set|updated) to)(?:[ \t]{1,3}(?:now|still|currently|actually|just|set to))?[ \t]{0,3}:?[ \t]{1,3}|:[ \t]{1,3})(["'\x60*]{0,2})${unquotedValue(String.raw`(?:(?!\\[nrt])[^\s"'\x60])`, 4, String.raw`\3(?=[.,;!?)\]]{0,3}(?:[\s"'\x60]|\\n|$|<\/[a-zA-Z]))`)}\3?`,
	"dg",
);

/** A credential named in a sentence: `my wifi password is …`, `API key: …`, `the token was …`. */
function prose(text: string, out: Finding[]) {
	if (!CREDENTIAL_SENTENCE.test(text)) return;
	// A passphrase or password quoted after a label: `Your passphrase (between double-quotes): "falcon tiger quartz"`.
	for (const m of text.matchAll(
		/\b(passphrase|pass phrase|mnemonic|recovery phrase|seed phrase)\b[^:\n"]{0,40}:[ \t]*(["'])([^"'\n]{8,200})\2/dgi,
	)) {
		const value = m[3];
		if (
			/\$\{|\{\{|^<|%s/.test(value) ||
			isInert(value) ||
			isPlaceholder(value) ||
			!(
				/^[a-z]+(?:[ -][a-z]+){2,}$/.test(value) ||
				(looksSecret(value) && /\d/.test(value) && /[A-Za-z]/.test(value) && !/\s/.test(value))
			)
		)
			continue;
		namedFinding(out, m.indices![3]![0], m.indices![3]![1], m[1], "named:prose", 0.85);
	}
	for (const m of text.matchAll(PROSE)) {
		// (A preposition or a determiner before the name is the sentence's: `Cache restored from key: …` names a `key`.)
		const words = m[1].split(/\s+/);
		const name = words.length > 1 && PHRASE_STOP.test(words[0]) ? words[1] : m[1];
		const before =
			words.length > 1
				? words.at(-2)!
				: (/(\p{L}+)[ \t]*$/u.exec(text.slice(Math.max(0, m.index - 30), m.index))?.[1] ?? "");
		if (/^pass$/i.test(lastWord(name)) && isPassInEnglish(before)) continue;
		if (isVerdictUnderPass(name, withoutUnopenedClosers(m[4]))) continue;
		const last = lastWord(name);
		const value = withoutUnopenedClosers(m[4]);
		if (!isCredentialName(name.replace(/\s+/g, "_")) || /cookie/i.test(name) || clientSdkAt(text, m.index)) continue;
		// A signature's parameter and its type, `decode(secret: Base32SecretKey): …`: the line opens a bracket before the
		// name and the value closes it.
		if (/^[A-Za-z_$][\w$.<>[\]]*\)/.test(m[4]) && enclosingCall(text, m.index) !== undefined) continue;
		const bare = value.replace(/[.,;:!?]+$/, "").toLowerCase();
		// (A passphrase of words, cut at its first blank by the value's grammar: read whole, before any test of one word.)
		const phrase = takesAnyWord(name.replace(/\s+/g, "_"))
			? passphraseEnd(text, m.indices![4]![0], m.indices![4]![0] + value.length)
			: 0;
		if (phrase > m.indices![4]![0] + value.length) {
			namedFinding(out, m.indices![4]![0], phrase, name, "named:prose", 0.85);
			continue;
		}
		const pin = isPinName(name.replace(/\s+/g, "_")) && /^\d{4,8}$/.test(value.replace(/[.,;:!?]+$/, ""));
		if (
			!pin &&
			(/\?$/.test(value) ||
				/^[a-z]+ed(?:\/[a-z]+ed)*$/.test(bare) ||
				/^[[(<{].*[\])>}]$/.test(value) ||
				/^\d+-\d+$|^(?:min|max)\.?$/i.test(value) ||
				!isProseValue(value))
		)
			continue;
		// (After `=` the sentence is code: `user_password = Arcfour(key).decrypt(…)`; and so it is when code's punctuation
		// follows, `password: proxyPass);`, or the value ends a literal's last entry (isLastEntry). A template's hole,
		// `{c.Password}`, `v2-cache-{{`, and a symbol, `[:public]`, aren't values.)
		// (A reference, a member's path or a call, is code wherever it's written: `pass: process.env.SMTP_PASSWORD`,
		// `password: this.data.password`; a bare name isn't, `The password is: BlueSecret`.)
		if (
			((/=/.test(m[2]) ||
				/^[);,]/.test(text.slice(m.indices![4]![1])) ||
				(/^[ \t]*\r?$/.test(text.slice(m.indices![4]![1], lineEndAt(text, m.indices![4]![1]))) &&
					isLastEntry(text, m.index))) &&
				isCode(value)) ||
			(/[.([]/.test(value) && isCode(value, true))
		)
			continue;
		if (/\{\{|^\[?:[a-z_]\w*\]?$/.test(value) || (text[m.indices![4]![0] - 1] === "{" && /\}$/.test(value))) continue;
		const start = m.indices![4]![0];
		if (
			/^(PIN|SEED|MNEMONIC|PHRASE|SIG|SIGNATURE)$/.test(last) &&
			!isNamedSecret(name.replace(/\s+/g, "_"), `"${value}"`, true)
		)
			continue;
		if (isHashWithWords(value)) continue;
		if (takesAnyWord(name.replace(/\s+/g, "_"))) {
			if (/^[a-z]+(-[a-z]+)+$/.test(value) || isLabel(value, name) || isSettingOrSelfName(name, value)) continue;
			// (`pass: 12/12`, `Pass: 98.5%`: a test count.)
			if (/^pass$/i.test(name) && /^\d+(?:[/.,]\d+)*%?[,;]?$/.test(value)) continue;
			const after = text.slice(start + value.length, start + value.length + 40);
			// (A digit or a symbol makes it one; a letter outside ASCII doesn't: `confirm_password: Potwierdź moje konto`.)
			// (Or the object around it closes after it, `{user: svc, password: acez}`, and it's no test word or ordinary word.)
			const closed = /^[ \t]*[)\]}]/.test(after) && !isTestValue(value) && naturalness(value) < 0.5;
			if (!(
				m[3] ||
				closed ||
				/\d/.test(value) ||
				/[^\p{L}\p{N}_]/u.test(value) ||
				/^[.,;!?)\]]{0,3}[ \t]*(?:$|\r|\n|\\n|(?:and|but|so|btw|if|or|lol|thanks|thx|please|pls|then|for|ok)\b)/i.test(
					after,
				)
			))
				continue;
		} else if (
			!isNamedSecret(name.replace(/\s+/g, "_"), `"${value}"`, false) ||
			(value.length < 16 && !(value.length >= 10 && hasThreeClasses(value) && /[^A-Za-z0-9]/.test(value)))
		)
			continue;
		namedFinding(out, start, start + value.length, name, "named:prose", 0.85);
	}
	// Listed in a sentence: `user is ro_analytics, password R0ck3t#46, host …`; and the new value of a credential
	// the sentence named: `ops rotated the db password yesterday, new one is Thund3r&55`.
	for (const m of text.matchAll(
		/(?:^|[,;:(]\s*|\b(?:and|with)\s+)(password|passwd|pwd|pw|passphrase)\s+([^\s,;()"'`]{6,64}?)(?=[,;)]|\s+(?:and|host|user|db|port|for|account|role|warehouse|database|schema|on|at|in|via|to)\b|[.!]?\s*$)|\b(password|passwd|token|secret|api key|key)\b[^.\n]{0,80}?\b(?:new one|the new one|it)(?:'s| is| is now|’s)\s+["'`*]{0,2}([^\s"'`*,;]{6,64}?)["'`*]{0,2}(?=[.,;!?]?(?:\s|$))/dgim,
	)) {
		const k = m[2] !== undefined ? 2 : 4;
		const value = m[k];
		const noun = (m[1] ?? m[3]).toLowerCase();
		// (`it is …` only for a credential just rotated: `rotated the password, new one is …`.)
		// (Or a quoted value that reads as a password: ``the password instead? It's `Apple2007!` ``.)
		if (
			k === 4 &&
			!/rotat|chang|reset|regenerat|replac|updat|new one/i.test(m[0]) &&
			!(/["'`*]$/.test(text.slice(m.index, m.indices![4]![0])) && /\d/.test(value) && /[^\w]/.test(value))
		)
			continue;
		// (A label before the word, `Password: …`, is the label rules'.)
		if (
			!value ||
			/:\/\/|\\/.test(value) ||
			(k === 2 && text[m.indices![1]![0] - 1] === ":") ||
			!isProseValue(value) ||
			isCode(value, true) ||
			!(/\d/.test(value) && /[A-Za-z]/.test(value)) ||
			// (A key's or a token's value as those are judged: `the SSH key was updated, it is id_ed25519 now` names a file.)
			(!/^pass|^pw/.test(noun) && !isNamedSecret(noun.replace(/\s+/g, "_"), `"${value}"`, true))
		)
			continue;
		namedFinding(out, m.indices![k]![0], m.indices![k]![1], noun, "named:prose", 0.8);
	}
	// A value in parentheses after its name: `rotate the passwd (M34d0w) before Friday`, `the DB_PASSWORD (Xk9…)`.
	for (const m of text.matchAll(
		new RegExp(
			String.raw`(?<![\w.$-])([A-Za-z][\w-]{1,60})[ \t]+\((["'\x60]?)${unquotedValue(String.raw`[^\s()"'\x60]`, 4, String.raw`\2\)`)}`,
			"dg",
		),
	)) {
		const [, name, , value] = m;
		// (`tests pass (40/40)`: the verb, and a count.)
		// (A number is a password under a password's name, six digits or more, or a PIN of four to eight.)
		const digits =
			/^\d+$/.test(value) &&
			((isPinName(name) && value.length >= 4 && value.length <= 8) || (isPasswordName(name) && value.length >= 6));
		// (Nor a module's path after a function's name: unittest's `test_set_password (auth_tests.test_models.UserTests)`.)
		if (
			/^pass(?:es|ed)?$/i.test(name) ||
			(!/\p{L}/u.test(value) && !digits) ||
			!isCredentialName(name) ||
			!isProseValue(value) ||
			isCode(value, true) ||
			/^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*){2,}$/.test(value)
		)
			continue;
		// (Under a password's name a word with a digit or a symbol, not a letter outside ASCII: Czech `heslo (volitelné)`,
		// "password (optional)"; under another, what that name takes.)
		const password = takesAnyWord(name);
		const accepted =
			digits ||
			(password
				? (/\d/.test(value) || /[^\p{L}\p{N}_]/u.test(value)) &&
					!isLabel(value, name) &&
					isNamedSecret("password", `"${value}"`, true)
				: isNamedSecret(name, `"${value}"`, true));
		if (ALGORITHM.test(value) || !accepted) continue;
		namedFinding(out, m.indices![3]![0], m.indices![3]![1], name, "named:prose", 0.8);
	}
}

/**
 * Whether a value a sentence gives (`the password is …`, `pass (…)`, `**Password:** …`, `密码：…`) can be a secret: not a
 * word a sentence goes on with or a common one, an algorithm's name, code that prose names (PROSE_CODE), or anything
 * else a literal secret never looks like. Sentence punctuation after it isn't part of it. Each rule adds its own terms.
 */
function isProseValue(value: string): boolean {
	const v = value.replace(/[.,;:!?)]+$/, "");
	const lower = v.toLowerCase();
	return (
		!PROSE_WORDS.has(lower) &&
		!COMMON_WORDS.has(lower) &&
		!ALGORITHM.test(v) &&
		!PROSE_CODE.test(v) &&
		looksSecret(`"${v}"`, true)
	);
}

/**
 * Code where prose names a credential (a value prose delimits is otherwise a literal, brackets and all): a call
 * or a type cut at its bracket (`from_private_bytes(`, `&ChangePassword{`, `[parameters(`), an instance or shell
 * variable (`@user_password`, `${JWT_SECRET:?…`), a call's end (`bool):`), a reference type (`pwd: &Path`), an
 * interpolation's hole cut at its brace (`{result2`); and an issue's reference (`[GH-975]`) or a list of formats
 * (`(DER/PEM/P12)`) that a sentence about a password goes on to.
 */
const PROSE_CODE =
	/^(?:[@$&%]{0,2}\{?)[A-Za-z_][\w.]*[([{][\w"'., :=$({[]*[)\]}]?:?$|^[@$]{1,2}\{?[A-Za-z_]\w*[})]?$|^\$\{|^\[[A-Za-z_][\w.]*\(|^[\w.]+\):?$|^&(?:mut )?[A-Z][\w:]*(?:<[^>]*>)?$|^\{[A-Za-z_]\w*$|^\[?[A-Z][A-Z0-9]{1,9}-\d{1,6}\]?$|^\(?[A-Z0-9]{2,8}(?:\/[A-Z0-9]{2,8})+\)?$/;

/** How far into a sentence a credential's noun reaches to the verb or the value that gives it (`the admin password for the billing team's production cluster is …`). */
const SENTENCE_REACH = 200;

/** Credential nouns that sentences and labels use. */
const CRED_NOUN = String.raw`(?:pass(?:word|code|phrase)|pass phrase|(?:${CREDENTIAL_QUALIFIERS}|authentication|application)[ _-]?(?:key|token|secret)|token|secret|pin(?: code)?)`;
/**
 * A credential as a sentence names it: a determiner, up to three qualifiers and the noun (`the root password`, `the
 * webhook secret`, `your new API key`), or a variable's name (`DB_PASSWORD`). The noun, or the name, is group 1.
 */
const CRED_PHRASE = String.raw`(?:(?:the|a|an|their|his|her|its|our|my|your|this|that)\s+)?(?:[\w-]+\s+){0,3}?(${CRED_NOUN}|[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*_(?:PASSWORD|PASSWD|PASS|PWD|SECRET|TOKEN|KEY)(?:_[A-Z0-9]+)*)`;
const CRED_NOUN_IN = new RegExp(CRED_NOUN, "i");
/**
 * Words that don't make a passphrase: the grammar a sentence goes on with (`hunter2 and the user is bob`, `is sometimes
 * passed into`, `is more than enough`, `each time he uses sudo`), and what one says about a password instead of
 * giving it (`see vault entry`, `case sensitive`, `blank`, `expires next week`).
 */
const FUNCTION_WORDS = new Set([
	"and",
	"or",
	"but",
	"nor",
	"the",
	"a",
	"an",
	"is",
	"was",
	"are",
	"were",
	"be",
	"been",
	"being",
	"has",
	"have",
	"had",
	"do",
	"does",
	"did",
	"to",
	"for",
	"of",
	"in",
	"on",
	"at",
	"by",
	"with",
	"via",
	"from",
	"into",
	"onto",
	"upon",
	"about",
	"over",
	"under",
	"than",
	"so",
	"if",
	"then",
	"that",
	"this",
	"these",
	"those",
	"it",
	"its",
	"as",
	"not",
	"no",
	"you",
	"we",
	"i",
	"he",
	"she",
	"they",
	"him",
	"her",
	"them",
	"me",
	"us",
	"my",
	"your",
	"our",
	"their",
	"his",
	"please",
	"thanks",
	"use",
	"uses",
	"set",
	"change",
	"now",
	"sometimes",
	"always",
	"never",
	"often",
	"also",
	"only",
	"just",
	"still",
	"here",
	"there",
	"see",
	"check",
	"ask",
	"refer",
	"look",
	"find",
	"get",
	"contact",
	"stored",
	"kept",
	"provided",
	"above",
	"below",
	"per",
	"blank",
	"empty",
	"unset",
	"random",
	"sensitive",
	"insensitive",
	"default",
	"expires",
	"changes",
	"required",
	"optional",
	"next",
	"week",
	"month",
	"day",
	"when",
	"where",
	"which",
	"who",
	"what",
	"how",
	"why",
	"should",
	"will",
	"would",
	"can",
	"could",
	"must",
	"may",
	"might",
	"very",
	"too",
	"quite",
	"rather",
	"really",
	"more",
	"most",
	"less",
	"least",
	"much",
	"many",
	"few",
	"enough",
	"each",
	"every",
	"all",
	"any",
	"some",
	"both",
	"either",
	"neither",
	"other",
	"another",
	"such",
	"same",
	"own",
	"else",
	"somewhere",
	"anywhere",
	"everywhere",
	"nowhere",
]);
/**
 * The grammar of the languages UI text is most often translated into (Dutch, German, French, Spanish, Portuguese,
 * Italian): articles, possessives, prepositions and conjunctions that are no English word nor BIP39's. Among a label's
 * capitalised words they make it a translation (`Bevestig mijn account`, `Confirmar minha conta`), not a passphrase.
 * (Only there: in lower case, `t la xk zmtwvhw`, a short one is as likely a passphrase's.)
 */
const FOREIGN_FUNCTION_WORDS = new Set([
	"mijn",
	"uw",
	"jouw",
	"het",
	"een",
	"voor",
	"niet",
	"naar",
	"bij",
	"wordt",
	"deze",
	"ons",
	"onze",
	"mein",
	"meine",
	"dein",
	"deine",
	"ihr",
	"ihre",
	"und",
	"der",
	"das",
	"ist",
	"nicht",
	"mit",
	"für",
	"zu",
	"ein",
	"eine",
	"einen",
	"bitte",
	"oder",
	"wird",
	"sie",
	"mon",
	"mes",
	"votre",
	"vos",
	"le",
	"la",
	"les",
	"des",
	"du",
	"et",
	"est",
	"avec",
	"une",
	"vous",
	"nous",
	"de",
	"au",
	"aux",
	"ce",
	"cette",
	"mi",
	"mis",
	"tu",
	"tus",
	"su",
	"sus",
	"el",
	"los",
	"las",
	"del",
	"para",
	"una",
	"es",
	"por",
	"minha",
	"meu",
	"sua",
	"seu",
	"você",
	"voce",
	"uma",
	"não",
	"nao",
	"da",
	"dos",
	"ao",
	"il",
	"gli",
	"della",
	"di",
	"è",
	"tuo",
	"tua",
	"mio",
	"mia",
	"non",
]);
/** nsswitch.conf's sources: `passwd: files cache ldap` lists where the system looks users up. */
const NSS_SOURCES = new Set([
	"files",
	"systemd",
	"ldap",
	"sss",
	"nis",
	"nisplus",
	"db",
	"compat",
	"cache",
	"dns",
	"winbind",
	"altfiles",
	"mymachines",
	"resolve",
	"myhostname",
	"hesiod",
	"extrausers",
	"oslogin",
]);

/**
 * A word a sentence has and a passphrase doesn't: a function word, or a verb's or an adverb's form (`hashed`, `using`,
 * `effectively`) that isn't a word of BIP39's list, which passphrases are drawn from (`jelly`, `bring`, `speed`).
 */
export function isSentenceWord(word: string): boolean {
	const w = word.toLowerCase().replace(/[.,;:!?]+$/, "");
	// (A participle or an adverb has a stem before its ending: `using`, `generated`, `randomly`; not `red`, `king`, `holy`.)
	return FUNCTION_WORDS.has(w) || (/^[a-z]{2,}(?:ed|ing)$|^[a-z]{3,}ly$/.test(w) && !bip39().has(w));
}

/** BIP39's word list as each word's index in it, built on first use. */
let BIP39: Map<string, number> | undefined;
export const bip39 = () => (BIP39 ??= new Map(BIP39_WORDS.split(" ").map((w, i) => [w, i])));

/**
 * Whether words read as a passphrase (`correct horse battery staple`): three to twelve of them, none repeated, no
 * sentence's word, and not a list of nsswitch sources.
 */
function isPassphrase(words: string[]): boolean {
	const lower = words.map((w) => w.toLowerCase());
	return (
		lower.length >= 3 &&
		lower.length <= 12 &&
		new Set(lower).size === lower.length &&
		!lower.every((w) => NSS_SOURCES.has(w)) &&
		!lower.some(isSentenceWord)
	);
}

/**
 * Where a value under a password's or a passphrase's name ends, when its reader cut it at a blank: at its closing quote
 * when quoted (`is "correct horse battery staple"`), or, unquoted, after the lower-case words that run to its line's end
 * (`The wifi password is correct horse battery staple`; not `hunter2 and the user is bob`). Either way the words must be
 * a passphrase's.
 */
function passphraseEnd(text: string, start: number, end: number): number {
	const q = text[start - 1];
	if (q === '"' || q === "'" || q === "`") {
		const close = text.indexOf(q, end);
		const lineEnd = text.indexOf("\n", end);
		return close > end &&
			close - start <= 200 &&
			(lineEnd < 0 || close < lineEnd) &&
			isPassphrase(text.slice(start, close).trim().split(/\s+/))
			? close
			: end;
	}
	if (!/^[a-z]{2,20}$/.test(text.slice(start, end))) return end;
	const rest = /^(?:[ \t]+[a-z]{2,20}){2,11}(?=[.!]?[ \t]*(?:\r?\n|$))/.exec(text.slice(end, end + 300));
	return rest && isPassphrase([text.slice(start, end), ...rest[0].trim().split(/\s+/)]) ? end + rest[0].length : end;
}

/**
 * A value as prose writes it: no spaces, up to its closing quote or emphasis, sentence punctuation, a blank, a closing
 * tag (`is **X**.`, `<p>… is X.</p>`) or an escaped line break (`… if -force is specified\n\` in a string).
 */
const PROSE_VALUE = String.raw`["'\x60*]{0,2}${unquotedValue(String.raw`[^\s"'\x60]`, 4, String.raw`["'\x60*]{0,2}[.,;:!?]?(?:\s|$|<\/[a-zA-Z]|\\[nrt])`)}["'\x60*]{0,2}`;

/**
 * Credentials named in prose with words in between, and in Markdown labels:
 * - `Our password for accessing the strategy documents is River@2025.`, `The API key utilized … was b2d1…`
 * - `…logged into the portal using the password River2025! to access…`, `Catherine's password, Elephant99#, is…`
 * - `- **Password:** m4P$9tR#7kLw`, `**Temporary Password:** Ocean@2025`, `| Password for Accessing Records | R@2025 |`
 * The value must read as one: a password with a digit, a symbol or mixed case; a key or token generated.
 */
function labelledProse(text: string, out: Finding[]) {
	if (!/pass|key|token|secret|pin\b/i.test(text)) return;
	const accept = (noun: string, value: string): boolean => {
		const v = value.replace(/[.,;:)]+$/, "");
		// (A question or a verb ends the sentence about it: `the password is reset?`, `was guessed/hacked`, `is POSTed`.)
		if (/\?$/.test(value) || /^[A-Za-z]+ed(?:\/[A-Za-z]+ed)*$/.test(v)) return false;
		// (A PIN is a few digits, which no other value test takes: checked first.)
		if (isPinName(noun.replace(/\s+/g, "_"))) return /^\d{4,8}$/.test(v);
		// (A secret's path or name in a store, not the secret: consul-template's `{{ with secret "kv-v2/data/app" }}`.)
		if (/^[a-z0-9_.-]+(?:\/[a-z0-9_.*-]+)+$/.test(v)) return false;
		if (v.length < 4 || !isProseValue(v)) return false;
		// (A password, or a secret a person set: `Set the webhook secret to Maple1319%`.)
		if (/pass|secret/i.test(noun))
			return (
				isNamedSecret("password", `"${v}"`, true) &&
				(/\d/.test(v) || /[^\w]/.test(v) || (/[a-z]/.test(v) && /[A-Z]/.test(v.slice(1))))
			);
		return v.length >= 12 && isNamedSecret(noun.replace(/\s+/g, "_"), `"${v}"`, true);
	};
	// The value is group 2; the noun ends at `nounEnd`.
	const add = (m: RegExpMatchArray, noun: string, nounEnd: number) => {
		const [start] = m.indices![2]!;
		// (The noun is the subject, not a qualifier: `password policy is …`, `password manager is …`, `**Password reset:**
		// <url>`; checked before a passphrase is read on.)
		if (
			/^[ \t]+(?:policy|policies|reset|field|requirements?|rules?|manager|strength|length|hint|prompt|change|expir\w*|history|complexity|recovery|rotation|storage|hash(?:ing)?|form|page|screen|dialog|input|protected|protection|less)\b/i.test(
				text.slice(nounEnd, start),
			)
		)
			return;
		const phrase = /pass|phrase/i.test(noun) ? passphraseEnd(text, start, start + m[2].length) : start;
		if (phrase > start + m[2].length) {
			namedFinding(out, start, phrase, noun.replace(/\s+/g, "_"), "named:prose-label", 0.85);
			return;
		}
		const v = m[2].replace(/[.,;:)]+$/, "");
		if (/^https?:\/\//.test(v) || !accept(noun, v)) return;
		namedFinding(out, start, start + v.length, noun.replace(/\s+/g, "_"), "named:prose-label", 0.85);
	};
	// `<noun> … is|was <value>`: up to 60 characters of the same sentence between them.
	for (const m of text.matchAll(
		new RegExp(
			String.raw`\b(${CRED_NOUN})\b(?:[^.!?\n:=]{0,${SENTENCE_REACH}}?)\b(?:is|was|are|were|reads|remains|stays)\s+(?:now\s+|still\s+|set to\s+|changed to\s+)?${PROSE_VALUE}`,
			"dgi",
		),
	))
		add(m, m[1], m.indices![1]![1]);
	// `using|with|enter the (new) password <value>`.
	for (const m of text.matchAll(
		new RegExp(
			String.raw`\b(?:using|with|via|enter(?:ed)?|type[d]?|use|set|reset (?:it )?to|changed (?:it )?to|try)\s+(?:the |a |an |their |his |her |its |our |my |your )?(?:new |temporary |default |current |updated |initial )?(${CRED_NOUN})\s+${PROSE_VALUE}`,
			"dgi",
		),
	))
		add(m, m[1], m.indices![1]![1]);
	// `set|changed|update the webhook secret to <value>`, `rotate DB_PASSWORD to <value>`.
	for (const m of text.matchAll(
		new RegExp(
			String.raw`\b(?:set|sets|setting|change[ds]?|changing|reset(?:s|ting)?|update[ds]?|updating|rotate[ds]?|rotating)\s+${CRED_PHRASE}\s+(?:to|as)\s+(?:be\s+)?${PROSE_VALUE}`,
			"dgi",
		),
	))
		add(m, m[1], m.indices![1]![1]);
	// `use <value> as the (new) password`: the value before the noun.
	for (const m of text.matchAll(new RegExp(String.raw`\buse[ds]?\s+${PROSE_VALUE}\s+as\s+${CRED_PHRASE}`, "dgi"))) {
		const [start] = m.indices![1]!;
		const v = m[1].replace(/[.,;:)]+$/, "");
		if (accept(m[2], v))
			namedFinding(out, start, start + v.length, m[2].replace(/\s+/g, "_"), "named:prose-label", 0.85);
	}
	// `X's password, <value>, …` (apposition).
	for (const m of text.matchAll(
		new RegExp(String.raw`['’]s\s+(?:new |temporary |current )?(${CRED_NOUN}),\s+${PROSE_VALUE}`, "dgi"),
	))
		add(m, m[1], m.indices![1]![1]);
	// Markdown: `**Password:** v`, `**Password for Access**: v`, `| API Key | v |`.
	for (const m of text.matchAll(
		new RegExp(
			String.raw`\*\*([^*\n]{0,30}\b${CRED_NOUN}\b[^*\n]{0,30}?)[:：]?\*\*[ \t]*[:：]?[ \t]+${PROSE_VALUE}`,
			"dgi",
		),
	)) {
		const noun = labelNoun(m[1]);
		if (m[1].split(/\s+/).length <= 6) add(m, noun[0], m.indices![1]![0] + noun.index + noun[0].length);
	}
	for (const m of text.matchAll(
		new RegExp(
			String.raw`^[ \t]*\|[ \t]*\**([^|\n*]{0,30}\b${CRED_NOUN}\b[^|\n*]{0,30}?)\**[ \t]*\|[ \t]*\x60?${unquotedValue(String.raw`[^|\s\x60]`, 4, String.raw`\x60?[ \t]*\|[ \t]*\r?$`)}`,
			"dgim",
		),
	)) {
		const noun = labelNoun(m[1]);
		if (m[1].trim().split(/\s+/).length <= 6) add(m, noun[0], m.indices![1]![0] + noun.index + noun[0].length);
	}
}

/**
 * The credential noun a label names its value by: its password's, secret's or PIN's when it has one (`API Key Password`
 * names a password), else its last (`Client ID and Secret Key`).
 */
function labelNoun(label: string): RegExpExecArray {
	const nouns = [...label.matchAll(new RegExp(String.raw`\b${CRED_NOUN}\b`, "gi"))];
	return (nouns.find((n) => /pass|secret|pin/i.test(n[0])) ?? nouns.at(-1) ?? CRED_NOUN_IN.exec(label))!;
}

/** "Password" in the languages agents' users write in (and its common inflections). */
const PASSWORD_WORD = `(?:${PASSWORD_SPELLINGS.join("|")})`;
/** A value no identifier, word or hash looks like: letters of both cases, a digit and a symbol, 6 to 64 characters. */
const PASSWORD_SYMBOL = /[!@#$%^&*()+=?~[\]{}<>|]/;
const PASSWORD_SHAPE = new RegExp(
	String.raw`^(?=\S*[a-z])(?=\S*[A-Z])(?=\S*\d)(?=\S*${PASSWORD_SYMBOL.source})[!-~]{6,64}$`,
);

/**
 * A password-shaped value a few characters after a password word, in any language: `логин porfiri16, пароль
 * cOq&8SWy&5`, `Kullanıcı adı onat63, şifre &9OO0u!qxg`, `username debrajohnson and password _ZP8RqQT*2`,
 * `كلمة المرور الحالية للحساب: fOM4pSDb&6`. The shape carries it: case-mixed with a digit and a symbol.
 */
function passwordShaped(text: string, out: Finding[]) {
	if (!PASSWORD_SYMBOL.test(text)) return;
	// (A quoted value is read to its closing quote, and an unquoted one to a blank, its sentence's punctuation cut off
	// after it but a password's own `!` and `?` kept: `Password "Abc1!" is too short`, `the password is Xk9mPq2&Rt7vLw4!`.)
	for (const m of text.matchAll(
		new RegExp(
			String.raw`(?<![\p{L}\d_:/@.-])${PASSWORD_WORD}(?![\p{L}\d_-])[^\n.;!?=]{0,${SENTENCE_REACH}}?[ \t:：](?:(["'\x60])([^\s"'\x60]{1,64})\1|«([^\s»]{1,64})»|\(([^\s)]{1,64})\)|([^\s"'\x60«][!-~]{5,63}))(?=\s|$|[、。，])`,
			"dgiu",
		),
	)) {
		// (Each opener with its own closer, so a quoted password may hold the others: `"Abc)1!"`, `«Mot(de)Passe1»`.)
		const k = [2, 3, 4, 5].find((i) => m[i] !== undefined)!;
		const value = withoutUnopenedClosers(m[k].replace(/[.,;:)]+$/, ""));
		// (A bracket is a symbol a password may hold; a tag, a template's hole, a path of names or an escape is markup's,
		// code's or an encoding's; a pair or a flag with its value, `--pass="$P12Pass"`, the readers' of those.)
		if (
			!PASSWORD_SHAPE.test(value) ||
			/:\/\/|^[\w.-]+@|^-{0,2}[A-Za-z_][\w.-]*=|<\/?[A-Za-z][\w:-]*>|\$\{|\{\{|::|\\["'nrt\\]|"\w*"[:,]/.test(value) ||
			isCode(value, true) ||
			!looksSecret(`"${value}"`, true)
		)
			continue;
		const [start] = m.indices![k]!;
		namedFinding(out, start, start + value.length, "password", "named:password-word", 0.85);
	}
}
