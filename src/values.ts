/**
 * Tests on a value that sits under a credential name: is it a literal secret, or something that only
 * stands in for one (a reference, a template, a placeholder, a mask, code)? Agents read config and
 * code full of `password: ${DB_PASSWORD}` and `api_key = os.environ["KEY"]`; hiding those costs the
 * agent the structure it needs and protects nothing.
 */

import { naturalness } from "./charlm.ts";
import { FOREIGN_PASSWORD_SPELLINGS, isCredentialName } from "./names.ts";
import { base64Binary } from "./base64.ts";
import { isBech32Address } from "./checksums.ts";
import { isPlaceholder, isTruncated } from "./public.ts";
import { isDerCertificate, isDerPublicKey, isDerSignature, isRsaPublicKey } from "./publickeys.ts";
import { isPasswordlessUrl } from "./urls.ts";
import { MAX_VALUE } from "./syntax.ts";
import { decodeEntities } from "./normalize.ts";

/**
 * An identifier, and a member of one as the languages write it: `.`, `?.` (TypeScript, C#, Kotlin), `->` (PHP, C), `::`
 * (Rust, C++, Ruby). One source for every shape below that reads names, so none forgets a language's operator.
 */
const IDENT = String.raw`[A-Za-z_$][\w$]*`;
const MEMBER = String.raw`(?:\??\.|->|::)${IDENT}`;
/** An identifier path: `config.db.password`, `cfg?.pw`, `$this->password`, `Settings::SECRET`. */
export const IDENT_PATH = String.raw`${IDENT}(?:${MEMBER})*`;
/** A path of two links or more, whole. */
const MEMBER_PATH = new RegExp(String.raw`^${IDENT}(?:${MEMBER})+$`);
/**
 * A reference as code writes it: a path, called with names (`decrypt(m_pwd)`), and members of what the call returns
 * (`getPassword().trim()`; reached only through the call, so a path splits one way).
 */
const CREDENTIAL_REFERENCE = new RegExp(
	String.raw`^${IDENT_PATH}(?:\((?:\$?[\w.]+(?:\s*,\s*\$?[\w.]+)*)?\)(?:(?:\??\.|->)${IDENT}(?:\(\))?)*)?$`,
);

/** Strips quotes, a trailing comma or semicolon, and an inline comment from a raw value. */
export function cleanValue(raw: string): string {
	const value = raw.trim().replace(/[,;]$/, "").trim();
	const quoted = value.match(/^(["'`])(.*?)\1(?:\s+#.*)?$/s);
	if (quoted) return quoted[2].replace(/\\(["'\\])/g, "$1");
	return value.replace(/(?<!\s)\s+#.*$/, "").trim();
}

/** What joins the parts of a wordy value: `acme-prod-uploads-2024`, `refs/pull/482/merge`. */
const WORD_SEPARATORS = /[-_./=+:,@ !?]+/;

/**
 * Words, short numbers and short IDs joined by separators: names like `acme-prod-uploads-2024`,
 * `refs/pull/482/merge` or `--max-old-space-size=4096`, not keys.
 */
export function isWordy(value: string): boolean {
	// (Real words or numbers in it, and most of its longer parts words: `F--Cuj=_yu-/`, `yAhcb,anc/NW?` are fragments.)
	const parts = value.split(WORD_SEPARATORS).filter(Boolean);
	const real = (p: string) =>
		/^\d+$/.test(p) || /^(?=[a-f]*\d)[0-9a-f]{6,12}$/i.test(p) || (p.length >= 3 && naturalness(p) > 0.3);
	const long = parts.filter((p) => p.length >= 3);
	if (!parts.some(real) || long.filter(real).length * 3 < long.length * 2) return false;
	return value
		.split(WORD_SEPARATORS)
		.every(
			(part) =>
				part === "" ||
				(/^\p{L}+\d{0,4}$/u.test(part) &&
					!isRandomCase(part) &&
					!(part.length >= 3 && /[A-Z]/.test(part.slice(1)) && /[a-z]/.test(part) && !WORD_CASE.test(part))) ||
				/^[0-9a-f]{1,12}$/i.test(part),
		);
}

/** The longest segment `isNameLike` takes as a name for its length alone. */
const MAX_SHORT_NAME = 4;
/** A short name that is one word, lower, upper or capitalised, then a digit or two: `db`, `API`, `Key`, `s3`, not `Xk9p`. */
const PLAIN_SHORT_NAME = /^(?:[a-z]+|[A-Z]+|[A-Z][a-z]+)\d{0,2}$/;

/**
 * Identifier segments that read as names (a word's case, or short): `md5`, `htmlspecialchars`, `jmat.gId`, not
 * `IWNwpPK.QC.BXh`, nor humps a generator's case flips made (`hqArruGhkoRtvpQplEac`).
 */
export function isNameLike(path: string): boolean {
	const parts = path.split(/[^A-Za-z0-9_]+/).filter(Boolean);
	return (
		parts.length > 0 &&
		parts.every(
			(p) =>
				p.length <= MAX_SHORT_NAME ||
				(!isRandomCase(p) &&
					(WORD_CASE.test(p.replace(/_/g, "")) ||
						/^[a-z_][a-z0-9_]*$|^[A-Z][A-Z0-9_]*$/.test(p) ||
						(/^[A-Z]{0,2}[a-z]+(?:[A-Z][a-z]+)*\d{0,4}$/.test(p) && naturalness(p) > -0.5))),
		)
	);
}

/** A word in brackets that names something: a name, and a plain one when short (`<db password>`, `[API]`; not `[Xk9p]`). */
function isBracketedWord(word: string): boolean {
	return isNameLike(word) && (word.length > MAX_SHORT_NAME || PLAIN_SHORT_NAME.test(word));
}

/** The path of a reference to a secret: every part a name or a number (`secret/data/app`, `projects/123/secrets/db`). */
function isReferencePath(path: string): boolean {
	return path
		.split(/[^A-Za-z0-9_]+/)
		.filter(Boolean)
		.every((p) => /^\d+$/.test(p) || isNameLike(p));
}

/** The cases a word or an identifier comes in: `bucket`, `URL`, `Bucket`, `myBucketName`, `GitHub`, `iPhone`, `OAuth2`. */
const WORD_CASE = /^(?:[a-z]+|[A-Z]+|[A-Z]{0,2}[a-z]+(?:[A-Z][a-z]{2,})*)\d{0,4}$/;

/** Letters whose case flips the way a generator's do, not a word's or an identifier's: `hqArruGHKoRtvpQplEAc`. */
function isRandomCase(part: string): boolean {
	return (
		part.length >= 12 &&
		/[a-z]/.test(part) &&
		(part.slice(1).match(/[A-Z]/g)?.length ?? 0) >= 4 &&
		naturalness(part) < 0.5
	);
}

const PLACEHOLDER_WORDS = new Set([
	"your",
	"my",
	"the",
	"a",
	"an",
	"example",
	"sample",
	"dummy",
	"fake",
	"test",
	"placeholder",
	"replace",
	"replaceme",
	"change",
	"changeme",
	"insert",
	"enter",
	"put",
	"here",
	"this",
	"with",
	"me",
	"make",
	"something",
	"up",
	"whatever",
	"anything",
	"key",
	"api",
	"secret",
	"token",
	"password",
	"pass",
	"value",
	"goes",
	"redacted",
	"hidden",
	"removed",
	"omitted",
	"masked",
	"xxx",
	"todo",
	"fixme",
	"tbd",
	"none",
	"null",
	"empty",
	"default",
	"foo",
	"bar",
	"baz",
	"qux",
	"some",
	"random",
	"string",
	"s3cr3t",
	"secure",
	"strong",
	"real",
	"actual",
	"to",
	"be",
	"set",
	"fill",
	"in",
	"id",
	"access",
	"private",
	"client",
	"auth",
	"user",
	"username",
	"name",
	"db",
	"database",
	"admin",
	"app",
	"service",
	"account",
	"personal",
	"bot",
	"webhook",
	"url",
	"credentials",
	"credential",
	"passphrase",
	"pwd",
	"pw",
	"new",
	"old",
	"generated",
	"own",
	"provided",
]);
const PLACEHOLDER_MARKERS = new Set([
	"your",
	"my",
	"example",
	"sample",
	"dummy",
	"fake",
	"placeholder",
	"replace",
	"replaceme",
	"changeme",
	"insert",
	"enter",
	"here",
	"xxx",
	"todo",
	"fixme",
	"tbd",
	"redacted",
	"hidden",
	"removed",
	"omitted",
	"masked",
	"goes",
	"fill",
]);

/**
 * A PHP variable's name, without its `$`: it reads as words, its capitals few (`loginPass`) or each of its parts in a
 * word's case (`API_Password`); `XkPqWm` is random.
 */
function isPhpVariableName(name: string): boolean {
	return (
		naturalness(name) > 0 &&
		((name.slice(1).match(/[A-Z]/g)?.length ?? 0) <= 2 ||
			name
				.split("_")
				.filter(Boolean)
				.every((part) => WORD_CASE.test(part)))
	);
}

/** A name as a template or a tool writes one: an identifier path whose parts read as names (`db.password`, `DB_PASS`). */
const isRefName = (name: string) => /^[A-Za-z_][\w.:-]*$/.test(name) && isNameLike(name);

/**
 * Shell command substitution, whole or read up to an inner quote: `$(cat f)`, `` `cmd` ``, `$((pass+1))`, `$$(cat f)`
 * (Make), `$(kubectl get secret … -o jsonpath="`; Azure Pipelines' and Make's `$(SqlAdminPassword)` variables. Arithmetic holds names, numbers and operators; a command line
 * starts with a command's name (a word, or a path to one) and then a blank or the end.
 */
function isCommandSubstitution(v: string): boolean {
	const arithmetic = /^\$\$?\(\(([^()]*)\)\)$/.exec(v);
	if (arithmetic) return /^[\w\s+*/%$-]+$/.test(arithmetic[1]) && /[A-Za-z_]/.test(arithmetic[1]);
	const body =
		/^\$\$?\(([\s\S]*)\)$/.exec(v)?.[1] ??
		/^`([^`]{0,400})`$/.exec(v)?.[1] ??
		/^\$\$?\(([A-Za-z][\w.-]{1,30}(?: [^\n]*)?)$/.exec(v)?.[1];
	const command =
		body === undefined
			? undefined
			: /^\s*([A-Za-z_][\w.-]*|(?:\.{0,2}\/)?[\w.-]+(?:\/[\w.-]+)+)(?:\s|$)/.exec(body)?.[1];
	return command !== undefined && command.split("/").every((p) => p === "" || p === "." || p === ".." || isNameLike(p));
}

/** Shapes the printf family writes; see `printf template` below. */
const SPEC = /%[-+ #0]{0,3}(?:\d{1,3}|\*)?(?:\.(?:\d{1,3}|\*))?[sdvxfiu]|%\(\w+\)[sd]|\{\d*\}|\{:\w*\}/g;

/**
 * Shapes of values that can't be credentials, by name: constants, paths, references to a value held elsewhere
 * (variables, templates, secret managers), masks and placeholders, encrypted values, public identifiers.
 * Each shape is whole (closers included, the value nothing but the shape), and the names inside it read as names:
 * a generated password can start with `<`, `{{`, `$(` or `@`, and contain `%d` or `${`. test/values.test.ts runs
 * every shape against generated passwords and keys.
 */
const INERT_SHAPES: [name: string, test: (v: string) => boolean][] = [
	[
		"constant",
		(v) =>
			v === "" ||
			/^(true|false|null|none|nil|undefined|yes|no|on|off|inherit|required|optional|string|str|int|number|bool|boolean|object|any|secret|password|token)$/i.test(
				v,
			),
	],
	["path", isPath],
	// `${NAME}`, `${NAME:-default}`, Spring's `${NAME:default}`, `%{NAME}`, `@{NAME}`, `$NAME`, `%NAME%`; PowerShell's
	// environment, `$env:NAME`, `${env:NAME}`, `$($env:NAME)`. (A default is a value of its own, read by named.ts.)
	[
		"variable",
		(v) => {
			const m = /^[$%@&]\{([\w.-]{1,80})(?:(?::?[-?=+]|:)[^}]{0,80})?\}$/.exec(v);
			const ps = /^\$(?:env:([A-Za-z_]\w{0,80})|\{env:([A-Za-z_]\w{0,80})\}|\(\$env:([A-Za-z_]\w{0,80})\))$/i.exec(v);
			// (A long name reads as words: `$rqcy7duhdjbjv` is a password.)
			const reads = (name: string) => name.length <= 8 || naturalness(name.replace(/[_.-]+/g, " ")) > 0;
			// (Lower case with digits closing it reads as a password: `$summer2024`, not `$db_pass2`.)
			return (
				(!!m && isRefName(m[1])) ||
				(!!ps && isRefName(ps[1] ?? ps[2] ?? ps[3])) ||
				(/^\$(?:[A-Z_][A-Z0-9_]{0,80}|[a-z_][a-z0-9_]{0,80}|\d)$/.test(v) &&
					reads(v.slice(1)) &&
					!/^\$[a-z]+\d{2,}$/.test(v)) ||
				(/^%(?:[A-Z_][A-Z0-9_]{0,80}|[a-z_][a-z0-9_.-]{0,80}|[A-Z][a-z]+(?:[A-Z][a-z]+)*)%$/.test(v) &&
					reads(v.slice(1, -1)))
			);
		},
	],
	// `$loginPass`, `$API_Password`, `{$pwd}`, `$this->passwd`, `{$cfg['db']['pass']}` (mixed case only without digits:
	// `$Secr3t` is a password); run together, as PHP interpolates them: `SIGNATURE=$API_Signature$nvpStr_`.
	[
		"PHP variable",
		(v) =>
			(/^(?:\$[A-Za-z_][A-Za-z_]{0,80}){1,4}$/.test(v) && v.split("$").slice(1).every(isPhpVariableName)) ||
			/^\{\$\w+(?:->\w+|\[[^\]]{1,40}\])*\}$|^\$\w+(?:->\w+)+$/.test(v),
	],
	// `$(cat f)`, `$((pass+1))`, `$$(cat f)` (Make), `` `cmd` ``; or opening with a command's name, read up to an inner
	// quote: `$(kubectl get secret … -o jsonpath="`.
	["command substitution", isCommandSubstitution],
	// `{{ var }}`, `${{ secrets.X }}`, `<%= pw %>`, `#{var}`, `@VAR@` (Maven, Autoconf): whole, a name inside. (Go's
	// templates trim blanks with a `-` inside the braces: `{{- .Values.password -}}`, `{{- end }}`.)
	[
		"template",
		(v) => {
			const m = /^(?:\$?\{\{-?(.{0,200}?)-?\}\}|<%=?([^%]{0,200})%>|#\{([^}]{0,200})\}|@([\w.-]{1,80})@)$/.exec(v);
			if (!m) return false;
			const inner = (m[1] ?? m[2] ?? m[3] ?? m[4]).trim();
			return /^[A-Za-z_@$.]/.test(inner) && isNameLike(inner.split(/[^\w.]/)[0] || "x");
		},
	],
	// `<db password>`, `[TOKEN]`, `{api_key}`: a name in brackets.
	[
		"bracketed name",
		(v) => {
			const m = /^(?:<([\w .-]{1,60})>|\[([\w .-]{1,60})\]|\{([\w.-]{1,60})\})$/.exec(v);
			return (
				!!m &&
				(m[1] ?? m[2] ?? m[3])
					.split(/[ .-]+/)
					.filter(Boolean)
					.every(isBracketedWord)
			);
		},
	],
	// A reference to a secret held elsewhere, as the tools write it: `op://vault/item/field`, `sm://…`, `ref+vault://…`
	// (the scheme's `//`, then a path of names); `vault:secret/data/app#key`, `ssm:/prod/db`, `env:DB_PASS` (a path, or a
	// variable's name in capitals); `arn:aws:secretsmanager:region:account:secret:name`; TeamCity's `credentialsJSON:<uuid>`.
	// (Not a word after a scheme's colon: `env:hunter2`, `op:Passw0rd` are passwords.)
	[
		"secret manager",
		(v) => {
			const m =
				/^(?:(op|sm|gcpsm|awssm|azkv|doppler|infisical|bws|ref\+\w+):\/\/|(vault|keyring|secretsmanager|ssm|env|file):)([\w.@+${}/#:?=&-]{1,200})$/.exec(
					v,
				);
			if (m)
				return (
					isReferencePath(m[3]) &&
					(m[1] !== undefined || m[3].includes("/") || (m[2] === "env" && /^[A-Z_][A-Z0-9_]*$/.test(m[3])))
				);
			return (
				/^credentialsJSON:[0-9a-f-]{36}$/.test(v) ||
				/^arn:aws[\w-]*:(?:secretsmanager|ssm|kms):[a-z0-9-]*:(?:\d{12})?:[\w/:+=.@*${}-]+$/.test(v)
			);
		},
	],
	// `****`, `xxxxxxxx`, `••••`, `[REDACTED]`, `<hidden>`, `ab****yz`; AWX's `$encrypted$`;
	// `xxxx`, `xxx-xxx`, `xxxx1234`, `sk-ant-xxxxx`, `ghp_xxxx` (but `Xxxq7Lm2x` is a password); an elision, `(...)`, `[…]`.
	[
		"mask",
		(v) =>
			(/^(.)\1{2,}$/u.test(v) && /[*x•·#?X0-]/.test(v[0])) ||
			/^(?:\.{3}|…|\(\.{3}\)|\(…\)|\[\.{3}\]|\[…\]|\{\.{3}\}|\{…\}|<\.{3}>|<…>)$/.test(v) ||
			/^\[?(redacted|hidden|masked|filtered|secret|removed|omitted|censored|sanitized|obfuscated|scrubbed|protected|not set|unset|not[ _-]?set|empty)\]?(?:\s+\([^()]{0,20}\))?$/i.test(
				v,
			) ||
			/^\*+[^*\s]{0,6}$/.test(v) ||
			/^[^*\s]{0,6}\*{4,}[^*\s]{0,6}$/.test(v) ||
			v === "$encrypted$" ||
			/^x{3,}(?:[-_.\d]*$|[-_.]x)/i.test(v) ||
			/^[a-z]{1,10}(?:[-_][a-z]{1,10}){0,2}[-_](?:x{4,}|X{4,}|\*{4,}|\.{3,})$/.test(v),
	],
	// An interpolation cut where the reader stopped, at a quote inside it: Ruby `#{ENV['`, `#{node['db'`, JS `${cfg[`.
	[
		"cut interpolation",
		(v) => {
			const m = new RegExp(String.raw`^[#$]\{@{0,2}(${IDENT_PATH})([([](?:["'][\w.-]*["']?)?)?$`).exec(v);
			return !!m && (!!m[2] || m[1].includes(".")) && isNameLike(m[1]);
		},
	],
	// `<?php echo $password ?>`, `<p></p>`, `<dbname>_maint_ps` (a tag that reads as a word, then a name).
	[
		"markup",
		(v) =>
			/^<\?(?:php|=)[\s\S]*\?>$/.test(v) ||
			/^<([a-z][\w-]*)\b[^<>]*>[\s\S]*<\/\1>$/.test(v) ||
			(/^<[a-z][a-z0-9_-]{1,30}>[\w.-]{0,40}$/.test(v) &&
				naturalness(v.slice(1, v.indexOf(">")).replace(/[_-]+/g, " ")) > 0),
	],
	// Other tools' references: YAML tags (`!Ref DbPassword`, `!secret x`, `!ENV ${X}`), a YAML alias (`*default_password`),
	// ARM (`[parameters('adminPassword')]`), Grafana (`$__env{X}`), Hiera (`%{hiera('x')}`, `%{::x}`), Nutanix Calm
	// (`@@{x}@@`), Home Assistant's translations (`[%key:common::config_flow::data::password%]`).
	[
		"tool reference",
		(v) =>
			/^!(?:Ref|GetAtt|Sub|ImportValue|FindInMap|Select|Join|Base64|Cidr|GetAZs|If|Split|secret|env_var|ENV|env|vault|include|input|lambda|Var)\b(?:[ \t]+\S[^\n]{0,200})?$/.test(
				v,
			) ||
			(/^\*[A-Za-z_][\w-]{0,60}$/.test(v) &&
				naturalness(v.slice(1).replace(/[_-]+/g, " ")) > 0.5 &&
				isNameLike(v.slice(1))) ||
			/^\[(?:parameters|variables|reference|concat|format|listKeys|listSecrets|resourceId)\(.*\)\]$/.test(v) ||
			/^\$__(?:env|file|vault)\{[^}\n]{1,200}\}$/.test(v) ||
			/^%\{(?:::)?[A-Za-z_][\w:]*(?:\([^}\n]{0,200}\))?\}$/.test(v) ||
			/^@@\{[^}\n]{1,100}\}@@$/.test(v) ||
			/^\[%key:[\w:]{1,200}%\]$/.test(v),
	],
	// A placeholder after a prefix: `sk.<ask-in-#atlas-dev>`, `ghp_<your token>`; in words: `<from vault: "Android upload keystore">`,
	// `<your-key>`; names in brackets, a path of them too: `<SecretsManager:prod/db>` (not `<Xk9p>`); marked: `change-me`,
	// `your_token`, `KEY_HERE`, `sk-...`, `abc…`.
	[
		"placeholder",
		(v) =>
			/^[\w.-]{0,12}<[a-z][a-z0-9_ #.:/-]{2,40}>$/.test(v) ||
			(/^<[A-Za-z][^<>\n]{0,80}>$/.test(v) &&
				/\s/.test(v) &&
				naturalness(
					v
						.slice(1, -1)
						.replace(/[^A-Za-z]+/g, " ")
						.trim(),
				) > 0.5) ||
			(/^<[A-Za-z][\w .:/-]{0,60}>$/.test(v) &&
				v
					.slice(1, -1)
					.split(/[ .:/-]+/)
					.filter(Boolean)
					.every(isBracketedWord)) ||
			isTruncated(v) ||
			/change[-_ ]?me|^your[-_ ]|_here$|-here$/i.test(v),
	],
	// A template whose literal text is too short or plain to be a secret: `${PREFIX}_db`, `#{user}-key` (formats.ts).
	["template text", (v) => /^[$#]\{/.test(v) && isPlaceholder(v)],
	// `%s/%s.gpg`, `{}:{}`, `%(password)s`, `{0}`. Each specifier stands apart (a boundary or a non-alphanumeric
	// character on one side: `k3%dq7pz` is random; and no letter right after a `%` one: `%silver2024` is a word),
	// and what's left reads as words (`%s/%s.gpg`, not `%v^IqngjRymtGin`).
	[
		"printf template",
		(v) => {
			if (!new RegExp(SPEC.source).test(v)) return false;
			const residue = v.replace(/\\[nrt]/g, " ").replace(SPEC, " ");
			return (
				((residue.match(/[A-Za-z]/g)?.length ?? 0) <= 4 ||
					naturalness(residue.replace(/[^A-Za-z]+/g, " ").trim()) > 0) &&
				residue.split(/[^A-Za-z]+/).every((w) => w.length <= 3 || (naturalness(w) > 0.6 && isNameLike(w))) &&
				v
					.replace(SPEC, "")
					.replace(/\\[nrt]/g, "")
					.replace(/[\w.\-/: ]/g, "").length <= 1 &&
				!(/[A-Z]/.test(v) && /\d/.test(v.replace(/%[sdv]/g, ""))) &&
				[...v.matchAll(SPEC)].every(
					(m) =>
						(!/[A-Za-z0-9]/.test(v[m.index - 1] ?? "") || !/[A-Za-z0-9]/.test(v[m.index + m[0].length] ?? "")) &&
						!(m[0][0] === "%" && /[A-Za-z]/.test(v[m.index + m[0].length] ?? "")),
				)
			);
		},
	],
	["option", (v) => /^--[a-z][a-z0-9]*(?:-[a-z0-9]+)+$/.test(v)], // `--password-stdin`: a flag named, not a value
	// Symfony's environment references, resolved when the configuration loads: `env(RESEND_API_KEY)`, `%env(resolve:DB_URL)%`.
	["environment reference", (v) => /^%?env\((?:[a-z]+:)*[A-Za-z_][\w.]*\)%?$/.test(v)],
	["heredoc marker", (v) => /^<<[-~]?(["']?)[A-Za-z_]\w*\1$/.test(v)], // `<<EOT`: the value is on the lines below
	[
		"escaped variable",
		(v) => /^\$\$(?:[A-Z_][A-Z0-9_]*|[a-z_][a-z0-9_]*|\{\w+\})$/.test(v) && isNameLike(v.replace(/[${}]/g, "")),
	], // docker compose's `$$VAR`
	// `%Y-%m-%dT%H`, `%d/%m/%Y %H:%M:%S`.
	[
		"strftime",
		(v) =>
			(v.match(/%[aAbBcdDeFgGhHIjklmMnpPrRsStTuUVwWxXyYzZ]/g)?.length ?? 0) >= 2 &&
			/^(?:%[aAbBcdDeFgGhHIjklmMnpPrRsStTuUVwWxXyYzZ]|[-:T _/.,])+$/.test(v),
	],
	// A value in an encryption wrapper (ENCRYPTION_WRAPPER), Ansible's `!vault |`, Splunk's `$7$…` (and older `$1$…`: one
	// base64 field, where a crypt hash has a salt and a hash).
	// (Pulumi's passphrase-encrypted values and its stack's salt: `v1:<salt>:v1:<nonce>:<ciphertext>`, `v1:<nonce>:<ciphertext>`.)
	[
		"encrypted",
		(v) =>
			/^\$[17]\$[A-Za-z0-9+/]{16,}={0,2}$/.test(v) ||
			ENCRYPTED_VALUE.test(v) ||
			/^v1:[A-Za-z0-9+/=]{8,}:(?:v1:[A-Za-z0-9+/=]{8,}:)?[A-Za-z0-9+/=]{8,}$/.test(v),
	],
	// What a secret listing shows instead of the value: `16 bytes`, a timestamp, an object repr (`Secret{name=db}`),
	// a relative time (`about 1 month ago`).
	[
		"listing metadata",
		(v) =>
			/^\d+ bytes?$/i.test(v) ||
			/^\d{4}-\d\d-\d\d(?:[T ][\d:.]+(?:Z|[+-]\d\d:?\d\d)?)?$/.test(v) ||
			(/^[A-Za-z_]\w{2,}\{(?:\w+=[\w, :'".-]*)?\}$/.test(v) &&
				naturalness(v.slice(0, v.indexOf("{"))) > 0 &&
				isNameLike(v.slice(0, v.indexOf("{")))) ||
			/^[A-Z][A-Za-z]{2,40}\{[0-9a-f]{6,8}(?:[ }]|$)/.test(v) ||
			/^(?:about |less than |over |almost )?(?:a|an|\d+) (?:second|minute|hour|day|week|month|year)s? ago$/i.test(v),
	],
	// Public identifiers: blockchain addresses and content IDs (`0x…`, bc1…, Qm…/bafy…, npub1…), Twilio SIDs, Windows
	// SIDs and GUIDs in braces (`{a75eafe9-…}`), Firebase app IDs (`1:1234…:web:3f2a…`), IAM statement IDs, email Message-IDs, hex numbers up to 64 bits (`0x3f2a…` in ZooKeeper, addresses in dumps).
	[
		"public identifier",
		(v) =>
			/^0x[0-9a-fA-F]{40}$/.test(v) ||
			(/^(?:bc1|tb1)[02-9ac-hj-np-z]{25,90}$/.test(v) && isBech32Address(v)) ||
			/^Qm[1-9A-HJ-NP-Za-km-z]{44}$/.test(v) ||
			/^bafy[a-z2-7]{50,}$/.test(v) ||
			/^npub1[a-z0-9]{58}$/.test(v) ||
			/^(?:AC|SM|MM|PN|CA|MG|AP|CF|RE|TR|US|IS|PK|WS|WA|WK|EV|QU|XE|NO|IP|CR|BU|CL|FW|KS|NP|PA|PH|PV|RT|SC|SD|SL|TO|TP|VA|VE|ZS)[0-9a-f]{32}$/.test(
				v,
			) ||
			/^S-1-\d+(?:-\d+){1,14}$/.test(v) ||
			/^\{[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\}$/.test(v) ||
			/^\d:\d{6,15}:(?:web|android|ios):[0-9a-f]{16,40}$/.test(v) ||
			/^Stmt\d*$/.test(v) ||
			/^<[\w.$=+%-]{1,200}@[\w.-]{1,200}>$/.test(v) ||
			/^0x[0-9a-fA-F]{1,16}$/.test(v),
	],
	// DER public keys, certificates and signatures in base64, by their structure (publickeys.ts): SPKI (`MIIBIjAN…`,
	// `MCowBQYDK2Vw…`), PKCS #1 (`MIIBCgKC…`), X.509 (`MIIDdzCCAl+gAwIBAgI…`), ECDSA signatures (`MEUCI…`); an SSH public
	// key line, an `age1…` recipient.
	[
		"public key",
		(v) =>
			isDerPublicKey(v) ||
			isRsaPublicKey(v) ||
			isDerCertificate(v) ||
			isDerSignature(v) ||
			isSshPublicKey(v) ||
			/^age1[0-9a-z]{58}$/.test(v),
	],
	// Hardhat/Anvil's first account, BIP-39's `abandon … about` test vectors.
	[
		"published test key",
		(v) =>
			/^(?:0x)?ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80$/i.test(v) ||
			/^(?:test ){11}junk$|^(?:abandon ){11}about$|^(?:abandon ){23}art$/.test(v),
	],
	// Every word a placeholder word, at least one an unmistakable marker: `your-api-key`, `example_token`.
	[
		"placeholder words",
		(v) => {
			const words = v
				.toLowerCase()
				.split(/[-_. ]+/)
				.filter(Boolean);
			return (
				words.length > 0 &&
				words.every((w) => PLACEHOLDER_WORDS.has(w)) &&
				words.some((w) => PLACEHOLDER_MARKERS.has(w))
			);
		},
	],
];

/** An OpenSSH public key line: the key type, a space, base64 that opens with that type (length-prefixed), maybe cut at `...`, and a comment. */
const SSH_KEY_LINE =
	/^(ssh-(?:rsa|dss|ed25519|ed448)|ecdsa-sha2-nistp\d{3}|sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com) ([A-Za-z0-9+/]{8,}={0,2})(?:\.{3}|…)?(?: .*)?$/s;

function isSshPublicKey(v: string): boolean {
	const m = SSH_KEY_LINE.exec(v);
	if (!m) return false;
	// (Whole groups of four characters only; a truncated key is read as far as it goes.)
	const opening = base64Binary(m[2].slice(0, m[2].length - (m[2].length % 4)));
	const expected = `\0\0\0${String.fromCharCode(m[1].length)}${m[1]}`;
	return opening !== undefined && expected.startsWith(opening.slice(0, expected.length));
}

/** Which inert shape a value has (INERT_SHAPES), if any. (Written in markup's escapes, a shape is that shape: `&lt;redacted&gt;`.) */
export function inertShape(value: string): string | undefined {
	// (Read through HTML's entities and a URL's percent-encoding too: `&lt;token&gt;`, `?apikey=%7B%7Bapi_key%7D%7D`.)
	const decoded = value.includes("&") ? decodeEntities(value) : percentDecoded(value);
	return INERT_SHAPES.find(([, test]) => test(value) || (decoded !== value && test(decoded)))?.[0];
}

/** `value` with its percent-encoded bytes decoded, or as it is when it has none or they aren't UTF-8. */
function percentDecoded(value: string): string {
	if (!/%[0-9A-Fa-f]{2}/.test(value)) return value;
	try {
		return decodeURIComponent(value);
	} catch {
		return value;
	}
}

/** A value that can't be a credential: empty, a boolean, a path, a placeholder or a reference to one held elsewhere. */
export function isInert(value: string): boolean {
	return inertShape(value) !== undefined;
}

/** A file path: path-shaped, with no segment that a generator made (`/NKR7uXt0UfYN9/`, `/eB7/ZDoDhDrnTAZWfbkgNMM`). */
export function isPath(path: string): boolean {
	// (A variable in a template's syntax is one too: Puppet's and RPM's `%{KEY}`, read as `${KEY}`.)
	const value = path.replace(/%\{([A-Za-z_]\w*)\}/g, "$${$1}");
	// (Relative, a directory's name then a file's with its extension, in lower case: `vpn/auth.txt`, `certs/dev-key.pem`.
	// Names switch between letters and digits three times at most, `x509v3`; a generator's `a1b2c3d4` more.)
	if (/^[a-z0-9_-]+(?:\/[a-z0-9_.-]+)*\/[a-z0-9_-]+(?:\.[a-z0-9_-]+)*\.[a-z0-9]{1,8}$/.test(value))
		return value.split(/[/._-]/).every((seg) => (seg.match(/[a-z](?=\d)|\d(?=[a-z])/g)?.length ?? 0) <= 3);
	// (Rooted at a variable too: `$HOME/.config`, `$PWD/.kube/config`, `${GITHUB_WORKSPACE}/out`. Braces only around a
	// name, a variable's or a template's: `/srv/{app}/logs`, not `/srv/{4}/x`.)
	if (
		!/^(\.{1,2}\/|~\/|\/|\$\{?[A-Za-z_]\w*\}?\/|[A-Za-z]:\\)[\w.\-/+@${}\\ ]+$/.test(value) ||
		!/[/\\]/.test(value.slice(1)) ||
		/[{}]/.test(value.replace(/\$?\{[A-Za-z_]\w*\}/g, ""))
	)
		return false;
	return !value.split(/[/\\]/).some(isGeneratedSegment);
}

/**
 * A path segment a generator made, not a person: one that mixes cases and digits and is long, isn't a name, or has a
 * symbol no name has (`Tv$-ycX.K9+`); mixed-case letters that read as no word, lower-cased (`ZDoDhDrnTAZWfbkgNMM`:
 * the character model reads each camel-case hump on its own, and random humps often score as words); or a `+`
 * inside mixed-case letters, base64's (`GbeaKB+qGmA+X`; mkcert's `localhost+2-key.pem` is one case, `c++` ends with it).
 */
export function isGeneratedSegment(seg: string): boolean {
	const mixed = /[a-z]/.test(seg) && /[A-Z]/.test(seg);
	if (mixed && /\d/.test(seg) && (seg.length >= 16 || /[$+@ ]/.test(seg) || (seg.length >= 5 && !isNameLike(seg))))
		return true;
	if (mixed && /[A-Za-z0-9]\+[A-Za-z0-9]/.test(seg)) return true;
	return mixed && seg.length >= 6 && !isNameLike(seg) && naturalness(seg.toLowerCase()) < 0.5;
}

/** Abbreviations code names things with, which read as no word to the character model. */
const CODE_WORDS = new Set([
	"ctx",
	"pwd",
	"pw",
	"usr",
	"cfg",
	"env",
	"db",
	"tmp",
	"vm",
	"msg",
	"req",
	"res",
	"err",
	"args",
	"kwargs",
	"opts",
	"obj",
	"src",
	"dst",
	"idx",
	"ptr",
	"buf",
	"str",
	"num",
	"cls",
	"fn",
	"cb",
	"el",
	"js",
	"os",
	"io",
	"id",
	"ui",
	"api",
	"url",
	"uri",
	"jwt",
	"otp",
	"pin",
	"pass",
	"key",
	"md",
	"sha",
	"hex",
	"enc",
	"dec",
	"b",
	"rsa",
	"aes",
	"ecdsa",
	"ec",
	"hmac",
	"jwk",
	"tls",
	"ssl",
	"pem",
	"der",
	"gcm",
	"cbc",
	"ssh",
]);

/** An identifier path with a word in it (`config.password`, `ctx.pw`): code is written in words; `KY4_.XT`, `zpu.KcqEeQfd` are not. */
function hasWord(path: string): boolean {
	return path
		.split(/[^A-Za-z]+|(?<=[a-z])(?=[A-Z])/)
		.some((p) => CODE_WORDS.has(p.toLowerCase()) || (p.length >= 3 && naturalness(p.toLowerCase()) > 0.5));
}

/**
 * Most of a value's letters are in words: its runs of letters (camel-case humps apart) of three or more read as
 * words or as code's abbreviations, and hold two thirds of its letters. `env(DATABASE_URL)`, `CORP\svc_deploy`,
 * `logger.warning(` do; `JujvAIngWfOqw`, `)AM{?NfoSuFiMi.s` don't.
 */
export function readsAsWords(value: string): boolean {
	const letters = value.match(/[A-Za-z]/g)?.length ?? 0;
	return letters > 0 && wordLetters(value, 3) * 3 >= letters * 2;
}

/** How many of a value's letters are in words: runs of letters (camel-case humps apart) of `shortest` or more that read as words, or code's abbreviations. */
function wordLetters(value: string, shortest: number): number {
	const runs = value.match(/[A-Z]+(?![a-z])|[A-Z]?[a-z]+/g) ?? [];
	return runs
		.filter((r) => CODE_WORDS.has(r.toLowerCase()) || (r.length >= shortest && naturalness(r.toLowerCase()) > 0.3))
		.reduce((n, r) => n + r.length, 0);
}

/**
 * A value made of words, run together or joined by `_` or `-` (`required`, `not-set`, `sameorigin`, `Bearer`), as
 * opposed to random letters, which have no digit by chance (`XGxAdcVIefCUMAVsDhkYhErsQwPz`,
 * `kXbQzMwRpLtY-vNcDhJsGfWqZr_mKdTy`): every part of three letters or more reads as a word.
 */
export function isWordsValue(value: string): boolean {
	return (
		/^[a-z]+(?:[_-][a-z]+)*$/i.test(value) &&
		readsAsWords(value) &&
		value.split(/[_-]/).every((p) => p.length < 3 || !isRandomCase(p))
	);
}

/**
 * A token a generator made, by its characters alone: 16 or more of a token's alphabet, with letters, random as the
 * character model reads it lower-cased, and not half words. Hex with digits is one whatever the model reads in its
 * letters (`cafe`, `dead`). Fewer than one random token in two hundred fails this at 16 characters (hex with one
 * letter reads as a number), one in ten thousand at 32; words run together (`reset-password-confirm`, `ProjectSettingsPage`), with numbers in them
 * (`VerifyEmailPage2024.tsx`, `sso-saml-setup-v2`), and a date with a letter in it (`2024-01-15T10-30-00`) pass.
 */
export function isRandomToken(v: string, min = 16): boolean {
	if (v.length < min || !/^[A-Za-z0-9_~=+/.-]+$/.test(v) || !/[A-Za-z][^A-Za-z]*[A-Za-z]/.test(v)) return false;
	if (/^(?=.*\d)(?:[0-9a-f]+|[0-9A-F]+)$/.test(v)) return true;
	return naturalness(v.toLowerCase()) < 0.3 && wordLetters(v, 4) * 2 < v.length;
}

/**
 * A name as people write identifiers: named the way code names things (isNameLike), not mixed-case letters a
 * generator made (isGeneratedSegment), and words to the character model read lower-cased (mixed case alone inflates
 * its score): `changePasswd`, `lPass`, `login-form`; not `AssvKlk`, `cpPygBl`.
 */
function readsAsIdentifier(name: string): boolean {
	return isNameLike(name) && !isGeneratedSegment(name) && naturalness(name.toLowerCase()) > 0.5;
}

/**
 * A credential's name written as an identifier and ending in its credential word (`set_guest_wifi_password`,
 * `DB_PASSWORD`, `githubToken`): a value that names a credential, not one. (Not kebab-case, which passwords are written
 * in too, `test-pass-123`; nor a passphrase in title case, `FluffyBunnyPassword`; nor one that only holds the word,
 * `verde_dev_pw`, `admin_pass1`.)
 */
export function namesCredential(value: string): boolean {
	return (
		/^(?:[a-z][a-z0-9]*(?:_[a-z0-9]+)+|[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+|[a-z]+(?:[A-Z][a-z0-9]+)+)$/.test(value) &&
		/(?:password|passwd|passphrase|secret|token|key)s?$/i.test(value) &&
		isCredentialName(value)
	);
}

/**
 * A version range as package managers write one (`^4.0.0`, `~1.2`, `>=1.2.0 <2`, `1.x || 2.x`), after a protocol
 * (`npm:`, `workspace:`, `patch:`). Each version has an operator or a dot: a bare number is no range.
 */
const VERSION = String.raw`(?:(?:[~^]|[<>]=?|=)v?\d+(?:\.(?:\d+|[xX*])){0,2}|v?\d+(?:\.(?:\d+|[xX*])){1,2})(?:-[\w.]+)?`;
const SEMVER_RANGE = new RegExp(
	String.raw`^(?:(?:npm|workspace|patch|link|portal|file):)?(?:\*|${VERSION}(?:[ \t]*(?:\|\||-|[ \t])[ \t]*${VERSION})*)$`,
);

/** Brackets that close in order: `f(a[0], {b})`, not `Ssaw(53n9DYc!(l7)`. (Quotes aren't tracked.) */
export function isBalanced(s: string): boolean {
	const open: string[] = [];
	for (const c of s) {
		if (c === "(" || c === "[" || c === "{") open.push(c);
		else if (c === ")" || c === "]" || c === "}") if (open.pop() !== { ")": "(", "]": "[", "}": "{" }[c]) return false;
	}
	return open.length === 0;
}

/**
 * Variables and the punctuation between them, nothing literal: `$RANDOM***$RANDOM`, `%RANDOM%@%RANDOM%`, `${*}`.
 * (A bare variable in capitals, after no letter, digit or `$`: `Pa$$WORD`, `P@$SWORD1` keep letters of their own.)
 */
function isExpansionsOnly(v: string): boolean {
	const rest = v.replace(
		/\$\{[^{}]{1,80}\}|(?<![\p{L}\p{N}$])\$[A-Z_][A-Z0-9_]{2,40}(?![\w$])|%[A-Z_][A-Z0-9_]{2,40}%/gu,
		"",
	);
	// (One variable at least: `!@#$%^&*()` is a password of symbols.)
	return rest !== v && !/[\p{L}\p{N}]/u.test(rest);
}

/**
 * Types the languages build in, or their standard libraries and secret wrappers give: Python's and pydantic's (`str`,
 * `Optional`, `Dict`, `SecretStr`), TypeScript's and the platform's (`string`, `Record`, `Uint8Array`, `CryptoKey`), Go's
 * (`byte`, `rune`), Rust's and its crates' (`u8`, `Vec`, `Option`, `SecretString`), Kotlin's, Java's and C#'s (`String`,
 * `CharArray`, `SecureString`).
 */
const BUILT_IN_TYPES = new Set(
	[
		"str bytes bytearray int float bool None NoneType Any object dict list tuple set frozenset Optional Union List Dict",
		"Tuple Set FrozenSet Sequence Mapping MutableMapping Iterable Iterator Callable Literal Annotated Path PathLike",
		"SecretStr SecretBytes",
		"string number boolean bigint symbol null undefined void unknown any never Array ReadonlyArray Record Partial",
		"Readonly Promise Map WeakMap Buffer ArrayBuffer ArrayBufferLike SharedArrayBuffer DataView Uint8Array",
		"Uint8ClampedArray Int8Array Uint16Array Int16Array Uint32Array Int32Array Float32Array Float64Array BigInt64Array",
		"BigUint64Array CryptoKey CryptoKeyPair KeyObject KeyLike",
		"byte rune error uint uint8 uint16 uint32 uint64 int8 int16 int32 int64 float32 float64",
		"u8 u16 u32 u64 u128 usize i8 i16 i32 i64 i128 isize f32 f64 char String Vec Option Result Box Rc Arc Cow HashMap",
		"BTreeMap SecretString SecretBox Zeroizing",
		"Int Long Boolean Double Integer CharArray ByteArray SecureString Nullable",
	]
		.join(" ")
		.split(" "),
);

/**
 * A class whose name ends in a word only types end in: `PasswordField`, `EncryptedStr`, `SecretModel`. (Title-case words
 * ending `String`, `Secret`, `Type` or `Model` are a passphrase too, `LittleSecret`: see isTypeExpression's `classes`.)
 */
const TYPE_CLASS = /^[A-Z]\w*(?:Str|String|Bytes|Field|Type|Secret|Model)$/;

/** A type's token: a lifetime (`'a`), a string literal's type, a name (maybe qualified), a number, punctuation. */
const TYPE_TOKEN =
	/[ \t]*(?:('[a-z_]\w*)(?![\w'])|("[^"\n]{0,40}"|'[^'\n]{0,40}')|([A-Za-z_]\w*(?:(?:\.|::)[A-Za-z_]\w*)*)|(\d{1,6})|(\.\.\.|=>|\[\]|[[\]<>(),|&?!*;:]))/y;

/**
 * A type as a declaration writes one, in Python, TypeScript, Go, Rust, Kotlin, Java or C#: a name, maybe qualified, with
 * its arguments (`Optional[str]`, `Dict[str, Any]`, `Map<String, String>`, `Vec<u8>`) and marks (`string[]`, `String?`,
 * `[]byte`, `*string`, `char*`, `&'a str`, `String!`), in a union (`str | None`, `string | null`; not an intersection,
 * `Path&Ember&winter` is a passphrase), a tuple, a function's type (`() => string`) or a type query (`typeof DEFAULT`).
 * One of its names at least is a type the language builds in, and every other reads as a name:
 * `Optional[PasswordData]` is a type, `Summer|Winter`, `Hunter2!` and `Optional[Xk9mQ2vL]` aren't. With `classes`, a
 * class named as types are (TYPE_CLASS) counts as built in: `"any"` where code is written; `"marked"` in a literal
 * context, where a name alone is a type only by a type's own ending, `SecretStr`, `PasswordField` (`LittleSecret` is a
 * passphrase there, and `Uint8Array` alone may be a password), but `Optional[ClientSecret]` is a type.
 */
export function isTypeExpression(value: string, classes: "none" | "marked" | "any" = "none"): boolean {
	const v = value.trim();
	if (v.length > 200) return false;
	const tokens: string[] = [];
	for (TYPE_TOKEN.lastIndex = 0; TYPE_TOKEN.lastIndex < v.length;) {
		const m = TYPE_TOKEN.exec(v);
		if (!m) return false;
		tokens.push(m[1] ?? m[2] ?? m[3] ?? m[4] ?? m[5]);
	}
	// A recursive descent over the tokens from `i`, collecting the names it reads. (Nesting deeper than 8 isn't read.)
	let i = 0;
	const names: string[] = [];
	// A lifetime or a type query, which only types have.
	let typeOnly = false;
	const eat = (t: string) => {
		if (tokens[i] !== t) return false;
		i++;
		return true;
	};
	const isName = (t: string | undefined) => /^[A-Za-z_]/.test(t ?? "");
	// Types joined by `|`, a union.
	const union = (depth: number): boolean => {
		if (depth > 8) return false;
		eat("|");
		do if (!withMarks(depth)) return false;
		while (eat("|"));
		return true;
	};
	// A type and the marks after it: an array's `[]`, a nullable's `?`, GraphQL's non-null `!`, C's pointer `*`.
	const withMarks = (depth: number): boolean => {
		if (!prefixed(depth)) return false;
		while (eat("[]") || eat("?") || eat("!") || eat("*"));
		return true;
	};
	// A type and the marks before it: a pointer or a reference (`*T`, `&'a mut T`), Go's slice and array (`[]T`,
	// `[32]T`), a keyword (`dyn Error`, `readonly string[]`, `typeof DEFAULT`), Go's map (`map[string]T`).
	const prefixed = (depth: number): boolean => {
		if (eat("*") || eat("[]")) return prefixed(depth + 1);
		if (eat("&")) {
			if (/^'\w/.test(tokens[i] ?? "") && !tokens[i].endsWith("'")) {
				typeOnly = true;
				i++;
			}
			eat("mut");
			return prefixed(depth + 1);
		}
		if (tokens[i] === "[" && /^\d/.test(tokens[i + 1] ?? "") && tokens[i + 2] === "]") {
			i += 3;
			return prefixed(depth + 1);
		}
		if ((tokens[i] === "typeof" || tokens[i] === "keyof") && isName(tokens[i + 1])) {
			typeOnly = true;
			i++;
			return atom(depth + 1);
		}
		if (/^(?:dyn|impl|mut|const|readonly|chan)$/.test(tokens[i] ?? "") && i + 1 < tokens.length) {
			i++;
			return prefixed(depth + 1);
		}
		if (tokens[i] === "map" && tokens[i + 1] === "[") {
			i += 2;
			return union(depth + 1) && eat("]") && prefixed(depth + 1);
		}
		return atom(depth + 1);
	};
	// Types up to the bracket that closes them, separated by commas (Python's `...` among them; Rust's array, `[u8; 32]`).
	const list = (depth: number, close: string): boolean => {
		if (eat(close)) return true;
		do if (!eat("...") && !union(depth)) return false;
		while (eat(","));
		if (eat(";") && !/^\d/.test(tokens[i++] ?? "")) return false;
		return eat(close);
	};
	// A function type's parameters, to the `)`: `a: string, b?: number`.
	const parameters = (depth: number): boolean => {
		if (eat(")")) return true;
		do {
			if (!isName(tokens[i])) return false;
			i++;
			eat("?");
			if (!eat(":") || !union(depth)) return false;
		} while (eat(","));
		return eat(")");
	};
	// A name with its arguments, a type in parentheses, a function's type, a tuple, a string literal's type.
	const atom = (depth: number): boolean => {
		const t = tokens[i++];
		if (t === "(") {
			const from = i;
			if (parameters(depth) && eat("=>")) return union(depth);
			i = from;
			return union(depth) && eat(")");
		}
		if (t === "[") return list(depth, "]");
		if (/^(["']).+\1$/.test(t ?? "")) return true;
		if (!isName(t)) return false;
		names.push(t);
		if (eat("<")) return list(depth, ">");
		if (eat("[")) return list(depth, "]");
		return true;
	};
	if (!union(0) || i !== tokens.length) return false;
	if (classes === "marked" && tokens.length === 1 && !/(?:Str|Bytes|Field)$/.test(tokens[0])) return false;
	const last = (n: string) => n.split(/\.|::/).pop()!;
	// (Built in by its name, maybe from a module in lower case: `typing.Optional`, `std::string`; `Path.Ember.list` is a
	// passphrase.)
	const typeName = (n: string) =>
		(BUILT_IN_TYPES.has(last(n)) && /^(?:[a-z_]\w*(?:\.|::))*\w+$/.test(n)) ||
		(classes !== "none" && TYPE_CLASS.test(n) && readsAsWords(n));
	return (
		(typeOnly || names.some(typeName)) &&
		names.every((n) => typeName(n) || (isNameLike(n) && (n.length <= 2 || readsAsWords(last(n)))))
	);
}

const ENV_LOOKUP =
	/process\.env|os\.environ|getenv|ENV\[|System\.getenv|Environment\.GetEnvironmentVariable|env::var|std::env|Deno\.env|import\.meta\.env|^(config|settings|secrets|params|args|options|opts|self|this|props|ctx|context|req|request|env)\./;

/**
 * Code rather than a literal value: an environment lookup, a call, member access, a variable.
 * Quoted strings are literals, unless built from code. Each shape below is code in any context; in a literal context
 * (`NAME=value` in env, `key: value` in YAML, a CLI flag) only REFERENCES are code besides; elsewhere CODE_ONLY too,
 * where an unquoted lower-case word without digits is taken as a variable (`password = userPassword`; with digits,
 * `PASSWORD=hunter2` in a .env, it's a literal).
 */
export function isCode(raw: string, literal = false): boolean {
	const v = raw.trim().replace(/[;,]$/, "").trim();
	// A quoted string built from variables alone: `"${prefix}${key}"`, `"$RANDOM***$RANDOM"`. (One spliced into code,
	// `"…'".$password."'…"`, is the decision stage's to read, by the quotes around it: policy.ts codeShape.)
	if (/^["'`]/.test(v)) return /^"[^"]*"$/.test(v) && isExpansionsOnly(v.slice(1, -1));
	if (CODE_SHAPES.some(([, test]) => test(v, literal))) return true;
	return (literal ? REFERENCES : CODE_ONLY).some(([, test]) => test(v));
}

/** Links joined by `||`, `&&`, `??`, `or` or `and`; a link an identifier path, `options[:password]`, `self.get_password()`. */
const LINK = String.raw`@?${IDENT}(?:(?:\??\.|->|::)[\w$]+|\[:?[\w'"]+\]|\(\))*`;
const ALTERNATIVES = new RegExp(String.raw`^${LINK}(?:\s*(?:\|\||&&|\?\?)\s*${LINK}|\s+(?:or|and)\s+${LINK})+\)?$`);

/** An operand: an identifier path or a call (its arguments without brackets or quotes), a string, a number. (No run crosses a bracket or a quote, so operands split one way.) */
const OPERAND = String.raw`(?:!?${LINK}(?:\([^()"'\n]{0,200}\))?|"[^"\n]{0,200}"|'[^'\n]{0,200}'|-?\d{1,20}(?:\.\d{1,20})?)`;
/** Operands joined by operators, a ternary's among them. */
const OPERATION = new RegExp(String.raw`^\(?${OPERAND}(?:\s(?:\|\||&&|\?\?|!=|==|->|\?|:|or|and)\s${OPERAND})+\)?$`);
const PY_CONDITIONAL = new RegExp(String.raw`^${OPERAND}\s+if\s+\S[^\n]{0,200}?\s+else\s+${OPERAND}$`);

/**
 * A path subscripted by a key in quotes or a symbol, then more members or subscripts: `parts['password']`,
 * `$row["pwd"]`, `cfg["db"]["pw"]`, `params[:password]`. (Not by a number or a bare word: a password may hold
 * brackets, `Summer[2024]`.)
 */
const KEY_INDEX = String.raw`\[(?:"[\w.-]{1,80}"|'[\w.-]{1,80}'|:[A-Za-z_]\w{0,80})\]`;
const SUBSCRIPT = new RegExp(String.raw`^${IDENT_PATH}${KEY_INDEX}(?:${MEMBER}|${KEY_INDEX})*,?$`);

/** A keyword and what it takes: a constructor's call, an awaited call or member, a module, a function's parameters and body, a lambda. */
const KEYWORD_EXPRESSION = new RegExp(
	String.raw`^(?:new[ \t]+${IDENT_PATH}\(.*\)|await[ \t]+${IDENT_PATH}(?:\(.*\)|${MEMBER})|(?:require|import)\([ \t]*(["'\x60])[^"'\x60\n]+\1[ \t]*\)|(?:function\b[ \t]*[\w$]*|fn)[ \t]*\([^()]*\)[ \t]*(?:\{.*\}|->.+)|lambda\b[^:\n]{0,80}:[ \t]*\S.*)$`,
);

/** Code in any context. */
const CODE_SHAPES: [shape: string, test: (v: string, literal: boolean) => boolean][] = [
	// `generate_password_hash(self.password.data)`, `getenv(KEY, default)`, `getSecret(names[0])`; or a variable quoted,
	// `password('%passwd%')`, `md5("$pw")`.
	[
		"a call whose arguments are names",
		(v) => {
			const m = /^([A-Za-z_][\w.]*)\((.*)\)$/.exec(v);
			return (
				!!m &&
				/[a-z_]$/.test(m[1]) &&
				hasWord(m[1]) &&
				(!m[2].trim() ||
					m[2]
						.split(",")
						.map((a) => a.trim())
						.every(
							(a) =>
								/^[A-Za-z_][\w.]*(?:\(\)|\[\w{1,20}\])?$/.test(a) ||
								(/^(["'`]).+\1$/.test(a) && isInert(a.slice(1, -1))),
						))
			);
		},
	],
	// Go's pointer to a qualified type or a slice of one, `*corev1.Secret`, `[]byte`: no password starts so.
	[
		"a pointer or slice type",
		(v) => /^(?:[*&]|\[\])(?:\[\])*[a-z][a-z0-9]*(?:\.[A-Z][A-Za-z0-9]*)?$/.test(v) && readsAsWords(v),
	],
	// `!local.is_replica`, `var.db_password`, `module.db.password`.
	["a Terraform reference", (v) => /^!?(?:local|var|module|data|each|count|path|terraform)\.[\w.[\]"-]+$/.test(v)],
	[
		"a C cast",
		(v) =>
			/^\((?:const\s+)?(?:unsigned\s+)?(?:char|wchar_t|void|int|uint8_t|u_char|BYTE|LPCSTR|LPSTR|LPWSTR|LPCWSTR|string|String|byte|NSString)\s*\*{0,2}\)?$/.test(
				v,
			),
	],
	// `Get-Content .\\secrets.txt`, `ConvertTo-SecureString $pw -AsPlainText`: the cmdlet, before its arguments (alone,
	// only where code is written: `DB_PASSWORD=Copy-Paste` is a password), or opening a subexpression, which says code
	// anywhere: `-Password (ConvertTo-SecureString`, as a flag's value is cut at its blank.
	[
		"a PowerShell cmdlet",
		(v, literal) => {
			const m =
				/^(\$?\()?((?:Get|Set|New|Remove|ConvertTo|ConvertFrom|Invoke|Start|Stop|Write|Read|Test|Add|Import|Export|Out|Select|Where|ForEach|Format|Join|Split|Resolve|Enter|Exit|Measure|Sort|Group|Update|Register|Enable|Disable|Install|Restart|Wait|Clear|Copy|Move|Rename|Compare|Find|Save|Send|Receive|Connect|Protect|Unprotect)-[A-Z][A-Za-z]+)(?:$|[ \t]+[-$.\\"'A-Za-z])/.exec(
					v,
				);
			return !!m && (!literal || !!m[1] || /[ \t]/.test(v)) && readsAsWords(m[2]);
		},
	],
	// `user != null ? user.password : ""`, `cfg.pw == nil`, `$this -> password` (`or` and `and` only where code is written).
	[
		"an operator between operands",
		(v, literal) => OPERATION.test(v) && (!literal || /\s(?:\|\||&&|\?\?|!=|==|->|\?)\s/.test(v)),
	],
	// `$pw | base64`, `${TOKEN} | jq -r .access_token`.
	["a shell variable piped", (v) => /^\$\{?[A-Za-z_]\w*\}?[ \t]*\|[ \t]*[a-z][\w.-]*(?:[ \t].*)?$/.test(v)],
	// `PasswordField`, `SecretManager2`: a camel-case class name, unquoted in code.
	[
		"a class name",
		(v, literal) =>
			!literal &&
			/^[A-Z][A-Za-z0-9]{2,40}$/.test(v) &&
			/[a-z][A-Z]/.test(v) &&
			naturalness(v) > (/\d/.test(v) ? 0.5 : 1.2),
	],
	["an environment lookup", (v) => ENV_LOOKUP.test(v)],
	// `new Buffer(pw, "base64")`, `await vault.read(path)`, `require("crypto")`, `function () { … }`, `lambda: os.environ["PW"]`:
	// the keyword and the code it takes, whole (`fn(Harbor)2291`, `new moon rising` aren't).
	["a keyword expression", (v) => isBalanced(v) && KEYWORD_EXPRESSION.test(v)],
	// `(await vault.read("db")).data.password`: code in parentheses, and a member of what it gives.
	[
		"a member of an expression",
		(v, literal) => {
			const m = /^\((.+)\)((?:\??\.[A-Za-z_$][\w$]*)+)$/.exec(v);
			return !!m && isBalanced(m[1]) && isNameLike(m[2]) && isCode(m[1], literal);
		},
	],
	// `function password() {`, `async function* gen(a, b)`, a shell function's `() {`: a function's head, its body below.
	[
		"a function's head",
		(v) => /^(?:async[ \t]+)?function\b[ \t]*\*?[ \t]*[\w$]*[ \t]*\([\w$, \t]*\)[ \t]*\{?$|^\(\)[ \t]*\{$/.test(v),
	],
	// `%RANDOM%@%RANDOM%`: variables and the punctuation between them.
	["expansions only", isExpansionsOnly],
	// `quote(pw) if pw else None`: code on either side (a call, a member, a literal), so `rain if sun else snow` isn't.
	["a Python conditional", (v) => PY_CONDITIONAL.test(v) && /[.([\]"']|\b(?:None|True|False)\b/.test(v)],
	// `password: SecretStr`, `db_password: Optional[str]`, `password: string | null;`, `key: &'a [u8],`, `PasswordField`;
	// and where code is written `ClientSecret`, `SecretString`, `PasswordType`. (Alone elsewhere, words in title case
	// ending so are a passphrase: `DB_PASSWORD=LittleSecret`, `The password is: HarborModel`.)
	["a type", (v, literal) => isTypeExpression(v, literal ? "marked" : "any")],
	// `@options.password`.
	["a Ruby member", (v) => /^@[A-Za-z_]\w*(?:\.\w+)+$/.test(v) && isNameLike(v.slice(1))],
	// `@user_password`, unquoted in code.
	["a Ruby instance variable", (v, literal) => !literal && /^@{1,2}[a-z]\w*_\w+\)?$|^@{1,2}[a-z_]\w*\)$/.test(v)],
	// `password||options[:password]||self.get_password`, `dest.password or self.password`: every link an identifier path
	// (and with Python's `or` and `and`, one of them a member path, so a passphrase of words isn't code).
	[
		"an alternatives chain",
		(v) =>
			ALTERNATIVES.test(v) &&
			(!/\s(?:or|and)\s/.test(v) || /\.\w/.test(v)) &&
			v
				.replace(/\)$/, "")
				.split(/\|\||&&|\?\?|\s(?:or|and)\s/)
				.every((p) => isNameLike(p.trim())) &&
			hasWord(v),
	],
	// `t.authorizePassword=t.preAuthorizeImplicit=…` (two links make it code anywhere), its targets names
	// (`xo.n0B46v=AqN=` is base64).
	[
		"a chained assignment",
		(v, literal) =>
			new RegExp(String.raw`^${IDENT}(?:${MEMBER})+=(?!=)`).test(v) &&
			(!literal || new RegExp(String.raw`^${IDENT}(?:${MEMBER})+=${IDENT_PATH}=`).test(v)) &&
			v
				.split("=")
				.slice(0, literal ? 2 : 1)
				.every(isNameLike) &&
			hasWord(v.split("=")[0]),
	],
];

/** An argument of a lookup call: a name or a quoted name. (Commas between them: run together, two names are one.) */
const LOOKUP_ARG = String.raw`[ \t]*(?:"[\w.:/-]{1,80}"|'[\w.:/-]{1,80}'|[A-Za-z_][\w.]{0,80})[ \t]*`;

/** References, code in a literal context too: `$(cat /run/secrets/db)`, `${{ secrets.X }}`, `credentials.value`, `credentials.get('password')`. */
const REFERENCES: [shape: string, test: (v: string) => boolean][] = [
	["a command substitution", (v) => isCommandSubstitution(v)],
	["a workflow expression", (v) => /^\$\{\{.*\}\}$/.test(v)],
	[
		"a member path",
		(v) =>
			MEMBER_PATH.test(v) &&
			!/\d/.test(v) &&
			isNameLike(v) &&
			/^(?:self|this|cls|config|settings|options|opts|params|args|kwargs|request|req|ctx|context|credentials|creds|env|os|process|app|data|user|secrets|auth|form|cfg|conf)\./.test(
				v,
			),
	],
	[
		"a member call",
		(v) =>
			new RegExp(String.raw`^${IDENT}(?:${MEMBER})+\(.*\),?$`).test(v) &&
			isBalanced(v) &&
			hasWord(v.slice(0, v.indexOf("("))),
	],
	// `password: data["password"]`, `pwd: $row['pwd']`, `params[:password]`.
	["a subscript by key", (v) => SUBSCRIPT.test(v)],
	// `EnvVar("SNOWFLAKE_PASSWORD")`, `Secret(name)`: a capitalised call of names (`Summer(2024)` is a password).
	[
		"a lookup call",
		(v) =>
			new RegExp(String.raw`^[A-Z][A-Za-z]{2,40}\(${LOOKUP_ARG}(?:,${LOOKUP_ARG})*,?\),?$`).test(v) &&
			hasWord(v.slice(0, v.indexOf("("))),
	],
];

/** Code only where code is written, not in a literal context. */
const CODE_ONLY: [shape: string, test: (v: string) => boolean][] = [
	// `oauth2.Token`. (A pointer or a slice is code anywhere.)
	["a qualified type", (v) => /^[a-z][a-z0-9]*\.[A-Z][A-Za-z0-9]*$/.test(v) && readsAsWords(v)],
	["a Ruby symbol", (v) => /^:[A-Za-z_]\w*$/.test(v) && isNameLike(v.slice(1))],
	// `password: !prompt.echo,`: a member negated.
	[
		"a negated member",
		(v) => /^!{1,2}[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/.test(v) && readsAsWords(v.replace(/^!+/, "")),
	],
	["a call or a subscript", (v) => new RegExp(String.raw`^${IDENT_PATH}[ \t]*[([]`).test(v)],
	// `config.password`, `mqttConfig?.password`, `template.users.user2.data.password`.
	[
		"member access",
		(v) => MEMBER_PATH.test(v) && (!/\d/.test(v) || /\?\.|(?:\.[A-Za-z_$][\w$]*){2,}/.test(v)) && isNameLike(v),
	],
	// `password: str):`, `token: str) -> None:`.
	["the end of a Python parameter list", (v) => /\)\s*(?:->\s*[\w.[\], |]+)?:$/.test(v)],
	// Member access, calls, generics, operators, statement ends.
	["code's punctuation", (v) => /->|::|[()[\]{}<>;]|\s[-+*/|&?:]{1,2}\s|^\$\w/.test(v)],
	["a variable", (v) => /^[a-z_$][A-Za-z_$]{0,39}$/.test(v) && /[a-z]/.test(v) && (/[A-Z_]/.test(v) || v.length <= 12)],
];

/**
 * Digits in groups, six or more of them, as a PIN or a phone number is written: `4821-7730`, `0171 555 2368`. Under a
 * password's or a PIN's name, that is the password; elsewhere an ID. (`12/12`, `8-64`, `1.2.3` are counts, lengths and
 * versions under any name, and an ISO date is the date a listing shows: `password: 2024-05-01`, when it was set.)
 */
export function isGroupedDigits(value: string): boolean {
	return (
		/^\d{2,8}(?:[-./ ]\d{1,8}){1,4}$/.test(value) &&
		value.replace(/\D/g, "").length >= 6 &&
		!/^(?:19|20)\d\d-\d\d-\d\d$/.test(value)
	);
}

/** The crypt alphabet (`./0-9A-Za-z`), and base64's. */
const C = String.raw`[./A-Za-z0-9]`;
const B64 = String.raw`[A-Za-z0-9+/]`;
/** Modular crypt hashes, `$<id>$…`, each with its salt's and its digest's lengths. */
const CRYPT: [scheme: string, whole: string][] = [
	["bcrypt", String.raw`\$2[abxy]?\$\d\d\$${C}{53}`],
	["MD5-crypt, Apache's", String.raw`\$(?:1|apr1)\$${C}{1,8}\$${C}{22}`],
	[
		"SHA-crypt",
		String.raw`\$5\$(?:rounds=\d{1,9}\$)?${C}{1,16}\$${C}{43}|\$6\$(?:rounds=\d{1,9}\$)?${C}{1,16}\$${C}{86}`,
	],
	["yescrypt, GOST yescrypt", String.raw`\$g?y\$${C}{3,}\$${C}{1,86}\$${C}{43}`],
	["scrypt (libxcrypt)", String.raw`\$7\$${C}{11,}\$${C}{43}`],
	["NT hash", String.raw`\$3\$\$[0-9a-f]{32}`],
	["argon2", String.raw`\$argon2(?:id|i|d)\$(?:v=\d+\$)?m=\d+,t=\d+,p=\d+\$${B64}{11,}\$${B64}{16,}`],
	// (passlib writes its own base64 with `.` for `+`; other libraries write the standard one.)
	[
		"passlib scrypt and pbkdf2",
		String.raw`\$scrypt\$ln=\d+,r=\d+,p=\d+\$[./A-Za-z0-9+]{1,64}\$[./A-Za-z0-9+]{16,}={0,2}|\$pbkdf2(?:-sha\d+)?\$\d+\$[./A-Za-z0-9+]{1,64}\$[./A-Za-z0-9+]{27,}={0,2}`,
	],
	["SHA1-crypt, Sun MD5", String.raw`\$sha1\$\d+\$${C}{1,64}\$${C}{28}|\$md5(?:,rounds=\d+)?\$${C}{1,8}\$\$?${C}{22}`],
	[
		"balloon",
		String.raw`\$BALLOON(?:-SHA256)?\$v=\d+\$[a-z]=\d+(?:,[a-z]=\d+){0,3}\$${B64}{11,}={0,2}\$${B64}{16,}={0,2}`,
	],
];
const CRYPT_HASH = CRYPT.map(([, whole]) => whole).join("|");

/**
 * Password hash formats, each by its whole shape as its software writes it: identifiers, parameters, and a salt and a digest of the lengths it makes (LDAP's
 * scheme in capitals). A password that only starts like one (`$1$Summer$2024`, `md5$Xk9#mP2vQ!&z`, `{SSHA}Xk9#mP2vQ!&z`)
 * isn't one.
 */
const PASSWORD_HASHES: [format: string, whole: string][] = [
	["MySQL", String.raw`\*[0-9A-F]{40}`],
	["Cisco type 8 and 9", String.raw`\$[89]\$${C}{14}\$${C}{43}`],
	["Postgres MD5", String.raw`md5[0-9a-f]{32}`],
	["Postgres SCRAM", String.raw`SCRAM-SHA-256\$\d+:${B64}+={0,2}\$${B64}+={0,2}:${B64}+={0,2}`],
	["crypt(3)", CRYPT_HASH],
	// `pbkdf2_sha256$870000$<salt>$<base64>`, `argon2$argon2id$v=19$m=…$<salt>$<hash>`, `sha1$<salt>$<40 hex>`,
	// `md5$<salt>$<32 hex>`, `bcrypt_sha256$$2b$…`, `scrypt$16384$<salt>$8$1$<base64>`, `crypt$$<DES crypt>`.
	[
		"Django",
		String.raw`pbkdf2_sha\d+\$\d+\$\w{1,64}\$${B64}{27,88}={0,2}|argon2\$argon2(?:id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$${B64}{11,}\$${B64}{16,}|sha1\$\w{1,64}\$[0-9a-f]{40}|md5\$\w{1,64}\$[0-9a-f]{32}|bcrypt(?:_sha256)?\$\$2[aby]\$\d\d\$${C}{53}|scrypt\$\d+\$\w{1,64}\$\d+\$\d+\$${B64}{43,88}={0,2}|crypt\$\$${C}{13}`,
	],
	// `{SSHA}<base64>`, `{PBKDF2-SHA256}<iterations>$<salt>$<hash>`, `{CRYPT}$6$…`, `{BCRYPT}$2b$…`.
	[
		"LDAP",
		String.raw`\{(?:SSHA\d*|SHA\d*|MD5|SMD5)\}${B64}{16,}={0,2}|\{PBKDF2(?:-SHA\d+)?\}\d+\$${C}+\$${C}{16,}|\{(?:CRYPT|ARGON2|BCRYPT)\}(?:${CRYPT_HASH})`,
	],
	// Spring Security's DelegatingPasswordEncoder names the encoder first, `{bcrypt}$2a$10$…`, `{argon2}$argon2id$…`
	// (not `{noop}`, the password itself); Werkzeug's, its method and parameters, `scrypt:32768:8:1$<salt>$<hex>`,
	// `pbkdf2:sha256:600000$<salt>$<hex>`.
	["Spring Security", String.raw`\{(?:bcrypt|argon2)\}(?:${CRYPT_HASH})`],
	["Werkzeug", String.raw`(?:scrypt:\d+:\d+:\d+|pbkdf2:sha\d+(?::\d+)?)\$[A-Za-z0-9]{1,64}\$[0-9a-f]{40,128}`],
];
const HASH_WHOLE = new RegExp(`^(?:${PASSWORD_HASHES.map(([, whole]) => whole).join("|")})$`);

/**
 * Password hashes in text, as a global search: each format's whole shape, every `$` possibly doubled (Compose escapes
 * it: `$$2y$$10$$…`), with no hash character on either side (a full stop after it ends a sentence, unless more hash follows).
 */
export const PASSWORD_HASH_IN_TEXT = new RegExp(
	String.raw`(?<![\w$./+])(?:${PASSWORD_HASHES.map(([, whole]) => whole)
		.join("|")
		.replaceAll(String.raw`\$`, String.raw`\$\$?`)})(?![\w$/+=]|\.[\w$./+=])`,
	"g",
);

/** Password hashes: bcrypt, argon2, scrypt, crypt(3), Django, LDAP. Sensitive, but not a credential anyone can use. */
export function isPasswordHash(value: string): boolean {
	return HASH_WHOLE.test(value);
}

/** Words test suites and docs use as stand-in credentials: `testpass`, `secret123`, `my-api-key`, `abc123`. */
const TEST_WORD =
	/^(?:hoge|fuga|piyo|hogehoge|fugafuga|piyopiyo|hogera|s3krit|s3cr3t|s3cret|secr3t|p4ss|p@ss|p4ssw0rd|passw0rd|p@ssw0rd|test(?:ing)?|secret|secrets|password|passwd|pass|pw|pwd|token|key|api|apikey|my|your|foo|bar|baz|qux|dummy|fake|sample|example|demo|user|mock|stub|value|bearer|auth|access|client|private|super|top|very|valid|invalid|wrong|bad|good|new|old|default|local|dev|one|two|abc|xyz)$/i;
/** At least one of these makes a value a stand-in; `admin2024` or `hunter22` alone could be someone's real password. */
const TEST_MARKER =
	/^(?:hoge|fuga|piyo|hogehoge|fugafuga|piyopiyo|hogera|test(?:ing)?|dummy|fake|sample|example|demo|mock|stub|foo|bar|baz|qux|invalid|wrong|abc|xyz|secret|password|pass|token|key)$/i;

/**
 * Digits as a stand-in writes them: one or two, a count (`123`, `1234`, `6789`) or one digit repeated (`000`). A real
 * password's digits are arbitrary (`Example7392`).
 */
export function isCountingDigits(digits: string): boolean {
	if (digits.length <= 2) return true;
	const step = Number(digits[1]) - Number(digits[0]);
	return (
		(step === 0 || step === 1) && [...digits].every((d, i) => i === 0 || Number(d) - Number(digits[i - 1]) === step)
	);
}

/** A stand-in credential from a test or a doc: only test words and a few digits as a stand-in writes them. */
export function isTestValue(value: string): boolean {
	// (The famous four words joined as a fixture spells one identifier, `correct-horse-battery-staple`. Spaced, as the
	// comic writes them, they are as often someone's passphrase in its style: hidden.)
	if (/^correct[-_.]horse[-_.]battery[-_.]staple$/.test(value)) return true;
	if (/^(?:open ?sesame|hunter2|swordfish|letmein|trustno1|p@ssw0rd|passw0rd|tr0ub4dor&3)$/i.test(value)) return true;
	// `mypassword`, `testpass1`, `thePwd`, `yourpasswordhere`, `StrongPasswordHere`, `secret-key-here`: a placeholder
	// phrase run together.
	if (
		(/^(?:my|your|the|some|test|dummy|fake|example|sample|default|secret|super|strong|new|good|real|actual)[-_]?(?:password|passwd|pass|pwd|pw|secret|token|key|apikey|api[-_]?key)(?:\d{1,4}|[-_]?here)?$/i.test(
			value,
		) &&
			isCountingDigits(/\d*$/.exec(value)![0])) ||
		/(?:^|[-_.])(?:password|secret|token|key)[-_]?here$/i.test(value) ||
		/(?:^|[a-z0-9])(?:Password|Secret|Token|Key)Here$/.test(value)
	)
		return true;
	const parts = value.split(/[-_.: ]+|(?<=[a-z])(?=[A-Z0-9])|(?<=\d)(?=[A-Za-z])/).filter(Boolean);
	return (
		parts.length > 0 &&
		parts.every((p) => TEST_WORD.test(p) || (/^\d{1,4}$/.test(p) && isCountingDigits(p)) || /^[!@#$*]+$/.test(p)) &&
		parts.some((p) => TEST_MARKER.test(p))
	);
}

/**
 * Names built from short parts: `BOB_sect163r2`, `KAS-ECC-CDH_P-256_C14`, `ED448-1-PUBLIC-Raw`, `ALICE_cf_c2pnb368w1`,
 * `us-east-1a`, `login_and_password_removed`. The first part starts with a letter, and every part reads as a name
 * part: short, a number, lower-case hex, a word, an acronym, letters then digits (`amd64`, `SECP521R1`), or a word then
 * a code (`brainpoolP224r1`). Beside a word (`ALICE`, `PUBLIC`), any part of one case with digits is a code
 * (`c2pnb368w1`). A random part mixes cases with digits (`JWPa`, `Xk9mP2`), and a product key's groups are random
 * letters and digits of one length (`VKXQR-8B2MP-7WJ4T`): not names.
 */
export function isIdentifierShaped(value: string): boolean {
	const parts = value.split(/[-_.:]/);
	if (
		parts.length < 2 ||
		!/^[A-Za-z]/.test(parts[0]) ||
		!parts.every((p) => /^[A-Za-z0-9]*$/.test(p)) ||
		isKeyGroups(parts)
	)
		return false;
	const word = parts.some((p) => p.length >= 3 && /^[A-Za-z]+$/.test(p) && naturalness(p.toLowerCase()) > 0.3);
	const named = (p: string) =>
		p.length <= 3 ||
		/^[0-9a-f]+$/.test(p) ||
		/^[A-Z]{2,5}$/.test(p) ||
		/^(?:[a-z]+|[A-Z]+)\d+[A-Za-z]?\d*$/.test(p) ||
		naturalness(p) > 0 ||
		(word && /^(?:[a-z][a-z0-9]*|[A-Z][A-Z0-9]*)$/.test(p));
	const wordThenCode = (p: string) =>
		/^[a-z]{4,}[A-Z0-9][A-Za-z0-9]{0,7}$/.test(p) && naturalness(/^[a-z]+/.exec(p)![0]) > 0.3;
	const random = (p: string) =>
		(/[a-z]/.test(p) && /[A-Z]/.test(p) && /\d/.test(p)) ||
		(/[a-z]/.test(p) && /[A-Z].*[A-Z]/.test(p.slice(1)) && p.length > 6);
	return parts.every((p) => (p.length <= 12 && named(p) && !random(p)) || (p.length <= 16 && wordThenCode(p)));
}

/** A product or licence key's groups: three or more of one length (four or more), random letters and digits, no word among them. */
function isKeyGroups(parts: string[]): boolean {
	if (parts.length < 3 || parts[0].length < 4 || !parts.every((p) => p.length === parts[0].length)) return false;
	return (
		parts.filter((p) => /\d/.test(p) && /[A-Za-z]/.test(p)).length >= 2 &&
		!parts.some((p) => /^[A-Za-z]+$/.test(p) && naturalness(p) > 0.5)
	);
}

/**
 * A Kubernetes pod's name: its workload's name, then the generated suffixes of a ReplicaSet (6–10 characters)
 * and of the pod (5): `ledger-api-58d4f7c9b-rbjl3`, `search-i12seefem-wq3g4`. (A word in the workload's name: its first
 * part may be none, `k8s-agent-…`.)
 */
export function isPodName(value: string): boolean {
	return (
		/^[a-z][a-z0-9]*(?:-[a-z][a-z0-9]*)*-[a-z0-9]{6,10}-[a-z0-9]{5}$/.test(value) &&
		value
			.split("-")
			.slice(0, -2)
			.some((part) => naturalness(part) > 0)
	);
}

/**
 * A lower-case letter, a capital and a digit: the classes a password rule asks for, in a password made of words
 * (`Maple-Orbit-42`, `Harvest2025`) or by a generator (`Xk9mP2vQ7`).
 */
export function hasThreeClasses(value: string): boolean {
	return /[a-z]/.test(value) && /[A-Z]/.test(value) && /\d/.test(value);
}

/** How many of the four character classes a value has: lower case, upper case, digits, symbols. */
function characterClasses(value: string): number {
	return [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9\s]/].filter((r) => r.test(value)).length;
}

/**
 * A password made to a password rule's demands: eight characters or more of three classes, a symbol among them (not
 * only a name's `.` `_` `-`), and neither code nor words: `CANYpfso8s%`, `Harbor2291!`.
 */
export function isMadePassword(value: string): boolean {
	return (
		value.length >= 8 &&
		characterClasses(value) >= 3 &&
		/[^A-Za-z0-9._-]/.test(value) &&
		!isCode(value, true) &&
		naturalness(value) < 1
	);
}

/**
 * Names of algorithms, encodings and formats that sentences about credentials mention: `password (UTF-8)`, `SHA-256`;
 * and password hashers as libraries name them: Django's `pbkdf2_sha256`, `bcrypt_sha256`, passlib's `sha512_crypt`.
 */
export const ALGORITHM =
	/^(?:SHA-?(?:1|224|256|384|512)(?:\/\d{3})?|SHA3-\d{3}|AES-?(?:128|192|256)(?:-[A-Z]{2,4})?|RSA-?(?:1024|2048|3072|4096)|MD[245]|3?DES|HMAC-SHA-?(?:1|256|384|512)|PBKDF2(?:[-_](?:HMAC[-_])?SHA-?(?:1|224|256|384|512))?|(?:md5|sha1|sha256|sha512)_crypt|ECDSA|Ed(?:25519|448)|X(?:25519|448|509)|UTF-?(?:8|16|32)(?:LE|BE)?|UCS-?[24]|PKCS#?(?:1|5|7|8|11|12)|IPv[46]|ChaCha20(?:-Poly1305)?|TLSv?1\.[0-3]|SSLv[23]|ISO-8859-\d{1,2}|Windows-125\d|Latin-?\d|CP\d{3,4}|RFC-?\d{3,5}|base(?:32|58|64)(?:url)?|hex|bcrypt(?:_sha256)?|argon2(?:id|i|d)?|scrypt|\d+-(?:stellig|chiffres|caracteres|digits?|characters?))(?:-(?:encoded|decoded|encrypted))?$/i;
/** A format string's hole: `%d`, `%1$s`, `{0}`, `{{count}}`, `%{n}`. */
const FORMAT_HOLE = /%(?:\d+\$)?[-+ 0#]*\d*(?:\.\d+)?[sdifuxXc@]|\{\{?\s*\w*\s*\}?\}|%\{\w+\}/;

/** "Password" in another language, anywhere in a value. */
const PASSWORD_WORD = new RegExp(FOREIGN_PASSWORD_SPELLINGS.join("|"), "iu");

/** A number with the word that counts in CJK: `6位`, `8文字`, `3回`, `8자`, `2번`. */
export const CJK_COUNT =
	/\d+(?:位|文字|字符?|个|個|次|回|桁|件|名|人|歩|步|秒|分|日|天|月|年|時間|小时|자리?|번|개|회|글자)/u;

/**
 * A password in a script other than Latin: letters with digits or ASCII symbols glued among them (`Солнце2024!`,
 * `密码2024!`, `Зима1240Солнце#Луна`, `ネコ*ラーメン*`), and nothing a UI string has: no blank, no full-width bracket, no CJK
 * punctuation, no format hole, no number counting what follows (`请输入6位密码`, `8文字以上`), and not just a word with
 * a required field's star (`パスワード*`).
 */
function isForeignPassword(v: string): boolean {
	// (The word "password" itself, with no digit, is a label's: `密码*必填`, `パスワード*`.)
	if (PASSWORD_WORD.test(v) && !/\d/.test(v)) return false;
	return (
		!FORMAT_HOLE.test(v) &&
		!/[\s（）【】「」『』〔〕［］｛｝、。，！？：；〜]/u.test(v) &&
		/[\d!@#$%^&*+=?_.~-]/.test(v.replace(/^\*+|\*+$/g, "")) &&
		!CJK_COUNT.test(v)
	);
}

/**
 * Text in a script other than Latin: a label or a sentence (`アクセストークン`, `тот,`, `Введите пароль`, `パスワード*`,
 * `密码错误，还剩%d次机会`, `は変更して下さい。`), unless it is a password in that script. Mostly in that script, or
 * mixed with Latin words and no digit (`パスワード/Password`, `【tomcat-users.xmlで設定したパスワード】`).
 */
function isForeignText(v: string): boolean {
	const foreign = v.match(/(?!\p{Script=Latin})\p{L}/gu)?.length ?? 0;
	// (Mixed with Latin: no digit, and each long Latin run a word, not random letters among the foreign ones.)
	const latinWords = !/\d/.test(v) && (v.match(/\p{Script=Latin}{5,}/gu) ?? []).every((run) => naturalness(run) > 0.3);
	return foreign > 0 && (foreign * 2 >= (v.match(/\p{L}/gu)?.length ?? 0) || latinWords) && !isForeignPassword(v);
}

/**
 * A quantity written with its unit: a ratio (`3.52x`), a price (`~$280`), a test count and its share (`40/42 —
 * 95.2%`). Benign, except under a password's name, where `1337x` and `$4821` are what was chosen. (A PIN's value is
 * digits: named.ts proposes no other.)
 */
export const QUANTITY = /^\d+(?:\.\d+)?x$|^~?[$€£¥]\d[\d,.]*[kKmM]?$|^\d+\/\d+[ \t]*[—–-][ \t]*\d+(?:\.\d+)?%$/;

/** HTML's elements, opened with an attribute or closed: `<input name="password" …>`, `any</span>`, a comment's end. */
const HTML_ELEMENT =
	"a|b|i|p|br|hr|em|li|ol|ul|td|th|tr|h[1-6]|div|span|img|form|input|button|label|select|option|textarea|table|thead|tbody|script|style|link|meta|strong|small|code|pre|iframe|section|header|footer|nav|main|article";
const HTML_MARKUP = new RegExp(
	String.raw`^<(?:${HTML_ELEMENT})(?:\s[^<>]*=[^<>]*)?\/?>|<\/(?:${HTML_ELEMENT})>|\s-->$`,
	"i",
);

/**
 * Bytes percent-encoded, none a letter or a digit, fewer than a key has: a test's `%07%7F`, a URL's `%E2%9C%93` (✓).
 */
function isEscapedSymbols(v: string): boolean {
	const m = /^(?:%[0-9A-Fa-f]{2}){1,12}$/.exec(v);
	return (
		!!m && v.match(/%[0-9A-Fa-f]{2}/g)!.every((e) => !/[0-9A-Za-z]/.test(String.fromCharCode(parseInt(e.slice(1), 16))))
	);
}

/**
 * A package's path, a host and then words: Go's `github.com/hashicorp/go-secure-stdlib/password`. (No piece is long
 * and unreadable, as a webhook's token in `hooks.example.com/<token>` is; at least half read as words.)
 */
function isPackagePath(v: string): boolean {
	const m = /^(?:[a-z0-9-]+\.)+[a-z]{2,}((?:\/[a-z0-9._~-]+)+)$/.exec(v);
	if (!m) return false;
	const pieces = m[1].split(/[/._~-]/).filter(Boolean);
	const words = pieces.filter((w) => naturalness(w) > 0.5).length;
	return words * 2 >= pieces.length && pieces.every((w) => w.length <= 12 || naturalness(w) > 0.5);
}

/**
 * Values that are never a secret, whatever names them and whichever rule read them: counts, ratios and
 * percentages (`12/12`, `98.5%`), ranges (`8-64`), versions (`v2.4.1`), dates and times, algorithm and
 * encoding names, key chords (`ctrl+shift+F12`, `ctrl-p,ctrl-q`), type annotations (`str|None`), cloud regions, the
 * words of a password rule (`min.`, `at least`), and code or markup that a reader can take for a value: regular
 * expressions, package and class paths, IAM actions (`iam:ChangePassword`), XAML bindings, HTML elements, tickets
 * (`[GH-784]`), hash schemes (`md5$`), short escaped or percent-encoded bytes, hex numbers, constants and the brackets
 * after them (`None):`). Every name- and structure-based finding passes this
 * gate (policy.ts keepReason), so a new rule can't bring back an over-redaction another rule already ruled out.
 * Values from secret files and formats don't: there the file or the vendor format says what it is.
 */
export function isBenignValue(value: string): boolean {
	const v = value.trim().replace(/[.,;:!?)]+$/, "");
	return (
		/^\d+(?:[/.:]\d+)+%?$|^\d+(?:\.\d+)?%$/.test(v) || // 12/12, 98.5%, 10:30, 1.2.3.4
		/^\d{1,4}-\d{1,4}$/.test(v) || // 8-64
		/^\d{1,7}[-:]$/.test(value.trim()) || // a listing's line number, `1800-` in grep's context lines
		/^\(?(?:e\.g|i\.e|etc|cf|viz)\.?$/i.test(v) || // an abbreviation, `(e.g`
		QUANTITY.test(v) ||
		// v2.4.1, 1.0.0-rc1, and PEP 440's pre-, post- and dev-releases: 4.12.0b2, 1.1.0rc3, 0.1.dev3, 1.0.post1.
		/^v?\d+(?:\.\d+){1,3}(?:[-.]?(?:a|b|c|rc|alpha|beta|pre|preview|dev|post)\d*)*(?:-(?:alpha|beta|rc|dev|pre)[.\w]*)?$/i.test(
			v,
		) ||
		// Debian and RPM versions, a repack's suffix among them: 3.1.6+~cs8.7.18-1, 1:2.3-4.el9, 1:1.2.11.dfsg-2ubuntu9.2.
		/^(?:\d+:)?\d+(?:\.\d+)+(?:\.[a-z]+\d*)?(?:[-+~][\w.]*)+$/.test(v) ||
		/^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?$/.test(v) || // dates
		ALGORITHM.test(v) ||
		/^(?:(?:ctrl|cmd|alt|shift|meta|option|opt|super|mod|win|control|command)\+)+\S{1,12}$/i.test(v) || // key chords
		// Key chords with `-`, a key's name after them, in a sequence: Docker's `ctrl-p,ctrl-q`, Emacs's `C-x`, an editor's
		// `Down|Ctrl-N`, `Command-Left|Home|Ctrl-A`. (A key named alone, `Home`, only in a list.)
		/^(?:(?:(?:ctrl|cmd|alt|shift|meta|option|opt|super|control|command|[CMS])-)+(?:[a-z0-9@[\]\\^_]|f\d{1,2}|enter|esc|escape|tab|space|up|down|left|right|home|end|delete|del|backspace|pageup|pagedown|insert)(?:[,|]|$))+$/i.test(
			v,
		) ||
		(/\|/.test(v) &&
			/^(?:(?:(?:ctrl|cmd|alt|shift|meta|option|opt|super|control|command)-)*(?:f\d{1,2}|enter|esc|escape|tab|space|up|down|left|right|home|end|delete|del|backspace|pageup|pagedown|insert|[a-z0-9])(?:\||$))+$/i.test(
				v,
			)) ||
		/^\[[A-Z][A-Z0-9]{1,9}-\d{1,6}\]$/.test(v) || // a ticket, `[GH-784]`, `[PROJ-1234]`
		// A constant and the brackets that close its call or literal, read past the value: `password=None):`, `True))[:-2]`;
		// or compared, a ternary's branches after it: `password2==null?password:password2`.
		/^(?:None|True|False|null|nil|undefined)(?:[)\]}][)\]},;:[\]\d-]*|\?[\w$.]+:[\w$.]+[)\]},;]*)$/.test(
			value.trim(),
		) ||
		// A regular expression: a group's construct or a character range, `(?:%s)`, `[a-zA-Z_][a-zA-Z0-9_-]*`.
		/\(\?(?:[:=!]|<[=!])|\[\^?(?:a-z|A-Z|0-9|a-f|A-F|\\[dwsDWS])/.test(v) ||
		/^\{[!-]?[A-Za-z_$][\w$.]*\}\/?>$/.test(value.trim()) || // a JSX attribute's expression with its tag's end, `key={idx}>`
		isPackagePath(v) ||
		// An AWS IAM action: a service, then a verb and what it acts on, `iam:ChangePassword`, `ec2:GetPasswordData`.
		/^[a-z][a-z0-9-]{1,40}:(?:Get|Put|List|Create|Delete|Describe|Update|Set|Change|Reset|Admin|Associate|Disassociate|Attach|Detach|Enable|Disable|Start|Stop|Tag|Untag|Add|Remove|Modify|Invoke|Retrieve|Send|Receive|Register|Deregister|Import|Export|Run|Batch|Decrypt|Encrypt|Generate|Assume|Pass|Rotate|Restore|Copy|Upload|Download|Respond|Confirm|Initiate|Verify|Validate|Accept|Reject|Cancel|Publish|Subscribe|Unsubscribe|Search|Query|Scan|Execute)[A-Z][A-Za-z]*$/.test(
			v,
		) ||
		// A class by its module's path, `allauth.account.forms.SetPasswordForm`.
		/^[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)+\.[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]*)*$/.test(v) ||
		// XAML's markup extensions, `{Binding LightBrush, Mode=OneWay}`, `{StaticResource Brush}`.
		/^\{(?:Binding|MultiBinding|StaticResource|DynamicResource|ThemeResource|TemplateBinding|RelativeSource|x:Static|x:Bind|x:Null|x:Type)\b[^{}]*\}$/.test(
			value.trim(),
		) ||
		/^-?0x[0-9a-f]{1,16}$/i.test(v) || // a number in hex, `-0x3f879678`
		isEscapedSymbols(v) ||
		// Markup: an HTML element, `<input name="password" type="password">`, or text closing one or a comment, `any</span> -->`.
		HTML_MARKUP.test(value.trim()) ||
		/^\$\{\([^()]*\)[^{}]*\}$/.test(v) || // a shell's expansion with flags, zsh's `${(j:-:)words}`
		/^(?:md5|sha1|sha224|sha256|sha384|sha512|bcrypt|bcrypt_sha256|crypt|scrypt|argon2(?:id|i|d)?|pbkdf2_sha\d+|unsalted_\w+)\$+$/.test(
			v,
		) || // a hash's scheme, `password__startswith="md5$"`
		// A type with its punctuation, `str|None`, `Optional[str]`, `string | null;`, or one before its default, read up to
		// the `=`: `password: str=''`, `token: str | None=None`. (A name alone may be a password in a literal context,
		// `password: Uint8Array`: isCode reads one where code is written.)
		(/[^\w\s]/.test(value.trim().replace(/[;,]$/, "")) && isTypeExpression(value.trim().replace(/[ \t]*[=;,]$/, ""))) ||
		// A parameter's type in API docs, with its note: `string (required)`, `boolean (optional)`, `SecureString`.
		/^(?:string|str|integer|int|number|boolean|bool|object|array|list|map|dict|bytes|float|double|long|any|secret|securestring)(?:\s*\((?:required|optional|sensitive|secret|read-only|write-only|default[^()]{0,30})\)?)?$/i.test(
			v,
		) ||
		/^(?:us|eu|ap|sa|ca|me|af|il|cn|mx)-(?:gov-)?(?:north|south|east|west|central|northeast|southeast|northwest|southwest)-\d$|^(?:us|europe|asia|australia|northamerica|southamerica|me|africa)-[a-z]+\d$/.test(
			v,
		) || // regions
		// A version range, with a package manager's protocol: `npm:^4.0.0`, `workspace:*`, `>=1.2.0 <2`, `~1.4 || ^2`.
		SEMVER_RANGE.test(v) ||
		// A length in a password policy: `min 8`, `minimum: 12 characters`, `between 8 and 64`, `max`.
		/^(?:min|max|minimum|maximum|at least|between|up to)(?:\.?[:\s]*\d{1,4}(?:\s*(?:-|and|to)\s*\d{1,4})?(?:\s*(?:chars?|characters|symbols|letters|digits)\.?)?)?$/i.test(
			v,
		) ||
		isForeignText(v) ||
		// SQL and ORM column types, with constraints: `varchar(255)`, `character varying(255) NOT NULL`, `TEXT`.
		/^(?:(?:var)?char(?:acter)?(?:\s+varying)?(?:\(\d+\))?|n?varchar\((?:\d+|max)\)|varchar2\(\d+(?:\s+(?:byte|char))?\)|text|tinytext|mediumtext|longtext|bytea|blob|binary\(\d+\)|varbinary\(\d+\)|string(?:\(\d+\))?)(?:\s+(?:not\s+null|null|unique|default\s+\S+|collate\s+\S+|primary\s+key|character\s+set\s+\S+))*[,;]?$/i.test(
			value.trim(),
		) ||
		// A validation rule list: `required|string|min:8|confirmed`, `required|alpha_num|between:8,64`.
		(/^[a-z_]+(?::[^|]*)?(?:\|[a-z_]+(?::[^|]*)?)+$/.test(v) &&
			/(?:^|\|)(?:required|nullable|string|min|max|between|size|confirmed|regex|alpha\w*|email|unique|sometimes|present|filled|same|different)(?::|\||$)/.test(
				v,
			)) ||
		/^(?:\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|\\u\{[0-9a-f]{1,6}\}|\\[0-7]{3}){1,3}$/i.test(v) || // `"\x41"`: one to three escaped characters
		// Bytes escaped, fewer than a key has: an object identifier's encoding, `"\x2B\x06\x01\x05\x05\x07\x03\x01"`.
		/^(?:\\x[0-9a-f]{2}){4,12}$/i.test(v) ||
		(/^\*+[\p{L} _-]{1,24}\*+$/u.test(v) &&
			v
				.replace(/^\*+|\*+$/g, "")
				.split(/[ _-]+/)
				.filter(Boolean)
				.every((w) => isNameLike(w))) || // `*secret*`, a mask
		// A label from a form or a settings file: words ending in a colon, or words naming the credential
		// they label, capitalized as a label is (`Email password (app-specific password recommended)`).
		// (At most eight words, and the credential word the label's head: a seed phrase holding `secret` isn't one, nor a
		// passphrase in lower case, `purple monkey dishwasher secret`.)
		(/^(?:[?>*•-]\s*)?[\p{L}'’-]+(?:\s+[\p{L}'’()-]+){1,7}$/u.test(value.trim().replace(/[:：]$/, "")) &&
			(/[:：]$/.test(value.trim()) ||
				(/^(?:[?>*•-]\s*)?\p{Lu}/u.test(value.trim()) &&
					/\b(?:password|passphrase|token|secret|api key|pin)(?:\s+(?:setup|settings?|field|prompt|reset|hint|policy|label|placeholder|change|recovery|manager|strength|confirmation|required|missing|expired|invalid|incorrect|page|screen|dialog|form|input))?\s*(?:\([^)]*\))?[:：]?$/i.test(
						value.trim(),
					)))) ||
		// A value built at run time: `Lea5_#{SecureRandom.base58(24)}`, `0x#{key.unpack('H*')[0]}`.
		(/[#$]\{\s*[A-Za-z_@$][\w@$]*(?:\.[A-Za-z_]\w*|\([^(){}]*\)|\[[^\]{}]*\])+\s*\}/.test(v) &&
			v.replace(/[#$]\{[^}]*\}/g, "").length < 8) ||
		(/^\/[A-Za-z][A-Za-z_-]{2,40}$/.test(v) && readsAsIdentifier(v.slice(1))) || // a route: `/changePasswd`
		// A regular expression, as Python's raw string or read out of its quotes with an escape class quantified among its
		// anchors and brackets: `r'-?\d+\.?[0-9A-F]*'`, `^\S{8,}$`, `\w{32}\b`.
		((/^r["'].*["']$/.test(value.trim()) || /\\[dswDSW](?:[*+?]|\{\d+,?\d*\})/.test(v)) &&
			(value.match(/\\[dswDSWbB]|[[\]()*+?{}|^$]/g)?.length ?? 0) >= 4) ||
		(/^[#.][A-Za-z][A-Za-z_-]{2,40}$/.test(v) && readsAsIdentifier(v.slice(1))) // a selector: `#lPass`
	);
}

// (Lower or camel case, as names are written; `Password1`, `Secret24` are how passwords are.)
const CREDENTIAL_PART =
	/^(?:[a-z]{1,3}_|[A-Z]|\w*_)?(?:pass(?:word|wd|w|phrase)?|pwd|pw|secret|token|credentials?|creds)s?\d{0,2}$/;

/**
 * Unquoted code that refers to a credential by name, maybe ending its statement: `account.password`, `m_password;`,
 * `md5($password);`, `secrets.db` (policy.ts, for unquoted values only). (Not a credential's member, `passwords.pop`,
 * `txtPassword.Text`: under an env line's name that may be the password.)
 */
export function isCredentialReference(value: string): boolean {
	const v = value.replace(/;\s*(?:\/\/.*)?$/, "").replace(/,$/, "");
	if (!CREDENTIAL_REFERENCE.test(v) || !isNameLike(v)) return false;
	// A bare word needs a sign it's code: a sigil, a member, a call, a statement end, an underscore prefix (`m_password`).
	if (!/[$.(]|->|::/.test(v) && !/;/.test(value) && !/^[a-z]{1,3}_/.test(v)) return false;
	// The credential is what it names last (`account.password`, `get_password()`, `decrypt(m_pwd)`), or what a container
	// of credentials holds (`credentials.value`, `secrets.db`): `token.Magic144` is a password with a dot in it.
	const parts = v.split(/[^\w]+/).filter(Boolean);
	const credential = (p: string) => CREDENTIAL_PART.test(p) || /[a-z](?:Password|Passwd|Pwd|Secret|Token)s?$/.test(p);
	return (
		credential(parts.at(-1)!) ||
		(/^\$?(?:credentials?|creds|secrets?|vault)$/i.test(parts[0]) && /^[a-z_][a-z0-9_]*$/.test(parts.at(-1)!))
	);
}

/**
 * What an encryption tool writes before its ciphertext: SOPS `ENC[AES256_GCM,data:`, Jasypt `ENC(`, Spring Cloud
 * Config `{cipher}`, Vault's `${VAULT::…::`, IIS configuration encryption `[enc:IISCngProvider:`, DigitalOcean App
 * Platform's `EV[1:<nonce>:`. A value that starts with one (ENCRYPTED_VALUE), or a token right after one (the random
 * layer's `encrypted` veto), is ciphertext, whose key isn't there.
 */
export const ENCRYPTION_WRAPPER = String.raw`ENC\[[A-Z0-9_]+,data:|ENC\(|\{cipher\}|\$\{VAULT::(?:[^:}\s]+::){0,3}|\[enc:\w+:|\bEV\[\d+:(?:[A-Za-z0-9+/=]+:)?`;
// (Jenkins's `hudson.util.Secret`, `{AQAAABAAAA…}`: a version byte and the IV's length, then the IV and the ciphertext.)
const ENCRYPTED_VALUE = new RegExp(
	String.raw`^(?:${ENCRYPTION_WRAPPER}|ENC\[|!vault\b|\$ANSIBLE_VAULT|\{?AQAAABAAAA[A-Za-z0-9+/]{30,}={0,2}\}?$)`,
);

/** Default passwords and words that show up in ordinary output, too common to be anyone's secret. */
export const COMMON_WORDS = new Set([
	"files",
	"systemd",
	"sss",
	"compat",
	"nis",
	"ldap",
	"winbind",
	"changeit",
	"requisite",
	"required",
	"sufficient",
	"fail",
	"failed",
	"failure",
	"success",
	"ok",
	"okay",
	"error",
	"pass",
	"passed",
	"skip",
	"skipped",
	"pending",
	"unknown",
	"ignore",
	"valid",
	"invalid",
	"match",
	"nomatch",
	"enabled",
	"disabled",
	"optional",
	"plain",
	"plaintext",
	"md5",
	"sha1",
	"sha256",
	"scram",
	"blank",
	"empty",
	"unset",
	"trust",
	"reject",
	"peer",
	"ident",
	"basic",
	"digest",
	"bearer",
	"none",
	"auto",
	"manual",
	"prompt",
	"keyring",
	"file",
	"path",
	"stdin",
	"env",
	"vault",
	"password",
	"passwords",
	"passwd",
	"credential",
	"credentials",
	"creds",
	"token",
	"tokens",
	"apikey",
	"passphrase",
	"postgres",
	"postgresql",
	"database",
	"changeme",
	"secret",
	"secrets",
	"admin",
	"administrator",
	"example",
	"mariadb",
	"mongodb",
	"default",
	"development",
	"production",
	"staging",
	"localhost",
	"testing",
	"letmein",
	"welcome",
	"superuser",
	"sqlserver",
	"rabbitmq",
	"minioadmin",
	"keycloak",
	"elastic",
	"grafana",
	"jenkins",
	"vagrant",
	"username",
	"anonymous",
	"readonly",
	"readwrite",
	"internal",
	"external",
	"visible",
	"show",
	"hide",
	"toggle",
	"text",
	"sandbox",
	"guest",
	"root",
	"test",
	"user",
	"demo",
	"public",
	"private",
]);

/**
 * "Password" in another language, as a form's label (i18n files, string resources): `wachtwoord`, `mot de passe
 * actuel`, run together or plural (`Motdepasse`, `Passwörter`, `Contraseñas`), with a word or two around it
 * (`Ubah kata sandi`, "change password"; `Kata sandi inisialisasi admin`) or a note in words after it
 * (`Phrase de passe (facultative)`, `Contraseña (opcional)`).
 */
const PASSWORD_LABEL = new RegExp(
	String.raw`^(?:\p{L}+\s+){0,2}(?:${FOREIGN_PASSWORD_SPELLINGS.map((s) => s.replace(/ /g, "\\s*")).join("|")})(?:s|es|er|en|e)?(?:\s+\p{L}+){0,2}(?:\s*\([\p{L} ,.'’/-]{1,30}\))?\*?$`,
	"iu",
);
const isPasswordLabel = (value: string) => PASSWORD_LABEL.test(value);

/**
 * Whether a value under a credential name is a literal secret worth hiding: not a type, a placeholder,
 * a reference, code, a lone word or a number. (A password hash, and text in another script, are the decision stage's
 * to keep: policy.ts keepReason, isBenignValue.)
 */
export function looksSecret(raw: string, literal = false): boolean {
	const v = cleanValue(raw);
	if (v.length < 4 || v.length > MAX_VALUE || isInert(v) || isCode(raw, literal) || isTestValue(v)) return false;
	if (isPasswordLabel(v)) return false;
	// A list, a call, an object: closed, its items quoted strings, numbers, names or pairs.
	const ITEM = String.raw`(?:"[^"]*"|'[^']*'|-?\d[\d.]*|[A-Za-z_$][\w$.]*(?:\s*[:=]\s*(?:"[^"]*"|'[^']*'|-?\d[\d.]*|[A-Za-z_$][\w$.]*))?)`;
	if (
		/^[[({]/.test(raw.trim()) &&
		isBalanced(raw.trim()) &&
		new RegExp(String.raw`^[\[({]\s*(?:${ITEM}\s*(?:,\s*${ITEM}\s*)*,?)?\s*[\])}][,;]?$`).test(raw.trim())
	)
		return false;
	if (/^[[({<](?:[A-Z][A-Z0-9_]{2,}|[a-z][a-z_ -]{2,})[\])}>]?$/.test(v)) return false; // `[REPMGR_PASSWORD`, `<your token`: a placeholder cut at its bracket
	if (v.length >= 8 && isPlaceholder(v)) return false;
	if (/^\d{1,5}$/.test(v)) return false; // ports, counts, lengths
	if (/^[\w.+-]+@(?:[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,24}|[A-Z0-9-]+(?:\.[A-Z0-9-]+)*\.[A-Z]{2,4})$/.test(v))
		return false; // emails (a domain in one case)
	// Endpoints of other schemes without credentials (`postgres://db.internal/app`) are settings; an http(s) URL goes on,
	// as a path segment of it may be a generated token (webhooks; see isNamedSecret).
	if (isPasswordlessUrl(v) && !/^https?:/i.test(v)) return false;
	if (/^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$/.test(v)) return false; // CONSTANT_NAMES
	if (/^`[A-Z][A-Z0-9_]*`(?:\s*[–-]\s*`[A-Z][A-Z0-9_]*`)?$/.test(v)) return false; // `KEY_F1`–`KEY_F10` in a table
	// (With the sentence's mark after it: `Passwort: root!`.)
	if (/^\p{L}{1,12}[!?.]?$/u.test(v) && COMMON_WORDS.has(v.toLowerCase().replace(/[!?.]$/, ""))) return false;
	return true;
}

/**
 * Analytics, consent, load-balancer and preference cookies: `_ga=GA1.1.35…`, `_gid`, `_fbp`, `AWSALB`, `__cf_bm`,
 * PostHog's `ph_…_posthog`, a locale or a theme. Not a session.
 */
export const ANALYTICS_COOKIE =
	/^(?:AWSALB(?:CORS)?|AWSALBTG(?:CORS)?|ai_user|ai_session|ph_\w+_posthog|_ga\w*|_gid|_gat\w*|_fbp|_fbc|_gcl\w*|_hj\w*|ajs_\w+|amplitude\w*|AMP_\w*|mp_\w+|_clck|_clsk|_uetsid|_uetvid|edgebucket|loid|cookieconsent\w*|consent\w*|OptanonConsent|OptanonAlertBoxClosed|intercom-id-\w+|intercom-device-id-\w+|hubspotutk|__hstc|__hssc|__hssrc|__stripe_mid|__stripe_sid|_pk_\w+(?:\.\w+)*|__cf_bm|_cfuvid|cf_clearance|lang|locale|theme|tz|timezone)$/i;
