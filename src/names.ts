/**
 * What a name says about its value. `DB_PASSWORD` and `client-key-data` hold credentials;
 * `PASSWORD_MIN_LENGTH`, `TOKEN_URL` and `commit_sha` don't. A name is judged by its last meaningful
 * word, the one that says what the value is, after dropping words that only qualify it (`_V2`,
 * `_PROD`) or describe its encoding (`_B64`, `_DATA`).
 */
import { lookup } from "./lookup.ts";
import { IMPORTED_FORMATS } from "./formats-data.ts";

/**
 * "Password" in the languages names, labels and sentences are written in: per language, the word a name holds it with
 * (ASCII, upper case: `DB_WACHTWOORD`), and the spellings labels and prose use, inflections included (`hasła`, `пароля`).
 */
const PASSWORD_LANGUAGES: [name: string | undefined, spellings: string[]][] = [
	["PASSWORD", ["password", "passwords", "passwd", "pwd", "passcode", "passphrase"]],
	["PASSWORT", ["passwort", "passwörter", "zugangspasswort"]],
	["KENNWORT", ["kennwort"]],
	["CONTRASENA", ["contraseña", "contrasena"]],
	["SENHA", ["senha"]],
	["PAROLA", ["parola", "parolă"]],
	["MOTDEPASSE", ["mot de passe"]],
	["HASLO", ["hasło", "hasła", "hasłem"]],
	["HESLO", ["heslo", "hesla", "heslem"]],
	["SALASANA", ["salasana", "salasanan"]],
	["SIFRE", ["şifre", "şifreniz", "şifresi"]],
	["WACHTWOORD", ["wachtwoord"]],
	["WAGWOORD", ["wagwoord"]],
	["LOSENORD", ["lösenord", "losenord"]],
	["ADGANGSKODE", ["adgangskode", "kodeord"]],
	["PASSORD", ["passord"]],
	["PAROL", ["пароль", "пароля", "паролем", "пароли"]],
	["JELSZO", ["jelszó", "jelszava"]],
	["LOZINKA", ["lozinka", "лозинка"]],
	["GESLO", ["geslo"]],
	["PAROOL", ["parool"]],
	["PASAHITZA", ["pasahitza"]],
	["CONTRASINAL", ["contrasinal"]],
	["PASVORTO", ["pasvorto"]],
	["CYFRINAIR", ["cyfrinair"]],
	[
		undefined,
		[
			"palavra-passe",
			"phrase de passe",
			"frase de passe",
			"frase secreta",
			"frase de acceso",
			"frase segreta",
			"parole",
			"slaptažodis",
			"fjalëkalimi",
			"kupuhipa",
			"focal faire",
			"mật khẩu",
			"kata sandi",
			"كلمة المرور",
			"كلمة السر",
			"パスワード",
			"暗証番号",
			"密码",
			"密碼",
			"口令",
			"비밀번호",
			"암호",
			"รหัสผ่าน",
			"סיסמה",
			"κωδικός",
		],
	],
];
/** Every spelling of "password" (PASSWORD_LANGUAGES), and those of languages other than English. */
export const PASSWORD_SPELLINGS = PASSWORD_LANGUAGES.flatMap(([, spellings]) => spellings);
export const FOREIGN_PASSWORD_SPELLINGS = PASSWORD_LANGUAGES.slice(1).flatMap(([, spellings]) => spellings);
/** "Password" as a name's word in each language (`PASSWORT`, `WACHTWOORD`). */
const PASSWORD_NAME_WORDS = PASSWORD_LANGUAGES.flatMap(([name]) => (name ? [name] : []));

/** Words that, as the last word of a name, say the value is a credential. */
const CREDENTIAL_WORDS = new Set([
	"KEY",
	"APIKEY",
	"TOKEN",
	"SECRET",
	"PASSWORD",
	"PASSWD",
	"PASS",
	"PWD",
	"PW",
	"PASSPHRASE",
	"CREDENTIAL",
	"CREDENTIALS",
	"COOKIE",
	"PAT",
	"AUTH",
	"AUTHTOK",
	"PASSKEY",
	"UNSEAL",
	"SALT",
	"SIG",
	"SIGNATURE",
	"PIN",
	"REQUIREPASS",
	"SID",
	"SESSIONID",
	"SESSID",
	"MNEMONIC",
	"SEED",
	"PHRASE",
	"PASSCODE",
	"PSK",
	...PASSWORD_NAME_WORDS,
	"APIKEYS",
	"JWT",
	"BEARER",
	"ACCESSKEY",
	"SECRETKEY",
	"PRIVATEKEY",
	"HMAC",
	"OTP",
	"TOTP",
	"CLIENTSECRET",
	"AUTHORIZATION",
	"XSRF",
	"KEYFILE",
	"CREDS",
	"CRED",
	"SECRETS",
	"PASSWORDS",
	"PASSPHRASES",
	"ACCESSTOKEN",
	"AUTHTOKEN",
	"REFRESHTOKEN",
	"IDTOKEN",
	// (Cloud consoles' abbreviations for an access key and its secret: `AK=…`, `SK=…`.)
	"AK",
	"SK",
]);
/** Single words that end in a credential word: PGPASSWORD, AUTHKEY, WRITEKEY, APITOKEN. */
const CREDENTIAL_SUFFIX =
	/(PASSWORD|PASSWD|PASSPHRASE|PASSCODE|TOKEN|SECRET|APIKEY|AUTH|AUTHKEY|WRITEKEY|READKEY|SECRETKEY|PRIVATEKEY|ACCESSKEY|SESSID|SESSIONID|PASS|PWD|APPKEY|MASTERKEY|SIGNINGKEY|ENCRYPTIONKEY|LICENSEKEY|DEVKEY|USERKEY)$/;
/** Last words that describe a form of the word before: `client-key-data`, `SECRET_B64`, `secret_key_base`. */
const WRAPPER_WORDS = new Set([
	"DATA",
	"VALUE",
	"B64",
	"BASE64",
	"ENC",
	"ENCODED",
	"RAW",
	"HEX",
	"BASE",
	"STRING",
	"STR",
	"TXT",
	"BYTES",
	"PLAIN",
	"PLAINTEXT",
]);
/** Last words that only qualify the word before: `API_KEY_V2`, `DB_PASSWORD_PROD`. */
const QUALIFIER_WORDS =
	/^(V\d+|\d+|PROD|PRODUCTION|DEV|DEVELOPMENT|STAGING|STAGE|TEST|LIVE|OLD|NEW|PREVIOUS|PREV|CURRENT|NEXT|PRIMARY|SECONDARY|BACKUP|FALLBACKS?|ROTATED|LOCAL|REMOTE|DEFAULT|SANDBOX|QA|UAT|INT|EXT|ADMIN|ROOT|MASTER|CONFIRM|CONFIRMATION|AGAIN|REPEAT|VERIFY|VERIFICATION)$/;
/** Words before a credential word that make it public or not a credential at all. */
const NOT_CREDENTIAL_BEFORE = lookup<Set<string>>({
	KEY: new Set([
		"PUBLIC",
		"PUBLISHABLE",
		"SITE",
		"GPG",
		"PGP",
		"PARTITION",
		"SORT",
		"HASH",
		"RANGE",
		"FOREIGN",
		"CACHE",
		"IDEMPOTENCY",
		"OBJECT",
		"TOPOLOGY",
		"SEARCH",
		"SORTING",
		"MAP",
		"SSH",
		"PRIMARY",
		"UNIQUE",
		"COMPOSITE",
		"DICT",
		"ROW",
		"LOOKUP",
		"GROUP",
		"SHARD",
		"ROUTING",
		"DEDUP",
		"DEDUPE",
		"STORAGE",
		"REDIS",
		"S3",
		"BUCKET",
		"REGISTRY",
		"LABEL",
		"ANNOTATION",
		"CONFIG",
		"SETTING",
		"SETTINGS",
		"TRANSLATION",
		"I18N",
		"LOCALE",
		"MESSAGE",
		"STATE",
		"QUERY",
		"SELECTOR",
		"MATCH",
		"FIELD",
		"PROPERTY",
		"ATTR",
		"ATTRIBUTE",
		"ENTRY",
		"ITEM",
		"ELEMENT",
		"NODE",
		"INDEX",
		"COLUMN",
		"TABLE",
		"HOTKEY",
		"SHORTCUT",
		"KEYBOARD",
		"PRESS",
		"ESCAPE",
		"ENTER",
		"MODIFIER",
		"VERIFYING",
		"VERIFICATION",
		"PEER",
		"RECV",
		"RSA",
		"DSA",
		"ECDSA",
		"ED25519",
		"HOST",
		"SERVER",
		"CA",
		"ROOT",
		"TRUSTED",
		"IMPORT",
		"FETCH",
		"LIST",
		"RESTORE",
		"RESTORED",
		"SAVED",
		"MINISIGN",
		"SIGNIFY",
		"EDDSA",
		"EXPERIMENT",
		"RUN",
		"FILE",
		"ASSET",
		"JOB",
		"LOCK",
		"SURROGATE",
		"BLOB",
		"UPLOAD",
		"IMAGE",
		"VIDEO",
		"DOCUMENT",
		"RECORD",
		"PAGE",
		"ENTITY",
		"ATTACHMENT",
		"MEDIA",
		"THUMBNAIL",
		"AVATAR",
		"PHOTO",
		"INSTRUMENTATION",
		"MATCHED",
		"ANALYSIS",
	]),
	TOKEN: new Set([
		"CLIENT",
		"CHANGE",
		"IDEMPOTENCY",
		"REQUEST",
		"STARTING",
		"SKIP",
		"DELTA",
		"RESUMPTION",
		"DEVICE",
		"PUSH",
		"FCM",
		"APNS",
		"NOTIFICATION",
		"CONTINUE",
		"NEXTPAGE",
		"NEXT",
		"PAGE",
		"CONTINUATION",
		"CURSOR",
		"SYNC",
		"RESUME",
		"PAGINATION",
		"MAX",
		"MIN",
		"NUM",
		"COUNT",
		"LEXER",
		"PARSER",
		"CANCELLATION",
		"CANCEL",
		"INPUT",
		"OUTPUT",
		"PROMPT",
		"COMPLETION",
		"TOTAL",
		"LIMIT",
		"STOP",
		"SPECIAL",
		"PAD",
		"EOS",
		"BOS",
		"UNK",
		"SEP",
		"CLS",
		"MASK",
	]),
	SID: new Set([
		"ORACLE",
		"DB",
		"DATABASE",
		"SERVICE",
		"OBJECT",
		"USER",
		"GROUP",
		"SECURITY",
		"DOMAIN",
		"MACHINE",
		"ACCOUNT",
	]),
	SECRET: new Set(["EXISTING", "EXTERNAL"]),
	PIN: new Set(["GPIO", "CERT", "CERTIFICATE", "SSL", "TLS", "PUBLIC", "VERSION"]),
	SEED: new Set([
		"RANDOM",
		"RANDOMLY",
		"RNG",
		"NP",
		"TORCH",
		"NUMPY",
		"DATA",
		"TEST",
		"GLOBAL",
		"SHUFFLE",
		"HASH",
		"PYTHONHASH",
		"FAKER",
		"INITIAL",
		"MANUAL",
		"CUDA",
		"JAX",
		"TF",
	]),
	SIGNATURE: new Set(["METHOD", "FUNCTION", "TYPE", "CALL"]),
	AUTH: new Set([
		"NO",
		"OAUTH",
		"USE",
		"REQUIRE",
		"REQUIRES",
		"ENABLE",
		"SKIP",
		"WITH",
		"ALWAYS",
		"STRICT",
		"NEEDS",
		"HTTP",
		"SASL",
		"LDAP",
		"OIDC",
		"SAML",
		"JWT",
		"TYPE",
	]),
	SALT: new Set(["PUBLIC"]),
});
/** Words that say a value identifies or locates something rather than authenticating. */
const IDENTIFIER_WORDS = new Set([
	"ID",
	"IDS",
	"ARN",
	"URL",
	"URI",
	"HOST",
	"HOSTNAME",
	"DOMAIN",
	"NAME",
	"REGION",
	"ZONE",
	"BUCKET",
	"PRICE",
	"PRODUCT",
	"PLAN",
	"SKU",
	"ENDPOINT",
	"PATH",
	"DIR",
	"FILE",
	"EMAIL",
	"USER",
	"USERNAME",
	"PORT",
	"VERSION",
	"PUBLIC",
	"PUBLISHABLE",
	"SITE",
	"PROJECT",
	"ACCOUNT",
	"TENANT",
	"ORG",
	"TEAM",
	"CHANNEL",
	"STYLE",
	"LOCALE",
	"UUID",
	"GUID",
	"REF",
	"KIND",
	"TYPE",
	"MODE",
	"LABEL",
	"TITLE",
	"IMAGE",
	"ALGORITHM",
	"ALG",
	"FORMAT",
	"LEVEL",
	"STATUS",
	"TIMEOUT",
	"TTL",
	"EXPIRY",
	"EXPIRES",
	"LENGTH",
	"SIZE",
	"COUNT",
	"UID",
	"STATE",
	"GCLID",
	"FBCLID",
	"TTCLID",
	"MSCLKID",
	"DCLID",
	"WBRAID",
	"GBRAID",
	"PLAYBACK",
	"MESSAGEID",
	"MSGID",
	"REFERENCES",
	"INREPLYTO",
	"EXAMPLE",
	"EXAMPLES",
	"X5T",
	"H",
	"INSTRUMENTATIONKEY",
	"SAMPLE",
	"EUI",
	"DEVEUI",
	"APPEUI",
	"JOINEUI",
]);
/** Words that say a value is a hash, a checksum or a content address: random, but published. */
const HASH_WORDS = new Set([
	"SHA",
	"SHA1",
	"SHA256",
	"SHA384",
	"SHA512",
	"SHA224",
	"MD5",
	"HASH",
	"HASHES",
	"DIGEST",
	"CHECKSUM",
	"CHECKSUMS",
	"INTEGRITY",
	"ETAG",
	"COMMIT",
	"REV",
	"REVISION",
	"FINGERPRINT",
	"CRC",
	"CRC32",
	"BLAKE2",
	"BLAKE3",
	"XXHASH",
	"OID",
	"SUM",
	"SHASUM",
	"CID",
	"MULTIHASH",
	"CONTENTHASH",
	"NONCE",
	"CURSOR",
	"RESOURCEVERSION",
	"GENERATION",
	"CHECKPOINT",
	"OBJECTID",
	"TRACE",
	"SPAN",
	"REQUEST",
	"CORRELATION",
	"TRANSACTION",
	"TXN",
	"TX",
	"TXID",
	"TXHASH",
	"BLOCKHASH",
	"ADDRESS",
	"ADDR",
	"PUBKEY",
	"PUBLICKEY",
	"THUMBPRINT",
	"KID",
	"SRI",
	"HMACSHA256",
	"CHALLENGE",
	"PEER",
	"PEERS",
	"SIGNATURES",
	"NONCES",
	"IV",
	"TAG",
	"LINEAGE",
	"SERIAL",
	"ETAGS",
	"VERSIONID",
	"UPLOADID",
]);
/** Tokens that analytics and realtime SDKs put in every browser page: public by design. */
const PUBLIC_NAMES =
	/(?:^|[._-])(?:(?:client|js|browser|frontend|web)[_-]?key|kakao[_-]?(?:js|javascript|native)[_-]?(?:app[_-]?)?key|shopify[_-]?api[_-]?key|naver[_-]?client[_-]?id|mixpanel[_-]?(?:project[_-]?)?token|pusher[_-]?(?:app[_-]?)?key|posthog[_-]?(?:project[_-]?|api[_-]?)?key|amplitude[_-]?api[_-]?key|algolia[_-]?search[_-]?(?:only[_-]?)?(?:api[_-]?)?key|search[_-]?only[_-]?(?:api[_-]?)?key|rzp[_-]?key[_-]?id|razorpay[_-]?key[_-]?id|(?:recaptcha|captcha|turnstile|hcaptcha)[_-]?site[_-]?key|site[_-]?key)$/i;
/** Prefixes of variables that frameworks expose to the browser, so they're public by design. */
const PUBLIC_PREFIX = /^(NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|PUBLIC|NUXT_PUBLIC|GATSBY|VUE_APP|STORYBOOK)_/i;
/**
 * Words anywhere in a name that make it about a credential rather than holding one: UI text
 * (`LABEL_NEW_PASSWORD`, `FORGOT_PASSWORD_TITLE`), error codes (`ERROR_WRONG_PASSWORD`), flags
 * (`HAS_PASSWORD`, `REQUIRE_AUTH`) and settings (`PASSWORD_MIN_LENGTH` is caught by its last word).
 */
const ABOUT_WORDS = new Set([
	"LABEL",
	"LABELS",
	"TITLE",
	"MSG",
	"MESSAGE",
	"MESSAGES",
	"TEXT",
	"HINT",
	"PROMPT",
	"PLACEHOLDER",
	"TOOLTIP",
	"BUTTON",
	"BTN",
	"ERROR",
	"ERRORS",
	"ERR",
	"STATUS",
	"FORGOT",
	"FORGOTTEN",
	"MANDATORY",
	"INVALID",
	"WRONG",
	"BAD",
	"MISSING",
	"REQUIRED",
	"NO",
	"NULL",
	"HAS",
	"IS",
	"SHOW",
	"HIDE",
	"ENABLE",
	"ENABLED",
	"DISABLE",
	"DISABLED",
	"ALLOW",
	"USE",
	"REQUIRE",
	"REQUIRES",
	"VALIDATE",
	"VALIDATION",
	"VALIDATOR",
	"POLICY",
	"RULE",
	"RULES",
	"ICON",
	"I18N",
	"TRANSLATION",
	"DESCRIPTION",
	"DESC",
	"HELP",
	"EXPIRED",
	"EXPIRY",
	"LENGTH",
	"MIN",
	"MAX",
	"STRENGTH",
	"WEAK",
	"CAPTION",
	"HEADING",
	"INSTRUCTIONS",
	"NOTICE",
	"WARNING",
	"SUCCESS",
	"FAIL",
	"FAILED",
	"FAILURE",
	"MISMATCH",
	"MATCH",
	"CHANGED",
	"RESET",
	"EMPTY",
	"TOGGLE",
	"VISIBILITY",
	"VISIBLE",
	"DIALOG",
	"MODAL",
	"PAGE",
	"SCREEN",
	"ROUTE",
	"VIEW",
	"EVENT",
	"HANDLER",
	"PATTERN",
	"REGEX",
	"HASHER",
	"HASHED",
	"HASHING",
	"ENCODER",
]);
/** About words that can also say what a credential belongs to. */
const ROUTE_WORDS = new Set(["PAGE", "SCREEN", "ROUTE", "VIEW", "EVENT", "HANDLER", "DIALOG", "MODAL", "STATUS"]);
/**
 * Shell variables whose names end in a credential word but hold something else (`PWD`, `OLDPWD`),
 * bare upper-case `KEY` and `AUTH` (loop keys, auth modes) and `PASS`, `XPASS` (`PASS: test name`, a test runner's
 * verdicts; named.ts still reads `PASS=value`).
 */
const NOT_CREDENTIAL_NAMES = new Set(["PWD", "OLDPWD", "AUTH", "KEY", "PASS", "XPASS"]);

/** The words of a name in upper case: `clientSecret` → CLIENT, SECRET; `x-api-key` → X, API, KEY. */
export function words(name: string): string[] {
	// (Accents dropped first, so `contraseña` is CONTRASENA and `hasło` HASLO, as CREDENTIAL_WORDS spells them.)
	return name
		.normalize("NFD")
		.replace(/\p{M}/gu, "")
		.replace(/ł/gi, (c) => (c === "ł" ? "l" : "L"))
		.replace(/([a-z0-9])([A-Z])/g, "$1_$2")
		.replace(/([A-Z])([A-Z][a-z])/g, "$1_$2")
		.toUpperCase()
		.split(/[^\p{L}\p{N}]+/u)
		.filter(Boolean);
}

/**
 * A web session's ID, its bearer credential: `session_id`, `sessionId`, `X-Session-Id`, `auth_session_id`. Not a
 * terminal's (`TERM_SESSION_ID`), a TLS session's (openssl prints `Session-ID:`, in that case) or an audit log's
 * (`externalSessionId`). And the session cookies of PHP, Express, Google, Laravel, Rails, ASP.NET and GitHub
 * (`PHPSESSID`, `connect.sid`, `SAPISID`, `__Secure-1PSID`, `laravel_session`, `grafana_session`, Rails'
 * `_myapp_session`, `_session_id`, `ASP.NET_SessionId`, `_gh_sess`; not a terminal's or a desktop's, `tmux_session`).
 */
const SESSION_COOKIE =
	/^_?(?!(?:tmux|screen|zellij|byobu|desktop|xdg|ssh|term|dbus|shell|login|vnc|x11)_)[a-z][a-z0-9]*_session$|^_session_id$|^ASP\.NET_SessionId$|^_gh_sess$/;
const SESSION_ID =
	/^(?:x-)?(?:auth[_-]|user[_-]|web[_-]|app[_-])?(?:session|sess)[_-]?id$|^(?:auth|user|web|app)?[sS]essionId$|^(?:php)?sessid$|^connect\.sid$|^(?:__Secure-[13]P)?(?:SID|HSID|APISID|SAPISID|OSID|LSID|SIDTS|SIDCC)$/i;
const isSessionIdName = (name: string): boolean =>
	(name !== "Session-ID" && SESSION_ID.test(name)) || SESSION_COOKIE.test(name);

/**
 * The owners of sessions that are no web login: a terminal's, a desktop's, a remote shell's (`ITERM_SESSION_ID`,
 * `WT_SESSION`, `XDG_SESSION_ID`, `DESKTOP_SESSION`), as an environment's listing shows them.
 */
const LOCAL_SESSION_OWNERS = new Set([
	"TMUX",
	"SCREEN",
	"ZELLIJ",
	"BYOBU",
	"DESKTOP",
	"XDG",
	"SSH",
	"TERM",
	"ITERM",
	"TERMINAL",
	"WT",
	"KITTY",
	"WEZTERM",
	"KONSOLE",
	"DBUS",
	"SHELL",
	"LOGIN",
	"VNC",
	"X11",
]);

/**
 * Whether a name names a session or its ID, whoever's session it is: `INSTAGRAM_SESSION_ID`, `LINKEDIN_SESSION`,
 * `tiktokSessionId`; not a terminal's or a desktop's (LOCAL_SESSION_OWNERS). Read so only in a secret file, which says
 * its values are secrets: elsewhere a session's ID under another's name is as often a checkout's or an agent's
 * (`CHECKOUT_SESSION_ID`, `CLAUDE_SESSION_ID`), and only the names isSessionIdName knows are credentials.
 */
export function namesSession(name: string): boolean {
	const w = words(name);
	if (w.at(-1) === "ID") w.pop();
	return /^(?:SESSION|SESSIONID|SESS|SESSID)$/.test(w.at(-1) ?? "") && !w.some((x) => LOCAL_SESSION_OWNERS.has(x));
}

/**
 * Bundler's setting for a gem server's credentials, named by its host (`.` written `__`, `-` `___`):
 * `BUNDLE_GEMS__CONTRIBSYS__COM`, `BUNDLE_RUBYGEMS__PKG__GITHUB__COM`. Its value is `user:password` or a token. Not
 * Bundler's own settings that take a gem's or a URL's name the same way (`BUNDLE_BUILD__NOKOGIRI`, `BUNDLE_LOCAL__RACK`,
 * `BUNDLE_MIRROR__…`, `BUNDLE_GEM__TEST`).
 */
function isBundlerHostName(name: string): boolean {
	return /^BUNDLE_(?!(?:BUILD|LOCAL|MIRROR|GEM)__)[A-Z0-9]+(?:_{2,3}[A-Z0-9]+)*__[A-Z]{2,6}$/.test(name);
}

/**
 * Data files' extensions: as a key, a data file's name maps to its checksum (`"data.csv": "<sha256>"` in a lockfile or a
 * registry). A config file's name maps to its contents (a Kubernetes Secret's `config.yaml`, `default_user.conf`).
 */
const DATA_FILE =
	/^[\w.-]{1,80}\.(?:csv|json|txt|tar|gz|tgz|zip|whl|jar|js|css|py|so|dll|exe|bin|dat|h5|nc|parquet|pkl|pt|onnx|png|jpg|svg|wasm|xz|bz2|deb|rpm)$/i;
/** File names' extensions, so a file name that holds a credential word (`has_key_spec.rb`) isn't one; never a qualifier (`.prod`, `.old`, `.value`, `.test`). */
export const FILE_EXTENSION =
	/\.(?:csv|json|txt|vue|svelte|tar|gz|tgz|zip|whl|jar|js|mjs|cjs|ts|tsx|jsx|css|scss|py|pyc|rb|erb|pp|epp|go|rs|java|kt|swift|php|cs|c|h|cc|cpp|hpp|so|dll|exe|bin|dat|h5|nc|parquet|pkl|pt|onnx|png|jpg|jpeg|gif|svg|ico|wasm|xz|bz2|deb|rpm|yml|yaml|toml|ini|cfg|conf|md|rst|html|xml|sh|bash|ps1|lock|log|sql|tf|proto)$/i;
/** A file's name or path as a name (`spec/has_key_spec.rb`, `manifests/key.pp`): its words name the file, not a credential. */
const isFileName = (name: string) => FILE_EXTENSION.test(name) && /^[\w./-]+$/.test(name);

/**
 * A name that says its value is public: an SDK's public key by name (`MIXPANEL_TOKEN`, `client_key`), a browser
 * prefix or a public word (`NEXT_PUBLIC_MAPS_KEY`, `STRIPE_PUBLISHABLE_KEY`, `SITE_KEY`, `VAPID_KEY`). A secret's
 * word, or any credential's but a key's or a token's, says what the value is and wins (`EXPO_PUBLIC_STRIPE_SECRET_KEY`,
 * `NEXT_PUBLIC_DB_PASSWORD`, `PUBLIC_SUPABASE_SERVICE_ROLE_KEY`, `VAPID_SECRET`, `VITE_MNEMONIC`, `VITE_SENTRY_AUTH`);
 * a prefix or a public word before a token's name keeps it a token (`PUBLIC_API_TOKEN`): only keys and IDs are
 * shipped to browsers by design.
 */
function isPublicName(name: string, w: string[]): boolean {
	// (Before the SDK names: `PRIVATE_CLIENT_KEY`, `SECRET_SITE_KEY`; and an mTLS pair's private half, `tls_client_key`.)
	if (
		w.some(
			(x) =>
				/^(?:PRIVATE|SERVICE|ADMIN|MASTER|TLS|SSL|MTLS)$/.test(x) ||
				(isCredentialWord(x) && !/^(?:KEY|APIKEY|TOKEN)S?$/.test(x)),
		)
	)
		return false;
	// (By the name and without its qualifiers: `MIXPANEL_TOKEN_PROD` is `MIXPANEL_TOKEN`'s. Not without a wrapper word:
	// kubeconfig's `client-key-data` is a private key.)
	const unqualified = unqualifiedName(name);
	if (PUBLIC_NAMES.test(name) || PUBLIC_NAMES.test(unqualified) || /^application_?server_?key$/i.test(unqualified))
		return true;
	// (A token is public only when its own name says so: `MAPBOX_PUBLIC_TOKEN`, not `NEXT_PUBLIC_SANITY_TOKEN`.)
	if (/^TOKENS?$/.test(w.at(-1) ?? ""))
		return w
			.slice(PUBLIC_PREFIX.test(name) ? PUBLIC_PREFIX.exec(name)![1].split("_").length : 0)
			.some((x) => x === "PUBLIC" || x === "PUBLISHABLE");
	// (`PUB` abbreviates public before a key: `pubKey`, `PUB_KEY`; `SITE` and `VAPID` keys are public by design.)
	return (
		PUBLIC_PREFIX.test(name) ||
		w.some(
			(x) =>
				x === "PUBLIC" ||
				x === "PUBLISHABLE" ||
				x === "PUBKEY" ||
				x === "PUBLICKEY" ||
				((x === "SITE" || x === "VAPID" || x === "PUB") && /^KEY\d*$/.test(w.at(-1)!) && w.at(-2) === x),
		)
	);
}

// (Not vendors whose name is also a word or a thing in code: `cursor=` paginates, `checkout`, `linear`, `sentry` DSNs are public.)
const NOT_VENDOR_NAMES = new Set([
	"apollo",
	"beamer",
	"checkout",
	"cisco",
	"clerk",
	"crates",
	"cursor",
	"defined",
	"hunter",
	"instantly",
	"kraken",
	"lark",
	"linear",
	"looker",
	"monday",
	"plaid",
	"rainforest",
	"retell",
	"sentry",
	"sonar",
	"stability",
	"telegram",
	"twitter",
	"weights",
	"ollama",
	"facebook",
	"linkedin",
	"discord",
	"ebay",
	"etsy",
	"flickr",
	"twitch",
	"gitter",
	"kimi",
	"highnote",
	"lighton",
	"miro",
	"tableau",
	"snowflake",
	"nytimes",
	"datagov",
	"squarespace",
	"dropbox",
	"heroku",
	"netlify",
	"vercel",
	"intercom",
	"okta",
	"figma",
	"gitea",
	"mattermost",
	"paypal",
	"zendesk",
	"yandex",
	"alibaba",
	"coinbase",
	"polymarket",
]);
/**
 * Vendors' names, from the imported rules anchored on one (`airtable API key` → `airtable`): a bare vendor name
 * holds that vendor's key (`deepgram = <hex>`, `postmark: <uuid>`): the name is a credential's, and the value is judged
 * under it as the unnamed layer judges a token.
 */
const VENDORS = new Set(
	IMPORTED_FORMATS.filter(([, , , , , byVendorWord]) => byVendorWord === 1)
		.map(([name]) => name.split(" ")[0].toLowerCase())
		.filter((w) => /^[a-z][a-z0-9]{3,}$/.test(w) && !NOT_VENDOR_NAMES.has(w)),
);
/**
 * Vendors whose SDK clients take a bare key positionally, a hex or base64 string with no prefix of its own:
 * `twilio(sid, "<32 hex>")`, `new Pusher({ secret })`, `Mailjet.apiConnect(key, secret)`. With the vendors above, a
 * string passed to their clients is a key (isVendorClient).
 */
const KEY_TAKING_CLIENTS = [
	"twilio",
	"pusher",
	"mailjet",
	"trello",
	"etherscan",
	"infura",
	"alchemy",
	"spotify",
	"mixpanel",
	"plivo",
	"telnyx",
	"mailgun",
	"nexmo",
	"vonage",
	"messagebird",
	"onesignal",
	"agora",
	"paystack",
	"braintree",
	"cloudinary",
	"bitly",
	"clearbit",
	"sparkpost",
	"mandrill",
	"imgur",
	"giphy",
	"unsplash",
	"algolia",
	"pubnub",
	"ably",
	"contentful",
	"airtable",
	"postmark",
	"brevo",
	"mapbox",
	"tomtom",
	"pinecone",
	"replicate",
];
export const VENDOR_CLIENTS = new Set([...VENDORS, ...KEY_TAKING_CLIENTS]);

/** "Password" as a name's word, in the languages names are written in. */
const PASSWORD_WORDS = new Set([
	"PASSWD",
	"PASS",
	"PWD",
	"PW",
	"PASSPHRASE",
	"PASSCODE",
	"REQUIREPASS",
	...PASSWORD_NAME_WORDS,
]);

/**
 * Whether a name's word names a password: "password" in any language, or one glued to the word before it (`PGPASSWORD`,
 * `adminpasswd`, `DBPASSCODE`); the short `PASS`, `PWD` and Redis's `AUTH` glued only after what they belong to
 * (`REDISPASS`, `ROOTPWD`, `masterauth`; not `bypass`, `OAuth`), as isCredentialWord reads them.
 */
function isPasswordWord(word: string): boolean {
	if (PASSWORD_WORDS.has(word)) return true;
	const glued = /(PASSWORD|PASSWD|PASSPHRASE|PASSCODE|PASS|PWD|AUTH)$/.exec(word);
	if (!glued) return false;
	const head = word.slice(0, glued.index);
	return /^PASS(?:WORD|WD|PHRASE|CODE)$/.test(glued[1]) || PASSWORD_OWNERS.has(head) || isVendorName(head);
}

/**
 * A credential's name written as a phrase of words, as one word or several: `mot_de_passe` and `palavra_passe` (a
 * password's), `code_secret`. (Read on the name without its qualifiers: `mot_de_passe_prod`.)
 */
function phraseName(core: string[]): string | undefined {
	return [3, 2, 1]
		.map((n) => core.slice(-n).join("_"))
		.find((p) => /^(?:MOT_?DE_?PASSE|PALAVRA_?PASSE|CODE_?SECRET)$/.test(p));
}

/** Whether a name's value is a password: its last word names one (`DB_PASSWORD`, `adminpasswd`, `DB_WACHTWOORD`, `REDISPASS`, `mot_de_passe`). */
export function isPasswordName(name: string): boolean {
	const { last, core, class: cls } = readName(name);
	// (Or a password's word leads a credential's name, its owner after it: `PASSWORD_DB`, `pwd_root_mysql`.)
	return (
		isPasswordWord(last) ||
		/PASSE$/.test(phraseName(core) ?? "") ||
		(cls === "credential" && isPasswordWord(core[0] ?? ""))
	);
}

/**
 * Whether a name's value may be an ordinary word and still be its secret: a password's, a PIN's, a pre-shared key's
 * or a seed phrase's (`DB_PASSWORD=sunshine`, `pin: 4821`, `mnemonic: …`).
 */
export function takesAnyWord(name: string): boolean {
	return isPasswordName(name) || /^(?:PSK|PIN|MNEMONIC|PHRASE|SEED)$/.test(readName(name).last);
}

/** Whether a name says its value is a password or a PIN, by any of its words (`DB_PASSWORD_HINT`, `PGPASSWORD`, `admin-pin`, `door_code`). */
export function namesPasswordOrPin(name: string): boolean {
	// (A phrase as a name, `mot_de_passe`, `palavra_passe`, as isPasswordName reads it.)
	return words(name).some(isPasswordWord) || /PASSE$/.test(phraseName(readName(name).core) ?? "") || isPinName(name);
}

/** A vendor's name alone, which holds that vendor's key: `deepgram`, `NGROK` (VENDORS). */
export function isVendorName(name: string): boolean {
	return VENDORS.has(name.toLowerCase().replace(/[_-]/g, ""));
}

/** Words a vendor's name takes glued to it for its SDK or client: `algoliasearch`, `mapboxgl`, `MailgunClient`, `twilioSdk`, `pusherJs`. */
const CLIENT_SUFFIX = /^(?:search|gl|sdk|client|api|js|v\d+)?$/;

/** A vendor's SDK or client by its name: `algoliasearch`, `Mailgun`, `TWILIO`, `twilio.Client` (a vendor's name, then a client word or nothing; not `imgurian`). */
export function isVendorClient(name: string): boolean {
	const first = /^[A-Za-z][A-Za-z0-9]*/.exec(name.replace(/^new\s+/, ""))?.[0].toLowerCase() ?? "";
	for (let n = first.length; n >= 4; n--)
		if (VENDOR_CLIENTS.has(first.slice(0, n)) && CLIENT_SUFFIX.test(first.slice(n))) return true;
	return false;
}

/** What a `…_code` is a PIN for: `alarm_code`, `door-code`, `keypadCode` (not `block_code`, `clock_code`). */
const PIN_OWNERS = new Set(["ALARM", "DOOR", "LOCK", "UNLOCK", "KEYPAD", "SAFE", "GATE", "ACCESS", "SECURITY"]);

/**
 * A credential's word somewhere in a name, as a regex source for the readers' cheap prefilters (named.ts `NAME`,
 * setter calls): every word CREDENTIAL_WORDS and CREDENTIAL_SUFFIX know, in lower case, so a word added there reaches
 * them all; `sess` and `private` for `session_id` and `vapidPrivate`; and "password" as other languages spell it in a
 * name, accents and all (`db_jelszó`, `DB_HASŁO`, `contraseña`), which CREDENTIAL_WORDS holds folded. A prefilter only:
 * whether `pin` in `pinValue` or `spinner` is a credential's word is isCredentialName's (the readers' `i` flag leaves
 * no way to tell a camel-case hump from a lower-case letter here).
 */
export const CREDENTIAL_WORD = [
	...new Set(
		[
			...CREDENTIAL_WORDS,
			...(CREDENTIAL_SUFFIX.source.match(/[A-Z]+/g) ?? []),
			"PINCODE",
			"SESS",
			"PRIVATE",
			...PASSWORD_LANGUAGES.flatMap(([, spellings]) => spellings.filter((w) => /^[^\s-]*[^\x00-\x7f][^\s-]*$/.test(w))),
		].map((w) => w.toLowerCase()),
	),
]
	.sort((a, b) => b.length - a.length)

	.concat(`(?:${[...PIN_OWNERS].join("|")})[_-]?code`)
	.join("|");

/** Words after `PIN` in a setting about PINs, not a PIN: `PIN_TIMEOUT_MS`, `pin_attempts`, `Pin-Priority`, `PIN_LENGTH`. */
const PIN_SETTING =
	/^(?:TIMEOUT|TTL|EXPIRY|EXPIRES|EXPIRATION|SECONDS|SECS|MS|MINUTES|ATTEMPTS|TRIES|RETRIES|PRIORITY|LENGTH|LEN|SIZE|MAX|MIN|COUNT|ROUNDS|MEMORY|CACHE|LOCKOUT|DURATION|LIMIT|ENABLED|DISABLED|REQUIRED|MODE|POLICY|FORMAT|PATTERN|REGEX|HASH|HASHES|SALT|ALGORITHM|ITERATIONS|BLOCK|BLOCKED|LOCKED|RESET|CHANGE|CHANGED|STATUS|STATE|TYPE|LABEL|HINT|PROMPT|FIELD|PAGE|SCREEN|DIALOG|ERROR|MESSAGE|MSG)$/;

/**
 * A PIN's name: `PIN` among its words (`pin`, `door_pin`, `PIN_CODE`, `pinCode`, `pin_input`, `user_pin_value`; not a
 * GPIO's or a certificate's pin, a setting about PINs, `PIN_TIMEOUT_MS`, `Pin-Priority`, nor a key or a secret a PIN
 * qualifies, `PIN_ENCRYPTION_KEY`, whose own word decides), `PINCODE`, `PASSCODE` (not `PASSCODE_API_KEY`), or a code
 * named for what it opens (`alarm_code`). namesPasswordOrPin, the name readers and the prose readers all ask this one.
 */
export function isPinName(name: string): boolean {
	const w = words(name);
	const at = w.findIndex(
		(x, i) => (x === "PIN" && !NOT_CREDENTIAL_BEFORE.PIN!.has(w[i - 1] ?? "")) || x === "PINCODE" || x === "PASSCODE",
	);
	if (at >= 0) return !w.slice(at + 1).some((x) => PIN_SETTING.test(x) || (x !== "CODE" && isCredentialWord(x)));
	const last = w.at(-1) ?? "";
	return (
		(last === "CODE" && PIN_OWNERS.has(w.at(-2) ?? "")) ||
		(last.endsWith("CODE") && PIN_OWNERS.has(last.slice(0, -"CODE".length)))
	);
}

/**
 * `PAT` names a personal access token after a forge's or a CI's name, or alone (`GITHUB_PAT`, `ADO_PAT`, `pat`); after
 * another word it's a pattern (`exclude_pat`, `DATE_PAT`).
 */
const PAT_OWNERS = new Set([
	"GITHUB",
	"GH",
	"GITLAB",
	"GL",
	"ADO",
	"AZURE",
	"DEVOPS",
	"AZDO",
	"BITBUCKET",
	"BB",
	"GITEA",
	"FORGEJO",
	"HF",
	"HUGGINGFACE",
	"JIRA",
	"CONFLUENCE",
	"ATLASSIAN",
	"SONAR",
	"FIGMA",
	"NPM",
	"DOCKER",
	"DOCKERHUB",
	"QUAY",
	"CI",
	"BOT",
	"PERSONAL",
	"ACCESS",
	"MY",
	"YOUR",
	"API",
]);

/**
 * What a password or an auth string glued to its word belongs to: `PGPASS`, `ROOTPWD`, `storepass`, `REDISAUTH`,
 * `masterauth`, `X-AUTH`. Glued to anything else the word is part of another (`bypass`, `compass`, `lowpass`,
 * `subpass`, `OAuth`, `preauth`, `NextAuth`) or a product's name (`KeePass`, `LastPass`, `gopass`).
 */
const PASSWORD_OWNERS = new Set([
	"DB",
	"PG",
	"PSQL",
	"MYSQL",
	"MARIADB",
	"MSSQL",
	"POSTGRES",
	"REDIS",
	"MONGO",
	"ROOT",
	"ADMIN",
	"USER",
	"MY",
	"YOUR",
	"TEST",
	"DEV",
	"API",
	"APP",
	"SECRET",
	"EMAIL",
	"MAIL",
	"SMTP",
	"IMAP",
	"FTP",
	"SFTP",
	"SSH",
	"MQTT",
	"AMQP",
	"LDAP",
	"KEY",
	"STORE",
	"KEYSTORE",
	"TRUSTSTORE",
	"DESTSTORE",
	"SRCSTORE",
	"REQUIRE",
	"MASTER",
	"NPM",
	"VNC",
	"RPC",
	"SUDO",
	"WIFI",
	"PROXY",
	"HTTP",
	"X",
	"SERVER",
	"CLIENT",
	"SERVICE",
	"DEFAULT",
	"ACCOUNT",
	"LOGIN",
	"BIND",
	"CLUSTER",
	"BASIC",
	"BEARER",
]);

/**
 * Whether one word of a name is a credential word: `PASSWORD`, `TOKEN`, `KEY`, or one glued to it, `PGPASSWORD`,
 * `APITOKEN`, `WRITEKEY`. The short `PASS`, `PWD` and `AUTH` count glued only after what they belong to (PASSWORD_OWNERS).
 */
function isCredentialWord(word: string): boolean {
	if (CREDENTIAL_WORDS.has(word)) return true;
	const glued = CREDENTIAL_SUFFIX.exec(word);
	if (!glued) return false;
	const head = word.slice(0, glued.index);
	return !/^(?:PASS|PWD|AUTH)$/.test(glued[1]) || PASSWORD_OWNERS.has(head) || isVendorName(head);
}

export type NameClass = "credential" | "hash" | "identifier" | "neutral" | "public";

/** What a name says, read once: its words, the meaningful ones, its last meaningful word (singular, undigited) and its class. */
export interface Name {
	words: string[];
	/** The words without the qualifiers and encodings after the meaningful one: `DB_PASSWORD_PROD_B64` → DB, PASSWORD. */
	core: string[];
	/** The last core word, singular and without a version: `API_KEYS2` → KEY. */
	last: string;
	class: NameClass;
}

/**
 * What a name says about its value:
 * - credential: `api_key`, `X-Auth-Token`, `password`
 * - hash: `sha256`, `commit`, `etag`, `integrity`, `nonce`, `cursor` (random but not secret)
 * - identifier: `user_id`, `bucket`, `url`, `sort_key`
 * - public: `public_key`, `NEXT_PUBLIC_*`, `publishable_key`
 * - neutral: anything else (`data`, `value`, `X-Lumen`)
 */
export function readName(name: string): Name {
	let cached = NAME_CACHE.get(name);
	if (!cached) {
		const w = words(name);
		const core = w.slice();
		while (core.length > 1 && (WRAPPER_WORDS.has(core.at(-1)!) || QUALIFIER_WORDS.test(core.at(-1)!))) core.pop();
		const last = (core.at(-1) ?? "")
			.replace(/(?<=[A-Z])\d+$/, "")
			.replace(/(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)S$/, "$1");
		cached = { words: w, core, last, class: classify(name, w, core, last) };
		if (NAME_CACHE.size >= 10_000) NAME_CACHE.clear();
		NAME_CACHE.set(name, cached);
	}
	return cached;
}
const NAME_CACHE = new Map<string, Name>();

/** A name's words without the qualifiers after them (`MIXPANEL_TOKEN_PROD` → `MIXPANEL_TOKEN`), joined by `_`. */
function unqualifiedName(name: string): string {
	const w = words(name);
	while (w.length > 1 && QUALIFIER_WORDS.test(w.at(-1)!)) w.pop();
	return w.join("_");
}

/**
 * Words before `KEY` that name a lookup key in a schema or a store, and a cloud's access key as well (see classify); and
 * a key's algorithm or kind, `SSH_KEY`, `CA_KEY`, its public half or its private one: such a name is neutral, its value
 * judged by its shape. (Not `SEARCH`: a search key is more often Algolia's public one than an Azure secret.)
 */
const AMBIGUOUS_BEFORE_KEY = new Set([
	"PRIMARY",
	"SECONDARY",
	"STORAGE",
	"HOST",
	"ROOT",
	"REDIS",
	"SERVER",
	"MASTER",
	"SSH",
	"RSA",
	"DSA",
	"ECDSA",
	"ED25519",
	"CA",
]);

/** Credential words that may come first in a name, its owner after them (`PASSWORD_DB`, `TOKEN_GITHUB`). */
const OWNED_CREDENTIAL = new Set(["PASSWORD", "PASSWD", "PWD", "PASSPHRASE", "TOKEN", "SECRET", "APIKEY"]);
/** Last words that make a credential-first name a thing about credentials, not one: `SECRET_MANAGER`, `TOKEN_COUNT`. */
const ABOUT_CREDENTIAL = new Set([
	"MANAGER",
	"MANAGERS",
	"BACKEND",
	"ENGINE",
	"MOUNT",
	"SOURCE",
	"SOURCES",
	"REF",
	"REFS",
	"COUNT",
	"LIMIT",
	"LIMITS",
	"ROTATION",
	"LIFETIME",
	"EXPIRATION",
	"EXPIRES",
	"HEADER",
	"PARAM",
	"FIELD",
	"NAMES",
	"KEYS",
	"LIST",
	"VAR",
	"VARS",
	"ENCODING",
	"BUDGET",
	"USAGE",
	"USED",
	"LEFT",
	"RATE",
	"SIZE",
	"CACHE",
	"STORE",
	"COMPLEXITY",
	"GENERATOR",
	"HASHER",
	"HASHERS",
	"HISTORY",
	"CHANGE",
	"UPDATE",
	"AGE",
	"SCHEME",
	"VERSION",
	"FORMAT",
	"STRATEGY",
	"TYPE",
	"TYPES",
	"FLOW",
	"EXCHANGE",
	"REFRESH",
	"REVOCATION",
	"VALIDATION",
	"VERIFICATION",
	"AUTH",
	"FILE",
	"PATH",
	"DIR",
	"ID",
	"IDS",
	"STDIN",
	"STDOUT",
	"FD",
	"CMD",
	"COMMAND",
	"INPUT",
	"OUTPUT",
	"DATE",
	"TIME",
	"SIGN",
	"VERIFY",
	"ENCODE",
	"DECODE",
	"GENERATE",
	"CREATE",
	"NEW",
	"GET",
	"SET",
	"LITERAL",
	"STRING",
	"STREAM",
	"ENDPOINT",
	"PROVIDER",
	"HANDLER",
	"GRANT",
	"GRANTS",
	"CHECK",
	"TEST",
	"TESTS",
	"SPEC",
]);

/** The rules, in order: the first that applies decides. */
function classify(name: string, w: string[], core: string[], last: string): NameClass {
	if (!name || name.length > 120 || !last) return "neutral";
	// A file's path names the file, whatever words it holds (`lib/pin.rb`, `manifests/pin.pp` in a checksum manifest).
	// (A bare file name is read below, after the PIN's: it may be a Kubernetes Secret's key, `pin.txt`.)
	if (name.includes("/") && isFileName(name)) return "neutral";
	// A vendor's name holds that vendor's key; Bundler's name for a gem server's host, that server's credentials.
	if (isVendorName(name) || isBundlerHostName(name)) return "credential";
	// Unity's serialized localization keys and names; a list item's key (Sanity's and React's `_key`); a generated
	// fixture's, numbered with zeros (`tagKey000003`); Postman's per-request UUID.
	if (/^m_(?:Key|KeyId|Name|Id)$|[a-z](?:Key|Token|Secret)0\d{4,}$/.test(name) || /^_+key$|^postman-token$/i.test(name))
		return "identifier";
	// The WebSocket handshake's nonce and its answer, public by RFC 6455.
	if (/^sec-websocket-(?:key|accept)$/i.test(name)) return "hash";
	// nginx's and Apache's upstream directives: `proxy_pass http://app:8000;`, `fastcgi_pass unix:/run/php.sock;`, `ProxyPass / …`.
	// (Lower case as nginx writes them; `PROXY_PASS`, `HTTP_PASS` in an environment are passwords.)
	if (
		/^(?:proxy|fastcgi|uwsgi|scgi|grpc|memcached|ajp)_pass(?:_\w+)?$|^ProxyPass(?:Reverse(?:Cookie\w*)?|Match|Interpolate)?$/.test(
			name,
		)
	)
		return "identifier";
	// Azure's credentials that sign in as an identity take its IDs, not a secret: `ManagedIdentityCredential("<client id>")`.
	if (
		/(?:ManagedIdentity|WorkloadIdentity|AzureCli|AzureDeveloperCli|AzurePowerShell|DefaultAzure|InteractiveBrowser|DeviceCode|VisualStudioCode|SharedTokenCache)Credential$/.test(
			name,
		)
	)
		return "identifier";
	// An alarm's, a door's or a keypad's code is a PIN; `vapidPrivate`, `push_private`: the private half of a key pair.
	// (A key's private half named as a camel-case hump or after a separator, `vapidPrivate`, `VAPID_PRIVATE`; not a word
	// that ends so, `isprivate`, `semiprivate`.)
	if (
		isPinName(name) ||
		(/^[a-z][a-z0-9]*(?:Private|[_-]private)$|^[A-Za-z][A-Za-z0-9]*[_-]PRIVATE$/.test(name) && !ABOUT_WORDS.has(w[0]))
	)
		return "credential";
	if (isPublicName(name, core)) return "public";
	// A session's ID is its bearer credential; Consul's tokens and Vault's AppRole logins are `SecretID`s.
	if (
		isSessionIdName(name) ||
		/(?:^|[-_ .])secret[-_ ]?id$|secretId$/i.test(name) ||
		/^x-[\w-]*-session(?:-token)?$/i.test(name)
	)
		return "credential";
	// A certificate's or a public key's file (`tls.crt`, `ca.cer`, `id_ed25519.pub`, a signing request): public material.
	if (/\.(?:crt|cer|cert|pub|csr)$/i.test(name)) return "public";
	if (DATA_FILE.test(name)) return "hash";
	if (isFileName(name)) return "neutral";
	// A credential word that the word before rules out (`GPG_KEY`, `SORT_KEY2`, `PAGE_TOKEN`); PagerDuty's routing and
	// integration keys are its Events API credentials. (A word that clouds' keys share with lookup keys makes the name
	// neutral, its value judged by how it looks: Azure's `primaryKey`, `AZURE_STORAGE_KEY`, `hostKey`, `REDIS_KEY`.)
	// (Not the secret half of a pair whose public half the word names, a secret's word before it: reCAPTCHA's
	// `SECRET_SITE_KEY`, `PRIVATE_GPG_KEY`.)
	if (
		core.length > 1 &&
		NOT_CREDENTIAL_BEFORE[last]?.has(core.at(-2)!) &&
		!core.some((x) => x === "PAGERDUTY" || x === "PD") &&
		!(
			last === "KEY" &&
			/^(?:SITE|GPG|PGP)$/.test(core.at(-2)!) &&
			core.slice(0, -2).some((x) => /^(?:SECRET|PRIVATE)$/.test(x))
		)
	)
		return last === "KEY" && AMBIGUOUS_BEFORE_KEY.has(core.at(-2)!) ? "neutral" : "identifier";
	// Encrypted or wrapped key material, CSRF tokens: random, not usable as credentials. (In a dotted name, only the
	// last part counts: `encryptedSavedObjects.encryptionKey` is a key.)
	// (By its words: `UNENCRYPTED_PASSWORD` and `unwrapped_key` name the plaintext. A CSRF name ending in a secret's or a
	// key's word names what signs the tokens, a server's secret: `WTF_CSRF_SECRET_KEY`, `csrfSecret`, `CSRF_AUTH_KEY`.)
	const lastPart = name.slice(name.lastIndexOf(".") + 1);
	const partWords = words(lastPart);
	if (
		partWords.some((x) => /^(?:ENCRYPTED|WRAPPED|SEALED|CIPHERTEXT)/.test(x)) ||
		(partWords.some((x) => /^(?:CSRF|XSRF)/.test(x)) && !/^(?:SECRET|KEY)$/.test(partWords.at(-1)!))
	)
		return "hash";
	// A Vault token's accessor looks the token up; git's `signingkey` and `gpgkey` (in its lower case), key IDs and
	// gspread's `open_by_key` name keys.
	if (
		/accessor$/i.test(lastPart) ||
		/(?:^|[._])(?:signingkey|gpgkey)$/.test(name) ||
		/(?:^|[._])(?:keyid|key_id|signing_key_id|(?:\w+_)?by_key)$/i.test(name)
	)
		return "identifier";
	// Client-side error reporting: Sentry's DSN and key are public.
	if (/^(?:SENTRY_KEY|DSN)$/.test(unqualifiedName(name))) return "public";
	// Computed signatures in headers (`X-Hub-Signature-256`, `Stripe-Signature`), pagination tokens (`$skiptoken`,
	// `resumptionToken`), email and WebAuthn plumbing: hashes, not credentials.
	if (
		/signature_?base/i.test(name) ||
		/^x-.*signature(?:-\d+)?$|-signature(?:-\d+)?$|^(?:\$?skiptoken|\$?deltatoken|resumptiontoken|starting-token|next-?token|page-?token|authenticatordata|clientdatajson|attestationobject|userhandle|rawid|credentialid|x-google-smtp-source|x-gm-message-state|arc-seal|arc-message-signature|dkim-signature|x-received|message-id|in-reply-to|references)$/i.test(
			name,
		)
	)
		return "hash";
	// The digest of something, as Helm's annotations name it: `checksum/secrets`, `sha256/config`.
	if (/^(?:checksum|hash|digest|sha\d*|md5|fingerprint)\//i.test(name)) return "hash";
	if (phraseName(core)) return "credential";
	// Shell variables (`PWD`, `OLDPWD`), loop keys and auth modes (`KEY`, `AUTH`), test output (`PASS:`).
	if (core.length === 1 && NOT_CREDENTIAL_NAMES.has(name)) return "neutral";
	// Route and screen words name what a credential is for when it ends in a full credential phrase
	// (`PAGE_ACCESS_TOKEN`, `EVENT_API_KEY`) or in `SECRET`, a word no lookup key ends in (`EVENT_SECRET`); elsewhere they,
	// and other words about a credential, mark UI text, lookup keys, errors, flags and settings (`PASSWORD_PAGE_TITLE`,
	// `LOGIN_PAGE_PASSWORD`, `ROUTE_KEY`, `ERROR_WRONG_PASSWORD`, `HAS_PASSWORD`, `NOPASS`).
	const fullPhrase =
		last === "SECRET" ||
		(core.length >= 2 &&
			/^(ACCESS|API|SECRET|CLIENT|APP|AUTH|SIGNING)$/.test(core.at(-2)!) &&
			/^(TOKEN|KEY)$/.test(last));
	const about =
		core.some((x) => ABOUT_WORDS.has(x) && !(fullPhrase && ROUTE_WORDS.has(x))) ||
		/^NO(PASS|PASSWD|PASSWORD|AUTH)$/.test(last);
	if (!about && isCredentialWord(last) && !(last === "PAT" && core.length > 1 && !PAT_OWNERS.has(core.at(-2)!)))
		return "credential";
	// A credential's word first, then whose it is: `PASSWORD_DB`, `TOKEN_GITHUB`, `SECRET_STRIPE`, `password_for_db`; not
	// a setting or a thing about it (`TOKEN_LIMIT`, `PASSWORD_POLICY`, `SECRET_MANAGER`, `TOKEN_URL`).
	// (The credential's word leads the name, and none after it makes the name a thing about credentials.)
	const owned =
		OWNED_CREDENTIAL.has(core[0]) &&
		core.slice(1).every((x) => !ABOUT_CREDENTIAL.has(x) && !HASH_WORDS.has(x) && !IDENTIFIER_WORDS.has(x));
	if (!about && owned && !isSettingName(name)) return "credential";
	if (
		HASH_WORDS.has(last) ||
		/^(SHA|MD|BLAKE|CRC)\d*$/.test(last) ||
		(last === "ID" && core.some((x) => HASH_WORDS.has(x)))
	)
		return "hash";
	if (IDENTIFIER_WORDS.has(last)) return "identifier";
	return "neutral";
}

/** Words that end a setting's name (see isSettingName). */
const SETTING_WORDS = new Set([
	"ID",
	"UUID",
	"NAME",
	"URL",
	"URI",
	"HOST",
	"PORT",
	"PATH",
	"DIR",
	"FILE",
	"ENV",
	"MODE",
	"LEVEL",
	"VERSION",
	"USER",
	"EMAIL",
	"DOMAIN",
	"SHA",
	"HASH",
	"COMMIT",
	"DIGEST",
	"TZ",
	"TERM",
	"SHELL",
	"HOME",
	"DISPLAY",
	"EDITOR",
	"PAGER",
	"RELEASE",
	"REVISION",
	"LOGIN",
	"REGION",
	"ZONE",
	"TIMEOUT",
	"LIMIT",
	"SIZE",
	"COUNT",
	"LENGTH",
	"TTL",
	"ENABLED",
	"DISABLED",
	"LANG",
	"LOCALE",
	"COLOR",
	"THEME",
	"SOCK",
	"SOCKET",
	"PREFIX",
	"DSN",
	"TYPE",
	"METHOD",
	"PROVIDER",
	"ARN",
	"ENDPOINT",
	"PROJECT",
	"STORE",
	"ADDRESS",
	"POLICY",
	"EVENTS",
	"ALGORITHM",
	"ISSUER",
	"AUDIENCE",
	"SCOPE",
	"SCOPES",
	"BACKEND",
	"FORMAT",
	"STRATEGY",
]);

/**
 * A name a setting has, by its last word: `HOSTNAME`, `TZ`, `APP_URL`, `TENANT_ID`, `SMTP_LOGIN`, `SSH_AUTH_SOCK`,
 * `TOKEN_ENDPOINT`, `PASSWORD_POLICY`. (Glued to a setting's word or an owner's, `HOSTNAME`, `DBHOST`; not `PAID`,
 * `MY_TOKEN_VALID`, whose last word merely ends like one.) Where the context says every value is a secret (a secret
 * file, the caller's environment), this is what says one isn't.
 */
export function isSettingName(name: string): boolean {
	const last = words(name).at(-1) ?? "";
	if (SETTING_WORDS.has(last)) return true;
	for (const word of SETTING_WORDS)
		if (
			last.endsWith(word) &&
			(SETTING_WORDS.has(last.slice(0, -word.length)) || PASSWORD_OWNERS.has(last.slice(0, -word.length)))
		)
			return true;
	return false;
}

/** Whether a name's value is a credential. */
export function isCredentialName(name: string): boolean {
	return readName(name).class === "credential";
}

export function nameClass(name: string): NameClass {
	return readName(name).class;
}

/** Generic credential names that are also everyday dictionary/map keys. */
const GENERIC_NAMES =
	/^(key|keys|token|tokens|auth|sig|pin|salt|seed|sid|pat|cookie|cookies|secret|signature|hmac|otp|session|sess|private|cred|creds|ak|sk)$/i;
export const isGenericName = (name: string) => GENERIC_NAMES.test(name);

/** Words that make a bare `key`/`token` after them a credential's (`api key`, `client secret`), with QUALIFIER_WORDS (`old key`) and vendors' names (`stripe key`); as an alternation, for the sentences that name a credential (named.ts). */
export const CREDENTIAL_QUALIFIERS =
	"api|secret|access|private|auth|client|signing|encryption|master|app|license|licence|admin|root|bearer|session|refresh|service|deploy|personal|bot|webhook|account|user|integration|partner|consumer|shared|write|read|ingest|dev|prod|live|test|github|gitlab|aws|gcp|azure";
const CREDENTIAL_QUALIFIER = new RegExp(`^(?:${CREDENTIAL_QUALIFIERS})$`, "i");
/** Words that end a name's phrase in prose: determiners, pronouns, verbs and prepositions (`Here is the token`). */
export const PHRASE_STOP =
	/^(?:is|was|are|were|be|been|the|a|an|your|my|our|their|his|her|its|this|that|these|those|here|there|of|for|to|with|from|in|on|at|by|and|or|use|using|set|get|got)$/i;

/**
 * The words just before a name, up to `max` (`next page` in `next page token:`), for readPhrase: none that are a pair's
 * value (`msg=hello token=…`, `id=web-portal secret=…` in a log line) or follow a quote, nor a word that continues a
 * token (`portal` in `web-portal`).
 */
export function phraseBefore(text: string, max: number): string[] {
	let pattern = PHRASE_BEFORE.get(max);
	if (!pattern)
		PHRASE_BEFORE.set(
			max,
			(pattern = new RegExp(String.raw`(?<![=:"'\p{L}\p{N}_./-])((?:\p{L}{1,30}[ \t_-]{1,3}){1,${max}})["']?$`, "u")),
		);
	return (
		pattern
			.exec(text)?.[1]
			.trim()
			.split(/[ \t_-]+/) ?? []
	);
}
const PHRASE_BEFORE = new Map<number, RegExp>();

/**
 * A bare generic name (`key`, `token`, `secret`, `id`, `hash`) read with the prose words before it: `public key`,
 * `next page token`, `old key`, `the search-only key`. The phrase starts after the last determiner, verb or
 * preposition ("Here is the token" names a token); one that reads as another name (two words, then one) gives its
 * class, and a credential word after a word that qualifies no credential (`cache warm key`) is a neutral one.
 */
export function readPhrase(before: string[], name: string): { name: string; class: NameClass } {
	const cls = nameClass(name);
	const phrase = before.slice(before.findLastIndex((w) => PHRASE_STOP.test(w)) + 1).slice(-2);
	for (const q of [phrase.join("_"), phrase.at(-1)]) {
		if (q && nameClass(`${q}_${name}`) !== cls) return { name: `${q}_${name}`, class: nameClass(`${q}_${name}`) };
	}
	const q = phrase.at(-1);
	return {
		name,
		class:
			q &&
			cls === "credential" &&
			!CREDENTIAL_QUALIFIER.test(q) &&
			!QUALIFIER_WORDS.test(q.toUpperCase()) &&
			!isVendorName(q)
				? "neutral"
				: cls,
	};
}

/**
 * Whether the name is a credential's, or a neutral name has a credential word that the word before doesn't rule out
 * (`auth_header`, `api_key_header`; not `cache.key.prefix`, nor a file's name, `has_key.rb`).
 */
export function mentionsCredential(name: string): boolean {
	const cls = readName(name).class;
	return cls === "credential" || (cls === "neutral" && hasCredentialWord(name) && !isFileName(name));
}

/** Whether any word of a name is a credential word that the word before doesn't rule out (`BASIC_AUTH`; not `CACHE_KEY`), whatever the name's class. */
export function hasCredentialWord(name: string): boolean {
	const w = readName(name).words;
	const ruledOut = (x: string, before: string | undefined) =>
		NOT_CREDENTIAL_BEFORE[x]?.has(before!) && !(x === "KEY" && AMBIGUOUS_BEFORE_KEY.has(before!));
	return w.some((x, i) => isCredentialWord(x) && !ruledOut(x.replace(/S$/, ""), w[i - 1]));
}
