/**
 * The decision stage. The layers (known values, formats, structure, names, random tokens) propose spans;
 * this decides, once and the same way for every layer, which proposals are values that are public by
 * design or never secrets at all, and so stay. A policy written here can't drift between layers: a
 * format match and a named match on the same value get the same answer.
 *
 * Not judged here: known values (the caller vouched for them), secret files and a secret command's output
 * (`file:`, `command:`: there the file or command says what the value is), and repeats of a value already
 * judged. Each rule still decides what counts as a value at all (placeholders, references, code).
 */
import {
	clientSdkAt,
	isClientGoogleKey,
	isPublicJwt,
	PUBLIC_FORMAT,
	PUBLIC_SDK_PARAM,
	PUBLISHED_EXAMPLE,
} from "./public.ts";
import { isBase58Address, isBech32Address, isNatsPublicKey, isStellarPublicKey, isXrpAddress } from "./checksums.ts";
import { isPairLabel } from "./named.ts";
import { nameClass, namesPasswordOrPin } from "./names.ts";
import { base64Binary, base64Prefix } from "./base64.ts";
import { isDerPublicKey, isPgpPublicKey, isPublicPem } from "./publickeys.ts";
import { inJwk } from "./json.ts";
import { lineEnd, trailingRun } from "./lines.ts";
import type { Finding } from "./types.ts";
import { isPlaceholderBasic, isPublishedMnemonic } from "./structure.ts";
import {
	IDENT_PATH,
	isBenignValue,
	isCountingDigits,
	QUANTITY,
	isCredentialReference,
	namesCredential,
	isGroupedDigits,
	isNameLike,
	isPasswordHash,
	readsAsWords,
} from "./values.ts";
import { CONTRACTION, escapedLineStart } from "./syntax.ts";
import { isGuess, isKeyMaterial, isVouched, layerOf, readsByPlace } from "./rules.ts";
import { Doc } from "./context.ts";
import { publicReason } from "./unnamed.ts";

/**
 * Passwords products ship with and document, each with the line it is that product's on: the JDK's truststore
 * (`-storepass changeit`), Android's debug keystore (`-keystore ~/.android/debug.keystore -storepass android`),
 * Oracle's sample schema (`scott/tiger`), Sauce Labs' demo shop (`login("standard_user", "secret_sauce")`).
 */
const PUBLISHED_DEFAULTS: [value: string, where: RegExp][] = [
	["changeit", /cacerts|trust[-_]?store|keytool|javax\.net\.ssl|keystore/i],
	["android", /debug\.keystore|androiddebugkey/],
	["tiger", /\bscott\//i],
	["secret_sauce", /standard_user|locked_out_user|problem_user|performance_glitch_user|saucedemo/],
];

/**
 * A proposal that says what it is (a vendor format whose prefix says secret, private-key armour or DER) is
 * never kept by the context around it: a public-sounding name (`VITE_OPENAI_API_KEY=sk-proj-…`), a public
 * key earlier on the line, a nearby `kty` or `sitekey`. Context decides only for values whose shape is
 * shared by public and secret ones: Google `AIza` keys, JWTs, a format found only by a keyword nearby
 * (an Amplitude key is 32 hex), a format for a public key (Langfuse `pk-lf-`), and whatever names and
 * places propose.
 */
function saysWhatItIs(f: Finding, value: string, secretJwt: boolean): boolean {
	if (secretJwt || isKeyMaterial(f.rule)) return true;
	// A vendor format with a prefix (`sk-proj-`, `ghp_`, `xoxb-`) or an AWS key ID, but not one whose shape public
	// values share (`AIza`, `eyJ`) or a format for a public value.
	return (
		layerOf(f.rule) === "format" &&
		/^(?:[A-Za-z][A-Za-z0-9]{0,11}[-_.]|A[KS]IA[A-Z0-9]{16}$)/.test(value) &&
		!/^(?:AIza|eyJ)/.test(value) &&
		!/Google API key|GCP API key|JSON Web Token|JWT|algolia|public|publishable|client[ _-]?(?:id|key|sdk)|sdk key|site key/i.test(
			f.rule,
		)
	);
}

/** Whether a value that SDK initialiser `sdk` takes under `name` is its public key, `before` being the text before it: its line up to it and the line above (not a trailing comment, `algoliasearch(id, key) // public docs`). */
function isClientSdkKey(sdk: string, name: string, before: string): boolean {
	if (/secret|passw|private|admin|master|server|write/i.test(name)) return false;
	// (The unnamed layer names a positional argument by its call: `algoliasearch`.)
	const callee = sdk.replace(/^new\s+/, "").replace(/\s*[({[:=].*$/s, "");
	const positional = !name || callee === name || callee.endsWith(`.${name}`);
	if (!positional) return PUBLIC_SDK_PARAM.test(name.replace(/^.*[.\s]/, ""));
	return (
		!/^(?:algoliasearch|instantsearch)/.test(sdk) || /search[-_ ]?(?:only|key)|public|read[-_ ]?only/i.test(before)
	);
}

/**
 * A `WWW-Authenticate` or `Proxy-Authenticate` header's scheme and parameters, up to inside one of the parameters the
 * challenge schemes define (RFC 7235, 7616, 6750, 9728, Azure's), which say where and how to authenticate.
 */
const AUTH_CHALLENGE =
	/\b(?:WWW|Proxy)-Authenticate["']?[ \t]*[:=][ \t]*["']?[A-Za-z][\w-]*(?:[ \t]+[\w-]+=(?:"[^"\n]*"|[^\s,"]*)[ \t]*,)*[ \t]+(?:realm|authorization(?:_uri)?|resource(?:_metadata)?|scope|error|nonce|opaque|algorithm|qop|domain|stale|charset|userhash|trusted_issuers|client_id)=(?:"[^"\n]*|[^\s,"]*)$/i;

/** A line's text with JSON's escaped quotes read as quotes, and without a CRLF's `\r`. */
const unescapeQuotes = (line: string) => line.replace(/\\+(["'])/g, "$1").replace(/\r$/, "");

/** The line before the one starting at `start` (after a line break, real or escaped), looking back no further than `floor`. */
function lineBefore(text: string, start: number, floor: number): string {
	const end = text[start - 1] === "\n" ? start - 1 : text.startsWith("\\n", start - 2) ? start - 2 : -1;
	return end < floor ? "" : text.slice(escapedLineStart(text, end, floor), end);
}

/** Why a proposed span stays in the text, or `undefined` to hide it. `hashes: "hide"` hides password hashes too. */
export function keepReason(text: string, f: Finding, hashes: "keep" | "hide" = "keep"): string | undefined {
	// In a secret file or a secret command's output everything is hidden, whatever it looks like (README), except
	// what is there under no credential's name (`file:opaque`).
	// (`known` and `known:partial`: the caller vouched for the value, or it was learned from where it was a secret.)
	if (isVouched(f.rule)) return undefined;
	const value = text.slice(f.start, f.end);
	const left = text.slice(Math.max(0, f.start - 200), f.start);
	// A device's published default PIN, counting or one digit repeated, that its line calls the default or an example
	// (`The default Bluetooth PIN is 0000`, `factory PIN: 1234`). Anywhere else a PIN of `0000` is someone's PIN
	// (`pin_value=0000`, `--password 123456`).
	if (
		/^\d{4,8}$/.test(value) &&
		isCountingDigits(value) &&
		f.name !== undefined &&
		namesPasswordOrPin(f.name) &&
		/\b(?:default|factory|example|e\.g\.|such as|for instance)\b/i.test(left.slice(left.lastIndexOf("\n") + 1))
	)
		return "a published default PIN";
	// The token the span sits in, to blanks, quotes and separators, and its part after a label (`key_id:rzp_…`,
	// `SHA256:…`; a Mapbox `pk.` token's segment, a JWT behind a diff's `+`): a layer may have cut into either.
	const leftRun = trailingRun(left, /[\s"'`=,;()]/);
	const token = leftRun + value + (text.slice(f.end, f.end + 200).match(/^[^\s"'`,;()]*/)?.[0] ?? "");
	const word = token.slice(leftRun.lastIndexOf(":") + 1).replace(/^[+-](?=eyJ)/, "");
	// Password hashes (bcrypt, argon2, crypt and its `$$`-escaped Compose form, LDAP, MySQL, Pi-hole's BALLOON):
	// kept unless asked otherwise. A weak password's hash can be cracked offline; most labelled data keeps them.
	// A hash by its format, read whole (the token too: a layer that cut into a hash, `$9$salt$X.<tail>`, leaves it
	// whole), or by its place: a hash-named field (structure.ts).
	if (
		hashes === "keep" &&
		(f.rule === "structure:hash-field" ||
			[value, token].some((v) => isPasswordHash(v.replace(/\$\$/g, "$").replace(/^[\w.@-]{1,64}:(?=\$)/, ""))))
	)
		return "password hash";
	// Encrypted values: Windows DPAPI blobs (NuGet), and a JWE (five parts, an `enc` header) named as encrypted
	// data. Not a JWE elsewhere: Auth.js session cookies and encrypted ID tokens are bearer credentials, accepted
	// as they are. Not Jenkins' or Maven's `{…}`: their key sits on the same machine (`secrets/master.key`,
	// `settings-security.xml`), where an agent that read one can usually read the other.
	// (And AWS KMS ciphertext, `AQICAH…`: a data key a SOPS file's `kms:` entry holds, decrypted only by KMS.)
	if (/^AQAAANCMnd8BFdERjHoAwE\/Cl\+s|^AQICAH[A-Za-z0-9+/]{40}/.test(value)) return "encrypted value";
	// A Sealed Secret's ciphertext (`Ag…`), in a SealedSecret's `encryptedData`: by its context, as a random base64
	// secret starts with `Ag` too, 1 time in 4,096.
	if (
		/^Ag[A-Za-z0-9+/]{100,}={0,2}$/.test(value) &&
		/kind:[ \t]*SealedSecret|"kind":[ \t]*"SealedSecret"|encryptedData["']?:/.test(
			text.slice(Math.max(0, f.start - 20_000), f.start),
		)
	)
		return "encrypted value";
	// The line the span is on, up to it and after it, and the line above, read as text: in JSON-escaped text a `\n`
	// ends a line too and `\"` is a quote.
	const lineAt = escapedLineStart(text, f.start, f.start - left.length);
	const line = unescapeQuotes(text.slice(lineAt, f.start));
	const lineAfter = text.slice(f.end, lineEnd(text, f.end, 200));
	const above = unescapeQuotes(lineBefore(text, lineAt, f.start - left.length));
	// A server's authentication challenge holds no client's secret: its parameters say where and how to get one
	// (`WWW-Authenticate: Bearer authorization="https://login…/<tenant>", resource="…"`, a Digest `nonce`).
	// (A vendor's format echoed in one, `error_description="… ghp_…"`, is that token still.)
	// (Recorded as YAML too: `www-authenticate:` above, `  - Bearer authorization="…"` on the line.)
	const challenge =
		AUTH_CHALLENGE.test(line) ||
		(/(?:www|proxy)-authenticate["']?[ \t]*:[ \t]*$/i.test(above) &&
			AUTH_CHALLENGE.test(`WWW-Authenticate: ${line.replace(/^[ \t]*-[ \t]+/, "")}`));
	if (layerOf(f.rule) !== "format" && challenge) return "authentication challenge";
	// (The whole token, whichever part of it a layer found, named on the line before it.)
	const wordLead = leftRun.slice(leftRun.lastIndexOf(":") + 1);
	if (
		/^eyJ[\w-]+\.[\w-]*\.[\w-]+\.[\w-]+\.[\w-]+$/.test(word) &&
		// (Read as far as it decodes: a header with a character past its last whole group still names its `enc`.)
		/"enc"\s*:/.test(new TextDecoder().decode(base64Prefix(word.split(".")[0]) ?? new Uint8Array())) &&
		/(?:encrypt|cipher|jwe)\w*["'`]?[ \t]*[:=][ \t]*["'`]?$/i.test(
			line.endsWith(wordLead) ? line.slice(0, line.length - wordLead.length) : line,
		)
	)
		return "encrypted value";
	// The name the value sits under (`NAME=`, `"name":`, `name:`, `| name |`), if any.
	// The name the layer read, or the one read here (without a shell's `export`/`set` before it), whichever says
	// more: a layer that read `key` in `anon key:` or `client key:` gets the qualifier back.
	// (Seen through a type annotation, `NAME: string = "`, `api_key: str = "`; a subscript, `cfg["NAME"] = "`; `setx NAME "`;
	// and without a search tool's prefix, `src/a.ts:7:` or `rg`'s `7:`.)
	const plain = line
		.replace(/^(?:[\w./@+-]{1,200}\.\w{1,10}[:-])?\d{1,7}[:-](?=[A-Za-z_])/, "")
		.replace(/(?<!\w)([A-Za-z_]\w*)\??:[ \t]*[A-Za-z_][\w.<>[\]|, ]{0,40}?(?=[ \t]*=(?!=))/, "$1")
		.replace(/\[["']([\w.-]{1,60})["']\][ \t]*(?==)/g, ".$1")
		.replace(/^([ \t]*)setx[ \t]+([\w.-]{1,60})[ \t]+(?=["'])/i, "$1$2=");
	const read =
		/(?<![\w.-])([A-Za-z_][\w.-]{0,60}(?: [A-Za-z][\w-]{0,30})?)["'`]?[ \t]*(?:[:=]|=>|\|)[ \t]*["'`]?$/
			.exec(plain)?.[1]
			?.replace(/^(?:export|set|setx|declare|local|readonly|const|let|var) /, "")
			.replace(/^.*\./, (m) => (/^(?:cfg|config|settings|env|os\.environ|process\.env)\.$/.test(m) ? "" : m)) ?? "";
	const squash = (s: string) => s.toLowerCase().replace(/[\s_.-]/g, "");
	// (A type a layer took for the name, `NAME: string = "…"`, isn't one.)
	const layerName =
		f.name && !/^(?:string|str|int|bool|boolean|number|bytes|SecretStr|Optional\[str\]|String|char\*?)$/.test(f.name)
			? f.name
			: undefined;
	const name =
		layerName && !(read.length > layerName.length && squash(read).endsWith(squash(layerName))) ? layerName : read;
	// Never secrets, whatever names them (counts, versions, algorithm names, key chords…), for the rules that
	// read a value by its name or its place; formats and private-key armour say what a value is themselves.
	if (readsByPlace(f.rule)) {
		// (A number under a password's or a PIN's name is one: `PIN=4821-7730`, `DB_PASSWORD=21.05.1987`; an ISO date, `2024-05-01`, is a date.)
		// (A bare `pass` is as often the word: `single-pass: 3.52x`.)
		if (
			isBenignValue(value) &&
			!(
				(isGroupedDigits(value) || (QUANTITY.test(value.trim()) && !/(?:^|[^a-z])pass$/i.test(name))) &&
				namesPasswordOrPin(name)
			)
		)
			return "never a secret";
		if (namesCredential(value)) return "names a credential";
		// A Twilio resource's SID (`AccountSid`, `streamSid`: two letters and 32 hex), an ID; its auth token is the secret.
		if (/sid$/i.test(name) && /^[A-Z]{2}[0-9a-f]{32}$/.test(value)) return "a Twilio SID";
		// A service account's Secrets by their generated names: `kubectl describe sa`'s `Image pull secrets:  <sa>-dockercfg-4qz9g`.
		if (
			/(?:^|[\s_-])(?:secrets|tokens)$/i.test(name) &&
			/^[a-z0-9]+(?:-[a-z0-9]+)*-(?:token|dockercfg)-[a-z0-9]{5}$/.test(value)
		)
			return "a Secret's name";
		const code = codeShape(text, f, value, left);
		if (code) return code;
	}
	// What the random layer's vetoes know is public by design (a key's fingerprint, an APK checksum, an AWS unique ID…),
	// for the layers that read a value by its name or its place.
	if (["named", "structure"].includes(layerOf(f.rule))) {
		const reason = publicReason(Doc.of(text), f.start, f.end);
		if (reason) return `public by its shape (${reason})`;
	}
	// Example values published in RFCs and docs, whichever layer read them.
	if (PUBLISHED_EXAMPLE.test(value) || isPublishedMnemonic(value)) return "published example";
	// (A JWT whose claims give it a secret role says what it is too, whatever it's named: Supabase's `service_role`.)
	const secretJwt =
		/^eyJ[\w-]+\.eyJ[\w-]+\./.test(word) &&
		/"role"\s*:\s*"(?:service_role|admin|supabase_admin)"/.test(base64Binary(word.split(".")[1]) ?? "");
	// A vendor format matched in the middle of a longer base64 run (a pasted image, a certificate): not that token.
	if (
		layerOf(f.rule) === "format" &&
		/[A-Za-z0-9+]$/.test(left) &&
		/^[A-Za-z0-9+][A-Za-z0-9+/]{15}/.test(text.slice(f.end, f.end + 16))
	)
		return "inside a longer token";
	const typed = saysWhatItIs(f, value, secretJwt);
	// Publishable keys: `pk_live_`, `pk.eyJ`, Datadog `pub…`, PostHog `phc_`, Razorpay key IDs, Supabase `sb_publishable_`,
	// Square app IDs, SonarQube badge tokens.
	// (Also after a label the span took in: `auth=key_id:rzp_live_…`.)
	if (
		(PUBLIC_FORMAT.test(value) ||
			PUBLIC_FORMAT.test(word) ||
			PUBLIC_FORMAT.test(value.replace(/^[A-Za-z][\w.-]{0,40}:/, ""))) &&
		!/^AIza/.test(value)
	)
		return "publishable key";
	// A Basic credential that decodes to a docs placeholder (`user:pass`), whichever layer read it.
	if (/\bBasic[ \t]+$/i.test(left) && isPlaceholderBasic(value)) return "placeholder";
	if (/(?:^|[^\w])pk[._]$/.test(left)) return "publishable key";
	if (typed) return undefined;
	// A status-badge URL's token, made to sit in a README: `dl.circleci.com/status-badge/…?circle-token=…`.
	if (/(?:status-badge|project_badges|\/badges?)\/[^\s"'<>()]*[?&](?:circle-)?token=$/.test(left)) return "badge token";
	if (PUBLISHED_DEFAULTS.some(([v, where]) => v === value && where.test(line + lineAfter))) return "published default";
	// A reCAPTCHA or Turnstile site key where a page or an SDK takes one (its secret key has the same shape).
	if (/(?:ReCaptcha\w*Provider|grecaptcha\.\w+|data-sitekey|sitekey)[ \t"'`=:(,]{0,4}$/i.test(left))
		return "publishable key";
	const serverLine = /server|backend|admin|gemini|genai|generative|vertex/i.test(line);
	// A value under a name that says it's public (`MAPS_BROWSER_KEY`, `STRIPE_PUBLISHABLE_KEY`, `NEXT_PUBLIC_…`),
	// from whichever layer, unless the line says server or Gemini.
	// (A name of key-like words: `Token for the public API:` is a sentence, not a name.)
	if (name && nameClass(name.replace(/\s+/g, "_")) === "public" && /key|token|id\b|dsn|sid/i.test(name) && !serverLine)
		return "public by its name";
	// A random token the unnamed layer guessed at, under a name that says ID or hash (`bridgeSessionId`, `sha`): what the
	// unnamed layer's own name vetoes say, for a finding whose name only this stage sees (a transcript leaf's key).
	if (isGuess(f.rule) && name && ["identifier", "hash"].includes(nameClass(name.replace(/\s+/g, "_"))))
		return "an ID by its name";
	// JWTs meant to be public (anon and publishable roles, published samples). Under a credential's name, only
	// a published sample is, unless the name itself says anon or public: an anon key assigned to `SUPABASE_KEY`
	// is treated as the key it's named; `anon key:` in `supabase status` is what it says.
	if (/^eyJ/.test(word) && isPublicJwt(word, layerOf(f.rule) === "named" && !/anon|public|publishable/i.test(name)))
		return "public JWT";
	// The ID half of an `id:secret` value under a name (`credential: <client id>:<secret>`): the secret half is
	// hidden on its own (named.ts credentialPair).
	// (Not Basic auth's user info, where both halves are the credential: `basic.auth.user.info=<key>:<secret>`.)
	// (Or its secret half already a placeholder: redacting redacted text changes nothing.)
	if (
		isGuess(f.rule) &&
		/^:(?:[A-Za-z0-9+/_~-]{16,}|\[REDACTED )/.test(text.slice(f.end, f.end + 20)) &&
		/[:=][ \t]*["'`]?$/.test(left) &&
		!/user[._-]?info|basic/i.test(name) &&
		isPairLabel(name, value)
	)
		return "ID of an ID and secret pair";
	// Client-side SDK configuration takes public keys: `Bugsnag.start({ apiKey: … })`, `new Pusher({ key: … })`,
	// `braintree.client.create({ authorization: … })`. Not a name that says it's server-side: `new Pusher({ secret })`,
	// `algoliasearch(id, adminKey)`. A positional argument is public unless the SDK takes its admin key in the same
	// place: Algolia's search key and admin key are both `algoliasearch(appId, key)`, so only a search key said so.
	const sdk = clientSdkAt(text, f.start);
	if (sdk && isClientSdkKey(sdk, name, `${above}\n${line}`)) return "client SDK key";
	// A Google API key in a client app's configuration (see isClientGoogleKey).
	if (/^AIza/.test(value) && isClientGoogleKey(text, f.start)) return "client-side Google key";
	// The search-only key of an Algolia DocSearch config (`appId`, `apiKey`, `indexName`), in every docs site;
	// never a key named admin, write or secret.
	if (/^[0-9a-f]{32}$/.test(value)) {
		const near = text.slice(Math.max(0, f.start - 300), f.end + 300);
		const key = /([\w-]+)["']?[ \t]*[:=][ \t]*["'`]?$/.exec(left.slice(-80))?.[1] ?? "";
		if (/\bindexName\b/.test(near) && /\bappId\b/.test(near) && !/admin|write|secret|private|password/i.test(key))
			return "DocSearch key";
	}
	// Public identifiers and keys whose shape or checksum says so.
	if (/^wx[0-9a-f]{16}$/.test(value)) return "WeChat app ID";
	if (
		isNatsPublicKey(value) ||
		isStellarPublicKey(value) ||
		isBase58Address(value) ||
		isXrpAddress(value) ||
		isBech32Address(value)
	)
		return "public key (checksum verified)";
	if (isDerPublicKey(value)) return "DER public key";
	if (isPgpPublicKey(value)) return "OpenPGP public key";
	// Public keys and fingerprints: Nix cache keys (`name:<32 bytes base64>=`), a JWK's public members next to
	// `kty`, SSH fingerprints, base64 of a PEM certificate or public key, anything labelled a public key.
	// (A Nix key's name is a host and a number, `cache.nixos.org-1:`; `ci-bot:<base64>=` is a user and a password.)
	const nixName = /^[\w-]+(?:\.[\w-]+)*-\d+:/;
	const nix = nixName.test(value) ? value : (/(?:^|[^\w.-])([\w-]+(?:\.[\w-]+)*-\d+:)$/.exec(left)?.[1] ?? "") + value;
	if (/^[\w-]+(?:\.[\w-]+)*-\d+:[A-Za-z0-9+/]{43}=$/.test(nix)) return "public key";
	// A Nix signature has the shape of a Nix secret key (a key name and 64 bytes): kept where signatures are listed.
	if (
		/^[\w-]+(?:\.[\w-]+)*-\d+:[A-Za-z0-9+/]{86}==$/.test(nix) &&
		/"signatures"\s*:\s*\[[^\]]*$|(?:^|\n)[ \t]*Sig:[ \t]*[\w.-]*:?$/.test(
			text.slice(Math.max(0, f.start - 2000), f.start),
		) &&
		nameClass(name) !== "credential"
	)
		return "signature";
	if (/^(?:x|y|n|e|crv|kid|x5t)$/.test(name) && inJwk(text, f.start, f.end)) return "public key";
	if ((/(?:SHA256|SHA1|MD5):$/.test(left) || /^(?:SHA256|MD5):/.test(word)) && nameClass(name) !== "credential")
		return "fingerprint";
	// (Base64 of PEM, read whole: a certificate with its key after it isn't public.)
	if (/^LS0tLS1CRUdJTi/.test(value) && isPublicPem(base64Binary(value) ?? "")) return "public certificate";
	// (The label applies to the value right after it, not to everything later on the line.)
	// (`Public Key: main:<base64>`: a key name may sit between; `key id (public half):`, `site key (frontend):`.)
	// (A label alone on the line above counts too: `Public Key:` then the key, as `web-push generate-vapid-keys` prints.)
	const labelLine = line.trim() === "" ? above : line.replace(/[\w.-]{1,60}:$/, "");
	if (
		/\bpublic[\s_-]?key\b|\bpubkey\b|public half/i.test(name) ||
		/(?:\bpublic[\s_-]?key|\bpubkey|public half|\bsite[\s_-]?key)s?\)?(?:\s*\([^)\n]{0,30}\))?(?:\s+is)?[ \t"'`]*[:=]?[ \t"'`]*$/i.test(
			labelLine,
		)
	)
		return "public key";
	if (
		/(?:google-site-verification|msvalidate\.01|facebook-domain-verification|yandex-verification|p:domain_verify)["']?\s+content=["']$/i.test(
			left,
		)
	)
		return "site verification token";
	return undefined;
}

/** An identifier path: `pw`, `this.old_pwd`, `StrTools::unMagic`, `FS->Pass`, `$sql_passwd`, `{$secrets`. */
const PATH = String.raw`\{?${IDENT_PATH}`;

/** Types the platform provides for bytes and keys: a field holding one is declared, not given a value. */
const BUILTIN_TYPE =
	/^(?:(?:Big)?U?[Ii]nt(?:8|16|32|64)Array|Uint8ClampedArray|Float(?:32|64)Array|ArrayBuffer|SharedArrayBuffer|DataView|Buffer|CryptoKey|CryptoKeyPair|KeyObject|ArrayBufferLike)$/;

/** A GraphQL type with its non-null marks and directives: `[String!]!`, `String! @constraint(minLength: 12)`. */
const GRAPHQL_TYPE = /^\[*[A-Z]\w*!?\]*!?(?:[ \t]+@\w+(?:\([^()\n]{0,80}\))?)*$/;

/**
 * Proposals that are code, read from the characters around the span: whatever a rule took for the value
 * after `password=` isn't one when the quote before it closes a string literal and the span is the code
 * between two literals (`"&pwd=" + passwd + "&v="`, `'pass=' . md5($pw) . '&'`, `"<Password>",FS->Pass,"`),
 * a call or subscript cut at its quote (`md5('$password')`, `datastore['PASS']`), a Go struct field's type
 * and tag, a hole in an interpolated string (`$"Pwd={DB_Password};"`), or a SQL bind parameter.
 */
function codeShape(text: string, f: Finding, value: string, left: string): string | undefined {
	const v = value.replace(/^["'`]|["'`]$/g, "");
	const before = left.slice(-1);
	const after = text[f.end] ?? "";
	// (Without contractions: an apostrophe in prose before it, `Here's the fix: export TOKEN='…'`, is no quote.)
	const line = left.slice(left.lastIndexOf("\n") + 1).replace(CONTRACTION, "");
	// A declaration's type, with no value given: `val passwordData: PasswordData?,`, `privateKey: Uint8Array;`.
	// (A type's mark says so, nullable, generic or an array, or a word only types end in, `…Array`, `…Json`, `…Dto`:
	// `SunnyDay`, `BlueKey` are passwords. A generic's arguments may follow the name read: `Branded<string, "Password">;`; Rust's `let password: Secret<String> = …`.)
	if (
		/:[ \t]*$/.test(line) &&
		!f.literal &&
		v === value &&
		(/^[A-Z][a-z0-9]*(?:[A-Z][a-z0-9]*)+(?:<[\w, ]*>)?(?:\[\])?\??$/.test(v) ||
			(/^[A-Z][a-z0-9]+$/.test(v) && text[f.end] === "<") ||
			/^[A-Z][a-z0-9]+<[\w, :<>]*>$/.test(v)) &&
		(/[?<[]/.test(v + text[f.end]) ||
			/(?:Json|Dto|Type|Model|Array|Map|Info|Config|Options|Spec|Request|Response|Result|String|Buffer|Bytes|Holder|Provider)$/.test(
				v,
			)) &&
		readsAsWords(v.replace(/[<?[].*$/, "")) &&
		/^[?;,)]?[ \t]*(?:[;,)=]|\r?$|\n)/.test(
			text
				.slice(f.end, f.end + 204)
				.replace(/^<[^<>\n]{0,200}>/, "")
				.slice(0, 4),
		)
	)
		return "a type";
	// A built-in type's name as a declaration's type, alone or in a union: `secret: Uint8Array;`, `key: Uint8Array | KeyLike`.
	if (
		/:[ \t]*$/.test(line) &&
		!f.literal &&
		v === value &&
		BUILTIN_TYPE.test(v) &&
		/^[ \t]*(?:[;,)=|&}]|\r?$|\n)/.test(text.slice(f.end, f.end + 4))
	)
		return "a type";
	// A GraphQL field's type: a scalar (in a list or not) or a type with a directive, non-null marks and directives after it:
	// `password: String!`, `tokens: [String!]!`, `password: String! @constraint(minLength: 12)`.
	// (A lone `Hunter2!` is a password: the type needs a scalar's name or a directive.)
	if (
		/:[ \t]*$/.test(line) &&
		v === value &&
		GRAPHQL_TYPE.test(v) &&
		(/^\[*(?:String|Int|Float|Boolean|ID)\b/.test(v) || v.includes("@"))
	)
		return "a type";
	// An operator at the edge: `+ passwd +`, `, 40, true, 20, `, `) { |a| …`, `+= decipher.final(…)`, `!== form.password`.
	if (
		/^\s*[)\]]*\s*(?:[+.,)]|\+=|-=|\.=|!==?|===?|\|\||&&|<<|\.\.)\s/.test(v) ||
		/\s(?:[+.,(]|\|\||&&|<<|\.\.)\s*$|\S[,(]\s+$/.test(v)
	)
		return "code between string literals";
	// Without spaces, the operator must follow the quote that closed a literal and lead into a name: `'+pass+'`, `".htmlspecialchars($x)."`.
	// (The quote closes a literal when the line has an even number of them up to it: `"x=" + y` vs `pw = "+Xk9…+"`.)
	const upTo = line + (v !== value ? value[0] : "");
	const q = upTo.slice(-1);
	const closes = /["'`]/.test(q) && upTo.replace(/\\./g, "").split(q).length % 2 === 1;
	const splice = new RegExp(String.raw`^(?:\+|\.|,|\.\.|\|\|)(${PATH})(?:\(|\[|(?:\+|\.|,|\.\.|\|\|)$)`).exec(
		v.trimEnd(),
	);
	// (Parity breaks across lines and HTML attributes; a name with a sigil, a member or a call is code anyway.)
	// (Only after a quote, and the name a name: `.GJP9Evi(` alone is a password. Without a closed literal before
	// it, only a sigil, a member path or a call says code: `$sql_passwd`, `this.old_pwd`, `str(pw)`.)
	// (A call's name reads as words: `,X9MY$(^JM…` is a password.)
	const codey =
		splice &&
		(/^\$[A-Za-z_]/.test(splice[1]) ||
			/\.|->|::/.test(splice[1]) ||
			(v.trimEnd()[1 + splice[1].length] === "(" && readsAsWords(splice[1]))) &&
		splice[1].length >= 3 &&
		(splice[1].length > 4 || /^\$?[a-z_][a-z0-9_]*$/.test(splice[1]));
	if (splice && (/["'`]/.test(before) || v !== value) && isNameLike(splice[1]) && (closes || codey))
		return "code between string literals";
	// Whatever starts with punctuation after the quote that closed the literal holding the name is code:
	// `"Password:"),h?m.default.createElement(`, `"pass=");`, `'token:']`.
	// (Blanks first too: VB's `" & txtPassword.Text & "`, Elixir's `<>`, Haskell's `++`, MATLAB's juxtaposition.)
	if (closes && v === value && (/^[)\],;?:|&+.]/.test(v) || /^[ \t]/.test(v))) return "code after a string literal";
	// A literal that starts a string built with code: `"password=" + cnti.password`, `"root@" + host`, `" --password-file=" + p`.
	// (PHP's and Perl's `.` joins only before a variable, a call or a blank: `'…' . $x`; `' .env` is a file's name.)
	if (
		/[=:@/&?;,\s-]$|\\[nrt]$/.test(v) &&
		/^["'`][ \t]*(?:\+[ \t]*[$@A-Za-z_(]|\.\.[ \t]*[$@A-Za-z_(]|<<[ \t]*[$@A-Za-z_(]|\.[ \t]*[$@]|\.[ \t]+[A-Za-z_(]|\.(?=\w*\())/.test(
			text.slice(f.end, f.end + 40),
		)
	)
		return "start of a built string";
	// The next attribute's name: `placeholder="Enter Password:" name="password"`.
	if (/^\s+[A-Za-z_][\w-]*=$/.test(v) && /^["']/.test(after)) return "attribute name";
	// A call or subscript cut at its argument's quote: `md5(` and `credentials[` before the quote that opens the argument,
	// `URLEncoder.encode(password, ` before the next one's, `result[0` before its `]`. (A quote that closes a literal,
	// by the line's count of it, ends a password: `"Winter(24"`, `-p'Harbor(99'`, `-u 'admin:a22F(UG,'`.)
	const opens = /["'`]/.test(after) && (line + value).replace(/\\./g, "").split(after).length % 2 === 1;
	const cut = new RegExp(String.raw`^(?:${PATH}[([])+(?:(?<index>\$?\d{1,3})|${PATH}\s*,\s*)?$`).exec(v);
	if (cut && isNameLike(v) && (cut.groups!.index !== undefined ? after === "]" : opens)) return "call or subscript";
	// Unquoted code that refers to a credential by name: `passwd: account.password`, `pwd=m_password;`.
	// (Its credential part as names are written, so `Company.Password1` in an env line is a password.)
	if (v === value && !/["'`]/.test(before) && isCredentialReference(v.trim())) return "reference";
	// An identifier ending a struct or object literal's line: `IssuerPrivateKey: keyRSA2048,` (a literal would be quoted).
	if (
		!f.literal &&
		v === value &&
		!/["'`]/.test(before) &&
		/^[A-Za-z_$][\w$]*$/.test(v) &&
		/[a-z]/.test(v) &&
		/[A-Z_]/.test(v) &&
		readsAsWords(v) &&
		/^,[ \t]*(?:\/\/[^\n]*)?(?:\r?\n|$)/.test(text.slice(f.end, f.end + 200))
	)
		return "identifier";
	// A Go struct field: `Password string \`json:"password"\``.
	if (/^(?:\*|\[\])*[\w.]+\s+`[a-z]+:"/.test(v)) return "struct field";
	// A hole in an interpolated or format string: C# `$"…{DB_Password}"`, Python f-strings and `.format`, Rust `format!`.
	if (
		before === "{" &&
		after === "}" &&
		new RegExp(`^${PATH}$`).test(v) &&
		(/\$@?"|@\$"|\bf["']|format!?\(|String\.Format\(/.test(line) ||
			/^\}[^\n]*\.format\(/.test(text.slice(f.end, f.end + 200)))
	)
		return "template hole";
	// A SQL bind parameter: `WHERE password=@CONTRASEÑA`, `:password`, `?`.
	// (A SQL token in a SQL statement: after a comparison or in `VALUES (…)`, in a statement its keywords say is one, in
	// capitals or starting the line; not cmd's `set NAME=@…` nor a sentence's "update the password to @…".)
	if (
		!/^structure:cli/.test(f.rule) &&
		/^[@:?][\p{L}_][\p{L}\d_]*$/u.test(v) &&
		v === value &&
		!/["'`]/.test(before) &&
		/(?:[=<>]|\(|,)[ \t]*$/.test(before) &&
		!/^[ \t]*set[ \t]+[\w.-]+=$/i.test(line) &&
		(/\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|VALUES|SET)\b/.test(line) ||
			/^[ \t]*(?:select|insert|update|delete)\b/i.test(line))
	)
		return "bind parameter";
	return undefined;
}
