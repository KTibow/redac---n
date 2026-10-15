/**
 * What a value can be shown to be public or a stand-in by, whatever found it: keys published for browsers (a
 * publishable key's format, a Google API key used client-side), values published as examples in specifications and
 * documentation, placeholders and masked or truncated keys, JSON Web Tokens anyone can read or sign, and keys passed to
 * browser and mobile SDKs. The detectors
 * consult these to drop stand-ins early; the decision stage (policy.ts) to keep public values whoever proposed them.
 */
import { base64Binary } from "./base64.ts";
import { naturalness } from "./charlm.ts";
import { hmacSha256 } from "./hmac.ts";
import { type Argument, callArguments } from "./calls.ts";
import { lastText } from "./lines.ts";

/** Keys that are public by design: publishable, site and project keys meant for browsers. */
export const PUBLIC_FORMAT =
	/^(?:pk_(?:live|test)_|NRJS-[0-9a-f]{19}$|rzp_(?:live|test)_[A-Za-z0-9]{14}$|pk\.(?:eyJ|[A-Za-z0-9]{20})|pub[0-9a-f]{32}$|phc_|sb_publishable_|sq0idp-|sqb_[0-9a-f]{40}$)/;

/** Where the bracket that encloses the end of `before` opens, skipping balanced pairs, or -1. */
function openingBracket(before: string): number {
	let depth = 0;
	for (let i = before.length - 1; i >= 0; i--) {
		if (before[i] === "}" || before[i] === ")") depth++;
		else if (before[i] === "{" || before[i] === "(") {
			if (depth === 0) return i;
			depth--;
		}
	}
	return -1;
}

/** Where the bracket that encloses the start of `after` closes, skipping balanced pairs, or `after.length`. */
function closingBracket(after: string): number {
	let depth = 0;
	for (let i = 0; i < after.length; i++) {
		if (after[i] === "{" || after[i] === "(") depth++;
		else if (after[i] === "}" || after[i] === ")") {
			if (depth === 0) return i;
			depth--;
		}
	}
	return after.length;
}

/**
 * A Google API key in a client app's configuration, where it ships to every user (Google: "API keys for
 * Firebase are not secret"): the object a Firebase web or Flutter config builds, `google-services.json`,
 * the Maps JS loader URL, an Android manifest's or the iOS SDK's Maps key. Elsewhere an `AIza` key is
 * hidden, whatever it's named (`GOOGLE_MAPS_API_KEY=` in a server's environment, a Gemini key): an
 * unrestricted server key costs money. Used by the decision stage, policy.ts.
 */
export function isClientGoogleKey(text: string, start: number): boolean {
	const before = text.slice(Math.max(0, start - 600), start);
	const line = before.slice(before.lastIndexOf("\n") + 1);
	if (/maps\.googleapis\.com\/maps\/api\/js\?(?:[^\s"'&]*&)*key=$/.test(line)) return true;
	// A HAR's record of that loader's request: its `queryString` entry, `{"name": "key", "value": "…"}`.
	if (
		/"url"\s*:\s*"https:\/\/maps\.googleapis\.com\/maps\/api\/js\?[^"]*"(?:(?!"url")[^])*"queryString"\s*:\s*\[[^\]]*\{\s*"name"\s*:\s*"key"\s*,\s*"value"\s*:\s*"$/.test(
			before,
		)
	)
		return true;
	// Expo's app config, `ios.config.googleMapsApiKey` and `android.config.googleMaps.apiKey`: the Maps SDKs' keys,
	// built into the app.
	if (
		/\bconfig["']?\s*:\s*\{[^{}]*?(?:["']?googleMapsApiKey|["']?googleMaps["']?\s*:\s*\{[^{}]*?["']?apiKey)["']?\s*:\s*["']$/.test(
			before,
		)
	)
		return true;
	// An Android manifest's Maps key and the iOS SDK's: the app ships them. (The manifest's within its `<meta-data>` tag,
	// its attributes on one line or several, in either order.)
	if (/GMSServices\.provideAPIKey\(\s*"$|GMSPlacesClient\.provideAPIKey\(\s*"$/.test(line)) return true;
	// The files Firebase's tools generate into an app: the Android plugin's `values.xml` (`<string
	// name="google_api_key">`), and iOS's `GoogleService-Info.plist` (`<key>API_KEY</key>` beside `GOOGLE_APP_ID`).
	if (/<string\b[^<>]*\bname="google(?:_crash_reporting)?_api_key"[^<>]*>$/.test(line)) return true;
	if (
		/<key>API_KEY<\/key>\s*<string>$/.test(before) &&
		/<key>(?:GOOGLE_APP_ID|GCM_SENDER_ID)<\/key>/.test(text.slice(Math.max(0, start - 3000), start + 3000))
	)
		return true;
	const tag = /<meta-data\b[^<>]*android:value="$/.exec(before)?.[0];
	if (
		tag &&
		(/android:name="com\.google\.android\.geo\.API_KEY"/.test(tag) ||
			/^[^"<>]*"[^<>]*android:name="com\.google\.android\.geo\.API_KEY"/.test(text.slice(start, start + 600)))
	)
		return true;
	// A server's key by name (Gemini, Vertex), whatever is around it.
	if (/server|backend|admin|gemini|genai|generative|vertex|functions:(?:config|secrets)|^[ \t]*export[ \t]/i.test(line))
		return false;
	// A Firebase web config: the object the key sits in has `authDomain` or `messagingSenderId`, or is
	// passed to `initializeApp(` / named `firebaseConfig`; or the line calls the key Firebase's. Not merely
	// a Firebase config nearby (a Gemini key declared next to one is a server key).
	const after = text.slice(start, start + 600);
	const lineAfter = after.split("\n", 1)[0];
	if (/firebase/i.test(line + lineAfter) || /GoogleService-Info|google-services\.json/.test(before)) return true;
	// The object or call it sits in (`{ … }`, Dart's `FirebaseOptions( … )`), else its paragraph.
	const open = openingBracket(before);
	const close = closingBracket(after);
	let object: string;
	if (open >= 0) object = before.slice(open) + after.slice(0, close);
	else {
		// No enclosing brackets in view (a fragment of a config): its sibling lines, at the key line's indentation.
		const indent = /^[ \t]*/.exec(line)![0];
		const sibling = (l: string) => l.startsWith(indent) && !/^[ \t]/.test(l.slice(indent.length)) && l.trim() !== "";
		const up = before.split("\n").slice(0, -1).reverse();
		const down = after.split("\n").slice(1);
		const siblings = (ls: string[]) => {
			const stop = ls.findIndex((l) => !sibling(l));
			return stop < 0 ? ls : ls.slice(0, stop);
		};
		object = [...siblings(up), line + lineAfter, ...siblings(down)].join("\n");
	}
	// (The bracket must be the config's own: `firebaseConfig = {`, `initializeApp({`, `FirebaseOptions(`, an Angular
	// environment's `firebase: {`.)
	return (
		/authDomain|messagingSenderId|"api_key"\s*:\s*\[/.test(object) ||
		(open >= 0 &&
			/(?:firebaseConfig\w*\s*[:=]\s*\{|\bfirebase["']?\s*:\s*\{|initializeApp\(\s*\{?|FirebaseOptions\(|"api_key"\s*:\s*\[\s*\{)$/.test(
				before.slice(0, open + 1),
			))
	);
}

/**
 * Example keys from vendor docs and RFCs, which are published on purpose: RFC 6749's authorization code,
 * tokens and client credentials, RFC 6750's bearer token, RFC 7636's PKCE verifier and challenge, RFC 5849's
 * OAuth 1 examples, RFC 6265's and 9110's, and the TOTP secret every authenticator library's docs use. Kept in
 * every syntax (policy.ts).
 */
export const PUBLISHED_EXAMPLE =
	/SplxlOBeZQQYbYS6WxSbIA|2YotnFZFEjr1zCsicMWpAA|tGzv3JOkF0XG5Qx2TlKWIA|s6BhdRkqt3|7Fjfp0ZBr1KtDRbnfVdmIw|gX1fBat3bV|czZCaGRSa3F0MzpnWDFmQmF0M2JW|mF_9\.B5f-4\.1JqM|8xLOxBtZp8|dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk|E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM|hh5s93j4hdidpola|hdk48Djdsa|kd94hf93k423kf44|pfkkdhi9sl3r4s00|nnch734d00sl2jdk|9djdj82h48djs9d2|kkk9d7dh3k39sjv7|j49sk3j29djd|dh893hdasih9|31d4d96e407aad42|aGVsbG86d29ybGQ=|QWxhZGRpbjpvcGVuIHNlc2FtZQ==|JBSWY3DPEHPK3PXP|frAQBc8Wsa1xVPfvJcrgRYwTiizs2trQ|GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ/;
/**
 * Published examples by their whole or a fixed part, found anywhere in a value: the vendors' own (AWS's
 * `AKIAIOSFODNN7EXAMPLE` and the `…EXAMPLE`, `…EXAMPLEKEY` its docs end every key with; Stripe's, GitHub's and jwt.io's
 * documented keys; MySQL's marker of a locked account's password), and filler (`deadbeefdeadbeef`, `EXAMPLEEXAMPLE`).
 * (A documented key's vendor prefix is escaped, `ghp\x5f`, so this source isn't taken for a live key by a scanner.)
 */
const EXAMPLES = new RegExp(
	PUBLISHED_EXAMPLE.source +
		"|" +
		/(?:deadbeef|DEADBEEF|cafebabe|CAFEBABE){2}|SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c|sk\x5ftest_4eC39HqLyjWDarjtT1zdp7dc|ghp\x5f16C7e42F292c6912E7710c838347Ae178B4a|AKI\x41IOSFODNN7|wJalrXUtnFEMI\/K7MDENG|EXAMPLE(?:KEY)?$|(?:EXAMPLE){2}|AbCdEfGh|aBcDeFgH|THISISACOMBINATIONOFINVALIDSALTANDPASSWORDTHATMUSTNEVERBRBEUSED/
			.source,
);

/**
 * Words that say a value stands in for one: `YOUR_API_KEY_HERE`, `my-fake-token`, `INVALID_TOKEN`, `sk_test_xxxxxxxx`,
 * `<redacted>`, `not-a-real-key`, `changeMe`. Whole words, in any of their cases (`There` holds no `here`).
 */
const STAND_IN = (() => {
	const words = [
		"fake",
		"invalid",
		"notvalid",
		"dummy",
		"changeme",
		"change[-_ ]?me",
		"replace[-_ ]?me",
		"placeholder",
		"redacted",
		"obscured",
		"masked",
		"hidden",
		"removed",
		"omitted",
		"scrubbed",
		"censored",
		"sanitized",
		"example",
		"your",
		"here",
		"not[-_ ]?a[-_ ]?real",
		"not[-_ ]?real",
		"changed",
	];
	const cases = words.flatMap((w) => [
		w,
		w.toUpperCase(),
		w[0].toUpperCase() + w.slice(1),
		w.replace(/(\])\?me$/, "$1?Me"),
	]);
	// (A word starts after a non-letter or at a camel-case hump, and ends before a non-lower-case letter.)
	return new RegExp(
		String.raw`(?:(?<![A-Za-z])|(?<=[a-z])(?=[A-Z]))(?:${[...new Set(cases)].join("|")}|[xX]{3,})(?![a-z])`,
		"g",
	);
})();

/** What separates the parts of a placeholder:`YOUR_API_KEY_HERE`, `example-token`, `<your-key>`, `sk-[redacted]`. */
const PLACEHOLDER_SEPARATORS = /[-_. :/[\]<>(){}*]+/;

/**
 * A value made of stand-in words and plain ones: each part between separators is a plain one (a small number, a short
 * part like a vendor's `sk_`, `ghp_`, or a word), or holds a stand-in word joined to a word of its own by a case
 * boundary (`exampleToken`) or to the last characters a mask shows (`xxxx1234`). A stand-in word joined to anything
 * else is a weak password built on one, not a placeholder: `Changed2024`, `Example7392`, `ExampleXkqz`,
 * `Fake!Orbit2291`, `invalidXk9mP2vQ7tL4`, `Q7tL4wR8nZ_HERE91kd`.
 */
function isStandIn(token: string): boolean {
	if (token.search(STAND_IN) < 0) return false;
	const isWord = (p: string) => /^[A-Za-z]+$/.test(p) && naturalness(p.toLowerCase()) > 0.3;
	const parts = token.split(PLACEHOLDER_SEPARATORS).filter(Boolean);
	return parts.every((part) => {
		const standIns = [...part.matchAll(STAND_IN)];
		if (!standIns.length) return /^\d{1,4}$/.test(part) || /^[A-Za-z]{1,4}$/.test(part) || isWord(part);
		// (The parts around the stand-in words; the mask `xxxx` shows the last 1 to 4 characters after it.)
		let from = 0;
		return [...standIns.map((m) => m.index), part.length].every((to, i) => {
			const joined = part.slice(from, to);
			const mask = /^[xX]+$/.test(standIns[i - 1]?.[0] ?? "");
			from = to + (standIns[i]?.[0].length ?? 0);
			return joined === "" || isWord(joined) || (mask && /^[A-Za-z0-9]{1,4}$/.test(joined));
		});
	});
}

/** A masked key, a few characters shown around the stars: `sk-****abcd`, `ab****yz`. */
const MASKED = /^[^*\s]{0,8}\*{4,}[^*\s]{0,8}$/;

/**
 * A token shown cut short, as tools print keys: a vendor's prefix and a few of the key before an ellipsis and a few
 * after (`sk-proj-abc...xyz`, `AKIA…WXYZ`, `...4f2a`), or words after it (`sk-...set-in-1password`). Not a password
 * with an ellipsis in it, a word before it (`Winter...2024`, `Maple...River3012`), or a key with only its front cut
 * off (`...` then 300 characters).
 */
export function isTruncated(token: string): boolean {
	const m = /^([\w+/=:.-]{0,32}?)(?:\.\.\.|…)([\w+/=:.-]{0,40})$/.exec(token);
	if (!m) return false;
	// (Up to 16 characters before the ellipsis, or a longer vendor prefix of short parts and up to 10 of the key:
	// `sk-ant-api03-Zx9K…`, `github_pat_11ABCDE0Y0…`.)
	const prefix = /^(?:[a-z][a-z0-9]{1,7}[-_]){2,4}(?=[A-Za-z0-9+/=]{0,10}$)/.exec(m[1])?.[0];
	if (m[1].length > 16 && !prefix) return false;
	const runs = (side: string) => side.match(/[A-Za-z]+/g) ?? [];
	const isWord = (run: string) => naturalness(run.toLowerCase()) > 0.3;
	// (A person's word: capitalised, or five letters that read as one; a vendor's prefix is neither: `sk-proj`, `AKIA`,
	// and a long one's words are the vendor's: `github_pat_`.)
	return (
		!runs(m[1].length > 16 ? m[1].slice(prefix!.length) : m[1]).some(
			(run) => /^[A-Z][a-z]{3,}$/.test(run) || (run.length >= 5 && isWord(run)),
		) &&
		(m[2].length <= 8 || runs(m[2]).every((run) => run.length <= 2 || isWord(run)))
	);
}

/** A template's holes: `{{ secrets.DB }}`, `${API_KEY}`, `%(password)s`, `{db_pass}`, `<password>`. */
const HOLE = /\{\{[^{}]*\}\}|\$\{[A-Za-z_][\w.:/-]*\}|%\(\w+\)s|\{[a-z_][a-z0-9_.-]{2,60}\}|<[a-z][a-z_ .-]{2,60}>/g;

/**
 * A stand-in for a key, not one: mostly one repeated character (`sk_test_xxxxxxxx`, `ghp_0000…`, `AKIAXXXX…`; not
 * base64 of bytes with many zeros, `TlRMTVNTUAADAAAAGAAY…`, where the other characters vary), a published
 * example or a placeholder word, a counting sequence, or a template whose literal text is too short or too
 * plain to be a secret on its own (`Bearer ${TOKEN}`, `postgres://${USER}:${PASS}@db:5432/app`; not
 * `{;${EC}4S*A)HbUw`).
 */
export function isPlaceholder(token: string): boolean {
	const counts = new Map<number, number>();
	for (let i = 0; i < token.length; i++) counts.set(token.charCodeAt(i), (counts.get(token.charCodeAt(i)) ?? 0) + 1);
	// (Of the characters that aren't the repeated one or a separator, few: a prefix and the filler.)
	const separators = (token.match(/[-_.:/]/g) ?? []).length;
	for (const n of counts.values())
		if (n >= 6 && n >= token.length * 0.4 && token.length - n - separators <= token.length * 0.35) return true;
	if (EXAMPLES.test(token) || isStandIn(token) || isSequential(token) || isTruncated(token) || MASKED.test(token))
		return true;
	if (!/[{<]|%\(/.test(token)) return false;
	// (A hole in a docs' syntax, `<…>` or `{…}`, names something: `<password>`, not `<qjk>`.)
	const rest = token.replace(HOLE, (h) =>
		/^[<{][^{$]/.test(h) && naturalness(h.slice(1, -1).replace(/[_ .-]+/g, " ")) <= 0.5 ? h : "",
	);
	if (rest === token) return false;
	const letters = rest.replace(/[^A-Za-z0-9]+/g, " ").trim();
	return rest.replace(/\s/g, "").length < 8 || naturalness(letters) > 0.5;
}

/**
 * Counting sequences, after a vendor's prefix: `abcdef123456`, `sk_test_1234567890abcdef`, hex test vectors like
 * `000102030405…` or `fffefdfc…`. Four in five characters (or bytes) count; a person's password made of a run and a word
 * (`123456789Maple6543%`) is a password.
 */
function isSequential(token: string): boolean {
	const body = token.replace(/^(?:[A-Za-z]{1,8}[_-])+/, "");
	if (body.length < 8) return false;
	// Characters inside runs of 4+ counting steps, one step all the way (`abcd`, `4321`, `aaaa`; not `9887`).
	let inRuns = 0;
	let run = 1;
	let step = 2;
	for (let i = 1; i <= body.length; i++) {
		const next = i < body.length ? body.charCodeAt(i) - body.charCodeAt(i - 1) : 2;
		if (Math.abs(next) <= 1 && (run === 1 || next === step)) run++;
		else {
			if (run >= 4) inRuns += run;
			// (The pair that broke the run may start the next: `aaab`… `bcd`.)
			run = Math.abs(next) <= 1 ? 2 : 1;
		}
		step = next;
	}
	if (inRuns >= body.length * 0.8) return true;
	// Hex as bytes, the same way: bytes inside runs of 4+ that step by 0, 1 or 0x11, one step all the way (`00010203`,
	// `aabbccdd`, `fffefdfc`). (`7f3b9c2e1d4a5b6c` has steps of 0x11 here and there, not runs: a key. Digits alone step
	// by 0x11 as a number's pairs do, `12233445`, `98879887`: a PIN, not bytes counting.)
	if (/^[0-9a-f]+$/i.test(body) && body.length % 2 === 0) {
		const strides = /[a-f]/i.test(body) ? [0, 1, 0x11] : [0, 1];
		const n = body.length / 2;
		let inByteRuns = 0;
		let byteRun = 1;
		let step = NaN;
		for (let i = 1; i <= n; i++) {
			const d = i < n ? parseInt(body.slice(i * 2, i * 2 + 2), 16) - parseInt(body.slice(i * 2 - 2, i * 2), 16) : NaN;
			if (strides.includes(Math.abs(d)) && (byteRun === 1 || d === step)) byteRun++;
			else {
				if (byteRun >= 4) inByteRuns += byteRun;
				// (The pair that broke the run may start the next.)
				byteRun = strides.includes(Math.abs(d)) ? 2 : 1;
			}
			step = d;
		}
		return inByteRuns >= n * 0.8;
	}
	return false;
}

/**
 * A JWT meant to be public or published: Supabase anon keys, the jwt.io and RFC samples. With
 * `samplesOnly`, only the published samples (an anon key assigned to a name is still hidden).
 */
export function isPublicJwt(token: string, samplesOnly = false): boolean {
	if (!token.startsWith("eyJ")) return false;
	const [head, body] = token.split(".");
	const payload = base64Binary(body ?? "");
	if (!payload) return false;
	// (jwt.io's sample claims say a sample when a public key signed them, RS256's and the others'; an HMAC token is a
	// sample only by its docs key, signedWithDocsKey, as one signed with a real secret may copy the claims.)
	// (The samples name no issuer and set no expiry: a token that does, `"iss":"https://dev-…auth0.com/"`, came from a
	// real one, whose test user may well be John Doe.)
	const hmac = /"alg"\s*:\s*"HS\d+"/.test(base64Binary(head) ?? "");
	return (
		(!samplesOnly && /"role"\s*:\s*"anon"/.test(payload)) ||
		(!hmac &&
			(/"sub"\s*:\s*"1234567890"/.test(payload) || /"name"\s*:\s*"John Doe"/.test(payload)) &&
			!/"(?:iss|exp)"\s*:/.test(payload)) ||
		signedWithDocsKey(token)
	);
}

/**
 * The keys docs and tutorials sign their example HS256 tokens with, each one spelled as a stand-in: jwt.io's, the
 * jsonwebtoken README's and express-session's.
 */
const DOCS_JWT_KEYS = ["your-256-bit-secret", "your-secret-key", "your_jwt_secret", "shhhhh", "keyboard cat"];

/**
 * The weak keys both docs and apps in development sign with. A token signed with one is a sample only when its claims
 * say nothing of a session (PyJWT's `{"a": "b"}`, `{"some": "payload"}`); one with a subject, a user or a time is that
 * app's bearer credential.
 */
const WEAK_JWT_KEYS = ["secret", "test", "key", "changeme", "password"];

/** Claims a session's token carries: a subject, a user, an expiry or an issue time. */
const SESSION_CLAIM = /"(?:sub|exp|iat|nbf|jti|uid|user(?:_?id|name)?|email|role|scope|sid|session(?:_?id)?)"\s*:/i;

/**
 * Whether an HS256 JWT's signature verifies under a docs key (DOCS_JWT_KEYS), or under a weak key with no session
 * claims (WEAK_JWT_KEYS): anyone can mint it, so it's a sample.
 */
function signedWithDocsKey(token: string): boolean {
	const [header, payload, signature] = token.split(".");
	if (!signature || !/"alg"\s*:\s*"HS256"/.test(base64Binary(header) ?? "")) return false;
	const utf8 = new TextEncoder();
	const message = utf8.encode(`${header}.${payload}`);
	const keys = SESSION_CLAIM.test(base64Binary(payload) ?? "") ? DOCS_JWT_KEYS : [...DOCS_JWT_KEYS, ...WEAK_JWT_KEYS];
	return keys.some((key) => base64url(hmacSha256(utf8.encode(key), message)) === signature);
}

const base64url = (bytes: Uint8Array) =>
	btoa(String.fromCharCode(...bytes))
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/, "");

/**
 * Browser and mobile SDK initialisers, whose keys are public by design: calls (`Sentry.init(`, `new Pusher(`,
 * `loadStripe(`) or config objects (`firebaseConfig = {`, `_rollbarConfig = {`). Not a vendor word alone:
 * `IntercomClient(…)` is a server SDK, a bare `createInstance(` is any factory unless Optimizely's is imported (see
 * clientSdkAt), and a comment naming the vendor initialises nothing. Nor `Rollbar.init(`, which Node servers call with
 * their server token, as `new Rollbar(` is: only the browser snippet's `_rollbarConfig` says client.
 */
const CLIENT_SDK_CALL =
	/(?:\b(?:AnalyticsBrowser\.load|analytics\.load|Bugsnag\.start|optimizely(?:Sdk)?\.createInstance|createInstance|(?:new\s+)?GrowthBook|Purchases\.configure|braintree\.\w+\.create|(?:new\s+)?AdyenCheckout|branch\.init|initializeApp|new\s+mapboxgl\.\w+|(?:new\s+)?Pusher|Sentry\.init|posthog\.init|amplitude\.(?:init|getInstance\(\)\.init)|mixpanel\.init|LDClient\.initialize|datadogRum\.init|DD_RUM\.init|heap\.load|algoliasearch|docsearch|instantsearch|Intercom|loadStripe|Stripe|Square\.payments)\s*\(|\b(?:_rollbarConfig|firebaseConfig\w*)\s*[:=]\s*\{)/g;

/**
 * The client SDK initialiser whose arguments `at` is directly inside, or inside an object or list given as one of them,
 * if the call starts within 300 characters before it: its call as written (`algoliasearch(`).
 */
export function clientSdkAt(text: string, at: number): string | undefined {
	if (!hasClientSdkCall(text)) return undefined;
	const from = Math.max(0, at - 300);
	let last: RegExpExecArray | undefined;
	for (const m of text.slice(from, at).matchAll(CLIENT_SDK_CALL)) last = m;
	if (!last || (/^createInstance/.test(last[0]) && !/@optimizely\//.test(text.slice(0, at)))) return undefined;
	const holding = (args: Argument[] | undefined) => args?.find((a) => a.start <= at && at < a.end);
	const arg = holding(callArguments(text, from + last.index + last[0].length));
	if (!arg) return undefined;
	const inside =
		arg.literal || at === arg.start || (/^[{[]/.test(arg.text) && holding(callArguments(text, arg.start + 1)));
	return inside ? last[0] : undefined;
}

/** Whether a text calls a client SDK's initialiser anywhere: most don't, and need no look 300 characters back. */
const hasClientSdkCall = lastText((text) => new RegExp(CLIENT_SDK_CALL.source).test(text));

/** The parameters client SDKs take public keys under (positional arguments count too). */
export const PUBLIC_SDK_PARAM =
	/^(?:api_?key|key|client_?key|client_?token|sdk_?key|app_?id|application_?id|dsn|authorization|publishable_?key|public_?key|site_?key|access_?token|token|search_?(?:only_?)?api_?key)$/i;
