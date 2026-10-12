/**
 * Random tokens with no recognizable format: the key passed straight to `Client("…")`, the token in a
 * neutral `X-Lumen:` header or a webhook URL's path, the value pasted into chat. Two questions decide
 * each candidate:
 *
 * 1. Is it random? Measured against what a random string of the same length and alphabet would show
 *    (random.ts), and against a model of the identifiers and words people write (charlm.ts).
 * 2. Does its context make a random string a secret or a hash? `api_key=`, `Client(`, `/hooks/` and
 *    "here's your token" say secret; `sha256:`, `"integrity":`, `commit `, `cursor=` say hash or ID.
 *
 * Hard rules sit outside the score: hex, UUIDs and hash-prefixed values never count without a
 * credential name; API object IDs (`toolu_`, `chatcmpl-`) never count, payment and SaaS IDs (`cus_`, `pi_`)
 * only when passed to a call, a header or a command. Values public by design are decided in policy.ts.
 */
import { base64Binary, base64Bytes } from "./base64.ts";
import { naturalness } from "./charlm.ts";
import { contextOf, type Context, Doc } from "./context.ts";
import { isCredentialName, isVendorClient, mentionsCredential } from "./names.ts";
import { isPlaceholder } from "./public.ts";
import { alphabetOf, entropyZ, shape, type Alphabet } from "./random.ts";
import type { Finding, Guessing } from "./types.ts";
import { trailingRun } from "./lines.ts";
import {
	ENCRYPTION_WRAPPER,
	ANALYTICS_COOKIE,
	isIdentifierShaped,
	isInert,
	isPodName,
	PASSWORD_HASH_IN_TEXT,
	isWordsValue,
	readsAsWords,
} from "./values.ts";
import { predict } from "./model.ts";
import { backslashesBefore, escapeLength } from "./syntax.ts";
import { asciiSet, longRuns } from "./runs.ts";
import { urlAround } from "./urls.ts";

/**
 * IDs that LLM APIs and GitHub put everywhere in transcripts: public by design, whatever the context. Each prefix with
 * its own separator: OpenAI's function calls are `fc_…`, and Firecrawl's API keys `fc-…`. (And Fly.io's image tags,
 * `deployment-<ULID>`; GitHub's advisory IDs, `GHSA-m7j5-r2p5-c39r`, in their own alphabet; GitHub's GraphQL node IDs,
 * `PRR_kwDOarJHIC…`, a type and the base64 of a MessagePack array of a version and integers; AWS's resource IDs,
 * `vpc-0bddc3783c4aae5fc`, a type and 8 or 17 hex digits; Anthropic's request IDs, `req_011CwAGnE86XcDAUWRVjP5fG`.)
 */
const API_OBJECT_ID =
	/^(?:(?:vpc|subnet|sg|i|ami|vol|snap|eni|igw|rtb|acl|nat|eipalloc|tgw|tgw-attach|lt|pcx|vpce|dopt|cgw|vgw|fs|fsmt)-[0-9a-f]{8}(?:[0-9a-f]{9})?$|[OI]v23li[A-Za-z0-9]{14}$|req_011[A-Za-z0-9]{21}$|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}$|[A-Z]{1,6}_(?:k[gw]|l[AQ])D[M-P]|(?:toolu|srvtoolu|msg|msgbatch|call|fc|resp|asst|thread|run|step|batch|vs|proj|file)_|(?:chatcmpl|cmpl|modr|ftjob|ft|img|org|file|deployment)-)/;
/**
 * Prefixes of payment, messaging and SaaS object IDs (Stripe `cus_`, `pi_`, `ch_`, Twilio, Svix…). Some
 * are also prefixes of keys (`re_` is Resend's), so these are public only outside a key's place (keyPlace).
 */
const OBJECT_ID =
	/^(?:env|usr|svc|srv|db|setl|order|job|raysubmit|ins|client|sia|sms|idn|pri|pro|sub|txn|ctm|add|biz|dsc|dpl|prj|team|conn|directory|user|ap|in|ta|fu|vol|sb|sess(?=_)|we|promo|qt|cs|dp|cus|pi|ch|il|ii|price|prod|evt|acct|tr|po|pm|seti|src|card|ba|btok|tok|re|plink|si|pmc|ipi|cbtxn|ich|ic|fee|link|req|test_clock|whe|wh|ca|cn|du|py|mandate|pyr|trr|setatt|sched|subi|ri|gsk_live_?)[-_]/;
/** Right after an encryption wrapper (values.ts ENCRYPTION_WRAPPER), or SOPS's `,iv:` and `,tag:` fields, or Splunk's `$7$`. */
const AFTER_ENCRYPTION_WRAPPER = new RegExp(String.raw`(?:${ENCRYPTION_WRAPPER}|,iv:|,tag:|(?:^|[\s=:"'])\$[17]\$)$`);

/** Shapes that are IDs or encodings, not keys. */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ULID = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$|^[0-7][0-9a-hjkmnp-tv-z]{25}$/;
/** Words of a path segment a secret sits under: a webhook's, a bot's, a token's, a share link's or an invite's. */
const HOOK_WORD =
	/^(?:hooks?|webhooks?|incomingwebhooks?|bots?|catch|tokens?|keys?|secrets?|apikeys?|invites?|invitations?|resets?|verify|magic|unsubscribe|shares?|links?|push|ping|triggers?|deploy|ingest|notify|callbacks?|incoming|dl|downloads?|send|services)$/i;

/** A path segment a secret sits under (`/hooks/<token>`, `/deploy-hooks/<id>`, `/api_keys/<key>`, Slack's `/t/<id>`, `/s/<share>`). */
function isHookSegment(segment: string): boolean {
	return (
		/^[st]$/i.test(segment) || segment.split(/[-_.]/).some((w) => HOOK_WORD.test(w)) || /^api[-_]?keys?$/i.test(segment)
	);
}

export interface Candidate {
	start: number;
	end: number;
	token: string;
	/**
	 * What the run had before the token that the token drops (`_`, `-`, `+`, `=`): its context is read from before it,
	 * as `Client("` and not `Client("_`.
	 */
	lead?: string;
}

/** The shortest token judged: 16 characters, about 95 bits in base62, the shortest key length vendors issue. */
const MIN_TOKEN = 16;
/** The characters a candidate run is made of: base64 and base64url, `=` for padding and `name=value`. */
const CANDIDATE_SET = asciiSet("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-");
/** A value that is one such run, whole. */
const CANDIDATE = new RegExp(`^[A-Za-z0-9+/=_-]{${MIN_TOKEN},}$`);

/**
 * A run of what `encodeURIComponent` leaves as it is, with `%XX` escapes: a percent-encoded value (`nPdn…%2FFuUO…`,
 * `%40scope%2Fname`). A base64 value's `/`, `+` and `=` are escaped in one.
 */
const PERCENT_RUN = /(?:[A-Za-z0-9_.~-]|%[0-9A-Fa-f]{2}){16,}/g;

/**
 * Runs of token characters long enough to be a key. A run that is a path (`/api/v1/<id>/users`) or
 * dotted (`a.b.c`) is split into its segments, each judged alone. A percent-encoded run that decodes to one token is
 * judged whole, as its decoded value (`token` then differs from the text it spans); its pieces between the escapes
 * aren't judged apart.
 */
export function candidates(text: string): Candidate[] {
	const out: Candidate[] = [];
	const encoded: [number, number][] = [];
	if (text.includes("%")) {
		for (const m of text.matchAll(PERCENT_RUN)) {
			if (!m[0].includes("%")) continue;
			let token = "";
			try {
				token = decodeURIComponent(m[0]);
			} catch {} // an escape that isn't UTF-8
			if (token.length > 256 || !CANDIDATE.test(token)) continue;
			out.push({ start: m.index, end: m.index + m[0].length, token });
			encoded.push([m.index, m.index + m[0].length]);
		}
	}
	// (Both in the text's order: the encoded run a token run may be in is the first not ended before it.)
	let k = 0;
	for (const [runStart, runEnd] of longRuns(text, CANDIDATE_SET, MIN_TOKEN)) {
		while (k < encoded.length && encoded[k][1] <= runStart) k++;
		if (k < encoded.length && runStart >= encoded[k][0] && runEnd <= encoded[k][1]) continue;
		if (runEnd - runStart > 256) continue; // blobs: images, certificates, bundles; longer tokens are caught by format or header
		const run = text.slice(runStart, runEnd);
		// `name=value` inside a run (query strings, form bodies): split at an `=` that isn't padding.
		for (const [eqOff, piece] of splitKeep(run, /=(?=[A-Za-z0-9+/_-])/g)) {
			const parts =
				/\//.test(piece) && !isBase64Run(piece, text, runStart + eqOff)
					? splitKeep(piece, "/")
					: [[0, piece] as [number, string]];
			for (const [off, part] of parts) {
				let lead = part.match(/^[=_+-]*/)![0].length;
				const dropped = part.slice(0, lead);
				// The tail of an escape before the run: `\n<token>`, `\u001b[32m<token>`, `ESC[0m<token>`, `%2b<token>`.
				const at = runStart + eqOff + off;
				const before = text.slice(Math.max(0, at - 12), at);
				if (backslashesBefore(text, at) % 2) lead += escapeLength(text, at - 1) - 1;
				else if (/(?:\x1b|\\u001b|\\x1b|\\e|\\033)\[$/i.test(before))
					lead += part.match(/^[\d;]*[A-Za-z]/)?.[0].length ?? 0;
				else if (text[at - 1] === "%" && /^[0-9A-Fa-f]{2}/.test(part)) lead += 2;
				const body = part
					.slice(lead)
					.replace(/=+$/, "")
					.replace(/[_-]+$/, "");
				if (body.length < MIN_TOKEN) continue;
				const pad = part.slice(lead + body.length).match(/^={0,2}/)![0];
				const start = runStart + eqOff + off + lead;
				// (Not after an escape's tail, `\n_`: the left side is read from the token as it was.)
				out.push({
					start,
					end: start + body.length + pad.length,
					token: body + pad,
					...(dropped && lead === dropped.length ? { lead: dropped } : {}),
				});
			}
		}
	}
	return out;
}

/**
 * A run with `/` that is base64 rather than a path: of base64's alphabet, not inside a URL or after a path's characters,
 * and with `+` or padding, or with no segment that reads as a word (`src`, `heads`, `Users`), wherever it stands (a
 * quoted value, a shell argument, a line of its own). `/tmp/tmpab12cd34`, `refs/heads/main` and `api/v1/users` are paths.
 */
function isBase64Run(run: string, text: string, at: number): boolean {
	if (/[\w.~-]$/.test(text[at - 1] ?? "") || urlAround(text, at, at + run.length) >= 0) return false;
	// (With a prefix: `sha512-<base64>==`. Otherwise `_` and `-` are base64url's, which has no `/`.)
	if (/[+]|=$/.test(run)) return true;
	if (/[_-]/.test(run)) return false;
	// (A path has a segment that is a word, `tmp`, `heads`, `Users`; a key's segments are random, wherever it stands.)
	return !run.split("/").some((seg) => /^(?:[a-z]{3,}|[A-Z][a-z]{2,})$/.test(seg) && readsAsWords(seg));
}

/** `run` cut at each `sep` (a string, or a global regex), as [offset, piece], the separators dropped. */
function splitKeep(run: string, sep: string | RegExp): [number, string][] {
	const out: [number, string][] = [];
	let at = 0;
	if (typeof sep === "string") {
		for (let i = run.indexOf(sep); i >= 0; i = run.indexOf(sep, at)) {
			out.push([at, run.slice(at, i)]);
			at = i + sep.length;
		}
	} else {
		for (const m of run.matchAll(sep)) {
			out.push([at, run.slice(at, m.index)]);
			at = m.index + m[0].length;
		}
	}
	out.push([at, run.slice(at)]);
	return out;
}

/** Bytes a base64 or hex token decodes to, or 0. Hash outputs are 16, 20, 28, 32, 48 or 64 bytes. */
function decodedBytes(token: string, alphabet: Alphabet): number {
	if (alphabet === "hex" || alphabet === "HEX") return token.length % 2 ? 0 : token.length / 2;
	if (alphabet !== "b64" && alphabet !== "b64url" && alphabet !== "b62") return 0;
	const body = token.replace(/=+$/, "");
	return Math.floor((body.length * 3) / 4);
}

/** The byte lengths of digests: MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512. */
const DIGEST_BYTES = [16, 20, 28, 32, 48, 64];
/** The unpadded base64 lengths of the digests that padding doesn't mark: MD5, SHA-1, SHA-256, SHA-512 (a SHA-384 or SHA-224 is as long as a random key of that size, so no length vouches for it). */
const UNPADDED_DIGEST_LENGTHS = [22, 27, 43, 86];

/** Whether a token is the size of a digest: hex of one, or base64 of one (padded, or of a length only a digest has). */
function isHashSize(token: string, alphabet: Alphabet): boolean {
	if (!DIGEST_BYTES.includes(decodedBytes(token, alphabet))) return false;
	return alphaIsHex(alphabet) || /=$/.test(token) || UNPADDED_DIGEST_LENGTHS.includes(token.length);
}

/** What base64 decodes to: printable text, binary, or not base64 at all. */
function decodesTo(token: string): "text" | "binary" | "none" {
	const bin = /^[A-Za-z0-9+/_-]+={0,2}$/.test(token) ? base64Binary(token) : undefined;
	if (!bin) return "none";
	let printable = 0;
	for (let i = 0; i < bin.length; i++) {
		const c = bin.charCodeAt(i);
		if ((c >= 32 && c < 127) || c === 9 || c === 10 || c === 13) printable++;
	}
	return printable >= bin.length * 0.95 ? "text" : "binary";
}

/** Whether base64 decodes to ordinary text (words, JSON, a path) rather than another random token. */
function decodedIsNatural(token: string): boolean {
	// (Printable text first: random bytes hold a space or a slash by chance.)
	if (decodesTo(token) !== "text") return false;
	const d = base64Binary(token)?.trim();
	if (d === undefined) return false;
	// A token of its own, decoded (a key encoded twice, as a Kubernetes Secret holds a base64 key): not text, though its
	// own base64 has a slash.
	if (/^[A-Za-z0-9+/_-]{16,}={0,2}$/.test(d) && naturalness(d) < 0.5) return false;
	return /\s/.test(d) || /^[{[<"]/.test(d) || naturalness(d) > 0.5 || /^[\w.-]+@|^https?:|\//.test(d);
}

function alphaIsHex(a: Alphabet): boolean {
	return a === "hex" || a === "HEX";
}

export interface Features {
	token: string;
	alphabet: Alphabet;
	length: number;
	natural: number;
	entropyZ: number;
	switches: number;
	digits: number;
	upper: number;
	lower: number;
	vendorPrefix: boolean;
	decodes: "text" | "binary" | "none";
	hashSize: boolean;
	leftHashy: boolean;
	ctx: Context;
	/** What the token dropped from the front of its run (Candidate.lead); its context's left side ends before it. */
	lead: string;
	secretFile: boolean;
}

export function features(doc: Doc, c: Candidate, secretFile: boolean): Features {
	const text = doc.text;
	const s = shape(c.token);
	const alphabet = alphabetOf(c.token);
	return {
		token: c.token,
		alphabet,
		length: c.token.length,
		natural: naturalness(c.token),
		entropyZ: entropyZ(c.token, alphabet),
		switches: s.expectedSwitches > 0 ? s.switches / s.expectedSwitches : 0,
		digits: s.digit / s.length,
		upper: s.upper / s.length,
		lower: s.lower / s.length,
		// `acme_live_8f7Qx…`, `tok-9fK2…`: a short lowercase word, a separator, then a random body.
		vendorPrefix:
			/^[a-z]{2,10}(?:_(?:live|test|prod|dev|sk|pk|key|api))?[_-][A-Za-z0-9]{16,}$/.test(c.token) &&
			naturalness(c.token.slice(c.token.search(/[_-][A-Za-z0-9]{16,}$/) + 1)) < 0,
		decodes: alphabet === "b64" || alphabet === "b64url" || alphabet === "b62" ? decodesTo(c.token) : "none",
		hashSize: isHashSize(c.token, alphabet),
		leftHashy:
			/hash|digest|checksum|sha\d|md5|integrity|fingerprint|etag|nonce|commit|revision|cursor|ksuid|ulid|uuid|guid|playlist|video|chain|mask|example|signature|\bsig\b|\btx\b|txid|transaction|block|address|public/i.test(
				text.slice(Math.max(0, c.start - 80), c.start),
			),
		ctx: contextOf(doc, c.start - (c.lead?.length ?? 0), c.end),
		lead: c.lead ?? "",
		secretFile,
	};
}

/** Whether `token` is the salt or digest of a password hash: one found whole in the word around it covers it. */
function isPasswordHashPart(left: string, token: string, right: string): boolean {
	const before = trailingRun(left, /[\s"'`;()]/);
	const word = before + token + /^[^\s"'`;()]*/.exec(right)![0];
	for (const m of word.matchAll(PASSWORD_HASH_IN_TEXT))
		if (m.index <= before.length && m.index + m[0].length >= before.length + token.length) return true;
	return false;
}

/** The start of a URL, `://` on, up to a host that serves public IDs, and what follows it (a host alone ends at a path, a port, a query or a fragment). */
const PUBLIC_ID_URL =
	/^:\/\/(?:[\w-]+\.)*(?:(?:(?:image|stream)\.mux\.com|lh\d\.googleusercontent\.com|kroki\.io|lore\.kernel\.org|(?:docs|drive|sheets|slides|forms|script|sites|colab\.research)\.google\.com|youtube\.com|youtu\.be|figma\.com|notion\.so|notion\.site|loom\.com|vimeo\.com|miro\.com|canva\.com|mp\.weixin\.qq\.com|1drv\.ms|gist\.github(?:usercontent)?\.com|forms\.gle|goo\.gl|bit\.ly|t\.co|calendly\.com|medallia\.com|surveymonkey\.com|qualtrics\.com|typeform\.com)(?=[/:?#]|$)|join\.slack\.com\/t\/[^/\s]+\/shared_invite|vercel\.com\/[^/\s]+\/[^/\s]+\/|airtable\.com\/(?:app|shr|tbl)|(?:x|twitter)\.com\/\w+\/status\/\d+\?|nel\.heroku\.com\/reports)/i;

/**
 * Public namespaces that IDs sit in: the text just before a token (`spotify:track:`, `pkg:npm/`, `pin-sha256="`), just
 * after it (`.oastify.com`, `._domainkey`), or a host earlier in its URL whose paths and queries carry public
 * document and video IDs (`docs.google.com`, `youtube.com`). An ID there is the namespace's, not a credential.
 */
const PUBLIC_ID_CONTEXTS: { left?: RegExp; right?: RegExp; url?: RegExp }[] = [
	// SDP stream identifiers (`a=ssrc:… cname:…`, `msid:`), Google image thumbnails (`tbn:`).
	{ left: /\b(?:cname|msid|label|mslabel):$|\btbn:$/ },
	// LVM UUIDs (`PV UUID 3rsJgY-…`, `Found duplicate PV <32>`).
	{ left: /\b(?:[PVL]V|VG)(?: UUID)?[ \t]+$|duplicate PV[ \t]+$/ },
	// DKIM selectors, HPKP pins, ACME challenge files.
	{ right: /^\._domainkey\b/ },
	{ left: /\bpin-sha256=["']?$|acme-challenge\/$/ },
	// A Snowflake storage integration's external ID, given to AWS as public config: `<ACCOUNT>_SFCRole=<n>_<base64>`.
	{ left: /_SFCRole=\d+_$/ },
	// Out-of-band testing hosts and canary tokens (`<id>.oastify.com`), a malicious package's name in an advisory.
	{
		right:
			/^\.(?:oastify\.com|burpcollaborator\.net|interact\.sh|oast\.(?:fun|pro|live|site|online|me)|canarytokens\.com)\b|^ \((?:npm|pypi|PyPI|crates\.io|RubyGems|NuGet|Go|Maven)\)/,
	},
	{ left: /pkg:(?:npm|pypi|gem|cargo|nuget)\/$|npmjs\.com\/package\/$|pypi\.org\/project\/$/ },
	// A Firebase app ID's tail: `1:123456789012:web:3f2a8c1e…`.
	{ left: /(?:^|[^\w:])\d:\d{6,15}:(?:web|android|ios):$/ },
	{ left: /\bspotify:(?:track|album|artist|playlist|show|episode|user):$/ },
	// A domain's verification record in DNS (`atlassian-domain-verification=…`, `google-site-verification=…`): public.
	{ left: /\b[\w-]*-verification=$/ },
	// GitHub's push protection bypass links, Go's checksum database tree head, GitHub Actions' OIDC request URL.
	{
		left: /secret-scanning\/unblock-secret\/$|go\.sum database tree\s*(?:\\n|\n)\d+\s*(?:\\n|\n)$|actions\.githubusercontent\.com\/$/,
	},
	// Services that put public document, image, diagram, video and invite IDs in their URLs (the host of the token's own URL, any subdomain).
	{ url: PUBLIC_ID_URL },
	{ left: /\bgdrive:\/\/\S*$/ },
];

/** The calls whose argument is a public key or ID: a vendor's loader (`analytics.load`, `window.posthog.init`, `fbq`) or a database reference's path (`doc`, `getDoc`). A name of its own: `setPrefs` is not `FS`. */
const PUBLIC_KEY_CALLEE =
	/^(?:doc|collection|child)$|(?:^|\.)(?:getDoc|setDoc|authenticatedContext|branch\.init|analytics|ttq|posthog|mixpanel|amplitude|heap|hj|clarity|rudderanalytics|plausible|intercom|crisp|grecaptcha|fbq|gtag|Sentry|LogRocket|FullStory)(?:\.(?:load|init|execute|identify|render|config))?$/i;
/** FullStory's global, upper case only (`fs` is Node's). */
const FULLSTORY_GLOBAL = /(?:^|\.)FS(?:\.(?:load|init|execute|identify|render|config))?$/;

/** Whether the token sits in a public namespace (PUBLIC_ID_CONTEXTS). */
function inPublicNamespace(f: Features): boolean {
	const left = f.ctx.left.replace(/\\\//g, "/");
	// (The token's own URL: from the last `://` before it, so a host earlier in the line, or in a parameter before this one, doesn't count.)
	const url = f.ctx.inUrl ? left.slice(left.lastIndexOf("://")) : "";
	return PUBLIC_ID_CONTEXTS.some(
		(c) => (!c.url || c.url.test(url)) && (!c.left || c.left.test(left)) && (!c.right || c.right.test(f.ctx.right)),
	);
}

/** A hook's, a ping's or a download's URL, whose path segments are secrets: `/hooks/<token>`, `hc-ping.com/<uuid>`. */
function isHookUrl(f: Features): boolean {
	if (!f.ctx.inUrl) return false;
	// (The parent or a segment up to three above it, `/services/T…/B…/<token>`; or the host, `hc-ping.com`, `hooks.slack.com`.)
	const ancestors = /\/((?:[^/\s]+\/){1,4})$/.exec(f.ctx.left)?.[1].split("/").filter(Boolean) ?? [];
	return (
		ancestors.some(isHookSegment) ||
		/^bot\d/.test(ancestors.at(-1) ?? "") ||
		// (The token's own URL's host: an earlier URL on the line is another's.)
		/:\/\/(?:[\w-]+\.)*(?:hooks?|webhooks?|hc-ping|ping)[.-]/i.test(f.ctx.left.slice(f.ctx.left.lastIndexOf("://")))
	);
}

/** The token is the user information of a URL: `https://<token>@host`. */
const isUserinfo = (f: Features) => /^[^\s"'<>@?#/]*@[\w-]+(?:\.[\w-]+)+/.test(f.ctx.right);

/**
 * A URL path segment that names an object: under a collection (`/v1/predictions/<id>`), or anywhere when its shape
 * says ID (a file name, `<key>~noop.jpeg`, `<id>.png`; short; one case). A mixed-case random run of 20 or more is a
 * token whatever path it's in, unless the host serves media (`inews.gtimg.com`) or a content word is its parent
 * (`/article/<id>`). Never a hook's URL, the user part before an `@`, or a secret file's value.
 */
function urlPathId(f: Features): string | undefined {
	if (f.ctx.syntax !== "path" || f.secretFile || isHookUrl(f) || isUserinfo(f)) return undefined;
	if (/^[a-z][a-z-]{2,30}s$/i.test(f.ctx.pathParent) && !isHookSegment(f.ctx.pathParent)) return "collection-id";
	if (f.ctx.nameClass === "credential") return undefined;
	const mediaHost =
		/:\/\/(?:[\w-]+\.)*[\w-]*(?:img|image|images|cdn|static|media|pic|pics|photo|photos|thumb|thumbs|resiz|assets?)[\w-]*\.[\w.-]+\/[^\s"']*$/i.test(
			f.ctx.left,
		);
	const contentParent =
		/^(?:article|articles|post|posts|p|story|stories|news|item|items|video|videos|watch|status|statuses|question|questions|answer|issue|issues|pull|commit|blob|tree|wiki|doc|docs|d|album|track|playlist|episode|product|products)$/i.test(
			f.ctx.pathParent,
		);
	const t = f.token;
	const tokenShaped =
		t.length >= 20 && /[a-z]/.test(t) && /[A-Z]/.test(t) && /\d/.test(t) && !mediaHost && !contentParent;
	return /^[~.][A-Za-z0-9]{2,6}\b|^~|^=[swhc]\d+/.test(f.ctx.right) || !tokenShaped ? "url-path-id" : undefined;
}

/**
 * Hex, hashes and IDs until a key context says otherwise: under a credential's name, or (32 characters or more) a
 * neutral name with a credential word, a handover or an argument to a vendor's client (`algoliasearch(appId,
 * '8f2a…')`). In a secret file a whole value is suspect, but not hex inside a larger value (an ARN, a URL, a path).
 */
function hexVeto(f: Features): string | undefined {
	const t = f.token;
	const cred = f.ctx.nameClass === "credential";
	const wholeValue = f.secretFile && /(?:[=:][ \t]*["']?|^[ \t]*)$/.test(f.ctx.left);
	// Hex in dashed groups: traceparent `00-<32>-<16>-01`, X-Ray `1-<8>-<24>`, UUID variants. IDs, not keys.
	if (/^[0-9a-f]{1,8}(?:-[0-9a-f]{2,32}){2,}$/i.test(t) && !cred) return "hex-groups";
	const keyContext =
		f.ctx.nameClass === "neutral" &&
		(mentionsCredential(f.ctx.name) || f.ctx.handover || (f.ctx.syntax === "call" && isVendorClient(f.ctx.name))) &&
		!f.ctx.hashPhrase;
	// A word prefix before hex (`build-9f3a…`, `etag-…`, `jb-env-…`): judged as the hex it carries.
	const hexTail = /^(?:[a-z][a-z0-9]*[-_])+([0-9a-f]{16,})$/i.exec(t)?.[1];
	if (hexTail && !cred && !wholeValue && !((f.ctx.lineCredential || keyContext) && hexTail.length >= 32))
		return "hex-suffix";
	if (!alphaIsHex(f.alphabet) || cred || wholeValue) return undefined;
	return t.length < 32 || !keyContext ? "hex" : undefined;
}

/**
 * A place keys are passed, where an ID seldom stands alone, so an ID's shape (a ULID, a cuid, an object ID's prefix, a
 * slug) says nothing there: an HTTP header (`X-Lumen: …`, not a log's `Error: Post …`), a handover ("your key: …"), a
 * command's arguments after a prompt or a script's path (`$ ./notify.sh prod …`, not a chat's `job id …`), or a
 * client's constructor or a vendor's SDK (`new Client("k3j9…")`).
 */
function keyPlace({ ctx }: Features): boolean {
	return (
		(ctx.syntax === "header" && (/-/.test(ctx.name) || /^authorization$/i.test(ctx.name))) ||
		ctx.handover ||
		(ctx.shellArg && /^[ \t]*(?:[$#>][ \t]|sudo[ \t]|\.{0,2}\/)/.test(ctx.left)) ||
		(ctx.syntax === "call" &&
			(/client|auth|token|key|secret|credential|api|sdk/i.test(ctx.name) || isVendorClient(ctx.name)))
	);
}

/**
 * A place IDs are written: under a name of an identifier's class or ending in `id` (`job_id`, `orderId`), as a URL's
 * or a REST path's segment (`PATCH /api/posts/<id>`; not a query's value, where keys go too), or after the word `id`
 * (`job id <id>`, `ID: <id>`).
 */
function idPlace({ ctx }: Features): boolean {
	return (
		ctx.nameClass === "identifier" ||
		/(?:^|[^A-Za-z])(?:id|ID|Id)s?$|[a-z](?:Id|ID)s?$|^uids?$/.test(ctx.name) ||
		(ctx.inUrl && /\/$/.test(ctx.left)) ||
		/(?:^|[\s"'(])(?:\/[\w.~-]+)+\/$/.test(ctx.left) ||
		/\b(?:id|uid|ref)[ \t]*[:=#]?[ \t]*["'`]?$/i.test(ctx.left)
	);
}

/** Crockford's base32, as a ULID's timestamp is written. */
function crockford(s: string): number {
	let n = 0;
	for (const c of s.toUpperCase()) n = n * 32 + "0123456789ABCDEFGHJKMNPQRSTVWXYZ".indexOf(c);
	return n;
}

/** Whether milliseconds since the epoch fall between 2015 and 2035, as an ID made now has. */
function isRecentTime(ms: number): boolean {
	return ms >= Date.UTC(2015, 0) && ms < Date.UTC(2035, 0);
}

/**
 * Hard rules: shapes and contexts that rule a candidate out whatever its score, each by the reason it gives, in the
 * order they're tried. Most hold whatever names the token (digits, placeholders, public IDs, encrypted values,
 * versions, hashes); those about what a name or a place says (an ID's name, a data field, a file path, a wrapped
 * blob, a UUID) yield to a credential's name, which says more. A rule is a reason and its test, or a function that
 * gives one of several reasons (urlPathId, hexVeto).
 */
type Veto =
	[reason: string, vetoes: (f: Features, t: string, cred: boolean) => boolean] | ((f: Features) => string | undefined);
const VETOES: Veto[] = [
	// The token's own shape.
	["digits", (_, t) => /^\d+$/.test(t)],
	["placeholder", (_, t) => isPlaceholder(t)],
	// Hex of one short unit written over and over (`Key = ef012345ef012345ef012345ef012345`): a filler someone typed, not
	// key bytes, which never repeat in step. (Other alphabets' fillers, `foobarfoobar…`, are in the model's training
	// negatives, which a veto would change.)
	["repeating", (f, t) => alphaIsHex(f.alphabet) && /^(.{2,8}?)\1{2,}$/.test(t)],
	["public-id", (_, t) => API_OBJECT_ID.test(t)],
	// Ciphertext inside an encryption wrapper: sops `ENC[AES256_GCM,data:…`, Spring Cloud Config `{cipher}…`, jasypt
	// `ENC(…)`, WildFly `${VAULT::…}`, IIS `[enc:IISCngProvider:…`, Splunk's `$7$…`, Pulumi's passphrase-encrypted
	// values (`v1:<salt>:v1:<nonce>:<ciphertext>`, `v1:<nonce>:<ciphertext>`). (Not Jenkins' or Maven's `{…}`: see
	// policy.ts.)
	[
		"encrypted",
		(f) =>
			/(?:^|["'\s])v1:(?:[A-Za-z0-9+/=]{8,}:v1:)?(?:[A-Za-z0-9+/=]{8,}:)?$/.test(f.ctx.left) &&
			/^(?::[A-Za-z0-9+/=]+)*(?:["'\s,]|$)/.test(f.ctx.right),
	],
	// (And DigitalOcean App Platform's `EV[1:<nonce>:<ciphertext>]`.)
	["encrypted", (f) => AFTER_ENCRYPTION_WRAPPER.test(f.ctx.left)],
	// Analytics and load-balancer cookies: `__cf_bm=`, `cf_clearance=`, `AWSALB=`, `ai_user=`, PostHog `ph_…`.
	[
		"analytics-cookie",
		(f) => ANALYTICS_COOKIE.test(/(?:^|[\s;"'])([\w.-]{1,60})[ \t]*=[ \t]*$/.exec(f.ctx.left)?.[1] ?? ""),
	],
	// Tracking parameters in URLs (Amazon `pf_rd_r=`, `utm_*`, click IDs) and Go build IDs.
	[
		"tracking-param",
		(f) =>
			/[?&](?:pf_rd_\w+|pd_rd_\w+|utm_\w+|fbclid|gclid|msclkid|dclid|mc_eid|igshid|_hsenc|crid|qid|sprefix|ved|usg|ei|sei|iflsig|refRID|sca_esv|sca_upv|sxsrf|oq|aqs|gs_lcp|gs_lp|uact|rlz|ictx|vin)=$/i.test(
				f.ctx.left,
			),
	],
	["build-id", (f) => /\bBuildID=\S*$/.test(f.ctx.left)],
	["public-id", (f) => inPublicNamespace(f)],
	// A hashed host in `~/.ssh/known_hosts` (`|1|<salt>|<HMAC-SHA1 of the host name>`, both base64 of 20 bytes): public, as the host names are.
	[
		"hashed-host",
		(f, t) => /^[A-Za-z0-9+/]{27}=$/.test(t) && /(?:^|[\s,])\|1\|(?:[A-Za-z0-9+/]{27}=\|)?$/.test(f.ctx.left),
	],
	// Facebook post IDs, LVM's PV UUIDs, OpenRouter generations, Cloudflare rays, a Snowflake external ID as a whole token.
	[
		"public-id",
		(_, t) =>
			/^pfbid0[1-9A-HJ-NP-Za-km-z]{30,}$|^[A-Za-z0-9]{6}(?:-[A-Za-z0-9]{4}){5}-[A-Za-z0-9]{6}$|^gen-\d{10}-[A-Za-z0-9]{12,40}$|^[0-9a-f]{16}-[A-Z]{3}$|^[A-Z0-9]+_SFCRole=/.test(
				t,
			),
	],
	// A protobuf message in base64 (grpcurl, gRPC-web, Google API page tokens): it parses to the last byte and
	// carries readable text. Random key bytes almost never parse, let alone with a readable field.
	["encoded message", (_, t) => /^[A-Za-z0-9+/_-]+={0,2}$/.test(t) && isProtobufText(t)],
	// A file in base64, by its format's magic number: gzip (`H4sI`: Google's `stick=`, kroki's diagrams), PNG, JPEG, GIF,
	// PDF, zip, RIFF (WebP, WAV), WebAssembly. A key's random bytes start so once in millions at most.
	[
		"encoded file",
		(_, t) => /^(?:H4sI|iVBORw0KGg|\/9j\/|R0lGOD[dl]h|JVBERi|UEsDB|UklGR|AGFzb)[A-Za-z0-9+/_-]{12}/.test(t),
	],
	// DNSSEC record data; OpenPGP fingerprints and key IDs where an OpenPGP tool or a fingerprint is mentioned.
	[
		"public-id",
		(f) => /\bIN[ \t]+(?:RRSIG|DNSKEY|CDNSKEY|DS|NSEC3?|NSEC3PARAM|TLSA|SSHFP)\b/.test(`${f.ctx.left} ${f.ctx.right}`),
	],
	[
		"public-id",
		(f, t) =>
			/^(?:[0-9A-Fa-f]{40}|[0-9A-Fa-f]{16})$/.test(t) &&
			/\b(?:gpg2?|gpgv|pacman-key|apt-key)\b|\bfpr\b|fingerprint/i.test(`${f.ctx.left} ${f.ctx.right}`),
	],
	// The argument of an option that takes OpenPGP key IDs (`gpg --sign-key <40 hex>`, `pacman-key --lsign-key`,
	// `--recv-keys <id> <id>`, `--default-key <16 hex>`): what the option says, whatever else is on the line.
	[
		"key-id-option",
		(f, t) => /^(?:0x)?(?:[0-9A-Fa-f]{40}|[0-9A-Fa-f]{16}|[0-9A-Fa-f]{8})$/.test(t) && KEY_ID_OPTION.test(f.ctx.left),
	],
	// Model names (`diffusiongemma-26B-A4B-it-GGUF`, `Llama-3.1-8B-Instruct`), Ollama tags, and long hyphenated slugs.
	[
		"model-name",
		(_, t) =>
			/^[A-Za-z][\w.]*(?:-[\w.]+){2,}$/.test(t) &&
			t
				.split("-")
				.some((p) =>
					/^\d+(?:\.\d+)?[BbMmKk]$|^(?:A\d+B|GGUF|AWQ|GPTQ|EXL2|MLX|it|Instruct|instruct|chat|Chat|base|Base|hf|HF|Q\d_K(?:_[SML])?|fp16|bf16|int[48])$/.test(
						p,
					),
				),
	],
	[
		"slug",
		(_, t) =>
			/^[a-z][a-z0-9]*(?:-[a-z0-9]+){4,}$/.test(t) &&
			t.split("-").filter((p) => naturalness(p) > 0.3 || /^\d+$/.test(p)).length * 2 >= t.split("-").length,
	],
	// A JWK's public members (`n`, `e`, `x`, `y`, `x5c`, `x5t`); a shell's `-n` isn't one.
	[
		"data-name",
		(f) => /^(?:n|e|x|y|x5c|x5t)$/.test(f.ctx.name) && f.ctx.jwk && !/(?:^|\s)-[a-z]\s*["']?$/.test(f.ctx.left),
	],
	// An object storage key (`'Bucket': 'b', 'Key': '<sha>/dist/…'`, `<Key>` in S3's XML): a path, not a credential.
	["object-key", (f) => /^key$/i.test(f.ctx.name) && (/\bbucket\b/i.test(f.ctx.near) || /^\//.test(f.ctx.right))],
	// C's 64-bit literals (`0x1f911b719147c712ull`), rustc's codegen units (`uv_auth.<hash>-cgu.0`) and its v0 mangled
	// symbols (`_RNvCs30UZn7PijB2_3uvx4main`: `_R`, then path tags and length-prefixed identifiers).
	[
		"number",
		(f, t) =>
			/^0x[0-9a-fA-F]+(?:u?ll?|ULL?|LL?)$/.test(t) || (/^[0-9a-f]{16}-cgu$/.test(t) && /^\.\d/.test(f.ctx.right)),
	],
	[
		"mangled-symbol",
		(f, t) => /^R[CMXYNIBS][A-Za-z0-9_]*\d[a-z_]{2,}\w*$/.test(t) && /(?:^|[^A-Za-z0-9])_$/.test(f.ctx.left + f.lead),
	],
	// A function's name, called, or an object's or a class's whose method is: `EVP_PKEY_get1_DH(pkey)`,
	// `X25519PrivateKey.from_private_bytes(raw)`.
	["callee", (f, t) => /^(?:\.[A-Za-z_$][\w$]*)*\(/.test(f.ctx.right) && /^[A-Za-z_$][\w$]*$/.test(t)],
	// A type name: `H225_ArrayOf_CryptoH323Token`, its parts words, acronyms and numbers (each lower-case run follows a
	// capital: no digit before one).
	["identifier-shaped", (_, t) => /^[A-Z][A-Za-z0-9]*(?:_[A-Z][A-Za-z0-9]*){2,}$/.test(t) && !/\d[a-z]/.test(t)],
	// Codecov's report anchors (`#diff-<base64 of a file path>`), GitHub's diff anchors (`/files#diff-<sha256>`, to a
	// line `…R55`), Alpine's APK checksums (`Z:Q1<base64 SHA-1>=`, 30 characters; in a diff, `+Z:…`).
	[
		"hash-prefix",
		(f, t) =>
			(/^diff-[A-Za-z0-9+/=_-]{8,}$/.test(t) && decodedIsNatural(t.slice(5))) ||
			/^diff-[0-9a-f]{40,64}(?:[LR]\d+)?$/.test(t) ||
			(/^Q1[A-Za-z0-9+/]{27}=$/.test(t) && /(?:^|[\s"'+-])[CZ]:$/.test(f.ctx.left)),
	],
	// Part of a password hash (bcrypt, argon2, crypt, Django, LDAP): kept, as the name layer keeps them.
	["password-hash", (f, t) => isPasswordHashPart(f.ctx.left, t, f.ctx.right)],
	// AWS unique IDs of roles, users, groups, policies and instance profiles, and CloudFront key pair IDs.
	["aws-unique-id", (_, t) => /^(?:AROA|AIDA|AGPA|ANPA|ANVA|AIPA|APKA)[A-Z0-9]{12,20}$/.test(t)],
	// (In a key's place the same prefixes are credentials: Resend `re_…`, Wompi `prod_events_…`.)
	["object-id", (f, t) => OBJECT_ID.test(t) && !keyPlace(f)],
	["hash-prefix", (f) => f.ctx.hashPrefix],
	// Signatures by name, Gemini's `thoughtSignature` among them; a `sig` only when longer than an HMAC key; a mail's
	// DKIM or ARC signature (`b=`), which every receiving server checks.
	[
		"public-signature",
		(f, t) =>
			/signatures?$/i.test(f.ctx.name) ||
			(/(?:^|[^a-z])sigs?$/i.test(f.ctx.name) && t.length > 64) ||
			(f.ctx.name === "b" && /\b(?:DKIM-Signature|ARC-Message-Signature|ARC-Seal):/i.test(f.ctx.near)),
	],
	// Accessors, page tokens, hashes and IDs by name: Vault `token_accessor`, `nextPageToken`, detect-secrets'
	// `hashed_secret`, `node_id`, `job_id`.
	[
		"id-name",
		(f, _, cred) =>
			!cred &&
			(/accessor$|^(?:open|union)_?id$|(?:^|[_-]|next|prev)page_?token$|^(?:cursor|continuation(?:_?token)?)$|^(?:app_?id|to_?user|from_?user|key_?id|kid|InResponseTo|AssertionID|SessionIndex|slug)$|^hash(?:ed)?_|(?:^|[_\s-])id$|(?:request|trace|correlation|span|message|event|transaction|amzn-request)[-_]?id$|(?:^|[_-])(?:prefix|hint|last4|suffix)$/i.test(
				f.ctx.name,
			) ||
				/[a-z](?:Id|ID)$/.test(f.ctx.name)),
	],
	// Named as data: `"embedding": "…"`, `frame_796=…`, `mac = …`, `cnonce=…`. (Digests, nonces and IVs by name are
	// hashes: `name-hash` below.)
	[
		"data-name",
		(f, _, cred) =>
			!cred &&
			/^(?:data|embeddings?|vectors?|payload|blob|frame(?:_?\d+)?|thumbnail|bytes|mac|cnonce|opaque|protected|aad)$/i.test(
				f.ctx.name,
			),
	],
	// Where it sits: a file path, a PEM block of public material, a line of a wrapped blob.
	["fs-path", (f, _, cred) => f.ctx.fsPath && !cred],
	["armored-public", (f) => f.ctx.armored],
	// A PEM block's label on the line above it, a name of parts (`ALICE_cf_c2pnb163v1`, `PRIME192V1_RFC5114-Peer`): the
	// block holds the key.
	["block-label", (f, t) => f.ctx.labelsBlock && /^[A-Za-z][A-Za-z0-9]*(?:[_-][A-Za-z0-9]+)+$/.test(t)],
	["blob-line", (f, _, cred) => f.ctx.blobLine && !cred],
	["ssh-public-key", (_, t) => /^AAAA[A-Z]\d?Nza|^AAAAE2Vj/.test(t)],
	// (After a version's number, `1.2.`, not after the last digit of a token cut at a dot: `<id>7.<secret>`.)
	["version", (f, t) => /(?:^|[^\w.])v?\d{1,4}(?:\.\d{1,6})*\.$/.test(f.ctx.left) || /\+g[0-9a-f]{7,40}$/.test(t)],
	["hash-word", (_, t) => /(?:^|[-_./])(?:md5|sha\d*|etag|hash|checksum|digest|crc32|blake\d*)(?:[-_./]|$)/i.test(t)],
	// (Under a credential's name only codes of short parts, `KAS-ECC-CDH_K-233_C7`: a product key's groups are
	// longer, `VKXQR-8B2MP-7WJ4T`, and so are a made password's words, `Summer-Breeze-2024`.)
	[
		"identifier-shaped",
		(_, t, cred) =>
			!cred &&
			(/^[A-Z0-9]{1,10}(?:[_-][A-Z0-9]{1,10}){2,}$/.test(t) ||
				/^[A-Z]{2,}(?:_[A-Za-z0-9]+){2,}$/.test(t) ||
				isIdentifierShaped(t)),
	],
	["pod-name", (_, t, cred) => !cred && isPodName(t)],
	[
		"identifier-shaped",
		(_, t, cred) => cred && isIdentifierShaped(t) && t.split(/[-_.:]/).every((p) => p.length <= 3 || /^\d+$/.test(p)),
	],
	[
		"slug",
		(f, t, cred) =>
			/^(?:[a-z][a-z0-9]{0,15}[-_.]){2,}[a-z0-9]{1,16}$/.test(t) &&
			t.split(/[-_.]/).every((p) => p.length <= 16 && (naturalness(p) > 0 || p.length <= 4)) &&
			!cred &&
			!keyPlace(f),
	],
	["filename", (f, _, cred) => f.ctx.fileish && !cred],
	// (Elsewhere a UUID is hex in groups: hexVeto.)
	["uuid", (f, t, cred) => cred && UUID.test(t) && /session[_-]?id$|sessionId$/i.test(f.ctx.name)],
	// (A ULID's and a cuid's own timestamp says ID wherever it stands; a key's random characters rarely make one.)
	[
		"ulid",
		(f, t, cred) => ULID.test(t) && !cred && !keyPlace(f) && (idPlace(f) || isRecentTime(crockford(t.slice(0, 10)))),
	],
	[
		"cuid",
		(f, t, cred) =>
			/^c[a-z0-9]{24}$/.test(t) && !cred && !keyPlace(f) && (idPlace(f) || isRecentTime(parseInt(t.slice(1, 9), 36))),
	],
	// A minisign public key: base64 of `Ed`, a key ID and 32 bytes of key, 42 bytes in all (`RWQ…`, 56 characters);
	// or whatever minisign is given as one (`minisign -Vm <file> -P <key>`).
	[
		"minisign-public-key",
		(f, t) => /^RW[QRST][A-Za-z0-9+/]{53}$/.test(t) || /\bminisign\b[^\n|;&]*[ \t]-P[ \t]+["']?$/.test(f.ctx.left),
	],
	["inert", (_, t) => isInert(t)],
	// Pure hex or a hash under a bare `key`: an object key, a cache key, a test vector. (Not a key handed over: "your
	// key: …".)
	[
		"bare-key-hash",
		(f, t) =>
			/^keys?$/i.test(f.ctx.name) &&
			!f.ctx.handover &&
			((/[0-9a-f]{16,}/i.test(t) && /[-_/.:]/.test(t)) ||
				(alphaIsHex(f.alphabet) &&
					/"(?:Bucket|StorageClass|LastModified|ETag|Contents|VersionId)"|\bcache\b/i.test(f.ctx.near))),
	],
	// Test vectors, examples and test output: Wycheproof, CAVP, RFC samples, "for example", pytest IDs, Jest diffs.
	[
		"test-vector",
		(f) =>
			alphaIsHex(f.alphabet) &&
			/\btcId\b|\bCOUNT = \d|Test Case \d|test vectors?|\bKAT\b|wycheproof|\[(?:EN|DE)CRYPT\]|for example|e\.g\./i.test(
				f.ctx.near,
			),
	],
	// What a test compares its result to (`want := "<HMAC digest>"`, `expected = …`, `const golden = …`): output, not input.
	[
		"test-expectation",
		(f, _, cred) => !cred && /^(?:want|wanted|expect|expected|golden)(?:[_-]?[A-Za-z0-9]+)?$/i.test(f.ctx.name),
	],
	[
		"test-output",
		(f) => /::test\w*\[$/.test(f.ctx.left) || /\b(?:Expected|Received)(?: value)?:[ \t]*["']?$/.test(f.ctx.left),
	],
	// The local part of an email address or Message-ID (`<CAOS…@mail.gmail.com>`, its first piece when an `=` in it
	// split it, `CAPig+…=JtAj…@mail.gmail.com`), a push token's body. (Not a URL's userinfo, `https://<token>@host`: a
	// password or a token there.)
	[
		"local-part",
		(f) =>
			(/^(?:=[\w+=.-]*)?@/.test(f.ctx.right) && !/:\/\/[^\s/@]*$/.test(f.ctx.left)) ||
			/ExponentPushToken\[$|ExpoPushToken\[$/.test(f.ctx.left),
	],
	// An Android app's signature hash in MSAL's redirect URI (`msauth://com.contoso.app/<base64 SHA-1>`, encoded or in
	// the manifest's `android:path`): the app's identity, public.
	[
		"app-signature",
		(f, t) =>
			/^[A-Za-z0-9+/]{26,27}(?:=|%3D)?$/.test(t) &&
			(/msauth(?::\/\/|%3A%2F%2F)[\w.]+(?:\/|%2F)(?:\+|%2B)?$/i.test(f.ctx.left) ||
				(/android:path=["']\/\+?$/.test(f.ctx.left) && /android:scheme=["']msauth["']/.test(f.ctx.left))),
	],
	// Telegram file IDs, nostr notes: public handles.
	[
		"public-handle",
		(_, t) => /^(?:AgAC|BQAC|CAAC|BAAC|AwAC|DQAC|CQAC)[A-Za-z0-9_-]{20,}$/.test(t) || /^note1[a-z0-9]{50,}$/.test(t),
	],
	// A value in an SQL row whose table and column don't name a credential: row data and IDs.
	[
		"sql-row",
		(f, _, cred) => !cred && !!f.ctx.sqlCell && ![f.ctx.sqlCell.table, f.ctx.sqlCell.column].some(isCredentialName),
	],
	// A fragment of a percent-encoded value (`…%2fAx%2bTHQ…`): the whole value, not a key, if anything.
	["percent-fragment", (f) => /%[0-9A-Fa-f]{2}$/.test(f.ctx.left) || /^%[0-9A-Fa-f]{2}/.test(f.ctx.right)],
	// Cloud resource IDs: `/subscriptions/<uuid>/resourceGroups/<name>/providers/…`, ARNs.
	// (The path ends at a query: a parameter after `?` or `&` is its own, and a credential's name keeps it.)
	[
		"resource-id",
		(f, _, cred) =>
			!cred &&
			(/\/(?:subscriptions|resourceGroups|resourcegroups|providers|projects|locations|instances|clusters|namespaces)\/[^\s"'?&#]*$/.test(
				f.ctx.left,
			) ||
				/\barn:aws[\w-]*:[^\s"'?&#]*$/.test(f.ctx.left)),
	],
	// IDs that frameworks generate: cuid2 (24 lowercase characters starting with a letter, random all through: only
	// where IDs are written says it's one).
	["cuid2", (f, t, cred) => /^[a-z][a-z0-9]{23}$/.test(t) && !cred && idPlace(f)],
	// A label of a URL's host (`https://<id>.appsync-api.…`).
	["hostname", (f) => /:\/\/[\w-]*$/.test(f.ctx.left) && /^\./.test(f.ctx.right)],
	// Browser analytics and widget loaders take public keys: `analytics.load("…")`, `posthog.init('…')`.
	[
		"public-browser-key",
		(f) => f.ctx.syntax === "call" && (PUBLIC_KEY_CALLEE.test(f.ctx.name) || FULLSTORY_GLOBAL.test(f.ctx.name)),
	],
	// A Solana address near Solana's words. (Other blockchain addresses and content IDs are `inert`'s: values.ts.)
	[
		"public-address",
		(f, t) =>
			/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(t) && /solana|devnet|mainnet-beta|lamports|phantom|pubkey/i.test(f.ctx.near),
	],
	["timestamp", (_, t) => /^\d{8}T\d{6}Z$/.test(t)],
	// A Google Drive file's ID near Drive's words.
	[
		"public-url-id",
		(f, t, cred) =>
			/^1[A-Za-z0-9_-]{32}$|^1[A-Za-z0-9_-]{43}$/.test(t) &&
			/drive|docs?\b|sheets?|spreadsheet|slides|folder/i.test(f.ctx.near) &&
			!cred,
	],
	// What the name says, when it isn't a credential's.
	["name-hash", (f) => f.ctx.nameClass === "hash"],
	["name-public", (f) => f.ctx.nameClass === "public"],
	["name-identifier", (f) => f.ctx.nameClass === "identifier"],
	["base64-text", (f, t, cred) => f.decodes === "text" && f.length >= 24 && !cred && decodedIsNatural(t)],
	// Words, and words around a digit or two: package and module names (`qtquick3dphysics`, `oauth2client`).
	[
		"words",
		(_, t) =>
			(/[_-]/.test(t) && isWordsValue(t)) ||
			(/^[a-z]{3,}\d{1,2}[a-z]{3,}$/.test(t) && t.split(/\d+/).every((p) => naturalness(p) > 0.3)),
	],
	["natural", (f) => f.natural > 1.2],
	urlPathId,
	hexVeto,
];

/** An option that takes OpenPGP key IDs, and the IDs already given it, just before a token. */
const KEY_ID_OPTION =
	/(?:^|[ \t])--(?:(?:recv|send|delete|delete-secret|delete-secret-and-public|edit|export|export-secret|export-secret-sub|list|list-secret|list-public|fingerprint|l?sign|default|trusted|refresh)-keys?|quick-(?:sign|lsign|add|revoke|set-expire|set-primary-uid|revoke-sig|add-adsk|add-uid|revoke-uid)(?:-key)?|local-user|recipient|hidden-recipient|encrypt-to)(?:[ \t]+(?:0x)?[0-9A-Fa-f]{8,40})*[ \t]+["']?(?:0x)?$/;

/**
 * The vetoes that say a value is public by design, whatever names it: the same in every layer, so policy.ts asks them
 * of every named and structural proposal too (publicReason). Each reads the value's own format or its own place (an
 * encryption wrapper, a public armored block, the option that takes it), which no name can contradict. The others
 * are guesses about a token nothing names, from its shape or from words elsewhere on its line (a model's name, a
 * wallet address near `solana`, a hex ID near `gpg`): a credential's name or a password's flag outvotes those.
 */
const PUBLIC_VETOES = new Set([
	"encrypted",
	"aws-unique-id",
	"hash-prefix",
	"armored-public",
	"ssh-public-key",
	"minisign-public-key",
	"key-id-option",
]);

/**
 * Why the value at `[start, end)` is public by design, by the vetoes in PUBLIC_VETOES; undefined if none says so. Only
 * of a value the random layer would judge, one run of token characters as long as MIN_TOKEN, which they're written for.
 */
export function publicReason(doc: Doc, start: number, end: number): string | undefined {
	const token = doc.text.slice(start, end);
	if (!CANDIDATE.test(token)) return undefined;
	const f = features(doc, { start, end, token }, false);
	const cred = f.ctx.nameClass === "credential";
	for (const v of VETOES) if (typeof v !== "function" && PUBLIC_VETOES.has(v[0]) && v[1](f, token, cred)) return v[0];
	return undefined;
}

/** The reason `veto` gives for the candidate, if it applies. */
function reasonOf(veto: Veto, f: Features, cred: boolean): string | undefined {
	return typeof veto === "function" ? veto(f) : veto[1](f, f.token, cred) ? veto[0] : undefined;
}

/** Every hard rule that rules the candidate out (see VETOES), by its reason: for tracing, where vetoed() stops at the first. */
export function vetoes(f: Features): string[] {
	const cred = f.ctx.nameClass === "credential";
	return [...new Set(VETOES.map((v) => reasonOf(v, f, cred)).filter((r) => r !== undefined))];
}

/** The first hard rule that rules the candidate out, or undefined. */
export function vetoed(f: Features, { statistical = true } = {}): string | undefined {
	const cred = f.ctx.nameClass === "credential";
	for (const v of VETOES) {
		const reason = reasonOf(v, f, cred);
		if (reason && (statistical || !STATISTICAL_VETOES.has(reason))) return reason;
	}
	return undefined;
}

/**
 * The vetoes that are a judgment about how a token looks, which the model's features measure too (its naturalness,
 * its alphabet, its name's class), rather than a fact about what it is: without them (`without: ["statistical-vetoes"]`),
 * the model decides those tokens alone. For measuring whether a model trained on them can (scripts/unnamed-data.ts
 * `--statistical`).
 */
const STATISTICAL_VETOES = new Set([
	"natural",
	"words",
	"slug",
	"identifier-shaped",
	"hex",
	"hex-groups",
	"hex-suffix",
	"name-identifier",
	"name-hash",
	"id-name",
	"model-name",
	"pod-name",
]);

/** The model's probability that the candidate is a secret: boosted trees trained by scripts/train-unnamed.py. */
export function score(f: Features): number {
	return predict(vector(f));
}

// The syntaxes and alphabets that tell the model something. (Not prose, which no tree split on, nor hex, which
// hexVeto decides before the model sees it.)
const SYNTAXES = ["assign", "flag", "header", "query", "path", "call", "xml", "bare", "list", "other"] as const;
const ALPHABETS: Alphabet[] = ["b32", "b36", "B36", "b62", "b64", "b64url", "other"];
const flag = (b: boolean) => (b ? 1 : 0);

/** The model's inputs, in order: each feature's name (for inspecting the model) and its value. */
const FEATURES: [name: string, value: (f: Features) => number][] = [
	["natural", (f) => f.natural],
	["natural_neg", (f) => Math.max(0, -f.natural)],
	["entropyZ", (f) => Math.max(-6, Math.min(4, f.entropyZ))],
	["entropyZ_low", (f) => flag(f.entropyZ < -2.5)],
	// (Past the longest key it was trained on, the model has seen only blobs: a longer token of base62 or URL-safe base64,
	// as OAuth and session tokens are, is judged as that longest. Standard base64 keeps its length: its keys run to
	// `openssl rand -base64 128`'s 172 characters in training, and longer is a blob. So does a URL path's segment, an
	// image's or a payload's ID, but for a hook's.)
	[
		"logLength",
		(f) =>
			Math.log2(
				f.alphabet === "b64" || (f.ctx.inUrl && /\/$/.test(f.ctx.left) && !isHookUrl(f))
					? f.length
					: Math.min(f.length, LONGEST_TRAINED),
			),
	],
	["len_lt20", (f) => flag(f.length < 20)],
	["len_ge32", (f) => flag(f.length >= 32)],
	["len_ge64", (f) => flag(f.length >= 64)],
	["switches", (f) => Math.min(2, f.switches)],
	["digits", (f) => f.digits],
	["upper", (f) => f.upper],
	["lower", (f) => f.lower],
	["vendorPrefix", (f) => flag(f.vendorPrefix)],
	["decodes_binary", (f) => flag(f.decodes === "binary")],
	["hashSize", (f) => flag(f.hashSize)],
	["leftHashy", (f) => flag(f.leftHashy)],
	...ALPHABETS.map((a): [string, (f: Features) => number] => [`alpha_${a}`, (f) => flag(f.alphabet === a)]),
	["name_neutral", (f) => flag(f.ctx.nameClass === "neutral" && !!f.ctx.name)],
	["name_none", (f) => flag(!f.ctx.name)],
	["lineCredential", (f) => flag(f.ctx.lineCredential)],
	["lineHash", (f) => flag(f.ctx.lineHash)],
	["handover", (f) => flag(f.ctx.handover)],
	["quoted", (f) => flag(f.ctx.quoted)],
	["inUrl", (f) => flag(f.ctx.inUrl)],
	["path_hooky", (f) => flag(isHookSegment(f.ctx.pathParent))],
	["shellArg", (f) => flag(f.ctx.shellArg)],
	...SYNTAXES.map((s): [string, (f: Features) => number] => [`syntax_${s}`, (f) => flag(f.ctx.syntax === s)]),
	["neutral_x_long", (f) => flag(f.ctx.nameClass === "neutral" && f.length >= 32)],
];

export function vector(f: Features): number[] {
	return FEATURES.map(([, value]) => value(f));
}

/** The longest random key in the model's training positives but for standard base64's (scripts/unnamed-data.ts `randomKey`). */
const LONGEST_TRAINED = 90;

/** The score a token needs, by how hard to guess (RedactOptions.guessing); in a secret file, the eager one. */
const THRESHOLD = { confident: 0.8, eager: 0.5 };

/** The score a token needs to be hidden; undefined where nothing is guessed ("off", outside a secret file). */
export function thresholdFor(guessing: Guessing, secretFile: boolean): number | undefined {
	if (secretFile || guessing === "eager") return THRESHOLD.eager;
	return guessing === "off" ? undefined : THRESHOLD.confident;
}

/**
 * A long mixed-case random value quoted on its own (`"X1Am…"`, `` `X1Am…` `` in prose), with no name: the model learned
 * quoted strings from code, where they're rarely keys, but this shape is one (0.01 per MB of real text). Hidden in the
 * balanced mode whatever the model scores it.
 */
function isLoneQuotedKey(f: Features): boolean {
	return (
		f.ctx.quoted &&
		!f.ctx.name &&
		(f.ctx.syntax === "bare" || f.ctx.syntax === "list") &&
		/^[A-Za-z0-9]{32,64}$/.test(f.token) &&
		/[a-z]/.test(f.token) &&
		/[A-Z]/.test(f.token) &&
		/\d/.test(f.token) &&
		f.natural < -0.3 &&
		!/(?:\b[A-Z][A-Z0-9_]{2,}|\b[a-z][a-z0-9]*_[a-z0-9_]+)[ \t:=]+["'`]$/.test(f.ctx.left)
	);
}

/** The vetoes that say a token is an ID by its shape where it stands, and the shapes they read (another veto may come first). */
const ID_VETOES = new Set(["ulid", "cuid", "cuid2", "public-id", "object-id"]);
const ID_SHAPED = /^[a-z][a-z0-9]{23,24}$|^[0-7][0-9A-Za-z]{25}$|^[a-z]{2,12}_/;

export function findUnnamed(
	text: string,
	taken: (start: number, end: number) => boolean,
	guessing: Guessing,
	secretFile: boolean,
	without: ReadonlySet<string> = new Set(),
): Finding[] {
	const out: Finding[] = [];
	// (In a secret file a generated-looking value is a secret whatever it's named: the eager threshold, whatever the
	// guessing; outside one, "off" guesses nothing.)
	const threshold = thresholdFor(guessing, secretFile);
	if (threshold === undefined) return out;
	let doc: Doc | undefined;
	// (A token the text shows as an ID somewhere, `/api/posts/<id>`, is that ID where it stands alone: `Post <id> not found`;
	// not where a key goes, `Client("<id>")`, nor where a credential's name has it, `config.password = "<id>"`.)
	const ids = new Set<string>();
	const keyed = new Set<Finding>();
	for (const c of candidates(text)) {
		if (taken(c.start, c.end)) continue;
		// Cheap randomness gate before the context work: most candidates are identifiers and words.
		if (naturalness(c.token) > 1.2 && !/\d/.test(c.token)) continue;
		doc ??= Doc.of(text);
		// (Measuring what context buys: the token scored where nothing surrounds it.)
		const f = without.has("token-context")
			? features(new Doc(c.token), { start: 0, end: c.token.length, token: c.token }, secretFile)
			: features(doc, c, secretFile);
		const reason = without.has("vetoes") ? undefined : vetoed(f, { statistical: !without.has("statistical-vetoes") });
		if (reason) {
			if (ID_VETOES.has(reason) || (ID_SHAPED.test(c.token) && vetoes(f).some((r) => ID_VETOES.has(r))))
				ids.add(c.token);
			continue;
		}
		let p = score(f);
		if (isLoneQuotedKey(f)) p = Math.max(p, THRESHOLD.confident);
		if (p < threshold) continue;
		const finding: Finding = {
			start: c.start,
			end: c.end,
			kind: "random token",
			rule: "unnamed",
			confidence: p,
			...(f.ctx.name ? { name: f.ctx.name } : {}),
		};
		if (keyPlace(f) || (f.ctx.name && isCredentialName(f.ctx.name))) keyed.add(finding);
		out.push(finding);
	}
	return ids.size ? out.filter((f) => !ids.has(text.slice(f.start, f.end)) || keyed.has(f)) : out;
}

/** Whether base64 decodes to a complete protobuf message with at least one readable string field (4+ characters, mostly printable). */
function isProtobufText(b64: string): boolean {
	const bytes = base64Bytes(b64);
	return !!bytes && parsesAsMessage(bytes, 0, bytes.length, 0) === true;
}

/** The highest field number read as a schema's: messages number their fields densely from 1, and a larger "tag" is random bytes. */
const MAX_FIELD_NUMBER = 536;

/** `true` if bytes[from, to) is a message with a readable string somewhere in it; `false` if it parses without one; `undefined` if it doesn't parse. */
function parsesAsMessage(bytes: Uint8Array, from: number, to: number, depth: number): boolean | undefined {
	let i = from;
	let fields = 0;
	let readable = false;
	// (Up to 5 bytes for a key or a length, 10 for a value: a negative int64 takes all 10.)
	const varint = (longest = 5): number | undefined => {
		let v = 0;
		for (let shift = 0; shift < 7 * longest && i < to; shift += 7) {
			const b = bytes[i++];
			v += (b & 127) * 2 ** shift;
			if (!(b & 128)) return v;
		}
		return undefined;
	};
	while (i < to) {
		const key = varint();
		if (key === undefined) return undefined;
		// (A tag is `field << 3 | wire type`, up to 2^35 here: `>>` would wrap past 32 bits. `& 7` keeps the low bits.)
		const field = Math.floor(key / 8);
		if (field === 0 || field > MAX_FIELD_NUMBER) return undefined;
		const wire = key & 7;
		if (wire === 0) {
			if (varint(10) === undefined) return undefined;
		} else if (wire === 1 || wire === 5) {
			i += wire === 1 ? 8 : 4;
		} else if (wire === 2) {
			const len = varint();
			if (len === undefined || i + len > to) return undefined;
			const s = bytes.subarray(i, i + len);
			const printable = s.filter((b) => (b >= 32 && b < 127) || b === 9 || b === 10).length;
			if (len >= 4 && printable >= 0.8 * len && /[ -~]{4}/.test(String.fromCharCode(...s))) readable = true;
			else if (len >= 2 && depth < 4 && parsesAsMessage(bytes, i, i + len, depth + 1)) readable = true;
			i += len;
		} else return undefined;
		fields++;
	}
	return i === to && fields > 0 ? readable : undefined;
}
