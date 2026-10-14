/**
 * Credentials recognizable by format alone: a vendor prefix (`ghp_`, `sk-ant-`, `xoxb-`), a fixed
 * structure (AWS key IDs, JWTs), or a vendor name right before an assignment of the right shape.
 * These are the most certain findings, so they're redacted wherever they appear.
 *
 * The core list is maintained here; the long tail is generated from Betterleaks (formats-data.ts).
 * A rule runs only on text that contains one of its keywords (one Aho-Corasick pass finds which), which
 * keeps over 500 rules fast; the one rule with no keyword (Mailgun's) always runs. A match that is a stand-in
 * (`sk-your-key-here`) is dropped here; which are public by design (publishable keys, public JWTs, client-side
 * Google keys) is decided in policy.ts, from what public.ts knows.
 */
import { lookup } from "./lookup.ts";
import { KeywordSet } from "./aho.ts";
import { naturalness } from "./charlm.ts";
import { isPlaceholder } from "./public.ts";
import { entropy } from "./random.ts";
import { isCredentialName, nameClass } from "./names.ts";
import { IMPORTED_FORMATS } from "./formats-data.ts";
import { backslashesBefore } from "./syntax.ts";
import type { Finding } from "./types.ts";
import { leadingUrl } from "./urls.ts";

interface Format {
	name: string;
	re: RegExp;
	keywords: string[];
	/** The fewest characters a match may have: the core rules bound their own; the imported ones are held to 8. */
	shortest: number;
	minEntropy: number;
	/** Found by a vendor word before an assignment rather than by the token's own shape. */
	byVendorWord: boolean;
	/** What the rule also matches that isn't its vendor's token, given the value and the text before it. */
	rejects?: (value: string, before: string) => boolean;
	/** Text a match can't be without, tested first (see GATES). */
	gate?: RegExp;
}

/**
 * For the rules whose keywords are common (`.`, `--`) or none: what any match holds, led by a literal, which the regex engine
 * finds by skipping ahead (a class-led rule like the Mailgun signing key's `[0-9a-f]{32}-…` is tried at every character). The
 * rule runs only on text that has it.
 */
const GATES = lookup<RegExp>({
	"Rails session cookie": /--[0-9a-f]{40}/,
	"Zhipu API key": /\.[A-Za-z0-9]{16}/,
	"Mailgun signing-style API key": /-[0-9a-f]{8}-[0-9a-f]{8}\b/,
});

/**
 * Rules' own false matches, by rule name: a link's signed payload (Cursor's "open in Cursor" buttons,
 * `cursor.com/open?data=<JWT>`), Airtable's object IDs (`tbl…`, `app…`, `rec…`) under a vendor word, a Kubernetes pod
 * name with its ReplicaSet hash (`sk-api-worker-7d9f8b6c5-x2x9q`) for the generic `sk-` rule.
 */
const REJECTS = lookup<(value: string, before: string) => boolean>({
	"Bearer token in JSON Web Token form": (_, before) => /cursor\.com\/[\w/-]*\?data=$/.test(before.slice(-60)),
	"airtable API key": (value) => /^(?:tbl|app|rec|viw|fld|sel|usr|wsp)[A-Za-z0-9]{14}$/.test(value),
	"airtable OAUTH token": (value) => /^(?:tbl|app|rec|viw|fld|sel|usr|wsp)[A-Za-z0-9]{14}$/.test(value),
	"API key": (value) => /^[a-z0-9]+(?:-[a-z0-9]+)*-[a-z0-9]{8,10}-[a-z0-9]{5}$/.test(value),
});

let keywordSet: KeywordSet | undefined;
/** For each keyword index, the formats that need it. */
let byKeyword: number[][] = [];
/** Formats with no keyword, which always run. */
let always: number[] = [];

/** The core rules: a name, a regex whose one capture group is the secret, and keywords one of which a text must hold for the rule to run (any case). */
export const CORE_FORMATS: [name: string, rule: RegExp, keywords: string[]][] = [
	[
		"AWS access key ID",
		/\b((?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z0-9]{16})\b/,
		["akia", "asia", "abia", "acca", "a3t"],
	],
	// The secret key printed next to its key ID (`--output text`, CSV exports, credentials files, `export-credentials`),
	// in an argument list or a row (`s3('…', 'AKIA…', '<secret>', …)`) or named. (Base64 of random bytes, so both cases:
	// a 40-hex SHA-1 in a scanner's report row isn't one.)
	[
		"AWS secret access key",
		/(?:\b(?:AKIA|ASIA)[A-Z0-9]{16}["'`]?[ \t,;|:=]{1,10}["'`]?|(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|secret_access_key|SecretAccessKey|secretAccessKey)["']?[ \t]{0,5}[:=][ \t]{0,5}["']?)((?=[A-Za-z0-9/+]{0,39}[a-z])(?=[A-Za-z0-9/+]{0,39}[A-Z])[A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])/,
		["akia", "asia", "secret_access_key", "secretaccesskey"],
	],
	[
		"AWS session token",
		/\b((?:IQoJb3JpZ2luX2Vj|FwoGZXIvYXdz|FQoGZXIvYXdz|FQoDYXdz|IQoJb3Jp)[A-Za-z0-9/+]{80,4096}={0,2})(?![A-Za-z0-9/+=])/,
		["iqojb3jp", "fwogzxivyxdz", "fqogzxivyxdz", "fqodyxdz"],
	],
	[
		"GitHub token",
		/\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b/,
		["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"],
	],
	["GitLab token", /\b(gl(?:pat|dt|ptt|rt|soat|cbt|imt|ft|agent|oas|ffct|wt)-[A-Za-z0-9_-]{20,255})/, ["gl"]],
	["OpenAI API key", /\b(sk-(?:proj|svcacct|admin|None)-[A-Za-z0-9_-]{20,255})/, ["sk-"]],
	["Anthropic API key", /\b(sk-ant-[a-z]{2,10}\d{0,3}-[A-Za-z0-9_-]{20,255})/, ["sk-ant-"]],
	["OpenRouter API key", /\b(sk-or-v1-[a-f0-9]{64})\b/, ["sk-or-"]],
	// Gateway and older keys: `sk-` then 20+ token characters; dots inside are allowed (`sk-llm-…`).
	["API key", /\b(sk-(?:[A-Za-z0-9_-]|\.(?=[A-Za-z0-9_-])){20,255})/, ["sk-"]],
	["Stripe key", /\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,255})\b/, ["sk_", "rk_"]],
	["secret key", /\b(sk_(?:live|test)_[A-Za-z0-9]{8,}_[A-Za-z0-9_]{40,250})\b/, ["sk_live_", "sk_test_"]],
	// The `<vendor>_sk_` convention (`aria_sk_…`, ElevenLabs' `sk_…`): a secret key by name, with a random body. (Not
	// OpenSSL's stack functions, a type's words in capitals then the operation's: `sk_X509_NAME_ENTRY_pop_free`.)
	[
		"API secret key",
		/\b((?:[a-z][a-z0-9]{1,15}_)?sk_(?!live_|test_)(?!(?:[A-Z][A-Z0-9]*_)+[a-z]+(?:_[a-z]+)*\b)(?=[A-Za-z_-]{0,40}\d)[A-Za-z0-9_-]{24,255})/,
		["sk_"],
	],
	["Twitter bearer token", /\b(A{18,24}[A-Za-z0-9%]{60,160})/, ["aaaaaaaaaaaaaaaaaa"]],
	["Stripe webhook secret", /\b(whsec_[A-Za-z0-9+/=]{20,255})/, ["whsec_"]],
	["Slack token", /\b(xox[abposre]-[A-Za-z0-9-]{10,255}|xapp-\d-[A-Za-z0-9-]{20,255})/, ["xox", "xapp-"]],
	[
		"Slack webhook",
		// (A services webhook's secret is its third segment: `T…/B…/<24 characters>`; one cut to `T…/B…/...` has none.)
		/hooks\.slack\.com\/(?:services|workflows|triggers)\/((?<=services\/)T[A-Z0-9]{6,}\/B[A-Z0-9]{6,}\/[A-Za-z0-9]{16,64}|(?<!services\/)[A-Za-z0-9/_-]{20,255})/,
		["hooks.slack.com"],
	],
	[
		"Microsoft Teams webhook",
		/(?:(?<![\w-])[\w-]+\.webhook\.office\.com\/webhookb2|outlook\.office(?:365)?\.com\/webhook)\/[\w-]{36}@[\w-]{36}\/IncomingWebhook\/([a-f0-9]{32}\/[\w-]{36}(?:\/[A-Za-z0-9_-]{20,})?)/i,
		["incomingwebhook"],
	],
	[
		"Microsoft Teams workflow webhook",
		/\.webhook\.office\.com\/[\w/-]{0,200}?\/workflows\/[a-f0-9]{32}\/triggers\/manual\/paths\/invoke\?[^\s"']*?sig=([A-Za-z0-9_%-]{20,})/i,
		["workflows"],
	],
	["Zapier webhook", /hooks\.zapier\.com\/hooks\/catch\/\d{3,12}\/([a-z0-9]{5,40})\b/i, ["hooks.zapier.com"]],
	[
		"IFTTT webhook key",
		/maker\.ifttt\.com\/(?:trigger\/[\w-]+\/(?:json\/)?with\/key|use)\/([A-Za-z0-9_-]{16,64})/i,
		["maker.ifttt.com"],
	],
	// (The `key` is one public constant every Chat webhook carries; the `token` is the secret.)
	[
		"Google Chat webhook",
		/chat\.googleapis\.com\/v1\/spaces\/[\w-]+\/messages\?key=[\w-]{20,}&token=([\w%=-]{20,})/i,
		["chat.googleapis.com"],
	],
	[
		"Mattermost or Rocket.Chat webhook",
		/\/hooks\/([a-z0-9]{26}|[A-Za-z0-9]{17}\/[A-Za-z0-9]{40,50})(?![\w-])/,
		["/hooks/"],
	],
	["Discord webhook", /discord(?:app)?\.com\/api\/webhooks\/\d{5,30}\/([A-Za-z0-9_-]{40,255})/, ["discord"]],
	["Google API key", /\b(AIza[A-Za-z0-9_-]{35})(?![A-Za-z0-9_-])/, ["aiza"]],
	["Google OAuth token", /\b(ya29\.[A-Za-z0-9_.-]{20,2048}|1\/\/0[A-Za-z0-9_-]{30,512})/, ["ya29.", "1//0"]],
	["Google OAuth client secret", /\b(GOCSPX-[A-Za-z0-9_-]{28})(?![A-Za-z0-9_-])/, ["gocspx-"]],
	["npm token", /\b(npm_[A-Za-z0-9]{36,255})\b/, ["npm_"]],
	["PyPI token", /\b(pypi-AgE[A-Za-z0-9_-]{50,1024})/, ["pypi-"]],
	["Docker Hub token", /\b(dckr_(?:pat|oat)_[A-Za-z0-9_-]{20,255})/, ["dckr_"]],
	["DigitalOcean token", /\b(do[opr]_v1_[a-f0-9]{64})\b/, ["_v1_"]],
	["Hugging Face token", /\b(hf_[A-Za-z0-9]{30,255})\b/, ["hf_"]],
	["Shopify token", /\b(shp(?:at|ss|ca|pa)_[a-fA-F0-9]{32})\b/, ["shp"]],
	["Grafana token", /\b(gl(?:sa|c)_[A-Za-z0-9+/=_]{32,255})/, ["glsa_", "glc_"]],
	["Vault token", /\b(hv[sbr]\.[A-Za-z0-9_-]{20,512})/, ["hvs.", "hvb.", "hvr."]],
	["age secret key", /\b(AGE-SECRET-KEY-1[0-9A-Z]{58})\b/, ["age-secret-key-"]],
	["Supabase key", /\b(sb(?:p|_secret)_[A-Za-z0-9_-]{20,255})/, ["sbp_", "sb_secret_"]],
	["Doppler token", /\b(dp\.(?:st|ct|sa|scim|audit|pt)\.[A-Za-z0-9._-]{30,255})/, ["dp."]],
	["Tailscale key", /\b(tskey-(?:auth|api|client|scim|webhook|secret)-[A-Za-z0-9-]{20,255})/, ["tskey-"]],
	["Linear API key", /\b(lin_(?:api|oauth)_[A-Za-z0-9]{30,255})/, ["lin_"]],
	["Postman API key", /\b(PMAK-[a-f0-9]{24}-[a-f0-9]{34})\b/, ["pmak-"]],
	["Atlassian API token", /\b(ATATT3[A-Za-z0-9_=-]{100,512})/, ["atatt3"]],
	["1Password token", /\b(ops_eyJ[A-Za-z0-9_+/=-]{50,4096})/, ["ops_eyj"]],
	[
		"Fly.io token",
		/\b(fm[12]_[A-Za-z0-9+/=_-]{50,4096}|FlyV1 fm\d_[A-Za-z0-9+/=_,-]{50,4096})/,
		["fm1_", "fm2_", "flyv1"],
	],
	["Mailgun API key", /\b(key-[0-9a-f]{32})\b/, ["key-"]],
	["SendGrid key", /\b(SG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{32,64})/, ["sg."]],
	["Telegram bot token", /(?:\b|(?<=bot))(\d{8,10}:AA[A-Za-z0-9_-]{32,33})(?![\w-])/, [":aa"]],
	["Firebase Cloud Messaging key", /\b(AAAA[A-Za-z0-9_-]{7}:APA91b[A-Za-z0-9_-]{134,})/, ["apa91b"]],
	["Okta token", /(?<=okta[\s\S]{0,40})\b(00[A-Za-z0-9_-]{40})\b/i, ["okta"]],
	["Discord bot token", /\b([MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38})(?![\w-])/, ["."]],
	["Notion token", /\b(ntn_[A-Za-z0-9]{40,255}|secret_[A-Za-z0-9]{43})\b/, ["ntn_", "secret_"]],
	["Groq API key", /\b(gsk_[A-Za-z0-9]{48,64})\b/, ["gsk_"]],
	["Replicate token", /\b(r8_[A-Za-z0-9]{37,40})\b/, ["r8_"]],
	["Perplexity API key", /\b(pplx-[A-Za-z0-9]{40,64})\b/, ["pplx-"]],
	["xAI API key", /\b(xai-[A-Za-z0-9]{70,90})\b/, ["xai-"]],
	// Meta's Model API (Muse Spark): `LLM|`, the app's ID and a base64url secret, or the same with underscores. Bare, the
	// ID's 15 or 16 digits leave too little entropy for the random layer to take the whole for a key.
	[
		"Meta Model API key",
		/\b(LLM(?:\|\d{15,16}\||_\d{15,16}_)[A-Za-z0-9_-]{20,255})(?![A-Za-z0-9_-])/,
		["llm|", "llm_"],
	],
	["Tavily API key", /\b(tvly-(?:dev-|prod-)?[A-Za-z0-9]{24,48})\b/, ["tvly-"]],
	["Fireworks API key", /\b(fw_[A-Za-z0-9]{24,48})\b/, ["fw_"]],
	["NVIDIA API key", /\b(nvapi-[A-Za-z0-9_-]{60,72})/, ["nvapi-"]],
	["Pinecone key", /\b(pcsk_[A-Za-z0-9_]{50,90})\b/, ["pcsk_"]],
	["Sentry token", /\b(sntry[su]_[A-Za-z0-9+/=_-]{40,512})/, ["sntry"]],
	["RubyGems key", /\b(rubygems_[a-f0-9]{48})\b/, ["rubygems_"]],
	["Mapbox secret token", /\b(sk\.eyJ[A-Za-z0-9_-]{20,512}\.[A-Za-z0-9_-]{20,128})/, ["sk.eyj"]],
	["Alibaba access key", /\b(LTAI[A-Za-z0-9]{12,24})\b/, ["ltai"]],
	["Tencent secret ID", /\b(AKID[A-Za-z0-9]{32})\b/, ["akid"]],
	["Azure DevOps PAT", /\b([a-zA-Z0-9]{52}AZDO[a-zA-Z0-9]{4})\b/, ["azdo"]],
	// Microsoft's common annotated security key format: 52 random characters, then `JQQJ9` and a date and provider tag.
	["Azure key", /\b([A-Za-z0-9]{52}JQQJ9(?:9|D|H)[A-Za-z0-9]{4,40})/, ["jqqj9"]],
	[
		"Azure identifiable key",
		/\b([A-Za-z0-9+/]{33}(?:AZEY|\+ASb|\+AEh|\+ARm|AzCa|AzFu|AzSe|APIM|ACDb|\+ABa|\+AMC|AzSc)[A-Za-z0-9+/]{5}[AQgw]==|[A-Za-z0-9+/]{76}(?:\+ASt|AzSe)[A-Za-z0-9+/]{5}[AQgw]==|[A-Za-z0-9+/]{42}AzCa[A-P][A-Za-z0-9+/]{5}=)/,
		["azey", "+asb", "+aeh", "+arm", "azca", "azfu", "azse", "apim", "acdb", "+aba", "+amc", "azsc", "+ast"],
	],
	[
		"Azure AD client secret",
		/(?<![a-zA-Z0-9_~.-])([a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})(?![a-zA-Z0-9_~-]|\.[a-zA-Z0-9_~])/,
		["q~"],
	],
	["Databricks token", /\b(dapi[a-f0-9]{32}(?:-\d)?)\b/, ["dapi"]],
	["Figma token", /\b(figd_[A-Za-z0-9_-]{40,})/, ["figd_"]],
	// PostHog personal API keys (`phc_` is the public project key).
	["PostHog personal key", /\b(phx_[A-Za-z0-9]{40,50})\b/, ["phx_"]],
	["New Relic key", /\b(NRAK-[A-Z0-9]{27}|NRII-[A-Za-z0-9_-]{32}|NRJS-[a-f0-9]{19})\b/, ["nrak-", "nrii-", "nrjs-"]],
	["Pulumi token", /\b(pul-[a-f0-9]{40})\b/, ["pul-"]],
	["Square token", /\b(sq0(?:atp|csp)-[A-Za-z0-9_-]{22,43}|EAAA[A-Za-z0-9_-]{60})(?![A-Za-z0-9_-])/, ["sq0", "eaaa"]],
	// An API key SID, like an AWS key ID: an identifier, but hidden alongside its secret for the same reason.
	["Twilio API key SID", /\b(SK[0-9a-f]{32})\b/, ["sk"]],
	["Facebook access token", /\b(EAA[A-Za-z0-9]{6,8}ZD[A-Za-z0-9]{60,300}|EAAG[A-Za-z0-9]{100,300})\b/, ["eaa"]],
	[
		"Cloudflare token",
		/\b(cf[ua]t_[A-Za-z0-9]{40}[a-f0-9]{8}|cfk_[A-Za-z0-9]{40}[a-f0-9]{8})\b/,
		["cfut_", "cfat_", "cfk_"],
	],
	["Vercel token", /\b(vc[pkiar]_[A-Za-z0-9]{24,64})\b/, ["vcp_", "vck_", "vci_", "vca_", "vcr_"]],
	[
		"Docker swarm token",
		/\b(SWMTKN-1-[a-z0-9]{50}-[a-z0-9]{25}|SWMKEY-1-[A-Za-z0-9+/]{43})(?![A-Za-z0-9+/=])/,
		["swmtkn-1-", "swmkey-1-"],
	],
	// The imported Resend rule wants the word "resend" nearby, and only base58; the shape (an underscore after
	// eight characters, then 24) is distinctive on its own. Stripe's refund IDs are `re_` and 24, unbroken.
	["Resend API key", /\b(re_[A-Za-z0-9]{8}_[A-Za-z0-9]{24})\b/, ["re_"]],
	// Vendor tokens whose prefix or shape is distinctive on its own (each seen bare in output, with no name around it).
	// (Not a word and hex alone, `key_<hex>` or `live_<hex>`: cache keys, file and room names have that shape. Cursor's and
	// Retell's keys are found with their vendor's name nearby, as the imported rules do.)
	["Twitch stream key", /\b(live_\d{6,12}_[A-Za-z0-9]{30})\b/, ["live_"]],
	// (The second part is mixed-case; an Application Insights `Request-Id: |<32 hex>.<16 hex>` is hex.)
	["Zhipu API key", /(?<![|\w])([0-9a-f]{32}\.(?=[a-z0-9]*[A-Z])[A-Za-z0-9]{16})\b/, ["."]],
	["Zoho token", /\b(1000\.[0-9a-f]{32}\.[0-9a-f]{32})\b/, ["1000."]],
	["Salesforce session ID", /\b(00D[A-Za-z0-9]{12,15}![A-Za-z0-9._]{80,200})/, ["00D"]],
	["CodeRabbit API key", /\b(cr-[0-9a-f]{64})\b/, ["cr-"]],
	["Riot Games API key", /\b(RGAPI-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b/, ["RGAPI-"]],
	["Pixie API key", /\b(px-(?:api|dep)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b/, ["px-"]],
	["New Relic admin key", /\b(NRAA-[0-9a-f]{27})\b/, ["NRAA-"]],
	["Cloudflare origin CA key", /\b(v1\.0-[0-9a-f]{24}-[0-9a-f]{146})\b/, ["v1.0-"]],
	["Infura project secret", /infura\.io\/v3\/([0-9a-f]{32})\b/, ["infura.io"]],
	[
		"Amazon MWS auth token",
		/\b(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b/,
		["amzn.mws."],
	],
	[
		"Kubernetes bootstrap token",
		/(?:bootstrap[\w-]*token[\w"']*[ \t]*[:=][ \t]*["']?|kubeadm\b[^\n]{0,200}?--token[ \t=]+["']?)([a-z0-9]{6}\.[a-z0-9]{16})\b/i,
		["bootstrap", "kubeadm"],
	],
	// Nix binary-cache signing keys: a key name (`cache.example.org-1`) and 64 bytes of base64. The public half
	// (32 bytes) is kept by policy.ts. (The name is read from a token's start, a host's length at most: one attempt a token.)
	["Nix signing key", /(?<![\w.-])\w[\w.-]{0,252}-\d{1,5}:([A-Za-z0-9+/]{86}==)/, ["=="]],
	// Airtable personal access tokens: `pat`, 14 characters, a dot and 64 hex (the imported rule wants "airtable" nearby).
	["Airtable personal access token", /\b(pat[A-Za-z0-9]{14}\.[a-f0-9]{64})\b/, ["pat"]],
	[
		"Claude Platform on AWS API key",
		/\b(aws-external-anthropic-api-key-[A-Za-z0-9_-]{20,1000}={0,2})/,
		["aws-external-anthropic-api-key-"],
	],
	[
		"Claude Platform on AWS API key (base64 form)",
		/\b(AEAAQWVhQXBpS2V5[A-Za-z0-9+/]{40,2000}={0,2})/,
		["aeaaqwvhqxbps2v5"],
	],
	["Amazon Bedrock API key", /\b(bedrock-api-key-[A-Za-z0-9+/_-]{40,2000}={0,2})/, ["bedrock-api-key-"]],
	[
		"Heroku API key",
		/\b(HRKU-(?:[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}|AA[0-9A-Za-z_-]{58}))\b/,
		["hrku-"],
	],
	["Atlassian Connect token", /\b(ATCTT3xFfGN0[0-9A-Za-z_-]{150,250}=[0-9A-F]{8})\b/, ["atctt3"]],
	["Asana personal access token", /(?<![\w/])((?:1\/\d{14,16}|2\/\d{16}\/\d{16}):[0-9a-f]{32})\b/, ["1/", "2/"]],
	["CircleCI token", /\b(CCI(?:PAT|PRJ)_[A-Za-z0-9]{22}_[0-9a-f]{40})\b/, ["ccipat_", "cciprj_"]],
	["Flutterwave secret key", /\b(FLWSECK(?:_TEST)?(?:-[0-9A-Ha-h]{32}-X|[0-9a-h]{12}))\b/, ["flwseck"]],
	["GitHub App installation token", /\b(v1\.[0-9A-Fa-f]{40})\b/, ["v1."]],
	["Mailchimp API key", /\b([0-9a-f]{32}-us\d{1,2})\b/, ["-us"]],
	["Shopify Partner API token", /\b(prtapi_[0-9a-f]{32})\b/, ["prtapi_"]],
	["Aiven service password", /\b(AVNS_[0-9A-Za-z_-]{15,123})\b/, ["avns_"]],
	["Artifactory API key", /\b(AKCp[0-9A-Za-z/+]{69})(?![0-9A-Za-z/+])/, ["akcp"]],
	["Lob API key", /(?<![\w/.-])((?:live|test)_[0-9a-f]{35})(?![\w.])/, ["live_", "test_"]],
	["Azure API Management key", /\b(GatewayKey [A-Za-z0-9_-]{3,64}&\d{12}&[A-Za-z0-9+/]{60,90}==)/, ["gatewaykey"]],
	["Dropbox access token", /\b(sl\.[A-Za-z0-9_-]{130,200})(?![A-Za-z0-9_-])/, ["sl."]],
	["Oculus access token", /\b(OCA[A-Za-z0-9]{90,400})\b/, ["oca"]],
	["New Relic REST API key", /\b(NRRA-[0-9a-f]{42})\b/, ["nrra-"]],
	[
		"PlanetScale token",
		/\b(pscale_(?:app_secret|tkn|oauth|pw)_[0-9A-Za-z_=.-]{32,64})(?![0-9A-Za-z_=.-])/,
		["pscale_"],
	],
	["SonarQube token", /\b(sq[upa]_[0-9a-f]{40})\b/, ["squ_", "sqp_", "sqa_"]],
	["Dynatrace token", /\b(dt0[a-z]\d{2}\.[A-Z0-9]{8,24}\.[A-Z0-9]{64})\b/, ["dt0"]],
	["Render API key", /\b(rnd_[A-Za-z0-9]{32})\b/, ["rnd_"]],
	[
		"Render deploy hook key",
		/api\.render\.com\/deploy\/srv-[a-z0-9]{10,40}\?key=([A-Za-z0-9_-]{8,64})/,
		["api.render.com/deploy"],
	],
	[
		"PagerDuty routing key",
		/\b(?:routing|integration|service)_key["']?[ \t]*[:=][ \t]*["']?([0-9a-f]{32})\b/,
		["routing_key", "integration_key", "service_key"],
	],
	["Yandex Cloud IAM token", /\b(t1\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{60,200})(?![A-Za-z0-9_-])/, ["t1."]],
	// DER prefixes: PKCS#8 RSA (`30 82 … 02 01 00 30 0D 06 09 2A 86 48 86 F7 0D 01 01 01`), PKCS#1 RSA, PKCS#8 and SEC1 EC P-256.
	[
		"private key (base64 DER, no PEM armour)",
		/(?<![A-Za-z0-9+/])((?:MII[A-Za-z0-9+/]{3}IBADANBgkqhkiG9w0BAQEFAASC|MII[A-Za-z0-9+/]{3}IBAAKCA[QgI]EA|MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0w|MHcCAQEEI)[A-Za-z0-9+/]{60,8000}={0,2})/,
		["mii", "mighageambmgbyqgsm49", "mhccaqeei"],
	],
	["Akamai EdgeGrid token", /\b(akab-[a-z0-9-]{30,40})(?![a-z0-9-])/, ["akab-"]],
	["Elasticsearch enrollment token", /\b(eyJ2ZXIiOiI[4-9][A-Za-z0-9+/]{60,600}={0,2})/, ["eyj2zxiioii"]],
	["New Relic license key", /\b([0-9a-f]{36}NRAL)\b/, ["nral"]],
	["Honeycomb API key", /\b(hc(?:ai|xi|am|xm)k_[a-z0-9]{58})\b/, ["hcaik_", "hcxik_", "hcamk_", "hcxmk_"]],
	["Mailgun signing-style API key", /\b([0-9a-f]{32}-[0-9a-f]{8}-[0-9a-f]{8})\b/, []],
	["LaunchDarkly SDK key", /\b(sdk-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b/, ["sdk-"]],
	["Rails session cookie", /(?<![A-Za-z0-9+/=-])([A-Za-z0-9+/]{40,4000}={0,2}--[0-9a-f]{40})\b/, ["--"]],
	["Mercado Pago access token", /\b((?:APP_USR|TEST)-\d{16}-\d{6}-[0-9a-f]{32}-\d{6,10})\b/, ["app_usr-", "test-"]],
	["LangSmith API key", /\b(lsv2_(?:pt|sk)_[0-9a-f]{32}(?:_[0-9a-f]{10})?)\b/, ["lsv2_"]],
	[
		"HubSpot private app token",
		/\b(pat-(?:na|eu|ap)\d-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b/,
		["pat-na", "pat-eu", "pat-ap"],
	],
	["Midtrans server key", /\b((?:SB-)?Mid-server-[A-Za-z0-9_-]{20,40})/, ["mid-server-"]],
	[
		"Yandex Cloud key",
		/\b(AQVN[A-Za-z0-9_-]{35,38}|YCAJ[A-Za-z0-9_-]{21}|YC[A-Za-z0-9_-]{38})(?![A-Za-z0-9_-])/,
		["aqvn", "ycaj", "yc"],
	],
	["DigitalOcean Spaces access key", /\b(DO00[A-Z0-9]{16})\b/, ["do00"]],
	["Neon password", /\b(npg_[A-Za-z0-9]{12,40})\b/, ["npg_"]],
	["Wakatime key", /\b(waka_[a-f0-9-]{36})\b/, ["waka_"]],
	["Bitwarden token", /\b(0\.[a-f0-9-]{36}\.[A-Za-z0-9]{30}:[A-Za-z0-9+/=]{24})(?![A-Za-z0-9+/=])/, ["0."]],
	[
		"Bearer token in JSON Web Token form",
		/\b(eyJ[A-Za-z0-9_-]{8,4096}\.eyJ[A-Za-z0-9_-]{8,8192}\.[A-Za-z0-9_-]{8,2048})/,
		["eyj"],
	],
	[
		"Encrypted JSON Web Token",
		/\b(eyJ[A-Za-z0-9_-]{8,2048}\.[A-Za-z0-9_-]{0,2048}\.[A-Za-z0-9_-]{16,2048}\.[A-Za-z0-9_-]{16,65536}\.[A-Za-z0-9_-]{16,256})/,
		["eyj"],
	],
];

let formats: Format[] | undefined;
function load(): Format[] {
	if (formats) return formats;
	formats = CORE_FORMATS.map(([name, re, keywords]) => ({
		name,
		re: new RegExp(re.source, `${re.flags.replace(/[gd]/g, "")}gd`),
		keywords,
		shortest: 1,
		minEntropy: 0,
		byVendorWord: false,
		rejects: REJECTS[name],
		gate: GATES[name],
	}));
	for (const [name, source, flags, keywords, minEntropy, byVendorWord] of IMPORTED_FORMATS) {
		try {
			formats.push({
				name,
				re: new RegExp(source, `${flags}gd`),
				keywords,
				shortest: 8,
				minEntropy,
				byVendorWord: byVendorWord === 1,
				rejects: REJECTS[name],
				gate: GATES[name],
			});
		} catch {
			// A rule this JS engine can't compile is skipped, never fatal (test/formats.test.ts checks that none is).
		}
	}
	const index = new Map<string, number>();
	byKeyword = [];
	always = [];
	formats.forEach((f, i) => {
		if (!f.keywords.length) always.push(i);
		for (const k of f.keywords) {
			let at = index.get(k);
			if (at === undefined) {
				at = index.size;
				index.set(k, at);
				byKeyword.push([]);
			}
			byKeyword[at].push(i);
		}
	});
	keywordSet = new KeywordSet([...index.keys()]);
	return formats;
}

/**
 * The text with the letters of its escapes blank (`\n`, `\t`, `\r`, `\u0027`, `\x27` after an odd run of backslashes;
 * not a path's `C:\\new`), the same length: where an escaped string's line breaks and quotes are, words start.
 */
function withoutEscapeLetters(text: string): string {
	if (!text.includes("\\")) return text;
	return text.replace(/\\(?:[ntr]|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2})/g, (escape, at: number) =>
		backslashesBefore(text, at) % 2 === 0 ? `\\${" ".repeat(escape.length - 1)}` : escape,
	);
}

/** The front of a link that names no one's secret: its scheme, host and the all-lower-case words of its path (`https://hooks.slack.com/services/`). */
const URL_READABLE_PREFIX = /^(?:https?:\/\/)?[a-z0-9-]+(?:\.[a-z0-9-]+)+\/(?:[a-z]+\/)*/;

/**
 * Where a rule's secret is: its first group that has no name of its own, since a rule names the parts that
 * describe the secret (`Endpoint=(?<endpoint>https://…);Id=(?<id>…);Secret=(…)`); else its first group, else the match.
 */
function secretSpan(indices: RegExpIndicesArray): [number, number] {
	const named: unknown[] = Object.values(indices.groups ?? {});
	for (let i = 1; i < indices.length; i++)
		if (indices[i] && !named.includes(indices[i])) return indices[i] as [number, number];
	return (indices[1] ?? indices[0]) as [number, number];
}

const CONNECTION_STRING_NAME = /connection string$/;

/**
 * A connection string's key, not the whole of it: its endpoint, key name and entity path say where it connects and stay
 * (`Endpoint=sb://shop-bus.servicebus.windows.net/;SharedAccessKeyName=Root;SharedAccessKey=<key>;EntityPath=orders`).
 * The span is kept whole if no part of it is named like a secret.
 */
function connectionStringSecret(text: string, start: number, end: number): [number, number] {
	const m = /(?:^|;)[^;=]*(?:key|secret|password|pwd|signature)=([^;]*)/i.exec(text.slice(start, end));
	if (!m) return [start, end];
	const at = start + m.index + m[0].length - m[1].length;
	return [at, at + m[1].length];
}

/** Every credential in `text` recognizable by format. */
export function findFormats(text: string): Finding[] {
	const out: Finding[] = [];
	const all = load();
	const run = new Set(always);
	for (const k of keywordSet!.find(text)) for (const i of byKeyword[k]) run.add(i);
	// (Matched on the text with each escape's letters blank, positions kept: after `\t` or `\n` in a repr or a log, a
	// token starts there, not at the `t` or `n`.)
	const scan = withoutEscapeLetters(text);
	for (const i of [...run].sort((a, b) => a - b)) {
		const f = all[i];
		if (f.gate && !f.gate.test(text)) continue;
		for (const m of scan.matchAll(f.re)) {
			let [start, end] = secretSpan(m.indices!);
			// A URL-shaped rule that matches the whole link has its secret in the path: keep the readable part (`https://hooks.slack.com/services/`).
			if (!m.indices![1]) start += URL_READABLE_PREFIX.exec(m[0])?.[0].length ?? 0;
			if (CONNECTION_STRING_NAME.test(f.name)) [start, end] = connectionStringSecret(scan, start, end);
			if (end - start < f.shortest) continue;
			const value = text.slice(start, end);
			// (A token that goes on past the match isn't this vendor's: a rule of fixed length matched its prefix.)
			if (/[A-Za-z0-9]/.test(scan[end] ?? "") && /[A-Za-z0-9]$/.test(value)) continue;
			// (Publishable keys, public JWTs and client-side Google keys: decided in policy.ts.)
			if (isPlaceholder(value)) continue;
			if (f.rejects?.(value, text.slice(Math.max(0, start - 200), start))) continue;
			// A whole connection string: the URL rule hides just its password and keeps the host.
			if (leadingUrl(value)?.user) continue;
			// Real tokens don't read as words: `sk-toggleable__label-arrow`, `sk-NotificationsClient.Models.Response`.
			if (naturalness(value) > 1.0) continue;
			// A vendor-word rule: the name the value is assigned to must not say it's an ID, a hash or public.
			if (f.byVendorWord) {
				const gap = text.slice(m.index, start);
				// `virustotal,<sha256>` in an IOC list: a comma isn't an assignment, and a bare hash isn't a key.
				if (
					!/key|token|secret|pass|auth|cred|api|pat\b|sid/i.test(gap) &&
					(!/[=:]/.test(gap) || /^[0-9a-f]+$/i.test(value))
				)
					continue;
				const name =
					text
						.slice(m.index, start)
						.match(/([A-Za-z_][\w.-]{0,80})[ \t]{0,8}["'\]]?[ \t]{0,8}(?:=|:|=>)[^=:]{0,10}$/)?.[1] ?? "";
				const cls = name ? nameClass(name) : "neutral";
				if (cls === "identifier" || cls === "hash" || cls === "public") continue;
				if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value) && !isCredentialName(name))
					continue;
			}
			if (f.minEntropy && entropy(value) < f.minEntropy) continue;
			out.push({ start, end, kind: f.name, rule: `format:${f.name}`, confidence: 1 });
		}
	}
	return out;
}
