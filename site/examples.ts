/**
 * The demo's examples: agent output with secrets in it, and the look-alikes around them that must stay. The secrets
 * are drawn from a seeded generator, so every visit shows the same ones (and test/site.test.ts checks what each example
 * shows), and no vendor's token is written out in full here (test/hygiene.test.ts).
 */
import { mulberry32Bits } from "../eval/random.ts";
import type { Hint } from "../src/index.ts";

export interface Example {
	label: string;
	text: string;
	hint: Hint;
	/** The secrets in `text`, which redaction must hide (with the default guessing). */
	secrets: string[];
	/** Values that look like secrets but aren't, which redaction must keep. */
	kept: string[];
}

const next = mulberry32Bits(0x5eed);
const draw = (alphabet: string, n: number) =>
	Array.from({ length: n }, () => alphabet[next() % alphabet.length]).join("");
const b62 = (n: number) => draw("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", n);
const hex = (n: number) => draw("0123456789abcdef", n);

const env = { password: b62(16), stripe: `sk_live_${b62(24)}`, salt: b62(10) };
const shell = {
	sha: hex(40),
	github: `ghp_${b62(36)}`,
	digest: hex(64),
	aws: draw("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 40),
};
const code = { smtp: `${b62(6)}-${b62(6)}-${b62(4)}`, api: b62(32) };
const log = { token: b62(40), request: hex(32) };

export const examples: Example[] = [
	{
		label: ".env file",
		hint: { command: "cat .env" },
		text: `# Written by setup.sh
NODE_ENV=production
PORT=8080
DATABASE_URL=postgres://app:${env.password}@db.internal:5432/app
REDIS_URL=redis://cache.internal:6379/0
STRIPE_SECRET_KEY=${env.stripe}
SESSION_SALT=${env.salt}
FEATURE_FLAGS=search,checkout-v2
`,
		secrets: Object.values(env),
		kept: ["production", "8080", "redis://cache.internal:6379/0", "search,checkout-v2"],
	},
	{
		label: "Shell session",
		hint: {},
		text: `$ git log -1 --format='%H %s'
${shell.sha} Fix retry backoff in uploader
$ export GITHUB_TOKEN=${shell.github}
$ curl -s -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user | jq .login
"octocat"
$ docker inspect --format '{{.Id}}' app:latest
sha256:${shell.digest}
$ aws configure get aws_secret_access_key
${shell.aws}
`,
		secrets: [shell.github, shell.aws],
		kept: [shell.sha, shell.digest, "$GITHUB_TOKEN"],
	},
	{
		label: "Config in code",
		hint: { path: "app/settings.py" },
		text: `import os

DEBUG = False
DB_PASSWORD = os.environ["DB_PASSWORD"]
SMTP_PASSWORD = "${code.smtp}"
API_BASE = "https://api.example.com/v2"
CACHE_KEY_PREFIX = "settings-v3"

client = PaymentsClient(api_key="${code.api}", timeout=30)
`,
		secrets: Object.values(code),
		kept: ['os.environ["DB_PASSWORD"]', "https://api.example.com/v2", "settings-v3"],
	},
	{
		label: "Bare token in a log",
		hint: {},
		text: `[deploy] uploading build 2026.10.11-3 to the artifact store
[deploy] request ${log.request} accepted
[deploy] using ${log.token}
[deploy] done in 41.2s
`,
		secrets: [log.token],
		kept: [log.request, "2026.10.11-3"],
	},
];
