/**
 * Public parts of secret-shaped things: a URL-shaped format's readable front, a connection string's endpoint, hashes,
 * ids, addresses and public client keys, an asset's name, a test's expected value; and the scans that keep large
 * texts fast.
 *
 *   node --test test/public-values.test.ts
 *
 * (A fake key's vendor prefix is written with an escape, `"ghp\x5f…"`: written whole, the repository would hold text
 * that secret scanners, GitHub's push protection among them, take for a live key.)
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { KeywordSet } from "../src/aho.ts";
import { Redactor } from "../src/index.ts";
import { asciiSet, longRuns } from "../src/runs.ts";
import { hidden, kept, r } from "./helpers.ts";
import { random, randomBytes } from "./random.ts";

test("a webhook's URL keeps its host and path words, hides the secret path", () => {
	const secret = "T024BE7LD/B07QJ3K2M9P/yQxCGClbaNFDpCWNX0D1lZEz";
	for (const prefix of [
		"https://hooks.slack.com/services/",
		"hooks.slack.com/workflows/",
		"http://hooks.slack.com/triggers/",
	]) {
		kept(`SLACK_WEBHOOK_URL=${prefix}${secret}`, prefix);
		hidden(`SLACK_WEBHOOK_URL=${prefix}${secret}`, secret);
	}
	hidden(
		"curl -X POST https://hooks.slack.com\x2fservices/T024BE7LD/B07QJ3K2M9P/yQxCGClbaNFDpCWNX0D1lZEz -d '{}'",
		"yQxCGClbaNFDpCWNX0D1lZEz",
	);
});

test("a connection string keeps the endpoint and key name, hides the key", () => {
	const endpoint =
		"Endpoint=sb://shop-bus.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=";
	const key = "pX4mT8vQ2kL9rW3nZ7bY5cH1dF6gJ0sA+eUo=";
	kept(`${endpoint}${key}`, endpoint);
	hidden(`${endpoint}${key}`, key);
	kept(`${endpoint}${key};EntityPath=orders`, ";EntityPath=orders");
	const config =
		"Endpoint=https://myconf.azconfig.io;Id=abcd-l0-s0:Zx81kP0qLm2Vb7Rt;Secret=\x51m9vZ1xLp7Rt3Vw8Ny2Kc5Hj0Df4Gs6Bz0123456789abcdefg=";
	kept(config, "https://myconf.azconfig.io");
	hidden(config, "Qm9vZ1xLp7Rt3Vw8Ny2Kc5Hj0Df4Gs6Bz0123456789abcdefg=");
});

test("a hashed known_hosts entry is a salted hash of a public host name", () => {
	const entry = "|1|kXz5n8cFq1u3Yx7mM3p0wqY9d2s=|q3w8vZbN2c1pL4kQ0eT7rY6uI9o=";
	kept(`${entry} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl`, entry);
	kept(
		`github.com,140.82.112.3 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n${entry} ssh-rsa AAAAB3NzaC1yc2E`,
		entry,
	);
});

test("a bundler's hashed asset name under a sign-in path is no token", () => {
	for (const name of [
		"app-Kx81kP0qLm2Vb7Rt.js",
		"chunk.3f9a2c1e.css",
		"Inter-Bold.Zk3mP9qL.woff2",
		"vendor-Qm7Rt3Vw8Ny2Kc5H.mjs",
	])
		kept(`https://cdn.example.com/assets/login/${name}`, name);
	hidden("https://example.com/reset/Qm9vZ1xLp7Rt3Vw8Ny2Kc5Hj0Df4Gs6Bz", "Qm9vZ1xLp7Rt3Vw8Ny2Kc5Hj0Df4Gs6Bz");
});

test("what a test compares its result to is output", () => {
	const digest = "ZdzRnJ3Rk1R6OBZ8u2vKpXN1cS0yZ3d4V0JxT2NYb2c";
	for (const name of ["want", "expected", "golden", "wantDigest", "expected_output"])
		kept(`\t${name} := "${digest}"\n\tif got != ${name} {}`, digest);
	hidden(`\tsigningKey := "${digest}"`, digest);
});

test("runs of a character set are found as a regex finds them", () => {
	const set = asciiSet("abc=");
	for (let n = 0; n < 3000; n++) {
		const alphabet = "abcab=d é";
		let text = "";
		for (let i = Math.floor(random() * 80); i > 0; i--) text += alphabet[Math.floor(random() * alphabet.length)];
		for (const min of [1, 2, 3, 5, 16]) {
			const expected = [...text.matchAll(new RegExp(`[abc=]{${min},}`, "g"))].map((m) => [
				m.index,
				m.index + m[0].length,
			]);
			assert.deepEqual([...longRuns(text, set, min)], expected, JSON.stringify([text, min]));
		}
	}
});

test("keywords are found in any case, and non-ASCII ones whole", () => {
	const keywords = ["he", "she", "his", "hers", "Ünï", "😀x", "abc", "bc", "c"];
	const text = "ushers HIS ÜNÏ SHE 😀x aBc zzz ABC Ünï";
	for (const caseSensitive of [true, false]) {
		const folded = caseSensitive ? text : text.replace(/[A-Z]/g, (c) => c.toLowerCase());
		const expected: string[] = [];
		keywords.forEach((k, i) => {
			const word = caseSensitive ? k : k.replace(/[A-Z]/g, (c) => c.toLowerCase());
			for (let at = folded.indexOf(word); at >= 0; at = folded.indexOf(word, at + 1)) expected.push(`${at}:${i}`);
		});
		const found = [...new KeywordSet(keywords, caseSensitive).matches(text)].map(([at, i]) => `${at}:${i}`);
		assert.deepEqual(found.sort(), expected.sort());
	}
});

test("a base64 body inside an element keeps its first and last lines; one-line elements are values", () => {
	const eager = (text: string) => new Redactor({ fingerprintKey: "test", guessing: "eager" }).redact(text).text;
	const lines = randomBytes(48 * 12 - 3)
		.toString("base64")
		.match(/.{1,64}/g)!;
	for (const xml of [
		`<ds:X509Certificate>${lines.join("&#xA;")}</ds:X509Certificate>`,
		`<X509Certificate>${lines.join("\n")}</X509Certificate>`,
	]) {
		assert.equal(eager(xml), xml);
	}
	const values = [1, 2, 3].map((n) => `<value${n}>${randomBytes(48).toString("base64")}</value${n}>`).join("\n");
	for (const line of values.split("\n")) assert.ok(!eager(values).includes(line), line);
});

test("hashes, digests, cache keys and pinned versions are kept", () => {
	const sha = randomBytes(20).toString("hex");
	kept(`commit ${sha}\nAuthor: Jane <j@x.io>`, sha);
	kept(`git checkout ${sha.slice(0, 12)}`, sha.slice(0, 12));
	const digest = randomBytes(32).toString("hex");
	kept(`image: nginx@sha256:${digest}`, digest);
	const integrity = `sha512-${randomBytes(64).toString("base64")}`;
	kept(`"integrity": "${integrity}"`, integrity);
	kept(
		"go.opentelemetry.io/otel v1.24.0 h1:0LAOdjNmQeSTzGBzduGe/rU4tZhMwL5rWgtp9Ku5Jfo=",
		"h1:0LAOdjNmQeSTzGBzduGe/rU4tZhMwL5rWgtp9Ku5Jfo=",
	);
	const hex = (n: number) => randomBytes(n).toString("hex");
	const h = hex(32);
	kept(`      annotations:\n        checksum/secret: ${h}\n`, h);
	kept(`  with:\n    path: ~/.npm\n    key: Linux-node-${h}\n`, `Linux-node-${h}`);
	kept(`Cache restored from key: node-cache-Linux-x64-pnpm-${h}`, `node-cache-Linux-x64-pnpm-${h}`);
	kept(`gpg --batch --keyserver keys.openpgp.org --recv-keys ${hex(20).toUpperCase()}`, "--recv-keys");
	kept(
		"        id: generate_token\n        uses: actions/create-github-app-token@29824e69f54612133e76f7eaac726eef6c875baf # v2.2.1",
		"29824e69f546",
	);
	kept('    js-tokens: "npm:^4.0.0"\n"chalk@npm:^4.0.0":\n  version: 4.1.2', "npm:^4.0.0");
	kept(
		"github.com/aws/aws-sdk-go-v2/credentials v1.20.6/go.mod h1:mcZCoiPnyMvP8VMNxVrmTzlnC4bDhYcFpq9Yt1MpJ0c=",
		"v1.20.6/go.mod",
	);
	kept(
		'      "integrity": "sha1-IpnwLG3tMNSllhsLn3RSShj2NPw= sha512-BNGbWLfd0eUPabhkXUVm0j8uuvREyTh5ovRa/dyow/BqAbZJyC+5fU+IzQOzmAKzYqYRAISoRhdQr3eIZ/PXqg==",',
		"sha512-BNGbWLfd0e",
	);
	kept("Cache restored from key: windows-template|master|232e6b14abf6e590b41d60f11704e42de22bff72", "232e6b14abf6");
	const t = '"salt": "v1:t4ZEsDDBDbZn:v1:inJ1HwcImHrrlC7x:gS/g3TtV9TKP9yyaZV5EhFqdgBC17MJID0smDiFHej40"';
	assert.equal(r().redact(t).text, t);
});

test("a checksum manifest's file names name files, not credentials", () => {
	const md5 = () => randomBytes(16).toString("hex");
	const [key, pin, type, api] = [md5(), md5(), md5(), md5()];
	const manifest = `{\n  "manifests/key.pp": "${key}",\n  "manifests/pin.pp": "${pin}",\n  "lib/puppet/type/apt_key.rb": "${type}",\n  "api_key": "${api}"\n}`;
	for (const v of [key, pin, type]) kept(manifest, v);
	hidden(manifest, api);
	// A key file's name, as a Kubernetes Secret's key: its value is the key.
	const master = md5();
	hidden(`stringData:\n  master.key: ${master}\n`, master);
});

test("ids of requests, traces, customers, refunds, events and jobs are kept", () => {
	kept("request_id=d389154b-f4aa-4049-a502-f7360774dea4", "d389154b-f4aa-4049-a502-f7360774dea4");
	kept("traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01", "0af7651916cd43dd8448eb211c80319c");
	kept("customer cus_NffrFeUfNV2Hib paid", "cus_NffrFeUfNV2Hib");
	kept('  "resolved": "https://registry.npmjs.org/onetime/-/onetime-5.1.2.tgz",', "onetime-5.1.2.tgz");
	kept(`INSERT INTO "Post" ("id","title") VALUES ('mqns7rh5ogkrsomqbiyz1zpv','Hello');`, "mqns7rh5ogkrsomqbiyz1zpv");
	kept("Created refund re_3MtwBwLkdIwHu7ix0snN0B15 for the charge.", "re_3MtwBwLkdIwHu7ix0snN0B15");
	kept("2026-05-18 14:02:11   --> customer.created [evt_nDjs7UVsuRCE1w7ZLmi5F3Nr]", "evt_nDjs7UVsuRCE1w7ZLmi5F3Nr");
	kept(
		"PATCH /api/posts/fiadlouehgdc7y4p8uld6h4g 500 in 41ms\nError: Post fiadlouehgdc7y4p8uld6h4g not found",
		"Post fiadlouehgdc7y4p8uld6h4g",
	);
	kept("job id 01KYXZARV8RCAP7ZT2WNZ8FTXC", "01KYXZARV8RCAP7ZT2WNZ8FTXC");
	kept('"aliases":["CVE-2026-56304","GHSA-m7j5-r2p5-c39r"]', "GHSA-m7j5-r2p5-c39r");
	kept(
		'{"functionCall":{"name":"read_file","args":{"absolute_path":"/x"}},"thoughtSignature":"CnhZ/7SwCJpBk+7mQq6yV6XiDD3NIbUpsv3APuj54jpvYcrLamuaKQS9IzNoIzC3gMWHTrw3y2QbkO0"}',
		"CnhZ/7SwCJpBk+7mQq6yV6XiDD3NIbUpsv3APuj54jpvYcrLamuaKQS9IzNoIzC3gMWHTrw3y2QbkO0",
	);
	kept("token_accessor       F7gaT4UlTlyF7R3DNcUGESnW", "F7gaT4UlTlyF7R3DNcUGESnW");
	kept('"nextPageToken": "CiAKGjBpNDd2Nmp2Zml2cXRwYjBpOXA2NWQ"', "CiAKGjBpNDd2Nmp2Zml2cXRwYjBpOXA2NWQ");
	kept(
		"Click [here](https://survey3.medallia.com/?EAHeSx-AP01bZqG0Ld9QLQ) to start the survey.",
		"EAHeSx-AP01bZqG0Ld9QLQ",
	);
	kept(
		'<a href="https://github.com/o/r/pull/1774/files#diff-536fe11895519a527a35ae35dd0e1621e975d23022a06887114752aabbccddee">',
		"diff-536fe11895519a527a35ae35dd0e1621e975d23022a06887114752aabbccddee",
	);
});

test("public keys and client-side keys are kept", () => {
	kept(
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC1PG3wgMudF3AWAPXyVoViLae2O2W2pe/PsBVaiIW+z me@host",
		"AAAAC3NzaC1lZDI1NTE5AAAAIC1PG3wgMudF3AWAPXyVoViLae2O2W2pe/PsBVaiIW+z",
	);
	kept(
		"posthog.init('\x70hc_DDNmfMZ2O5f6powLQU8zkE96mrWzYDigX8PD7wXTlqM', {api_host: 'https://us.i.posthog.com'})",
		"\x70hc_DDNmfMZ2O5f6powLQU8zkE96mrWzYDigX8PD7wXTlqM",
	);
	kept(
		"interface: wg0\n  public key: Xq7Lm2Vb9Rt4Np8KwZ3cAbQx7Lm2Vb9Rt4Np8KwZ3c=\n",
		"Xq7Lm2Vb9Rt4Np8KwZ3cAbQx7Lm2Vb9Rt4Np8KwZ3c=",
	);
	kept(
		'SHOPIFY_API_KEY = ENV.fetch("SHOPIFY_API_KEY", "5df6881d8dcd52ca7af63584a8af9389")',
		"5df6881d8dcd52ca7af63584a8af9389",
	);
	kept(
		'  apiKey: "AIz\x61X7c4lsgg386vsnKo5j5zoobiOPt2wwdjOhe",\n  authDomain: "acme.firebaseapp.com",',
		"AIz\x61X7c4lsgg386vsnKo5j5zoobiOPt2wwdjOhe",
	);
	kept(
		"      NEXT_PUBLIC_MAPBOX_TOKEN: pk.uGd0pw7StHQENed0156f_bm1Ry6hrbazVAukzHjD5Lxra2hXImh2xaWqeB05",
		"uGd0pw7StHQENed0156f",
	);
	kept(
		"new ReCaptchaEnterpriseProvider('6LOFVXuFfhlM_pt0t47k936zypIDhbHgsl14pYTK')",
		"6LOFVXuFfhlM_pt0t47k936zypIDhbHgsl14pYTK",
	);
	kept(
		"resend._domainkey TXT p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQUlJCpi2gvcnXxxhn3wXqTDJv/IUxzh4kJF0uIZYBq7vFi1gq",
		"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQUlJCpi2gvcnXxxhn3wXqTDJv",
	);
	kept("FLY_IMAGE_REF=registry.fly.io/harbor-crm:deployment-ONCAGR7JGSLAPXLVJOSHS8ZAKW", "ONCAGR7JGSLAPXLVJOSHS8ZAKW", {
		command: "printenv",
	});
	kept(
		'<meta name="google-site-verification" content="KIO5H8Bg3i0oAEAzTEMK5qIlYJLbd2zogLs_-im4rI0" />',
		"KIO5H8Bg3i0oAEAzTEMK5qIlYJLbd2zogLs_-im4rI0",
	);
	kept(
		"options: {\n  appId: 'ZTF29HGJ69',\n  apiKey: '9c3ced6fed60d2670bb36ab7e8bed8bc',\n  indexName: 'vitest',",
		"9c3ced6fed60d2670bb36ab7e8bed8bc",
	);
	kept(
		"LOB_PUBLISHABLE_KEY=live\x5fpub_8f3a9c1e2b4d5a6c7b8e9f0a1b2c3d4",
		"live\x5fpub_8f3a9c1e2b4d5a6c7b8e9f0a1b2c3d4",
	);
	kept(
		'<script src="https://maps.googleapis.com/maps/api/js?key=AIz\x61SyD2kP9xW4vR7tN1mQ8zL3cH6jF0bY5gU2e&callback=initMap"></script>',
		"AIz\x61SyD2kP9xW4vR7tN1mQ8zL3cH6jF0bY5gU2e",
	);
	for (const t of [
		"[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=foo&metric=alert_status&token=sqb_3f9a1c2d4e5b6a7c8d9e0f1a2b3c4d5e6f7a8b9c)](https://sonarcloud.io)",
		"[![CircleCI](https://dl.circleci.com/status-badge/img/gh/foo/bar/tree/main.svg?style=svg&circle-token=9f8e7d6c5b4a3928170615243f5e6d7c8b9a0f1e)](https://circleci.com)",
	])
		assert.equal(r().redact(t).text, t);
	for (const t of [
		"// search-only key: safe in the browser\nexport const searchClient = algoliasearch('0OAZG8IZTI', 'a6253cf115d0d641f97b6f9d92f2800a')",
		'import { createInstance } from "@optimizely/react-sdk";\nconst optimizely = createInstance({ sdkKey: "c11WoOAeDOWgf0DPGI3OAG" });',
	])
		assert.equal(r().redact(t).text, t);
	for (const line of [
		"gpg --sign-key 40DFB630FF42BCFFB047046CF0134EE680CAC571",
		"sudo pacman-key --lsign-key 40DFB630FF42BCFFB047046CF0134EE680CAC571",
		"gpg --default-key 3AA5C34371567BD2 --sign x",
	])
		kept(line, line.match(/[0-9A-F]{16,40}/)![0]);
});

test("a client SDK's key is an argument or a member of its config; not a comment in it, nor a bare factory's", () => {
	kept('const pusher = new Pusher(Kx9mQv2Lp7Rt3Vw8Ny2K, { cluster: "eu" });', "Kx9mQv2Lp7Rt3Vw8Ny2K");
	const bugsnag =
		'Bugsnag.start({\n  apiKey: "9f8e7d6c5b4a3928170615243f5e6d7c",\n  // CI\'s upload token: Kx9mQv2Lp7Rt3Vw8Ny2Kc5Hj\n});';
	kept(bugsnag, "9f8e7d6c5b4a3928170615243f5e6d7c");
	hidden(bugsnag, "Kx9mQv2Lp7Rt3Vw8Ny2Kc5Hj");
	hidden(
		'const client = createInstance({ baseURL: "https://api.acme.dev", token: "Kx9mQv2Lp7Rt3Vw8Ny2Kc5Hj" });',
		"Kx9mQv2Lp7Rt3Vw8Ny2Kc5Hj",
	);
});

test("a Google key is a client's only in a client config's own object, call or paragraph", () => {
	const client = "AIz\x61SyB3kP9xW4vR7tN1mQ8zL3cH6jF0bY5gU2e";
	const server = "AIz\x61SyD2kP9xW4vR7tN1mQ8zL3cH6jF0bY5gU2e";
	// The object it sits in has a Firebase config's fields, before or after a call in it; google-services.json's `api_key`.
	for (const config of [
		`const config = {\n  messagingSenderId: "448618578101",\n  projectId: env("PROJECT_ID"),\n  apiKey: "${client}",\n};`,
		`const config = {\n  apiKey: "${client}",\n  appId: env("APP_ID"),\n  messagingSenderId: "448618578101",\n};`,
		`      "api_key": [\n        {\n          "current_key": "${client}"\n        }\n      ],`,
	])
		kept(config, client);
	// A server's key in a call, or beside a client config: in the next statement, a paragraph below, a nested section.
	for (const text of [
		`const translate = new Translate({ projectId: "acme", key: "${server}" });`,
		`final places = GoogleMapsPlaces(apiKey: '${server}');\nfinal options = FirebaseOptions(apiKey: '${client}', appId: '1:448618578101:android:0b650370bb29e29c', messagingSenderId: '448618578101', projectId: 'acme');`,
		`GOOGLE_TRANSLATE_KEY = "${server}"\nTRANSLATE_REGION = "us-central1"\n\nFIREBASE_WEB = {"authDomain": "acme.firebaseapp.com", "messagingSenderId": "448618578101"}`,
		`google:\n  translate_key: ${server}\n  web:\n    authDomain: acme.firebaseapp.com\n    messagingSenderId: "448618578101"`,
	])
		hidden(text, server);
});

test("wallet addresses are kept", () => {
	kept(`token0: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"`, "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
	kept("destination = '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2'", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
	kept(
		"Send it to `7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU` on devnet.",
		"7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
	);
	kept('signer:"celestia1rky9086t340m7rmkctuj4spxwv2gc62vlwx59v"', "celestia1rky9086t340m7rmkctuj4spxwv2gc62vlwx59v");
	kept("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq");
	// An XRP Ledger account, by its checksum in XRP's own base58 alphabet; one character off, it's a random token.
	kept("{ issuer: 'rfXK4fN2AAqH7H5Uo94JQwT88qQkv69pqR', value: '0' }", "rfXK4fN2AAqH7H5Uo94JQwT88qQkv69pqR");
	hidden("{ issuer: 'rfXK4fN2AAqH7H5Uo94JQwT88qQkv69pqS', value: '0' }", "rfXK4fN2AAqH7H5Uo94JQwT88qQkv69pqS");
});

test("build, tracking and protocol data that looks like a secret is kept", () => {
	kept("CSRF_COOKIE\t'RoSuecQMH3vZXsFp13np3lgymaXlV498'", "RoSuecQMH3vZXsFp13np3lgymaXlV498");
	kept(
		"script-src 'self' 'nonce-kPXDxABNuZat3yDNgk494nPB' 'sha256-WhV5zA0zHotqcTgxWlKXGChzzYzib4vbbGwB0Dk1H9z='",
		"WhV5zA0zHotqcTgxWlKXGChzzYzib4vbbGwB0Dk1H9z=",
	);
	kept("https://www.amazon.com/s?k=x&pf_rd_r=B5MPZV3NBWCBQEBDWXSF&text=y", "B5MPZV3NBWCBQEBDWXSF");
	kept(
		'"inspectorUrl": "https:\\/\\/vercel.com\\/acme-projects\\/portfolio\\/CmRHhgqaCzL3LWSNfsRmxen8Saz1",',
		"CmRHhgqaCzL3LWSNfsRmxen8Saz1",
	);
	kept(
		"    // resp.razorpay_signature  = db7f4df2236495424e89e5468f8480459bb03395e8e02d1f56da5057c9244d5a",
		"db7f4df2236495424e89e5468f8480459bb03395e8e02d1f56da5057c9244d5a",
	);
	kept(
		'{ "orderId": "88213", "receipt": "CggIkOjTvAYQABIQOWY4YzJiMWE0ZTZkN2MzYhoDVVNE" }\ngrpc-status-details-bin: CAgSHW9yZGVyIDg4MjEzIGFscmVhZHkgc2V0dGxlZBoA',
		"CAgSHW9y",
	);
	kept(
		'"Signature-Input":["sig1=(\\"@authority\\");keyid=\\"poqkLGiymh_W0uP6PZFw-dvez3QJT5SGQqjpZqRzCQ4\\";alg=\\"ed25519\\""]',
		"poqkLGiymh_W0uP6PZFw-dvez3QJT5SGQqjpZqRzCQ4",
	);
	kept('"a=ssrc:OFFERSSRC1 msid:fAB8s1VfJrRwiz2r fAB8s1VfJrRwiz2r-audio\\n"', "fAB8s1VfJrRwiz2r");
	kept("H225_ArrayOf_CryptoH323Token tokens;", "H225_ArrayOf_CryptoH323Token");
	kept(
		'www-authenticate:\n  - Bearer authorization="https://login.microsoftonline.com/213e87ed-8e08-4eb4-a63c-c073058f7b00",\n    resource="https://vault.azure.net"',
		"213e87ed-8e08-4eb4-a63c-c073058f7b00",
	);
	kept('"test_set_password (auth_tests.test_models.AnonymousUserTests)",', "auth_tests.test_models.AnonymousUserTests");
	kept("function _RNvCs30UZn7PijB2_3uvx4main Hash = 6344", "RNvCs30UZn7PijB2_3uvx4main");
	kept("    value: EV[1:nfgkn7v0t4VAqAVUsxEB3ayR/oTGt5MW:mPsSFnSD8CpAUX4b6o5MBbqdT]", "EV[1:nfgkn7v0t4VAqAVUsxEB3ayR");
	kept('  "MIXPANEL_TOKEN": "a0f560e0205d352c166a569086a873ca",', "a0f560e0205d352c166a569086a873ca");
	for (const t of [
		"x ^= 0x1f911b719147c712ull;",
		"   Compiling uv_auth.2a85a8e79fbf3728-cgu.0",
		"Malicious code in 3layerdipstackvd6za6 (npm)",
		"curl http://288utkkq2xbq8e0yi1r5mzkd0y6ou.oastify.com/",
		"stellar: GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H",
		"tron: TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW",
		"https://www.amazon.com/dp/B08N5WRWNW?ref_=x&refRID=K9VQ2X7M3TPA8B4CND6E",
	])
		assert.equal(r().redact(t).text, t);
});

test("a NATS public key is kept and its seed hidden", () => {
	kept(
		'    ADM2CIIL3RWXBA6T2HW3FODNCQQOUJEHHQD6FKCPVAMHDNTTSMO73ROX: "x"',
		"ADM2CIIL3RWXBA6T2HW3FODNCQQOUJEHHQD6FKCPVAMHDNTTSMO73ROX",
	);
	hidden(
		'var seed = []byte("SUAKYRHVIOREXV7EUZTBHUHL7NUMHPMAS7QMDU3GTIUWEI5LDNOXD43IZY")',
		"SUAKYRHVIOREXV7EUZTBHUHL7NUMHPMAS7QMDU3GTIUWEI5LDNOXD43IZY",
	);
});

test("a Cisco type-5 hash is kept", () => {
	kept("enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0", "$1$mERr$hx5rVt7rPNoS4wqbXKX7m0");
	const t = "enable secret 5 $1$abc$xyz";
	assert.equal(r().redact(t).text, t);
});

test("a client SDK's key written as prose writes a pair is the SDK's public key", () => {
	const off = new Redactor({ guessing: "off", fingerprintKey: "test" });
	const t = "mixpanel.init(token: Kx9mQ2vL7pRt4Nw8Yz3aBcDe)";
	assert.equal(off.redact(t).text, t);
});

test("a value in an encryption wrapper is ciphertext, under any name", () => {
	const off = new Redactor({ guessing: "off", fingerprintKey: "test" });
	for (const value of [
		"{cipher}f4c18c30ba955ea000bf139742992cf8d00917732fde4af3ab08550112ece117",
		"ENC[AES256_GCM,data:Tr7o3w==,iv:1BH0fsl1=,tag:Kq0F2mR8==,type:str]",
		"ENC(Hx7mQ2pL9vRt4Wz8Bn3Cd6Fh)",
	])
		assert.ok(off.redact(`spring:\n  datasource:\n    password: "${value}"`).text.includes(value), value);
});

test("an encrypted JWT named as encrypted data is kept, its header read as far as it decodes", () => {
	const header = Buffer.from('{"alg":"PBES2-HS256+A128KW","enc":"A256GCM","p2c":600000}').toString("base64url");
	const part = (n: number) => Buffer.from(Array.from({ length: n }, (_, i) => (i * 37) % 251)).toString("base64url");
	for (const h of [header, `${header}Q`]) {
		const jwe = `${h}.${part(40)}.${part(12)}.${part(80)}.${part(16)}`;
		assert.ok(r().redact(`"encryptedKey": "${jwe}"`).text.includes(jwe), h);
	}
});
