/**
 * Structure: Kubernetes Secrets, hosts, URL and DSN passwords, JWKs, JSON documents and mnemonics.
 *
 *   node --test test/structure.test.ts
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { BIP39_WORDS } from "../src/bip39-data.ts";
import { Redactor } from "../src/index.ts";
import {
	inJwk,
	jsonDocuments,
	jsonLiteralSpans,
	jsonStringLiterals,
	parseJson,
	pythonReprLiterals,
} from "../src/json.ts";
import { findStructure } from "../src/structure.ts";
import { urlEnd, urls } from "../src/urls.ts";
import { siblingValue, yamlLines } from "../src/yaml.ts";
import { b62, hidden, kept, r } from "./helpers.ts";
import { randomBytes } from "./random.ts";
import { assertLinear } from "./timing.ts";

test("a Kubernetes Secret's short number is kept under a plain name, hidden under a credential's", () => {
	const secret = (key: string) => `apiVersion: v1\nkind: Secret\nstringData:\n  ${key}: 482910\n`;
	hidden(secret("api-key"), "482910");
	hidden(secret("token"), "482910");
	hidden(secret("password"), "482910");
	kept(secret("replicas"), "482910");
});

test("isHarmlessText keeps hosts, not dotted tokens", () => {
	hidden('apiVersion: v1\nkind: Secret\nstringData:\n  value: "AbCdEf123456.zzSecret"\n', "AbCdEf123456.zzSecret");
	hidden("apiVersion: v1\nkind: Secret\nstringData:\n  key1: Qwerty.Secretkey\n", "Qwerty.Secretkey");
	kept("apiVersion: v1\nkind: Secret\nstringData:\n  server: mycluster.example.com\n", "mycluster.example.com");
	const pw = `Xk${b62(10)}`;
	hidden(`sqlplus scott/${pw}@x@orcl`, pw);
	hidden(`SQL> connect scott/${pw}@x@orcl`, pw);
	const long = b62(300);
	hidden(`expdp system/${long}@ORCL`, long);
});

test("URL passwords of any length and with brackets and quotes", () => {
	for (const n of [380, 500, 4100, 20_000]) {
		const pw = `a${b62(n)}`;
		for (const form of [`app:${pw}`, `app:a)${pw}`, `app:a]${pw}`, `app:a'${pw}`, `admin:<${pw}>`]) {
			const url = `postgres://${form}@db.internal:5432/app`;
			hidden(`DATABASE_URL=${url}`, pw);
			const [u] = urls(url);
			assert.equal(u.end, url.length, `${form.slice(0, 8)} ${n}`);
		}
	}
	// A run of closers is looked ahead once, not once per closer.
	assertLinear("a run of closers", (n) => urlEnd(`https://x.io/${")".repeat(n)}`, 0), 20_000);
	// A port before a quote still ends the URL, with an `@` after the quote or before the port.
	assert.equal(urlEnd("'redis://cache:6379'x@y", 1), 19);
	assert.equal(urlEnd("'postgres://u:p@h:5432'x@y", 1), 22);
});

test("structure.ts caps on JWK members, URL user tokens and the Vault root token", () => {
	const d = b62(5000);
	hidden(`{"kty":"OKP","crv":"Ed25519","d":"${d}"}`, d);
	const token = b62(350);
	hidden(`git clone https://${token}@github.com/a/b.git`, token);
	const root = `hvs.${b62(300)}`;
	hidden(`Initial Root Token: ${root}\n`, root);
});

test("inJwk reads the object's own kty, and a symmetric key's k stays secret", () => {
	const n = "Xk7mP2qRv9LsT4wN8bH3jDq5";
	hidden(`{"meta": {"kty": "oct"}, "n": "${n}"}`, n);
	hidden(`{"note": "kty: RSA", "n": "${n}"}`, n);
	kept(`{"kty": "RSA", "n": "${n}", "e": "AQAB"}`, n);
	kept(`{ kty: "RSA", n: "${n}" }`, n);
	const text = `{"kty": "oct", "k": "${b62(43)}"}`;
	assert.ok(inJwk(text, text.indexOf('"k"'), text.indexOf('"k"') + 3));
	const k = b62(43);
	hidden(`{"kty":"oct","k":"${k}","alg":"HS256"}`, k);
});

test("string literals are read by their grammar: JSON's, a Python repr's, and only where JSON's syntax stands around them", () => {
	const decoded = (text: string) => jsonStringLiterals(text).map((l) => l.decoded);
	// A raw line break, or a backslash before one, ends a literal that doesn't close: no document, and none from its middle.
	assert.deepEqual(decoded('echo "first line\\tA\\nmore of it\nsecond line"'), []);
	assert.deepEqual(decoded('echo "first line\\tA\\\nmore\\nsecond line"'), []);
	// `\u` takes four hex digits; another escape JSON doesn't have stays as written.
	assert.deepEqual(decoded('{"log": "C:\\users\\deploy\\tok\\u00e9\\n"}'), ["C:\\users\\deploy\tok\u00e9\n"]);
	assert.equal(parseJson('{"a": "\\uZZZZ"}', 0), undefined);
	const repr = [...pythonReprLiterals("{'stdout': 'it\\'s \\xe9t\\xe9\\nC:\\xampp\\n', 'rc': 0}")];
	assert.deepEqual(
		repr.map((l) => l.decoded),
		["it's \u00e9t\u00e9\nC:\\xampp\n"],
	);
	// Blanks of any kind between JSON's `[` or `,` and a literal; and a quote in a shell word, `Kx9m"Qv2"`, opens none.
	assert.deepEqual(jsonLiteralSpans('[\n\t"a",\r\n\t"b"\n]'), [
		[4, 5],
		[11, 12],
	]);
	assert.deepEqual(jsonLiteralSpans('export DB_PASSWORD=Kx9m"Qv2Lp7Rt"'), []);
});

test("jsonDocuments finds documents after a run of starts that fail", () => {
	const text = "[\n".repeat(400) + "x\n" + '{"password": "hunter2-secret-value"}\n';
	assert.equal([...jsonDocuments(text)].length, 1);
});

test("a JSON document is read by JSON's grammar: tabs and CRLF are blanks, and a Python set or a missing comma is none", () => {
	assert.equal([...jsonDocuments('{\r\n\t"kind": "Secret",\r\n\t"data": {"a": "b"}\r\n}')].length, 1);
	for (const text of ['{"a": "x\ny"}', '{"api_key", "secret"}', '{"a": 1 "b": 2}', '["a" "b"]'])
		assert.equal(parseJson(text, 0), undefined, text);
});

test("tool keys match whole, header breaks in all escaped forms, pem tail trim is linear", () => {
	// A key that merely ends in a tool key isn't one.
	const line = "      private_key_passphrase: a b c";
	assert.equal(jsonStringLiterals(`{"text": "${line}"}`).length, 1);
	assert.equal(jsonStringLiterals(`{"context": "${line}"}`).length, 0);
	assert.equal(jsonStringLiterals(`{"command": "mysql -u root -pV shop"}`).length, 1);
	assert.equal(jsonStringLiterals(`{"rerun": "mysql -u root -pV shop"}`).length, 0);
	const body = b62(64);
	for (const brk of ["\\n", "\\\\n"]) {
		const pem = `"-----BEGIN PRIVATE KEY-----${brk}Comment: x${brk}${body}${brk}${body}${brk}-----END PRIVATE KEY-----"`;
		hidden(pem, body);
	}
	const tail = b62(100);
	assertLinear(
		"a key's tail after long runs",
		(n) =>
			r().redact(
				`-----END PRIVATE KEY-----\n${" ".repeat(6 * n)}\n${tail}${"\"',;+".repeat(n)}\n-----END PRIVATE KEY-----`,
			),
		10_000,
	);
});

/** A random 128-bit entropy and its checksum, as 12 words of the BIP-39 list. */
function randomPhrase(): string[] {
	const entropy = randomBytes(16);
	const bits =
		[...entropy].map((b) => b.toString(2).padStart(8, "0")).join("") +
		createHash("sha256").update(entropy).digest()[0].toString(2).padStart(8, "0").slice(0, 4);
	const list = BIP39_WORDS.split(" ");
	return Array.from({ length: 12 }, (_, i) => list[parseInt(bits.slice(i * 11, i * 11 + 11), 2)]);
}

test("a phrase one word per line, deeply indented, is found", () => {
	const words = randomPhrase();
	for (const indent of [0, 12, 16]) {
		const text = words.map((w) => " ".repeat(indent) + w).join("\n");
		assert.ok(!r().redact(text).text.includes(words[5]), `indent ${indent}`);
	}
});

test("a phrase is found on its own line, after a label anywhere on its line, in curly quotes and before a 13th word", () => {
	const forms: ((p: string[]) => string)[] = [
		([p]) => `Here is the seed for the old one\n${p}`,
		([p]) => `Seed phrase: ${p}`,
		([p]) => `Copy this seed phrase: ${p}`,
		([p]) => `My seed is “${p}”`,
		([p]) => `${p}. Keep it safe`,
		// Several, one a line: past 30 words, and past 48.
		(p) => p.slice(0, 3).join("\n"),
		(p) => p.join("\n"),
	];
	for (const form of forms) {
		const phrases = Array.from({ length: 5 }, randomPhrase);
		const text = form(phrases.map((p) => p.join(" ")));
		const out = r().redact(text).text;
		// (Each hidden as a phrase, a wallet's key, not as another rule's credential.)
		const shown = phrases.filter((p) => text.includes(p.join(" ")) && out.includes(p.slice(4, 8).join(" ")));
		assert.ok(!shown.length && out.includes("[REDACTED seed phrase #"), out);
	}
	// A word list is no phrase: one word a line, or the list's own words in order, whose windows verify by chance.
	const list = BIP39_WORDS.split(" ");
	for (const text of [list.slice(0, 100).join("\n"), list.slice(32, 45).join(" ")])
		assert.equal(r().redact(text).text, text);
});

test("a URL password is hidden and its endpoint kept", () => {
	hidden("postgres://app:S3cr3tPassw0rd@db.internal:5432/app", "S3cr3tPassw0rd");
	kept("postgres://app:S3cr3tPassw0rd@db.internal:5432/app", "db.internal:5432");
});

test("a URL password may hold @ or be all capitals, and an @ in a path is no userinfo", () => {
	hidden("postgres://admin:Winter@2024@db.example.com/x", "Winter@2024");
	hidden("postgres://admin:WINTER2024PASS@db.example.com/x", "WINTER2024PASS");
	kept("http://localhost:4873/@babel/core", "4873/");
});

test("a URL password may hold brackets", () => {
	hidden("postgres://u:Wint(er)2024@h/db", "Wint(er)2024");
});

test("a URL password equal to its user is kept", () => {
	kept("DATABASE_URL=postgresql+asyncpg://tally:tally@localhost:5432/tally", "tally:tally@");
});

test("a token as a URL user is hidden, a generated database user kept and a word password hidden", () => {
	hidden(
		"git clone https://Zq81mXw0pLr7Tb2Nc9VdQ4kP:x-oauth-basic@github.com/org/repo.git",
		"Zq81mXw0pLr7Tb2Nc9VdQ4kP",
	);
	kept(
		"postgresql://v-kubernet-billing--XF9ff9Lb1a6msRaDBeVr-4408119095:ewauZT8IiceCA3dwQ0wN@pg:5432/billing",
		"v-kubernet-billing--XF9ff9Lb1a6msRaDBeVr",
	);
	hidden("DATABASE_URL=postgres://app:Compassionate@db:5432/app", "Compassionate");
});

test("a URL password may be percent-encoded", () => {
	hidden("snowflake://AIRFLOW_SVC:Birch%216@/ANALYTICS?account=xy12345", "Birch%216");
});

test("a service account's email as a URL user does not hide the password after it", () => {
	hidden(
		"url = postgresql+psycopg2://writer@acme-prod-471203.iam.gserviceaccount.com:tSXiXG4lsJa29D0bDcnHBj@10.42.7.19:5432/warehouse",
		"tSXiXG4lsJa29D0bDcnHBj",
	);
});

test("a URL password may hold angle brackets or a slash", () => {
	for (const [t, v, hint] of [
		["mongodb+srv://admin:<Harbor2291x>@cluster0.mongodb.net/db", "Harbor2291x"],
		["postgres://app:Xk9/mQ2pLrT@db/app", "Xk9/mQ2pLrT"],
	] as [string, string, { command?: string }?][])
		hidden(t, v, hint);
});

test("a DSN password is hidden and an empty one leaves the URL alone", () => {
	kept("migrate -database mysql://root:@tcp(127.0.0.1:3306)/m", "//root:");
	hidden('dsn := "root:Harbor2291x@tcp(127.0.0.1:3306)/db"', "Harbor2291x");
});

test("a key=value connection string's password ends at the blank before the next key", () => {
	assert.equal(
		r().redact('psql "host=db password=Kx9mQ2pLw7v user=app dbname=x"').text.replace(/#\w+/, "#"),
		'psql "host=db password=[REDACTED password #] user=app dbname=x"',
	);
});

test("a ' in a URL's password is the password's, and a quoted URL keeps its closing quote", () => {
	const line = "postgres://app:Kx9m'Qv2Lp7Rt9@db/app";
	hidden(line, "Qv2Lp7Rt");
	kept("DATABASE_URL='postgres://app:Kx9mQv2Lp7Rt9@db/app'", "@db/app'");
	hidden("postgres://app:Kx9m'Qv2'Lp7Rt9@db/app", "Qv2");
});

test("a Kubernetes Secret is hidden when data comes before kind, and in a block scalar", () => {
	const pw = "Winter2024pass";
	hidden(
		'{\n  "apiVersion": "v1",\n  "data": {\n    "blob": "V2ludGVyMjAyNHBhc3M="\n  },\n  "kind": "Secret"\n}',
		"V2ludGVyMjAyNHBhc3M=",
	);
	hidden(`apiVersion: v1\nkind: Secret\nstringData:\n  blob: |\n    ${pw}\n`, pw);
});

test("a Secret's kind is read across blank lines and block scalars, and not across documents", () => {
	const pw = "Winter2024pass";
	hidden(`apiVersion: v1\nkind: Secret\n\nstringData:\n  blob: ${pw}\n`, pw);
	hidden(
		`apiVersion: v1\nkind: Secret\nmetadata:\n  annotations:\n    note: |\n      rotated monthly\nstringData:\n  blob: ${pw}\n`,
		pw,
	);
	const configMap = "apiVersion: v1\ndata:\n  greeting: Winter2025pass\nkind: ConfigMap\n";
	kept(`apiVersion: v1\nkind: Secret\nstringData:\n  blob: ${pw}\n---\n${configMap}`, "Winter2025pass");
	// Two resources printed back to back (`kubectl get configmap app -o yaml; kubectl get secret app -o yaml`): each its own.
	const secret =
		"apiVersion: v1\ndata:\n  blob: V2ludGVyMjAyNHBhc3M=\nkind: Secret\nmetadata:\n  name: app\ntype: Opaque\n";
	for (const text of [configMap + secret, secret + configMap]) {
		hidden(text, "V2ludGVyMjAyNHBhc3M=");
		kept(text, "Winter2025pass");
	}
});

test("a mapping's keys are its siblings: not a list item's, nor past a compact list", () => {
	const lines = yamlLines("- name: app\n  kind: Secret\n- data:\n    k: v\nimage:\n- name: a\nkind: Pod\n");
	assert.equal(siblingValue(lines, 2, "kind"), undefined);
	assert.equal(siblingValue(lines, 4, "kind"), "Pod");
});

test("a YAML value: single-quoted with a ` #`, a block scalar with a blank line, an empty block at the end", () => {
	const out = r().redact("apiVersion: v1\nkind: Secret\nstringData:\n  blob: 'Winter 2024 #pass'\n").text;
	assert.ok(!out.includes("#pass") && out.includes("blob: '[REDACTED"), out);
	// A file in a Secret is scanned as text: its lines aren't values.
	kept("apiVersion: v1\nkind: Secret\nstringData:\n  app.conf: |\n    mode = fast\n\n    retries = 3\n", "mode = fast");
	assert.equal(r().redact("db:\n  password: |\n").text, "db:\n  password: |\n");
});

test("a certificate in a Kubernetes Secret is kept", () => {
	kept(
		"apiVersion: v1\ndata:\n  tls.crt: L0ZtMG01WHVHSS9FM3FMaERFNU9SeEFTVFNSTlFITVJ2ZzNBNHo3YkdnYjI1VDNZ\n  tls.key: c2VjcmV0\nkind: Secret\n",
		"L0ZtMG01WHVHSS9FM3FMaERFNU9SeEFTVFNSTlFITVJ2ZzNBNHo3YkdnYjI1VDNZ",
	);
});

test("the command a Kubernetes Secret's JSON config runs is read as a command line, and kept", () => {
	const config = '{\n  "execProviderConfig": {\n    "command": "argocd-k8s-auth",\n    "args": ["aws"]\n  }\n}';
	const secret = `apiVersion: v1\nkind: Secret\nstringData:\n  config: |\n    ${config.replace(/\n/g, "\n    ")}\n`;
	kept(secret, "argocd-k8s-auth");
});

test("a published BIP-39 test mnemonic is kept", () => {
	kept("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "about");
	for (const t of [
		'MNEMONIC="letter advice cage absurd amount doctor acoustic avoid letter advice cage above"',
		"Mnemonic: candy maple cake sugar pudding cream honey rich smooth crumble sweet treat",
		'"legal winner thank year wave sausage worth useful legal winner thank yellow",',
	])
		assert.equal(r().redact(t).text, t);
});

test("a JWK literal's private member is hidden with guessing off", () => {
	const off = new Redactor({ guessing: "off", fingerprintKey: "t" });
	assert.ok(
		!off
			.redact('const jwk = { kty: "OKP", crv: "Ed25519", d: "ls0dONFH_05yxveCF3Q1_2LN2dA1WMmv0lcGu6_Dl2k" };')
			.text.includes("ls0dONFH"),
	);
});

test("a PEM block of public parameters in a .pem file is kept", () => {
	kept("-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----", "BggqhkjOPQMBBw==", {
		path: "ec.pem",
	});
});

test("a Secret's fields that name no credential and hold a word, a boolean or a host are its structure", () => {
	const out = r().redact(
		"apiVersion: v1\nkind: Secret\nstringData:\n  type: git\n  server: mycluster.example.com\n  insecure: false\n  password: Harbor2291x\n",
	).text;
	for (const v of ["git", "mycluster.example.com", "false"]) assert.ok(out.includes(v), v);
	assert.ok(!out.includes("Harbor2291x"));
});

test("a cookie's value is read quoted, and ends at an escaped line break", () => {
	const g = new Redactor({ guessing: "off" });
	const quoted = g.redact('Cookie: session="Zq8Vn3Kx9mQv2Lp7Rt"; theme=dark').text;
	assert.ok(
		!quoted.includes("Zq8Vn3Kx9mQv2Lp7Rt") && quoted.includes('session="[REDACTED') && quoted.includes("theme=dark"),
		quoted,
	);
	const escaped = g.redact('{"h":"Cookie: sid=Zq8Vn3Kx9mQv2Lp7Rt\\r\\nHost: x"}').text;
	assert.ok(!escaped.includes("Zq8Vn3Kx9mQv2Lp7Rt") && escaped.includes("\\r\\nHost: x"), escaped);
});

/** `text` redacted with guessing off: what the rules decide without the unnamed layer's guesses. */
const ruled = (text: string) => new Redactor({ guessing: "off", fingerprintKey: "t" }).redact(text).text;

test("docs' passwords and default credentials are kept in a URL, a command line and a Basic header", () => {
	for (const [text, value] of [
		["postgres://app:test@db.example.com/app", "app:test@"],
		["postgres://app:postgres@db.example.com/app", "app:postgres@"],
		["postgres://app:encodeURIComponent(pw)@db.example.com/app", "encodeURIComponent(pw)"],
		["redis-cli -a database-password ping", "database-password"],
		["redis-cli -a 'guest' ping", "'guest'"],
		["mysql -u root -pmysql app", "-pmysql"],
		["mysql -u root -p'$(DB_PASSWORD)' app", "$(DB_PASSWORD)"],
		["sshpass -p 'your-password-here' ssh host", "your-password-here"],
		["sshpass -p 'xxxxxxxx' ssh host", "xxxxxxxx"],
		// `admin:changeme`, `admin:<password>`, `admin:my_db_password`, and `user` with no password at all.
		["Authorization: Basic YWRtaW46Y2hhbmdlbWU=", "YWRtaW46Y2hhbmdlbWU="],
		["Authorization: Basic YWRtaW46PHBhc3N3b3JkPg==", "YWRtaW46PHBhc3N3b3JkPg=="],
		["Authorization: Basic YWRtaW46bXlfZGJfcGFzc3dvcmQ=", "YWRtaW46bXlfZGJfcGFzc3dvcmQ="],
		["Authorization: Basic dXNlcg==", "dXNlcg=="],
	])
		kept(text, value);
	hidden("postgres://app:Harbor2291x@db.example.com/app", "Harbor2291x");
	hidden("mysql -u root -p'Harbor2291x' app", "Harbor2291x");
});

test("a Go DSN's password is hidden after a key", () => {
	for (const text of [
		"dsn: root:Harbor2291x@tcp(127.0.0.1:3306)/app",
		'dsn: "root:Harbor2291x@tcp(127.0.0.1:3306)/app"',
	])
		assert.ok(!ruled(text).includes("Harbor2291x"), text);
});

test("a token as a URL user is hidden whatever its host and with an empty password; a name, a mask or a fixed word is kept", () => {
	const token = "Zq81mXw0pLr7Tb2Nc9VdQ4kP";
	for (const text of [
		`git clone https://${token}@\${GIT_HOST}/org/repo.git`,
		`curl https://${token}:@api.example.com/v1/charges`,
		`git clone https://${token}:x-oauth-basic@github.com/org/repo.git`,
	]) {
		const out = ruled(text);
		assert.ok(!out.includes(token) && !out.includes("[REDACTED password"), out);
	}
	// The same token as the user and the password: both are hidden.
	assert.ok(!ruled("https://Kx9mQv2Lp7Rt9Wz4:Kx9mQv2Lp7Rt9Wz4@host.example.com/").includes("Kx9mQv2Lp7Rt9Wz4"));
	for (const [text, value] of [
		// (A Twilio account SID, built here so the file holds none.)
		[
			`https://AC${["8f3a9b2c", "4d5e6f70", "8192a3b4", "c5d6e7f8"].join("")}:Harbor2291x@api.twilio.com/2010-04-01`,
			"AC8f3a9b2c4d5e6f",
		],
		["git clone https://xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx@github.com/org/repo.git", "xxxxxxxxxxxxxxxx"],
		["git clone https://ci-runner-8f3a9b2c4d5e@git.example.com/repo.git", "ci-runner-8f3a9b2c4d5e"],
	])
		assert.ok(ruled(text).includes(value), text);
});

test('an Authorization credential ending in = is hidden inside quotes, and an OAuth header\'s k="v" list is not one', () => {
	hidden("curl -H 'Authorization: Basic ZGV2OlhrOWYycFE=' https://api.example.com", "ZGV2OlhrOWYycFE=");
	hidden("headers = {'Authorization': 'ApiKey ZGV2OlhrOWYycFE='}", "ZGV2OlhrOWYycFE=");
	const oauth = 'Authorization: OAuth oauth_consumer_key="xvz1evFS4wEEPTGEFPHBog", oauth_version="1.0"';
	assert.ok(ruled(oauth).includes("oauth_consumer_key="));
});

test("an Authorization credential is labelled by a known scheme, and a dotted token is no member path", () => {
	const out = ruled(
		"Authorization: Digest Zq81mXw0pLr7Tb2Nc9VdQ4kP\nProxy-Authorization: Custom Kx9mQv2Lp7Rt9Wz4Lp7Rt9W",
	);
	assert.match(
		out,
		/Digest \[REDACTED digest credential #\w+\]\nProxy-Authorization: Custom \[REDACTED authorization /,
	);
	const call = 'headers.set("Authorization", "Xk9fPq2LmZ.Ab3dEf9hIjKl")';
	assert.deepEqual(
		findStructure(call).map((f) => call.slice(f.start, f.end)),
		["Xk9fPq2LmZ.Ab3dEf9hIjKl"],
	);
});

test("a bare Bot token is read without an Authorization header and is not learned; a Bearer path in prose is kept", () => {
	const token = "Zq81mXw0pLr7Tb2Nc9VdQ4kP";
	assert.equal(ruled(`const t = "Bot ${token}"; log(${token})`).split(token).length, 2);
	assert.equal(ruled(`const t = "Bearer ${token}"; log(${token})`).split(token).length, 1);
	kept("see the Bearer tokens/authentication-flows guide", "tokens/authentication-flows");
});

test("a query credential is judged decoded, and a page's token or an app's name is no credential", () => {
	// (`${API_KEY}` and `$DB_PASSWORD` percent-encoded.)
	for (const query of ["apikey=%24%7BAPI_KEY%7D", "password=%24DB_PASSWORD"])
		assert.deepEqual(findStructure(`https://api.example.com/v1/items?${query}&page=2`), []);
	for (const [text, value] of [
		["https://api.example.com/v1/items?api_key=1234567890abcdef&page=2", "1234567890abcdef"],
		["https://api.example.com/v1/items?token=next-page-2", "next-page-2"],
		["https://api.example.com/data/2.5/weather?q=London&appid=MyCoolApp2024", "MyCoolApp2024"],
	])
		kept(text, value);
	hidden(
		"https://api.example.com/data/2.5/weather?q=London&appid=8f3a9b2c4d5e6f708192a3b4c5d6e7f8",
		"8f3a9b2c4d5e6f708192a3b4c5d6e7f8",
	);
});

test("a cookie's attributes, CSRF token, analytics id, reference, email, words and numbers are kept; a session's hidden", () => {
	for (const [text, value] of [
		["Set-Cookie: sid=Zq81mXw0pLr7Tb2Nc9VdQ4kP; Domain=.example.com; Path=/", ".example.com"],
		["csrf_token=Zq81mXw0pLr7Tb2Nc9VdQ4kP; Path=/; HttpOnly", "Zq81mXw0pLr7Tb2Nc9VdQ4kP"],
		["_uetsid=8f3a9b2c4d5e6f708192a3b4c5d6e7f8; Path=/; Max-Age=86400", "8f3a9b2c4d5e6f708192a3b4c5d6e7f8"],
		["session_id=${SESSION_ID}; Path=/; HttpOnly", "${SESSION_ID}"],
		["login_email=alice@example.com; Path=/", "alice@example.com"],
		["Cookie: session=${SESSION_ID}; view=compact_list_mode", "${SESSION_ID}"],
		["Cookie: session=${SESSION_ID}; view=compact_list_mode", "compact_list_mode"],
		["Cookie: offset=-12345678; visits=12345678", "-12345678"],
		["Cookie: offset=-12345678; visits=12345678", "visits=12345678"],
	])
		assert.ok(ruled(text).includes(value), text);
	assert.ok(!ruled("user_session=Zq81mXw0pLr7Tb2Nc9VdQ4kP; Path=/; HttpOnly").includes("Zq81mXw0pLr7Tb2Nc9VdQ4kP"));
});

test("a connection string's template, reference or code is no password; its literal is", () => {
	const helm = "Data Source=db;Initial Catalog=app;User ID=sa;Password={{ .Values.dbPassword }};";
	assert.equal(r().redact(helm).text, helm);
	kept('$cs = "Server=db;Database=app;User Id=sa;Password=$env:DB_PASSWORD;"', "$env:DB_PASSWORD");
	kept(
		"Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=Root;SharedAccessKey=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG=",
		"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG=",
	);
	assert.deepEqual(findStructure("Server=db;Database=app;User Id=sa;Password=settings.Database.Password;"), []);
	hidden("Driver={ODBC Driver 18 for SQL Server};Server=db;Uid=sa;Pwd={Harbor2291x!};", "Harbor2291x!");
	assert.ok(!ruled("Server=db;Uid=sa;Pwd=Xk9fPq2LmZ8bW4kY=").includes("Xk9fPq2LmZ8bW4kY="));
	// The tokens a deployment replaces (Octopus, Azure DevOps' Replace Tokens), in JSON or bare; a literal stays hidden.
	for (const token of ["#{DbPassword}#", "#{Db.Password}", "__DbPassword__", "@@DbPassword@@"]) {
		kept(`{"Default": "Server=#{DbServer}#;Database=app;User Id=app;Password=${token};"}`, token, {
			path: "appsettings.json",
		});
		kept(`Server=db;Database=app;User Id=app;Password=${token};`, token);
	}
	hidden("Server=db;Database=app;User Id=app;Password=__Hx7mQ2pL9vRt__;", "Hx7mQ2pL9vRt");
});

test("a connection string written from its password on ends the password at its first ;", () => {
	for (const [line, secret, rest] of [
		["Password=Hx7mQ2pL9vRt;Server=db;Database=app;User Id=sa", "Hx7mQ2pL9vRt", ";Server=db;Database=app;User Id=sa"],
		["ClientSecret=Xk9fPq2LmZvRt7Hn4Jw8Bc3Ds6;TenantId=abc;ClientId=def", "Xk9fPq2LmZvRt7Hn4Jw8Bc3Ds6", ";TenantId=abc;ClientId=def"],
		['export CONN="Pwd=Hx7mQ2pL9vRt;Server=db;Database=app"', "Hx7mQ2pL9vRt", ';Server=db;Database=app"'],
	]) {
		hidden(line, secret);
		kept(line, rest);
	}
	// (A password's own `;` with no pairs after it is the password's.)
	hidden("DB_PASSWORD=Hx7m;Q2pL9vRt", "Q2pL9vRt");
});

test("a Secret's config file, certificates, public keys, endpoint and base64 settings are kept, its credentials hidden", () => {
	const secret = (data: string) => `apiVersion: v1\nkind: Secret\nmetadata:\n  name: app\nstringData:\n${data}`;
	const config = ruled(
		secret(
			"  config.yaml: |\n    database:\n      driver: postgresql\n      password: Harbor2291x\n    features:\n      owner: platform-team\n",
		),
	);
	assert.ok(
		config.includes("postgresql") && config.includes("platform-team") && !config.includes("Harbor2291x"),
		config,
	);
	for (const [data, value] of [
		["  type: git\n  url: https://github.com/argoproj/private-repo\n", "https://github.com/argoproj/private-repo"],
		['  config.json: {\n    "auths": {}\n  }\n', "config.json: {"],
		// `db.example.com` and `12345678`.
		["  smtp-relay: ZGIuZXhhbXBsZS5jb20=\n", "ZGIuZXhhbXBsZS5jb20="],
		["  max-conns: MTIzNDU2Nzg=\n", "MTIzNDU2Nzg="],
		// The CA's certificate (its value made up, as in the test above).
		[
			"  ca: L0ZtMG01WHVHSS9FM3FMaERFNU9SeEFTVFNSTlFITVJ2ZzNBNHo3YkdnYjI1VDNZ\n",
			"L0ZtMG01WHVHSS9FM3FMaERFNU9SeEFTVFNSTlFITVJ2ZzNBNHo3YkdnYjI1VDNZ",
		],
	])
		assert.ok(ruled(secret(data)).includes(value), data);
	for (const [data, value] of [
		["  webhook: https://hooks.example.com/notify Zq81mXw0pLr7Tb2Nc9VdQ4kP\n", "Zq81mXw0pLr7Tb2Nc9VdQ4kP"],
		["  webhook: Zq81mXw0pLr7Tb2Nc9VdQ4kP https://hooks.example.com/notify\n", "Zq81mXw0pLr7Tb2Nc9VdQ4kP"],
	])
		assert.ok(!ruled(secret(data)).includes(value), data);
	// A public key by its name.
	assert.deepEqual(
		findStructure(secret("  VAPID_PUBLIC_KEY: BEl62iUYgUivxIkv69yViEuiBIa40HI0F8m6V1r9Xk9fPq2LmZ8b\n")),
		[],
	);
	// A URL holding a password, base64'd (`postgres://app:Tiger4414yx@db/app`), and one under a key that names it a
	// secret: the Secret's rule hides them, whatever the others do.
	for (const data of [
		"  DATABASE_URL: cG9zdGdyZXM6Ly9hcHA6VGlnZXI0NDE0eXhAZGIvYXBw\n",
		"  webhook-secret: https://hooks.example.com/catch/23808906/7c06jvh/\n",
	])
		assert.ok(
			findStructure(secret(data)).some((f) => f.rule === "structure:kube-secret"),
			data,
		);
});

test("a ConfigMap listed beside a Secret keeps its values, in YAML and in JSON", () => {
	const value = "Zq81mXw0pLr7Tb2Nc9VdQ4kP";
	const secret = "V2ludGVyMjAyNHBhc3M=";
	const yaml = `apiVersion: v1\nkind: ConfigMap\ndata:\n  release: ${value}\n---\napiVersion: v1\nkind: Secret\ndata:\n  blob: ${secret}\n`;
	const json = JSON.stringify({
		items: [
			{ kind: "ConfigMap", data: { release: value } },
			{ kind: "Secret", data: { blob: secret } },
		],
	});
	for (const text of [yaml, json]) {
		const out = ruled(text);
		assert.ok(out.includes(value) && !out.includes(secret), out);
	}
});
