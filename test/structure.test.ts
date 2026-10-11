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
import { inJwk, jsonDocuments, jsonStringLiterals } from "../src/json.ts";
import { urlEnd, urls } from "../src/urls.ts";
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
	// A port before a quote still ends the URL.
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

test("jsonDocuments finds documents after a run of starts that fail", () => {
	const text = "[\n".repeat(400) + "x\n" + '{"password": "hunter2-secret-value"}\n';
	assert.equal([...jsonDocuments(text)].length, 1);
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

test("a phrase one word per line, deeply indented, is found", () => {
	// A random 128-bit entropy and its checksum, as 12 words of the list.
	const entropy = randomBytes(16);
	const bits =
		[...entropy].map((b) => b.toString(2).padStart(8, "0")).join("") +
		createHash("sha256").update(entropy).digest()[0].toString(2).padStart(8, "0").slice(0, 4);
	const list = BIP39_WORDS.split(" ");
	const words = Array.from({ length: 12 }, (_, i) => list[parseInt(bits.slice(i * 11, i * 11 + 11), 2)]);
	for (const indent of [0, 12, 16]) {
		const text = words.map((w) => " ".repeat(indent) + w).join("\n");
		assert.ok(!r().redact(text).text.includes(words[5]), `indent ${indent}`);
	}
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

test("a certificate in a Kubernetes Secret is kept", () => {
	kept(
		"apiVersion: v1\ndata:\n  tls.crt: L0ZtMG01WHVHSS9FM3FMaERFNU9SeEFTVFNSTlFITVJ2ZzNBNHo3YkdnYjI1VDNZ\n  tls.key: c2VjcmV0\nkind: Secret\n",
		"L0ZtMG01WHVHSS9FM3FMaERFNU9SeEFTVFNSTlFITVJ2ZzNBNHo3YkdnYjI1VDNZ",
	);
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
