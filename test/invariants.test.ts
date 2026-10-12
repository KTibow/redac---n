/**
 * What holds for every output: valid JSON stays valid, redacting twice changes nothing, one value gets one tag, and a
 * failing detector hides its text.
 *
 *   node --test test/invariants.test.ts
 *
 * (A fake key's vendor prefix is written with an escape, `"ghp\x5f…"`: written whole, the repository would hold text
 * that secret scanners, GitHub's push protection among them, take for a live key.)
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { GENERATORS, seed } from "../eval/fuzz-secrets.ts";
import { Redactor } from "../src/index.ts";
import { hidden, kept, r } from "./helpers.ts";

test("a redacted JSON string still parses, whatever escape ends the value", () => {
	const a = r().redact(JSON.stringify({ cmd: "set PASSWORD=Xq7Lm2Vb9Rt4Np8K\\", next: "ok" })).text;
	assert.equal(JSON.parse(a).next, "ok");
	const b = r().redact(
		JSON.stringify({ nested: JSON.stringify({ inner: "x\nDB_PASSWORD=Xq7Lm2Vb9Rt4Np8K\ny" }) }),
	).text;
	assert.ok(!JSON.stringify(JSON.parse(JSON.parse(b).nested)).includes("Xq7Lm2Vb9Rt4Np8K"));
});

test("redacted output stays valid JSON at every level of encoding", () => {
	const R = r();
	assert.doesNotThrow(() => JSON.parse(R.redact('{"password":123456}').text));
	const twice = JSON.stringify(JSON.stringify({ password: 123456, a: "token\n2J4GLGGEsistantQ" }));
	assert.doesNotThrow(() => JSON.parse(JSON.parse(R.redact(twice).text)));
});

test("a log's [07:12:44] is no JSON document and nothing throws", () => {
	for (const text of ['[07:12:44] {"value": "ok"}', '{"value": "x"}\n[02:39] chris: hi'])
		assert.equal(r().redact(text).text, text);
});

test("redacted JSON is JSON: every generator in every context, encoded once and twice", () => {
	seed(13);
	for (const [gen, make] of Object.entries(GENERATORS)) {
		for (let i = 0; i < 20; i++) {
			const v = make();
			for (const line of [
				`the password is ${v}`,
				`password: ${v}`,
				`machine a.example login u password ${v}`,
				`DB_PASSWORD=${v}`,
			]) {
				for (const json of [
					JSON.stringify({ content: line }),
					JSON.stringify({ note: line }),
					JSON.stringify([line]),
					JSON.stringify(JSON.stringify({ content: line })),
				]) {
					assert.doesNotThrow(() => JSON.parse(r().redact(json).text), `${gen}: ${json}`);
				}
			}
		}
	}
});

test("JSON stays valid when a secret is a number anywhere", () => {
	const known = new Redactor({ fingerprintKey: "x", known: ["981277341209"] });
	for (const t of [
		'{"password": 9812773412, "previous": [9812773412, 5512340987]}',
		'{"codes": [981277341209, 5]}',
		"[981277341209]",
		'{"pin": -981277341209}',
		'{"pin": 981277341209.5}',
		'{"s": "{\\"pin\\": [981277341209]}"}',
	]) {
		const out = known.redact(t).text;
		assert.doesNotThrow(() => JSON.parse(out), out);
		assert.ok(!out.includes("98127"), out);
	}
	// Only there: a number in prose, or after a key but before more text, keeps its place unquoted.
	for (const t of ["the code is 981277341209", '"pin": 981277341209 (the old one)']) {
		const out = known.redact(t).text;
		assert.ok(!out.includes('"[REDACTED') && !out.includes("98127"), out);
	}
});

test("a known value gets one tag in text, JSON, a URL and a shell escape", () => {
	const tag = (text: string) => /#([0-9a-f]{6})\]/.exec(text)?.[1];
	const value = 'Ab"cd9Xq2Lm#7';
	const known = new Redactor({ known: [value] });
	const tags = [
		"x " + value + " y",
		JSON.stringify({ p: value }),
		`postgres://u:${encodeURIComponent(value)}@h/db`,
		'export P="Ab\\"cd9Xq2Lm#7"',
	].map((t) => tag(known.redact(t).text));
	assert.equal(new Set(tags).size, 1, `tags ${tags.join(" ")}`);
});

test("a found value gets one tag in JSON, an env line and a URL", () => {
	const tag = (text: string) => /#([0-9a-f]{6})\]/.exec(text)?.[1];
	const found = new Redactor();
	const unknown = [
		JSON.stringify({ password: 'Ab"cd9Xq2Lm' }),
		'PASSWORD=Ab\\"cd9Xq2Lm',
		"postgres://u:Ab%22cd9Xq2Lm@h",
	].map((t) => tag(found.redact(t).text));
	assert.equal(new Set(unknown).size, 1, `tags ${unknown.join(" ")}`);
});

test("redacting redacted text changes nothing, also for a secret file's placeholders", () => {
	const R = r();
	for (const s of [
		"KKFPCX1642oOuz7CV26o\nRZqV4xi6USe+IwpJ",
		":dop\x5fv1_71dec02e97b602168f0432330d8794494b7a961480e2e7d564ad6694c5657a8c wEMxVidB6OYyHw5z",
	]) {
		const once = R.redact(s).text;
		assert.equal(R.redact(once).text, once);
	}
	const pgpass = "localhost:5432:*:postgres:Harbor2291!\nlocalhost:5432:app:app_rw:Copper7781#x\n";
	const once = r().redact(pgpass, { hint: { path: "/home/deploy/.pgpass" } }).text;
	assert.equal(r().redact(once, { hint: { path: "/home/deploy/.pgpass" } }).text, once);
});

test("one secret gets one tag whatever line or encoding it sits in", () => {
	const R = r();
	const gh = "ghp\x5faB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zA4";
	const tag = R.redact(gh).text;
	for (const [text, hint] of [
		[`export GITHUB_TOKEN="${gh}"\n`, { command: "cat .env" }],
		[`git clone https://user:${gh}@github.com/o/r.git\n`, { command: "cat .env" }],
		[`GITHUB_TOKEN=${gh}`, { command: "gh auth token" }],
	] as const) {
		assert.ok(R.redact(text, { hint }).text.includes(tag), text);
	}
	const tags = [
		"DB_PASSWORD=Harbor2291!x",
		"DATABASE_URL=postgres://app:Harbor2291%21x@db/app",
		"PGPASSWORD=Harbor2291\\!x psql",
		"https://x.io/login?password=Harbor2291%21x",
	].map((t) => /#[0-9a-f]{6}/.exec(r().redact(t).text)?.[0]);
	assert.equal(new Set(tags).size, 1, tags.join(" "));
});

test("a placeholder holds a hex tag and no quote or backslash before its bracket", () => {
	const red = r();
	const a = red.redact('k="Zq8vR2mX7pL4tN9wK3yB6cD1fG5hJ0sA" and again Zq8vR2mX7pL4tN9wK3yB6cD1fG5hJ0sA', {}).text;
	const tags = a.match(/#[0-9a-f]{6}/g) ?? [];
	assert.ok(tags.length >= 1);
	assert.doesNotMatch(a, /["\\\\]\\]/);
});

test("a detector that fails hides its text whole, in every entry point", () => {
	const failing = r();
	(failing as unknown as { detectNormalized: () => never }).detectNormalized = () => {
		throw new Error("detector failed");
	};
	const text = "see SplxlOBeZQQYbYS6WxSbIA and Harbor#2291x";
	assert.ok(!failing.redact(text).text.includes("Harbor#2291x"));
	assert.ok(!JSON.stringify(failing.redactValue({ publishable_key: text }).value).includes("Harbor#2291x"));
	const stream = failing.stream();
	assert.ok(!(stream.write(`${text}\n`) + stream.end()).includes("Harbor#2291x"));
});

test("tables looked up by the text's words have no prototype: constructor is a word like any other", () => {
	hidden("DB_PASSWORD=Harbor2291x\nok", "Harbor2291x", { command: "constructor -v" });
	kept("a &constructor; b &toString; c", "&constructor;");
});

test("learn counts only values it didn't hold", () => {
	const red = r();
	const text = "API_KEY=Zk39dQpL7vXm2Rt8\n";
	assert.equal(red.learn(text, { hint: { command: "cat .env" } }), 1);
	assert.equal(red.learn(text, { hint: { command: "cat .env" } }), 0);
});

test("a finding detect returns is the caller's: changing it changes no later call", () => {
	const red = r();
	const text = "token ghp\x5fZ2r9Kq4Lm7Pw1Xv8Bt3Nc6Hd0Jf5Ys2Ge9Ua";
	const first = red.detect(text);
	first[0].start = 999;
	assert.notEqual(red.detect(text)[0].start, 999);
});

test("a result's value is the secret as the program reads it, the same as detect's", () => {
	const red = new Redactor({ fingerprintKey: "test", known: ["Hx7mQ2pL9v&Rt3"] });
	const text = "GET /login?u=admin&p=Hx7mQ2pL9v%26Rt3";
	assert.deepEqual(
		red.redact(text).findings.map((f) => f.value),
		["Hx7mQ2pL9v&Rt3"],
	);
	assert.deepEqual(
		red.detect(text).map((f) => f.value),
		["Hx7mQ2pL9v&Rt3"],
	);
});

test("every occurrence of a secret has the placeholder its first finding has", () => {
	const out = r().redact("password=Delta2018&x\nlogin https://u:Delta2018%26x@h/ then Delta2018&x").text;
	const tags = out.match(/\[REDACTED [^\]]+\]/g) ?? [];
	assert.equal(tags.length, 3, out);
	assert.equal(new Set(tags).size, 1, out);
});
