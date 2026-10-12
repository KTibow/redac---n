/**
 * The random-token layer's vetoes, value shapes, how often an unnamed key is missed, and which keys of a transcript
 * are structure.
 *
 *   node --test test/random-and-values.test.ts
 *
 * (A fake key's vendor prefix is written with an escape, `"ghp\x5f…"`: written whole, the repository would hold text
 * that secret scanners, GitHub's push protection among them, take for a live key.)
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { GENERATORS, seed } from "../eval/fuzz-secrets.ts";
import { naturalness } from "../src/charlm.ts";
import { type Context, contextOf, Doc } from "../src/context.ts";
import { redactValue } from "../src/transcript.ts";
import { findUnnamed } from "../src/unnamed.ts";
import { hidden, kept, r } from "./helpers.ts";
import { randomBytes } from "./random.ts";

const KEY = "q8Zr2TmX9vLp4NwK7sYd3HcB6jFg1Ae0";

test("public-browser-key veto needs a whole callee name", () => {
	hidden(`setPrefs("${KEY}")`, KEY);
	hidden(`setDefs("${KEY}")`, KEY);
	kept(`analytics.load("${KEY}")`, KEY);
	kept(`window.heap.load("${KEY}")`, KEY);
	kept(`FS.identify("${KEY}")`, KEY);
	kept(`hj("${KEY}")`, KEY);
});

test("diff- prefix veto needs the base64 to decode to text", () => {
	for (let i = 0; i < 40; i++) {
		const token = `diff-${randomBytes(32).toString("base64")}`;
		hidden(`the build log mentions ${token} as an anchor`, token);
	}
	const path = `diff-${Buffer.from("src/components/Button.tsx").toString("base64")}`;
	kept(`see #${path}`, path);
});

test("public-id veto reads the host of the value's own URL", () => {
	const x = "Xk9mP2qR7vLnB4tY8wZc3HsA";
	hidden(`curl "https://api.example.com/v1/q?src=youtube.com&x=${x}"`, x);
	hidden(`curl "https://orbit.ly/q?x=${x}"`, x);
	kept("https://www.youtube.com/watch?v=dQw4w9WgXcQ", "dQw4w9WgXcQ");
});

test("resource-id veto: credential names and query parameters", () => {
	const t = "Xk9mP2qR7vLnB4tY8wZc3HsAe5Uj6Dg1";
	hidden(`GET https://h/projects/p1/x?token=${t}`, t);
	hidden(`GET https://h/projects/p1/x?foo=${t}`, t);
	kept(`/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/${t}`, t);
});

test("ids filter keeps a credential-named occurrence", () => {
	const id = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
	const found = findUnnamed(`GET /api/posts/${id}\nconfig.password = "${id}"\n`, () => false, "confident", false);
	assert.ok(
		found.some((f) => f.name === "config.password"),
		JSON.stringify(found),
	);
});

test("protobuf field numbers past 31 bits are not read as small", () => {
	// A tag of 2^32 + 8 (field 2^29 + 1 under wire type 0) is past the cap; `>> 3` wrapped it to 1.
	const bytes = Uint8Array.from([0x88, 0x80, 0x80, 0x80, 0x10, 0x01]);
	const b64 = Buffer.from(bytes).toString("base64");
	hidden(`api_key = "${b64}Zk9pQ2xW7vTnB4yR"`, "Zk9pQ2xW7vTnB4yR");
});

test("hashSize names the digest lengths", () => {
	const sha256 = randomBytes(32).toString("base64").replace(/=+$/, "");
	kept(`checksum: ${sha256}`, sha256);
});

test("inert shapes must match exactly under a credential name", () => {
	hidden("password = ssh-rsaQ9xK2mZp7LwT8", "ssh-rsaQ9xK2mZp7LwT8");
	hidden("PASSWORD=op:Passw0rd", "op:Passw0rd");
	hidden("PASSWORD=env:hunter2", "hunter2");
	hidden('password = "[Xk9p]"', "Xk9p");
	hidden('password = "{Ab1Q}"', "Ab1Q");
	// (A password framed like a shape, its inside no name: a variable, a command, an interpolation, a placeholder, a
	// template, a path, code, a credential's name.)
	for (const v of [
		"<Xk9p>",
		"$XkPqWmTzRb",
		"$rqcy7duhdjbjv",
		"@{Tr0ub4dor}",
		"$(Tr0ub4dor)",
		"${Tr0ub4dor.Zx9",
		"${Summer2024",
		"<Xk9 mQ2vL8>",
		"%s-PASSword",
		"/Summer2024",
		"/home/me/Tv$-ycX.K9+/key",
		"/s/Xk9mQ",
		"cfg.QpEpSguu",
		"fluffy_monkey",
		"old_whiskey",
	])
		hidden(`DB_PASSWORD=${v}`, v);
	hidden("--password zpu.KcqEeQfd()", "zpu.KcqEeQfd()");
	kept("PASSWORD=op://prod/db/password", "op://prod/db/password");
	kept("PASSWORD=env:DB_PASS", "env:DB_PASS");
	kept("password: vault:secret/data/app#key", "vault:secret/data/app#key");
	kept("password = [TOKEN]", "[TOKEN]");
	kept("password = <db password>", "<db password>");
	const key = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@host`;
	kept(`key = "${key}"`, "AAAAC3NzaC1lZDI1NTE5");
});

test("a cmdlet-shaped word is a password in a literal context", () => {
	hidden("DB_PASSWORD=Copy-Paste", "Copy-Paste");
	hidden("DB_PASSWORD=Read-Only", "Read-Only");
	kept("password = Get-Content .\\secrets.txt", "Get-Content");
});

test("a password hash ending a sentence is still a hash", () => {
	const hash = "$2b$12$KIXQJ5mP8cT1uY3vN7wZeOq0lH4sD9aF6gB2rC8xV5nM1jE7tUiWy";
	kept(`The stored hash is ${hash}.`, hash);
});

test("mixed-script values with random Latin letters are not foreign text", () => {
	hidden("password = сумкаXkqzPwvRtnbYm", "XkqzPwvRtnbYm");
	kept("password = パスワード/Password", "パスワード/Password");
});

test("transcript: structure keys are skipped only for structure-shaped values", () => {
	const gh = "ghp\x5fXk9mP2qR7vLnB4tY8wZc3HsAe5Uj6Dg1TfVb";
	const out = (v: unknown) => JSON.stringify(redactValue(r(), v).value);
	assert.ok(!out({ role: "assistant", status: gh }).includes(gh));
	assert.ok(!out({ role: "assistant", id: "password=Sup3rS3cret!" }).includes("Sup3rS3cret"));
	assert.ok(!out({ type: "image", data: "password=Sup3rS3cret!" }).includes("Sup3rS3cret"));
	assert.ok(
		out({ role: "assistant", id: "toolu_01AbCdEfGhIjKlMnOpQrStUv", status: "completed" }).includes(
			"toolu_01AbCdEfGhIjKlMnOpQrStUv",
		),
	);
	assert.ok(out({ role: "assistant", model: "claude-sonnet-4-5-20250929" }).includes("claude-sonnet-4-5-20250929"));
});

test("an unnamed random key is missed at most once in a hundred, in a call, a header or a sentence", () => {
	// The unnamed layer is a classifier: a few random keys read as text to it (no digits, a case run like a word's).
	// Its operating point is measured here over many keys, from a fixed sequence so the test is the same every run.
	seed(32);
	for (const place of [
		(k: string) => `client = Helix("${k}")`,
		(k: string) => `curl -H "X-Lumen: ${k}" https://api.lumen.dev`,
		(k: string) => `here's the new key: ${k}`,
	]) {
		const keys = Array.from({ length: 500 }, () => (GENERATORS.alnum() + GENERATORS.alnum()).slice(0, 32));
		const missed = keys.filter((k) => r().redact(place(k)).text.includes(k));
		assert.ok(missed.length <= 5, `${missed.length}/500 missed in ${place("…")}: ${missed.slice(0, 5).join(" ")}`);
	}
});

test("random letters joined by a dash are random, though their runs read as words", () => {
	// (Most of its runs of letters score as words to the model; its case flips as no word's does.)
	hidden("session cookie: CiWjariaZPabaLm-MSLOTNicNPLocPtv", "CiWjariaZPabaLm-MSLOTNicNPLocPtv");
});

test("quoted random tokens and lists of keys are hidden", () => {
	const t = "X1AmNsYrAsPFlY1NKDWo7NhyaxA3DzcKJJmOFqyP";
	const u = "Hf7vT2kLp9RxN4wZ8bYc3HdF6gJ1sA5eUiKoP0qW";
	for (const s of [
		`"${t}"`,
		`'${t}'`,
		"Use `" + t + "` as the key",
		`api_keys:\n  - ${t}\n  - ${u}\n`,
		`{\n  "api_keys": [\n    "${t}",\n    "${u}"\n  ]\n}`,
	])
		hidden(s, t.slice(8, 30));
});

test("an ID-shaped token is hidden in a key's place, and a hash after the word commit is kept", () => {
	// An ID's shape yields to a key's place, and a hash word counts where it heads the phrase, not anywhere on the line.
	hidden("X-Lumen: k3j9x7q2m8p4w6z1v5t0r2ncq8", "k3j9x7q2m8p4w6z1v5t0r2nc");
	for (const label of ["for the git server", ", resolved from the vault", "for the parent account"])
		hidden(`Here's your new API key ${label}:\n9f3a1c7e5b2d8f4a6c0e9b1d7f3a5c82`, "9f3a1c7e5b2d8f4a6c0e9b1d7f3a5c82");
	kept("commit 9f3a1c7e5b2d8f4a6c0e9b1d7f3a5c82e1d0b9a8", "9f3a1c7e5b2d8f4a6c0e9b1d7f3a5c82");
});

test("a token's case changes its naturalness only at a camelCase break: after a lower-case letter, not a symbol or another script's", () => {
	assert.equal(naturalness("${DbPassword}"), naturalness("${dbPassword}"));
	assert.equal(naturalness("caféOrder"), naturalness("caféorder"));
	assert.notEqual(naturalness("orderId"), naturalness("orderid"));
});

test("a random token longer than any key the model was trained on is judged as the longest", () => {
	hidden(
		"X-Session: Q7mZt2Kx9LpV4cW8nR3bY6hF1sD5gJ0aE2uT9kM4wP7xN3qB8vC6zH1rL5yG0fS2dK9jU4iO7eA3tW6mX8nV1pQ5bR2cZ4hY7gT9sF3kL6wD0jM8",
		"Q7mZt2Kx9LpV4cW8nR3bY6hF1sD5gJ0a",
	);
});

test("a document's lines end at its line breaks, escaped ones among them", () => {
	// A `\r\n` ends its line before the `\r`, real or escaped; an escaped backslash before `n` or `r` is no break.
	const doc = new Doc("one\ntwo\\r\\nthree\\\\nfour\\\\r\\nfive\r\nsix");
	assert.deepEqual(
		[0, 1, 2, 3, 4].map((i) => doc.line(i)),
		["one", "two", "three\\\\nfour\\\\r", "five", "six"],
	);
});

test("a token's context: the name and syntax the text around it gives", () => {
	const t = "Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te";
	const n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPF";
	const cases: [text: string, want: Partial<Context>][] = [
		[`curl "https://api.example.com/v1/items?api_key=${t}"`, { name: "api_key", syntax: "query" }],
		[`curl -d "grant_type=client_credentials&client_secret=${t}"`, { name: "client_secret", syntax: "query" }],
		// A commented-out line of a .env is an assignment, not a URL's fragment.
		[`#API_TOKEN=${t}`, { name: "API_TOKEN", syntax: "assign" }],
		[`api_keys:\n  - ${t}\n`, { name: "api_keys", syntax: "list" }],
		[`[\n  "${t}"\n]`, { name: "", syntax: "bare" }],
		[`<input type="hidden" name="csrf" value="${t}">`, { syntax: "xml" }],
		[`token="${t}"`, { name: "token", syntax: "assign" }],
		// A sibling names the value: on its line, or alone on the line above.
		[`{"name": "STRIPE_KEY", "value": "${t}"}`, { name: "STRIPE_KEY" }],
		[`Name: DB_PASSWORD\n${t}\n`, { name: "DB_PASSWORD" }],
		// A value after a name and a tab is no list's item (Django's debug page lists `META:` above).
		[`META:\nCSRF_COOKIE\t'${t}'\n`, { name: "" }],
		// A wrapped string's later line is its name's; not past the line that ends it in padding, nor past other text,
		// nor for a token with text before it.
		[`"n": "${n}\n  ${t}\n`, { name: "n" }],
		[`"n": "${n}\n  4cbbfAAtVT86zwu1RK7aPFFxuh==\n${t}\n`, { name: "" }],
		[`"n": "${n}\nsome prose here\n${t}\n`, { name: "" }],
		[`"n": "${n}\n[INFO] done ${t}\n`, { name: "" }],
		// A CSV cell's header is its block's first line: not a whitespace table's row, a line without commas, a value
		// (an email, a number), nor for a token that is only part of its cell.
		[`HOST     ROLES\nweb1     api,worker\n${t}     api,worker\n`, { name: "" }],
		[`Here is the output\n${t}\n`, { name: "" }],
		[`id,note\n1,see ${t}\n`, { name: "" }],
		[`id,note\n1,${t} now\n`, { name: "" }],
		[`alice@example.com,pro\n${t},free\n`, { name: "" }],
		[`user123,pro\n${t},free\n`, { name: "" }],
		// An SQL row's cell is named by its column, on one line or many.
		[`INSERT INTO users (email, api_key) VALUES ('a@b.c', '${t}');`, { name: "api_key" }],
		[`INSERT INTO users (email, api_key) VALUES\n  ('a@b.c', '${t}'),\n  ('b@b.c', 'x');`, { name: "api_key" }],
		// Git's `HEAD`, as git writes it, is a hash word.
		[`HEAD is now at ${t}`, { lineHash: true }],
	];
	const wrong: string[] = [];
	for (const [text, want] of cases) {
		const at = text.indexOf(t);
		const ctx = contextOf(new Doc(text), at, at + t.length);
		const got = Object.fromEntries(Object.keys(want).map((k) => [k, ctx[k as keyof Context]]));
		if (JSON.stringify(got) !== JSON.stringify(want)) wrong.push(`${JSON.stringify(text)} → ${JSON.stringify(got)}`);
	}
	assert.deepEqual(wrong, []);
});
