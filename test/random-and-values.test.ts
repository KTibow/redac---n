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
import { createHash } from "node:crypto";
import { test } from "node:test";
import { GENERATORS, seed } from "../eval/fuzz-secrets.ts";
import { naturalness } from "../src/charlm.ts";
import { type Context, contextOf, Doc } from "../src/context.ts";
import { redactValue } from "../src/transcript.ts";
import { candidates, features, findUnnamed, namedVector } from "../src/unnamed.ts";
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

test("ids filter keeps a credential-named occurrence, and takes a token for an ID only where a veto says so", () => {
	const id = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
	const found = findUnnamed(`GET /api/posts/${id}\nconfig.password = "${id}"\n`, () => false, "confident", false);
	assert.ok(
		found.some((f) => f.name === "config.password"),
		JSON.stringify(found),
	);
	// A file named after a key (ID-shaped by its prefix) says nothing of its being an ID.
	const key = "acme_Kx9mQ2vL7pZrTq8Wn3Xc4Yb5";
	hidden(`cat ~/.cache/${key}.json\nexport ACME=${key}`, key);
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
	const hashSize = (token: string) => features(new Doc(token), candidates(token)[0], false).hashSize;
	const digest = createHash("sha256").update("x").digest();
	for (const token of [
		digest.toString("hex"),
		createHash("sha1").update("x").digest("hex").toUpperCase(),
		digest.toString("base64"),
		digest.toString("base64").replace(/=+$/, ""),
		digest.toString("base64url"),
		// (Base64 of the SHA-256 of `x2`, with no `+` or `/`: of base62's alphabet.)
		"hE7MCBZOLqsnY0qa3uGvplmeWJVw5xl4TggM50f8DkU",
	])
		assert.ok(hashSize(token), token);
	// 33 bytes, and 43 characters that aren't base64 at all.
	for (const token of [randomBytes(33).toString("base64"), "k3j9x7q2m8p4w6z1v5t0r2ncq8k3j9x7q2m8p4w6z1v"])
		assert.ok(!hashSize(token), token);
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

test("an ID-shaped token is hidden in a key's place, and a hash is kept where a hash word heads its phrase", () => {
	// An ID's shape yields to a key's place, and a hash word counts where it heads the phrase, not anywhere on the line.
	hidden("X-Lumen: k3j9x7q2m8p4w6z1v5t0r2ncq8", "k3j9x7q2m8p4w6z1v5t0r2nc");
	for (const label of ["for the git server", ", resolved from the vault", "for the parent account"])
		hidden(`Here's your new API key ${label}:\n9f3a1c7e5b2d8f4a6c0e9b1d7f3a5c82`, "9f3a1c7e5b2d8f4a6c0e9b1d7f3a5c82");
	kept("commit 9f3a1c7e5b2d8f4a6c0e9b1d7f3a5c82e1d0b9a8", "9f3a1c7e5b2d8f4a6c0e9b1d7f3a5c82");
	const sha256 = "9f3a1c7e5b2d8f4a6c0e9b1d7f3a5c82".repeat(2);
	kept(`Here's your new key\n${sha256} (sha256)`, sha256);
	kept(`Your new key, sha256 ${sha256}`, sha256);
	// A handover, a command's argument after a prompt, a client's constructor: an object ID's prefix, a ULID's shape or
	// a slug's says nothing there.
	for (const [text, token] of [
		["Copy it now, it won't be shown again: tok_Kx9mQ2vL7pZrTq8Wn3Xc4Yb5", "tok_Kx9mQ2vL7pZrTq8Wn3Xc4Yb5"],
		["Use this one:\n01HX3Q8Z9KJ2M4N6P8R0T2V4W6", "01HX3Q8Z9KJ2M4N6P8R0T2V4W6"],
		["$ ./notify.sh prod sess_Kx9mQ2vL7pZrTq8Wn3Xc4Yb5", "sess_Kx9mQ2vL7pZrTq8Wn3Xc4Yb5"],
		['client = AcmeClient("pro_Kx9mQ2vL7pZrTq8Wn3Xc4Yb5")', "pro_Kx9mQ2vL7pZrTq8Wn3Xc4Yb5"],
		['sdk.init("01HX3Q8Z9KJ2M4N6P8R0T2V4W6")', "01HX3Q8Z9KJ2M4N6P8R0T2V4W6"],
		["Use this one: kx9q-tw3v-pz2m-rr8n-lb4c", "kx9q-tw3v-pz2m-rr8n-lb4c"],
	])
		hidden(text, token);
});

test("a token's run starts after the escape before it, and is cut at a path's slashes but not a key's", () => {
	const key = "Kx9mQ2vL7pZrTq8Wn3Xc4Yb5";
	for (const [text, token] of [
		[`printf "100%\\n${key}"`, key],
		// (A `_` escaped in Markdown is the escape's tail and the separator the token drops, once.)
		["the key is Kx9mQ2vL\\_7pZrTq8Wn3Xc4Yb5Va6Ud", "7pZrTq8Wn3Xc4Yb5Va6Ud"],
		[`x=a%20${key}`, key],
		// (A `%` that starts no escape: a cmd variable's.)
		[`set "PW=%RANDOM%${key}"`, key],
		['"Kx9mQ2vL7pZr/qzxw/Tq8Wn3Xc4Yb5Va6U"', "Kx9mQ2vL7pZr/qzxw/Tq8Wn3Xc4Yb5Va6U"],
	]) {
		const tokens = candidates(text).map((c) => c.token);
		assert.ok(tokens.includes(token), `${text}: ${tokens.join(" ")}`);
	}
});

test("base64 of text is kept: a sentence, a table, words, a URL, a GraphQL node ID", () => {
	const b64 = (s: string) => Buffer.from(s).toString("base64");
	for (const [name, token] of [
		["note", Buffer.from("the quick brown fox jumps over the lazy dog ???>>>").toString("base64url")],
		["rows", b64("id\tname\r\n1\tbob\r\n2\tamy\r\n")],
		["target", b64("my-company-artifacts-bucket")],
		["returnTo", b64("https://app.acme.io/cb/7f3k2q")],
		["node", b64("019:AddedToProjectEvent1791766828")],
	])
		kept(`  ${name}: ${token}`, token);
	// Under 24 characters, text is as likely a password: `Winter 2024!`.
	hidden(`Use this one: ${b64("Winter 2024!")}`, b64("Winter 2024!"));
});

test("short base64 of words or of a JWT's header is kept; of a pair or other JSON, hidden", () => {
	const b64 = (s: string) => Buffer.from(s).toString("base64");
	// A tokenizer's vocabulary: each token's bytes in base64, then its rank.
	const vocab = [" necessarily", " regulations", " connections", " observation"].map((w, i) => `${b64(w)} ${6646 + i}`);
	kept(vocab.join("\n"), vocab.join("\n"));
	kept(`base64_string = "${b64("Random string")}"`, b64("Random string"));
	kept(`const base64Content = '${b64("test content")}';`, b64("test content"));
	kept("&assertion=eyJhbGciOiJFUzI1NiJ9.", "eyJhbGciOiJFUzI1NiJ9");
	hidden(`Use this one: ${b64("admin:Kx9mQ2vL")}`, b64("admin:Kx9mQ2vL"));
	hidden("tmux_session=eyJpdiI6IlZ4In0%3D", "eyJpdiI6IlZ4In0");
});

test("a word in a cased alphabet is read whole, not as its ASCII letters; a token after Chinese words is a token", () => {
	for (const line of [
		'    "Recovery key password" : "Endurheimtulykilorð",',
		'    "Recovery Key disabled" : "Endurheimtulykilorð óvirkt",',
		'    "Please check your recovery key password" : "Athugaðu endurheimtulykilorðið þitt!",',
	])
		kept(line, line);
	hidden("我的令牌是Xk9mQ2vLp7Rt3Wz8nB5c，别告诉别人", "Xk9mQ2vLp7Rt3Wz8nB5c");
});

test("the name a declaration gives is an identifier; a token in the class's body is still judged", () => {
	kept(
		"namespace esphome::xiaomi_lywsd03mmc {\n\nclass XiaomiLYWSD03MMC final : public Component {",
		"XiaomiLYWSD03MMC",
	);
	kept("struct QMI8658GyroCfg2 {\n  int range;\n};", "QMI8658GyroCfg2");
	hidden('class Client {\n  const char *token = "Xk9mQ2vLp7Rt3Wz8nB5c";\n};', "Xk9mQ2vLp7Rt3Wz8nB5c");
});

test("a random key in groups or with underscores is neither a slug nor an identifier", () => {
	for (const [text, token] of [
		["Use this one: xk9mq-2vl7p-zrtq8-wn3xc-4yb5v", "xk9mq-2vl7p-zrtq8-wn3xc-4yb5v"],
		["it printed Kx9m-Q2vL-7pZr-Tq8W-n3Xc and exited", "Kx9m-Q2vL-7pZr-Tq8W-n3Xc"],
		["it printed kx9mq2vl-pzrtq8w7-n3xc4yb5 and exited", "kx9mq2vl-pzrtq8w7-n3xc4yb5"],
		["curl -H 'X-Lumen: Kx9mQ2vL7pZrTq8W_N3xc4Yb5Va6U_Te8Sf9Rg0Hh1' https://x.io", "Kx9mQ2vL7pZrTq8W_N3xc4Yb5Va6U"],
	])
		hidden(text, token);
});

test("hex is kept in dashed groups and with a word before it, unless a credential's name or a secret file has it", () => {
	kept("traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", "4bf92f3577b34da6a3ce929d0e0e4736");
	kept("X-Amzn-Trace-Id: Root=1-5759e988-bd862e3fe1be46a994272793", "5759e988-bd862e3fe1be46a994272793");
	const requestId = "7a12d1d6-8c4f-449c-ba47-f1d76432a954";
	kept(`\treq.Header.Set("X-Api-Key", apiKey)\n\treq.Header.Set("X-Request-ID", "${requestId}")`, requestId);
	const login = `export VAULT_TOKEN="$(vault write -field=token auth/approle/login role_id=eac2dc73-2323-49d6-bd8b-aa36a28fceab secret_id=0c21e564-58d7-4a13-8ba9-946659ee0849)"`;
	hidden(login, "0c21e564-58d7-4a13-8ba9-946659ee0849");
	kept(login, "eac2dc73-2323-49d6-bd8b-aa36a28fceab");
	hidden("token=acme_9f86d081884c7d65", "9f86d081884c7d65");
	// In a secret file, a whole value; and a URL's path segment there.
	hidden("STAGE=build_9f86d081884c7d659a2f\n", "9f86d081884c7d659a2f", { secretFile: true });
	hidden("DOWNLOAD_URL=https://files.acme.io/d/kx9mq2vl7pzrtq8wn3xcz\n", "kx9mq2vl7pzrtq8wn3xcz", { secretFile: true });
});

test("the model's inputs: a neutral name only where there is one, a long token's length where the model saw it", () => {
	const key = "Q7mZt2Kx9LpV4cW8nR3bY6hF1sD5gJ0a";
	const featuresOf = (text: string, token: string) =>
		features(
			new Doc(text),
			candidates(text).find((c) => c.token === token)!,
			false,
		);
	const inputs = (text: string, token: string) => namedVector(featuresOf(text, token));
	assert.equal(inputs(`client = Helix("${key}")`, key).name_neutral, 1);
	assert.equal(inputs(`Use this one:\n${key}`, key).name_neutral, 0);
	assert.equal(inputs(`client = Helix("${key}")`, key).neutral_x_long, 1);
	assert.equal(inputs(`client = Helix("${key.slice(0, 24)}")`, key.slice(0, 24)).neutral_x_long, 0);
	// (Past the longest key trained on, a URL path's segment keeps its length, and a query's value and a hook's don't.)
	const long = key.repeat(4);
	assert.equal(inputs(`GET https://cdn.acme.io/${long}/x`, long).logLength, Math.log2(long.length));
	for (const url of [`https://acme.io/cb?state=${long}`, `https://hooks.acme.io/hooks/${long}`])
		assert.equal(inputs(url, long).logLength, Math.log2(90), url);
	// A vendor's prefix is a word before a random body, not before more words.
	assert.ok(featuresOf("acme_live_8f7QxK2mZp9LwT4vRn", "acme_live_8f7QxK2mZp9LwT4vRn").vendorPrefix);
	assert.ok(!featuresOf("get_UserProfileSettings", "get_UserProfileSettings").vendorPrefix);
});

test("a quoted random value is a key alone, not under a name or inside a larger value", () => {
	kept(
		'test_vectors = [\n    "X1AmNsYrAsPFlY1NKDWo7NhyaxA3DzcKJJmOFqyP",\n]',
		"X1AmNsYrAsPFlY1NKDWo7NhyaxA3DzcKJJmOFqyP",
	);
	// Django's signer, and its marker of an unusable password.
	const signed = "'eyJmb28iOiJiYXIifQ:1stLrZ:_QiOBHafwucBF9FyAr54qEs84ZO1UdsO1XiTJCvvdno'";
	kept(`    >>> value\n    ${signed}\n`, "QiOBHafwucBF9FyAr54qEs84ZO1UdsO1XiTJCvvdno");
	kept(
		'for password in [\n    "invalid",\n    "!b7pk7RNudAXGTNLK6fW5YnBCLVE6UUmeoJJYQHaO",\n]:',
		"b7pk7RNudAXGTNLK6fW5YnBCLVE6UUmeoJJYQHaO",
	);
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
		// (`VALUES (` is no call: a row's first cell reads as on many lines.)
		[`INSERT INTO users (api_key) VALUES ('${t}');`, { name: "api_key", syntax: "list" }],
		// A CSV header may name a digest; a bar table's header is its first row, with no rule under it.
		[`file,sha256,size\napp.tgz,${t},10\n`, { name: "sha256" }],
		[`| Service | Value |\n| billing | version |\n| stripe | ${t} |\n`, { name: "stripe" }],
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

test("keys handed over one per line are judged as keys, whatever widths they share", () => {
	const keys = [
		"IhRIAJZE/PEO5pJ8eQjG6ZuJftA791osjvBiB7MCDfw=",
		"lXgCzYiAz6EwdnsyAatoWBPEVC2txVnt280dN9YDbMY=",
		"mxeXTdT/W94sA8J0TV/BoCf2PA8zVvnHoWu/+2fUSTY=",
	];
	for (const key of keys) hidden(`Here are your new API keys:\n${keys.join("\n")}`, key);
	// (A list with no handover over it, `wg show wg0 peers`, is left to the blob rule: public keys, one per line.)
	for (const key of keys) kept(`$ wg show wg0 peers\n${keys.join("\n")}`, key);
});

test("a secret in a URL's path is one whether the URL has its scheme and host or a log shows its path alone", () => {
	const token = "Zk3vQ9xT2mLp7WnR4yUc8HbDq8Xk2LmN";
	for (const path of [`/hooks/${token}`, `/webhook/${token}`, `/api/keys/${token}/rotate`])
		hidden(`10.0.0.5 - - [15/Oct/2026:10:00:00 +0000] "POST ${path} HTTP/1.1" 200 12`, token);
	hidden(`curl -X POST https://ci.example.com/api/projects/42/webhooks/${token}`, token);
	hidden(`curl -X POST https://gitlab.example.com/api/v4/projects/7/trigger/${token}`, token);
	// (Other paths stay IDs and files: a resource's, a file on disk, a cloud resource's.)
	kept(`10.0.0.5 - - [15/Oct/2026:10:00:00 +0000] "GET /api/v1/users/${token} HTTP/1.1" 200 12`, token);
	kept(`cp /hooks/${token} /tmp/x`, token);
	kept(`https://compute.googleapis.com/compute/v1/projects/my-proj/zones/us-central1-a/instances/${token}`, token);
	kept(`curl https://api.elevenlabs.io/v1/text-to-speech/MEpx6aWSUhHeOdc1CcZ5 -o out.mp3`, "MEpx6aWSUhHeOdc1CcZ5");
});

test("a password after a user and a colon is hidden with or without the URL's scheme", () => {
	const pw = "Kd8fQ2mZx9Lp4VnR7sTb3WyH";
	hidden(`export HTTPS_PROXY=svc:${pw}@proxy.corp:8080`, pw);
	hidden(`export HTTPS_PROXY=http://svc:${pw}@proxy.corp:8080`, pw);
	kept(`Message-ID: <CAOS${pw}@mail.gmail.com>`, pw);
	kept(`From: ${pw}@users.noreply.github.com`, pw);
});

test("an RPC provider's key in a Solana URL is a key; an address near Solana's words stays", () => {
	const key = "QpDQ2eodexkZNDm3FHupsikXm4fjaPeY";
	hidden(`RPC_URL=https://solana-devnet.g.alchemy.com/v2/${key}\n`, key);
	hidden(`solana config set --url https://mainnet.helius-rpc.com/?api-key=${key}`, key);
	kept(`https://explorer.solana.com/address/${key}?cluster=devnet`, key);
	kept(`solana balance ${key}`, key);
});

test("IDs where commands, logs and SDKs print them stay: a table's cells, a cache buster, a lookup's argument", () => {
	kept("green open chunks-2026.10 z0JPk8Nk-z16-21STCuI2e 3 1 1820331 0 14.2gb 7.1gb", "z0JPk8Nk-z16-21STCuI2e");
	kept('<link href="/css/site.css?v=R1xcOGumKx9mQ2pLw7vRtZ8nB4cYd3HqT6uV1sWRUY7" rel="stylesheet" />', "R1xcOGum");
	kept('$result = ChargeBee\\Models\\Subscription::retrieve("b1AO9C0mWmtoh1Mlk");', "b1AO9C0mWmtoh1Mlk");
	kept("pspReference=5V59S4TGC5KYYSDW&eventCode=AUTHORISATION&success=false", "5V59S4TGC5KYYSDW");
	kept("  organization: 'org_YWW51UBRXV18GF09IKVYQMG2PN',", "org_YWW51UBRXV18GF09IKVYQMG2PN");
	kept(
		'{"base": "appx4ZUkcFSHS2ONg", "table": "tbl4tVn5FDqFM4EGs", "api_key": "patK9mQ2pLw7vRtZ8n.4f8a2c9e"}',
		"tbl4tVn5FDqFM4EGs",
	);
	// (The same places with a credential in them: a key's parameter, a secret's lookup, a client's argument.)
	hidden("https://x.io/app.js?token=R1xcOGumKx9mQ2pLw7vRtZ8nB4cYd3HqT6uV1sWRUY7", "R1xcOGum");
	hidden('secret = client.secrets.fetch("Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te")', "Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te");
});

test("a header names a value after its parameters and version tags", () => {
	kept("svix-signature: v1,j0N+Ji4l/S09vw5xgfcXlalZr04qXkw27r3i87b/nil=", "j0N+Ji4l");
	kept(
		"Stripe-Signature: t=1492774577,v1=5257a869e7ecebeda32affa62cdca3fa51cad7e77a0e56ff536d0ce8e108d8bd",
		"5257a869e7ecebeda32affa62cdca3fa51cad7e77a0e56ff536d0ce8e108d8bd",
	);
	hidden("X-Api-Key: v1,Kx9mQ2pLw7vRtZ8nB4cYd3HqT6uV1sW5", "Kx9mQ2pLw7vRtZ8nB4cYd3HqT6uV1sW5");
	hidden("error: pin=dGhpc0lzQVNlY3JldEtleTEyMw8x", "dGhpc0lzQVNlY3JldEtleTEyMw8x");
});

test("a query parameter's credential words are its own: a key's parameter doesn't make the next one a key", () => {
	const ctx = (text: string, token: string) =>
		features(
			new Doc(text),
			candidates(text).find((c) => c.token === token)!,
			false,
		).ctx;
	const url =
		"https://server.smithery.ai/exa/mcp?api_key=1b2c3d4e-1111-2222-3333-444455556666&profile=loexnc-wjfyad-li2q6";
	assert.equal(ctx(url, "loexnc-wjfyad-li2q6").lineCredential, false);
	assert.equal(
		ctx("token: x\nhttps://a.io/cb?profile=loexnc-wjfyad-li2q6", "loexnc-wjfyad-li2q6").lineCredential,
		true,
	);
});
