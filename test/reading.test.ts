/**
 * Reading text before detection: shell words, redirects, terminal escapes, entities, wrapped base64, repeats, learned
 * values, placeholders and streams.
 *
 *   node --test test/reading.test.ts
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { KeywordSet } from "../src/aho.ts";
import { base64Binary } from "../src/base64.ts";
import { printsSecret } from "../src/commands.ts";
import { Redactor } from "../src/index.ts";
import { normalize } from "../src/normalize.ts";
import { occurrences } from "../src/repeats.ts";
import { shellCommands, wordSpan } from "../src/shell.ts";
import { wrapped } from "../src/spans.ts";
import { b62, hidden, kept, r } from "./helpers.ts";
import { assertLinear } from "./timing.ts";

const commands = (line: string) => shellCommands(line).map((c) => c.words.map((w) => w.text).join(" "));

test("a finding ending inside an ANSI-C escape takes the escape whole", () => {
	const out = r().redact("echo $'\x73k-live-4eC39HqLyjWDarjtT1zdp7d\\x63' > .env").text;
	assert.ok(!out.includes("\\x63"), out);
	const [w] = shellCommands("$'ab\\x63d\\U0001F600e'")[0].words;
	assert.equal(w.text.length, w.map.length);
	assert.equal(w.raw.slice(w.map[2] - w.start, w.ends[2] - w.start), "\\x63");
	assert.deepEqual(wordSpan(shellCommands("echo a\\ b")[0].words[1], 1), { start: 7, end: 9 });
});

test("one quoting grammar: quotes inside substitutions and unterminated quotes", () => {
	assert.deepEqual(commands("echo $(printf '%s' \"a)b\") && cat .env"), ["echo $(printf '%s' \"a)b\")", "cat .env"]);
	assert.deepEqual(commands("echo $(echo $'it\\'s)') ; cat .env"), ["echo $(echo $'it\\'s)')", "cat .env"]);
	// An unterminated quote runs to the end of the text, into one word.
	assert.equal(commands("echo 'abc\ntee .env\nls").length, 1);
});

test("parser gaps: $(( subshell, case patterns, reserved words after then/else/!", () => {
	const inner = shellCommands("echo $((cat .env) | head)")[0].words[1].substitutions;
	assert.equal(inner.length, 1);
	assert.equal(shellCommands("echo $((1 + 2))")[0].words[1].substitutions.length, 0);
	assert.ok(
		shellCommands('echo "$(case x in x) cat .env;; esac)"')[0].words[1].substitutions.some((s) => s.end - s.start > 20),
	);
	assert.deepEqual(commands("case x in x) cat .env;; esac"), ["cat .env"]);
	assert.deepEqual(
		shellCommands("if true; then ! { cat .env; }; fi")
			.find((c) => c.words.some((w) => w.text === "cat"))!
			.groups.map((g) => g.kind),
		["{", "if"],
	);
});

test(">& and &> send output to a file", () => {
	for (const c of ["echo $GITHUB_TOKEN >& out.txt", "echo $GITHUB_TOKEN &> out.txt", "echo $GITHUB_TOKEN &>> out.txt"])
		assert.ok(!printsSecret(c), c);
	for (const c of ["echo $GITHUB_TOKEN 2>&1", "echo $GITHUB_TOKEN >&2", "echo $GITHUB_TOKEN 2>/dev/null"])
		assert.ok(printsSecret(c), c);
});

test("caret notation is read per position", () => {
	assert.equal(
		normalize("^[[32mred^[[0m\nregex ^[a-z]{8} password=Hunter2!").text,
		"red\nregex ^[a-z]{8} password=Hunter2!",
	);
	assert.equal(normalize("^[]0;title^G x").text, "0;title\n x");
});

test("a caret string terminator ends the OSC", () => {
	assert.equal(normalize("^[[0mA^[]0;t^[\\ and ^Gx").text, "A0;t\n and ^Gx");
});

test("every named entity the gate admits decodes", () => {
	assert.equal(normalize("sk&lowbar;live&lowbar;abc&lpar;1&rpar;&lsqb;&rsqb;").text, "sk_live_abc(1)[]");
	assert.equal(normalize("a&foo;b").text, "a&foo;b");
	hidden("key=sk&lowbar;live&lowbar;4eC39HqLyjWDarjtT1zdp7dc", "4eC39HqLyjWDarjtT1zdp7dc");
});

test("inline tags are still dropped", () => {
	assert.equal(normalize("<b>Password:</b> <code>X9</code>").text, "Password: X9");
});

test("wrapped base64 with a prefix on the first line and a suffix on the last", () => {
	const secret = "aws_access_key_id = AKI\x41J7QX3MZP5RTWV2KA\n# padding padding padding padding\n";
	const folded = Buffer.from(secret)
		.toString("base64")
		.match(/.{1,30}/g)!
		.join("\n");
	hidden(folded, "AKI\x41J7QX3MZP5RTWV2KA");
	assert.ok(!r().redact(`data: ${folded}`).text.includes(folded.split("\n")[1]), "prefixed first line");
	const json = `{"d":"${folded.replace(/\n/g, "\\n")}"}`;
	assert.ok(!r().redact(json).text.includes(folded.split("\n")[1]), json);
	assert.ok(!r().redact(`data: ${folded}\n`).text.includes(folded.split("\n")[0]));
});

test("encoded: hex bytes are validated", () => {
	assert.equal(r().redact("zz".repeat(20)).text, "zz".repeat(20));
});

test("hex dumps of a secret are hidden whole, in each tool's layout", () => {
	const key = "ghp\x5fZ2r9Kq4Lm7Pw1Xv8Bt3Nc6Hd0Jf5Ys2Ge9Ua";
	const bytes = Buffer.from(`API_KEY=${key}\nDEBUG=1\n`);
	const hex = (b: Buffer) => b.toString("hex");
	const ascii = (b: Buffer) => [...b].map((c) => (c >= 32 && c < 127 ? String.fromCharCode(c) : ".")).join("");
	const rows = (fn: (row: Buffer, offset: number) => string) =>
		Array.from({ length: Math.ceil(bytes.length / 16) }, (_, k) =>
			fn(bytes.subarray(k * 16, k * 16 + 16), k * 16),
		).join("\n");
	const pairs = (b: Buffer, size: number, swap = false) =>
		(hex(b).match(new RegExp(`.{1,${size * 2}}`, "g")) ?? []).map((g) =>
			swap && g.length === 4 ? g.slice(2) + g.slice(0, 2) : g,
		);
	const dumps = {
		xxd: rows((b, o) => `${o.toString(16).padStart(8, "0")}: ${pairs(b, 2).join(" ")}  ${ascii(b)}`),
		"xxd -p": hex(bytes)
			.match(/.{1,60}/g)!
			.join("\n"),
		hexdump: rows((b, o) => `${o.toString(16).padStart(7, "0")} ${pairs(b, 2, true).join(" ")}`),
		"hexdump -C": rows((b, o) => `${o.toString(16).padStart(8, "0")}  ${pairs(b, 1).join(" ")}  |${ascii(b)}|`),
		"od -A x -t x1z": rows((b, o) => `${o.toString(16).padStart(6, "0")} ${pairs(b, 1).join(" ")}  >${ascii(b)}<`),
	};
	for (const [tool, dump] of Object.entries(dumps)) {
		const out = r().redact(`$ ${tool} build.bin\n${dump}\n`).text;
		for (const line of dump.split("\n").slice(0, 3)) assert.ok(!out.includes(line.slice(0, 40)), `${tool}: ${out}`);
	}
});

test("base64Binary strips padding in linear time", () => {
	assert.equal(base64Binary("=".repeat(200_000) + "x"), undefined);
	assertLinear("padding", (n) => base64Binary("=".repeat(n) + "x"), 100_000);
	assert.equal(base64Binary("aGk=="), "hi");
});

test("KeywordSet refuses an empty keyword", () => {
	assert.throws(() => new KeywordSet(["", "abc"], true), RangeError);
});

test("known-value scan finds overlapping occurrences like the automaton", () => {
	const text = "see ab.ab.ab.ab here";
	const scan = occurrences(text, new Map([["ab.ab.ab", { kind: "secret", value: "ab.ab.ab" }]]), []).map(
		(f) => f.start,
	);
	assert.deepEqual(scan, [4, 7]);
	const set = new KeywordSet(["ab.ab.ab"], true);
	assert.deepEqual(
		[...set.matches(text)].map(([at]) => at),
		scan,
	);
});

test("a secret in a placeholder's kind slot is not trusted", () => {
	hidden("export KEY=[REDACTED sk\x5flive_4eC39HqLyjWDarjtT1zdp7dc #abcdef]", "4eC39HqLyjWDarjtT1zdp7dc");
	const once = r().redact('password = "xK9mQ2vLp8ZrT4wYc7NbE3sD"').text;
	assert.equal(r().redact(once).text, once);
});

test("two findings in one JSON number are hidden by one placeholder", () => {
	const red = new Redactor({ fingerprintKey: "test" });
	const text = '{"pin": 98127734120987}';
	const f = { kind: "x", rule: "known", confidence: 1 };
	const out = red.apply(text, [
		{ ...f, start: 9, end: 14 },
		{ ...f, start: 15, end: 22 },
	]).text;
	assert.equal(out.match(/REDACTED/g)?.length, 1, out);
});

test("batch and stream agree on findings inside a JSON number", () => {
	for (const [text, known] of [
		['{"pin": -98127734120987.5}', "98127734120987"],
		['{"a": [12.98127734120987]}', "98127734120987"],
		['{"a": 7, "pin": 1298127734120987}', "98127734120987"],
	]) {
		const red = new Redactor({ fingerprintKey: "test", known: [known] });
		const stream = red.stream();
		assert.equal(stream.write(text) + stream.end(), red.redact(text).text, text);
	}
});

test("wrapped() does not change its input", () => {
	const line = "A".repeat(80);
	const text = `Authorization: Bearer ${line.slice(22)}\n${"Xk9mQ2vLp8".repeat(2)}1\n`;
	const f = { start: 22, end: 80, kind: "x", rule: "format:x", confidence: 1 };
	const copy = { ...f };
	wrapped(text, [f]);
	assert.deepEqual(f, copy);
});

test("a long finding ends at an escape, so escaped JSON around it still parses", () => {
	const b64url = (n: number) =>
		Buffer.from(Array.from({ length: n }, (_, k) => (k * 7919) % 251)).toString("base64url");
	const jwt = `eyJhbGciOiJIUzI1NiJ9.${b64url(1700)}.${b64url(32)}`;
	const text = JSON.stringify({ body: JSON.stringify({ token: jwt, next: "Content-Type" }) });
	const out = r().redact(text).text;
	assert.ok(!out.includes(jwt.slice(-40)));
	assert.equal(JSON.parse(JSON.parse(out).body).next, "Content-Type");
});

test("terminal colours and entities around a value don't hide it", () => {
	hidden("export AWS=\x1b[1mAKI\x41QZGOQKYPAR27BIHL\x1b[0mxyz", "QZGOQKYPAR27BIHL");
	hidden("<password>Vq7m&lt;Zp2xK</password>", "Zp2xK");
});

test("values learned one at a time are all found, before and after the index is rebuilt whole", () => {
	const red = r();
	const values = Array.from({ length: 300 }, (_, k) => `Pw${k.toString(36)}#x9qLm2Z`);
	for (const v of values) {
		red.learn(`password=${v}`);
		assert.ok(!red.redact(`said ${v} twice`).text.includes(v), v);
	}
	for (const v of [values[0], values[150], values.at(-1)!]) assert.ok(!red.redact(`then ${v}`).text.includes(v), v);
});

test("a code fence ends the session a document shows", () => {
	kept("$ ruby -e 'puts SecureRandom.hex(64)'\n```\n\n```ruby\nhalt 410\n```\n", "```ruby");
});

test("every repeat of 100 passwords in a long text is found", () => {
	const values = Array.from({ length: 100 }, (_, i) => `Pw${i}x${b62(12)}`);
	const long =
		values.map((v, i) => `DB_PASSWORD_${i}=${v}`).join("\n") +
		"\n" +
		"filler line of text\n".repeat(60000) +
		values.map((v) => `connected using ${v} ok`).join("\n");
	const out = r().redact(long).text;
	assert.equal(values.filter((v) => out.includes(v)).length, 0);
});

test("a multi-line known value makes only its random lines known", () => {
	const sa = JSON.stringify(
		{
			type: "service_account",
			auth_uri: "https://accounts.google.com/o/oauth2/auth",
			private_key_id: "8c3a0f2e1d4b5c6a7e8f9a0b1c2d3e4f5a6b7c8d",
		},
		null,
		2,
	);
	kept(
		'{\n  "type": "service_account",\n  "auth_uri": "https://accounts.google.com/o/oauth2/auth"\n}',
		'"type": "service_account"',
		{},
	);
	assert.ok(new Redactor({ known: [sa] }).redact('  "type": "service_account",').text.includes("service_account"));
});

test("a viewer's line number on a one-line secret file is not part of the learned value", () => {
	const viewer = r();
	viewer.learn("     1→Harbor#2291x\n", { hint: { path: "/srv/app/.vault_pass" } });
	assert.ok(!viewer.redact("Decrypting with Harbor#2291x now.").text.includes("Harbor#2291x"));
});

test("a repeat after an escape is a whole token: the escape's letter is no part of it", () => {
	for (const around of ["connected\\nHarbor#2291xQ\\nok", "pw:\\tHarbor#2291xQ", "echo \\u0027Harbor#2291xQ\\u0027"])
		hidden(`DB_PASSWORD=Harbor#2291xQ\n{"content":"${around}"}`, "Harbor#2291xQ");
});

test("tag characters and other invisible characters outside the basic plane are dropped", () => {
	const key = "AKI\x41J7QX3MZP5RTWV2KA";
	hidden(`aws_access_key_id = ${[...key].join("\u{E0041}")}`, "3MZP5RTWV2KA");
	assert.equal(normalize("sk\u{E0041}\u{E0100}-abcㅤd").text, "sk-abcd");
	assert.equal(normalize("a&#0;b &#xD800;").text, "a&#0;b &#xD800;");
});
