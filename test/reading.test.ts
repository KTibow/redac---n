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
import { covered, merge, toWordEnd, wrapped } from "../src/spans.ts";
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
	for (const c of [
		"echo $GITHUB_TOKEN >& out.txt",
		"echo $GITHUB_TOKEN &> out.txt",
		"echo $GITHUB_TOKEN &>> out.txt",
		"echo $GITHUB_TOKEN 1> out.txt",
		"echo $GITHUB_TOKEN 1>& out.txt",
	])
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

test("what a terminal hides goes, and only that", () => {
	// Colour codes a JSON log writes as escapes, with no raw ESC in the text.
	assert.equal(normalize('{"log":"\\u001b[32mok\\u001b[0m"}').text, '{"log":"ok"}');
	// A title ends at its BEL; a `^` or a `G` in it is the title's. One never ended ends with its line: nano's
	// `^G Get Help` under it is text.
	assert.equal(normalize("\x1b]0;Go x^2\x07ok").text, "0;Go x^2\nok");
	assert.equal(normalize("^[]0;nano\n^G Get Help").text, "0;nano\n^G Get Help");
	// UTF-16 read as UTF-8 loses every NUL, its last one too; a letter beside an invisible character stays.
	assert.equal(normalize("p\0w\0=\0X\0Y\0").text, "pw=XY");
	assert.equal(normalize("café​").text, "café");
});

test("grep's prefixes go on consecutive lines of a file, not on a .pgpass's hosts and ports", () => {
	assert.equal(normalize("app.py:10:x = 1\napp.py:11:y = 2").text, "x = 1\ny = 2");
	assert.equal(normalize("application.properties:12:a=1\napplication.properties:13:b=2").text, "a=1\nb=2");
	const pgpass = "db.example.com:5432:app:app:Harbor#2291x\ndb.example.com:5433:app:app:Copper#7781x";
	assert.equal(normalize(pgpass).text, pgpass);
});

test("a hunk's markers go on the lines its header counts, and no further", () => {
	for (const [diff, plain] of [
		["@@ -1 +1 @@\n-a\n+b\n- note", "@@ -1 +1 @@\na\nb\n- note"],
		["@@ -1,2 +1,2 @@\n a\n-b\n+c\n- note", "@@ -1,2 +1,2 @@\na\nb\nc\n- note"],
		// (A context line an editor emptied, in CRLF; a hunk cut short by `head`.)
		["@@ -1,3 +1,3 @@\r\n a\r\n\r\n-b\r\n+c\r\n", "@@ -1,3 +1,3 @@\r\na\r\n\r\nb\r\nc\r\n"],
		["@@ -1,5 +1,5 @@\n-a\n+b\nDone.\n- note", "@@ -1,5 +1,5 @@\na\nb\nDone.\n- note"],
	])
		assert.equal(normalize(diff).text, plain);
});

test("spaces of other widths, full-width signs and line continuations, and backslashes that are none", () => {
	assert.equal(normalize("a b c　d e").text, "a b c d e");
	assert.equal(normalize("PASSWORD：x＝y").text, "PASSWORD:x=y");
	assert.equal(normalize("a&amp;b \\t c").text, "a&b \\t c");
	assert.equal(normalize("**Host:** db\\\n**Password:** x").text, "**Host:** db\\\n**Password:** x");
	// An entity escaped twice (JSON in an attribute escaped twice) is the character.
	assert.equal(normalize("{&amp;quot;a&amp;quot;:1} &amp;amp;lt;").text, '{"a":1} <');
});

test("typographic quotes, as autocorrect writes pasted JSON and config, are read as the straight ones", () => {
	assert.equal(normalize("“password”: ‘x’ „y“").text, `"password": 'x' "y"`);
	hidden("{\n  “username”: “bob”,\n  “password”: “Winter2024!kz”\n}", "Winter2024!kz");
	hidden("“api_key” = “Kx9mQ2pLrT7vW4nB”", "Kx9mQ2pLrT7vW4nB");
	hidden("DB_PASSWORD=‘Tr0ub4dor&3xQ’", "Tr0ub4dor&3xQ");
	// (The quotes themselves stay as written around the placeholder, and prose keeps its apostrophes.)
	kept("{“password”: “Winter2024!kz”}", "“password”: “");
	kept("The password’s rules don’t change: “at least 12 characters”.", "“at least 12 characters”");
	// (An apostrophe inside a word quotes nothing: a locale's label for the password, Corsican's.)
	assert.equal(normalize("chjave d’accessu").text, "chjave d’accessu");
	kept("  login_activities:\n    authentication_methods:\n      password: chjave d’accessu\n", "chjave d’accessu");
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
	const rows = (fn: (row: Buffer, offset: number) => string, width = 16) =>
		Array.from({ length: Math.ceil(bytes.length / width) }, (_, k) =>
			fn(bytes.subarray(k * width, k * width + width), k * width),
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
		"od -An -tx1": rows((b) => ` ${pairs(b, 1).join(" ")}`),
		"xxd -g 8": rows((b, o) => `${o.toString(16).padStart(8, "0")}: ${pairs(b, 8).join(" ").padEnd(33)}  ${ascii(b)}`),
		"xxd -c 32 -g1": rows(
			(b, o) => `${o.toString(16).padStart(8, "0")}: ${pairs(b, 1).join(" ").padEnd(95)}  ${ascii(b)}`,
			32,
		),
	};
	for (const [tool, dump] of Object.entries(dumps)) {
		const out = r().redact(`$ ${tool} build.bin\n${dump}\n`).text;
		for (const line of dump.split("\n").slice(0, 3)) assert.ok(!out.includes(line.slice(0, 40)), `${tool}: ${out}`);
	}
});

test("a hex dump's bytes are its hex columns, not a hex word in its text column or a hex line after it", () => {
	const xxd = (text: string) =>
		(
			Buffer.from(text)
				.toString("hex")
				.match(/.{1,32}/g) ?? []
		)
			.map((h, k) => {
				const groups = h.match(/.{1,4}/g)!.join(" ");
				const ascii = Buffer.from(h, "hex")
					.toString("latin1")
					.replace(/[^ -~]/g, ".");
				return `${(k * 16).toString(16).padStart(8, "0")}: ${groups.padEnd(39)}  ${ascii}`;
			})
			.join("\n");
	// (The first row's text column starts `face `, and `password` runs on into the second.)
	const dump = xxd("face id: off\npassword=Xk29fLq7Wm3Rt8Zp\n");
	assert.ok(!r().redact(`$ xxd settings.txt\n${dump}\n`).text.includes(dump.split("\n")[1].slice(0, 40)), dump);
	// (`xxd -p` puts 30 bytes on a line: the password runs on into the second. A binary file's dump comes first.)
	const binary = Buffer.from(Array.from({ length: 40 }, (_, k) => (k * 37) % 256)).toString("hex");
	const plain = Buffer.from("PORT=3000\nDB_PASSWORD=Xk29fLq7Wm3Rt8Zp\n")
		.toString("hex")
		.match(/.{1,60}/g)!;
	const out = r().redact(`${binary.match(/.{1,60}/g)!.join("\n")}\n\n${plain.join("\n")}\n`).text;
	assert.ok(out.startsWith(binary.slice(0, 60)) && !out.includes(plain[1]), out);
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

test("a known value is found as a whole token outside the findings, not as the start or end of a longer one", () => {
	const v = "Kx9mQv2Lp7Rt";
	const text = `${v} x${v} ${v}9 (${v}) ${v}`;
	const found = [{ start: text.length - v.length, end: text.length, kind: "secret", rule: "known", confidence: 1 }];
	const scan = occurrences(text, new Map([[v, { kind: "secret", value: v }]]), found).map((f) => f.start);
	assert.deepEqual(scan, [0, text.indexOf(`(${v}`) + 1]);
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

test("a token wraps on to the next line only at a terminal's width, CRLF too, and only a token's rule", () => {
	const token = `${"Ab1".repeat(19)}a`;
	const next = `${"Xk9mQ2vLp8".repeat(2)}1`;
	const f = { start: 22, end: 80, kind: "bearer credential", rule: "structure:authorization", confidence: 0.97 };
	assert.equal(wrapped(`Authorization: Bearer ${token}\r\n${next}\r\n`, [f])[0].end, 103);
	assert.equal(wrapped(`Authorization: Bearer ${token}\n${next}\n`, [{ ...f, rule: "named:assign" }])[0].end, 80);
	// (A token that ends a 40-character line: the line after it is no part of it.)
	assert.equal(wrapped(`${token.slice(0, 40)}\n${next}\n`, [{ ...f, start: 0, end: 40 }])[0].end, 40);
});

test("merged findings: a whole line gives way to a sure finding inside it; a value keeps to its span", () => {
	const at = (start: number, end: number, rule: string, confidence = 0.95, value?: string) => ({
		start,
		end,
		kind: "secret",
		rule,
		confidence,
		...(value === undefined ? {} : { value }),
	});
	const spans = (fs: { start: number; end: number }[]) => fs.map((f) => [f.start, f.end]);
	const line = at(0, 30, "file:whole");
	// Not to a guess, a repeat or an unsure finding: the line stays whole.
	for (const inner of [at(8, 30, "unnamed:token"), at(8, 30, "repeat", 0.9), at(8, 30, "named:assign", 0.8)])
		assert.deepEqual(spans(merge([line, inner])), [[0, 30]], inner.rule);
	assert.deepEqual(spans(merge([line, at(8, 30, "named:assign")])), [[8, 30]]);
	// One the same as the line names it; a finding that isn't a whole line keeps its span around a narrower one.
	assert.equal(merge([line, at(0, 30, "format:GitHub token", 0.9)])[0].rule, "format:GitHub token");
	assert.deepEqual(spans(merge([at(0, 30, "named:assign"), at(10, 20, "format:x", 0.99)])), [[0, 30]]);
	// A value is kept only by the span it was read from: on a tie the longer finding's fields win.
	assert.equal(merge([at(0, 10, "a", 0.95, "Kx9mQ2pLw7"), at(5, 15, "b", 0.5)])[0].value, undefined);
	assert.equal(merge([at(0, 5, "a", 0.9), at(0, 10, "b", 0.9, "Kx9mQ2pLw7")])[0].value, "Kx9mQ2pLw7");
	// In text encoded twice, a span right after an escaped backslash takes the pair in (`C:\\nKx82…`).
	const text = '{"cmd": "C:\\\\nKx82mQ2pLw7vZr9Tq"}';
	assert.equal(merge([at(13, 31, "named:assign")], text)[0].start, 11);
	assert.ok(covered(merge([at(0, 10, "a")]), 2, 8));
	assert.ok(!covered(merge([at(0, 10, "a")]), 5, 15));
});

test("a format's token is the span where a value read to the next blank runs past it", () => {
	const tok = "ghp\x5f0MDkfSKa7K7EeAKNsT3RLsNg5Wt5QRZ3XEna";
	const R = new Redactor({ fingerprintKey: "test" });
	const tag = R.redact(tok).text;
	for (const [text, after] of [
		[`GITHUB_TOKEN=${tok};git push origin main`, ";git push origin main"],
		[`export TOKEN=${tok};ls`, ";ls"],
		[`token=${tok}&q=foo&page=2&sort=desc`, "&q=foo&page=2&sort=desc"],
		[`wget https://x.io/a?token=${tok}#top`, "#top"],
		[`token=${tok}.`, "."],
		[`TOKEN=${tok},next`, ",next"],
	]) {
		const out = R.redact(text).text;
		assert.ok(out.endsWith(`${tag}${after}`), out);
	}
	// A token that stops where its format stops but the text goes on in token characters is hidden with its tail.
	for (const tail of ["%2Bab12", ".abc123", "-extra9"]) {
		const out = R.redact(`token=${tok}${tail} done`).text;
		assert.ok(!out.includes(tail), out);
	}
});

test("an unquoted value ends at the settings after it in a list with no blank between", () => {
	const R = new Redactor({ fingerprintKey: "test" });
	const pw = "Kx9mQ2vL8nRt4zWp";
	const tag = `#${R.fingerprint(pw)}]`;
	for (const [text, rest] of [
		[`password=${pw};username=bob`, ";username=bob"],
		[`DB_PASSWORD=${pw},DB_HOST=db,DB_PORT=5432`, ",DB_HOST=db,DB_PORT=5432"],
		[`user=bob;password=${pw};port=22`, ";port=22"],
		[`secret=${pw}&redirectUri=https://app.example.com/cb`, "&redirectUri=https://app.example.com/cb"],
	]) {
		const out = R.redact(text).text;
		assert.ok(out.endsWith(`${tag}${rest}`), out);
	}
	// A password's own punctuation is not a list: hidden whole.
	for (const value of ["86)68/C{,C=wyhJH9", "W;FHFj=7agoi1q%!#Fo", "Nakp&nDiqWJ-K=nW", "Kx9mQ2;vL8nRt=4zWp!x"])
		hidden(`DB_PASSWORD=${value}`, value);
	// Nor is a value that is a list itself, or a URL.
	hidden("DSN=host=db;password=Kx9mQ2vL8nRt4zWp;port=5432", "Kx9mQ2vL8nRt4zWp");
});

test("a long finding a read bound may have cut runs on to its word's end, through PHP's `\\/`", () => {
	const token = b62(3000);
	const f = { start: 0, end: 2500, kind: "token", rule: "named:assign", confidence: 0.95 };
	assert.equal(toWordEnd(`${token}\\/${"Ab1".repeat(4)} next`, f).end, 3014);
	// One that ends at its closing quote isn't inside a word.
	assert.equal(toWordEnd(`"${token}"x y`, { ...f, end: 3002 }).end, 3002);
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
	// (JSON in an attribute escaped twice.)
	hidden(
		'<div data-config="{&amp;quot;user&amp;quot;:&amp;quot;bob&amp;quot;,&amp;quot;password&amp;quot;:&amp;quot;Xk29fLmq81Zt&amp;quot;}"></div>',
		"Xk29fLmq81Zt",
	);
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

test("a value found once is hidden where it's written again, percent-encoded too; a guessed hash or a date isn't", () => {
	// A secret file's token shaped like a commit, echoed by a script; a password in a form body and a URL path.
	const token = "3f9a2c1e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a39";
	hidden(`$ cat .env\nDEPLOY_TOKEN=${token}\n$ ./deploy.sh\nauthenticating deploy-bot (${token})`, token);
	for (const use of [
		'curl -s -d "u=app&p=Wq8%23zLp2%2FvRk" http://localhost:8080/session',
		"sent: /connect/app/Wq8%23zLp2%2FvRk/db",
	])
		hidden(`export DB_PASSWORD='Wq8#zLp2/vRk'\n${use}`, "Wq8%23zLp2%2FvRk");
	// (One holding half a surrogate pair, as a transcript cut mid-character has, has no URL form: only it is hidden.)
	const cut = "Kx9mQ\uD83Dv2Lp7Rt";
	kept(`DB_PASSWORD=${cut}\nagain ${cut}`, "again");
	hidden(`DB_PASSWORD=${cut}\nagain ${cut}`, cut);
	// A guess at a value shaped like a commit spreads to no commit line; a password that is a date, to no other date.
	const sha = "9fceb02d0ae598e95dc970b74767f19372d61af8";
	kept(`KEY=${sha}\ncommit ${sha}`, `commit ${sha}`);
	kept("DB_PASSWORD=21.05.1987\nmigrations applied on 21.05.1987", "on 21.05.1987");
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
	// (Nor does an entity decode to NUL, half a surrogate pair, or a character of two UTF-16 units.)
	assert.equal(normalize("a&#0;b &#xD800; &#x1F600;").text, "a&#0;b &#xD800; &#x1F600;");
});

test("a value written with its quotes' escapes is learned and tagged as the program reads it", () => {
	const tag = (text: string, hint = {}) => /#(\w+)\]/.exec(r().redact(text, { hint }).text)?.[1];
	for (const [raw, forms] of [
		[
			"Tr0ub4dor'3xK9mQ",
			[
				"db_password: 'Tr0ub4dor''3xK9mQ'\n",
				"CREATE USER app WITH PASSWORD 'Tr0ub4dor''3xK9mQ';\n",
				"const password = 'Tr0ub4dor\\'3xK9mQ';\n",
				"export DB_PASSWORD='Tr0ub4dor'\\''3xK9mQ'\n",
			],
		],
		["Tr0ub4dor$3xK9mQ", ['export DB_PASSWORD="Tr0ub4dor\\$3xK9mQ"\nexport PORT=5432\n']],
		[
			'Tr0ub4dor"3xK9mQ',
			['{"password": "Tr0ub4dor\\"3xK9mQ"}', '{"body": "{\\"password\\": \\"Tr0ub4dor\\\\\\"3xK9mQ\\"}"}'],
		],
		["Pa$$w0rd x9Kq", ["mysql --password=Pa\\$\\$w0rd\\ x9Kq -u root\n"]],
	] as const) {
		const expected = tag(`DB_PASSWORD=${JSON.stringify(raw)}\n`);
		for (const text of forms) {
			assert.equal(tag(text, { path: "setup.sh" }), expected, text);
			const red = r();
			red.learn(text, { hint: { path: "setup.sh" } });
			assert.ok(!red.redact(`The login fails with ${raw} again.`).text.includes(raw), text);
		}
	}
	// (A shell's single quotes hold no escapes: its backslash is the value's own.)
	assert.equal(tag("export DB_PASSWORD='Tr0ub4dor\\3xK9mQ'\n"), tag('DB_PASSWORD="Tr0ub4dor\\\\3xK9mQ"\n'));
});

test("a known token cut short takes no path before it, only what its value is made of", () => {
	const red = new Redactor({ fingerprintKey: "t", known: ["ghp_Zq8vK2mX9pLw4RtYabcdefghijKLMN"] });
	const out = red.redact("see https://api.github.com/repos/o/r/ghp_Zq8vK2mX9pLw4Rt and more").text;
	assert.ok(out.startsWith("see https://api.github.com/repos/o/r/[REDACTED part of"), out);
	// (A value with `/` in it goes on through one.)
	const slash = new Redactor({ fingerprintKey: "t", known: ["Zq8vK2mX9pLw4Rt/YabcdefghijKLMNxyz"] });
	assert.ok(!slash.redact("see Zq8vK2mX9pLw4Rt/Yabcdefghij and more").text.includes("Yabcdefghij"));
});

test("a value with no letter or digit, or of one character repeated, is never known, nor a long value's end of one", () => {
	const red = r();
	for (const v of [
		"^^^^^^^^^^^^^^^^^^^^",
		"~~~~~~~~~~~~~~~^^^",
		"+----------+",
		"!@#$%^&*()",
		"0000000000",
		"a".repeat(16),
	])
		assert.equal(red.addKnown(v), false, v);
	assert.ok(red.addKnown("!@#$%^&*()x"));
	// (A key's zero bytes, `AAAA…`, open other blobs too: an ssh-rsa key's, here.)
	const zeros = new Redactor({ fingerprintKey: "t", known: [`${"A".repeat(16)}Qm9yZWFsaXNLZXlNYXRlcmlhbA`] });
	assert.equal(zeros.redact("data: AAAAAAAAAAAAAAAAB3NzaC1yc2E end").text, "data: AAAAAAAAAAAAAAAAB3NzaC1yc2E end");
	assert.ok(!zeros.redact(`k ${"A".repeat(16)}Qm9yZWFsaXNLZXlNYXRlcmlhbA e`).text.includes("Qm9y"));
});

test("a login under a name that says so teaches its password too; a base64 key or a signature is not split", () => {
	const redactor = r();
	redactor.learn("NEO4J_AUTH=neo4j/Xk2mP9vLqT\n", { hint: { path: ".env" } });
	const ps = "  73104 /opt/neo4j/bin/neo4j-admin --verbose Xk2mP9vLqT";
	assert.ok(!redactor.redact(ps).text.includes("Xk2mP9vLqT"));
	// (Within one text too, as a repeat.)
	hidden("NEO4J_AUTH=neo4j/Xk2mP9vLqT\n---\nconnecting with Xk2mP9vLqT\n", "connecting with Xk2mP9vLqT", {
		path: ".env",
	});
	// (A secret key with a slash in it is one value: its other occurrence is one placeholder, not two.)
	const aws = r();
	const key = "wJalrXUtnFEMIx/K7MDENGxbPxRfiCYzEXAMPLKEYq";
	aws.learn(`AWS_SECRET_ACCESS_KEY=${key}\n`, { hint: { path: ".env" } });
	assert.equal(aws.redact(`key ${key} end`).findings.length, 1);
	assert.equal(aws.known.size, 1);
	// (Nor is a signature's `abc:<id>`: a `:` in a secret makes no login unless its name says so.)
	const php =
		"$url = 'https://cloud.laravel.com/api/jobs/test-job-id?signature=abc:test-job-id';\n$this->assertSame('test-job-id', $job->id);\n";
	kept(php, "assertSame('test-job-id'");
});

test("a value ends at the settings after it only where their names read as names", () => {
	kept('docker run -e "DB_PASSWORD=Kx9mQ2pLw7vR;Host=db" app', "Host=db");
	for (const pw of ["2FayNFA;jAnr=_@wpj", "ywLhJ&mjW;uKj=JApMnWbN6g"]) {
		hidden(`  password: "${pw}"\n`, pw.split(/[;&]/).pop()!);
		hidden(`      - POSTGRES_PASSWORD=${pw}\n`, pw.split(/[;&]/).pop()!);
	}
});
