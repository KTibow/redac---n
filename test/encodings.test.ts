/**
 * Text that is encoded around a value: JSON escapes, terminal escapes, base64, hex, percent-encoding and invisible
 * characters are read as the text they encode.
 *
 *   node --test test/encodings.test.ts
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { Redactor } from "../src/index.ts";
import { b62, hidden, kept, r } from "./helpers.ts";

test("a known value is hidden in its base64, hex and percent-encoded forms", () => {
	const red = new Redactor({ fingerprintKey: "t", known: ["Wq7mN2vL9xK4"] });
	for (const form of [
		"Wq7mN2vL9xK4",
		Buffer.from("user:Wq7mN2vL9xK4").toString("base64"),
		Buffer.from("Wq7mN2vL9xK4").toString("hex"),
		encodeURIComponent("Wq7mN2vL9xK4"),
	]) {
		assert.ok(!red.redact(`value: ${form}`).text.includes(form), form);
	}
});

test("terminal escapes (colour codes, OSC, CSI, caret notation) around a name or a value do not hide it", () => {
	hidden(JSON.stringify({ out: "\u001b[32mSESSION_SALT\u001b[0m=Xq7Lm2Vb9R\n" }), "Xq7Lm2Vb9R");
	hidden('{"log":"\\u001b[32mAPI_KEY=Zr4Kp9Qx2Lm7Vb3Nw8Ty5Hc\\u001b[0m"}', "Zr4Kp9Qx2Lm7Vb3Nw8Ty5Hc");
	hidden(`\x1b[1mDB_PASSWORD\x1b(B\x1b[m=Winter2024pass`, "Winter2024pass");
	const pw = "Winter2024pass";
	hidden(`\x1b]0;build log\ntoken ghp_${b62(36)}\n`, "ghp_");
	hidden(`\x1b[38:5:196mDB_PASSWORD=${pw}\x1b[0m\n`, pw);
	hidden("\x1b[32mAKIA2QX7RT5LMN3VBW8K\x1b[0mdefault", "\x41KIA2QX7RT5LMN3VBW8K");
	hidden(
		String.raw`{"msg":"using \u001b[32mAKI${"A"}2E0A8F3B244C9986\u001b[0mdefault profile"}`,
		"2E0A8F3B244C9986",
		{},
	);
	kept("test dist::manifest::tests::manifest_serialized_with_sorted_keys ... ^[[32mok^[(B^[[m", "^[[32mok");
	hidden("API_KEY=^[[1mXk9mQ2pLrTvB7nWzQ4cD1aF5eH^[[0m", "Xk9mQ2pLrTvB7nWzQ4cD1aF5eH");
	// A line continuation inside a token joins it: the key read across it stands, not the part before it.
	const tail = b62(26);
	hidden(`TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0ODIxOTMifQ.${b62(20)}\\\n${tail}`, tail);
});

test("JSON escapes around a value or a flag are undone and the output stays valid JSON", () => {
	const pw = "Winter2024pass";
	hidden(JSON.stringify({ content: `\t--password ${pw}` }), pw);
	for (const s of ['x\nCookie: sid=Xq7Lm2Vb9Rt4Np8K"y', 'x\nDB_PASSWORD=Winter2024pass"y']) {
		for (const levels of [2, 3]) {
			let t = s;
			for (let k = 0; k < levels; k++) t = JSON.stringify(t);
			let o: string = r().redact(t).text;
			for (let k = 0; k < levels; k++) o = JSON.parse(o);
			assert.ok(!o.includes("Xq7Lm2Vb9Rt4Np8K") && !o.includes(pw));
		}
	}
	const known = new Redactor({ known: ["nKx82mQpZ7vR"] });
	assert.ok(!known.redact(JSON.stringify({ path: "C:\\nKx82mQpZ7vR\\data" })).text.includes("nKx82mQpZ7vR"));
	hidden("{'stdout': 'connecting...\\nPGPASSWORD=Harbor2291x\\nok\\n', 'returncode': 0}", "Harbor2291x");
	hidden(
		'{"input":{"old_string":"      private_key_passphrase: apple tango glacier juniper delta panda","new_string":"x\\n"}}',
		"apple tango glacier",
	);
	hidden(
		'{"name":"Edit","input":{"file_path":"a.yml","new_string":"  password: gravel orbit fungus tundra"}}',
		"gravel orbit",
	);
});

test("a slash, a tab or a Python repr's quote escaped in a one-line literal is undone where JSON stands around it", () => {
	// PHP's json_encode escapes every slash.
	hidden('{"db":"postgres:\\/\\/app:Kx9mQv2Lp7Rt@db.example.com:5432\\/shop"}', "Kx9mQv2Lp7Rt");
	for (const text of [
		'{"client_secret":"p\\/yeKx9mQv2Lp7RtZz81Xc4Vb"}',
		'{"password": "Kx9m\\/Qv2Lp7Rt\\/Zz81Xc4Vb", "user": "admin"}',
	])
		hidden(text, "Qv2Lp7Rt");
	// (In a sed script in a shell's string, `\/` is the script's delimiter, escaped: the value runs on past it.)
	const sed = 'sed -i "s/^DB_PASSWORD=.*/DB_PASSWORD=a\\/b+Kx9mQv2Lp7Rt==/" .env';
	assert.ok(!new Redactor({ guessing: "off" }).redact(sed).text.includes("Kx9mQv2Lp7Rt"));
	hidden('{"out": "DB_PASSWORD\\tKx9mQv2Lp7Rt"}', "Kx9mQv2Lp7Rt");
	hidden("{'stdout': 'DB_HOST=db\\nDB_PASSWORD=Kx9m\\'Qv2 Lp7Rt\\n', 'returncode': 0}", "Lp7Rt");
});

test("a guessed token is hidden again inside an escaped literal, where it stands without what made it a guess", () => {
	for (const json of ['{"items": "id\\nKx9mQv2Lp7RtZz81Xc4V\\n"}', '{"out": "commit Kx9mQv2Lp7RtZz81Xc4V\\nmerged"}']) {
		const out = r().redact(`using Kx9mQv2Lp7RtZz81Xc4V now\n${json}`).text;
		assert.ok(!out.includes("Kx9mQv2Lp7RtZz81Xc4V"), out);
	}
});

test("base64 is decoded and a secret inside it is hidden, wrapped or not", () => {
	hidden(
		"Authorization: Bearer ey\x4ahbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ey\x4azdWIiOiJ1c2VyLTQ4M\njkiLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3MjAwMDAwMDAsImV4cCI6MTcyMDA4NjQwMH0.Qm9vVHJhc\nFNpZ25hdHVyZVZhbHVlWHl6MTIzNDU2Nzg5MA\n",
		"FNpZ25hdHVyZVZhbHVl",
	);
	hidden(
		`powershell -EncodedCommand ${Buffer.from("$env:PASS='RiverStone88Kite'", "utf16le").toString("base64")}`,
		"JABlAG4AdgA6AFAAQQBTAFMA",
	);
	hidden(
		"echo //5EAEIAXwBQAEEAUwBTAFcATwBSAEQAPQBIAHgANwBtAFEAMgBwAEwAdwA5AHoASwAKAA== | base64 -d",
		"//5EAEIAXwBQAEEAUwBT",
	);
	hidden("send: 'AUTH PLAIN Ym9va2NsdWIubm90aWZ5QGdtYWlsLmNvbTpyYXpuYnN0b2RvdHB3b3Bu'", "Ym9va2NsdWIubm90aWZ5");
	hidden(
		" -> AUTH LOGIN\n<-  334 VXNlcm5hbWU6\n -> b3BzQGV4YW1wbGUuY29t\n<-  334 UGFzc3dvcmQ6\n -> SHg3bVEycEx3OXpL\n<-  235 ok",
		"SHg3bVEycEx3OXpL",
	);
	const env = "STRIPE_SECRET_KEY=sk\x5flive_51Hx7mQ2pLw9RtV3nK8cJ6hF1bY5gZ0dS2aE7u\n";
	const b64 = Buffer.from(`DATABASE_URL=postgres://app:Xk29fLq7Wm3Rt8Zp@db.internal:5432/app\n${env}`).toString(
		"base64",
	);
	hidden(`$ base64 -w 76 secrets.txt\n${b64.replace(/(.{76})/g, "$1\n")}`, b64.slice(-12));
	hidden(`data: ${Buffer.from(`# 設定\n${env}`).toString("base64")}`, "IyDoqK3l");
	const long = Buffer.from(`${"LOG_LEVEL=info\n".repeat(3300)}${env}`).toString("base64");
	assert.equal(r().redact(`$ base64 -w0 app.conf\n${long}`).findings.length, 1);
});

test("base64 is judged as its decoding would be in the clear, its commands and files included", () => {
	const b64 = Buffer.from("$ cat ~/.config/mytool/credentials\nKx9mQ2vL7pZrTq8Wn3Xc4Yb5").toString("base64");
	hidden(`$ echo ${b64} | base64 -d > restore.txt`, b64);
});

test("percent-encoded text is read as the text it encodes, by every layer", () => {
	hidden("password Delta2018&, host x.\npostgresql://ro:Delta2018%26@replica:5432/a", "Delta2018&");
	hidden(
		"curl -s https://api.example.com/shares/nPdnH6Po2QwQCN%2FFuUOTFOcNWuq812wPrdFbSoGqjVdLSAR/content",
		"nPdnH6Po2QwQCN",
	);
	hidden(
		"GET /login?redirect=https%3A%2F%2Fapp.example.com%2Fcb%3Ftoken%3DKx9mQ2vL7pZrTq8Wn3Xc4Yb5%26x%3D1&a=1",
		"Kx9mQ2vL7pZrTq8Wn3Xc4Yb5",
	);
	hidden("q=%7B%22password%22%3A%22Harbor1234x%22%7D", "Harbor1234x");
	hidden("msg=the%20password%20is%20Harbor2291%21%20ok", "Harbor2291");
});

test("invisible format characters inside a key do not hide it", () => {
	for (const [t, v] of [
		[
			`STRIPE_SECRET_KEY=${[..."sk\x5flive_51Hx7mQ2pLw9RtV3nK8cJ6hF1bY5gZ0dS2aE7uV4iO9tN3kM8xW1qP"].join("​")}`,
			"5​1​H",
		],
		// (Every invisible format character: direction marks, bidi controls, variation selectors.)
		[`key: sk\x5flive_51Nx\u200e7mQ2pLw9RtV3nK8cJ6hF1bY5gZ0dS2aE7uV4iO9`, "51Nx"],
		[`aws_access_key_id = AKI\x41J7QX\u202a3MZP5RTWV2KA`, "3MZP5RTWV2KA"],
	])
		hidden(t, v);
});

test("a line of a wrapped base64 blob is not read as one token's base64", () => {
	const blob = Buffer.from(
		JSON.stringify({
			ApplicationId: "e04423e4-7a67-4f9c-b291-99e63c1c2158",
			DeploymentGroupId: "fab9210f-f6c7-4285-aa2d-73760d88176a",
			Key: "xrd::sam.cdws::echoserver::1::.zip",
		}).repeat(3),
	).toString("base64");
	const wrapped = blob.match(/.{1,64}/g)!.join("\n");
	assert.equal(r().redact(`data:\n${wrapped}\n`).text, `data:\n${wrapped}\n`);
});

test("a line that is only base64 of a generated token or a password is hidden, of an ID, an address or a link kept", () => {
	const b64 = (value: string) => Buffer.from(value).toString("base64");
	const line = (value: string) => `$ echo -n "$VALUE" | base64\n${b64(value)}\n`;
	for (const value of ["kR7vQ2mXz9LpW4tN8sB3yH6c", "Liverpool#1892"]) hidden(line(value), b64(value));
	for (const value of [
		"e04423e4-7a67-4f9c-b291-99e63c1c2158",
		"Jane.Doe42@Example.com",
		"https://api.example.com/v1/Users/42",
	])
		kept(line(value), b64(value));
	// (A blob wrapped over lines later in the text leaves the line before it its own.)
	const blob = Buffer.from("LOG_LEVEL=info\nREGION=eu-west-1\n".repeat(6)).toString("base64");
	const later = `$ base64 app.conf\n${blob.match(/.{1,64}/g)!.join("\n")}\n`;
	hidden(line("kR7vQ2mXz9LpW4tN8sB3yH6c") + later, b64("kR7vQ2mXz9LpW4tN8sB3yH6c"));
});

test("base64 of text with tabs, CRLF line ends, another script or UTF-16 big-endian is read as text", () => {
	const encoded = [
		Buffer.from("DB_HOST=db\r\nDB_PASSWORD=Xk29fLq7Wm3R\r\nA=1\r\nB=2\r\n"),
		Buffer.from("machine\tapi.example.com\tlogin\tme\tpassword\tXk29fLq7Wm3Rt8Zp\n"),
		Buffer.from("# データベースの接続設定です\nDB_PASSWORD=Xk29fLq7Wm3R\n"),
		// (Java's `getBytes("UTF-16")`: big-endian, after a byte-order mark.)
		Buffer.concat([Buffer.from([0xfe, 0xff]), Buffer.from("DB_PASSWORD=Xk29fLq7Wm3Rt8Zp", "utf16le").swap16()]),
	].map((b) => b.toString("base64"));
	for (const b64 of encoded) hidden(`data:\n  app.env: ${b64}\n`, b64.slice(-12));
});

test("base64 wrapped in a string literal is read to its last line, which the closing quote ends", () => {
	// (The password is all of the last line, padded or not.)
	for (const password of ["Xk29fLq7Wm3Rt8Zp", "Xk29fLq7Wm3Rt8Zp9"]) {
		const b64 = Buffer.from(`PORT=30000\nNODE_ENV=production\nSMTP_PASSWORD=${password}\n`).toString("base64");
		hidden(`const env = \`${b64.replace(/(.{60})/g, "$1\n")}\`;\n`, b64.slice(60));
	}
});

test("base64 blobs one after another are read apart", () => {
	// (`for f in app.conf .env; do base64 "$f"; done`: the first ends on a full line, padded; the second's first line
	// ends at the password's `=`.)
	const conf = Buffer.from(`${"LOG_LEVEL=info\nREGION=eu-west-1\n".repeat(3)}WORKERS=4\nTZ=UTC\n`).toString("base64");
	const env = Buffer.from(
		"PORT=3000\nNODE_ENV=production\nLOG_LEVEL=info\nDB_PASSWORD=Xk29fLq7Wm3Rt8Zp\nREGION=eu-west-1\n",
	).toString("base64");
	const wrap = (b64: string) => b64.match(/.{1,76}/g)!.join("\n");
	const out = r().redact(`${wrap(conf)}\n${wrap(env)}\n`).text;
	assert.ok(out.startsWith(wrap(conf)) && !out.includes(env.slice(76, 100)), out);
	// (A padded value on one line, `base64 -w0`, wider than the blob's lines.)
	const line = Buffer.from(`${"LOG_LEVEL=info\nREGION=eu-west-1\n".repeat(2)}WORKERS=16\nTZ=UTC\n`).toString("base64");
	const after = r().redact(`${line}\n${wrap(env)}\n`).text;
	assert.ok(after.startsWith(line) && !after.includes(env.slice(76, 100)), after);
});

test("a pair's escaped quotes inside a JSON string stay around its hidden value", () => {
	kept('{"cmd": "PGPASSWORD=\\"Xk9mQ2pLrT\\" psql -h db"}', 'PGPASSWORD=\\"[REDACTED');
});
