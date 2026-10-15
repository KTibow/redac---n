/**
 * Values under credential names: env, JSON, header and query syntaxes, calls that take a secret, sibling pairs,
 * tables, cells and attributes, and which names are settings, PINs or credentials.
 *
 *   node --test test/names.test.ts
 *
 * (A fake key's vendor prefix is written with an escape, `"ghp\x5f…"`: written whole, the repository would hold text
 * that secret scanners, GitHub's push protection among them, take for a live key.)
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { Redactor } from "../src/index.ts";
import { bip39 } from "../src/named.ts";
import { isPinName, isSettingName, isVendorClient, nameClass, phraseBefore, readPhrase } from "../src/names.ts";
import { sqlCells } from "../src/sql.ts";
import {
	attributes,
	continuesToken,
	delimitedCells,
	escapedLineStart,
	isContraction,
	isEscapedBreak,
	PAIR_NAME,
	pipeCells,
	siblingName,
	stringEnd,
	withoutUnopenedClosers,
} from "../src/syntax.ts";
import { b62, hidden, kept, r } from "./helpers.ts";
import { assertLinear } from "./timing.ts";

test("an HMAC call's key is read by its callee, in either case", () => {
	for (const call of ["hmac.new", "HMAC.new", "hmac.digest"])
		hidden(`h = ${call}("Winter2026!Harbor", msg, digestmod=SHA256)`, "Winter2026!Harbor");
	hidden(`h = OpenSSL::HMAC.hexdigest("SHA256", "Winter2026!Harbor", data)`, "Winter2026!Harbor");
	hidden(`crypto.createHmac("sha256", "Winter2026!Harbor")`, "Winter2026!Harbor");
	kept(`h = HMAC.hexdigest("SHA256", key, "plain message text")`, "plain message text");
});

test("a balanced bracket at the end of a value is the value's own", () => {
	assert.equal(withoutUnopenedClosers("p)q(r)"), "p)q(r)");
	assert.equal(withoutUnopenedClosers("a(b))"), "a(b)");
	assert.equal(withoutUnopenedClosers("a(b]"), "a(b");
	assert.equal(withoutUnopenedClosers("foo}"), "foo");
	assert.equal(withoutUnopenedClosers("x)]", ")"), "x)]");
	hidden("The password is Kx7)q(mQ2)", "mQ2)");
	hidden("The password is Kx7)q(mQ2)", "Kx7");
});

test("NAME and VALUE sibling pairs are read in any case", () => {
	assert.ok(PAIR_NAME.test("NAME") && PAIR_NAME.test("Name") && PAIR_NAME.test("parameterkey"));
	const secret = `Tq${b62(14)}9!`;
	hidden(`{"NAME": "DB_PASSWORD", "VALUE": "${secret}"}`, secret);
});

test("a sibling pair's value is read before a comment", () => {
	hidden(`set {\n  name  = "smtp.auth.password"\n  value = "sunshine99" # set by CI\n}`, "sunshine99");
	hidden(`[{ name: "DB_PASSWORD", value: "sunshine99"// prod\n}]`, "sunshine99");
});

test("attributes: where a value ends, and what can follow one", () => {
	const read = (text: string) => [...attributes(text)].map((a) => [a.key, a.value.value]);
	assert.deepEqual(read("metadata:\n  name: api-key\n"), [["name", "api-key"]]);
	assert.deepEqual(read(`value = "x" # set by CI`), [["value", "x"]]);
	assert.deepEqual(read(`value: "x"// prod`), [["value", "x"]]);
	assert.deepEqual(read(`value: x # rotated`), [["value", "x"]]);
	assert.deepEqual(read(`value = "abc" + suffix`), []);
	assert.deepEqual(read(`, "label": "unclosed`), []);
	assert.deepEqual(read("password: ${DB_PASSWORD}"), []);
	assert.deepEqual(read(`Name: prod/db/password`), [["Name", "prod/db/password"]]);
	assert.deepEqual(read(`<input name=password value=abc/>`), [
		["name", "password"],
		["value", "abc"],
	]);
	assert.deepEqual(read(`<input value=abc />`), [["value", "abc"]]);
});

test("a sibling name: quoted in either quote, a name's shape, a line of its own", () => {
	assert.equal(siblingName(`{'name': 'api_key', 'value': '`), "api_key");
	assert.equal(siblingName(`{"label": "Work laptop", "value": "`), undefined);
	assert.equal(siblingName("  - name: API_KEY", { alone: true }), "API_KEY");
	assert.equal(siblingName("name: web, port: 80", { alone: true }), undefined);
});

test("string ends, escapes, contractions and token edges", () => {
	assert.equal(stringEnd('"abc\n"', 0), -1);
	assert.equal(stringEnd('"abc\n"', 0, { multiline: true }), 5);
	// (An escaped backslash before `n` is a backslash and a letter: `C:\\nginx` in JSON.)
	assert.ok(continuesToken(String.raw`"C:\\nginx"`, 5));
	assert.ok(!continuesToken(String.raw`"a\nb"`, 3));
	assert.ok(continuesToken("my-wifi-pass", 2, true) && !continuesToken("my-wifi-pass", 2));
	assert.ok(!isEscapedBreak(String.raw`"C:\\new"`, 4));
	assert.ok(!isEscapedBreak('"x = 1\\n",\n', 6));
	assert.ok(isEscapedBreak('{"a": "b\\nc"}', 8));
	assert.equal(escapedLineStart('{"a": "b\\nc"}', 10), 10);
	assert.ok(isContraction("it's", 2));
	assert.ok(!isContraction("re.compile(r'd+')", 12));
	assert.ok(!isContraction("WITH PASSWORD = N'Kx9mQ2'", 17));
});

test("table cells: an escaped bar, a line without bars, a doubled quote", () => {
	assert.deepEqual(
		pipeCells(String.raw`| a\|b | c |`).map((c) => c.text),
		[String.raw`a\|b`, "c"],
	);
	assert.deepEqual(pipeCells("mysql> SELECT 1;"), [{ text: "mysql> SELECT 1;", start: 0, end: 16 }]);
	assert.deepEqual(
		delimitedCells('"say ""hi""",x', ",").map((c) => c.text),
		['say "hi"', "x"],
	);
});

test("a password's own ! and ? stay in it, and its noun reaches across a long sentence", () => {
	hidden("the password for the db Xk9mPq2&Rt7vLw4!", "Rt7vLw4");
	assert.ok(
		r().redact("the password for the db Xk9mPq2&Rt7vLw4!").text.endsWith("]"),
		"the trailing ! is the password's",
	);
	hidden(
		"The database admin password for the production cluster used by the billing team in region eu-west-1 is Xk9mPq2&Rt7vLw4",
		"Xk9mPq2&Rt7vLw4",
	);
	assert.equal(bip39().get("abandon"), 0);
	assert.equal(bip39().size, 2048);
});

test("one-character column names, and a column of passwords under a bare header", () => {
	hidden("A  B  PASSWORD\n1  2  Zq8!kLm3Vw", "Zq8!kLm3Vw");
	hidden("id,name,password\n1,ann,Zq8!kLm3Vw", "Zq8!kLm3Vw");
});

test("a bare number is judged by one alternative", () => {
	kept("PORT=8080", "8080");
	kept("RATIO_KEY=1.5e3", "1.5e3");
});

test("values longer than the read bound are hidden whole", () => {
	const long = b62(5000);
	const cases = [
		`The password is ${long}.`,
		`the database password is ${long}.`,
		`Das Passwort des Dienstes lautet ${long}.`,
		`login admin / ${long}`,
		`DB_PASSWORD=\n${long}\n`,
		`requirepass ${long}`,
		`password ........ ${long}`,
		`userinfo=bob:${long}`,
		`**Password:** ${long}`,
		`| Password | ${long} |`,
		`rotate the passwd (${long}) before Friday`,
		`<table><tr><th>password</th><td>${long.slice(0, 2500)}</td></tr></table>`,
		`mot de passe: ${long}`,
		`DB_PASSWORD='${long}`,
	];
	for (const text of cases) {
		const out = r().redact(text).text;
		assert.ok(
			!out.includes(long.slice(100, 140)) && !out.includes(long.slice(-40)),
			`leaked from ${text.slice(0, 40)}`,
		);
	}
});

test("a cell is judged as what it holds, and a row of backticks is read once", () => {
	assert.equal(pipeCells("| **Name** and **Value** | x |")[0].text, "**Name** and **Value**");
	assert.equal(pipeCells("| **Name** | `a|b` |")[0].text, "Name");
	assert.equal(pipeCells("| **Name** | `a|b` |")[1].text, "a|b");
	assert.equal(pipeCells("|" + "`".repeat(80000) + "|").length, 1);
	assertLinear("a row of backticks", (n) => pipeCells("|" + "`".repeat(n) + "|"), 40_000);
	assert.deepEqual(
		delimitedCells('a,"b,c",d', ",").map((c) => c.text),
		["a", "b,c", "d"],
	);
	const [row1] = [...sqlCells(`INSERT INTO t ("a,b", password) VALUES ('x', 'y');`)];
	assert.equal(row1.column, "a,b");
});

test("attribute keys, contractions, astral letters and long lines", () => {
	assert.equal([...attributes("STRIPE_WEBHOOK_SIGNING_SECRET: whsec_x")][0]?.key, "STRIPE_WEBHOOK_SIGNING_SECRET");
	assert.equal("HERE'S DON’T it's".replace(/(?<=[A-Za-z])['’](?=(?:s|t|ll|re|ve|d|m)\b)/gi, ""), "HERES DONT its");
	assert.ok(continuesToken("x\u{1D400}y", 1) && continuesToken("x\u{1D400}y", 2));
	assertLinear("a long line after an escaped break", (n) => r().redact('{"a":"b\\n' + "x".repeat(n)), 250_000);
});

test("rows after a comment between rows are read", () => {
	const rows = (t: string) => [...sqlCells(t)].map((c) => c.value.text);
	assert.deepEqual(rows("INSERT INTO u (name, pw) VALUES ('b', 'p1'), -- next\n ('al', 'p2');"), [
		"'b'",
		"'p1'",
		"'al'",
		"'p2'",
	]);
	assert.deepEqual(rows("INSERT INTO u (name, pw) VALUES ('b', 'p1'),\n/* more */ ('al', 'p2')"), [
		"'b'",
		"'p1'",
		"'al'",
		"'p2'",
	]);
});

test("a dump cut short inside a row has the rows before it read", () => {
	const cut = "INSERT INTO users (name, password) VALUES ('alice', 'Kx9mQ2pLrTvB7nWz'), ('bob', 'Tq8v";
	assert.deepEqual(
		[...sqlCells(cut)].map((c) => c.value.text),
		["'alice'", "'Kx9mQ2pLrTvB7nWz'"],
	);
	hidden(cut, "Kx9mQ2pLrTvB7nWz");
});

test("a call between two contractions is read, a prefixed string isn't one", () => {
	hidden(`It's odd: set_password(user, "hunter2xyz") isn't called`, "hunter2xyz");
	hidden(`pattern = re.compile(r'd+'); set_password(user, "plugh7xyzzy")`, "plugh7xyzzy");
});

test("string pieces are joined however short each is", () => {
	hidden(`pw = "hunter" + "2" + "xyz"\ndb.connect(password=pw)`, "xyz");
});

test("an item of a list is named by the list", () => {
	const keys = [b62(40), b62(40), b62(40)];
	for (const k of keys) hidden(`api_keys:\n${keys.map((x) => `  - ${x}`).join("\n")}\n`, k);
	for (const k of keys) hidden(`{"api_keys": [\n${keys.map((x) => `  "${x}"`).join(",\n")}\n]}`, k);
});

test("a password that only holds a credential's word, or a placeholder word at its end, is a password", () => {
	hidden("POSTGRES_PASSWORD: verde_dev_pw", "verde_dev_pw");
	hidden("password=Zr8Q2mXkeyhere", "Zr8Q2mXkeyhere");
	hidden("postgres://app:SUMMER_2024@db.internal/app", "SUMMER_2024");
	kept("password=YourKeyHere", "YourKeyHere");
	kept("DB_PASSWORD=${DB_PASSWORD}", "DB_PASSWORD");
});

test("a client's own name, not a substring of it, is its positional key", () => {
	const key = b62(20);
	hidden(`const p = new Pusher({ e: "${key}" });`, key);
});

test("every credential word opens the rules that read sentences, columns and comparisons", () => {
	hidden("the wifi psk is Zk8#mQ2vLp9x", "Zk8#mQ2vLp9x");
	hidden("The <b>Authorization</b> is <b>Summer2024!x</b>.", "Summer2024!x");
	hidden("user,pw,host\nalice,Tq7#mPx2Lw9z,db1\n", "Tq7#mPx2Lw9z");
	hidden('if subtle.ConstantTimeCompare([]byte(password), []byte("Gx7#kQ2mVp9z")) == 1 {', "Gx7#kQ2mVp9z");
	hidden("wifi: guest / Walnut.thistle.44", "Walnut.thistle.44");
	hidden("env: {API_TOKEN: aB3&cD4eF5gH6iJ7}", "aB3&cD4eF5gH6iJ7");
	hidden('db, err := sql.Open("pgx", "host=db user=app password=Pq8#vLm2Zx7k dbname=app")', "Pq8#vLm2Zx7k");
});

test("a title or a password store's command is no name and value", () => {
	kept("$ pass\nPassword Store\n└── email", "Store");
	kept("$ pass init\n", "init");
});

test("a value under a credential name is hidden in env, JSON, command-line and call syntaxes", () => {
	hidden("DB_PASSWORD=hunter22", "hunter22");
	hidden('{"client_secret": "x8Kq2mN7vL4pR9tZ"}', "x8Kq2mN7vL4pR9tZ");
	hidden("mysql -u root -p'Wint3r!Sky' -h db", "Wint3r!Sky");
	hidden("curl -u admin:S3cr3t-Pa55 https://api", "S3cr3t-Pa55");
	hidden(`define('DB_PASSWORD', 'wP-Pr0d-db!pass');`, "wP-Pr0d-db!pass");
	hidden(`cfg.setPassword("Tr0ub4dor&3x");`, "Tr0ub4dor&3x");
});

test("a setting that merely mentions a credential word keeps its value", () => {
	kept("PASSWORD_MIN_LENGTH=12", "12");
	kept("TOKEN_URL=https://auth.example.com/oauth/token", "https://auth.example.com/oauth/token");
	kept('"LABEL_NEW_PASSWORD": "New password"', "New password");
});

test("a value holding = is hidden whole", () => {
	const k = b62(32);
	hidden(`  client_secret:     ${k}=`, k);
	hidden(`db_password:     Summer=Bay77`, "Summer=");
});

test("a block scalar and a name/value pair on separate lines are read as named values", () => {
	const pw = "Winter2024pass";
	hidden(`password: |\n  ${pw}\n`, pw);
	hidden("- name: DB_PASSWORD\n  value: correcthorse", "correcthorse");
});

test("a credential word inside a longer variable name still names a credential", () => {
	const k = b62(32);
	hidden(`DB_PW_PROD=Summer!Bay77`, "Summer!Bay77");
	hidden(`DB_PASSWORD_PROD=correcthorse7`, "correcthorse7");
	hidden(`export TOKEN=${k}`, k);
	hidden(`PAGE_ACCESS_TOKEN=${k}`, k);
});

test("a PIN and a passphrase under their names are hidden", () => {
	hidden("pin: 4821", "4821");
	hidden("PASSPHRASE=salt and pepper Xq7 vinegar", "pepper Xq7");
});

test("a setting beside a token keeps its value", () => {
	kept(
		"PULUMI_ACCESS_TOKEN=pul\x2de9a369532a38ce2862ab430d86eba7f87ae167f6\nPASSWORD_MIN_LENGTH=14\n",
		"PASSWORD_MIN_LENGTH=14",
	);
});

test("text after an env value on the same line is kept", () => {
	kept("password=Zr9Kx2Vm7Lt4Pq8N token ghp\x5fAb1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab12 then more", "then more");
});

test("a dotted word passphrase under password: is hidden", () => {
	hidden("password: gecko.robin.sunset.crystal.granite.kayak", "gecko.robin.sunset");
});

test("a short quoted value under pass: is hidden", () => {
	hidden("    pass: 'aybi'", "aybi");
});

test("a default inside a variable reference is a password", () => {
	hidden("    password: ${DB_PASSWORD:claims_dev_2024}", "claims_dev_2024");
});

test("a random key under a mobile deployment name is hidden", () => {
	hidden("CODEPUSH_KEY_ANDROID=n_v6vpyTsyIL3oYW14pq6oZTAyebEkl_p5B9", "n_v6vpyTsyIL3oYW14pq6oZTAyebEkl_p5B9");
});

test("a weak password is hidden under a name, in a default and in a sentence", () => {
	for (const t of [
		"DB_PASSWORD=x83920175",
		"ROOT_PASSWORD=Des2024",
		"password: ${DB_PASSWORD:-Plumb3rs}",
		"smtp:\n  user: mailer\n  pass: dragonfly",
		"Hasło jest Zx81mKq2",
		"The guest wifi password (84719263) changes monthly.",
	])
		hidden(t, t.match(/x83920175|Des2024|Plumb3rs|dragonfly|Zx81mKq2|84719263/)![0]);
});

test("a quoted password starting with * is hidden", () => {
	hidden('  password: "*Kitt3n9x"', "*Kitt3n9x");
});

test("PROXY_PASS and a dotted word password are hidden by name", () => {
	for (const [t, v] of [
		["DB_PASSWORD=Company.Password1", "Company.Password1"],
		["PROXY_PASS=Hunter2Prod!x", "Hunter2Prod!x"],
	])
		hidden(t, v);
});

test("a value is hidden whole when it starts with a symbol or holds a colon", () => {
	for (const [t, v, hint] of [
		["LICENSE_KEY=VKXQR-8B2MP-7WJ4T-QH9CD-3FY6K", "VKXQR-8B2MP"],
		["DB_PASSWORD=%silver2024", "silver2024"],
		['{"password": "$summer2024"}', "summer2024"],
		["ADMIN_PASSWORD=pR7kQ2mX9vL4nB8w:Ht6Jc3Fz1Gd5Ks0Ya2Ue", "pR7kQ2mX9vL4"],
	] as [string, string, { command?: string }?][])
		hidden(t, v, hint);
});

test("#+letters is a selector only when it reads as one", () => {
	hidden("DB_PASSWORD=#AssvKlk", "AssvKlk");
	kept("password: #lPass", "#lPass");
});

test("code's shapes in a literal context are the password: brackets, dots and a leading colon", () => {
	for (const v of [
		"Harbor[2291]",
		"Summer(2024)",
		":Harbor2291",
		"spring.Boot2024",
		"jaguar.Heavy.aware",
		"token.Magic144",
		"minimum.Rapid1164",
	])
		hidden(`DB_PASSWORD=${v}`, v);
	hidden("[db]\npassword = Planet(685)", "Planet(685)");
});

test("pass before a value is a password", () => {
	for (const line of ['char pass[] = "WILLwv60a6%";', "wifi pass: Harbor2291", "?user=bob&pass=Harbor2291"])
		hidden(line, line.match(/WILLwv60a6%|Harbor2291/)![0]);
	hidden("pass: drowssap", "drowssap");
});

test("trimming takes syntax only: a password's own first and last characters stay in it", () => {
	for (const v of ["Kx9mQ2vL7pZr)", ":Kx9mQ2vL7pZr", "Kx9mQ2vL7pZr;", "Kx9mQ2vL7pZr}"]) {
		const out = r().redact(`DB_PASSWORD=${v}`).text;
		assert.equal(out.replace(/\[REDACTED [^\]]+\]/, ""), "DB_PASSWORD=", v);
	}
});

test("pass after a thing is a label for the value after it", () => {
	for (const line of ["Redis pass: Kx9mQ2vL7pZr", "Jenkins pass: Kx9mQ2vL7pZr", "His pass: Kx9mQ2vL7pZr"])
		hidden(line, "Kx9mQ2vL7pZr");
});

test("a password in any script is a password", () => {
	for (const line of ["DB_PASSWORD=Солнце2024!", '{"password": "密码2024!"}', 'password: "Ωμέγα2024!"'])
		hidden(line, line.match(/Солнце2024!|密码2024!|Ωμέγα2024!/)![0]);
});

test("names whose structure says identifier keep their value", () => {
	for (const [line, v] of [
		['{"children": [{"_key": "c313f56be08e0"}]}', "c313f56be08e0"],
		['"tags":{"tagKey000003":"tagVal000004"}', "tagVal000004"],
		['{"streamSid": "MZ18ad3ab5a668481ce02b83e7395059f0"}', "MZ18ad3ab5a668481ce02b83e7395059f0"],
		["Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==", "dGhlIHNhbXBsZSBub25jZQ=="],
		["Image pull secrets:  sa-build-webhook-realworld-dockercfg-4qz9g", "sa-build-webhook-realworld-dockercfg-4qz9g"],
	])
		kept(line, v);
});

test("a credential's own name with a number is still a credential", () => {
	for (const line of [
		'apiKey123: "Kx9mQ2vL7pZrTq8Wn3Xc4Yb5"',
		"connectSid=Kx9mQ2vL7pZrTq8Wn3Xc4Yb5",
		"GITHUB_TOKEN2024=Kx9mQ2vL7pZrTq8Wn3Xc4Yb5",
		"IMAGE_PULL_SECRET=Kx9mQ2vL7pZrTq8Wn3Xc4Yb5",
	])
		hidden(line, "Kx9mQ2vL7pZrTq8Wn3Xc4Yb5");
});

test("non-Latin passwords in a sentence, with brackets, in three runs are hidden", () => {
	for (const [line, v] of [
		["初期パスワードはさくら3594@に設定しました", "さくら3594@"],
		["DB_PASSWORD=Солнце(3501)!", "Солнце(3501)!"],
		["DB_PASSWORD=Зима1240Солнце#Луна", "Зима1240Солнце#Луна"],
		["sapisid=Tiger7148!zy", "Tiger7148!zy"],
	])
		hidden(line, v);
});

test("an @ before a password is part of it", () => {
	for (const line of ["set DB_PASSWORD=@Harbor2291", "Please update the password to @Harbor2291x before Monday"])
		hidden(line, "Harbor2291");
});

test("a value's last backslash joins no lines", () => {
	hidden("DATA_DIR=C:\\data\\\nDB_PASSWORD=Harbor2291!x", "Harbor2291!x");
	// (A Windows path with a space, a share's, a variable's or a relative one: a word with another backslash in it.)
	for (const path of ["C:\\Program Files\\App\\", "\\\\fileserver\\share\\", "%ProgramData%\\app\\", ".\\src\\"])
		hidden(`INSTALL_DIR=${path}\nDB_PASSWORD=Xk29fLmq81Zt\nLOG=1\n`, "Xk29fLmq81Zt");
	// (A token wrapped with a backslash at a line's end is still joined.)
	hidden("TOKEN=ghp\x5fZ2r9Kq4Lm7Pw1Xv8Bt\\\n3Nc6Hd0Jf5Ys2Ge9Ua\n", "3Nc6Hd0Jf5Ys2Ge9Ua");
});

test("a quantity yields to a password's name", () => {
	hidden("password: 1337x", "1337x");
});

test("a credential's word first names whose it is, at any length", () => {
	for (const name of ["PASSWORD_DB", "TOKEN_GITHUB_CI", "PASSWORD_ROOT_MYSQL", "PASSWORD_SERVER"])
		hidden(`${name}=Harbor2291x`, "Harbor2291x");
});

test("a credential word with a limit or a manager is a setting", () => {
	for (const name of ["TOKEN_LIMIT", "PASSWORD_POLICY", "SECRET_MANAGER"]) kept(`${name}=strict-mode`, "strict-mode");
});

test("the words before a bare generic name are a phrase, not a log line's pair", () => {
	hidden("level=info msg=hello token=Kx9mQv2Lp7Rt", "Kx9mQv2Lp7Rt");
});

test("a password's word leading a name makes any word its value", () => {
	hidden("PASSWORD_DB=Zebra-Lamp-Cloud", "Zebra-Lamp-Cloud");
});

test("a capitalised passphrase is one", () => {
	hidden("DB_PASSWORD=Correct horse battery staple", "battery staple");
});

test("a long value is hidden whole in every syntax: no reader's bound leaves its tail", () => {
	// Quoted and line-bound values are read to their quote or bracket however long; an unquoted one cut where its
	// reader stops runs on to its word's end. (Past 256 characters the random layer doesn't look: the readers must.)
	const where: ((v: string) => string)[] = [
		(v) => `DB_PASSWORD=${v}`,
		(v) => `password: "${v}"`,
		(v) => JSON.stringify({ password: v }),
		(v) => `password = '${v}'`,
		(v) => `#define API_SECRET "${v}"`,
		(v) => `client = Client(api_key="${v}", timeout=3)`,
		(v) => `cfg.setPassword("${v}");`,
		(v) => `ENV DB_PASSWORD "${v}"`,
		(v) => `SECRET = """${v}"""`,
		(v) => `<password>${v}</password>`,
		(v) => `<input type="password" value="${v}">`,
		(v) => `user:${v}@tcp(db:3306)/app`,
		(v) => `: PSK "${v}"`,
		(v) => `const key = process.env.API_KEY ?? "${v}";`,
		(v) => `INSERT INTO users (name, password) VALUES ('a', '${v}');`,
		(v) => `mysql -uroot -p${v} app`,
		(v) => `Authorization: Bearer ${v}`,
	];
	for (const n of [300, 1200, 5000]) {
		const v = b62(n);
		for (const f of where) {
			const out = r().redact(f(v)).text;
			for (let i = 0; i + 16 <= n; i += 8)
				assert.ok(!out.includes(v.slice(i, i + 16)), `${n} characters in ${JSON.stringify(f("…"))}: leaked from ${i}`);
		}
	}
});

test("a logfmt line's values run to a blank, and the comma after a value stays", () => {
	assert.match(
		r().redact("level=info user=export_firma, passwort=COBAlyrxgo%, knownHosts=/etc/ssh").text,
		/passwort=\[REDACTED [^\]]+\], knownHosts/,
	);
	hidden("level=info msg=login user=admin password=Kx9m&Qv2,Lp7 host=db", "Qv2,Lp7");
});

test("a Bearer token in an Authorization header is hidden", () => {
	const tok = b62(32);
	hidden(`curl -H "Authorization: Bearer ${tok}" https://api`, tok);
});

test("a credential in an Authorization or Cookie header is hidden", () => {
	const pw = "Winter2024pass";
	hidden(
		"curl -H 'Authorization: ApiKey WHE3TG0yVmI5UjpXbjRUcDhLejJRYTVIcw==' https://es:9200",
		"WHE3TG0yVmI5UjpXbjRUcDhLejJRYTVIcw==",
	);
	hidden(`curl -H 'Cookie: theme=dark; _myapp=${pw}'`, pw);
});

test("a connection string's Password, braced or plain, and an ipsec PSK are hidden whole", () => {
	hidden(`Server=db;Database=x;User Id=sa;Password=Wi&nter2024pass;`, "nter2024pass");
	hidden("Server=h;Database=db;Uid=sa;Pwd={Win;ter2024};", "Win;ter2024");
	hidden('%any 10.0.0.1 : PSK "Xq7Lm2Vb9Rt4Np8K"', "Xq7Lm2Vb9Rt4Np8K");
});

test("an haproxy stats auth pair is hidden", () => {
	hidden("    stats auth admin:SIERwafssj!\n", "SIERwafssj!");
});

test("a YAML name and value on separate lines are read as a pair", () => {
	hidden(
		"  - key: RESEND_API_KEY\n    scope: RUN_TIME\n    value: Xq7Lm2Vb9Rt4Np8KwZ3cAbQx\n",
		"Xq7Lm2Vb9Rt4Np8KwZ3cAbQx",
	);
});

test("a Bearer value is hidden after a tab escape or as bare hex", () => {
	hidden('{"Authorization": "\\tBearer Xq7Lm2Vb9Rt4Np8KwZ3c"}', "Xq7Lm2Vb9Rt4Np8KwZ3c");
	hidden('curl -H "Authorization: Bearer 7F3A9C2E4B1D8F6A0C5E3B9D7A2F4C1E" https://x', "7F3A9C2E4B1D8F6A0C5E");
});

test("an Android string resource is hidden under a secret name and kept under a public key name", () => {
	hidden('    <string name="naver_client_secret" translatable="false">J1iHvBFRtp</string>', "J1iHvBFRtp");
	kept(
		'    <string name="kakao_native_app_key" translatable="false">4a6232c3491755dc3f0d14fb664ac71c</string>',
		"4a6232c3491755dc3f0d14fb664ac71c",
	);
});

test("a value named by a form's nested field or a properties file's entry key is hidden", () => {
	const v = "Zk8mQ2pL9vRt4Hx";
	for (const t of [
		`<input type="text" name="user[password]" value="${v}">`,
		`<input name="data[User][password]" value="${v}">`,
		`user%5Bemail%5D=a%40b.io&user%5Bpassword%5D=${v}&commit=Sign+in`,
		`GET /login?next=%2Fhome&user%5bpassword%5d=${v} HTTP/1.1`,
		`<properties>\n<entry key="db.password">${v}</entry>\n<entry key="db.user">app</entry>\n</properties>`,
		`<entry key='smtp.password'>${v}</entry>`,
	])
		hidden(t, v);
	// (A name that only ends with a bracket is no form's field.)
	kept('<entry key="db.url">jdbc:postgresql://db/app</entry>', "jdbc:postgresql://db/app");
	kept(
		"auth_token [env: TAP_GITHUB_AUTH_TOKEN] x\nrepos [env: TAP_GITHUB_REPOSITORIES] current value: ['acme/dbt', 'acme/dags']",
		"['acme/dbt', 'acme/dags']",
	);
});

test("a keystore password in a path-like name is hidden", () => {
	hidden('keystore/release_password="spring.kilo2389"', "spring.kilo2389");
});

test("a value under a vendor's own field name or in a query parameter is hidden", () => {
	hidden("║ RAILS_MASTER_KEY       │ cc2c46110fe3da2a0885b47c21b2e2ea          ║", "cc2c46110fe3da2a0885b47c21b2e2ea");
	hidden(
		"cookie        XSRF-TOKEN=abc; harbor_session=3xhngChJUUx3Tmir+179fDbICDt0+SE2aPW8tgajv6Izngkz",
		"3xhngChJUUx3Tmir",
	);
	hidden(
		"https://api.openweathermap.org/data/2.5/weather?q=Lisbon&appid=2ccccbfc5a83859dfc3a267a3bdc5f1b",
		"2ccccbfc5a83859dfc3a267a3bdc5f1b",
	);
	hidden('"Value": "\x38ab832ff74a3322b44420c9229641854-5429640c-b96fe9a9",', "8ab832ff74a3322b44420c9229641854");
	hidden("featureflags.sdkKey=\x73dk-c2b62cac-7097-4840-af1a-e27c38b83f59", "c2b62cac-7097-4840-af1a");
});

test("an nginx header directive's quoted pair is read as a name and its value", () => {
	hidden('proxy_set_header "X-Api-Key" "Xk9mQ2vL8nRt4Wz7Pq3s";', "Xk9mQ2vL8nRt4Wz7Pq3s");
});

test("a password in an INI section is hidden", () => {
	hidden("[client]\npassword = PurpleRain1984", "PurpleRain1984");
	for (const [t, v] of [
		["[mysqld]\nuser = mysql\npassword = c@I|wr=vsY6h[", "c@I|wr=vsY6h["],
		["[admin]\nadmin_passwd = correct horse battery 42", "correct horse battery 42"],
	])
		hidden(t, v);
});

test("tokens in a YAML list under a credential key are hidden", () => {
	hidden(
		"auth:\n  tokens:\n  # rotated monthly\n  - X1AmNsYrAsPFlY1NKDWo7NhyaxA3DzcKJJmOFqyP\n  - Hf7vT2kLp9RxN4wZ8bYc3HdF6gJ1sA5eUiKoP0qW\n",
		"Hf7vT2kLp9RxN4wZ8bYc3HdF6gJ1sA5eUiKoP0qW",
	);
});

test("a routing key is hidden when random and kept when it is a name", () => {
	hidden("+      - routing_key: \x36d8b2a05344a61274f75f5f4495edf9c", "6d8b2a05344a61274f75f5f4495edf9c");
	kept("set exchange routing_key: orders.created", "orders.created");
});

test("a signature constant is hidden", () => {
	hidden(
		"const orbitSig: string = '84bdb6da1a02f71796ace45bc1f0d58ee6b800e8608929d9428ee8c5c3f2ee92';",
		"84bdb6da1a02f71796ace45bc1f0d58ee6b800e8608929d9428ee8c5c3f2ee92",
	);
});

test("a secret query parameter is hidden and its appid kept", () => {
	kept(
		"$ curl -s 'https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=wx8c13fda63650f4d9&secret=c2f58c974c3e6a6681a6e45f99dd2f51'",
		"wx8c13fda63650f4d9",
	);
	hidden(
		"$ curl -s 'https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=wx8c13fda63650f4d9&secret=c2f58c974c3e6a6681a6e45f99dd2f51'",
		"c2f58c974c3e6a6681a6e45f99dd2f51",
	);
});

test("a prefix setting and a request id are kept", () => {
	kept("     2\tIONOS_API_PREFIX=810393c438fb3eafcad939da8f717f07", "810393c438fb3eafcad939da8f717f07");
	kept(
		"'x-amzn-requestid': 'K3HuzkS1QQLUfn6HY7aotbQL4kEfr2BeWrsUVbGjUXKNJlNwgvne'",
		"K3HuzkS1QQLUfn6HY7aotbQL4kEfr2BeWrsUVbGjUXKNJlNwgvne",
	);
});

test("a registry value and a search admin key are hidden by name", () => {
	hidden('"DefaultUserName"="kiosk"\n"DefaultPassword"="Tango2001#"', "Tango2001#");
	hidden(
		'const config = {\n  appId: "LX8QZ3K2PA",\n  adminApiKey: "9f3c2a7b1e4d6f8a0b5c3e7d2a9f1b4c",\n  indexName: "products",\n};',
		"9f3c2a7b1e4d6f8a0b5c3e7d2a9f1b4c",
	);
});

test("a session id is kept when it is a UUID and hidden when random, and a secret id is hidden", () => {
	hidden('{"session_id": "4V1vhyM2VBV5LABGVJcoMMjokqLRsN3QI2z7BOcM"}', "4V1vhyM2VBV5LABGVJcoMMjokqLRsN3QI2z7BOcM");
	kept(
		'{"cwd":"/home/x","sessionId":"2d07ad0e-f8e6-481b-97d4-1094a497810f","version":"1"}',
		"2d07ad0e-f8e6-481b-97d4-1094a497810f",
	);
	kept("TERM_SESSION_ID=05eac46b-b73a-4bb6-bd8e-b2f69b8f1e22", "05eac46b-b73a-4bb6-bd8e-b2f69b8f1e22");
	hidden("VAULT_SECRET_ID=6a174c20-f6de-a53c-74d2-6018fcceff64", "6a174c20-f6de-a53c-74d2-6018fcceff64");
});

test("a cookie named in prose is hidden", () => {
	hidden("The HTTP cookie for this consent is user_session=9f3b4a8e2d8f11; Path=/; HttpOnly;", "9f3b4a8e2d8f11");
});

test("a deleted session cookie is kept", () => {
	const t = "Set-Cookie: session=deleted; Path=/; Max-Age=0";
	assert.equal(r().redact(t).text, t);
});

test("a key:secret pair hides the secret half and keeps the key half", () => {
	hidden("    credential: ae261dfb1b28ff8b:e6de4ecbb5d4a721f0b7a7238bcef3fd", "e6de4ecbb5d4");
	kept("    credential: ae261dfb1b28ff8b:e6de4ecbb5d4a721f0b7a7238bcef3fd", "ae261dfb1b28ff8b");
	kept("     5\t    credential: ae261dfb1b28ff8b:[REDACTED credential #3b8282]", "ae261dfb1b28ff8b");
});

test("a Kubernetes env list with plain settings is kept", () => {
	const t = "  - name: LOG_LEVEL\n    value: debug\n  - name: DB_HOST\n    value: Harbor2291x.internal";
	assert.equal(r().redact(t).text, t);
});

test("an INSERT's values are read under their columns", () => {
	hidden(
		"INSERT INTO users (email, password) VALUES ('ann@x.io', 'Harbor2291!'), ('bob@x.io', 'Copper7781#x');",
		"Copper7781#x",
	);
	kept("INSERT INTO users (email, password) VALUES ('ann@x.io', 'Harbor2291!');", "ann@x.io");
});

test("a server's challenge holds no client secret, but a credential header after it does", () => {
	kept(
		'WWW-Authenticate: Bearer authorization="https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47", resource="https://vault.azure.net"',
		"72f988bf-86f1-41af-91ab-2d7cd011db47",
	);
	kept(
		'WWW-Authenticate: Digest realm="x", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093"',
		"dcd98b7102dd2f0e8b11d0f600bfb0c093",
	);
	hidden(
		"{'WWW-Authenticate': 'Bearer realm=\"x\"', 'Authorization': 'Bearer Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te8S'}",
		"Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te8S",
	);
});

test("a challenge's echoed token is hidden, and an SSID is kept", () => {
	hidden(
		'WWW-Authenticate: Bearer realm="api", error="invalid_token", error_description="token 7eBcsJVPkbfTuLi4YynYovFVyr08l7if9V2WkT0t expired"',
		"7eBcsJVPkbfTuLi4YynYovFVyr08l7if9V2WkT0t",
	);
	kept("ssid=HomeNetwork42", "HomeNetwork42");
});

test("a DSL's name 'value' call hides the value", () => {
	hidden("  bind_password 'Kx9mQv2Lp7Rt', # c", "Kx9mQv2Lp7Rt");
});

test("a framework's session cookies are credentials, a terminal's or desktop's session is a setting", () => {
	for (const name of ["laravel_session", "_myapp_session", "ASP.NET_SessionId", "_gh_sess"])
		hidden(`${name}=3f9a1c7e5b2d4f60a8e7c6b5d4f3a2b1`, "3f9a1c7e5b2d4f60a8e7c6b5d4f3a2b1");
	kept("DESKTOP_SESSION=ubuntu-wayland", "ubuntu-wayland");
	kept("tmux_session=3f9a1c7e5b2d4f60", "3f9a1c7e5b2d4f60");
	hidden("grafana_session=eaf67610a7b9912362b539141e5e4011", "eaf67610a7b9912362b539141e5e4011");
});

test("a PIN's name is one predicate everywhere", () => {
	for (const line of ["PIN_CODE=4821", 'pinCode: "4821"', "PASSCODE=4821", "The pin is 4821."]) hidden(line, "4821");
	kept("GPIO_PIN=21", "21");
});

test("a numbered pin is a PIN by its name, so a board's pin under one is kept", () => {
	for (const line of [
		"substitutions:\n  light_platform: rp2040_pwm\n  pin1: GPIO2\n  pin2: GPIO3\n",
		"substitutions:\n  i2s_din_pin1: GPIO33\n  i2s_din_pin2: GPIO34\n",
	])
		kept(line, line);
	hidden("door_pin2: 482193", "482193");
	hidden("pin1=7391", "7391");
});

test("a call on a shell's token sets no credential; a setter of one does", () => {
	kept('    assert ninja_helper.shell_token("-DMASK=(1<<3)") == _q("-DMASK=(1<<3)")', "-DMASK=(1<<3)");
	hidden('client.withToken("Kx9mQ2vLp7Rt3Wz8nB5c");', "Kx9mQ2vLp7Rt3Wz8nB5c");
	hidden('cfg.setPassword("Tr0ub4dor&3x");', "Tr0ub4dor&3x");
});

test("a value a test names after a placeholder's words is a stand-in, read past its separators and quotes", () => {
	for (const [line, value] of [
		['yaml_content = """key1: value1 # inline comment\nkey2: value2"""', "value2"],
		['        set_env({"DICT": "key1=1,key2=2"})', "key1=1,key2=2"],
		["2. To use it as string, quote the value: key='value1,value2'", "value1,value2"],
		["    'custom_token=value123'", "value123"],
	])
		kept(line, value);
	hidden("api_key = 'value9Kx2mQ'", "value9Kx2mQ");
	hidden("key2: Kx9mQ2vLp7,Rt3Wz8", "Kx9mQ2vLp7,Rt3Wz8");
});

test("a plural setting word is a setting too: a password's policies are no password", () => {
	kept("passwordPolicies: ['DisablePasswordExpiration', 'DisableStrongPassword'],", "DisablePasswordExpiration");
	kept("passwordPolicies: 'DisablePasswordExpiration,DisableStrongPassword',", "DisableStrongPassword");
	hidden("passwordProfile: { password: 'Kx9!mQ2vLp7' },", "Kx9!mQ2vLp7");
});

test("a device's published default PIN is kept, anywhere else a PIN is hidden", () => {
	kept("The default Bluetooth PIN is 0000 (some use 1234).", "0000");
	hidden("pin_value=0000", "0000");
	hidden("My PIN is 4821.", "4821");
	// (One called a default but not a published one: a bank's or a router's label's own PIN.)
	hidden("Your default PIN is 4821.", "4821");
});

test("a lock, alarm or door code is a PIN name, a block or clock code is not", () => {
	for (const name of ["LOCK_CODE", "lockcode", "ACCESSCODE", "alarm_code", "doorcode", "SECURITY_CODE"])
		assert.ok(isPinName(name), name);
	assert.ok(!isPinName("block_code") && !isPinName("clock_code") && !isPinName("blockcode"));
});

test("a vendor client's name matches whole, in any case, never by prefix", () => {
	for (const name of ["Twilio", "TWILIO", "twilio.Client", "algoliasearch", "MailgunClient", "new Pusher", "mapboxgl"])
		assert.ok(isVendorClient(name), name);
	for (const name of ["imgurian", "twiliosomething", "Tw", "pusherman"]) assert.ok(!isVendorClient(name), name);
	hidden('TWILIO("4f9c2b7a1e8d3f6a0b5c9e2d7a1f4b8c")', "4f9c2b7a1e8d3f6a0b5c9e2d7a1f4b8c");
});

test("a name is a setting when it names a host, tenant, client id or timezone, not a paid or valid token", () => {
	assert.ok(!isSettingName("PAID") && !isSettingName("MY_TOKEN_VALID"));
	for (const name of ["HOSTNAME", "TENANT_ID", "clientId", "DBHOST", "TZ", "SSH_AUTH_SOCK"])
		assert.ok(isSettingName(name), name);
});

test("a French credential name is a credential", () => {
	assert.equal(nameClass("mot_de_passe_prod"), "credential");
	assert.equal(nameClass("mot_de_passe"), "credential");
});

test("a file's path names the file; a Secret's key file names the key", () => {
	assert.equal(nameClass("lib/pin.rb"), "neutral");
	assert.equal(nameClass("manifests/pin.pp"), "neutral");
	assert.equal(nameClass("pin.txt"), "credential");
	assert.equal(nameClass("master.key"), "credential");
});

test("the phrase before a name is read word by word", () => {
	assert.deepEqual(phraseBefore("Ingrese su contraseña ", 3), ["Ingrese", "su", "contraseña"]);
	// (Not from inside a pair's value: `portal` of `id=web-portal` is no word before `secret`.)
	assert.deepEqual(phraseBefore("id=web-portal ", 2), []);
	assert.deepEqual(phraseBefore("the search-only ", 2), ["search", "only"]);
	hidden(
		"client registration: id=web-portal secret=Ap07QKFzylBs6qeRKd2mfcBW5EeAh9Fsu3b5pxOZ tokenUri=https://sso.example/token",
		"Ap07QKFzylBs6qeRKd2mfcBW5EeAh9Fsu3b5pxOZ",
	);
});

test("a trailing comment is no evidence that a positional SDK key is public", () => {
	const key = "7f3c9a1e8b2d4f6a0c5e9b7d3a1f8e2c";
	hidden(`const admin = algoliasearch("APPID", "${key}"); // public docs`, key);
	kept(
		`// search-only key: safe in the browser\nexport const searchClient = algoliasearch('0OAZG8IZTI', '${key}')`,
		key,
	);
});

test("a password's name written as a phrase is a password's name", () => {
	for (const text of ['mot_de_passe = "sunshine"', "MOT_DE_PASSE_PROD=sunshine", "palavra_passe: sunshine"])
		hidden(text, "sunshine");
});

test("words ending in a credential word are a passphrase, unless written as a label", () => {
	hidden('passphrase: "purple monkey dishwasher secret"', "purple monkey");
	hidden('password: "blue falcon pin"', "blue falcon");
	kept('emailServerPassword: "Email password (app-specific password recommended)"', "Email password");
	kept('label: "Current password"', "Current password");
});

test("a password that is the user's name is a default in every syntax", () => {
	kept("POSTGRES_USER=app\nPOSTGRES_PASSWORD=app", "PASSWORD=app");
	kept(
		"env:\n  - name: POSTGRES_USER\n    value: app\n  - name: POSTGRES_PASSWORD\n    value: app",
		"value: app\n  - name: POSTGRES_PASSWORD\n    value: app",
	);
	kept("POSTGRES_USER: appdb\nPOSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-appdb}", ":-appdb}");
	hidden("POSTGRES_USER=app\nPOSTGRES_PASSWORD=Xk9mQv2Lp7", "Xk9mQv2Lp7");
});

test("a reference's default is read after its operator", () => {
	const out = r().redact("DB_PASSWORD: ${DB_PASSWORD:-Xk9mQ2vLp7}").text;
	assert.ok(out.includes(":-[REDACTED") && !out.includes("Xk9mQ2vLp7"), out);
});

test("every dialect's insert statement is read as rows", () => {
	const rows = (t: string) => [...sqlCells(t)].map((c) => `${c.table}.${c.column}=${c.value.text}`);
	assert.deepEqual(rows('INSERT IGNORE INTO users (name, password) VALUES ("a", "p1");'), [
		'users.name="a"',
		'users.password="p1"',
	]);
	assert.deepEqual(rows("INSERT OR REPLACE INTO users (password) VALUES (2)"), ["users.password=2"]);
	assert.deepEqual(rows("REPLACE INTO `app`.`users` (password) VALUES (3)"), ["users.password=3"]);
	assert.deepEqual(rows('INSERT INTO "my t" (password) VALUES (4)'), ["my t.password=4"]);
	assert.deepEqual(rows("insert into [dbo].[Users] ([Password]) values (5)"), ["Users.Password=5"]);
	assert.deepEqual(rows("COPY public.users (id, password) FROM stdin;\n1\tKx9\n2\t\\N\n\\.\n"), [
		"users.id=1",
		"users.password=Kx9",
		"users.id=2",
		"users.password=\\N",
	]);
	// (The string a value gives its column, through SQL's prefixes, casts and functions.)
	const literals = (t: string) => [...sqlCells(t)].map((c) => c.value.literal?.value);
	assert.deepEqual(literals("INSERT INTO t (a, c, d) VALUES (N'x1', 'x3'::text, md5('x4'))"), ["x1", "x3", "x4"]);
	assert.deepEqual(literals("INSERT INTO t (a, b) VALUES (now(), 'x'||'y')"), [undefined, undefined]);
});

test("a reference, a lookup's name or a stand-in under a password's name is no password", () => {
	const off = new Redactor({ guessing: "off", fingerprintKey: "test" });
	for (const [text, kept] of [
		['[smtp]\nuser = "resend"\npass = "env(RESEND_API_KEY)"', "env(RESEND_API_KEY)"],
		["DATABASE_URL: '%env(resolve:DB_URL)%'", "%env(resolve:DB_URL)%"],
		['    pw = Secret.load("clickhouse-loader-password").get()', "clickhouse-loader-password"],
		["vendor=nextcloud user=kendra pass=--obscured-by-rclone--", "--obscured-by-rclone--"],
		["password: [obscured]", "[obscured]"],
		["password: **hidden**", "**hidden**"],
	])
		assert.ok(off.redact(text).text.includes(kept), text);
	hidden('pw = SecretStr("Hx7mQ2pL9vRt4")', "Hx7mQ2pL9vRt4");
});

test("code, a store's path or a setting is no credential's value", () => {
	const off = new Redactor({ guessing: "off", fingerprintKey: "test" });
	for (const [text, value] of [
		[
			"argument_spec=dict(\n    password_expire_warn=dict(type='int', no_log=False),\n)",
			"dict(type='int', no_log=False)",
		],
		["DB_PASSWORD=getpass('Password: ')", "getpass('Password: ')"],
		["if self.update_password == 'always' and self.password:", "always"],
		["password_mechanism=sshpass", "sshpass"],
		['{Contents: `{{ with secret "kv-v2/data/app" }}{{ .Data.data.password }}{{ end }}`}', "kv-v2/data/app"],
		["both anonymously and via a username and password [GH-975]", "GH-975"],
		["format of the key (DER/PEM/P12); has no effect", "DER/PEM/P12"],
		["pub fn find(pwd: &Path, file: &str)", "&Path"],
		["res.append('Set-Cookie', 'fizz=buzz')", "fizz=buzz"],
		[
			"        password, the authorization server MUST protect the endpoint against\n        brute force attacks (e.g., using rate-limitation",
			"brute force",
		],
		["    environment:\n      - PASSWORD_FILE_PATH=/run/secrets/db-password\n      - DB_HOST=db", "DB_HOST=db"],
	])
		assert.ok(off.redact(text).text.includes(value), text);
	for (const [text, value] of [
		["DB_PASSWORD=Tiger(6859)", "Tiger(6859)"],
		['command:\n  - "--requirepass"\n  - "Hx7mQ2pL9vRt"', "Hx7mQ2pL9vRt"],
		[
			"Name\tWert\tDomain\tPfad\tLäuft ab / Max. Alter\nJSESSIONID\tC25F5ED6367A45DE471ACDE182108D96\tshop.example\t/\tSitzung",
			"C25F5ED6367A45DE471ACDE182108D96",
		],
	])
		assert.ok(!off.redact(text).text.includes(value), text);
});

test("a pair is data after a blank, in a query string or an option's comma list, in quotes, after an env flag", () => {
	for (const [text, pw] of [
		["mount -t cifs //nas/share /mnt -o username=alice,password=sunshine", "sunshine"],
		["sshfs -o user=alice,password=sunshine nas:/ /mnt", "sunshine"],
		["http://rt.example.org/Ticket/Display.html?id=2900&user=guest&pass=bcrtg", "bcrtg"],
		["Set `DB_PASSWORD=sunshine` in your .env", "sunshine"],
		['args: ["password=sunshine", "--verbose"]', "sunshine"],
		["out=$(docker run -e db_password=sunshine postgres)", "sunshine"],
		["if [[ $PASSWORD == sunshine ]]; then", "sunshine"],
	])
		hidden(text, pw);
	// (An env value is a shell word, its commas its own.)
	hidden("heroku config:set DB_PASSWORD=Xk9m,Q2pLrT", "Q2pLrT");
	// (A connection string's next key is no part of a placeholder.)
	kept("Data Source=db;User ID=app;password=PASSWORD;Initial Catalog=test", "PASSWORD;Initial");
});

test("code's own pairs stay: a sigil's variable, a quoted name, a call's argument, a declaration's list", () => {
	for (const [text, value] of [
		["$DB_PASSWORD=sunshine;", "sunshine"],
		['SELECT id FROM users WHERE "password"=sunshine', "sunshine"],
		["env=dict(os.environ, PGPASSWORD=sunshine)", "sunshine"],
		["let user=a,password=input", "input"],
	])
		kept(text, value);
});

test("under an INI section, code is still code: a call's entries, a variable, a statement's later pair, a call", () => {
	for (const [text, value] of [
		['[database]\nhost = db\n\nconn = connect(\n    password=DbPass2024,\n    user="app",\n)', "DbPass2024,"],
		["[server]\n$password=sunshine;\n", "sunshine"],
		["[server]\nx = 1; password = sunshine\n", "sunshine"],
		["[server]\npassword = kdf(pw, salt)\n", "kdf(pw, salt)"],
	])
		kept(text, value);
});

test("a name in backticks is a Markdown label or a SQL column; glued to a path, a command substitution", () => {
	hidden("- `password`: `Kx9mQv2Lp7Rt`", "Kx9mQv2Lp7Rt");
	hidden("`token`: Summer2024!x", "Summer2024!x");
	hidden("UPDATE users SET `password` = 'Sunshine99!' WHERE id = 1", "Sunshine99!");
	kept("docker run -v `pwd`:/workspace -w /workspace node:20", "`pwd`:/workspace");
	// (A quoted key glued to its value is a key; an unquoted one, a namespace among others.)
	hidden('{"password":Kx9mQ2pLrT}', "Kx9mQ2pLrT");
	kept("redis keys: session:abc, token:x9f8e7d6c5b4", "x9f8e7d6c5b4");
});

test("a spaced pair's value is none when it is an operator, a member or a store's command, and whole otherwise", () => {
	for (const [text, value] of [
		["LoginField.PASSWORD -> input.text", "input.text"],
		["password .length > 8", ".length"],
		["pass init", "init"],
	])
		kept(text, value);
	for (const [text, pw] of [
		["requirepass [K9#mQ2!pL]", "K9#mQ2!pL"],
		["passwd sunshine!", "sunshine!"],
		["Username Bob\nPassword Sunshine!", "Sunshine!"],
		["login bob\npass Summer", "Summer"],
		["login bob\npass qzwxv", "qzwxv"],
		["password Summer Breeze 2024", "Summer Breeze"],
	])
		hidden(text, pw);
	// (A notebook's last source line is a JSON string without its `\n`.)
	hidden('{"cells": [{"source": [\n    "import redis\\n",\n    "requirepass Kx9mQ2pLrT"\n]}]}', "Kx9mQ2pLrT");
});

test("a password in parentheses after its name is hidden whole, and a word after it ends it", () => {
	assert.match(r().redact("Created user bob (password: sunshine!)").text, /\(password: \[REDACTED[^\]]*\]\)$/);
	hidden("Rotated it (token: Xk9mQ2pLrT88 expires soon)", "Xk9mQ2pLrT88");
});

test("a value with brackets is a password unless a call's whole: an unnatural callee, more after the call", () => {
	hidden("DB_PASSWORD=Kx9q(mQ2L)", "Kx9q(mQ2L)");
	hidden("DB_PASSWORD=Winter(Sun)2024!", "Winter(Sun)2024!");
	kept('password = pw.decode("ascii")', '"ascii"');
});

test("an env line's value is its first word when a command follows, and a YAML line's runs to the end", () => {
	kept("PASSWORD=sunshine && npm start", "&& npm start");
	hidden("DB_PASSWORD=Xk9mQ2pLrT && mysql", "Xk9mQ2pLrT");
	kept("PASSWORD=Sunshine99 FOO=bar ./run.sh", "FOO=bar ./run.sh");
	kept("PASSWORD=sunshine release 3f9a8b7c6d5e4f3a2b1c", "release 3f9a8b7c6d5e4f3a2b1c");
	hidden("password: tr0ub4dor & 3horse", "3horse");
});

test("a block of several lines is hidden whole unless each line is a template, a placeholder or code", () => {
	kept("secret: |\n  {{ .Values.a }}\n  {{ .Values.b }}\n", "{{ .Values.b }}");
	kept("token: |\n  TODO\n  TODO\n", "TODO");
	kept('password = <<EOT\nimport os\nos.getenv("PW")\nEOT', "os.getenv");
	kept("secret: |\n  stored in vault\n", "stored in vault");
	hidden("password: |\n  Kx9mQ2pLrT\n  Vb7nW3qZsY\n", "Vb7nW3qZsY");
});

test("a reference's default under a key's name is judged as any value is, digits or not", () => {
	hidden("${API_KEY:Kx#mQ!pLzz}", "Kx#mQ!pLzz");
	hidden("${JWT_SECRET:Kx#mQ!pL}", "Kx#mQ!pL");
	hidden("${SECRET_KEY:Kx9mQ2pLrTzz}", "Kx9mQ2pLrTzz");
	for (const value of ["86400000", "changeme", "abc1234", "localhost"]) kept(`\${API_KEY:${value}}`, value);
});

test("a sibling pair's value is read under any value key, past the block's other attributes, to its comment", () => {
	hidden("- name: DB_PASSWORD\n  data: Kx9mQ2vL7p!", "Kx9mQ2vL7p!");
	hidden("- key: api_key\n  val: Kx9mQ2vL7pRt4Nw8", "Kx9mQ2vL7pRt4Nw8");
	// (Only the name and value attributes are a pair's: a description, a flag and a tier between them aren't neighbours.)
	const off = new Redactor({ guessing: "off", fingerprintKey: "test" });
	for (const t of [
		'resource "aws_ssm_parameter" "db" {\n  name        = "db_password"\n  description = "Database password"\n  overwrite   = true\n  tier        = "Standard"\n  value       = "Kx9mQ2vL7p!"\n}',
		"- name: DB_PASSWORD\n  description: Database password for the app\n  sensitive: true\n  required: true\n  value: Kx9mQ2vL7p!",
	])
		assert.ok(!off.redact(t).text.includes("Kx9mQ2vL7p!"), t);
	// (A YAML line is read as yaml.ts reads it: its comment isn't the value's.)
	kept("- name: DB_PASSWORD\n  value: Kx9mQ2vL7p! # rotate monthly", "# rotate monthly");
	hidden('<input class="form-control" type="text" name="password"\n  value="Kx9mQ2vL7p!">', "Kx9mQ2vL7p!");
});

test("a sibling pair is one block's: a value less indented than its name, or a form's other input, isn't its", () => {
	// (grep's lines from two files: the value is another block's.)
	kept(
		'k8s/base/deployment.yaml:41:            - name: DB_PASSWORD\nk8s/overlays/dev/flags.yaml:12:          value: "release-2024"\n',
		"release-2024",
	);
	// (OAuth's password grant names a grant type, not a credential.)
	kept(
		'<form><input type="hidden" name="grant_type" value="password"><input type="hidden" name="client_id" value="web-app-prod"></form>',
		"web-app-prod",
	);
});

test("a Gradle project property is read as a Java system property is", () => {
	hidden("gradle publish -Psigning.password=Kx9mQ2vL7p!", "Kx9mQ2vL7p!");
});

test("an Authorization value is judged by its credential; a scheme's word before more words is prose", () => {
	hidden('AUTH_TOKEN="Bearer Xk9mQ2vL8nRt4Wz7Pq3sYb5"', "Xk9mQ2vL8nRt4Wz7Pq3sYb5");
	hidden("accessToken: 'Bearer Xk9mQ2vL8nRt4Wz7Pq3sYb5'", "Xk9mQ2vL8nRt4Wz7Pq3sYb5");
	kept(
		"        Request MUST be sent as a Bearer Token, per OAuth 2.0\n        Bearer Token Usage [RFC6750].\n",
		"Token Usage [RFC6750].",
	);
});

test("a password made of its own name is one, markup around the name a placeholder, a class under it code", () => {
	hidden('password = "password1!"', "password1!");
	hidden("password: password@123", "password@123");
	kept("password: password...", "password...");
	kept('DB_PASSWORD="${DB_PASSWORD:?}"', "${DB_PASSWORD:?}");
	kept("        widgets = {'password': PasswordInput}", "PasswordInput");
	kept("var password = PasswordHasher", "PasswordHasher");
	// (Accents and a symbol make a password, not a translated label; a salt in digits is a setting.)
	hidden('DB_PASSWORD="café olé&99"', "café olé&99");
	kept("PASSWORD_SALT=847362910564738291", "847362910564738291");
	// (A JSON value starts as JSON does; a password in brackets doesn't.)
	hidden("DB_PASSWORD='[1qaz@WSX]'", "1qaz@WSX");
	hidden("DB_PASSWORD='[bZ0{6tfzE&n2q:]'", "bZ0{6tfzE&n2q:");
	hidden("password: fjqx-vbnm", "fjqx-vbnm");
	kept("results:\n  pass: 1,024\n  fail: 3\n", "1,024");
});

test("an ID and a secret under one name: the ID stays when it is a name, an email or words", () => {
	const token = "Xk9mQ2vL8nRt4Wz7Pq3sYb5";
	for (const [text, id] of [
		[`DAGSTER_CLOUD_API_TOKEN=deployment-agent:${token}`, "deployment-agent:"],
		[`API_CREDENTIALS=svc_x7k2q9@m3x.io:${token}`, "svc_x7k2q9@m3x.io:"],
	]) {
		const out = r().redact(text).text;
		assert.ok(out.includes(id) && !out.includes(token), out);
	}
	// (A random ID is part of the key, hidden with it; a cache key and words after a colon are no pair.)
	assert.match(r().redact('API_KEY="Xk9mQ2vL8nRt4Wz7Pq:Ht6JbN3cV8xZ1aS5dF"').text, /^API_KEY="\[REDACTED key #\w+\]"$/);
	kept('"key": "users:9f8e7d6c5b4a39281706f5e4d3c2b1a0"', "users:9f8e7d6c5b4a39281706f5e4d3c2b1a0");
	kept('api_key: "billing:monthly-invoice-report"', "billing:monthly-invoice-report");
});

test("a hash among words, numbers or names is a content address; a token with a hash beside it is a token", () => {
	const off = new Redactor({ guessing: "off", fingerprintKey: "test" });
	for (const value of ["objects/12/9f8e7d6c5b4a39281706f5e4d3c2b1a0.json", "objects/9f8e7d6c5b4a39281706f5e4d3c2b1a0"])
		kept(`artifact_key: "${value}"`, value);
	for (const text of [
		"API_TOKEN=tk7q-9f8e7d6c5b4a39281706f5e4d3c2b1a0",
		"API_TOKEN=qWxZkLmBtR-9f8e7d6c5b4a39281706f5e4d3c2b1a0",
	])
		assert.ok(!off.redact(text).text.includes("9f8e7d6c5b4a"), text);
	// Under a bare `key`: an object key of names (an S3 one), not a key in base64.
	kept('{"Bucket": "acme", "Key": "exports/2024/Q3"}', "exports/2024/Q3");
	kept('"key": "apis/v1beta1/Namespaces"', "apis/v1beta1/Namespaces");
	hidden('"key": "GbeaKB/qGmA9X/Hk3Lm"', "GbeaKB/qGmA9X/Hk3Lm");
});

test("a constant's name under a dictionary key is no key, its acronyms read apart", () => {
	const text = "2024-01-02 12:00:00 Config: brandKey=KSBrandID, regionKey=USWestRegion";
	kept(text, "brandKey=KSBrandID");
	kept(text, "regionKey=USWestRegion");
	hidden('apiKey: "zvCadApKxYVYHo"', "zvCadApKxYVYHo");
	kept("level-seed=superflatworldgenerationseedvalue", "superflatworldgenerationseedvalue");
});

test("words, symbols and random letters under a key's name are read by what they make", () => {
	for (const [text, value] of [
		['api_secret: "!@#Winter$%^Harbor&*("', "!@#Winter$%^Harbor&*("],
		['secret_key: ")AM{?NfoSuFiMi.s"', ")AM{?NfoSuFiMi.s"],
		['jwt_secret: "orangeBANANAapple"', "orangeBANANAapple"],
		["api_key: 4f9c2a1b8e7d-4c3b-a2f19e8d7c6b-5a4f1a2b3c4d-77", "4f9c2a1b8e7d-4c3b-a2f19e8d7c6b"],
		['client_secret: "Kodaripefulamesoti"', "Kodaripefulamesoti"],
		["hmacKey=Xylophonequartzjumping", "Xylophonequartzjumping"],
		// (Words in a password rule's classes are a password, not a name.)
		["encryptionKey=WinterHarbor2024", "WinterHarbor2024"],
	])
		hidden(text, value);
	const off = new Redactor({ guessing: "off", fingerprintKey: "test" });
	assert.ok(!off.redact('"token": "kWZHhSeBwKLiwfKSCZeJmelQ"').text.includes("kWZHhSeBwKLiwfKSCZeJmelQ"));
	for (const [text, value] of [
		[
			'FIELDS = {"access_key": "AccessKeyId", "secret_key": "SecretAccessKey", "session_token": "SessionToken"}',
			'"AccessKeyId"',
		],
		['"key": "release2024candidate"', "release2024candidate"],
		['token: "os.Getenv(\\"API_TOKEN_V2\\")"', 'os.Getenv(\\"API_TOKEN_V2\\")'],
		['                # Prefix in your App ID.\n                "key": "UVNBQTBNJOALLA",', "UVNBQTBNJOALLA"],
	])
		kept(text, value);
});

test("a value is read to its own end: triple quotes, escapes, a template's braces, a comment", () => {
	const triple = r().redact("password = '''Hx7mQ2pL9vRt'''").text;
	assert.match(triple, /^password = '''\[REDACTED password #\w+\]'''$/);
	hidden("PASSWORD=\\$Hx7mQ2pL9vRt", "Hx7mQ2pL9vRt");
	hidden("const s = 'login(password=\\'Hx7mQ2pL9vRt\\')';", "Hx7mQ2pL9vRt");
	const escaped = r().redact("PASSWORD=Hx7mQ2pL9vRt\\nNEXT_VAR=1").text;
	assert.ok(!escaped.includes("Hx7mQ2pL9vRt") && escaped.endsWith("\\nNEXT_VAR=1"), escaped);
	const comment = r().redact("DB_PASSWORD=Kx9mQ2vL8nRt  # rotated monthly").text;
	assert.ok(!comment.includes("Kx9mQ2vL8nRt") && comment.endsWith("  # rotated monthly"), comment);
	// (A template's expression is the value's, blanks, pipes and quotes in it: a path, not a fragment of one.)
	for (const value of ["/etc/certs/v2/{{ .Values.keyFile }}", '/etc/certs/{{ .Values.keyFile | default "tls.key" }}'])
		kept(`            - --key=${value} --cert=/etc/certs/tls.crt`, value);
	const flags = r().redact("--key=/etc/certs/v2/{{ .Values.keyFile }} --password=Hx7mQ2pL9vRt").text;
	assert.ok(flags.includes("/etc/certs/v2/{{ .Values.keyFile }}") && !flags.includes("Hx7mQ2pL9vRt"), flags);
});

test("the text around a value: phrases beside it, a URL's words, a row's other columns", () => {
	hidden(
		"title: Welcome to the admin console\nsubtitle: Please sign in with your account\nfooter: Copyright Acme Corp all rights reserved\npassword: correct horse battery 42\n",
		"correct horse battery 42",
	);
	const url = r().redact("password: https://example.com/reset/Xk9mQ2vL8nRt4Wz7Pq3sYb5Hx").text;
	assert.ok(url.includes("https://example.com/reset/") && !url.includes("Xk9mQ2vL8nRt4Wz7"), url);
	const row = r().redact(
		"INSERT INTO users (id, email, password) VALUES ('Xk9mQ2vL8nRt4Wz7Pq3s', 'ann@x.io', 'Hx7mQ2pL9vRt');",
	).text;
	assert.ok(row.includes("'Xk9mQ2vL8nRt4Wz7Pq3s'") && !row.includes("Hx7mQ2pL9vRt"), row);
	kept("INSERT INTO users (name, password) VALUES ('ann', 'changeme');", "'changeme'");
});

test("an operator glued to its value, a quoted name and a code entry are read by their syntax", () => {
	assert.ok(!r().redact("spring.datasource.password==Hx7mQ2pL9vRt").text.includes("=="));
	kept("assert DB_PASSWORD==expected_password", "==expected_password");
	kept('"password"=Hx7mQ2pL9vRt "host"=db.internal', '"host"=db.internal');
	kept('[db]\n"password" = Hx7mQ2pL9vRt ; rotated\n', "; rotated");
	// A YAML value runs to its line's end, brackets balanced or not; a code entry's ends before its comma.
	assert.ok(!r().redact("user:\n  password: Hx7(mQ2)pL9,\n").text.includes(","));
	assert.ok(!r().redact("user:\n  password: Kx9(mQ2]vL8),\n").text.includes("),"));
	assert.ok(r().redact("login({\n  password: Hx7mQ2-pL9vRt,\n})").text.endsWith("],\n})"));
	kept("  password: Secret<String>;", "Secret<String>");
});

test("a public word, a browser prefix or an SDK's public key's name makes a key's name public; a secret's word decides", () => {
	for (const name of [
		"MIXPANEL_TOKEN_PROD",
		"applicationServerKey",
		"SHOPIFY_PUBLISHABLE_TOKEN",
		"MEDUSA_PUBLISHABLE_API_KEY",
		"SSH_PUBKEY",
		"peer_publickey",
		"VAPID_KEY",
		"PUB_KEY",
		"pubKey",
	])
		assert.equal(nameClass(name), "public", name);
	// (Not a name with a secret's, a private half's or another credential's word than a key's, a token only a browser
	// prefix calls public, nor a public word before another word: `SITE_COOKIE` is a site's cookie, `PUB_SUB_KEY` a
	// Pub/Sub key.)
	for (const name of [
		"TLS_CLIENT_KEY",
		"VITE_MNEMONIC",
		"VITE_SENTRY_AUTH",
		"NEXT_PUBLIC_SANITY_TOKEN",
		"SITE_COOKIE",
		"SITE_DB_KEY",
		"PUB_SUB_KEY",
	])
		assert.equal(nameClass(name), "credential", name);
	assert.equal(nameClass("SITE_URL"), "identifier");
	const key = b62(32);
	kept(`MEDUSA_PUBLISHABLE_API_KEY=${key}`, key);
	kept(`VAPID_KEY=${key}`, key);
	hidden(`TLS_CLIENT_KEY=${key}`, key);
	hidden(`SITE_COOKIE=${key}`, key);
	hidden(`VITE_SENTRY_AUTH=${key}`, key);
	hidden(
		"VITE_MNEMONIC=abandon ability able about above absent absorb abstract absurd abuse access accident",
		"absorb abstract",
	);
});

test("a name's own words say hash, ID, flag, pattern or setting before its credential's word does", () => {
	for (const [name, cls] of [
		["isPrivate", "neutral"],
		["private", "neutral"],
		["file_md5", "hash"],
		["blake3", "hash"],
		["COMMIT_ID", "hash"],
		["TRACE_ID", "hash"],
		["TOKEN_AUDIENCE", "neutral"],
		["NOPASSWORD", "neutral"],
		["INVALID_API_KEY", "neutral"],
		["DATE_PAT", "neutral"],
		["GITHUB_PAT", "credential"],
		["PD_ROUTING_KEY", "credential"],
	])
		assert.equal(nameClass(name), cls, name);
	// (An audience is a client's ID; PagerDuty's routing key is its Events API credential; `PAT` after a forge is a token.)
	const off = new Redactor({ guessing: "off", fingerprintKey: "test" });
	assert.ok(off.redact("TOKEN_AUDIENCE=0oa4kq1x2bZ9Q7mT5d7").text.includes("0oa4kq1x2bZ9Q7mT5d7"));
	assert.ok(!off.redact("PD_ROUTING_KEY=R03e8f1c2b7d4a9e6f0c5b8d2a7e4f1c").text.includes("R03e8f1c2b7d"));
	assert.ok(!off.redact("ADO_PAT=q7mt2vx9pl4wr8nk3cj6hf1by5gz0ds2ae7uv4io9tn3km8xw1qp").text.includes("q7mt2vx9pl4w"));
	kept('DATE_PAT = r"\\d{4}-\\d{2}-\\d{2}"', "\\d{4}-\\d{2}-\\d{2}");
});

test("a route or screen word marks a lookup key or UI text, not a secret or a full credential phrase", () => {
	for (const [name, cls] of [
		["ROUTE_KEY", "neutral"],
		["LOGIN_PAGE_PASSWORD", "neutral"],
		["LOGIN_PAGE_APP_PASSWORD", "neutral"],
		["PAGE_ACCESS_TOKEN", "credential"],
		["EVENT_SECRET", "credential"],
		["WEBHOOK_EVENT_SECRET", "credential"],
	])
		assert.equal(nameClass(name), cls, name);
	kept('const EVENT_KEY = "evt_1Nq9xY2eZvKYlo2C";', "evt_1Nq9xY2eZvKYlo2C");
	hidden("EVENT_SECRET=hunter22", "hunter22");
});

test("an about word that names a component, a word between it and the password's, leaves the name a password's", () => {
	for (const name of [
		"LABEL_STUDIO_PASSWORD",
		"EVENT_STORE_PASSWORD",
		"MESSAGE_BROKER_PASSWORD",
		"STATUS_DB_PASSWORD",
		"HELP_DESK_PASSWORD",
		"VNC_VIEW_ONLY_PASSWORD",
		"MATCH_PASSWORD",
		"MATCH_KEYCHAIN_PASSWORD",
	]) {
		assert.equal(nameClass(name), "credential", name);
		hidden(`      - ${name}=Tr0ub4dor&3x\n`, "Tr0ub4dor&3x");
	}
	hidden('export MATCH_PASSWORD="Harbor2291xq"', "Harbor2291xq");
	// (Next to the password's word, or with qualifiers between, they still mark UI text, errors and flags.)
	for (const name of [
		"LABEL_NEW_PASSWORD",
		"LOGIN_PAGE_PASSWORD",
		"ERROR_WRONG_PASSWORD",
		"HAS_DB_PASSWORD",
		"RESET_PASSWORD",
	])
		assert.equal(nameClass(name), "neutral", name);
	kept('"MATCH_PASSWORD": "Passwords must match"', "Passwords must match");
	kept('"LABEL_USER_PASSWORD": "User password"', "User password");
});

test("a password's word written as two words, or glued after what it belongs to, names a password", () => {
	for (const text of [
		"export GPG_PASS_PHRASE=Hunter2hunter2!x",
		'key_pass_phrase = "Hunter2hunter2!x"',
		"pass_phrase: Hunter2hunter2!x",
		'{"Name": "Orders.Smtp.PassPhrase", "Value": "Hunter2hunter2!x"}',
		"SmtpPassWord=Hunter2hunter2!x",
		"pass_word: Hunter2hunter2!x",
		"ClearTextPassword=Hunter2hunter2!x",
		"clear_text_password: Hunter2hunter2!x",
		"PlainTextPassword=Hunter2hunter2!x",
		"export JKSPASS='Hunter2hunter2!x'",
		"vpnpass=Hunter2hunter2!x",
		"kafkapass: Hunter2hunter2!x",
		"P12PASS=Hunter2hunter2!x",
		"adminpw: Hunter2hunter2!x",
		"userpw=Hunter2hunter2!x",
		"DBPW=Hunter2hunter2!x",
	])
		hidden(text, "Hunter2hunter2!x");
	// slapd.conf's and nslcd.conf's directives.
	hidden('database bdb\nrootdn "cn=Manager,dc=example,dc=com"\nrootpw Hx7mQ2pL9vRt\n', "Hx7mQ2pL9vRt", {
		command: "cat /etc/openldap/slapd.conf",
	});
	hidden("uri ldap://ldap.example.com\nbindpw Tq8vLm3KxR2n\n", "Tq8vLm3KxR2n", { command: "cat /etc/nslcd.conf" });
	// (`PASS` glued to a word it makes another of, a letter or a number; `PW` after a letter, as base64 ends.)
	for (const name of ["bypass", "compass", "lowpass", "subpass", "renderpass", "KEEPASS", "npass", "2pass", "xpw"])
		assert.equal(nameClass(name), "neutral", name);
	kept("proxy:\n  bypass: localhost\n", "localhost");
	kept(
		'"contentHash": "8o5PWkx1bCfWeh8ICXXsP27ZSgL7qCIFqlSQhZS1kd5MfnjhK1yKD8FChCG5XCjkQW6iXvMALUnwtdQBGS+xpw=="',
		"+xpw==",
	);
});

test("a framework's public prefix leaves an encryption or a signing key secret", () => {
	for (const name of [
		"NEXT_PUBLIC_ENCRYPTION_KEY",
		"REACT_APP_ENCRYPTION_KEY",
		"VITE_AES_KEY",
		"NEXT_PUBLIC_SIGNING_KEY",
		"NEXT_PUBLIC_CIPHER_KEY",
		"NEXT_PUBLIC_WEBHOOK_KEY",
	]) {
		assert.equal(nameClass(name), "credential", name);
		hidden(`${name}=Zx7Qp2Lm9Vb4Kd8W`, "Zx7Qp2Lm9Vb4Kd8W", { command: "cat .env.local" });
	}
	for (const name of ["NEXT_PUBLIC_MAPS_KEY", "VITE_SITE_KEY", "PUBLIC_SIGNING_KEY", "NEXT_PUBLIC_PUBLIC_KEY"])
		assert.equal(nameClass(name), "public", name);
});

test("an auth mode's word before AUTH leaves a login under it a credential", () => {
	hidden("HTTP_AUTH=admin:Harbor2291xq", "Harbor2291xq");
	hidden("http_auth: elastic:Harbor2291xq", "Harbor2291xq");
	kept("HTTP_AUTH=basic", "basic");
	kept("HTTP_AUTH=true", "true");
});

test("GitHub Actions' INPUT_TOKEN is an action's token input, a model's input token elsewhere", () => {
	hidden("GITHUB_ACTIONS=true\nINPUT_TOKEN=Zq8LmW3vTn5RkY2HpX7d", "Zq8LmW3vTn5RkY2HpX7d");
	for (const name of ["input_token", "INPUT_TOKENS", "OUTPUT_TOKEN", "inputToken"])
		assert.equal(nameClass(name), "identifier", name);
	kept('input_token = "<s>"', "<s>");
});

test("proxy_pass as a key holds a proxy's password; as an nginx directive, an upstream", () => {
	hidden("[proxy]\nproxy_user = bob\nproxy_pass = Hx7mQ2pL9vRtK4w\n", "Hx7mQ2pL9vRtK4w");
	hidden("proxy_pass: Hx7mQ2pL9vRtK4w", "Hx7mQ2pL9vRtK4w");
	hidden('{"proxy_pass": "Hx7mQ2pL9vRtK4w"}', "Hx7mQ2pL9vRtK4w");
	kept("location / {\n  proxy_pass backend;\n}\n", "backend");
	kept("location / {\n  proxy_pass http://app_backend_8f3k2;\n}\n", "app_backend_8f3k2");
	kept("location ~ \\.php$ {\n  fastcgi_pass php_upstream;\n}\n", "php_upstream");
});

test("a resource's private variant is no key's private half", () => {
	for (const name of ["alb_private", "zone_private", "role_private", "subnet_private", "VPC_PRIVATE"])
		assert.equal(nameClass(name), "neutral", name);
	for (const name of ["vapidPrivate", "push_private", "VAPID_PRIVATE", "WG_PRIVATE"])
		assert.equal(nameClass(name), "credential", name);
	const text =
		'alb_private = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/web/50dc6c495c0c9188"\nzone_private = "Z2FDTNDATAQYW2"\nrole_private = "arn:aws:iam::123456789012:role/app-private"\n';
	for (const value of ["Z2FDTNDATAQYW2", "arn:aws:iam::123456789012:role/app-private", "50dc6c495c0c9188"])
		kept(text, value, { command: "terraform output" });
});

test("a bare secret's hex of 20 to 40 is a secret, a pair's public key above it", () => {
	hidden("key: 278d425bdf160c739803\nsecret: 7ad3773142a6692b25b8\ncluster: eu\n", "7ad3773142a6692b25b8", {
		path: "config/pusher.yml",
	});
	hidden('new Pusher({ key: "278d425bdf160c739803", secret: "7ad3773142a6692b25b8" })', "7ad3773142a6692b25b8");
	hidden('{"key": "278d425bdf160c739803", "secret": "7ad3773142a6692b25b8"}', "7ad3773142a6692b25b8");
});

test("a file's name in a checksum manifest names the file, whatever words it holds", () => {
	kept(
		'{"files": {"token.go": "5f4dcc3b5aa765d61d8327deb882cf99", "secret.yml": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b"}}',
		"5f4dcc3b5aa765d61d8327deb882cf99",
	);
	kept('{"data.csv": "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="}', "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");
});

test("the words before a bare key say whose key it is, what else it is, or that it is no credential's", () => {
	kept(
		"2025/08/13 21:17:57 INFO  cache warm key=7d1e93a0c4b25f68e1a7d3c9b04f2e86a5c1d7b3e9f0a2c4b6d8e1f3a5c7b9d2",
		"7d1e93a0c4b25f68e1a7d3c9b04f2e86a5c1d7b3e9f0a2c4b6d8e1f3a5c7b9d2",
	);
	const body =
		"The admin key `c4e8a1f7b2d9e3c6a0f5b8d1e4a7c2f9` leaked. App id `KQ7ZR2XWPL`, search-only key `9b2e7d4a1c8f3e6b0a5d9c2f7e1b4a8d` is fine in the frontend.";
	hidden(body, "c4e8a1f7b2d9e3c6a0f5b8d1e4a7c2f9");
	kept(body, "9b2e7d4a1c8f3e6b0a5d9c2f7e1b4a8d");
	// (A word that qualifies no credential leaves an ID an ID; a vendor's name before `key` makes it that vendor's key.)
	assert.equal(readPhrase(["order"], "id").class, "identifier");
	const off = new Redactor({ guessing: "off", fingerprintKey: "test" });
	assert.ok(!off.redact("your mailgun key: Kx9mQv2Lp7Rt").text.includes("Kx9mQv2Lp7Rt"));
});

test("a key named for a host or a store is judged by its value, and long hex there is a key", () => {
	for (const text of [
		"SERVER_KEY=a3f1c9e27b4d8f6012e5a7c3b9d4f8e1a6c2b7d3e9f4a8c1b5d2e6f3a7c9b4d8",
		"REDIS_KEY: a3f1c9e27b4d8f6012e5a7c3b9d4f8e1",
		'"primaryKey": "a3f1c9e27b4d8f6012e5a7c3b9d4f8e1a6c2b7d3"',
	])
		hidden(text, "a3f1c9e27b4d8f6012e5a7c3b9d4f8e1");
});

test("a password's word glued to a vendor's name is that vendor's password", () => {
	for (const text of ["couchbasepass=sunshine", 'mailgunpass = "sunshine"']) hidden(text, "sunshine");
});

test("words with a digit run in under a password's name, and two words joined by a hyphen, are a password", () => {
	hidden("DB_PASSWORD='héllo wörld 2291x'", "2291x");
	kept('"password": "Mot de passe oublié ?"', "oublié");
	hidden("PASSWORD=blue-moon", "blue-moon");
	for (const t of [
		"password: app-specific",
		"password: case-sensitive",
		"password: write-only",
		"password: upper-case",
	])
		assert.equal(r().redact(t).text, t);
});

test("a fixture's password is its user's name with a password's word for the user's", () => {
	kept('{"username": "containrrr-user", "password": "containrrr-pass"}', "containrrr-pass");
	hidden('{"username": "containrrr-user", "password": "Xk9mQv2Lp7-pass"}', "Xk9mQv2Lp7");
});

test("under a bare key, words with a number between them and a translation's lookup are names", () => {
	for (const t of [
		'{ "key": "Windows10Home", "label": "Windows 10 Home" }',
		'{ "key": "Step2:Review", "title": "Review" }',
		"{ key: \"$t('auth.Login2')\", value: 1 }",
		'<el-tab-pane :key="$t(\'auth.Login2\')" name="login">',
	])
		assert.equal(r().redact(t).text, t);
	// A password's word and year, and a word spelled with digits, are still made secrets.
	hidden('"secret": "Sunshine2023"', "Sunshine2023");
	hidden('"key": "Pa55wordKey9x"', "Pa55wordKey9x");
});

test("under a bare token, letters in no words are a token at any naturalness; a table's bare auth is no API's", () => {
	const off = new Redactor({ guessing: "off", fingerprintKey: "test" });
	assert.ok(!off.redact("token: WnDKpEQCbOciskIKhAfdQxFmY").text.includes("WnDKpEQCbOciskIKhAfdQxFmY"));
	assert.equal(off.redact("token: RefreshTokenExpiresAtValue").text, "token: RefreshTokenExpiresAtValue");
	const md5 = "| auth | 5f4dcc3b5aa765d61d8327deb882cf99 |";
	assert.equal(off.redact(md5).text, md5);
	assert.ok(!off.redact(`| key | ${"9b8ab69c272a2ace".repeat(4)} |`).text.includes("9b8ab69c272a2ace"));
});

test("a secret's word before a site or GPG key names the pair's secret half", () => {
	for (const n of ["SECRET_SITE_KEY", "recaptchaSecretSiteKey", "PRIVATE_GPG_KEY"])
		assert.equal(nameClass(n), "credential", n);
	assert.equal(nameClass("RECAPTCHA_SITE_KEY"), "public");
	assert.equal(nameClass("SECRET_CACHE_KEY"), "identifier");
	hidden("SECRET_SITE_KEY=6LdKx9mP2vQ7tL4wR8a1b2c3d4e5f6g7h8i9j0kA", "6LdKx9mP2vQ7tL4wR8a1b2c3d4e5f6g7h8i9j0kA");
});

test("a list of strings under a credential's name is read item by item, on one line or over several", () => {
	const off = new Redactor({ guessing: "off", fingerprintKey: "test" });
	const [a, b] = [b62(20), b62(20)];
	for (const text of [
		`API_KEYS='["${a}","${b}"]'`,
		`API_KEYS='["${a}"]'`,
		`{"api_keys": ["${a}", "${b}"]}`,
		`{"api_keys": [\n  "${a}",\n  "${b}"\n]}`,
		`api_keys:\n  # rotated monthly\n  - ${a}\n  - "${b}"\n`,
	]) {
		const out = off.redact(text).text;
		// (Each item alone: the list's brackets, quotes and markers stay.)
		assert.ok(!out.includes(a) && !out.includes(b) && /\["\[|"\[|- \[/.test(out), out);
	}
	hidden('passwords: ["hunter2hunter2", "letmein2024"]', "letmein2024");
	hidden("passwords:\n  - Summer2024!\n  - Winter2023#\n", "Winter2023#");
	hidden('{"passwords": ["Summer2024!", "Winter2023#"]}', "Winter2023#");
	// A list of names, of references or of hashers' classes holds none; nor does a ternary's branch after a list.
	for (const [text, value] of [
		['required_secrets: ["github_token", "npm_token"]', "npm_token"],
		['api_keys: ["${KEY_ONE}", "${KEY_TWO}"]', "${KEY_TWO}"],
		["PASSWORD_HASHERS=['django.contrib.auth.hashers.PBKDF2PasswordHasher']", "PBKDF2PasswordHasher"],
		["auth: [ 'bamf,bamf_id,bamf_secret',\n  'baz,baz_id_new,baz_secret_new' ]", "bamf_secret"],
		["const fields = tab ? ['username', 'password'] : ['mobile', 'captcha']", "captcha"],
		[
			'Key                  Value\n---                  -----\ntoken_policies       ["default" "ci"]',
			'["default" "ci"]',
		],
	])
		kept(text, value);
});

test("a value's own comment, a keyword argument's comma and a command after a token are no part of it", () => {
	const off = new Redactor({ guessing: "off", fingerprintKey: "test" });
	const out = off.redact("bind 127.0.0.1\nrequirepass Kx9mQ2vL7pZr # set by ops\nmaxmemory 2gb").text;
	assert.ok(!out.includes("Kx9mQ2vL7pZr") && out.includes("] # set by ops"), out);
	const call = off.redact("login(\n  PASSWORD=Kx9mQ2vL7pZr,\n  USER=bob)").text;
	assert.ok(!call.includes("Kx9mQ2vL7pZr") && call.includes("],\n  USER=bob"), call);
	const key = b62(40);
	const dev = off.redact(`STRIPE_SECRET_KEY=${key} next dev`).text;
	assert.ok(!dev.includes(key) && dev.endsWith("] next dev"), dev);
	const long = b62(300);
	assert.ok(!off.redact(`TOKEN=${long} next`).text.includes(long.slice(0, 40)));
	// (Nor are Cypress's keystrokes after a typed password.)
	const typed = off.redact("cy.get('#password').type('Hq3mQ2vL9z{enter}')").text;
	assert.ok(!typed.includes("Hq3mQ2vL9z") && typed.includes("]{enter}')"), typed);
});

test("a row that leaves its last cells out is read under its columns, and a Go import's path is no value", () => {
	hidden("user,password,host\nalice,Xk9#fmQ2vLpz,db1\nbob,Hq3#mQ2vL9z", "Hq3#mQ2vL9z");
	for (const text of [
		'import (\n\tpwd "github.com/acme/password-x9"\n\t"fmt"\n)',
		'import pwd "github.com/acme/password-x9"',
	])
		kept(text, "github.com/acme/password-x9");
	// (Where a password is read from is no password: `| --pass-file | path |`.)
	kept("| Source | Password |\n|---|---|\n| --pass-file | path |\n| --pass-stdin | stdin |", "| path |");
	kept("| Source | Password |\n|---|---|\n| --pass-file | path |\n| --pass-stdin | stdin |", "| stdin |");
});

test("a line of several pairs is no YAML value, and a comment after a sibling's name leaves it the name", () => {
	for (const text of ['"password": null, "user": "bob"', '  "password": null, "user": "bob",'])
		kept(text, '"user": "bob"');
	hidden('  "password": Xk9fmQ2vLpzW, "user": "bob",', "Xk9fmQ2vLpzW");
	// (`REQUEST_ID` says the value is a request's ID, comment or not.)
	kept("env:\n  - name: REQUEST_ID  # set by CI\n    value: Xk9fmQ2vLpzWq7Rt4NbYc8Hd\n", "Xk9fmQ2vLpzWq7Rt4NbYc8Hd");
	assert.equal([...attributes("  - name: API_TOKEN  # from vault")][0].value.value, "API_TOKEN");
});

test("Bundler's name for a gem server's host holds its credentials; its other settings by gem or URL don't", () => {
	for (const name of [
		"BUNDLE_GEMS__CONTRIBSYS__COM",
		"BUNDLE_ENTERPRISE__CONTRIBSYS__COM",
		"BUNDLE_RUBYGEMS__PKG__GITHUB__COM",
		"BUNDLE_GEMS__GRAPHQL__PRO",
	])
		assert.equal(nameClass(name), "credential", name);
	for (const name of [
		"BUNDLE_PATH",
		"BUNDLE_BUILD__NOKOGIRI",
		"BUNDLE_LOCAL__RACK",
		"BUNDLE_GEM__TEST",
		"BUNDLE_MIRROR__RUBYGEMS__ORG",
	])
		assert.notEqual(nameClass(name), "credential", name);
});

test("an env value ends at a redirection", () => {
	for (const [text, rest] of [
		["DB_PASSWORD=Winter2024!Prod > out.txt", " > out.txt"],
		["DB_PASSWORD=Winter2024!Prod 2>&1 | tee log", " 2>&1 | tee log"],
		["MYSQL_PWD=Winter2024!Prod mysql < in.sql", " mysql < in.sql"],
	]) {
		hidden(text, "Winter2024!Prod");
		kept(text, rest);
	}
	// (A password's own `;` and `&`, with no command after them, stay in it.)
	hidden("DB_PASSWORD=Tr0ub;4dor&3horse", "4dor&3horse");
});

test("XML: a value named by a name or key attribute on any element, by a <name> child, or on a line of its own", () => {
	hidden(
		"<configuration>\n  <property>\n    <name>fs.s3a.secret.key</name>\n    <value>Winter2024!Prod</value>\n  </property>\n</configuration>",
		"Winter2024!Prod",
	);
	for (const text of [
		'<property name="hibernate.connection.password">Winter2024!Prod</property>',
		'<prop key="jdbc.password">Winter2024!Prod</prop>',
		'<Parameter name="db.password">Winter2024!Prod</Parameter>',
		"<server>\n  <id>nexus</id>\n  <password>\n    Winter2024!Prod\n  </password>\n</server>",
	])
		hidden(text, "Winter2024!Prod");
	kept(
		"<property>\n  <name>fs.s3a.endpoint</name>\n  <value>s3.eu-west-1.amazonaws.com</value>\n</property>",
		"s3.eu-west-1.amazonaws.com",
	);
	kept('<property name="hibernate.connection.username">deploy_user</property>', "deploy_user");
});

test("a dot leader stays before the value it leads to", () => {
	for (const label of ["password", "db_password"]) {
		hidden(`${label} ........ Winter2024!Prod`, "Winter2024!Prod");
		kept(`${label} ........ Winter2024!Prod`, `${label} ........ `);
	}
});

test("a mapping under a plural credential's name is its credentials, when every value in it is one", () => {
	for (const text of [
		"passwords:\n  admin: Tr0ub4dor&3xQ\n  grafana: Winter2024!kz\n",
		'{"passwords": {"admin": "Tr0ub4dor&3xQ", "grafana": "Winter2024!kz"}}',
	]) {
		hidden(text, "Tr0ub4dor&3xQ");
		hidden(text, "Winter2024!kz");
	}
	hidden("api_keys:\n  stripe: Zq8kLm2Pw9xRt4vKp8wZ\n  sendgrid: Ab3dEf5Gh7JkQ9xLm2vR\n", "Ab3dEf5Gh7JkQ9xLm2vR");
	for (const [text, value] of [
		["secrets:\n  enabled: true\n  name: app-secrets\n", "app-secrets"],
		["passwords:\n  minLength: 12\n  requireSymbols: true\n", "minLength: 12"],
		["passwords:\n  policy: strict\n", "strict"],
		["tokens:\n  github: ${GITHUB_TOKEN}\n  slack: ${SLACK_TOKEN}\n", "${SLACK_TOKEN}"],
	])
		kept(text, value);
});

test("a value object under a credential's key is named by the key: Spring's actuator /env, terraform output -json", () => {
	hidden(
		'{"properties": {"PAYMENT_GATEWAY_HMAC": {"value": "5e8addaed2a4e04c42e9c94897686a22e6316fd29b3006deb4b5e364836be4a3", "origin": "System Environment Property"}}}',
		"5e8addaed2a4e04c42e9c94897686a22e6316fd29b3006deb4b5e364836be4a3",
	);
	hidden('{"app.integration.erp.credential": {"value": "EMBEe2mkr9!"}}', "EMBEe2mkr9!");
	hidden('{"db_password": {"sensitive": false, "type": "string", "value": "Tr0ub4dor&3xQ"}}', "Tr0ub4dor&3xQ");
	kept('{"spring.datasource.password": {"value": "******"}}', "******");
	kept('{"app.security.token-expiry": {"value": "PT30M"}}', "PT30M");
	kept('{"HOSTNAME": {"value": "orders-api-7d9f6c8b5-x2kq4"}}', "orders-api-7d9f6c8b5-x2kq4");
});

test("a quoted .NET configuration key's sections before its name, and a Quarkus profile before a property's", () => {
	for (const text of [
		'{\n  "Ldap:BindPassword": "EMBEf0pw8a$"\n}',
		'{"ConnectionStrings:Db:Password": "EMBEf0pw8a$"}',
		"%dev.quarkus.datasource.password=EMBEf0pw8a$",
	])
		hidden(text, "EMBEf0pw8a$");
	hidden("%dev.quarkus.datasource.password=devdev", "devdev");
	kept('{"Ldap:BindDn": "CN=svc-ledger,OU=ServiceAccounts"}', "CN=svc-ledger");
	kept("%test.quarkus.datasource.password=${TEST_DB_PW:test}", "${TEST_DB_PW:test}");
	// (Unquoted, a colon after a word is a namespace's, as before: sed's `s:…:…:` script.)
	kept("sed -i 's:DB_PASSWORD: .*:DB_PASSWORD: x:g' values.yaml", "s:DB_PASSWORD");
});

test("a Name/Value table with more columns names each row's value by its Name cell", () => {
	const table = [
		"Name                     Value                SlotSetting",
		"-----------------------  -------------------  -----------",
		"Smtp__Password           quartz-apple3861     False",
		"WEBSITE_TIME_ZONE        GMT Standard Time    False",
		"WEBSITE_RUN_FROM_PACKAGE 1                    False",
	].join("\n");
	hidden(table, "quartz-apple3861");
	kept(table, "GMT Standard Time");
	kept(table, "SlotSetting");
});

test("a release, a VCS revision, a reference and an organization are named as IDs and hashes", () => {
	for (const name of ["SENTRY_RELEASE", "LANGFUSE_RELEASE", "RELEASE", "BUILD_VCS_NUMBER", "VCS_REVISION"])
		assert.equal(nameClass(name), "hash", name);
	for (const name of ["pspReference", "merchantReference", "payment_reference", "organization", "ORGANISATION"])
		assert.equal(nameClass(name), "identifier", name);
	for (const name of ["RELEASE_TOKEN", "SENTRY_AUTH_TOKEN", "ORGANIZATION_API_KEY"])
		assert.equal(nameClass(name), "credential", name);
	kept("LANGFUSE_RELEASE=63a66e12bb6436fe91488485a79d81f6f8966a55\n", "63a66e12", { path: ".env.observability" });
	kept("BUILD_VCS_NUMBER=0e38f1d46da738d2c1f329127d8f93f3fab0e2c2\n", "0e38f1d4", { command: "set" });
	hidden("RELEASE_TOKEN=63a66e12bb6436fe91488485a79d81f6f8966a55\n", "63a66e12", { path: ".env" });
});

test("a key and value table's row names its value by its key cell", () => {
	hidden(
		"INSERT INTO config (name, value) VALUES ('aws_secret_access_key', 'qT7xKp2LmZ9vRnB4sWyH8dFh6ZcQe3JaUo5GtN1c');",
		"qT7xKp2LmZ9vRnB4sWyH8dFh6ZcQe3JaUo5GtN1c",
	);
	const options =
		"INSERT INTO wp_options (option_name, option_value, autoload) VALUES ('mailserver_pass', 'Hx7mQ2pL9vRt', 'yes'), ('siteurl', 'https://x.io', 'yes'), ('blogname', 'My Blog', 'yes');";
	hidden(options, "Hx7mQ2pL9vRt");
	kept(options, "https://x.io");
	kept(options, "My Blog");
	kept("INSERT INTO settings (key, value) VALUES ('smtp_password', '{{ smtp_pass }}');", "{{ smtp_pass }}");
	kept("INSERT INTO settings (key, value) VALUES ('session_cookie_name', 'Hx7mQ2pL9vRtZk3v');", "Hx7mQ2pL9vRtZk3v");
});

test("a YAML value slot is named by its parent", () => {
	const v = "Zq8vT3mK9xLwPr2Yd7Hn";
	hidden(`variables:\n  DB_PASSWORD:\n    value: "${v}"\n    description: db\n`, v);
	hidden(`secrets:\n  api_key:\n    value: ${v}\n    expires: 2025\n`, v);
	kept(`variables:\n  DB_PASSWORD:\n    value: "{{ vault_db }}"\n`, "{{ vault_db }}");
});

test("a value ends where the syntax around it resumes: a page's markup, a shell expansion's close", () => {
	for (const [text, after] of [
		["<!-- DB_PASSWORD=Hx7mQ2pL9vRt-->", "]-->"],
		["<td>Password: Hx7mQ2pL9vRt<br />more</td>", "]<br />more</td>"],
		["<td>Password: Hx7mQ2pL9vRt<br>more</td>", "]<br>more</td>"],
		["<p>password=Hx7mQ2pL9vRt</p>", "]</p>"],
	]) {
		const out = r().redact(text).text;
		assert.ok(out.endsWith(after) && !out.includes("Hx7mQ2pL9vRt"), out);
	}
	// A shell expansion is read whole, as one word with the blanks in its brackets.
	for (const text of [
		"#!/bin/sh\nDB_PASSWORD=${DB_PASSWORD:-$(openssl rand -hex 16)}\nexport DB_PASSWORD\n",
		"export SECRET_KEY=${SECRET_KEY:-$(head -c 32 /dev/urandom | base64)}\n",
		'az webapp config appsettings set -g rg -n app --settings "DB_PASSWORD=@Microsoft.KeyVault(VaultName=kv;SecretName=db)"',
	])
		assert.equal(r().redact(text).text, text);
	hidden("DB_PASSWORD=${DB_PASSWORD:-Kx9mQ2pLw7vR} ./run.sh", "Kx9mQ2pLw7vR");
	hidden('docker run -e "DB_PASSWORD=Kx9mQ2pLw7vR;Host=db" app', "Kx9mQ2pLw7vR");
});
