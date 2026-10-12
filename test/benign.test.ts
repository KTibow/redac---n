/**
 * Values that are never secrets, in every syntax a rule reads, under every credential-like name: each
 * text must come out unchanged. A new rule that fires on one of these anywhere fails here, without anyone
 * having written that exact case. (Grow BENIGN with every over-redaction a review finds.)
 *
 * (A fake key's vendor prefix is written with an escape, `"ghp\x5f…"`: written whole, the repository would hold text
 * that secret scanners, GitHub's push protection among them, take for a live key.)
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { Redactor } from "../src/index.ts";

const BENIGN = [
	"12/12",
	"98.5%",
	"8-64",
	"1800-",
	"(e.g",
	"v2.4.1",
	"1.0.0-rc1",
	"4.12.0b2",
	"1.1.0rc3",
	"0.1.dev3",
	"1.0.post1",
	"2.0a1",
	"2024-05-01",
	"2024-05-01T10:00:00Z",
	"SHA-256",
	"AES-256",
	"UTF-8",
	"ISO-8859-1",
	"TLSv1.3",
	"base64url",
	"ctrl+shift+F12",
	"str|None",
	"str=",
	"us-east-1",
	"us-central1",
	"min.",
	"at least 12",
	"ctrl-p,ctrl-q",
	"[GH-784]",
	"{mgIdx}>",
	"iam:ChangePassword",
	"allauth.account.forms.SetPasswordForm",
	"-0x3f879678",
	"%E2%9C%93",
	"${(j:-:)words}",
	"None):",
	"[a-zA-Z_][a-zA-Z0-9_-]*",
	"(?:%s)(?(200)z)",
	"md5$$",
	"github.com/hashicorp/go-secure-stdlib/password",
	"bcrypt$",
	"pbkdf2_sha256",
	"sha512_crypt",
	"null?password:password2",
	String.raw`\x2B\x06\x01\x05\x05\x07\x03\x01`,
];
const NAMES = ["password", "pass", "passwd", "secret", "token", "api_key", "key", "DB_PASSWORD", "apiKey"];
const SYNTAXES: ((n: string, v: string) => string)[] = [
	(n, v) => `${n}=${v}`,
	(n, v) => `${n}: ${v}`,
	(n, v) => `{"${n}": "${v}"}`,
	(n, v) => `${n} = "${v}"`,
	(n, v) => `--${n} ${v}`,
	(n, v) => `| ${n} | ${v} |`,
	(n, v) => `${n}   ${v}`,
	(n, v) => `The ${n} is ${v}.`,
	(n, v) => `Check the ${n} (${v}) first.`,
	(n, v) => `- ${n.toUpperCase()} — ${v}`,
	(n, v) => `<string name="${n}">${v}</string>`,
	(n, v) => `os.getenv("${n.toUpperCase()}", "${v}")`,
	(n, v) => `${n.toUpperCase()} lautet ${v}`,
	(_n, v) => `Passwort: ${v}`,
	(_n, v) => `Das Passwort ist ${v}`,
	(_n, v) => `密码是 ${v}`,
];

test("benign values stay in every syntax under every name", () => {
	const r = new Redactor({ fingerprintKey: "benign" });
	const failures: string[] = [];
	for (const v of BENIGN)
		for (const n of NAMES)
			for (const s of SYNTAXES) {
				const text = s(n, v);
				const out = r.redact(text).text;
				if (out !== text) failures.push(`${JSON.stringify(text)} -> ${JSON.stringify(out)}`);
			}
	assert.equal(failures.length, 0, `${failures.length} benign values redacted:\n${failures.slice(0, 40).join("\n")}`);
});

/** The mirror: real-looking secrets in the same syntaxes under credential names are always hidden. */
const SECRETS = [
	"Xk9mQ2vL8nRt4Wz7Pq3sZ1aB",
	"Plumb3r#Kite77",
	"9f3c2a7b1e4d6f8a0b5c3e7d2a9f1b4c",
	"q8Zr2LmX0vT4nB7wK1pY5dH9eF3gJ6kM0sU2xV4z",
];
const CREDENTIAL_NAMES = [
	"password",
	"passwd",
	"secret",
	"token",
	"api_key",
	"DB_PASSWORD",
	"apiKey",
	"client_secret",
	"access_token",
];

test("secrets are hidden in every syntax under every credential name", () => {
	const r = new Redactor({ fingerprintKey: "secrets" });
	const failures: string[] = [];
	for (const v of SECRETS)
		for (const n of CREDENTIAL_NAMES)
			for (const s of SYNTAXES.slice(0, 13)) {
				const text = s(n, v);
				const out = r.redact(text).text;
				if (out.includes(v)) failures.push(`${JSON.stringify(text)} -> ${JSON.stringify(out)}`);
			}
	assert.equal(failures.length, 0, `${failures.length} secrets kept:\n${failures.slice(0, 40).join("\n")}`);
});

/**
 * Values public by design stay in every syntax and every encoding the pipeline unwraps (colour codes,
 * JSON escapes, a file viewer's line numbers): each of those is a separate path to the layers, and all of
 * them must reach the same decision (policy.ts).
 */
const PUBLIC = [
	"pk_live_51L8TZlth4cWjLcVQehjCoazCfiXN8lDFuyfbaDi7e0Y1GnD6OEO22baSEtfEOq5J3K",
	"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
	"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
	"ADM2CIIL3RWXBA6T2HW3FODNCQQOUJEHHQD6FKCPVAMHDNTTSMO73ROX",
	"wx8c13fda63650f4d9",
	"ey\x4ahbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ey\x4apc3MiOiJzdXBhYmFzZSIsInJlZiI6ImJncHJmYmZ2Y29oaG55dmt6b2VtIiwicm9sZSI6ImFub24iLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6MjAwMDAwMDAwMH0.Wl6TO0X9pXmJmUDk8SNAr4BuF9ChTvGkCyT3a2_9fJk",
];
const WRAPS: ((s: string) => string)[] = [
	(s) => s,
	(s) => `\x1b[32m${s}\x1b[0m`,
	(s) => JSON.stringify(JSON.stringify({ log: `value: ${s}\nnext line` })),
	(s) => `     1→const id = "${s}";\n     2→export default id;`,
	(s) => JSON.stringify({ log: `\x1b[32mid: ${s}\x1b[0m` }),
];
const PLACES: ((v: string) => string)[] = [
	(v) => `PUBLIC_VALUE=${v}`,
	(v) => `{"publishable": "${v}"}`,
	(v) => `id: ${v}`,
	(v) => `see ${v} for details`,
];

test("values public by design stay through every path", () => {
	const r = new Redactor({ fingerprintKey: "public" });
	const failures: string[] = [];
	for (const v of PUBLIC)
		for (const p of PLACES)
			for (const w of WRAPS) {
				const text = w(p(v));
				const out = r.redact(text).text;
				if (out !== text)
					failures.push(`${JSON.stringify(text).slice(0, 120)} -> ${JSON.stringify(out).slice(0, 160)}`);
			}
	assert.equal(failures.length, 0, `${failures.length} public values hidden:\n${failures.slice(0, 30).join("\n")}`);
});

/**
 * Code that handles a credential without holding one: the variable spliced between two string literals,
 * a call cut at its quote, a struct tag, an interpolation hole, a bind parameter, a label, a reference.
 * Every variable name and every wrap must reach the same answer (policy.ts codeShape, values.ts).
 */
const VARS = ["passwd", "pwd", "this.old_pwd", "form.pwd.value", "$sql_passwd", "cfg->pass", "params[0]", "getPw()"];
const BUILDERS: ((v: string) => string)[] = [
	(v) => `url = "https://host/login?user=" + user + "&password=" + ${v} + "&v=2";`,
	(v) => `url = 'https://host/login?user='+user+'&password='+${v}+'&v=2'`,
	(v) => `$q = "act=sql&sql_passwd=".htmlspecialchars(${v})."&sql_server=".$host;`,
	(v) => `cs = "SERVER=" + host + ";UID=" + user + ";PWD=" + ${v} + ";";`,
	(v) => `xml = "<username>"+usr+"</username><password>"+${v}+"</password>";`,
	(v) => `cmd = 'winexe --user=admin --password=' + ${v} + ' //' + ip;`,
	(v) => `q = 'UPDATE users SET password = ' + ${v} + ', phone = ' + phone;`,
	(v) => `if (x.Password == ${v.replace(/^\$/, "")}) {`,
	(v) => `payload = "password=" + ${v}`,
];
const CODE = [
	`$q = "SELECT * FROM u WHERE name='$user' AND password=md5('$password')";`,
	'Password string `json:"password,omitempty"`',
	`string cs = $"Server={DB_Host};Uid={DB_Username};Pwd={DB_Password};";`,
	`string q = "SELECT * FROM users WHERE DNI=@DNI AND CONTRASEÑA=@CONTRASEÑA";`,
	`emailServerPassword: 'Email password (app-specific password recommended)',`,
	`proxyServerPassword: 'SOCKS proxy settings:',`,
	`passwd: account.password`,
	`pwd=m_password;`,
	`$password =md5($password);`,
	`password = '$loginPass'`,
	`owner = create_user(email: "o@example.com", password: @user_password)`,
	`password=password||options[:password]||self.get_password`,
	`printf("password: %.*s\\n", n, sw->login.password);`,
	`password = await keytar.findPassword("https://idmsa.apple.com", username);`,
	`<input type="password" placeholder="Enter Password:" name="password">`,
	`const passwd = 'not_set';`,
];

test("code that handles a credential stays, in every wrap", () => {
	const r = new Redactor({ fingerprintKey: "code" });
	const failures: string[] = [];
	const texts = [...VARS.flatMap((v) => BUILDERS.map((b) => b(v))), ...CODE];
	for (const t of texts)
		for (const w of WRAPS.slice(0, 2).concat((s) => `     1→${s}`)) {
			const text = w(t);
			const out = r.redact(text).text;
			if (out !== text) failures.push(`${JSON.stringify(text)} -> ${JSON.stringify(out)}`);
		}
	assert.equal(failures.length, 0, `${failures.length} code texts redacted:\n${failures.slice(0, 40).join("\n")}`);
});

test("literal secrets in the same building positions are hidden", () => {
	const r = new Redactor({ fingerprintKey: "code-secrets" });
	const failures: string[] = [];
	const texts = [
		...["Xk9mQ2vL8nRt4Wz7", "Plumb3r#Kite77"].flatMap((s) => [
			`url = "https://host/login?user=" + user + "&password=${s}&v=" + v;`,
			`cs = "SERVER=" + host + ";UID=sa;PWD=${s};";`,
			`password = "${s}" + suffix`,
			`if (password == "${s}") {`,
			`passwd: "${s}"`,
		]),
		`password = "+Xk9mQ2vLp+"`,
		`DB_PASSWORD=+aB3dE5fG7hJ9kL+`,
		`password = @dm1nPa55`,
	];
	for (const text of texts) {
		const out = r.redact(text).text;
		if (!out.includes("[REDACTED")) failures.push(`${JSON.stringify(text)} -> ${JSON.stringify(out)}`);
	}
	assert.equal(failures.length, 0, `${failures.length} secrets kept:\n${failures.join("\n")}`);
});

/** References in every tool's syntax, under every credential name, in the syntaxes that carry them. */
const REFERENCES = [
	"${DB_PASSWORD}",
	"${DB_PASSWORD:-}",
	"${DB_PASSWORD:?required}",
	"$(cat /run/secrets/db)",
	"{{ .Values.db.password }}",
	"!Ref DbPassword",
	"!GetAtt DbSecret.Password",
	"!secret mqtt_password",
	"*default_password",
	"[parameters('adminPassword')]",
	"$__env{GF_DB_PASSWORD}",
	"%{hiera('vault_db_password')}",
	"@@{db_password}@@",
	"vault:secret/data/app#password",
	"op://vault/item/password",
	"%DB_PASSWORD%",
	"required|string|min:8|confirmed",
	"varchar(255)",
	"VARCHAR(255) NOT NULL",
];

test("references and schema values stay under every credential name", () => {
	const r = new Redactor({ fingerprintKey: "refs" });
	const failures: string[] = [];
	for (const v of REFERENCES)
		for (const n of CREDENTIAL_NAMES)
			for (const s of [
				(n: string, v: string) => `${n}: ${v}`,
				(n: string, v: string) => `${n} = "${v}"`,
				(n: string, v: string) => `  ${n}:   ${v}`,
			]) {
				const text = s(n, v);
				const out = r.redact(text).text;
				if (out !== text) failures.push(`${JSON.stringify(text)} -> ${JSON.stringify(out)}`);
			}
	assert.equal(failures.length, 0, `${failures.length} references redacted:\n${failures.slice(0, 40).join("\n")}`);
});
