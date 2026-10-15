/**
 * Credentials written as literals in source: declarations, call arguments, SQL, split and prefixed literals, and the
 * escapes of each syntax.
 *
 *   node --test test/code-literals.test.ts
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { callArguments } from "../src/calls.ts";
import { normalize } from "../src/normalize.ts";
import { hidden, kept, r } from "./helpers.ts";

test("adjacent string literals are one value in code, but a log's quoted fields stay apart", () => {
	hidden('auth_token = "xoxb-xXJbuizjE" "zT1a6209l4WO0Ms"', "zT1a6209l4WO0Ms");
	hidden('KEY = "sk-proj-Ab3De5Fg7" +\n  "Hi9Jk1Lm3No5Pq7Rs9Tu"', "Hi9Jk1Lm3No5Pq7Rs9Tu");
	hidden('KEY = ("sk-proj-Ab3De5Fg7"\n       "Hi9Jk1Lm3No5Pq7Rs9Tu")', "Hi9Jk1Lm3No5Pq7Rs9Tu");
	const v = r().redactValue([
		{ role: "user", content: 'DB_PASSWORD = "Hx7#mQ2p" + "Lw9zKq4T"' },
		{ role: "assistant", content: "Logging in with Hx7#mQ2pLw9zKq4T." },
	]).value;
	assert.ok(!JSON.stringify(v).includes("Hx7#mQ2pLw9zKq4T"));
	hidden('x = foo(\n    "ghp\x5f16C7e42F292c69"\n    "12E7710c838347Ae178B4b",\n)', "12E7710c838347Ae178B4b");
	hidden("token = ('ghp\x5f16C7e42F292c69' '12E7710c838347Ae178B4b')", "12E7710c838347Ae178B4b");
	kept('200 512 "https://app.example.com/reset?token=Qz8rT2mLx0vB4nW7kP1y" "curl/7.88.1"', '" "curl/7.88.1"');
	// (A C initializer's next piece is indented under it; a shell line's quoted value ends its line.)
	hidden('static const char *key =\n    "sk-proj-Ab3De5Fg7"\n    "Hi9Jk1Lm3No5Pq7Rs9Tu";', "Hi9Jk1Lm3No5Pq7Rs9Tu");
	for (const next of ['"$SCRIPT_DIR/run.sh" --migrate', '"$@"', '"/usr/local/bin/deploy" --prod']) {
		const script = `export DB_PASSWORD="Xk29fLmq81Zt"\n${next}\n`;
		hidden(script, "Xk29fLmq81Zt");
		kept(script, `"\n${next}\n`);
	}
});

test("pieces in single quotes join as double-quoted ones do; a string starts with three characters, of token-like pieces", () => {
	for (const [code, joined] of [
		["connect(host, 'Hx7#mQ2p' 'Lw9zKq4T')", "connect(host, 'Hx7#mQ2pLw9zKq4T')"],
		["KEY = (\n    'Ab3De5Fg7'\n    'Hi9Jk1Lm3No5Pq7Rs9Tu'\n)", "KEY = (\n    'Ab3De5Fg7Hi9Jk1Lm3No5Pq7Rs9Tu'\n)"],
		["return 'tok_' + 'Hi9Jk1Lm3No5Pq7Rs9Tu';", "return 'tok_Hi9Jk1Lm3No5Pq7Rs9Tu';"],
		['url = "/" + "v1"; key = "abc" + "def"', 'url = "/" + "v1"; key = "abcdef"'],
		['msg = "Hello" + " world"; key = "abc" + "def"', 'msg = "Hello" + " world"; key = "abcdef"'],
		["script-src: 'self' 'nonce-kPXDxABNuZat3yDNgk494nPB'", "script-src: 'self' 'nonce-kPXDxABNuZat3yDNgk494nPB'"],
	])
		assert.equal(normalize(code).text, joined);
});

test("a quote that closes a literal ends a password, and an unclosed quote or comment opens nothing", () => {
	hidden('DB_PASSWORD="Winter(24"', "Winter(24");
	hidden("mysql -u root -p'Harbor(99' app", "Harbor(99");
	hidden("curl -u 'admin:a22F(UG,' https://x.example.com", "a22F(UG,");
	const line = "DB_PASSWORD='Kx9mQv2Lp7Rt!9";
	hidden(line, "Qv2Lp7Rt");
	hidden('$ ls src/*.py\nconn = pymysql.connect("db.internal", "app", "Vq7mZp2Lx9wK", "shop")', "Vq7mZp2Lx9wK");
});

test("a literal with a prefix, triple quotes, a doubled quote or an escape is read to its real end", () => {
	for (const line of [
		'x = hmac.new(b"Vy9peTf5BIP6Xd4IQCmSqNFe", m)',
		'var c = new ApiClient(@"Vy9peTf5BIP6Xd4IQCmSqNFe");',
	])
		hidden(line, "Vy9peTf5BIP6Xd4IQCmSqNFe");
	for (const line of ["DB_PASSWORD = '''Harbor2291!'''", 'val password = """Harbor2291!"""'])
		hidden(line, "Harbor2291!");
	hidden("ConvertTo-SecureString 'Win''ter2024' -AsPlainText -Force", "ter2024");
	for (const line of [
		'mysql -h db -u app -p\'wc"Xq9mQ2vL7pZr\' -e "SELECT 1"',
		'conn = psycopg2.connect(password=\'C4zq&i+Dbi4Ab"x9\', host="db")',
		'DB_PASSWORD=\'9AJ+#PkojF@8e"Lm2\' DB_HOST="db" ./run.sh',
	])
		hidden(line, line.match(/'([^']+)'/)![1]);
	for (const line of [
		"password: 'Kx9m''Qv2Lp7Rt'",
		"$Password = 'Kx9m''Qv2Lp7Rt'",
		"INSERT INTO users (email, password) VALUES ('ann@x.io', 'Kx9m''Qv2Lp7Rt');",
		"password = 'Kx9m\\'Qv2Lp7Rt'",
		'$Password = "Kx9m""Qv2Lp7Rt"',
		'Dim password As String = "Kx9m""Qv2Lp7Rt"',
	])
		hidden(line, "Qv2Lp7Rt");
	hidden("UPDATE users SET password='Kx9m''Qv2Lp7Rt' WHERE id=1;", "Qv2Lp7Rt");
});

test("a shell's quoted pieces of one word are one value", () => {
	for (const line of [
		"export PGPASSWORD='Kx9m'\\''Qv2Lp7Rt'",
		"PGPASSWORD='Kx9m''Qv2Lp7Rt' psql -h db",
		"PGPASSWORD='Kx9m'\"Qv2;Lp7Rt\" psql -h db",
		"API_KEY='9b1d290ea99f6789'\\\n'Qv2Lp7Rt33426eb2'",
		"PASSWORD='Kx9m\\'Qv2 Lp7Rt'",
		"PGPASSWORD='Kx9m'Qv2Lp7Rt psql -h db",
	])
		hidden(line, "Lp7Rt");
	kept("PGPASSWORD='Kx9m'Qv2Lp7Rt;psql -h db", ";psql");
	hidden("export PGPASSWORD='Kx9mQv2Lp7'\\!", "\\!");
	// (A line continuation after the word is the command's, not the value's.)
	kept("PGPASSWORD='Kx9mQv2Lp7Rt'\\\n  psql -h db", "'\\\n  psql");
});

test("a call's arguments are split at its commas, past the strings, comments and brackets inside them", () => {
	const args = (call: string) => callArguments(call, call.indexOf("(") + 1)?.map((a) => a.literal?.value ?? a.text);
	assert.deepEqual(
		args(
			'psycopg2.connect(\n    host="db.internal",  # the replicas\' primary, for now\n    timeout=total / (2 * retries),\n    password="Kx9mQv2Lp7Rt",\n)',
		),
		["db.internal", "timeout=total / (2 * retries)", "Kx9mQv2Lp7Rt"],
	);
	assert.deepEqual(args("db.connect(this.#password, opts)"), ["this.#password", "opts"]);
	// (Python's floor division, read as a `//` comment, leaves the call unclosed.)
	assert.deepEqual(args("connect(host, port=total // 2)"), ["host", "port=total // 2"]);
	assert.deepEqual(args("connect(host, total / 2) /* see INC-42 */"), ["host", "total / 2"]);
	assert.deepEqual(args("mysql_real_connect(conn, host, /* 1) the replica, or */ user, port / 2, /* the port */ 0)"), [
		"conn",
		"host",
		"user",
		"port / 2",
		"0",
	]);
	assert.deepEqual(args("fetch(`${base}/login, then`, [1, 2], {c: 3, d: 4})"), [
		"${base}/login, then",
		"[1, 2]",
		"{c: 3, d: 4}",
	]);
	assert.deepEqual(args('client := New(\n\t"Kx9mQv2Lp7Rt",\r\n\tport,\n)'), ["Kx9mQv2Lp7Rt", "port"]);
	assert.deepEqual(args('new SqlConnection(@"Server=db;\n    Password=Kx9""mQv2;", opts)'), [
		'Server=db;\n    Password=Kx9""mQv2;',
		"opts",
	]);
	assert.deepEqual(args('conn.query(r#"\n  SELECT 1\n"#, pw)'), ["\n  SELECT 1\n", "pw"]);
	assert.deepEqual(args('Path::new(r"C:\\keys\\", mode)'), ["C:\\keys\\", "mode"]);
	assert.deepEqual(args('items.join("\\", \\"", sep)'), ['\\", \\"', "sep"]);
	assert.deepEqual(args("s.replace('\\'', '\"')"), ["\\'", '"']);
	// A string that doesn't close, or a bracket that closes what didn't open, leaves no call.
	for (const call of ['connect("db.internal, password)', "connect(host, port]"]) assert.equal(args(call), undefined);
});

test("SQL that sets a password hides the literal and keeps a password hash", () => {
	const pw = "vbrzzeN7T9J2xk";
	hidden(`CREATE USER 'app'@'%' IDENTIFIED BY '${pw}';`, pw);
	hidden(`SET PASSWORD FOR 'app'@'%' = '${pw}';`, pw);
	kept(
		"IDENTIFIED BY PASSWORD '*94BDCEBE19083CE2A1F959FD02F964C7AF4CFC29'",
		"*94BDCEBE19083CE2A1F959FD02F964C7AF4CFC29",
	);
	hidden("UPDATE users SET password = '@dmin_2024x' WHERE id = 1;", "@dmin_2024x");
	hidden("CREATE USER app IDENTIFIED BY ':Hq3nT8wZ5rK2';", "Hq3nT8wZ5rK2");
	// A keyword or a stand-in where the password goes is none.
	kept("CREATE USER 'app'@'%' IDENTIFIED BY RANDOM PASSWORD;", "RANDOM PASSWORD");
	kept("CREATE USER app WITH PASSWORD 'abcd1234';", "abcd1234");
	// A literal whose quote is escaped by a backslash (MySQL's default, Postgres' E'…'), whole.
	for (const line of [
		"CREATE USER 'app'@'%' IDENTIFIED BY 'Hx7m\\'Q2pL9vRtZk3w';",
		"ALTER USER 'u'@'h' IDENTIFIED WITH mysql_native_password BY \"Hx7m\\\"Q2pL9vRtZk3w\";",
		"SET PASSWORD FOR 'u'@'h' = 'Hx7m\\'Q2pL9vRtZk3w';",
		"CREATE ROLE app LOGIN PASSWORD E'Hx7m\\'Q2pL9vRtZk3w';",
	])
		hidden(line, "Q2pL9vRtZk3w");
	// The quoted form in a statement that makes, changes or grants to a user, over several lines too; prose says what
	// a record is identified by.
	hidden("CREATE USER app\n  IDENTIFIED BY 'Hx7mQ2pL9vRtZk3w';", "Hx7mQ2pL9vRtZk3w");
	hidden("GRANT ALL ON *.* TO 'u'@'h' IDENTIFIED BY 'Hx7mQ2pL9vRtZk3w';", "Hx7mQ2pL9vRtZk3w");
	hidden("CREATE DATABASE LINK l CONNECT TO u IDENTIFIED BY \"Hx7mQ2pL9vRtZk3w\" USING 'x';", "Hx7mQ2pL9vRtZk3w");
	for (const line of [
		"Each record is identified by 'order_id' in the table.",
		'The cluster is identified by "prod-eu-1".',
		"Nodes are identified by 'worker-3'; users by 'email address'.",
	])
		assert.equal(r().redact(line).text, line);
});

test("a common password's stand-in after a config's or a statement's password keyword is kept, as under a password's name", () => {
	for (const [line, value] of [
		["ALTER USER app WITH PASSWORD 'hunter2';", "hunter2"],
		["CREATE USER 'app'@'%' IDENTIFIED BY 'test123';", "test123"],
		["127.0.0.1:6379> AUTH hunter2", "hunter2"],
		["userlist L\n  user bob insecure-password hunter2", "hunter2"],
		['%any : PSK "hunter2"', "hunter2"],
	])
		kept(line, value);
	hidden("ALTER USER app WITH PASSWORD 'Harbor2291x';", "Harbor2291x");
	// (A command line's option names no password: `-phunter2` is hidden.)
	hidden("mysql -u root -phunter2 app", "hunter2");
	hidden("openssl enc -aes256 -pass pass:hunter2 -in a", "hunter2");
});

test("SQL's own strings are read as strings: N'…', E'…', a character set's, dollar quoting, a cast, a hash's input", () => {
	const pw = "Harbor2291!x";
	for (const t of [
		`INSERT INTO Users (Id, Email, Password) VALUES (1, N'a@b.com', N'${pw}');`,
		`UPDATE Users SET Password = N'${pw}' WHERE Id = 1;`,
		`CREATE LOGIN app WITH PASSWORD = N'${pw}', CHECK_POLICY = OFF;`,
		`ALTER LOGIN sa WITH PASSWORD=N'${pw}'`,
		`CREATE USER app IDENTIFIED BY N'${pw}';`,
		`INSERT INTO users (email, password) VALUES ('ann@x.io', E'${pw}');`,
		`INSERT INTO users (name, password) VALUES (_utf8mb4'ann', _utf8mb4'${pw}');`,
		`INSERT INTO users (email, password) VALUES ('ann@x.io', $$${pw}$$);`,
		`INSERT INTO users (email, password) VALUES ('ann@x.io', $pw$${pw}$pw$::text);`,
		`INSERT INTO users (email, password) VALUES ('ann@x.io', '${pw}'::character varying(64));`,
		`INSERT INTO users (email, password) VALUES ('ann@x.io', CAST('${pw}' AS varchar(64)));`,
		`INSERT INTO users (email, password) VALUES ('ann@x.io', crypt('${pw}', gen_salt('bf')));`,
		`INSERT INTO users (email, password) VALUES ('ann@x.io', encode(digest('${pw}', 'sha256'), 'hex'));`,
		`UPDATE users SET password = MD5('${pw}') WHERE id = 2;`,
		`UPDATE users SET password = SHA2('${pw}', 256) WHERE id = 2;`,
		`$password = md5("${pw}");`,
		`wchar_t *password = L"${pw}";`,
	])
		hidden(t, pw);
	// (A prefix is SQL's before SQL's quote only: a password may start `N"`. Prose's `N's` and `E'll` open nothing.)
	hidden('level=info user=admin password=N"4jVkMdXAoCDB! host=db', 'N"4jVkMdXAoCDB!');
	kept("SELECT N'Don''t panic' AS msg FROM t; It's N's turn, and E'll go.", "N'Don''t panic' AS msg");
	kept("INSERT INTO users (email, password) VALUES ('ann@x.io', crypt(:pw, gen_salt('bf')));", "gen_salt('bf')");
	kept("INSERT INTO users (email, created) VALUES ('ann@x.io', '2024-01-01'::timestamp);", "'2024-01-01'::timestamp");
});

test("a key/value table's value is named by its row, and pg_dump's COPY rows by their columns", () => {
	for (const [t, v] of [
		["INSERT INTO wp_options (option_name, option_value) VALUES ('smtp_password', 'Harbor2291!x');", "Harbor2291!x"],
		["INSERT INTO settings (name, value) VALUES ('site', 'x'), ('api_key', 'Winter2024pass');", "Winter2024pass"],
		[
			"INSERT INTO `wp_usermeta` (`user_id`, `meta_key`, `meta_value`) VALUES (1, 'stripe_secret', 'Hx7mQ2pL9vRt');",
			"Hx7mQ2pL9vRt",
		],
		["INSERT INTO config (setting_key, setting_value) VALUES ('mail.password', 'Hx7mQ2pL9vRt');", "Hx7mQ2pL9vRt"],
		[
			"COPY public.users (id, email, password) FROM stdin;\n1\tann@x.io\tHarbor2291!x\n2\tbob@x.io\tWinter2024pass\n\\.\n",
			"Winter2024pass",
		],
		["COPY public.users (id, email, password) FROM stdin;\r\n1\tann@x.io\tHarbor2291!x\r\n\\.\r\n", "Harbor2291!x"],
	])
		hidden(t, v);
	kept(
		"INSERT INTO settings (name, value) VALUES ('smtp_host', 'mail.x.io'), ('api_key', 'Winter2024pass');",
		"mail.x.io",
	);
	kept("INSERT INTO settings (name, value) VALUES ('blogname', 'Harbor Tales');", "Harbor Tales");
	kept("COPY public.users (id, email, password) FROM stdin;\n1\tann@x.io\t\\N\n\\.\nSELECT 1;", "ann@x.io");
});

test("a literal converted before it's passed, or given to a converter, is still the value", () => {
	const pw = "lamp-otter-91Qx-blue";
	for (const t of [
		`return new PasswordAuthentication("deploy", "${pw}".toCharArray());`,
		`mgr.setPassword("${pw}".getBytes(StandardCharsets.UTF_8));`,
		`sig = hmac.new("${pw}".encode("utf-8"), body, hashlib.sha256).hexdigest()`,
		`client.setPassword("${pw}".trim().toCharArray());`,
		`const token = jwt.sign(payload, new TextEncoder().encode("${pw}"));`,
		`config.setPassword(Secret::new("${pw}".to_string()));`,
		`config.set_password(SecretString::from("${pw}"));`,
		`token = jwt.sign(payload, Buffer.from("${pw}", "utf8"))`,
		`jwtKey := []byte("${pw}")`,
	])
		hidden(t, pw);
	// (A method that combines the literal with a variable makes another value; a lookup takes a name.)
	kept('client.setPassword("lamp-otter-{}".format(suffix));', "lamp-otter-{}");
	kept('client.setPassword(getSecret("prod-db-password"));', "prod-db-password");
	kept('client.setPassword(Secret.load("prod-db-password").get());', "prod-db-password");
	// (A declaration whose type is named for a password declares a variable: the literal is the value, not the line.)
	const out = r().redact(`PasswordAuthentication auth = new PasswordAuthentication("deploy", "${pw}");`).text;
	assert.ok(out.includes('auth = new PasswordAuthentication("deploy", "') && !out.includes(pw), out);
	kept("PasswordEncoder encoder = new BCryptPasswordEncoder();", "encoder = new BCryptPasswordEncoder();");
	hidden("requirepass Kx9mQ2vLp7Rt", "Kx9mQ2vLp7Rt");
});

test("call arguments and object fields that take a secret are hidden: setters, constructors, connect calls, basic auth, JWT and HMAC keys", () => {
	for (const [t, v] of [
		['os.Setenv("STRIPE_API_KEY", "3f7a2c9e1b4d4e8f9a6c2d5b8e1f0a3c")', "3f7a2c9e1b4d4e8f9a6c2d5b8e1f0a3c"],
		['user.setPassword("Harbor#2291x", true);', "Harbor#2291x"],
		['$pdo = new PDO("mysql:host=db;dbname=app", "root", "Harbor#2291x");', "Harbor#2291x"],
		['requests.get(url, auth=("alice", "Harbor#2291x"))', "Harbor#2291x"],
		['if (!"Harbor#2291x".equals(password)) throw', "Harbor#2291x"],
	])
		hidden(t, v);
	for (const [t, v] of [
		["$link = mysqli_connect('db.internal', 'admin', 'P@ssw0rd9', 'mydb');", "P@ssw0rd9"],
		['$cred = [Net.NetworkCredential]::new("admin", "P@ssw0rd!x")', "P@ssw0rd!x"],
	])
		hidden(t, v);
	for (const line of [
		'req.SetBasicAuth("admin", "Harbor2291x")',
		'Credentials.basic("admin", "Harbor2291x")',
		'jwt.sign(payload, "Harbor2291x")',
		'crypto.createHmac("sha256", "Harbor2291x")',
	])
		hidden(line, "Harbor2291x");
	hidden('jwt.verify(token, "Harbor2291xSecret")', "Harbor2291xSecret");
	hidden('const client = twilio(accountSid, "eee7a41d05da5ab7ceecf33ba58a1719");', "eee7a41d05da5ab7ceecf33ba58a1719");
	for (const line of [
		'client.setSigningKey("Harbor4821!x");',
		'client.setPwd("Harbor4821!x");',
		'withBearer("Harbor4821!x")',
		"VAULT_UNSEAL=Harbor4821!x",
	])
		hidden(line, "Harbor4821!x");
	hidden(
		'const pusher = new Pusher({\n  appId: "1234567",\n  key: "a1b2c3d4e5f6a7b8c9d0",\n  secret: "Winter2024passQZ",\n});',
		"Winter2024passQZ",
	);
});

test("declarations in PHP, VB, T-SQL, C++, CMake, AppleScript, R and PowerShell hide their literal", () => {
	const pw = "Winter2024pass";
	hidden(`"${pw}" | ConvertTo-SecureString -AsPlainText -Force`, pw);
	for (const t of [
		"$password='Tr0ub4dor.x';",
		'Password = "youshallnotpass9",',
		'string q = "SERVER=db;UID=sa;PWD=Kd8pQ2zX9mL;";',
	])
		hidden(t, t.match(/Tr0ub4dor\.x|youshallnotpass9|Kd8pQ2zX9mL/)![0]);
	for (const line of [
		'Dim password As String = "Harbor2291!x"',
		"DECLARE @password NVARCHAR(100) = N'Harbor2291!x'",
		'std::string password{"Harbor2291!x"};',
		'set(DB_PASSWORD "Harbor2291!x")',
		'set thePassword to "Harbor2291!x"',
		'password <- "Harbor2291!x"',
		"setx DB_PASSWORD Harbor2291!x",
		"set -gx DB_PASSWORD Harbor2291!x",
		'dotnet user-secrets set "Db:Password" "Harbor2291!x"',
	])
		hidden(line, "Harbor2291!x");
	hidden('Private Shared ApiPassword As String = "Harbor2291x"', "Harbor2291x");
});

test("a default, a fallback, a constant or a heredoc holds a secret literal that is hidden", () => {
	hidden('#define SECRET_PASS "AutumnRipple855"\n', "AutumnRipple855");
	hidden(
		'TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "46dda07e006108e727cff66b3cc89538")',
		"46dda07e006108e727cff66b3cc89538",
	);
	hidden('    password: process.env.DB_PASSWORD ?? "tango.panda9945",', "tango.panda9945");
	hidden('ActiveSupport::SecurityUtils.secure_compare(password, "EmberMeadow277")', "EmberMeadow277");
	hidden("app.use(session({ secret: 'CANYpfso8s%', resave: false }));", "CANYpfso8s%");
	for (const [t, v] of [
		["Your app password for your device: qwhz kfmt vbnr xplo", "qwhz kfmt"],
		['variable "datadog" {\n  sensitive = true\n  default   = "a8f5f167f44f4964e6c998dee827110c"\n}', "a8f5f167f44f"],
		['output "db_password" { value = "Hunter2Prod!x" sensitive = true }', "Hunter2Prod!x"],
		['variable "db_password" {\n  default = <<EOT\nHunter2Prod!x\nEOT\n}', "Hunter2Prod!x"],
		['secret = get_secret("prod/db", default="Xk9mQ2pLrT5vW8")', "Xk9mQ2pLrT5vW8"],
	])
		hidden(t, v);
	const S = "Harbor#2291x";
	for (const [t, v, hint] of [
		[
			"const client = algoliasearch('Q8XK2LP9ZN', '8f2a9c4e1b7d3f6a0c5e2b9d4f7a1c3e'); // admin key, for indexing",
			"8f2a9c4e1b7d",
		],
		['DATABASES_PASSWORD = (\n    "Harbor#2291x"\n)', S],
		["password = <<EOT\nHarbor#2291x\nEOT", S],
		[
			'resource "aws_ssm_parameter" "db" {\n  name  = "/prod/db/password"\n  type  = "SecureString"\n  value = "Harbor#2291x"\n}',
			S,
		],
	] as [string, string, { command?: string }?][])
		hidden(t, v, hint);
});

test("an argv list in code hides a literal password and keeps a variable", () => {
	hidden('subprocess.run(["redis-cli", "-a", "Harbor2291!", "ping"])', "Harbor2291!");
	kept('subprocess.run(["redis-cli", "-a", pw, "ping"])', "pw");
});

test("a plain string in a lookup fallback or a set command is kept", () => {
	for (const t of [
		'region = config.get("region", fallback="us-east-1")',
		'output "bucket" { value = "my-bucket-name" }',
	])
		assert.equal(r().redact(t).text, t);
	kept('set name to "hello world"', "hello world");
});

test("a setter's keyword argument named for the secret is read; other keywords leave its positional secret read", () => {
	hidden('user.set_password("Kq8wZ3nB5vXcT", commit=True)', "Kq8wZ3nB5vXcT");
	hidden('Secret(value="Kq8wZ3nB5vXcT").save("loader-password", overwrite=True)', "Kq8wZ3nB5vXcT");
	// A credentials call given one argument is given the secret; with a user first, the second.
	hidden('creds = Credentials("Kq8wZ3nB5vXcT")', "Kq8wZ3nB5vXcT");
	hidden('client.setCredentials("admin", "Kq8wZ3nB5vXcT", "realm")', "Kq8wZ3nB5vXcT");
	// The secret's slot named, the positional arguments are the service and the user.
	kept('keyring.set_password("myapp", "deploy-bot-7", password=pw)', "deploy-bot-7");
});

test("a connect or login call's password is read at its place, not a page object's argument there", () => {
	hidden('server.login("bob@example.com", "violet.indigo9079")', "violet.indigo9079");
	kept('page.login("https://app.example.com/login", "qa_admin_02", pw)', "qa_admin_02");
	kept('$link = mysqli_connect(hostname: "db.internal", username: "app", database: "shop_prod_eu");', "shop_prod_eu");
});

test("a setting set by name: a config path's colons are a name's, a route's slashes are not", () => {
	hidden("nconf.set('database:password', 'violet.indigo9079');", "violet.indigo9079");
	kept("$router->get('/oauth/token', 'OAuth2Controller@token');", "OAuth2Controller@token");
});

test("WordPress's generated keys and salts are hidden; the sample phrase and a cache's prefix are kept", () => {
	const key = "L|Dq8~z;(3fT]j?-Kf%Gz*w9 nN,%2hP)A>e4X~!b+H{qo-Y 7vR#mTl^sW&:Z1";
	hidden(`define('AUTH_SALT',        '${key}');`, key);
	kept("define( 'AUTH_KEY', 'put your unique phrase here' );", "put your unique phrase here");
	kept("define('WP_CACHE_KEY_SALT', 'mysite_production_object_cache_v2');", "mysite_production_object_cache_v2");
});

test("a credential compared with a literal, by its method or an operator, is hidden; its type is not", () => {
	hidden('if (password.equals("violet.indigo9079")) {', "violet.indigo9079");
	hidden('if (password !== "violet.indigo9079") throw new Error("denied");', "violet.indigo9079");
	kept("if (typeof password === 'function') password = password();", "'function'");
	// A form's other fields are filled with what they name.
	kept("await page.fill('#username', 'qa-user-7Xk2');", "qa-user-7Xk2");
});

test("a conditional in code that a JSON string holds is read once decoded, not across the string's end", () => {
	kept('{"cmd": "pw = ready ? \\"a\\" : y", "user": "deploy-bot42"}', "deploy-bot42");
});

test("Terraform's and JSON's values: a block's own attributes, a pair's sibling name, what a sensitive mark reaches", () => {
	hidden(
		'variable "db_password" {\n  description = <<EOT\nGive it as {user}:{password, or {token\nEOT\n  default = "Kq8wZ3nB5vXcT"\n}',
		"Kq8wZ3nB5vXcT",
	);
	// (The pair's name is its string sibling, not the number before it.)
	const pair = '{"id": 17, "name": "DB_PASSWORD", "value": "violet.indigo9079"}';
	hidden(pair, "violet.indigo9079");
	kept(pair, '"name": "DB_PASSWORD"');
	// A sensitive value that is JSON is read by its own names; a word marked sensitive is still a word.
	kept(
		'{"sensitive": true, "value": "{\\"username\\": \\"admin\\", \\"password\\": \\"Kq8wZ3nB5vXcT\\"}"}',
		'\\"username\\": \\"admin\\"',
	);
	kept('{"sensitive": true, "type": "string", "value": "postgres"}', "postgres");
	// A state's secret is hidden and the paths it lists as sensitive kept; a plan's change holds the secret too.
	const state =
		'{"type": "random_password", "instances": [{"attributes": {"result": "Hx7mQ2pL9vRt4wZk"}, "sensitive_attributes": [[{"type": "get_attr", "value": "override_special_chars"}]]}]}';
	hidden(state, "Hx7mQ2pL9vRt4wZk");
	kept(state, "override_special_chars");
	hidden(
		'{"resource_changes": [{"type": "random_password", "change": {"actions": ["delete"], "before": {"length": 12, "result": "tango-Panda-9945"}, "after": null}}]}',
		"tango-Panda-9945",
	);
});

test("a Go import block ends at its `)`, and Python's `import (` within a line opens none", () => {
	hidden('import (\n\t"fmt"\n)\nstorePassword "violet.indigo9079";', "violet.indigo9079");
	hidden('from app.models import (User, Token)\nstorePassword "violet.indigo9079";', "violet.indigo9079");
});

test("an interpolated string's holes are code, in the value's own string or the one its pair stands in", () => {
	kept('conn = $"Pwd={pw};User={u}"', "{pw};User={u}");
	kept('dsn = f"host={h} password={pw}xyz"', "{pw}xyz");
	// (A connection string in quotes: a value ends at the next `;name=`.)
	hidden('conn = "Server=db;Pwd=Xk9mQ2pLrT;User Id=sa"', "Xk9mQ2pLrT");
	kept('conn = "Server=db;Pwd=Xk9mQ2pLrT;User Id=sa"', "User Id=sa");
});

test("a Markdown code fence opens no template literal: the calls inside it are read", () => {
	const java = 'cfg.setUsername("jenkins");\ncfg.setPassword("Winter1!!");';
	const php = "<?php\ndefine( 'DB_PASSWORD', 'O9FyDB0k=HtE4' );";
	for (const [code, secret] of [
		[java, "Winter1!!"],
		[php, "O9FyDB0k=HtE4"],
	]) {
		hidden("```\n" + code + "\n```", secret);
		hidden("Here's what it printed:\n\n```java\n" + code + "\n```\n\nAnything look off?", secret);
		hidden("~~~\n" + code + "\n~~~", secret);
	}
});

test("a call that takes a secret is read in its older forms: jjwt's algorithm first, Jersey's basic", () => {
	for (const line of [
		'Jwts.builder().setSubject("u").signWith(SignatureAlgorithm.HS512, "Harbor2291xSecret").compact();',
		'Jwts.builder().signWith("Harbor2291xSecret").compact();',
		'HttpAuthenticationFeature.basic("admin", "Harbor2291xSecret")',
		'client.register(HttpAuthenticationFeature.basic("admin", "Harbor2291xSecret"));',
	])
		hidden(line, "Harbor2291xSecret");
	kept("Jwts.builder().signWith(key, SignatureAlgorithm.HS256).compact();", "SignatureAlgorithm.HS256");
	kept('Feature.basic("standard", "configuration")', "configuration");
});

test("a command that sets a variable takes its options before the name: setx /M, fish's long options", () => {
	for (const line of [
		"setx /M DB_PASSWORD Harbor2291!x",
		"setx DB_PASSWORD Harbor2291!x /M",
		"set --export DB_PASSWORD Harbor2291!x",
		"set -gx --path DB_PASSWORD Harbor2291!x",
		"set --global --export DB_PASSWORD Harbor2291!x",
	])
		hidden(line, "Harbor2291!x");
	kept("setx /M PATH C:\\tools\\bin", "C:\\tools\\bin");
	kept("set --export EDITOR vim", "vim");
});

test("an expression beside a credential's name in HCL is code; a literal there is the value", () => {
	for (const ref of [
		"random_password.db.result",
		"aws_secretsmanager_secret_version.db.secret_string",
		"var.db_password",
	])
		kept(
			`resource "aws_ssm_parameter" "db" {\n  name  = "db_password"\n  type  = "SecureString"\n  value = ${ref}\n}\n`,
			ref,
			{ path: "ssm.tf" },
		);
	hidden(
		'resource "aws_ssm_parameter" "db" {\n  name  = "db_password"\n  type  = "SecureString"\n  value = "Harbor2291!x"\n}\n',
		"Harbor2291!x",
		{ path: "ssm.tf" },
	);
	hidden("- name: DB_PASSWORD\n  value: Harbor2291x\n", "Harbor2291x");
	hidden("<input name=password value=Harbor2291x>", "Harbor2291x");
});

test("a form fill's options, a key pressed after it and calls between the field and the fill leave the value its", () => {
	for (const text of [
		"cy.get('#password').type('Xq7#Lm2vRt9Kp4Wz', { log: false })",
		"await page.fill('#password', 'Xq7#Lm2vRt9Kp4Wz', { timeout: 5000 })",
		"await page.type('#password', 'Xq7#Lm2vRt9Kp4Wz', { delay: 100 })",
		'driver.find_element(By.ID, "password").send_keys("Xq7#Lm2vRt9Kp4Wz", Keys.ENTER)',
		'driver.findElement(By.id("password")).sendKeys("Xq7#Lm2vRt9Kp4Wz" + Keys.RETURN);',
		"await page.getByLabel('Password', { exact: true }).fill('Xq7#Lm2vRt9Kp4Wz')",
		"await page.locator('#password').first().fill('Xq7#Lm2vRt9Kp4Wz')",
		"cy.get('[name=\"password\"]').clear().type('Xq7#Lm2vRt9Kp4Wz')",
		"await page.getByLabel('Password').fill('Xq7#Lm2vRt9Kp4Wz', { force: true })",
	]) {
		hidden(text, "Xq7#Lm2vRt9Kp4Wz");
		kept(text, /\{ \w+: \w+ \}|Keys\.\w+|\.(?:first|clear)\(\)|getBy\w+\('Password'/.exec(text)?.[0] ?? "Xq7#");
	}
	kept("cy.get('#search').type('Xq7#Lm2vRt9Kp4Wz', { log: false })", "Xq7#Lm2vRt9Kp4Wz");
	kept("await page.getByLabel('Username', { exact: true }).fill('qa-user-7Xk2Lm9')", "qa-user-7Xk2Lm9");
});

test("a literal converted where it's given, `.toCharArray()`, `.trim()`, `String.valueOf(…)`, is the value", () => {
	for (const text of [
		'cfg.setPassword("Xq7#Lm2vRt9Kp4Wz".toCharArray());',
		'new PasswordAuthentication("bob", "Xq7#Lm2vRt9Kp4Wz".toCharArray());',
		'cfg.setPassword(String.valueOf("Xq7#Lm2vRt9Kp4Wz"));',
		'cfg.setPassword("Xq7#Lm2vRt9Kp4Wz".trim());',
		'client.setPassword(Buffer.from("Xq7#Lm2vRt9Kp4Wz"));',
	]) {
		hidden(text, "Xq7#Lm2vRt9Kp4Wz");
		kept(text, /\.toCharArray\(\)|\.trim\(\)|String\.valueOf\("|Buffer\.from\("/.exec(text)![0]);
	}
	kept('cfg.setUsername("deploy-user".toCharArray());', "deploy-user");
});

test("a credential asserted equal to a literal, in either order or chained, is that literal", () => {
	for (const text of [
		'assertEquals(config.getPassword(), "Xq7#Lm2vRt9Kp4Wz");',
		'self.assertEqual(cfg.password, "Xq7#Lm2vRt9Kp4Wz")',
		'assert_eq!(cfg.password, "Xq7#Lm2vRt9Kp4Wz");',
		'Assert.AreEqual("Xq7#Lm2vRt9Kp4Wz", cfg.Password);',
		'assertThat(cfg.getPassword()).isEqualTo("Xq7#Lm2vRt9Kp4Wz");',
		"expect(cfg.password).toEqual('Xq7#Lm2vRt9Kp4Wz')",
	])
		hidden(text, "Xq7#Lm2vRt9Kp4Wz");
	kept('assertEquals(config.getUsername(), "deploy-user");', "deploy-user");
	kept('self.assertEqual(cfg.password_hash_scheme, "pbkdf2_sha256")', "pbkdf2_sha256");
	kept("expect(cfg.passwordMinLength).toBe(12)", "toBe(12)");
});
