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
