/**
 * Values that are code or labels: types, labels in other languages, famous stand-ins, documentation placeholders,
 * listings, and the code around a credential word.
 *
 *   node --test test/code-shapes.test.ts
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { Redactor } from "../src/index.ts";
import { b62, hidden, kept, r } from "./helpers.ts";

test("built-in type names are types", () => {
	kept("interface S {\n  secret: Uint8Array;\n  key: CryptoKey;\n}", "secret: Uint8Array;");
	kept(
		"type Keys = { signingKey: Uint8Array; verifyKey: Uint8Array | KeyLike };",
		"signingKey: Uint8Array; verifyKey: Uint8Array | KeyLike",
	);
	kept("type T = { secret: ArrayBuffer, token: Buffer }", "secret: ArrayBuffer, token: Buffer");
	kept("class A { private apiKey: BigUint64Array; }", "BigUint64Array");
});

test("a generic type annotation is not a value", () => {
	kept("    let password: Secret<String> = settings.db.password.clone();", "Secret<String>");
	kept("41 +     let password: Secret<String> = settings.x();", "Secret<String>");
	kept("let token: Option<Vec<u8>> = None;", "Option<Vec<u8>>");
	hidden("password: Dragon<Fire>", "Dragon<Fire>");
});

test("a password label with a note is a label", () => {
	kept('"passphrase": "Phrase de passe (facultative)"', "Phrase de passe (facultative)");
	kept('"pw": "Contraseña (opcional)"', "Contraseña (opcional)");
	hidden('"password": "Wachtwoord (Xk9mQ2vL)"', "Xk9mQ2vL");
});

test("the famous four words joined as one identifier are a stand-in; spaced, a passphrase in their style", () => {
	kept('hashPassword("correct-horse-battery-staple")', "correct-horse-battery-staple");
	kept("password: correct_horse_battery_staple", "correct_horse_battery_staple");
	hidden('hashPassword("correct horse battery staple")', "correct horse battery staple");
	hidden("DB_PASSWORD=correct horse battery staple", "correct horse battery staple");
});

test("a GraphQL field's type is not a value", () => {
	kept("input A {\n  password: String! @constraint(minLength: 12)\n}", "String! @constraint(minLength: 12)");
	kept("tokens: [String!]!", "[String!]!");
	hidden("password: Hunter2!", "Hunter2!");
});

test("a single-table sort key beside its partition key is not a secret", () => {
	kept("{\n  PK: 'CUSTOMER#c_8812',\n  SK: 'ORDER#2026-09-30#o_4411',\n}", "ORDER#2026-09-30#o_4411");
	kept('{"pk": "USER#42", "sk": "ORDER#2026#o_44119"}', "ORDER#2026#o_44119");
});

test("documentation examples, variable references and placeholders are kept under a credential name", () => {
	kept("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE");
	kept("api_key: ${API_KEY}", "${API_KEY}");
	kept('password: "{{ .Values.password }}"', "{{ .Values.password }}");
	kept("OPENAI_API_KEY=your-api-key-here", "your-api-key-here");
	kept("const key = process.env.STRIPE_SECRET_KEY;", "process.env.STRIPE_SECRET_KEY");
	kept("password = os.environ['DB_PASSWORD']", "os.environ['DB_PASSWORD']");
	kept("redis://[[username]:[password]]@localhost:6379/0", "[password]]");
	kept("$ http -a username:password pie.dev/basic-auth/username/password", "username:password");
	kept("BASIC_AUTH_HEADER_VALUE = 'Basic dXNlcjpwYXNzd29yZA=='", "dXNlcjpwYXNzd29yZA==");
	kept("http://theusername:thepassword@localhost", "thepassword");
	kept("ghp\x5fdeadbeefdeadbeefdeadbeefdeadbeefdead", "ghp\x5fdeadbeef");
	for (const [t, v] of [
		["grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA&redirect_uri=x", "SplxlOBeZQQYbYS6WxSbIA"],
		['{"access_token":"2YotnFZFEjr1zCsicMWpAA","refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA"}', "2YotnFZFEjr1zCsicMWpAA"],
		["code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "dBjftJeZ4CVP"],
		['assert.Equal(t, []byte("JBSWY3DPEHPK3PXP"), configs[0].Secret)', "JBSWY3DPEHPK3PXP"],
	])
		kept(t, v);
	for (const line of ["password: [REDACTED-SECRET]", "token: <REDACTED_TOKEN>"]) kept(line, line.replace(/^\w+: /, ""));
	for (const line of [
		"Collecting azure-keyvault-keys==4.12.0b2 (from -r requirements.txt)",
		"django-secrets==0.1.dev3",
	])
		kept(line, line.match(/==(\S+)/)![1]);
});

test("listings, tables, directives and settings that contain a credential word come out unchanged", () => {
	kept("switch:\n  - platform: gpio\n    pin: GPIO21\n", "GPIO21");
	kept("passwd:         files systemd\ngroup:          files systemd\n", "files systemd");
	kept("# /etc/pam.d/common-password\npassword\trequisite\t\t\tpam_pwquality.so retry=3\n", "requisite");
	kept('DEBUG=pw:api npx playwright test\npw:api navigating to "http://localhost:3000/"', "pw:api navigating");
	kept(
		`NAME              DIGEST            CREATED AT\nDATABASE_PASSWORD e17ed70e01f58de5  2 days ago`,
		"e17ed70e01f58de5",
	);
	kept(`    password: 16 bytes`, "16 bytes");
	kept("status | count\npass   | 41/41\nfail   | 0/41", "41/41");
	for (const t of [
		"cloud\t\t\tissue\t\tpasswd-\t\t     subgid\ncron.d\t\t\tissue.net\tperl\t\t     subuid",
		"        proxy_pass http://app_backend_8f3k2;",
		"    fastcgi_pass unix:/run/php/php8.2-fpm.sock;",
		"OLLAMA_MODEL=hf.co/unsloth/diffusiongemma-26B-A4B-it-GGUF:Q4_K_M",
		'"responseId":"gen-1779182113-4Fn9q7I4bvDXGPngLElv"',
		"GET /v1/orders?cursor=eyJpZCI6NDA2OTYwMiwiY3JlYXRlZF9hdCI6IjIwMjUtMDUifQ HTTP/1.1",
		'oauth_consumer_key="9djdj82h48djs9d2", oauth_token="kkk9d7dh3k39sjv7"',
		"Request-Id: |0fb19ba4a8fd7b064414365c1fdce1ff.1976ab59e12b6943",
	])
		assert.equal(r().redact(t).text, t);
	kept("chage   gpasswd  passwd  su\nchfn    groups   ping    sync", "groups   ping");
});

test("code that mentions a credential word is kept: calls, member paths, endpoints, expressions", () => {
	// Calls, member paths, endpoints, chained assignments, a struct literal's identifier, a regex and arithmetic after a credential word are code.
	kept('contraseña = os.getenv("DB_PASS")', "os.getenv");
	kept("enclave=sgx-enclave-1", "sgx-enclave-1");
	kept('password_bytes = password.encode("latin1")', "latin1");
	kept("pwd && ls -la src/", "ls -la");
	kept("token_provider=AccessTokenProvider", "AccessTokenProvider");
	kept("pass=$$((pass+1)); \\", "$$((pass+1");
	kept("    password=credentials.value,", "credentials.value");
	kept("    password=generate_password_hash(self.password.data),", "generate_password_hash");
	kept('authorization: "https://www.bungie.net/en/OAuth/Authorize?reauth=true",', "https://www.bungie.net");
	kept('req.Header.Set("Authorization", in.authorizationHeader)', "in.authorizationHeader");
	kept(
		'm.default.createElement("label",null,"Password:"),h?m.default.createElement("code",null," ****** ")',
		"),h?m.default",
	);
	kept("t.authorizePassword=t.preAuthorizeImplicit=t.CONFIGURE_AUTH=void 0;", "t.preAuthorizeImplicit");
	kept("\tIssuerPrivateKey: keyRSA2048,", "keyRSA2048");
	kept("pw2 = m.password2", "m.password2");
	kept("token: `r'-?\\d+\\.?[0-9A-F]*([eE][+-]?\\d+)?(h)'` - requires 'h' suffix", "[0-9A-F]");
	kept("data = {'subscriptions_client_secret': '$encrypted$'}", "$encrypted$");
	kept("request.headers = {'Authorization': 'Basic dGVzdA=='}", "dGVzdA==");
	for (const t of [
		"passwd: account.password",
		"  proxy_pass http://app:8000;",
		"the private key is x25519.X25519PrivateKey.from_private_bytes(raw)",
		'SnowflakeCredentials(account="xy12345.us-east-1", user="PREFECT_SVC")',
		"PASS: tests/test_auth.py::test_login",
		'hour_key = "%Y-%m-%dT%H"',
		"{'Bucket': 'rustup-builds', 'Key': '2a85a8e79fbf37282a85a8e79fbf37282a85a8e7/dist/x.tar.gz'}",
	])
		assert.equal(r().redact(t).text, t);
	const t = "[server]\nhttp_port = 3000\npassword = input('Password: ')";
	assert.equal(r().redact(t).text, t);
	for (const t of ["mongodb+srv://admin:<password>@c.mongodb.net", 'if [ "$X" == "y" ]; then'])
		assert.equal(r().redact(t).text, t);
	kept("$q = \"SELECT * FROM u WHERE name='$user' AND password=md5('$password')\";", "md5(");
	kept('x = URLEncoder.encode(password, "UTF-8")', "URLEncoder.encode(password");
	kept('password=EnvVar("SNOWFLAKE_PASSWORD"),', "SNOWFLAKE_PASSWORD");
	kept(
		'SERVICE_SET_GUEST_WIFI_PW = "set_guest_wifi_password"\n\nasync def _async_set_guest_wifi_password(call):',
		"_async_set_guest_wifi_password(",
	);
	kept(
		"use windows_sys::Win32::Security::Authorization::GetNamedSecurityInfoW;",
		"Authorization::GetNamedSecurityInfoW",
	);
	kept('@box.pass_("database_session")', "database_session");
	kept("SELECT * FROM users WHERE password = @pw", "@pw");
	kept("    storePassword file('keystore.pass').text.trim()", "file('keystore.pass')");
});

test("schema output, validation rules, XML builders and interpolation holes are code", () => {
	const xml = JSON.stringify({ text: 'xml = "<username>"+usr+"</username><password>"+passwd+"</password>";' });
	assert.equal(r().redact(xml).text, xml);
	for (const t of [
		"| password        | varchar(255) | NO   |     | NULL    |                |",
		"  password VARCHAR(255) NOT NULL,",
		"        'password' => 'required|string|min:8|confirmed',",
		'conn.ConnectionString = "Provider=SQLOLEDB;Data Source=" & server & ";Password=" & txtPassword.Text & ";"',
		'url = f"postgres://{user}:{quote_plus(password)}@{host}/app"',
		"subprocess.run(cmd, env=dict(os.environ, PGPASSWORD=quote(pw)))",
		"      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?required}",
		"PASSWORD=`openssl rand -hex 16`",
		"        password: Wachtwoord",
	])
		assert.equal(r().redact(t).text, t);
});

test("a well-known default password is kept", () => {
	const t =
		"keytool -list -v -keystore ~/.android/debug.keystore -alias androiddebugkey -storepass android -keypass android";
	assert.equal(r().redact(t).text, t);
});

test("labels in other scripts and locales are not passwords", () => {
	for (const [line, label] of [
		['{"password": "Пароль"}', "Пароль"],
		['"password": "Введите пароль",', "Введите пароль"],
		['password: "パスワードを入力"', "パスワードを入力"],
		["LINE_CHANNEL_SECRET=<チャネルシークレット>", "チャネルシークレット"],
	])
		kept(line, label);
	// A UI string in another script is a label with its stars, holes, counts and slashes; a password in it is letters
	// glued to digits or symbols.
	for (const label of [
		"パスワード*",
		"パスワード/Password",
		"パスワードは%d文字以上",
		"パスワード(8〜20文字)",
		"パスワード：英数字8文字以上",
		"请输入6位密码",
		"密码错误，还剩%d次机会",
		"비밀번호/PIN",
		"Пароль%s",
		"סיסמה*",
	])
		kept(`{"password":"${label}"}`, label);
	kept("sk: Slovensky", "Slovensky");
});

test("a declaration's type is no value, nor a generic type in an interface, but a bare name there is", () => {
	for (const line of ["val passwordData: PasswordData?,", "privateKey: Uint8Array;"])
		kept(line, line.replace(/^.*: /, "").replace(/[?,;]+$/, ""));
	for (const type of ['Branded<string, "Password">', "Opaque<string>", "Secret<String>"])
		kept(`interface A {\n  password: ${type};\n}`, type);
	hidden("interface A {\n  password: Kx9mQ2vL7pZr;\n}", "Kx9mQ2vL7pZr");
});

test("a port in a list is no password", () => {
	kept("x = ['http://localhost:8080','a@b.com']", "8080");
});

test("an entry of a call or a literal written over several lines is code, not an env or YAML line", () => {
	const off = new Redactor({ guessing: "off", fingerprintKey: "test" });
	for (const [text, value] of [
		[
			"        await login(\n            password=user_input[CONF_PASSWORD],\n            session=s,\n        )",
			"user_input[CONF_PASSWORD]",
		],
		["    {\n        'user': 'ci',\n        'password': None},\n", "None"],
		[
			'tests := map[string]testCase{\n\t"missing": {\n\t\tPassword: &dbplugin.ChangePassword{\n\t\t\tNewPassword: "",',
			"&dbplugin.ChangePassword{",
		],
		["Entry(\n    key=sha1(uuid4().bytes).hexdigest(),\n)", "sha1(uuid4().bytes).hexdigest()"],
	])
		assert.ok(off.redact(text).text.includes(value), text);
	// A literal in the entry is still read, and a quoted `NAME=value` pair in a list is a literal.
	hidden("creds = {\n    'user': 'ci',\n    'password': 'Hx7mQ2pL9vRt4',\n}", "Hx7mQ2pL9vRt4");
	hidden(
		'"Env": [\n    "DATABASE_HOST=db",\n    "DB_PASSWORD=aspen.garnet.lava.sage.cinder",\n]',
		"aspen.garnet.lava.sage.cinder",
	);
});

test("a struct's fields and their types are no table, and a package's import alias no credential", () => {
	const off = new Redactor({ guessing: "off", fingerprintKey: "test" });
	const struct =
		"type connectionInfo struct {\n\tUser           string\n\tPassword       string\n\tHostKey        string\n\tPort           uint16\n\tTimeout        time.Duration\n}";
	assert.equal(off.redact(struct).text, struct);
	const imports = 'import (\n\t"fmt"\n\tpwd "github.com/hashicorp/go-secure-stdlib/password"\n)';
	assert.equal(off.redact(imports).text, imports);
	// A table with a password column is still one.
	hidden("USER           PASSWORD       HOST\nalice          Xk9#mPq2vL     db1\n", "Xk9#mPq2vL");
});

test("a parameter's type before its default is no value; the default is", () => {
	kept("def extract_text(pdf_file: FileOrName, password: str='', page_numbers=None):", "password: str=''");
	hidden("def connect(password: str='Hx7mQ2pL9vRt4'):", "Hx7mQ2pL9vRt4");
});

test("OpenSSL's stack functions are no secret keys", () => {
	kept("if (!ossl_cmp_ctx_set0_statusString(ctx, sk_ASN1_UTF8STRING_new_null()))", "sk_ASN1_UTF8STRING_new_null");
	kept("    sk_X509_NAME_ENTRY_pop_free(entries, X509_NAME_ENTRY_free);", "sk_X509_NAME_ENTRY_pop_free");
});

test("code's joints and operators separate no seed phrase's words", () => {
	const code =
		'        _advance(chunk.output_index)\n        tool_output = chunk.item.model_dump(exclude_none=True, mode="json")\n        tool_output["index"] = current_index\n        content.append(tool_output)\n    elif (\n        chunk.type == "response.output_item.done"\n        and chunk.item.type == "custom_tool_call"\n    ):\n        _advance(chunk.output_index)\n        tool_output = chunk.item.model_dump(exclude_none=True, mode="json")\n';
	assert.equal(new Redactor({ guessing: "off", fingerprintKey: "test" }).redact(code).text, code);
});

test("a value's syntax says it is no credential: country codes, ternaries, XAML, prompts, comments, types", () => {
	const off = new Redactor({ guessing: "off", fingerprintKey: "test" });
	for (const [text, value] of [
		['{"AF":"Afghanistan","AL":"Albania","DZ":"Algeria","SK":"Slovakia","PW":"Palau","SI":"Slovenia"}', "Slovakia"],
		["    'confirmation question should '.($expected ? 'pass' : 'cancel'));", "cancel"],
		['    <converter:Minus10Converter x:Key="Minus10Converter" />', "Minus10Converter"],
		["    SET /P KEYSTORE_PASSWORD=Elasticsearch keystore password:", "Elasticsearch"],
		["sa-token: # any name will do\n    redis:", "# any name will do"],
		["  public decode(secret: Base32SecretKey): SecretKey {", "Base32SecretKey"],
		[
			'            \'PublicKey(key_id="568250167242549743", key="g0y8X95+p3dndYPe9Bx5h1l/qHwUH5UUGnYQlzJ2cg2=")\',',
			"g0y8X95+p3dndYPe9Bx5h1l",
		],
		['    "passphrase": "{AQAAABAAAAAQmEZaw8Ev9tClXWVQye1TR2KgF3p/wGoYs/TEQCmsxCk=}",', "AQAAABAAAAAQmEZaw8Ev9tCl"],
		['    bindKey: bindKey("Alt-Left|Home", "Command-Left|Home|Ctrl-A"),', "Command-Left|Home|Ctrl-A"],
		['<PasswordBox Password="{Binding LightBrush, Mode=OneWay}" />', "{Binding LightBrush, Mode=OneWay}"],
		['  Password: <input name="password" type="password"><br>', '<input name="password" type="password">'],
		['    "ChangePassword": "iam:ChangePassword",', "iam:ChangePassword"],
	])
		assert.ok(off.redact(text).text.includes(value), text);
	// The same places with a credential in them are read as before.
	hidden('config = {"SK": "Hx7mQ2pL9vRt4wZ"}', "Hx7mQ2pL9vRt4wZ");
	hidden("password: SunnySecret)", "SunnySecret");
	hidden('DB_PASSWORD="admin:Hx7mQ2pL9vRt"', "Hx7mQ2pL9vRt");
	hidden(
		'func openDB() (*sql.DB, error) {\n\treturn sql.Open("pgx", "host=db user=readonly password=glacier.ruby.reef.birch.iris.hickory dbname=export")\n}\n',
		"glacier.ruby.reef.birch.iris.hickory",
	);
});

test("code that computes a value holds none: typeof, function heads, references, expansions, an empty variable", () => {
	const off = new Redactor({ guessing: "off", fingerprintKey: "test" });
	for (const [text, value] of [
		["    if (typeof this.password === 'function') {", "function"],
		["    if (typeof passwordUpdaterDestr === 'function') {", "function"],
		["  password: function password() {", "function password()"],
		["_pass () {\n  echo hi\n}", "() {"],
		["    pass: process.env.SMTP_PASSWORD", "process.env.SMTP_PASSWORD"],
		["    password: this.template.users[user].data.password", "this.template.users[user].data.password"],
		['mysql_root_password="$RANDOM***$RANDOM"', "$RANDOM***$RANDOM"],
		["set passwd=%RANDOM%@%RANDOM%", "%RANDOM%@%RANDOM%"],
		['PASSWD="${*}"', "${*}"],
		["$ MYSQL_USER=root MYSQL_PASSWORD= FILTER=integration npm test", "FILTER=integration"],
	])
		assert.ok(off.redact(text).text.includes(value), text);
	// A literal among them is read as before.
	hidden('        String password = "!@#$%^&*()|\\\\<>/?";', "!@#$%^&*()|");
	hidden("if ($auth['password'] === 'Hx7mQ2pL9vRt4') {", "Hx7mQ2pL9vRt4");
	hidden('DB_PASSWORD="Pa$$WORD"', "Pa$$WORD");
	hidden("The password is: BlueSecret", "BlueSecret");
	hidden("MYSQL_PASSWORD=Hx7mQ2pL9vRt FILTER=integration", "Hx7mQ2pL9vRt");
});

test("a key's label above its PEM block, a placeholder naming its variable, a hashing scheme: no credentials", () => {
	const body = Array.from({ length: 4 }, () => b62(64)).join("\n");
	const pem = `PrivateKey=ALICE_cf_c2pnb163v1\n-----BEGIN PRIVATE KEY-----\n${body}\n-----END PRIVATE KEY-----`;
	const out = r().redact(pem).text;
	assert.ok(out.includes("ALICE_cf_c2pnb163v1") && !out.includes(body.slice(0, 64)), out);
	const curve = r().redact(pem.replace("ALICE_cf_c2pnb163v1", "SECP521R1_RFC5903-Peer")).text;
	assert.ok(curve.includes("SECP521R1_RFC5903-Peer") && !curve.includes(body.slice(0, 64)), curve);
	for (const [text, value] of [
		["POSTGRES_PASSWORD=!!!SET POSTGRES_PASSWORD!!!", "!!!SET POSTGRES_PASSWORD!!!"],
		["- ELASTIC_PASSWORD=$ELASTIC_PASSWORD <1>", "$ELASTIC_PASSWORD <1>"],
		[`await self.con.execute("SET password_encryption = 'scram-sha-256';")`, "scram-sha-256"],
	])
		assert.ok(r().redact(text).text.includes(value), text);
	// The same places with a credential in them are read as before.
	hidden("PrivateKey=Hx7mQ2pL9vRt4wZkLq8s\n-----BEGIN PRIVATE KEY-----", "Hx7mQ2pL9vRt4wZkLq8s");
	hidden("API_TOKEN=API_TOKEN_9fQ2mL7vXz3pR8sNw4Kd", "9fQ2mL7vXz3pR8sNw4Kd");
	hidden("sed -i '/# DBPassword=/a\\DBPassword=Hx7mQ2pL9vRt' /etc/zabbix_server.conf", "Hx7mQ2pL9vRt");
	hidden("ENCRYPTION_KEY=Hx7mQ2pL9vRt4wZkLq8s", "Hx7mQ2pL9vRt4wZkLq8s");
	hidden("password_encryption = Hx7mQ2pL9vRt", "Hx7mQ2pL9vRt");
});

test("references in other languages' syntax are kept: PowerShell's environment, PHP's variables run together", () => {
	kept("#      arguments: -ConfigFile $(Build.SourcesDirectory)/NuGet.config -Password $Env:Token", "$Env:Token");
	kept('      $accessTokenParameter="?access_token=$($env:HelixApiAccessToken)"', "$($env:HelixApiAccessToken)");
	kept("token=${env:API_TOKEN}", "${env:API_TOKEN}");
	const php =
		'  $nvpreq = "METHOD=$methodName_&PWD=$API_Password&USER=$API_UserName&SIGNATURE=$API_Signature$nvpStr_";';
	kept(php, "$API_Password");
	kept(php, "$API_Signature$nvpStr_");
	// The same places with a credential in them are read as before.
	hidden("-Password Hx7mQ2pL9vRt4", "Hx7mQ2pL9vRt4");
	hidden('$env:DB_PASSWORD = "Hx7mQ2pL9vRt4"', "Hx7mQ2pL9vRt4");
	hidden('$nvpreq = "METHOD=$methodName_&PWD=$Hx7mQ2pLvRtq&USER=$API_UserName";', "$Hx7mQ2pLvRtq");
	hidden('$nvpreq = "METHOD=$methodName_&PWD=Hx7m$Q2pL9vRt4&USER=$API_UserName";', "Hx7m$Q2pL9vRt4");
});

test("code around a credential's name: a subexpression, a sigil's variable, a call over lines, a null compared", () => {
	kept(
		"Set-ADAccountPassword -Identity $u -NewPassword (ConvertTo-SecureString $pw -AsPlainText -Force)",
		"(ConvertTo",
	);
	kept('@key=map("%ymm$_",(16..31));', 'map("%ymm$_",(16..31));');
	kept('            ],\n        ),\n        MasterUserPassword=Join(\n            "",', "Join(");
	kept("        dataSource.setPassword(password2==null?password:password2);", "null?password:password2");
	// The same places with a credential in them are read as before.
	hidden("New-MachineAccount -Password $(ConvertTo-SecureString 'Hx7mQ2pL9vRt4' -AsPlainText -Force)", "Hx7mQ2pL9vRt4");
	hidden('$password = "Hx7mQ2pL9vRt4";', "Hx7mQ2pL9vRt4");
	hidden("$DB_PASSWORD=Hx7mQ2pL9vRt4", "Hx7mQ2pL9vRt4");
	hidden('        ),\n        MasterUserPassword="Hx7mQ2pL9vRt4",', "Hx7mQ2pL9vRt4");
	hidden("        ),\n        MasterUserPassword=Hx7mQ2pL9vRt4(", "Hx7mQ2pL9vRt4");
	hidden('if (password == "Hx7mQ2pL9vRt4") {', "Hx7mQ2pL9vRt4");
});

test("a password hasher's name and a word in any script are no credentials", () => {
	kept("        encoded_weak_salt = make_password('lètmein', 'iodizedsalt', 'pbkdf2_sha256')", "pbkdf2_sha256");
	kept("hasher: sha512_crypt", "sha512_crypt");
	const tr = "Tam güvenlik için, Aria2'yi başlatırken (--rpc-secret bayrağını kullanın) ve bir yetkilendirme";
	kept(`"${tr}",`, "bayrağını");
	// The same places with a credential in them are read as before.
	hidden("user.set_password('Hx7mQ2pL9vRt4')", "Hx7mQ2pL9vRt4");
	hidden("aria2c --rpc-secret Hx7mQ2pL9vRt4wZk", "Hx7mQ2pL9vRt4wZk");
});

test("a query string's value ends at its next pair, percent-encoded too; a password's own & doesn't end it", () => {
	const base =
		'\t\tString baseString = "POST&http%3A%2F%2Flocalhost%3A8080%2Fsparklr%2Fphoto%2F1&oauth_consumer_key%3Dtonr-consumer-key%26oauth_nonce%3D0df9f35f%26oauth_timestamp%3D1204899002%26oauth_version%3D1.0";';
	kept(base, "oauth_nonce%3D0df9f35f%26oauth_timestamp%3D1204899002%26oauth_version%3D1.0");
	const key = b62(24);
	hidden(`oauth_consumer_key=tonr-consumer-key&oauth_nonce=0df9f35f&oauth_token=${key}`, key);
	hidden(`API_KEY=${key}&foo=bar`, key);
	hidden("DB_PASSWORD=Tr0ub4dor&3horse", "Tr0ub4dor&3horse");
});

test("words that label or describe a credential: a translation, an option's own name, a parameter's doc, a stand-in", () => {
	for (const [text, value] of [
		["  email:\n    confirmation:\n      confirm_password: Bevestig mijn account", "Bevestig mijn account"],
		["      confirm_password: Confirmar minha conta", "Confirmar minha conta"],
		["  dpl bintray --user user --key key --file file --passphrase phrase --cleanup", "--passphrase phrase"],
		["  --passphrase PHRASE      Passphrase as configured on Bintray (type: string)", "--passphrase PHRASE"],
		["      .with(body: { passphrase: 'phrase' }) }", "'phrase'"],
		["  #   keystore_path: Path to keystore.\n  #   keystore_password: Keystore password.", "Keystore password."],
		['  proxy.ClientCredentials.UserName.Password = "thePwd";', '"thePwd"'],
		["        u.set_password('testpw')", "'testpw'"],
	])
		kept(text, value);
	// The same places with a credential in them are read as before.
	hidden("      confirm_password: Correct horse battery staple", "Correct horse battery staple");
	hidden("  dpl bintray --user user --key key --passphrase Hx7mQ2pL9vRt --cleanup", "Hx7mQ2pL9vRt");
	hidden("      .with(body: { passphrase: 'Hx7mQ2pL9vRt' }) }", "Hx7mQ2pL9vRt");
	hidden("  #   keystore_password: Sunshine is the default.", "Sunshine");
	hidden("  # keystore_password: Sunshine", "Sunshine");
	hidden('  proxy.ClientCredentials.UserName.Password = "thePwd7391";', "thePwd7391");
});

test("references and code: an environment variable, a variable the script sets, a literal's entries, escaped markup", () => {
	const off = new Redactor({ guessing: "off", fingerprintKey: "test" });
	for (const [text, value] of [
		[
			'    Write-Host "##vso[task.setvariable variable=Helix_JobToken;issecret=true;]$env:Helix_JobToken"',
			"$env:Helix_JobToken",
		],
		['    local P12Pass="$2"\n\n    certutil ca --days=5000 --out ${PWD}/$P12File --pass="$P12Pass"', "$P12Pass"],
		['read -rsp "Password: " DbPass\npsql --password="$DbPass"', "$DbPass"],
		["        data: {\n          email: result.email,\n          password: hash\n        },", "password: hash"],
		[
			"export default (getApp: () => App, {\n  provider, email, password\n}: { provider: string, email: string, password: string }) => {",
			"password: string }) => {",
		],
		["Authorization: bearer &lt;redacted&gt;\nHost: demo.docusign.net", "&lt;redacted&gt;"],
		['{"body":"Authorization: bearer \\u0026lt;redacted\\u0026gt;\\nHost: x"}', "\\u0026lt;redacted\\u0026gt;"],
		['password = "&lt;your password&gt;"', "&lt;your password&gt;"],
	])
		assert.ok(off.redact(text).text.includes(value), text);
	// The same places with a credential in them are read as before.
	const token = b62(24);
	hidden(`Write-Host "##vso[task.setvariable variable=Helix_JobToken;issecret=true;]${token}"`, token);
	hidden('certutil ca --out x --pass="$Secr3t9"', "$Secr3t9");
	hidden(
		"        data: {\n          email: result.email,\n          password: Hx7mQ2pL9vRt\n        },",
		"Hx7mQ2pL9vRt",
	);
	hidden("authorization {\n  user: derek\n  password: hunter\n}", "hunter");
	hidden("email,password\nbob@example.com,Hx7mQ2pL9vRt", "Hx7mQ2pL9vRt");
	hidden(`Authorization: bearer &lt;${token}&gt;`, token);
	hidden(`password = "&lt;${token}"`, token);
});

test("a JWT shown cut short before its claims is its header alone, the same in every token signed so", () => {
	for (const header of [
		"eyJhbGciOiJIUzI1NiI...",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.…",
		"eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ…",
	])
		kept(`\`Authorization: Bearer ${header}\``, header);
	// Base64 of other JSON, a header shown whole (a token mangled, or made up), and a token with its claims, are
	// credentials.
	const json = Buffer.from(`{"password":"${b62(16)}"}`).toString("base64url");
	hidden(`Authorization: Bearer ${json}...`, json);
	hidden('"Authorization": []string{"Bearer eyJhbGciOiJHUzI3MSJ9"},', "eyJhbGciOiJHUzI3MSJ9");
	const claims = Buffer.from(`{"sub":"${b62(12)}","iat":1700000000}`).toString("base64url");
	hidden(`Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${claims}...`, claims);
});

test("a password word's password-shaped value isn't a flag with its value; SQL in a program's string is read", () => {
	// (`PWD` is a password word: the flag after it is password-shaped, and the flag's reader's.)
	kept('local P12Pass="$2"\ncertutil ca --out ${PWD}/$P12File --pass="$P12Pass"', '--pass="$P12Pass"');
	hidden("the password is --pass=Kx9#mPq2Lw", "Kx9#mPq2Lw");
	hidden('cur.execute("CREATE USER app IDENTIFIED BY Hx7mQ2pL9vRt")', "Hx7mQ2pL9vRt");
	hidden("CREATE USER app IDENTIFIED BY Hx7mQ2pL9vRt;", "Hx7mQ2pL9vRt");
});

test("a credential given through code: a conditional's branch, a hasher's argument, a Secret's file, SQL in a string", () => {
	for (const [text, secret] of [
		['dataSource.setPassword(password2==null?"Hx7mQ2pL9vRt4":password2);', "Hx7mQ2pL9vRt4"],
		['String pw = cfg == null ? "Hx7mQ2pL9vRt4" : cfg.password;', "Hx7mQ2pL9vRt4"],
		['password = os.environ.get("PW") if env else "Hx7mQ2pL9vRt4"', "Hx7mQ2pL9vRt4"],
		['token = os.getenv("API_TOKEN") or "Hx7mQ2pL9vRt4"', "Hx7mQ2pL9vRt4"],
		["encoded = make_password('Hx7mQ2pL9vRt4', 'iodizedsalt', 'pbkdf2_sha256')", "Hx7mQ2pL9vRt4"],
		["hashed = bcrypt.hashpw(b'Hx7mQ2pL9vRt4', bcrypt.gensalt())", "Hx7mQ2pL9vRt4"],
		['$h = password_hash("Hx7mQ2pL9vRt4", PASSWORD_DEFAULT);', "Hx7mQ2pL9vRt4"],
		['h = generate_password_hash("Hx7mQ2pL9vRt4", method="scrypt")', "Hx7mQ2pL9vRt4"],
		['ok = check_password_hash(stored, "Hx7mQ2pL9vRt4")', "Hx7mQ2pL9vRt4"],
		["kind: Secret\nstringData:\n  password.txt: Hx7mQ2pL9vRt4", "Hx7mQ2pL9vRt4"],
		["cur.execute(\"INSERT INTO users (email, password) VALUES ('bob@x.io', 'Hx7mQ2pL9vRt4')\")", "Hx7mQ2pL9vRt4"],
	])
		hidden(text, secret);
	// What isn't a credential there is kept.
	kept('type = show ? "text" : "password";', '"text"');
	kept('label: isAdmin ? "Admin password" : "User password"', "Admin password");
	kept('token = header or "Bearer"', '"Bearer"');
	kept("h = make_password(password, hasher='pbkdf2_sha256')", "pbkdf2_sha256");
	kept("kind: Secret\ndata:\n  checksums.txt: 3f2a9c1b4d5e6f708192a3b4c5d6e7f8", "3f2a9c1b4d5e6f708192a3b4c5d6e7f8");
	kept("cur.execute(\"INSERT INTO users (email, password) VALUES ('bob@x.io', %s)\", (pw,))", "bob@x.io");
});

test("found in review: tool and file lists, printf, CRLF, prefixed hex, password inputs, declarations, Terraform", () => {
	for (const [text, secret, hint] of [
		["$ mysqlcheck -u root -pHarbor2291 --all-databases", "Harbor2291"],
		["$ mariadb-admin -u root -pHarbor2291 status", "Harbor2291"],
		["DB_PASSWORD=correct horse battery staple\r\nAPI_URL=https://x.io", "battery staple"],
		["blob = 0x" + Buffer.from("password=hunter2hunter2xx").toString("hex"), "70617373776f7264"],
		['await page.fill("input[type=password]", "Tr0ub4dor&3xQ");', "Tr0ub4dor&3xQ"],
		["set(DB_PASSWORD Xk9fQ2mZp7Lw)", "Xk9fQ2mZp7Lw"],
		['variable "db_password" {\n  # default = "changeme"\n  default = "Tr0ub4dor&3xQ"\n}', "Tr0ub4dor&3xQ"],
		[
			"ADMIN=letmein99\nMAILGUN=mydomainpw\n",
			"mydomainpw",
			{ command: "docker run --rm --volumes-from db alpine cat .env" },
		],
		["ADMIN=letmein99\nMAILGUN=mydomainpw\n", "mydomainpw", { command: "sed -n 1,9p ssl/cert.key" }],
		["Token: Hx7mQ2pL9vRt4wZk\n", "Hx7mQ2pL9vRt4wZk", { command: "printf 'Token: %s\\n' \"$GITHUB_TOKEN\"" }],
	] as [string, string, object?][])
		assert.ok(
			!r()
				.redact(text, hint ? { hint } : {})
				.text.includes(secret),
			text,
		);
	// What isn't a credential there is kept.
	kept("Dim password As String = txtPassword.Text", "txtPassword.Text");
	kept("set(DB_PASSWORD Xk9fQ2mZp7Lw)", ")");
	kept("blob = 0x" + "9f".repeat(32), "9f".repeat(32));
	assert.equal(r().redact("hello %s\n", { hint: { command: "printf 'hello %s\\n' \"$USER\"" } }).text, "hello %s\n");
	assert.equal(r().redact("x\n", { hint: { command: "printf -v line '%s' \"$TOKEN\"" } }).text, "x\n");
});
