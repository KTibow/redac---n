/**
 * Values that are code or labels: types, labels in other languages, famous stand-ins, documentation placeholders,
 * listings, and the code around a credential word.
 *
 *   node --test test/code-shapes.test.ts
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { Redactor } from "../src/index.ts";
import { hidden, kept, r } from "./helpers.ts";

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
