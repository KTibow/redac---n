/**
 * Credentials stated in sentences, labels and markup, in any language, and the prose about passwords that must come
 * out unchanged.
 *
 *   node --test test/prose.test.ts
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { Redactor } from "../src/index.ts";
import { hidden, kept, r } from "./helpers.ts";

test("a key=value pair inside a sentence is hidden under a credential word and kept under a cache key", () => {
	const pw = "vbrzzeN7T9J2xk";
	hidden(`Deploying with token=${pw}`, pw);
	kept("the cache key=abc123def456 was evicted", "abc123def456");
});

test("a password stated in a French, Portuguese, German, Chinese or Spanish sentence is hidden", () => {
	hidden("Attention : le mot de passe du service est Sh4d0w99, à mettre dans le coffre-fort.", "Sh4d0w99");
	hidden("O cliente relata um erro. A senha dele é *Comet169*.", "Comet169");
	hidden(
		"Der aktuelle DATADOG_API_KEY lautet 7dc38ef67ad5ea1c8ca940efd9eb6093 — bitte prüfen.",
		"7dc38ef67ad5ea1c8ca940efd9eb6093",
	);
	hidden(
		"部署失败。当前的 DATADOG_API_KEY 是 9b8ab69c272a2ace84ca8d7bd805bffd，有人能检查一下吗？",
		"9b8ab69c272a2ace84ca8d7bd805bffd",
	);
	hidden("El access_token actual es WnDKpEQCbOciskIKhAfdQxFmY, ¿alguien puede revisarlo?", "WnDKpEQCbOciskIKhAfdQxFmY");
	hidden("Rappel : faire tourner le passwd (M34d0w) avant vendredi.", "M34d0w");
});

test("a password stated after its user and host in a sentence is hidden, a policy sentence kept", () => {
	hidden("user is ro_analytics, password R0ck3t#46, host replica-1.db.internal, db analytics.", "R0ck3t#46");
	hidden("ops rotated the db password yesterday, new one is Thund3r&55", "Thund3r&55");
	kept("the password policy requires 12 chars, and it is now enforced", "enforced");
});

test("a passphrase of words is read whole in prose, quoted or to its line's end", () => {
	hidden('Your passphrase (between double-quotes): "falcon tiger quartz sierra harbor"', "falcon tiger quartz");
	for (const line of [
		"The wifi password is correct horse battery staple",
		'The wifi password is "correct horse battery staple".',
		"Set the password to `correct horse battery staple`",
		"Root password: correct horse battery staple",
	])
		hidden(line, "battery staple");
});

test("a password stated in prose, a Markdown label or a table is hidden", () => {
	for (const [t, v] of [
		["Our password for accessing the strategy documents is River@2025.", "River@2025"],
		["The policyholder logged into the portal using the password River2025! to access the claim.", "River2025!"],
		["Catherine's password, Elephant99#, is required to access", "Elephant99#"],
		["- **Password:** m4P$9tR#7kLw for accessing the c", "m4P$9tR#7kLw"],
		["| Password for Accessing Records | Rainbow@2025 |", "Rainbow@2025"],
		["EventID 4634: Account Name: svc_web, Logon ID: 0x1a2b3c, Password:Rmtq@1234!", "Rmtq@1234!"],
	])
		hidden(t, v);
	for (const [t, v] of [
		["fyi the prod db password is kM7BN>g<YVBr&3jLY?DA (rotate monday)", "kM7BN>g<YVBr&3jLY?DA"],
		["- **API Key:** ccr[FWQ#9P5:pgncM", "ccr[FWQ#9P5:pgncM"],
	])
		hidden(t, v);
	for (const sentence of [
		"Set the webhook secret to Maple1319%",
		"I changed the root password to Falcon7353!",
		"Update DB_PASSWORD to Cobalt2864% in the vault",
		"use River3448# as the password",
	])
		hidden(sentence, sentence.match(/[A-Z][a-z]+\d+[%!#]/)![0]);
	hidden(
		"I pasted `spqk3L9fPJnKsZCTaRJqbMibQaE6bXTJ` into the settings page. The server's IP address is in the ticket.",
		"spqk3L9fPJnKsZCTaRJqbMibQaE6bXTJ",
	);
});

test("credential nouns in prose are names: a signing key and a private key are hidden, a sort key is not", () => {
	for (const line of ["**Signing key:** Kx9mQ2vL7pZrTq8Wn3Xc4", "Use Kx9mQ2vL7pZrTq8Wn3Xc4 as the private key"])
		hidden(line, "Kx9mQ2vL7pZrTq8Wn3Xc4");
	kept("the sort key is created_at_timestamp", "created_at_timestamp");
});

test("a password input's value and a label with inline markup between are hidden", () => {
	hidden('<input type="password" value="Kx9mQv2Lp7Rt" />', "Kx9mQv2Lp7Rt");
	for (const line of [
		"<b>Password:</b> Kx9mQv2Lp7Rt",
		"Password: <code>Kx9mQv2Lp7Rt</code>",
		"<p>The password is <b>Kx9mQv2Lp7Rt</b>.</p>",
	])
		hidden(line, "Kx9mQv2Lp7Rt");
	kept("<p>The password is <b>Kx9mQv2Lp7Rt</b>.</p>", "</b>.</p>");
});

test("emphasis around a word in prose is kept, around a password the password is hidden", () => {
	kept("The password is **required**. Use at least 12.", "**required**");
	hidden("The password is **Kx9mQ2vL7p**.", "Kx9mQ2vL7p");
});

test("sentences, headings and counts that mention a credential word are kept", () => {
	kept("If the login fails, check the password and retry.", "and retry");
	kept("Go to the login page / dashboard.", "dashboard");
	kept("Password changed on 2024-01-01", "2024-01-01");
	kept("✓ PASS: Zero shift works correctly", "Zero");
	for (const t of [
		"- SMTP_PASSWORD — app-specific password from Gmail",
		'{ "key": "ctrl+shift+F12", "command": "editor.action.peekImplementation" }',
		"pass: 12/12",
		"Your API key determines the region; it is us-east-1 by default.",
		"        password (str|None): optional.",
		"Encode the password (ISO-8859-1) before hashing.",
		'{"en": {"pwd_hint": "Password: 8-64 characters, at least 1 digit"}}',
		"http -a alice api.example.com/me",
		"GET http://[::1]:5173/@vite/client 200",
		"passwd ubuntu",
	])
		assert.equal(r().redact(t).text, t);
	kept("密码：Abc12345，请妥善保管", "请妥善保管");
	kept("Mode: PSK mode", "PSK mode");
	kept("> auth middleware", "auth middleware");
});

test("pass as an ordinary English word is kept", () => {
	kept("All technical requirements pass: AGPL FOSS", "AGPL");
	for (const line of [
		"All tests pass: NDJSON/CSV detection",
		"First pass: validate and collect all items into a set.",
		"XPASS tests/test_pool.py::test_runs",
		"- pass: expired_command",
	])
		kept(line, line);
	for (const [line, v] of [
		["clutter can't *fake* a\n  pass either.", "either."],
		["Proven single-pass: 3.52x efficiency.", "3.52x"],
		["- 7-day JR Pass: ~$280", "~$280"],
		["| agent | pass |\n|---|---|\n| claude | 40/42 — 95.2% |", "40/42 — 95.2%"],
	])
		kept(line, v);
});

test("foreign sentences and algorithm names that mention a password come out unchanged", () => {
	for (const t of [
		"Das Passwort ist 8-stellig",
		"La clave del éxito es Python3",
		"La clave pública es AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
		"senha é SHA-256",
		"Encode the password (UTF-8) before hashing it.",
		"The secret is base64url-encoded.",
	])
		assert.equal(r().redact(t).text, t);
	kept("Le mot de passe est requis.", "requis");
	kept("All existing tests pass (40/40)", "40/40");
});

test("sentences about a password policy are kept", () => {
	for (const t of [
		"The password policy requires that the password is changed every 90 days.",
		"if the site uses http then the password is POSTed in plaintext.",
		"should the account be locked until the password is reset?",
		"| Secret type | Commit |\n|---|---|\n| Generic Password | 3422ad1 | `crawler/settings.py` |",
	])
		assert.equal(r().redact(t).text, t);
	kept("I changed the password policy to require 12 characters", "require 12 characters");
	for (const t of ["password: case-sensitive", "The password policy is Strict@2024 compliant."])
		assert.equal(r().redact(t).text, t);
});

test("four 4-letter words after 'app password:' are the sentence going on; Google's random letters are hidden", () => {
	for (const t of [
		"You need an app password: this will work with most mail clients",
		"# Gmail requires an app password: this must come from your account settings.",
		"SMTP error: app password required: this will work with Gmail",
	])
		assert.equal(r().redact(t).text, t);
	hidden("Your app password for your device: qwhz kfmt vbnr xplo", "qwhz kfmt vbnr xplo");
	hidden("App password: `kfmt qwhz xplo vbnr`", "kfmt qwhz xplo vbnr");
});

test("a command's pattern list that names password words is kept", () => {
	const t = "Please run `config dump --only-changed -t all | grep -Ev 'token|password|client_secret'`.";
	assert.equal(r().redact(t).text, t);
});

test("a contraction in prose before a command or an assignment opens no quote", () => {
	hidden("You'll need `mysql -u root -p'Xk9mP2vQ7tL4wR8' app`", "Xk9mP2vQ7tL4wR8");
	hidden("Here's how: sshpass -p 'Xk9mP2vQ7tL4' ssh host", "Xk9mP2vQ7tL4");
	hidden("- Don't share: `mysql -u root -p'+V3-o#=rKgCnjNu-Hgeb' app`", "+V3-o#=rKgCnjNu-Hgeb");
	hidden("Here's the fix: export API_TOKEN=',%}_Gf4c8Cmc_U'", ",%}_Gf4c8Cmc_U");
});

test("a sentence going on after the copula is not a passphrase", () => {
	kept("The noise_psk is sometimes passed into the client", "sometimes passed into");
	kept("the password is hunter22 and the user is bob", "and the user is bob");
	for (const line of [
		"an 8-character password is more than enough.",
		"unless the password is very very short.",
		"The admin password is configured via environment variable",
		'the password is "effectively random." How',
		"passwd: files cache ldap",
	])
		kept(line, line.replace(/^.*?(?:is|:) "?/, "").replace(/["."]+(?: How)?$/, ""));
});

test("a syntax highlighter's spans between a name and its value do not hide it", () => {
	hidden('<span class="hljs-attr">password</span>: <span class="hljs-string">"Summer2024!x"</span>', "Summer2024!x");
});

test("password=Mot de passe* is a label", () => {
	kept("password=Mot de passe*", "Mot de passe*");
});

test("a note after 'password' in another language, and a sentence before an escaped line break, are prose", () => {
	kept('        "Enter the password (optional)": "Zadejte heslo (volitelné)",', "volitelné");
	kept("\t\t\t-password (required) Optional if -force is specified\\n\\", "specified");
	// The same places with a credential in them are read as before.
	hidden('"Zadejte heslo (Pivo2024!)"', "Pivo2024!");
	hidden('"The password is Hx7mQ2pL9vRt4\\nNext line"', "Hx7mQ2pL9vRt4");
});

test("a password stated in Dutch, Finnish or Chinese is hidden, a count after it too; what a sentence says of one is kept", () => {
	hidden("Het wachtwoord van de server is Tr0ub4dor-77", "Tr0ub4dor-77");
	hidden("Palvelimen salasana on Tr0ub4dor-77", "Tr0ub4dor-77");
	hidden("密码是 Xk9#mQ2p，共8位", "Xk9#mQ2p");
	hidden("初始密码为 Abc12345（8位）", "Abc12345");
	hidden("密码：Kx9mQ2pL，共8位", "Kx9mQ2pL");
	hidden("初始密码：Abc12345（8位）", "Abc12345");
	for (const t of [
		"パスワード：英数字8文字以上",
		"das Passwort ist Pflicht",
		"der DB_PASSWORD ist 2FA-geschützt",
		"- SMTP_PASSWORD – generated-by-ci",
		"mot de passe: process.env.DB_PASSWORD",
		"| API 키 | ${KAKAO_REST_KEY} |",
		"| 密钥 | your-secret-key-here |",
	])
		assert.equal(r().redact(t).text, t);
});

test("a user and a password after a slash in prose: random letters are a password, words a page's path", () => {
	hidden("wifi: guest / QwZxKvBnMp", "QwZxKvBnMp");
	kept("open the account settings/billing page", "settings/billing");
});

test("a parameter's description is no password, in any comment's syntax or a line of output", () => {
	for (const t of [
		"REM db_password: Primary password.",
		"% password: Master password.",
		"' password: Master password.",
		"# keystore_password = Keystore password.",
		"echo password: Master password.",
		"Request MUST be sent as a Bearer Token, per Section 2 of OAuth 2.0\nBearer Token Usage [RFC6750].",
	])
		assert.equal(r().redact(t).text, t);
	hidden("# password: Sunshine is the default.", "Sunshine");
});

test("a quoted passphrase after its label is words or a generated value, not a placeholder or an instruction", () => {
	hidden('Your passphrase (between double-quotes): "Xk9mQ2vL7pRt"', "Xk9mQ2vL7pRt");
	for (const [t, v] of [
		['Passphrase (optional): "Leave blank for none"', "Leave blank for none"],
		['Passphrase: "replace me later"', "replace me later"],
		['Passphrase: "your-secret-passphrase"', "your-secret-passphrase"],
		['Passphrase: "${PASSPHRASE}"', "${PASSPHRASE}"],
		['Mnemonic: "{{ mnemonic }}"', "{{ mnemonic }}"],
	])
		kept(t, v);
});

test("prose's words around a credential: pass, a verb, a test value, a code reference, a repeated word", () => {
	const off = new Redactor({ guessing: "off", fingerprintKey: "test" });
	for (const t of ["the wifi pass is Kx9mQ2vL7p!", "my pass is Kx9mQ2vL7p!"])
		assert.ok(!off.redact(t).text.includes("Kx9mQ2vL7p"), t);
	for (const [t, v] of [
		["The password was guessed.", "guessed"],
		["Your passcode is [hidden]", "[hidden]"],
		["{user: svc, password: apple}", "apple"],
		["The password is blah blah blah", "blah blah blah"],
		["user is ro_analytics, password changeme1, host db", "changeme1"],
		["user is admin, password os.environ.PW1, host db", "os.environ.PW1"],
		["Where's the password hashed? It's `hashPassword2` in auth.ts", "hashPassword2"],
		['password: os.getenv("Ab1!xYz")', 'os.getenv("Ab1!xYz")'],
		["set the password (self.pw1) first", "(self.pw1)"],
		["Enter your password (case-sensitive)", "case-sensitive"],
		["the voicemail PIN (482134567) is too long", "482134567"],
	])
		kept(t, v);
	// (An object that closes after the value: a word no sentence or test uses is its password.)
	hidden("{user: svc, password: acez}", "acez");
	hidden("user is ro_analytics, password hunter22, host db", "hunter22");
	hidden("The wifi password is 'correct horse battery staple'", "battery staple");
});

test("a rotated credential after `it's`, a PIN in parentheses or after 's, a mixed-case label value; a format's colon", () => {
	hidden("ops rotated the db password yesterday, it's Thund3r55 now", "Thund3r55");
	hidden("rotate the passwd (Kx-mQvL!) before Friday", "Kx-mQvL!");
	hidden("Your new card PIN (4821) has been set", "4821");
	hidden("my bank PIN's 4821, don't tell anyone", "4821");
	hidden("**PIN:** 4821", "4821");
	hidden("**Password:** BlueSecret", "BlueSecret");
	hidden("Set the webhook secret to MapleSyrup", "MapleSyrup");
	// (A word a colon joins to the one before is a format's: a .pgpass header, not a sentence about its next line.)
	kept("# hostname:port:database:username:password\nlocalhost:5432:*:postgres:Kx9mQ2vL7p", "localhost:5432");
	// (Under a token's or a key's name a short value with no symbol is a placeholder's shape.)
	kept("The token: AbCdEf123456", "AbCdEf123456");
});

test("a length rule, a time or a required field's star after a password's name is no password", () => {
	for (const t of [
		"Password: 8-64 characters",
		"Passwort: 8-12 Zeichen",
		"Password: 12 characters",
		"password (12:30)",
		"password (required*)",
		"<!-- password: Master password. -->",
		"/* password: Master password. */",
	])
		assert.equal(r().redact(t).text, t);
	// The same places with a password in them are read as before.
	hidden("Password: 8-64charsXk9", "8-64charsXk9");
	hidden("rotate the passwd (M34d0w) before Friday", "M34d0w");
	hidden("<!-- password: Sunsh1ne!x -->", "Sunsh1ne!x");
});

test("a noun that qualifies another names no credential the sentence goes on to give", () => {
	kept("the password policy changed in 2024 and it is now NIST800 compliant", "NIST800");
	hidden("ops rotated the db password yesterday, new one is Thund3r&55", "Thund3r&55");
});

test("a password's ! after it in a sentence is hidden with it, and a common word with one is a word", () => {
	assert.equal(r().redact("the pass is Xyzzy42!").text.at(-1), "]");
	assert.equal(r().redact("Passwort: root!").text, "Passwort: root!");
	kept("the pass is Xyzzy42? not sure", "? not sure");
});

test("a password in a Latin sentence with accents is one; hyphened words in the sentence's language are not", () => {
	hidden("Uusi salasana on Kesä2024!x", "Kesä2024!x");
	hidden("salasana on Kesä2024", "Kesä2024");
	kept("Das Passwort ist 2FA-geschützt", "2FA-geschützt");
});

test("a value under a label in another language is reported as a password's or a key's, in a sentence or not", () => {
	for (const [t, kind] of [
		["パスワード: hunter2abc", "password"],
		["パスワードは hunter2abc です", "password"],
		["密钥: 9b8ab69c272a2ace84ca8d7bd805bffd", "key"],
		["密钥是 9b8ab69c272a2ace84ca8d7bd805bffd", "key"],
	])
		assert.deepEqual(
			r()
				.detect(t)
				.map((f) => f.kind),
			[kind],
			t,
		);
});
