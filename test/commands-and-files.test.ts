/**
 * What a command prints without a value, what a secret file holds that is no secret, which commands and files print a
 * secret, and where line-end marks, names and sentences end a value.
 *
 *   node --test test/commands-and-files.test.ts
 *
 * (A fake key's vendor prefix is written with an escape, `"ghp\x5f…"`: written whole, the repository would hold text
 * that secret scanners, GitHub's push protection among them, take for a live key.)
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { Redactor } from "../src/index.ts";
import { isSecretFile, printsSecret } from "../src/commands.ts";
import { findInSecretFile, openScopes } from "../src/secretfile.ts";
import { b62, hidden, kept, r } from "./helpers.ts";
import { randomBytes } from "./random.ts";

const FILE = { secretFile: true };

test("a command that cuts a settings file down to its names prints no value", () => {
	for (const command of [
		"cut -d= -f1 .env",
		"cut -f1 -d= .env",
		"cut -d '=' -f 1 .env",
		"awk -F= '{print $1}' .env",
		"sed 's/=.*//' .env",
		"grep -v '^#' .env | cut -d= -f1",
		"cat .env | sed 's/=.*//'",
	]) {
		kept("NODE_ENV\nAWS_S3_BUCKET\nDB_HOST\n", "AWS_S3_BUCKET", { command });
	}
	hidden("DB_PASSWORD=Kx9mQ2pLrTvB7nWz\n", "Kx9mQ2pLrTvB7nWz", { command: "cut -d= -f2 .env" });
	hidden("DB_PASSWORD=Kx9mQ2pLrTvB7nWz\n", "Kx9mQ2pLrTvB7nWz", { command: "cut -d= -f1,2 .env" });
	hidden("production\nHarbor2291!x\n", "Harbor2291!x", { command: "cut -d= -f2 .env" });
	// (cut prints a line without its delimiter whole: a secret file's, not another file's.)
	hidden("NODE_ENV\nUPSTREAM=Harbor2291!x\n", "Harbor2291!x", { command: "cut -d: -f1 .env" });
	kept("NODE_ENV\nUPSTREAM=Harbor2291!x\n", "Harbor2291!x", { command: "cut -d: -f1 notes.txt" });
});

test("a substitution an argument takes is not printed by the command it is an argument of", () => {
	kept("1\n14:JWT_SECRET\n", "14:JWT_SECRET", {
		command: `sed -i.bak "s/^JWT_SECRET=.*/JWT_SECRET=$(openssl rand -hex 32)/" .env && grep -c '^JWT_SECRET=' .env && grep -n '^JWT_SECRET=' .env | cut -d= -f1`,
	});
	kept("ok\n", "ok", { command: "sed -i.bak 's/a/b/' .env && echo ok" });
	kept("ok\n", "ok", { command: `sed -i "s/^TOKEN=.*/TOKEN=$(openssl rand -hex 32)/" .env && echo ok` });
	hidden("Kx9mQ2pLrTvB7nWzQ4tY\n", "Kx9mQ2pLrTvB7nWzQ4tY", { command: "openssl rand -hex 32" });
	hidden("DB_PASSWORD=Kx9mQ2pLrTvB7nWz\n", "Kx9mQ2pLrTvB7nWz", { command: "diff <(cat .env) .env.example" });
});

test("cat -A marks line ends, which are no part of a value", () => {
	const shown = "PORT=3000$\nAPI_KEY=k8Hq2LmZ9xPvR4tN7wYc3Bd6^M$\nJWT_SECRET=b3f9Qz1Lx7Wm2Np8Rt4Yk6Hs $\n";
	for (const command of ["cat -A .env", "cat -e .env", "cat -vET .env"]) {
		const out = r().redact(shown, { hint: { command } }).text;
		assert.match(out, /API_KEY=\[REDACTED [^\]]+\]\^M\$\n/);
		assert.match(out, /JWT_SECRET=\[REDACTED [^\]]+\] \$\n/);
	}
	// A password that ends in `$` in a file that isn't shown so stays whole.
	hidden("DB_PASSWORD=Kx9mQ2pLrTvB7nW$\nPORT=1\n", "Kx9mQ2pLrTvB7nW", FILE);
});

test("a secret file's value that is a sentence is no secret, a passphrase is", () => {
	kept("3 DuplicatedKey: The PORT key is duplicated", "The PORT key is duplicated", FILE);
	kept(" LowercaseKey: The api_key key should be in uppercase", "should be in uppercase", FILE);
	kept("ASCII text, with CRLF line terminators", "CRLF line terminators", FILE);
	kept(" .env.example", ".env.example", FILE);
	// (A file's name has a template's suffix or a dot first: a dotted passphrase has neither.)
	hidden("UPSTREAM=harbor.2291x\n", "harbor.2291x", FILE);
	hidden("DB_PASSWORD=correct horse battery staple\n", "battery staple", FILE);
	hidden("correct horse battery staple\n", "battery staple", FILE);
	hidden(" Env.Local9x", "Env.Local9x", FILE);
	const paragraph =
		"This file is managed by the platform team and the values in it are rotated every month after review. ".repeat(4);
	kept(paragraph, "rotated every month", FILE);
});

test("a reference in code under a credential's name is kept in a secret file", () => {
	kept("  password: process.env.DB_PASSWORD,", "process.env.DB_PASSWORD", FILE);
	kept("  secret: os.environ['SECRET'],", "os.environ['SECRET']", FILE);
	hidden("  password: Kx9mQ2pLrTvB7nWz,", "Kx9mQ2pLrTvB7nWz", FILE);
});

test("a plain URL under a credential's name is kept, one with a token is not", () => {
	kept("    key: https://packages.microsoft.com/keys/microsoft.asc", "packages.microsoft.com", FILE);
	hidden(
		"    key: https://hooks.example.com/t/e8b41f0c7a92d6355bd1c4a09f37e268",
		"e8b41f0c7a92d6355bd1c4a09f37e268",
		FILE,
	);
	hidden("    key: https://example.com/keys?token=Kx9mQ2pLrTvB7nWz", "Kx9mQ2pLrTvB7nWz", FILE);
	// (A query, or more after the URL, is hidden with it; a password or a token in its path alone.)
	hidden("WEBHOOK_SECRET=https://hooks.acme.io/x?k=Harbor2291!x\n", "Harbor2291!x", { path: ".env" });
	hidden("BASIC_AUTH=https://acme.io/login Harbor2291!x\n", "Harbor2291!x", { path: ".env" });
	kept("    key: https://hooks.example.com/t/e8b41f0c7a92d6355bd1c4a09f37e268", "https://hooks.example.com/t/", FILE);
	const dsn = "webhook_secret: postgres://app:Harbor2291!x@db.internal:5432/app\n";
	hidden(dsn, "Harbor2291!x", FILE);
	kept(dsn, "@db.internal:5432/app", FILE);
});

test("a listing's durations and word lists are settings", () => {
	const table =
		'Key                  Value\n---                  -----\ntoken_duration       24h\ntoken_policies       ["ci" "default"]\ntoken_ttl_note       1h30m\n';
	kept(table, "token_duration       24h", { command: "vault token create" });
	kept(table, '["ci" "default"]', { command: "vault token create" });
	hidden(
		"Key  Value\n---  -----\ntoken  \x68vs.CAESIKq7Zr2mLx9vT4pN8wB3cY6dF1gH5jQ0sRtUeIa\n",
		"CAESIKq7Zr2mLx9vT4pN8wB3cY6dF1gH5jQ0sRtUeIa",
		FILE,
	);
	const lookup =
		"Key                 Value\n---                 -----\ntoken_duration      768h\ntoken_renewable     true\n";
	kept(lookup, "token_duration      768h", { command: "vault token lookup" });
	kept('token_policies: ["read-only", "default"]\n', '["read-only", "default"]', { path: "secrets.yml" });
	hidden('passwords: ["tr0ub4dor", "xk9mq2pl"]\n', "tr0ub4dor", { path: "secrets.yml" });
});

test("a file that holds only secrets hides a generated token under any name", () => {
	const text = "algolia:\n  app_id: ABCD1234EF\n  admin: e8b41f0c7a92d6355bd1c4a09f37e268\n";
	const hides = (path: string) =>
		findInSecretFile(text, { path }).some((f) => text.slice(f.start, f.end) === "e8b41f0c7a92d6355bd1c4a09f37e268");
	assert.ok(hides("config/secrets.staging.yml"));
	assert.ok(hides("credentials.json"));
	assert.ok(hides("/run/secrets/algolia"));
	assert.ok(!hides(".env"));
	assert.ok(!hides(""));
	// Not a word and a number, a host, or a cache's key: no generated token, only part of one, a word ahead of one.
	const settings =
		"production:\n  build: Release2024\n  cdn: d1a2b3c4e5f6g7h8i9j0k1l2.cloudfront.net\n  cache: gradle-7e2320944e9ecd11dd38f366bad4c32e\n";
	for (const v of ["build: Release2024", ".cloudfront.net", "cache: gradle-7e2320944e9ecd11dd38f366bad4c32e"])
		kept(settings, v, { path: "config/secrets.yml" });
});

test("under a vendor's word a .env's settings are kept by their shape, a password or random letters hidden", () => {
	const env = (line: string) => `NODE_ENV=production\n${line}\n`;
	for (const [line, value] of [
		["DOCKER=acme/api:1.4.2", "acme/api:1.4.2"],
		["POD=web-5d8gk7c9b-x2x4k", "web-5d8gk7c9b-x2x4k"],
		["DISCORD=https://discord.com/api/webhooks/1234567890/Kx9mQ2pLrTvB7nWzQ4tYKx9mQ2pL", "discord.com/api/webhooks/"],
		["SMTP=postmaster@sandbox8f14e45fceea467a95751c6b4d2a8f9e.mailgun.org", "postmaster@sandbox8f14e45f"],
		["BUILD=v20240601", "v20240601"],
		["CDN=d1a2b3c4e5f6g7.cloudfront.net", "d1a2b3c4e5f6g7.cloudfront.net"],
		["PYTHON=4.12.0b2", "4.12.0b2"],
		['CORS={"origins":["https://app.acme.io","https://admin.acme.io"]}', "https://admin.acme.io"],
		["SENTRY=ReleaseCandidate", "ReleaseCandidate"],
		["ENGINE=PostgreSQL", "PostgreSQL"],
	])
		kept(env(line), value, { path: ".env" });
	for (const [line, value] of [
		[
			"DISCORD=https://discord.com/api/webhooks/1234567890/Kx9mQ2pLrTvB7nWzQ4tYKx9mQ2pL",
			"Kx9mQ2pLrTvB7nWzQ4tYKx9mQ2pL",
		],
		["STRIPE=Summer2024!", "Summer2024!"],
		["STRIPE=XGxAdcVIefCUMAVsDhkYhErsQwPz", "XGxAdcVIefCUMAVsDhkYhErsQwPz"],
		["MY_SECRET_THING=90210!@#", "90210!@#"],
	])
		hidden(env(line), value, { path: ".env" });
});

test("a one-line password file's quotes are the password's unless they are a pair around it", () => {
	for (const pass of ['"Kx9mQ2pLw7v', "'Kx9'mQ2pLw7v'"])
		assert.equal(
			r()
				.redact(`${pass}\n`, { hint: { command: "cat ~/.vault_pass" } })
				.text.replace(/#\w+/, "#"),
			"[REDACTED secret #]\n",
			pass,
		);
});

test("a password file a command names by convention is a secret file", () => {
	hidden("remote vpn.example\nj.doe\nOvpn-Usr-pw-8Qx3\n", "Ovpn-Usr-pw-8Qx3", {
		command: "cat vpn/office.ovpn vpn/auth.txt",
	});
});

test("a cookie jar's preferences are kept, its sessions hidden, read as a file or as output", () => {
	const jar =
		"# Netscape HTTP Cookie File\nexample.com\tFALSE\t/\tTRUE\t1893456000\tsession_id\tKx9mQ2pLrTvB7nWzQ4tY\nexample.com\tFALSE\t/\tFALSE\t1893456000\tlocale\ten-GB\n";
	for (const hint of [{ path: "cookies.txt" }, { command: "cat cookies.txt" }, { secretFile: true }]) {
		hidden(jar, "Kx9mQ2pLrTvB7nWzQ4tY", hint);
		kept(jar, "locale\ten-GB", hint);
	}
});

test("a .env file's credential line is hidden and its settings kept", () => {
	hidden("NODE_ENV=production\nAPI_KEY=k8Hq2LmZ9xPvR4tN\n", "k8Hq2LmZ9xPvR4tN", { path: ".env" });
	kept("NODE_ENV=production\nAPI_KEY=k8Hq2LmZ9xPvR4tN\n", "NODE_ENV=production", { path: ".env" });
});

test("a ~/.netrc password is hidden, and an entry whose password is a reference is kept", () => {
	hidden("machine api.example.com login me password Tq8vR3nWx5", "Tq8vR3nWx5", { path: "~/.netrc" });
	kept('echo "machine github.com login x password ${GITHUB_TOKEN}" > ~/.netrc', "machine github.com login x");
});

test("a shell's listing of its variables is read as a .env: declare -p, export -p", () => {
	const listing = 'declare -x HOME="/home/me"\ndeclare -x MYAPP="Plover7Tango"\n';
	for (const command of ["declare -p", "export -p"]) {
		hidden(listing, "Plover7Tango", { command });
		kept(listing, 'declare -x HOME="/home/me"', { command });
	}
	kept('declare -x MYAPP="Plover7Tango"\n', "declare -x MYAPP=", { command: "declare -p MYAPP" });
});

test("netrc's tokens in any order, over lines and past a comment, and not in prose or a reference", () => {
	hidden("machine h password correct-horse login u", "correct-horse");
	hidden("machine api.example.com\n  # deploy bot\n  login bob\n  password correct-horse\n", "correct-horse");
	for (const t of [
		"Rotate the build machine root password quarterly",
		'{"error": "login or password incorrect"}',
		"default login anonymous password guest",
		"machine api.heroku.com login me@example.com password $HEROKU_API_KEY",
	])
		assert.equal(r().redact(t).text, t);
});

test("ipsec.secrets' XAUTH and EAP passwords are hidden without a PSK in the file", () => {
	hidden('alice : XAUTH "correct-horse"', "correct-horse");
	hidden('carol : EAP "correct-horse"', "correct-horse");
});

test("a cookie jar line's session value is hidden", () => {
	const pw = "Winter2024pass";
	hidden(`.example.com\tTRUE\t/\tTRUE\t1999999999\t_myapp\t${pw}`, pw);
});

test("a comment in a secret file and a command's own words are kept", () => {
	kept("# the secret is rotated monthly, see token docs\nAPI_URL=https://x\n", "docs", { path: ".env" });
	kept("release-candidate\nall-checks-done\n", "release-candidate", { command: "./ci.sh --mode pass smoke" });
});

test("a secret file in JSON stays JSON, pretty or minified", () => {
	const pretty = JSON.stringify({ client_secret: "hunter2", type: "authorized_user" }, null, 2);
	const out = r().redact(pretty, { hint: { path: "credentials.json" } }).text;
	assert.equal(JSON.parse(out).type, "authorized_user");
	assert.ok(!out.includes("hunter2"));
	hidden('{"client_secret":"short1x","refresh_token":"abcdefgh"}', "short1x", { path: "credentials.json" });
	// (A value that isn't a string ends at its comma; a published example is a placeholder.)
	const literals = JSON.stringify({ client_id: "acme-cli", password: null, pin: 4821, remember_token: false }, null, 2);
	const read = JSON.parse(r().redact(literals, { hint: { path: "credentials.json" } }).text);
	assert.equal(read.password, null);
	assert.equal(read.remember_token, false);
	hidden('{"client_id":"acme-cli","secret":"Harbor2291x"}', "Harbor2291x", { path: "credentials.json" });
	kept('{"aws_secret_access_key":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}', "wJalrXUtnFEMI", {
		path: "credentials.json",
	});
});

test("a .env value's comment and a YAML block's indicator are kept", () => {
	kept("API_KEY=Kx9mQ2pLrTvB7nWz # rotated monthly\n", "# rotated monthly", { path: ".env" });
	const yml = "tls:\n  key_password: |\n    Harbor2291x\n";
	kept(yml, "key_password: |\n", { path: "secrets.yml" });
	hidden(yml, "Harbor2291x", { path: "secrets.yml" });
});

test("a short number is a password in a .env only under a credential's name", () => {
	hidden("PORT=5432\nDB_PASSWORD=12345678\n", "12345678", { path: ".env" });
	kept("PORT=5432\nTOKEN_TTL=3600\n", "3600", { path: ".env" });
	hidden("PORT=5432\nSESSION_SECRET=48213977\n", "48213977", { path: ".env" });
});

test("a remote read of an .env prints a secret file, and env keeps a placeholder", () => {
	hidden("NODE_ENV=production\nhunter2hunter2\n", "hunter2hunter2", {
		command: "kubectl exec -n prod deploy/api -- cat /app/.env",
	});
	hidden("NODE_ENV=production\nhunter2hunter2\n", "hunter2hunter2", { command: "ssh deploy@host 'cat /srv/app/.env'" });
	kept("SECRET_KEY=sk-ant-xxxxx\n", "sk-ant-xxxxx", { command: "docker exec api env" });
});

test("a path that names a vault password file reads a passphrase", () => {
	hidden("coral lantern badger comet amber saffron\n", "lantern badger", { path: "/home/ops/.ansible/vault_pass" });
});

test("a cookie table's session value is hidden", () => {
	hidden(
		"Name\tValue\tDomain\nsessionid\tLRxXLyjkgBBxpa9qT2\t.example.com\ntheme\tdark\t.example.com\n",
		"LRxXLyjkgBBxpa9qT2",
	);
	hidden("Name\tValue\tDomain\nsessionid\tk3j2h4g5f6d7s8a9q0w1e2r3\texample.com", "k3j2h4g5f6d7s8a9q0w1e2r3");
});

test("a userlist file's second quoted field is hidden", () => {
	hidden('"alice" "Hx7mQ2pLw9zK"\n"bob" "Zr2LmX0vT4nB"', "Zr2LmX0vT4nB", { path: "secrets/userlist.txt" });
});

test("a file named like a password holds nothing but the password", () => {
	hidden("#Kd8pQ2!zX9mL", "Kd8pQ2!zX9mL", { path: "secrets/db_password.txt" });
	hidden("admin:Kd8pQ2zX9mL", "Kd8pQ2zX9mL", { path: "secrets/db_password.txt" });
	for (const v of ["kX9:mQ2#pLw7", "Hx7m=Q2pLw9zK", "{Kd8pQ2zX9mL}"])
		hidden(v, v.slice(3), { path: "secrets/db_password.txt" });
});

test("a one-line file of an address, a path or a published example holds no password", () => {
	for (const [text, value] of [
		["https://vault.acme.io:8200\n", "vault.acme.io:8200"],
		["db.internal:5432\n", "db.internal:5432"],
		["admin:/run/secrets/admin_password\n", "/run/secrets/admin_password"],
		["AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"],
	])
		kept(text, value, FILE);
	// (A .pgpass line keeps its host, port, database and user, whatever the host is named.)
	const pgpass = "auth-db.internal:5432:app:app_user:Harbor2291x\n";
	kept(pgpass, "auth-db.internal:5432:app:app_user:", { path: "~/.pgpass" });
	hidden(pgpass, "Harbor2291x", { path: "~/.pgpass" });
	// (A certificate's text dump in a .pem holds lines of hex pairs, no .pgpass line.)
	const dump =
		"Certificate:\n    Data:\n                Modulus:\n                    00:a6:64:ac:ae:9b:ad:5a:ca:3e:1f:eb:bb:f3:7b:\n                    f2:36:d0:9e:e7:f3:f4:0d:9f:97:11:f8:28:fb:d6:\n                    d9:08:ae:c7:ca:f4:1a:bb:07:58:c8:59:69:8f:85:\n                Exponent: 65537 (0x10001)\n";
	assert.equal(r().redact(dump, { hint: { path: "ca.pem" } }).text, dump);
});

test("bin/rails credentials:show prints secrets", () => {
	const keys =
		"active_record_encryption:\n  primary_key: 2XhEAsfmNvCd8zQu43efeffpWOEa99vu\n  deterministic_key: EGY8WhulUOXixybod7ZWwMIL68R9o5kC\n  key_derivation_salt: xEY0dt6TZcAMg52K7O84wYzkjvbA62Hz\n";
	for (const key of [
		"2XhEAsfmNvCd8zQu43efeffpWOEa99vu",
		"EGY8WhulUOXixybod7ZWwMIL68R9o5kC",
		"xEY0dt6TZcAMg52K7O84wYzkjvbA62Hz",
	])
		hidden(keys, key, { command: "bin/rails credentials:show" });
});

test("a PASS name in cat .env output is hidden", () => {
	hidden("PASS=dragonfly\nUSER=admin", "dragonfly", { command: "cat .env" });
});

test("a file written by a command or printed by cat is a secret file", () => {
	const S = "Harbor#2291x";
	for (const [t, v, hint] of [
		[
			"NODE_ENV=production\nSTRIPE=c261be78-a5a0-431d-acb8-d1b29db9b9eb\nPORT=3000",
			"c261be78-a5a0",
			{ command: "cat .env" },
		],
		["cat > .env <<'EOF'\nSTRIPE=c261be78-a5a0-431d-acb8-d1b29db9b9eb\nEOF", "c261be78-a5a0"],
		["cat <<EOF > ~/.pgpass\ndb:5432:app:app:Harbor#2291x\nEOF", S],
		["echo 'Harbor#2291x' > ~/.vault_pass", S],
		["!cat ~/.vault_pass\ncoral lantern badger comet amber\n", "badger comet"],
	] as [string, string, { command?: string }?][])
		hidden(t, v, hint);
});

test("what a command line writes into a secret file: a script's heredoc in a heredoc, `|&`, printf's format, a group's one echo", () => {
	for (const t of [
		"cat > deploy.sh <<'EOF'\n#!/bin/bash\ncat > /srv/app/.env <<ENV\nSTRIPE=Tiger1103#xq\nENV\nEOF\n",
		"echo 'Tiger1103#xq' |& sudo tee ~/.vault_pass\n",
		"printf 'coral Tiger1103#xq comet\\n' > ~/.vault_pass\n",
		"{ echo 'coral lantern Tiger1103#xq'; } > ~/.vault_pass\n",
	])
		hidden(t, "Tiger1103#xq");
	// A heredoc's body ends what is in it; a heredoc to a file that isn't secret leaves the prompt's command open.
	assert.deepEqual(openScopes("cat > deploy.sh <<'EOF'\ncat > .env <<ENV\nA=1\nEOF\n"), []);
	assert.deepEqual(openScopes("$ cat .env\nA=1\n$ cat > README.md <<EOF\n# Title\n"), ["$ cat > README.md <<EOF\n"]);
});

test("a quoted pipe through grep still reads a secret file", () => {
	hidden("A_TOKEN=Tiger1103#xq9Lm", "Tiger1103#xq9Lm", { command: "grep -E 'A|B' .env" });
});

test("a secret file's credential words count whatever the in-text classifier says", () => {
	hidden(
		"BASIC_AUTH=admin:Harbor2291!\nCACHE_KEY=gradle-7e2320944e9ecd11dd38f366bad4c32e08096b095c224c396e002fb42ceaac94\n",
		"Harbor2291!",
		{ command: "cat .env" },
	);
	kept("CACHE_KEY=gradle-7e2320944e9ecd11dd38f366bad4c32e08096b095c224c396e002fb42ceaac94\n", "gradle-7e23", {
		command: "cat .env",
	});
});

test("a finding is its value: the syntax around it stays and the value is learned", () => {
	const tfvars = r();
	const tf = 'db_password     = "CANYxh7686!"\n';
	assert.match(
		tfvars.redact(tf, { hint: { path: "envs/prod/terraform.tfvars" } }).text,
		/^db_password {5}= "\[REDACTED [^\]]+\]"\n$/,
	);
	tfvars.learn(tf, { hint: { path: "envs/prod/terraform.tfvars" } });
	assert.ok(!tfvars.redact("later: CANYxh7686! was used").text.includes("CANYxh7686!"));
});

test("a command that only counts or copies a secret file prints no value", () => {
	for (const c of [
		"cat .env | wc -l",
		"grep -c API_KEY .env",
		"cat .env > /tmp/backup",
		"cat .env | wl-copy",
		"export $(grep ^DISCORD_TOKEN .env) && python3 bot.py",
	])
		kept("12\n", "12", { command: c });
});

test("a command that filters a secret file prints its lines", () => {
	for (const c of ["cat .env | head -3", "env | grep -i dagster", "grep KEY .env 2>/dev/null"])
		hidden(
			"DAGSTER_CLOUD_API_TOKEN=agent:acme:fb865001ead104f0e47353ded32fb371\n",
			"fb865001ead104f0e47353ded32fb371",
			{ command: c },
		);
});

test("a secret file piped through any program but one that prints none of its input, or copied and read, is printed", () => {
	for (const c of [
		"cat .env | nl",
		"cat .env | xargs",
		"cat .env | python3 -c 'import sys; print(sys.stdin.read())'",
		"cat .env > /tmp/x; cat /tmp/x",
		"cp .env /tmp/e && cat /tmp/e",
		"sudo cat .env > /dev/stderr",
		"cp .env /tmp/a && mv /tmp/a /tmp/b && cat /tmp/b",
		'cat .env | sed -n "1,$(wc -l < .env.example)p"',
		"cat server.key | openssl rsa -check",
		"cat .env.enc | openssl enc -d -aes-256-cbc -pbkdf2 -pass env:KEY",
		"cat .env.gpg | gpg -d",
		"cat .env | gpg --clearsign",
		"diff <(cat .env) .env.example",
	])
		hidden("NODE_ENV=production\nUPSTREAM=Harbor2291!x\n", "Harbor2291!x", { command: c });
	for (const c of [
		"cp .env /tmp/env.bak && rm /tmp/env.bak",
		"cp .env .env.bak && cat package.json",
		"cp config.example.json config.json && cat config.json",
		"cat .env |& wc -l",
		"cat .env | gpg -c",
		"cat id.pem | openssl pkey -pubout",
	])
		kept("NODE_ENV=production\nUPSTREAM=Harbor2291!x\n", "Harbor2291!x", { command: c });
});

test("a search's pattern and its options' values are no files it reads", () => {
	for (const c of [
		"grep -e UPSTREAM .env",
		"grep --regexp=UPSTREAM .env",
		"grep -eUPSTREAM .env",
		"ag UPSTREAM .env",
		"Select-String -Path .env -Pattern UPSTREAM",
	])
		hidden("NODE_ENV=production\nUPSTREAM=Harbor2291!x\n", "Harbor2291!x", { command: c });
	for (const c of ["grep -rn -e password -e token src/", "grep -m 1 -n password src/", "grep -A 3 secret config/"])
		kept("NODE_ENV=production\nUPSTREAM=Harbor2291!x\n", "Harbor2291!x", { command: c });
});

test("a quoted .env value with a trailing comment is hidden whole", () => {
	hidden('OPENAI="Tiger1103#xQ" # prod', "Tiger1103#xQ", { path: ".env" });
});

test("pgbouncer's user list is a secret file, and an upper-case hex key in one is no constant's name", () => {
	hidden('"app" "Harbor2291x"', "Harbor2291x", { command: "cat /etc/pgbouncer/userlist.txt" });
	hidden("MAX_RETRIES\nA3F9C2E1B7D4086F5A2C9E1B3D7F4A68", "A3F9C2E1B7D4086F5A2C9E1B3D7F4A68", {
		command: "cat ~/.config/mytool/credentials",
	});
});

test("a secret file printed by find, xargs, a loop or a substitution is printed", () => {
	for (const c of [
		"find . -name .env -exec cat {} \;",
		"find . -name '.env*' | xargs cat",
		'for f in .env .env.local; do cat "$f"; done',
		"cat $(find . -name .env)",
		"python3 -c \"print(open('.env').read())\"",
		'while read l; do echo "$l"; done < .env',
		'for f in "$HOME/.env" "$HOME/.env.local"; do cat "$f"; done',
		"xargs -a .env echo",
		"xargs < .env",
		"tee out.log < <(cat .env)",
	])
		hidden("NODE_ENV=production\nUPSTREAM=Harbor2291!x\n", "Harbor2291!x", { command: c });
	for (const c of ["find . -name '*.ts' -exec cat {} \\;", "find . -name .env -exec cat {} \\; > /tmp/all.env"])
		kept("NODE_ENV=production\nUPSTREAM=Harbor2291!x\n", "Harbor2291!x", { command: c });
});

test("openssl x509 prints a certificate, not a secret file", () => {
	kept("NODE_ENV=production\nUPSTREAM=Harbor2291!x\n", "Harbor2291!x", {
		command: "openssl x509 -in /etc/ssl/certs/ca.pem -noout -text | head -32",
	});
});

test("hint.secretFile reads text as a .env is read, whatever its path", () => {
	const text = "db_host=prod-db\nAPI_PASS=hunter2x\nXk9mQ2pLzR7vT4wN8bHq\nnote=Wint3rH4rbor";
	const asEnv = r().redact(text, { hint: { path: ".env" } }).text;
	assert.equal(r().redact(text, { hint: { path: "deploy/prod.conf", secretFile: true } }).text, asEnv);
	kept(text, "Xk9mQ2pLzR7vT4wN8bHq", { path: "deploy/prod.conf" });
	hidden(text, "Xk9mQ2pLzR7vT4wN8bHq", { path: "deploy/prod.conf", secretFile: true });
});

test("a path rooted at any variable and mkcert's + in a file name are kept in a secret file", () => {
	kept("export KUBECONFIG=$PWD/.kube/config", "$PWD/.kube/config", { path: ".env" });
	kept("TLS_KEY=./certs/localhost+2-key.pem", "./certs/localhost+2-key.pem", { path: ".env" });
});

test("a shell expansion in a secret file is read whole, blanks and all, while a bare value is hidden", () => {
	kept("requirepass ${REDIS_PASSWORD:?set it first}\nmaxmemory 2gb", "${REDIS_PASSWORD:?set it first}", {
		path: "redis.conf",
	});
	kept("masterauth ${MASTER_AUTH}", "${MASTER_AUTH}", { path: "redis.conf" });
	hidden("requirepass Kx9mQ2vL7pZr", "Kx9mQ2vL7pZr", { path: "redis.conf" });
});

test("the output of a command that prints a token is hidden", () => {
	const t = `gho_${b62(36)}`;
	hidden(`${t}\n`, t, { command: "gh auth token" });
});

test("a command list, a Windows path and a shell wrapper with separate flags each name a secret source", () => {
	hidden("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\nok\n", "9f86d081884c7d659a2f", {
		command: "openssl rand -hex 32 && echo ok",
	});
	hidden("NODE_ENV=production\nhunter2hunter2\n", "hunter2hunter2", { path: "C:\\app\\.env" });
	hidden("NODE_ENV=production\nhunter2hunter2\n", "hunter2hunter2", { command: 'bash -l -c "cat .env"' });
});

test("echo $VAR prints its value, and a secret reference is kept", () => {
	const pw = "vbrzzeN7T9J2xk";
	hidden(`$ echo $DB_PASSWORD\n${pw}\n`, pw);
	kept("$ echo $OPENAI_API_KEY\nop://Engineering/OpenAI/credential\n", "op://Engineering/OpenAI/credential");
});

test("a NUL-separated environment dump hides the secret and keeps the other entries", () => {
	hidden(`PATH=/usr/bin\0API_SECRET=ifmb%5R6D67hwq\0HOME=/root`, "ifmb%5R6D67hwq");
	kept(`PATH=/usr/bin\0API_SECRET=ifmb%5R6D67hwq\0HOME=/root`, "HOME=/root");
	hidden("NODE_ENV=production\0UPSTREAM=Harbor2291!x\0", "Harbor2291!x", { command: "printenv -0" });
});

test("bundled shell flags and echo $(...) name the command that prints a secret", () => {
	hidden("wint3r-horse-42x\n", "wint3r-horse-42x", { command: 'bash -euo pipefail -c "cat .env"' });
	hidden("wint3r-horse-42x\n", "wint3r-horse-42x", { command: "echo $(gh auth token)" });
});

test("a printed JSON document keeps its host", () => {
	kept('{"username":"dkim","password":"a*2yu4&IhQ+T","host":"db.example.com"}', "db.example.com", {
		command: "aws secretsmanager get-secret-value --secret-id x --query SecretString --output text",
	});
	kept('{"host":"db.example.com","port":5432}', "db.example.com", {
		command: "aws secretsmanager get-secret-value --secret-id x --query SecretString --output text",
	});
});

test("a secrets download hides its secrets and keeps its public keys", () => {
	hidden('{"CLOUDINARY_API_SECRET":"c1_Xv8PSAlmFcfZ8"}', "c1_Xv8PSAlmFcfZ8", {
		command: "doppler secrets download --no-file --format json",
	});
	kept('{"CLOUDINARY_API_KEY":"121765559948535"}', "121765559948535", {
		command: "doppler secrets download --no-file --format json",
	});
});

test("a later command's output is not read as an earlier command's secret", () => {
	kept(
		"\x79a29.a0AfB_byC1x2y3z4A5b6C7d8E9f0G1h2I3j4K5l6M7\n$ gcloud auth list --format='value(account)'\njordan@acme.dev\n",
		"jordan@acme.dev",
		{ command: "gcloud auth print-access-token" },
	);
});

test("a command that prints a secret store hides its value, and git credential fill keeps its host", () => {
	hidden("DB_PASSWORD=k3%dq7pz!x2m", "k3%dq7pz!x2m", { command: "cat .env" });
	hidden(
		"Key              Value\nclient_secret    abc123def456\nsigning_key      kubernetesclusterkey",
		"kubernetesclusterkey",
		{ command: "vault kv get secret/app" },
	);
	kept(
		"protocol=https\nhost=github.com\nusername=octocat\npassword=gho\x5f16C7e42F292c6912E7710c838347Ae178B4b",
		"host=github.com",
		{ command: "git credential fill" },
	);
});

test("a secret store's listing keeps its header, its counts and a published example", () => {
	const listing =
		"====== Data ======\nKey                      Value\n---                      -----\naws_secret_access_key    wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\ntoken_num_uses           10\nclient_secret            Kx9mQ2pLrTvB7nWz\n";
	for (const v of ["Key                      Value", "wJalrXUtnFEMI", "token_num_uses           10"])
		kept(listing, v, { command: "vault kv get secret/aws" });
	hidden(listing, "Kx9mQ2pLrTvB7nWz", { command: "vault kv get secret/aws" });
});

test("a secret file's lines that are one token: a password before a certificate or made of words, not a table's rule", () => {
	const cert =
		"-----BEGIN CERTIFICATE-----\nMIIBeTCCAR+gAwIBAgIUHeKPK2ltA6P8OoCcZTscsGpeKiQwCgYIKoZIzj0EAwIw\nEjEQMA4GA1UEAwwHYWNtZS5pbzAeFw0yNjEwMTIxMDQ4NTJaFw0yNjEwMTMxMDQ4\n-----END CERTIFICATE-----\n";
	hidden(`Harbor2291!x\n${cert}`, "Harbor2291!x", FILE);
	for (const password of ["Maple-Orbit-42", "qwer-tyui-1234"])
		hidden(`j.doe\n${password}\n`, password, { path: "vpn/auth.txt" });
	const table =
		"+----------+--------------+\n| user     | password     |\n+----------+--------------+\n| admin    | Harbor2291x  |\n+----------+--------------+\n";
	kept(table, "+----------+--------------+\n| admin", FILE);
	hidden(table, "Harbor2291x", FILE);
});

test("aws ssm get-parameter output hides the value column", () => {
	hidden(
		"PARAMETER\tarn:aws:ssm:us-east-1:123456789012:parameter/prod/db/password\tjson\t2024-05-01T10:00:00.000000+00:00\t/prod/db/password\tSecureString\tHx7mQ2pLw9zK\t3",
		"Hx7mQ2pLw9zK",
		{ command: "aws ssm get-parameter --name /prod/db/password --with-decryption --output text" },
	);
});

test("grep output of /etc/passwd is kept", () => {
	assert.equal(
		r().redact("root:x:0:0:root:/root:/bin/bash", { hint: { command: "grep -rn password /etc/passwd" } }).text,
		"root:x:0:0:root:/root:/bin/bash",
	);
});

test("a printed row's value is found by its column, not by the first field that starts with it", () => {
	const row =
		"PARAMETER\tarn:aws:ssm:us-east-1:1:parameter/Kx9mQ2pL7vR\t2024-01-01\ttext\tKx9mQ2pL7vR\tSecureString\tKx9mQ2pL\t3";
	assert.ok(
		r()
			.redact(row, { hint: { command: "aws ssm get-parameter --name x --with-decryption --output text" } })
			.text.endsWith("]\t3"),
	);
});

test("a command that prints a credential prints it whole on its first line: a passphrase, a PIN, a [-leading value", () => {
	hidden("entry follow duty nerve\n", "follow duty", { command: "op read op://vault/bank/password" });
	hidden("8271\n", "8271", { command: "op read op://vault/bank/pin" });
	hidden("{EmxSQGxe%Fq6taV\n", "EmxSQGxe", { command: "pass show personal/bank" });
	hidden("Xk9mQ2pLrT\n", "Xk9mQ2pLrT", { command: "lpass show --password github" });
});

test("a record's ID line is not the credential", () => {
	kept("ID:          i6p0crlratgcr38kq3w31yrr6g\nTitle:       GitHub Deploy Bot\n", "i6p0crlratgcr38kq3w31yrr6g", {
		command: "op item get 'GitHub Deploy Bot' --reveal",
	});
});

test("a CLI's error message is no credential", () => {
	kept("no oauth token found for github.com", "no oauth token found", { command: "gh auth token" });
	kept("Warning token will expire in 3 days\n", "Warning token", { command: "gh auth token" });
});

test("an address a credential command prints, first or under the password, is no credential", () => {
	kept("bob@acme.io\n", "bob@acme.io", { command: "op read op://Private/GitHub/username" });
	kept("Kx9mQ2pLrTvB7nWz\nbob@acme.io\n", "bob@acme.io", { command: "pass show web/acme" });
	hidden("Kx9mQ2pLrTvB7nWz\nbob@acme.io\n", "Kx9mQ2pLrTvB7nWz", { command: "pass show web/acme" });
});

test("printenv NAME prints that variable: PATH is kept, a key hidden", () => {
	kept("$ printenv PATH\n/usr/local/sbin:/usr/local/bin", "/usr/local/sbin");
	hidden("$ printenv OPENAI_API_KEY\nXk9mQ2pLrTvB7nWzQ4cD", "Xk9mQ2pLrTvB7nWzQ4cD");
});

test("a passphrase a store prints is judged as a line, not by its words", () => {
	hidden(
		"$ pass show mail/work\ncorrect horse no battery staple\nusername: bob@example.com\n",
		"correct horse no battery staple",
	);
	hidden("$ pass show mail/work\ncorrect horse battery staple\n", "correct horse battery staple");
	hidden("$ op read op://v/i/f\nAdmin: bob\nmonkeykingdom\n", "monkeykingdom");
	kept("$ pass show mail/work\nno oauth token found\n", "no oauth token found");
	kept("$ pass show mail/work\nPermission denied\n", "Permission denied");
});

test("padded base64 is a bare token, not a NAME= line", () => {
	assert.equal(findInSecretFile("Zm9vYmFyYmF6cXV4MTIzNDU2==\n").length, 1);
	assert.equal(findInSecretFile("SOME_NAME=\n").length, 0);
});

test("a bare line of a secret file gives way to the narrower secret in it", () => {
	const text = "# alerts\nhooks.slack.com\x2fservices/T024BE7LD/B07QJ3K2M9P/yQxCGClbaNFDpCWNX0D1lZEz\n";
	kept(text, "hooks.slack.com/services/", { path: "secrets/webhooks.txt" });
	hidden(text, "yQxCGClbaNFDpCWNX0D1lZEz", { path: "secrets/webhooks.txt" });
});

test("a tool that prints a secret is read by its program's name, and only for secret keys", () => {
	hidden("gho\x5fx9Kd2mQ7vL4pZr8Tn3Wb5Yc1Fh6Js0Ae", "x9Kd2mQ7vL4pZr8Tn3Wb5Yc1Fh6Js0Ae", {
		command: "/usr/bin/gh auth token",
	});
	hidden("Wq9rT2xLm4", "Wq9rT2xLm4", { command: "/usr/local/bin/gh auth token" });
	kept("localhost", "localhost", { command: "wp config get DB_HOST" });
	hidden("Qp7zLm2Wx9", "Qp7zLm2Wx9", { command: "wp config get DB_PASSWORD" });
});

test("with guessing off, a secret file still has its generated values hidden, hinted or written in the text", () => {
	const off = new Redactor({ guessing: "off" });
	const written = off.redact("$ cat > .env <<EOF\nHOOK=Kx9mQ2vLp7RtWz8\nPORT=8080\nEOF").text;
	assert.ok(!written.includes("Kx9mQ2vLp7RtWz8") && written.includes("PORT=8080"), written);
	assert.ok(
		!off.redact("HOOK=Kx9mQ2vLp7RtWz8\nPORT=8080", { hint: { command: "cat .env" } }).text.includes("Kx9mQ2vLp7RtWz8"),
	);
	assert.ok(off.redact("HOOK=Kx9mQ2vLp7RtWz8\nPORT=8080").text.includes("Kx9mQ2vLp7RtWz8"));
});

test("a public key's file and the public key a pipeline prints are not secret", () => {
	for (const path of ["/var/lib/nix-serve/cache-pub-key.pem", "server.pub.pem", "fullchain.pem"])
		assert.ok(!isSecretFile(path), path);
	for (const path of ["key.pem", "id_ed25519", ".env"]) assert.ok(isSecretFile(path), path);
	assert.ok(!printsSecret("wg genkey | tee kp.key | wg pubkey | tee kp.pub"));
	assert.ok(printsSecret("wg genkey | tee kp.key"));
});

test("a login that takes its token on stdin prints none of it, unless it prints the token back (vault login)", () => {
	assert.ok(!printsSecret("echo $GH_TOKEN | gh auth login --with-token"));
	assert.ok(!printsSecret("echo $CR_PAT | docker login ghcr.io -u me --password-stdin"));
	assert.ok(printsSecret("echo $VAULT_TOKEN | vault login -"));
});

test("a secret file's word lists, table words, variables, hosts and certificates are settings; its lists of passwords are not", () => {
	const vault = 'Key                  Value\n---                  -----\ntoken_policies       ["default" "ci"]\n';
	kept(vault, '["default" "ci"]', { command: "vault login" });
	hidden('passwords: ["hunter2hunter2", "letmein2024"]\n', "letmein2024", { path: "secrets.yml" });
	kept("name       type\nsecret     value\ntoken      string\n", "secret     value", { secretFile: true });
	kept("admin:$ADMIN_PASSWORD\nops:$ADMIN_PASSWORD\n", "admin:$ADMIN_PASSWORD", { path: ".htpasswd" });
	hidden("admin:$apr1$Xk9fmQ2v$abcdEFGH12345678abcdEF\n", "abcdEFGH12345678abcdEF", { path: ".htpasswd" });
	kept("NGROK=abc123def456.ngrok.io\n", "abc123def456.ngrok.io", { path: ".env" });
	const cert = `MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ${b62(500)}`;
	kept(`CERT=${cert}\n`, cert, { path: ".env" });
});

test("a file that holds only secrets hides a made password under any name", () => {
	hidden("admin: Harbor2291!\n", "Harbor2291!", { path: "config/secrets.yml" });
	kept("admin: Harbor2291!\n", "Harbor2291!", { path: ".env" });
});

test("another occurrence of a guess is judged where it stands", () => {
	const pub = "rC6LxV3uCapgW94Y9+Wq/lsyx4zf04YAIuEZjQoHgWW=";
	const out = r().redact(`$ cat key.txt\n${pub}\n\n[Peer]\nPublicKey = ${pub}\nAllowedIPs = 10.8.0.9/32`).text;
	assert.ok(out.includes(`PublicKey = ${pub}`), out);
});

test("Symfony's vault key, a string of escaped bytes, is hidden; a prompt's few control bytes are kept", () => {
	const key = Array.from(randomBytes(64), (b) => `\\x${b.toString(16).toUpperCase().padStart(2, "0")}`).join("");
	const file = `<?php // prod.decrypt.private on Tue, 14 Jul 2026 09:12:44 +0000\nreturn "${key}";\n`;
	hidden(file, key.slice(0, 40), { path: "config/secrets/prod/prod.decrypt.private.php" });
	kept(file, "prod.decrypt.private on Tue, 14 Jul 2026", {
		command: "cat config/secrets/prod/prod.decrypt.private.php",
	});
	// (Its public half is public; a Python byte string reads the same as PHP's.)
	assert.ok(!isSecretFile("config/secrets/prod/prod.encrypt.public.php"));
	hidden(`SIGNING_SEED = b'${key}'\n`, key.slice(0, 40), FILE);
	kept('PS1="\\x1b[32m\\u@\\h\\x1b[0m $ "\nNODE_ENV=production\n', "\\x1b[32m", FILE);
});

test("Redis's ACL rules hide the passwords they give and take away, and their hashes; the rest of the rule stays", () => {
	const conf =
		"requirepass R3dis-Requ1re-pw\nuser worker on >R3dis-Acl-worker-pw ~jobs:* +@all\nuser old off <R3dis-Old-pw\n";
	for (const pw of ["R3dis-Requ1re-pw", "R3dis-Acl-worker-pw", "R3dis-Old-pw"])
		hidden(conf, pw, { path: "deploy/redis/redis.conf" });
	kept(conf, "user worker on >[REDACTED", { path: "deploy/redis/redis.conf" });
	kept(conf, "~jobs:* +@all", { path: "deploy/redis/redis.conf" });
	const hash = Array.from(randomBytes(32), (b) => b.toString(16).padStart(2, "0")).join("");
	hidden(`user default on #${hash} ~* &* +@all\n`, hash, { path: "/etc/redis/users.acl" });
	// (nginx's `user` directive is no ACL rule.)
	kept("user www-data;\nworker_processes auto;\n", "www-data", FILE);
});

test("Bundler's credentials for a gem server are hidden in its config and learned, its settings kept", () => {
	const config =
		'---\nBUNDLE_PATH: "vendor/bundle"\nBUNDLE_JOBS: "8"\nBUNDLE_BUILD__NOKOGIRI: "--use-system-libraries"\nBUNDLE_GEMS__CONTRIBSYS__COM: "c3a91f0e:5d27b4e8"\n';
	assert.ok(isSecretFile("/home/dana/.bundle/config") && isSecretFile(".bundle/config"));
	hidden(config, "5d27b4e8", { path: "/home/dana/.bundle/config" });
	for (const setting of ['BUNDLE_PATH: "vendor/bundle"', 'BUNDLE_JOBS: "8"', '"--use-system-libraries"'])
		kept(config, setting, { path: "/home/dana/.bundle/config" });
	// `bundle config` prints the setting under the host's name, after the file was read.
	const redactor = r();
	redactor.learn(config, { hint: { path: "/home/dana/.bundle/config" } });
	const listing = 'gems.contribsys.com\nSet for the current user (/home/dana/.bundle/config): "c3a91f0e:5d27b4e8"\n';
	assert.ok(!redactor.redact(listing, { hint: { command: "bundle config" } }).text.includes("5d27b4e8"));
});

test("in a secret file a session's ID is hidden under anyone's name, a terminal's or a desktop's session kept", () => {
	const cookie = "58291746033%3AqZt7Ym2LkP4xVn%3A11%3AAYcR8vJ2kLmN0pQ5sT7uW9xZ1bD3fH5jK7mN9pR";
	const env = `INSTAGRAM_USERNAME=acme.shop\nINSTAGRAM_SESSION_ID=${cookie}\n`;
	hidden(env, "AYcR8vJ2kLmN0pQ5sT7uW9xZ1bD3fH5jK7mN9pR", { path: ".env" });
	kept(env, "INSTAGRAM_USERNAME=acme.shop", { path: ".env" });
	const listing =
		"TERM_SESSION_ID=w0t0p0:6F0E2B1C-8A4D-4E5F-9B3A-2C7D1E0F4A5B\nITERM_SESSION_ID=w0t0p0:6F0E2B1C-8A4D-4E5F-9B3A-2C7D1E0F4A5B\nWT_SESSION=3c1d2e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f\nXDG_SESSION_ID=2\nDESKTOP_SESSION=ubuntu\nSESSION_STORE=redis\n";
	for (const line of listing.trim().split("\n")) kept(listing, line, { command: "env" });
});

test("a command run as another user prints what that command prints, and so do find's and xargs' printers", () => {
	const env = "APP_NAME=shop\nSALT=k2Lm9Qx\nPORT=8080\n";
	for (const command of [
		"su -c 'cat .env' app",
		"su - app -c 'cat ~/.env'",
		"runuser -l app -c 'cat .env'",
		"find . -maxdepth 2 -name .env | xargs grep SALT",
		"find . -name .env -exec grep -H SALT {} +",
		`node -e "console.log(require('fs').readFileSync('.env', 'utf8'))"`,
		`python3 -c "from pathlib import Path; print(Path('.env').read_text())"`,
	])
		hidden(env, "k2Lm9Qx", { command });
	// (Listing, counting and editing in place print none of it, and a script that reads a file to change it prints what
	// it says.)
	for (const command of [
		"find . -name '*.key' | xargs grep -l ENCRYPTED | head -5",
		"find . -name .env -exec grep -c SALT {} +",
		"grep -R -o 'secret' . > /app/secret.txt && find . -type f -exec sed -i 's/secret/X/g' {} + && echo done",
		"cat > /tmp/fix.py <<'PY'\nfrom pathlib import Path\np = Path('.env')\ntext = p.read_text()\nPY",
	])
		kept(env, "k2Lm9Qx", { command });
	hidden('su - backup -c "mysqldump -u root -pS3cr3tPassw0rdX1 appdb > /backup/app.sql"', "S3cr3tPassw0rdX1");
});

test("a script that prints a generated key or a credential's variable prints a credential", () => {
	const hex = "9f2b7c1d4e8a03b56c7d9e1f2a4b6c8d0e3f5a7b9c1d2e4f6a8b0c3d5e7f9a1b";
	for (const command of [
		`node -p "require('crypto').randomBytes(32).toString('hex')"`,
		`python3 -c "import os; print(os.urandom(32).hex())"`,
		`php -r "echo bin2hex(random_bytes(32));"`,
	])
		hidden(`${hex}\n`, hex, { command });
	for (const command of [
		"Write-Host $env:DB_PASSWORD",
		`python3 -c "import os; print(os.environ['DB_PASSWORD'])"`,
		`node -e "console.log(process.env.DB_PASSWORD)"`,
	])
		hidden("Hx7mQ2pLvRt9zK", "Hx7mQ2pLvRt9zK", { command });
	kept("8080", "8080", { command: `python3 -c "import os; print(os.environ['PORT'])"` });
	// (A script that makes an ID with a generator, or reads a credential to use it, prints what it says it does.)
	for (const command of [
		`python3 -c "import os, subprocess\nuser = os.urandom(8).hex()\nsubprocess.run(['useradd', user])\nprint('sent')"`,
		`sed -i "s/os.urandom(3)/os.urandom(4)/" camera.py`,
		`node -e "\nconst ws = connect();\ntype(process.env.DB_PASSWORD);\nconsole.log('submitted');\n"`,
	])
		kept("submitted\n", "submitted", { command });
});

test("a jq filter's key name and a list of keys are no secret file", () => {
	for (const path of [".private_key", "keys.txt", "monkey.txt"]) assert.ok(!isSecretFile(path), path);
	hidden("curl -sS --proxy-user svc_build:Tz4nQ8vLm2Xe https://registry.npmjs.org/-/ping", "Tz4nQ8vLm2Xe");
});

const ENV = "APP_NAME=shop\nDEBUG=false\nSALT=k2Lm9Qx\nADMIN_PASS=Zq7vK2mP\n";

test("Windows' commands read a secret file in any case, findstr too, and a backslashed path is a Windows path", () => {
	for (const command of [
		"get-content .env",
		"Get-content .env",
		"TYPE .env",
		"Select-string SALT .env",
		"findstr SALT .env",
		"findstr /i salt .env",
		"findstr KEY C:\\app\\.env",
		"cat apps\\web\\.env.local",
		"cat config\\secrets.yml",
		"more backend\\.env.production",
		"sls KEY apps\\web\\.env.local",
		"cat %USERPROFILE%\\.ssh\\id_rsa",
	])
		hidden(ENV, "k2Lm9Qx", { command });
	for (const command of [
		"get-content README.md",
		"findstr TODO notes.txt",
		"cat apps\\web\\README.md",
		"TYPE notes.txt",
	])
		kept(ENV, "k2Lm9Qx", { command });
});

test("xargs and fd hand a secret file to a printer", () => {
	for (const command of [
		"find . -name '.env*' | xargs -I {} cat {}",
		"find . -name '.env*' | xargs -n 1 cat",
		"find . -name .env | xargs -P 4 cat",
		"find . -name .env | xargs -I {} sh -c 'echo {}; cat {}'",
		"fd .env -x cat",
	])
		hidden(ENV, "k2Lm9Qx", { command });
	for (const command of [
		"find . -name '*.md' | xargs -n 1 cat",
		"xargs -n 1 -a hosts.txt echo",
		"find . -name .env | xargs -n 1 wc -l",
		"find . -name .env | xargs -I {} sh -c 'echo {}; wc -l {}'",
	])
		kept(ENV, "k2Lm9Qx", { command });
});

test("cmd's and PowerShell's variables, environment drive and expressions print a credential", () => {
	for (const command of [
		"echo %APP_SECRET%",
		"cmd /c echo %APP_SECRET%",
		"echo ${env:APP_SECRET}",
		"Write-Output $Env:APP_SECRET",
		"(Get-Item Env:APP_SECRET).Value",
		"$env:DB_PASSWORD",
		"$cred.GetNetworkCredential().Password",
		"Get-Secret DbPassword -AsPlainText",
	])
		assert.ok(printsSecret(command), command);
	for (const command of [
		"echo %PATH%",
		"Get-Content Env:PATH",
		"$env:COMPUTERNAME",
		"$cred.UserName",
		"(Get-Item Env:PATH).Value",
		"Get-Secret DbPassword",
		// (A dictionary's keys are its names.)
		"$hash.Keys",
		"(Get-Command -Name Test-MrParameter).Parameters.Keys",
		"$_.Key",
	])
		assert.ok(!printsSecret(command), command);
	hidden("PS> $cred.GetNetworkCredential().Password\nC0r4l&96\nPS> ", "C0r4l&96");
	kept("PS> $env:COMPUTERNAME\nBUILD-AGENT-07\nPS> ", "BUILD-AGENT-07");
	kept("PS> $p.Keys\nPowerShell\nNotepad\n\nPS> $p.PowerShell\n", "Notepad");
	// (A member of the drive's items prints that member: `.Name` prints names.)
	kept("PS /home/user01> (Get-Item -Path Env:hOM[E]).Name\nHOME\n", "HOME");
	kept("PS> (Get-ChildItem Env:).Name\nAPI_TOKEN\nPATH\n", "API_TOKEN");
	// (One variable named in full is judged by its name.)
	kept("72f988bf-86f1-41af-91ab-2d7cd011db47\n", "72f988bf-86f1-41af-91ab-2d7cd011db47", {
		command: "(Get-Item Env:AZURE_TENANT_ID).Value",
	});
	kept(
		"Name                           Value\n----                           -----\nTEST                           test value\n",
		"test value",
		{
			command: "Get-ChildItem env:TEST",
		},
	);
	// (`Get-ChildItem Env:` and `Get-Item Env:NAME` print a table of names and values, read as printenv's listing.)
	const table = "Name                           Value\n----                           -----\n";
	for (const command of ["Get-ChildItem Env:", "gci env:", "Get-Item Env:APP_SECRET"]) {
		const text = `${table}APP_SECRET                     k2Lm9QxZ8\nPATH                           C:\\Windows\n`;
		hidden(text, "k2Lm9QxZ8", { command });
		kept(text, "C:\\Windows", { command });
	}
});

test("aws ssm get-parameters' PARAMETERS rows hide every row's value", () => {
	const rows =
		"PARAMETERS\tarn:aws:ssm:us-east-1:123456789012:parameter/app/db_pw\ttext\t1728900000.0\t/app/db_pw\tSecureString\tHx7mQ2pL9vRt\t3\n" +
		"PARAMETERS\tarn:aws:ssm:us-east-1:123456789012:parameter/app/api\ttext\t1728900000.0\t/app/api\tSecureString\tZq7Lm2Kx9Pw\t1\n";
	for (const command of [
		"aws ssm get-parameters-by-path --path /app --with-decryption --output text",
		"aws ssm get-parameters --names /app/db_pw /app/api --with-decryption --output text",
	]) {
		hidden(`$ ${command}\n${rows}`, "Hx7mQ2pL9vRt");
		hidden(`$ ${command}\n${rows}`, "Zq7Lm2Kx9Pw");
		kept(`$ ${command}\n${rows}`, "/app/db_pw");
	}
});

test("a credential command's output ends at a blank line or a markup tag", () => {
	for (const after of ["\n\nPerfect!\n", "\n</tool_result>\n", "\n\nAssistant\nexit_code=0\n"]) {
		const text = `$ gh auth token\ngho\x5faB3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1fH3jL5${after}`;
		hidden(text, "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1fH3jL5");
		for (const word of after.trim().split("\n")) kept(text, word);
	}
	// (A harness's wrapper, `<output>`, opens the output; its closer glued to the last line ends it.)
	const wrapped = "<returncode>0</returncode>\n<output>\nPassword: 1998\nhoneybear</output>";
	hidden(wrapped, "honeybear", { command: "pass show app/db" });
	kept(wrapped, "<output>", { command: "pass show app/db" });
	hidden("$ op read op://v/i/f\nAdmin: bob\nmonkeykingdom\n", "monkeykingdom");
});

test("a secret file's platforms, sizes and ports are settings, under a bare word too", () => {
	for (const [line, value] of [
		["PLATFORM=linux/amd64", "linux/amd64"],
		["ARCH=linux/arm64/v8", "linux/arm64/v8"],
		["RESOLUTION=1920x1080", "1920x1080"],
		["PORTS=8080/tcp", "8080/tcp"],
		["RANGE=5000-5010/udp", "5000-5010/udp"],
	])
		kept(`NODE_ENV=production\n${line}\n`, value, { command: "cat .env" });
	for (const [line, value] of [
		["STRIPE=Summer2024!", "Summer2024!"],
		["OPENAI=Ab3/xY9+kL2m", "Ab3/xY9+kL2m"],
	])
		hidden(`NODE_ENV=production\n${line}\n`, value, { command: "cat .env" });
});

test("an empty document and an INI section are no one-line secret file; one token in brackets is", () => {
	for (const [text, command] of [
		["{}\n", "cat ~/.docker/config.json"],
		["[]\n", "cat secrets.json"],
		["[default]\n", "head -1 ~/.aws/credentials"],
		["[profile.prod]\n", "head -1 ~/.aws/credentials"],
	])
		kept(text, text.trim(), { command });
	hidden("{Kd8pQ2zX9mL}\n", "Kd8pQ2zX9mL", { command: "cat ~/.vault_pass" });
	hidden("[Kd8pQ2zX9mL]\n", "Kd8pQ2zX9mL", { command: "cat ~/.vault_pass" });
});

test("htpasswd's LDAP-scheme hashes are read as its crypt hashes are", () => {
	for (const hash of [
		"{SHA}qUqP5cyxm6YcTAhz05Hph5gvu9M=",
		"{SSHA}W6ph5Mm5Pz8GgiULbPgzG37mj9gZm9v",
		"{SSHA512}W6ph5Mm5Pz8GgiULbPgzG37mj9gZm9vW6ph5Mm5Pz8GgiULbPgzG37mj9g",
		"$apr1$x9Kd2mQ7$abcdefghijklmnopqrstuv",
	]) {
		const out = r().redact(`bob:${hash}\ncarol:${hash}\n`, { hint: { path: "/etc/nginx/.htpasswd" } }).text;
		assert.ok(!out.includes(hash.slice(-12)), out);
		assert.ok(out.includes("bob:") && out.includes("carol:"), out);
	}
});

test("a secret file's padded assignments are read as assignments, so a reference among them stays", () => {
	const tfvars = [
		'grafana_admin_pass  = "Kx9mQ2pLw7vR"',
		'db_password         = "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf"',
		'api_key_secret_id   = "projects/468039570476/secrets/vllm-api-key/versions/latest"',
		'region              = "us-central1"',
	].join("\n");
	const path = { path: "infra/envs/prod/terraform.tfvars" };
	hidden(tfvars, "Kx9mQ2pLw7vR", path);
	kept(tfvars, "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf", path);
	kept(tfvars, "projects/468039570476/secrets/vllm-api-key/versions/latest", path);
	// (A table that a secret manager prints still has its values: `vault kv get`.)
	hidden("Key              Value\n---              -----\nclient_secret    Kx9mQ2pLw7vRtZ8n\n", "Kx9mQ2pLw7vRtZ8n", {
		command: "vault kv get secret/app",
	});
});

test("a command that prints a secret file's lines has them read as that file, name by name", () => {
	const out =
		"CLOUDINARY_URL=cloudinary://293633814225778:QbHn4SnyUiS6r_FY4XBPpMmW1YN@tulipa-shop\nNEXT_PUBLIC_CLOUDINARY_CLOUD_NAME=tulipa-shop\nNEXT_PUBLIC_CLOUDINARY_UPLOAD_PRESET=unsigned_products\n";
	const hint = { command: "vercel env pull .env.local && cat .env.local | grep -i cloudinary" };
	hidden(out, "QbHn4SnyUiS6r_FY4XBPpMmW1YN", hint);
	kept(out, "NEXT_PUBLIC_CLOUDINARY_UPLOAD_PRESET=unsigned_products", hint);
	kept(out, "NEXT_PUBLIC_CLOUDINARY_CLOUD_NAME=tulipa-shop", hint);
	hidden("STRIPE_SECRET_KEY=Kx9mQ2pLw7vRtZ8nB4cYd3Hq\nAPP_ENV=prod\n", "Kx9mQ2pLw7vRtZ8nB4cYd3Hq", {
		command: "heroku config -s",
	});
});
