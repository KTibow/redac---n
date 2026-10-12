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
import { findInSecretFile } from "../src/secretfile.ts";
import { b62, hidden, kept, r } from "./helpers.ts";

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

test("a ~/.netrc password is hidden", () => {
	hidden("machine api.example.com login me password Tq8vR3nWx5", "Tq8vR3nWx5", { path: "~/.netrc" });
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
});

test("a short number is a password in a .env only under a credential's name", () => {
	hidden("PORT=5432\nDB_PASSWORD=12345678\n", "12345678", { path: ".env" });
	kept("PORT=5432\nTOKEN_TTL=3600\n", "3600", { path: ".env" });
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

test("bin/rails credentials:show prints secrets", () => {
	hidden(
		"active_record_encryption:\n  primary_key: 2XhEAsfmNvCd8zQu43efeffpWOEa99vu",
		"2XhEAsfmNvCd8zQu43efeffpWOEa99vu",
		{ command: "bin/rails credentials:show" },
	);
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
	] as [string, string, { command?: string }?][])
		hidden(t, v, hint);
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

test("another occurrence of a guess is judged where it stands", () => {
	const pub = "rC6LxV3uCapgW94Y9+Wq/lsyx4zf04YAIuEZjQoHgWW=";
	const out = r().redact(`$ cat key.txt\n${pub}\n\n[Peer]\nPublicKey = ${pub}\nAllowedIPs = 10.8.0.9/32`).text;
	assert.ok(out.includes(`PublicKey = ${pub}`), out);
});
