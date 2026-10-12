/**
 * Passwords and tokens given to command-line tools: option tables, positional and compound forms, wrappers and the
 * flags that look like one.
 *
 *   node --test test/command-lines.test.ts
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { hidden, kept, r } from "./helpers.ts";

test("a password flag hides its value in option, attached, list and compound forms, and the rest of the line is kept", () => {
	const pw = "Winter2024pass";
	hidden(`redis-cli -h localhost -p 6379 -a ${pw} ping`, pw);
	kept(`redis-cli -h localhost -p 6379 -a ${pw} ping`, "6379");
	hidden(`ldapsearch -x -D cn=admin,dc=x -w ${pw}`, pw);
	hidden(`htpasswd -nb admin ${pw}`, pw);
	hidden(`["--password", "${pw}"]`, pw);
	hidden(`CMD ["redis-server", "--requirepass", "${pw}"]`, pw);
	hidden(`        args:\n        - --password\n        - ${pw}`, pw);
	hidden(`curl -uadmin:${pw} https://x`, pw);
	hidden(`sshpass -p${pw} ssh user@h`, pw);
	hidden(`htpasswd -b -B -C 10 .htpasswd admin ${pw}`, pw);
	hidden("chown app:app /srv && curl -u admin:48213579 https://x.example.com", "48213579");
	hidden(`['machine h\\n', '  login bob\\n', '  password ${pw}\\n']`, pw);
	hidden("redis-cli -h cache -a '-Xk9mP2vQ7tL4wR8nZ3bY6' ping", "Xk9mP2vQ7tL4wR8nZ3bY6");
	kept("mysql -u root --password mydb", "mydb");
	hidden("mysql -h db -u admin \\\n  --password \\\n  Vq8#Lm2!Rz7pKw \\\n  -e 'select 1'", "Vq8#Lm2!Rz7pKw");
	hidden("mysql -u root -phxTws&.E%IC|WNojzKZO4 app", "WNojzKZO4");
	for (const line of [
		"az login --service-principal -u app -p 'Xk9mQ2pLrT' --tenant t",
		"gh secret set DB_PASS -b 'Xk9mQ2pLrT'",
		"unzip -P 'Xk9mQ2pLrT' backup.zip",
		"7z x backup.7z -pXk9mQ2pLrT",
		"vault login Xk9mQ2pLrT",
		"vault login -method=userpass username=bob password=Xk9mQ2pLrT",
		"lftp -u bob,Xk9mQ2pLrT sftp://host",
	])
		hidden(line, "Xk9mQ2pLrT");
});

test("a program's own password option is read, catalogued or not", () => {
	for (const line of [
		"hydra -l admin -p Kx9mQv2Lp7Rt ssh://h",
		"xfreerdp /u:alice /p:Kx9mQv2Lp7Rt /v:h",
		"ssh-keygen -t ed25519 -N Kx9mQv2Lp7Rt",
		"nmcli dev wifi connect HomeNet password Kx9mQv2Lp7Rt",
		"    storePassword 'Kx9mQv2Lp7Rt'",
	])
		hidden(line, "Kx9mQv2Lp7Rt");
	hidden("hydra -l admin -p correct_horse ssh://h", "correct_horse");
	hidden("keytool -genkey -keystore release.keystore -storepass android", "android");
	hidden("$ http -a ops:Xk9mQ2vL8nR GET https://x", "Xk9mQ2vL8nR");
	hidden("$ http -a ops:CANYttjlub% GET https://registry.internal.example.com/v2/_catalog", "CANYttjlub%");
	hidden('echo "Plover7Tango" | buildkite-agent redactor add\nlater: Plover7Tango', "Plover7Tango");
	hidden("http --auth=alice:Hx7mQ2pLw9zK GET https://api.example.com/me", "Hx7mQ2pLw9zK");
	kept("http --auth=alice:Hx7mQ2pLw9zK GET https://api.example.com/me", "alice:");
	kept(
		"helm upgrade r bitnami/postgresql --set auth.postgresPassword=Xk9mQ2vR7tL4,auth.database=app",
		"auth.database=app",
	);
	hidden(
		"helm upgrade r bitnami/postgresql --set auth.postgresPassword=Xk9mQ2vR7tL4,auth.database=app",
		"Xk9mQ2vR7tL4",
	);
	kept("date -u +%Y-%m-%dT%H:%M:%SZ", "%M:%SZ");
	hidden("Use -u admin:Xk9mQ2pL to log in", "Xk9mQ2pL");
	kept("docker run --rm -u 1000:1000 -p 443:443 img", "1000:1000");
	hidden("curl -u admin:48213579 https://x.example", "48213579");
});

test("a password in a tool's own syntax is hidden: user%password, user/password@db, +login, -passout pass:, net use, device keys", () => {
	hidden("./gradlew assembleRelease -PRELEASE_STORE_PASSWORD=Birch!76kq", "Birch!76kq");
	hidden("mosquitto_pub -h broker -u iot -P 'CINDnzcqwz!' -t x -m 1", "CINDnzcqwz!");
	hidden("sudo net ads join -U Administrator%Winter2008$", "Winter2008$");
	hidden("sqlplus scott/WILLwv60a6%@ORCL", "WILLwv60a6%");
	hidden("steamcmd +login builder QuartzLantern974 +quit", "QuartzLantern974");
	hidden("curl -b 'theme=dark; sessionid=LRxXLyjkgBBxpa9q' https://x", "LRxXLyjkgBBxpa9q");
	hidden("openssl pkcs12 -export -in c.crt -inkey c.key -out c.p12 -passout pass:RIPPr871d3%", "RIPPr871d3%");
	hidden(
		"printf '%s' 'qe2sLLGCUeJemSaDuso7oyLTsRv7q478' | podman login -u bob --password-stdin quay.io",
		"qe2sLLGCUeJemSaDuso7oyLTsRv7q478",
	);
	for (const [t, v] of [
		["jdbc:oracle:thin:admin/s3cr3tP4ss@ora.proddb.net:1521:ORCLDB", "s3cr3tP4ss"],
		["net use Z: \\\\server\\share /user:DOMAIN\\admin P@ssw0rd9", "P@ssw0rd9"],
		["enable secret SuperS3cret!", "SuperS3cret!"],
	])
		hidden(t, v);
	const S = "Harbor#2291x";
	for (const [t, v, hint] of [
		["docker run -e 'POSTGRES_PASSWORD==l=<c.$Sz8l@HA}&rYg*' postgres", "l=<c.$Sz8l"],
		["net use Z: \\\\srv\\share Harbor#2291x /user:CORP\\alice", S],
		["net user svc Harbor#2291x /add", S],
		["winrs -r:srv -u:admin -p:Harbor#2291x ipconfig", S],
	] as [string, string, { command?: string }?][])
		hidden(t, v, hint);
	for (const [t, v, hint] of [
		["crypto isakmp key Harbor#2291x address 0.0.0.0", S],
		[" ip ospf message-digest-key 1 md5 Harbor#2291x", S],
		["SQL> connect scott/Harbor#2291x@orcl", S],
		["rman target sys/Harbor#2291x@db", S],
	] as [string, string, { command?: string }?][])
		hidden(t, v, hint);
	hidden("docker exec -it oracle-db sqlplus sys/Oracle123x@ORCLPDB1 as sysdba", "Oracle123x");
	hidden("::add-mask::correct horse battery staple", "horse battery staple");
	// (What a workflow masks is secret whatever its shape, a version's included.)
	hidden('echo "::add-mask::v1.2.3"', "v1.2.3");
});

test("a command that wraps another still hides its password: pipes, sudo, images, substitutions, environment prefixes", () => {
	const pw = "vbrzzeN7T9J2xk";
	hidden(`127.0.0.1:6379> AUTH ${pw}\nOK`, pw);
	hidden(`127.0.0.1:6379> CONFIG GET requirepass\n1) "requirepass"\n2) "${pw}"`, pw);
	hidden(`java -Dspring.datasource.password=${pw} -jar app.jar`, pw);
	hidden(`echo '${pw}' | sudo -S apt update`, pw);
	hidden(`echo ${pw} | docker login -u bob --password-stdin`, pw);
	hidden('printf "%s\\n" "Plum-Harbor-77" | sudo -S apt-get update', "Plum-Harbor-77");
	hidden('echo -n "Xq7Lp2Nz4Kb8Rt3Wm6Yc1Vd5Hf0JsAe" | base64', "Xq7Lp2Nz4Kb8Rt3Wm6Yc1Vd5Hf0JsAe");
	for (const json of [
		'{"type":"tool_use","name":"Bash","input":{"command":"sshpass -p Harbor2291! ssh deploy@host"}}',
		'{"cmd":["bash","-lc","sshpass -p Harbor2291! ssh deploy@host"]}',
	])
		hidden(json, "Harbor2291!");
	for (const line of [
		"API_KEY=Kx9mQv2Lp7Rt gh pr list",
		"STRIPE_KEY=Summer2024! vercel deploy",
		"TOKEN=Kx9mQv2Lp7Rt nginx",
	]) {
		const out = r().redact(line).text;
		assert.ok(!/Kx9mQv2Lp7Rt|Summer2024!/.test(out) && / (?:gh pr list|vercel deploy|nginx)$/.test(out), out);
	}
	hidden("sed -i 's/^DB_PASSWORD=.*/DB_PASSWORD=Kx9mQ2vL7pZrTq8Wn3Xc/' .env", "Kx9mQ2vL7pZrTq8Wn3Xc");
	hidden("perl -pi -e 's/^API_KEY=.*/API_KEY=Harbor2291x/' .env", "Harbor2291x");
	hidden("sed -E 's/(API_KEY=).*/\\1Kx9mQ2vL7pZrTq8Wn3Xc/' .env", "Kx9mQ2vL7pZrTq8Wn3Xc");
	hidden("aws configure set aws_secret_access_key Kx9mQ2vL7pZrTq8Wn3Xc", "Kx9mQ2vL7pZrTq8Wn3Xc");
	hidden("reg add HKLM\\Software\\App /v Password /t REG_SZ /d Harbor2291x /f", "Harbor2291x");
	hidden("docker run --rm redis redis-cli -a Xk9mQ2vR7tL4pW8 ping", "Xk9mQ2vR7tL4pW8");
	hidden(
		'docker run --rm curlimages/curl -b "session=kX9mQ2vR7tL4pW8nZ3bY6c" https://x.example.com',
		"kX9mQ2vR7tL4pW8nZ3bY6c",
	);
});

test("a word that looks like a password option is no password", () => {
	kept('using commands: `id -u`:`id -G | cut -d" " -f2`', "`id -G");
	kept('curl --cookie "sessionid=Xq7Lm2Vb9Rt4Np8K" https://x', "sessionid=");
	kept("See the sqlplus docs/manual at /u01/app", "docs/manual");
	const t = "msbuild /p:Configuration=Release";
	assert.equal(r().redact(t).text, t);
	kept("docker exec -u www-data:www-data app php artisan migrate", "www-data:www-data");
	kept(
		'ldapsearch -D "cn=admin,dc=ldap-testing,dc=example,dc=com" -w Password1 -b "dc=ldap-testing,dc=example,dc=com"',
		"dc=ldap-testing,dc=example,dc=com",
	);
	kept('gh secret set AZURE_TENANT_ID --body "56154c80-8d45-45fc-96e8-b3c2f27931bf"', "56154c80-8d45");
	kept("gh pr create -b 'Fix the thing'", "Fix the thing");
	for (const line of [
		"docker run -p 8080:80 nginx",
		"mkdir -p Src/Main",
		"$ mongo -u admin -p --authenticationDatabase admin",
		"puts 'hello world'",
	])
		kept(line, line.split(" ").at(-1)!);
	kept("ncrack -p 22,3389 host", "22,3389");
});

test("OpenSSL's pass phrase source and helm's --set list: the phrase after pass:, a value to its list's comma", () => {
	const out = r().redact("openssl enc -aes-256-cbc -pass pass:sunshine -in f").text;
	assert.ok(out.includes("-pass pass:[REDACTED") && !out.includes("sunshine"), out);
	kept("openssl enc -aes-256-cbc -pass file:pw.txt -in f", "file:pw.txt");
	hidden("helm install db bitnami/postgresql --set auth.password=sun\\,shine9X,auth.database=app", "shine9X");
	hidden("helm install db bitnami/postgresql --set adminPassword='p-NK,fXk9mQ2pLrT'", "fXk9mQ2pLrT");
});
