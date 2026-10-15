/**
 * Passwords and tokens given to command-line tools: option tables, positional and compound forms, wrappers and the
 * flags that look like one.
 *
 *   node --test test/command-lines.test.ts
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { isCommandKey } from "../src/json.ts";
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

test("a command line under any key named for one is read as one", () => {
	for (const key of ["CommandLine", "commandLine", "bash_command", "COMMAND_LINE", "shellCmd"])
		hidden(`{"${key}":"mysql -u root -pQm7vTx2LpR9sWd4Nz8K shop","Cwd":"/app"}`, "Qm7vTx2LpR9sWd4Nz8K");
	for (const key of ["subcommand", "description", "commander"]) assert.ok(!isCommandKey(key), key);
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
	// (Past prose before the command, and without the stop that ends its sentence.)
	hidden("Brute-force it: hydra -l admin -p Winter2024.", "Winter2024");
	kept("Brute-force it: hydra -l admin -p Winter2024.", ".");
	// The password a hash is made of, in a substitution inside a string.
	hidden('useradd -m -p "$(openssl passwd -6 Winter2024pw)" bob', "Winter2024pw");
	kept('useradd -m -p "$(openssl passwd -6 Winter2024pw)" bob', ')" bob');
	hidden("mkpasswd -m sha-512 Winter2024pw", "Winter2024pw");
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
	// A proxy's password, and HTTPie's `-a user:password` in its clone xh and in hey.
	for (const line of [
		"curl --proxy-user proxyuser:Hx7mQ2pL9vRt -x http://proxy:8080 https://x.com",
		"curl --proxy-user=u:Hx7mQ2pL9vRt https://x.com",
		"wget --proxy-user=u:Hx7mQ2pL9vRt https://x.com",
		"xh -a admin:Hx7mQ2pL9vRt https://api.example.com/x",
		"xhs --auth admin:Hx7mQ2pL9vRt https://api.example.com/x",
		"hey -a admin:Hx7mQ2pL9vRt -n 100 https://x.example.com",
	])
		hidden(line, "Hx7mQ2pL9vRt");
	kept("curl --proxy-user proxyuser:Hx7mQ2pL9vRt -x http://proxy:8080 https://x.com", "proxyuser:");
	kept("xh -a username:password https://pie.dev/basic-auth", "username:password");
	kept("hey -n 100 -A application/json https://x.example.com", "application/json");
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
	// After a line's own prefix: a workflow's one-line `run:`, a Dockerfile's RUN.
	for (const line of [
		"  - run: echo Hx7mQ2pLvRt9 | docker login ghcr.io -u bob --password-stdin",
		"RUN echo Hx7mQ2pLvRt9 | docker login -u bob --password-stdin",
	])
		hidden(line, "Hx7mQ2pLvRt9");
	kept("RUN echo Hx7mQ2pLvRt9 | wc -c", "Hx7mQ2pLvRt9");
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
		// After a cmd or PowerShell prompt, whose `>` is no redirect; and schtasks' `/p` for its `/u`.
		["C:\\Users\\bob> net use Z: \\\\srv\\share Harbor#2291x /user:CORP\\alice", S],
		["C:\\>net user svc Harbor#2291x /add", S],
		["PS C:\\> psexec \\\\srv -u admin -p Harbor#2291x cmd", S],
		["C:\\Users\\bob> sqlcmd -U sa -P Harbor#2291x", S],
		["schtasks /create /s srv /u bob /p Harbor#2291x /tn Backup /tr C:\\b.bat /sc daily", S],
	] as [string, string, { command?: string }?][])
		hidden(t, v, hint);
	kept("C:\\Users\\bob> net use Z: \\\\srv\\share Harbor#2291x /user:CORP\\alice", "C:\\Users\\bob> net use Z:");
	kept("schtasks /create /s srv /u bob /p Harbor#2291x /tn Backup", "/tn Backup");
	for (const [t, v, hint] of [
		["crypto isakmp key Harbor#2291x address 0.0.0.0", S],
		[" ip ospf message-digest-key 1 md5 Harbor#2291x", S],
		["crypto isakmp key Harbor#2291x hostname r1.example.com", S],
		["crypto ikev2 keyring KR\n peer P\n  pre-shared-key local Harbor#2291x", S],
		["crypto ikev2 keyring KR\n peer P\n  pre-shared-key remote Harbor#2291x", S],
		["snmp-server community Harbor#2291x view v1 RW", S],
		["SQL> connect scott/Harbor#2291x@orcl", S],
		["rman target sys/Harbor#2291x@db", S],
	] as [string, string, { command?: string }?][])
		hidden(t, v, hint);
	for (const line of ["snmp-server community public view v1 RO", "pre-shared-key is set per peer"])
		assert.equal(r().redact(line).text, line);
	kept("crypto isakmp key Harbor#2291x hostname r1.example.com", "hostname r1.example.com");
	hidden("docker exec -it oracle-db sqlplus sys/Oracle123x@ORCLPDB1 as sysdba", "Oracle123x");
	// An Oracle login with no `@db`, before the command's next word: an option, a script, a redirect.
	for (const line of [
		"expdp system/Hx7mQ2pLvRt9 directory=DP dumpfile=a.dmp",
		"impdp scott/Hx7mQ2pLvRt9 schemas=HR directory=DP",
		"sqlldr userid=scott/Hx7mQ2pLvRt9 control=a.ctl",
		"rman target sys/Hx7mQ2pLvRt9 nocatalog",
		"sqlplus -S scott/Hx7mQ2pLvRt9 @/opt/run.sql arg1",
		"sqlplus scott/Hx7mQ2pLvRt9 < run.sql",
		"sqlplus scott/Hx7mQ2pLvRt9 <<EOF\nselect 1 from dual;\nEOF",
	])
		hidden(line, "Hx7mQ2pLvRt9");
	for (const line of ["Connect input/output ports to the board", "sqlplus input/output files are written here"])
		assert.equal(r().redact(line).text, line);
	hidden("::add-mask::correct horse battery staple", "horse battery staple");
	// (What a workflow masks is secret whatever its shape, a version's included.)
	hidden('echo "::add-mask::v1.2.3"', "v1.2.3");
});

test("a command that wraps another still hides its password: pipes, sudo, images, substitutions, environment prefixes", () => {
	const pw = "vbrzzeN7T9J2xk";
	hidden(`127.0.0.1:6379> AUTH ${pw}\nOK`, pw);
	hidden(`127.0.0.1:6379> CONFIG GET requirepass\n1) "requirepass"\n2) "${pw}"`, pw);
	// A Redis ACL rule's password, added or removed, in a session and in an ACL file.
	hidden(`127.0.0.1:6379> ACL SETUSER bob on >${pw} ~* +@all`, pw);
	hidden(`ACL SETUSER bob <${pw}`, pw);
	hidden(`user bob on >${pw} ~* +@all`, pw);
	kept("user default on nopass ~* +@all", "nopass ~* +@all");
	kept("user bob is logged in > out.txt", "out.txt");
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
	// (The group's blanks as the pattern writes them.)
	hidden("sed -i -E 's/(DB_PASSWORD[ ]*=[ ]*).*/\\1Summer2024!/' .env", "Summer2024!");
	hidden("sed -i 's/\\(DB_PASSWORD\\s*=\\s*\\).*/\\1Summer2024!/' .env", "Summer2024!");
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

test("a tool's own password word is read where its syntax puts it, and the words beside it are kept", () => {
	hidden("vault login -method=ldap username=alice password=correct-horse", "correct-horse");
	kept("vault login -method=ldap username=alice password=correct-horse", "username=alice");
	hidden("rabbitmqctl change_password guest Xk9mQ2pLrT", "Xk9mQ2pLrT");
	hidden("pulumi config set --secret db:pw correct-horse", "correct-horse");
	hidden("pulumi -C infra config set --secret -s dev db:pw correct-horse", "correct-horse");
	hidden("echo correct-horse | pulumi config set --secret db:pw", "correct-horse");
	kept("pulumi config set aws:region us-east-1", "us-east-1");
	hidden("openssl passwd -1 -salt xyz12 'correct horse'", "correct horse");
	kept("openssl passwd -1 -salt xyz12 'correct horse'", "-salt xyz12");
	for (const line of [
		"schtasks /create /tn Backup /tr C:\\b.bat /sc daily /ru CORP\\svc /rp correct-horse",
		"psexec \\\\srv01 -u admin -p correct-horse cmd",
		"osql -S srv -U sa -P correct-horse",
	])
		hidden(line, "correct-horse");
	// A wrapper's own options end where the command it runs starts: ssh's `-p` is a port.
	hidden("sshpass -p Xk9mQ2pLrT ssh -p 2222 deploy@host", "Xk9mQ2pLrT");
	kept("sshpass -p Xk9mQ2pLrT ssh -p 2222 deploy@host", "2222");
	// A one-letter option with its value attached is a password only when it's the password's letter.
	kept("mysql -hdb.internal -uadmin -pXk9mQ2pLrT", "-hdb.internal");
	kept("mysql -u root -p appdb_production", "appdb_production");
	kept("redis-cli -h cache -p6380 ping", "6380");
	kept("smbclient //server/share -U alice", "alice");
	// Only echo and printf print their operand into a pipe: cat prints the file it names.
	kept("echo start && cat registry-pass | docker login -u bob --password-stdin", "registry-pass");
});

test("a command cut short before its password, which it then asks for, keeps its line", () => {
	for (const t of [
		"rabbitmqctl add_user bob",
		"htpasswd -b .htpasswd admin",
		"mongo -u admin -p",
		"smbclient //srv/share -U",
		"schtasks /create /tn Backup /ru CORP\\svc /rp",
		"psexec \\\\srv01 -u admin -p",
		"echo hello |",
		'command: ["redis-server", "--requirepass", "--appendonly", "yes"]',
	])
		assert.equal(r().redact(t).text, t);
});

test("a program's own password option takes its quoted value whole; a bare one ends at a path or a sentence's end", () => {
	hidden("$ hydra -l admin -p 'Xk9(mP2vQ7' ssh://t", "Xk9(mP2vQ7");
	hidden("$ xfreerdp /u:a /p:'a1B2c3D4/e5' /v:h", "a1B2c3D4/e5");
	hidden("nmcli dev wifi connect Home password correct_horse", "correct_horse");
	hidden("unrar x -pXk9mQ2pLrT archive.rar", "Xk9mQ2pLrT");
	hidden("hurl --user bob:'$ecret99x' api.hurl", "$ecret99x");
	hidden("Run `ssh-keygen -t ed25519 -N Kx9mQv2Lp7Rt` first", "Kx9mQv2Lp7Rt");
	assert.match(r().redact("Here's how: hydra -l admin -p Winter2024.").text, /-p \[REDACTED password #\w+\]\.$/);
	kept("crackmapexec smb 10.0.0.0/24 -u admin -p /tmp/pwlist", "/tmp/pwlist");
	kept("nxc smb hosts.txt -u users.txt -p passwords.txt", "passwords.txt");
	// (rar's `-p` alone asks for the password.)
	kept("unrar x -p archive.rar", "archive.rar");
	kept("rar a -p backup.rar docs/", "backup.rar");
	// After a `password` word on any other command, only a password's shape.
	kept("Avoid password re-use across accounts", "re-use");
	kept("Store the password LastPass generated for you", "LastPass");
});

test("an option's value names no program: `dvc stage add -n hydra -p` gives a stage its parameters", () => {
	kept("dvc stage add -n hydra -p 'params.yaml:' 'cat params.yaml'", "params.yaml:");
	kept("dvc stage add -n medusa -p train.epochs python train.py", "train.epochs");
	hidden("hydra -l admin -p 'Xk9(mP2vQ7' ssh://t", "Xk9(mP2vQ7");
	hidden("Brute-force it: hydra -l admin -p Winter2024.", "Winter2024");
});

test("vault login takes one token: a changelog's sentence and a usage line after it are kept", () => {
	for (const [line, word] of [
		[
			"* auth/alicloud: fix regression in vault login command that caused login to fail [[GH-19005](https://x)]",
			"command",
		],
		["* auth: Fixed erroneous success message when using vault login in case of two-phase MFA", "two-phase"],
		[
			"* auth: Fixed missing information from table format when using vault login [[GH-15428](https://x)]",
			"[[GH-15428]",
		],
		["Usage: vault login TOKEN [CONFIG K=V...]", "[CONFIG"],
		["Usage: vault login -method=aws [CONFIG K=V...]", "[CONFIG"],
	])
		kept(line, word);
	hidden("$ vault login 96ddf4bc-d217-f3ba-f9bd-017055595017", "96ddf4bc-d217-f3ba-f9bd-017055595017");
	hidden("$ vault login correcthorse", "correcthorse");
	hidden("$ vault login token=Kx9mQ2vLp7Rt3Wz8 lookup=false", "Kx9mQ2vLp7Rt3Wz8");
});

test("a command written as a list is read in single quotes and over CRLF and tabs, and keeps its quotes", () => {
	hidden("subprocess.run(['redis-cli', '-a', 'correct-horse', 'ping'])", "correct-horse");
	hidden('{\r\n\t"cmd": [\r\n\t\t"redis-cli",\r\n\t\t"-a",\r\n\t\t"correct-horse"\r\n\t]\r\n}', "correct-horse");
	kept('{"cmd": ["redis-cli", "-a", "correct\\"horse"]}', '"-a", "[REDACTED');
});

test("cypher-shell's -p is a password, and a process listing's command is read past its columns", () => {
	const pw = "Xk2mP9vLqT";
	hidden(`cypher-shell -a bolt://localhost:7687 -u neo4j -p ${pw} -f seed.cypher`, pw);
	kept(`cypher-shell -a bolt://localhost:7687 -u neo4j -p ${pw} -f seed.cypher`, "-u neo4j");
	const ps = { command: "ps -eo pid,args" };
	hidden(
		`  73104 /var/lib/neo4j/bin/cypher-shell -a bolt://localhost:7687 -u neo4j -p ${pw} -f /import/seed.cypher`,
		pw,
		ps,
	);
	hidden(`root     73104  0.0  0.1 pts/0 Ss+ Oct10 0:00 /usr/bin/redis-cli -a ${pw} ping`, pw, { command: "ps aux" });
	// (A path after a command's own words is its argument: `find` runs, not mysql.)
	kept(`find /var/lib/mysql -perm ${pw}`, pw);
});
