/**
 * The shell lexer (src/shell.ts) and what is read through it: the commands a line runs, through wrappers and
 * reserved words; what a command writes into a secret file; and where a quoted or escaped password was written.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { printsSecret, printsSecretFile } from "../src/commands.ts";
import { Redactor } from "../src/index.ts";
import { shellCommands, simpleCommand, wordSpan } from "../src/shell.ts";

const read = (line: string) =>
	shellCommands(line).map((c) => [
		c.words.map((w) => w.text),
		c.redirects.map((r) => `${r.op}${r.target?.text ?? ""}`),
		c.then,
	]);

test("operators, redirections, comments, expansions and continuations", () => {
	assert.deepEqual(read("echo $DB_PASSWORD 2>&1 | head"), [
		[["echo", "$DB_PASSWORD"], [">&1"], "|"],
		[["head"], [], ""],
	]);
	assert.deepEqual(read("cat .env # a | b"), [[["cat", ".env"], [], ""]]);
	assert.deepEqual(read("x=$(a (b) && c); cat .env"), [
		[["x=$(a (b) && c)"], [], ";"],
		[["cat", ".env"], [], ""],
	]);
	assert.deepEqual(read("echo $(cat .env) `cat x y` ${A:-b c}"), [
		[["echo", "$(cat .env)", "`cat x y`", "${A:-b c}"], [], ""],
	]);
	assert.deepEqual(read("cat \\\n  .e\\\nnv &> out"), [[["cat", ".env"], ["&>out"], ""]]);
	assert.deepEqual(read("cat $'.e\\x6ev' \"a\\\"b\" 'c\\d'"), [[["cat", ".env", 'a"b', "c\\d"], [], ""]]);
});

test("quotes, expansions and escapes are read the way bash reads them", () => {
	// Quotes inside an expansion inside quotes; an expansion inside one, unquoted, with a blank in it.
	assert.deepEqual(read('cd "$(dirname "$0")" && cat .env'), [
		[["cd", '$(dirname "$0")'], [], "&&"],
		[["cat", ".env"], [], ""],
	]);
	assert.deepEqual(read('echo "${X:-"a b"}" ${GREETING:-${USER} was here}'), [
		[["echo", '${X:-"a b"}', "${GREETING:-${USER} was here}"], [], ""],
	]);
	assert.deepEqual(read('echo "today: `date`" | head'), [
		[["echo", "today: `date`"], [], "|"],
		[["head"], [], ""],
	]);
	assert.deepEqual(read("echo `dirname \\`which node\\`` x"), [[["echo", "`dirname \\`which node\\``", "x"], [], ""]]);
	// A backslash in single quotes is a character; in double quotes it escapes `"`, `\`, `$` and a backtick only.
	assert.deepEqual(read("tr '\\' '/' < in"), [[["tr", "\\", "/"], ["<in"], ""]]);
	assert.deepEqual(read('printf "%s\\n" "$TOKEN"'), [[["printf", "%s\\n", "$TOKEN"], [], ""]]);
	assert.deepEqual(read('echo $"Hello"'), [[["echo", "Hello"], [], ""]]);
	assert.deepEqual(read("find . -name \\*.env"), [[["find", ".", "-name", "*.env"], [], ""]]);
	// An expansion that doesn't close inside a quote runs to the end, as the quote does.
	assert.deepEqual(read('echo "a ${b c" d'), [[["echo", 'a ${b c" d'], [], ""]]);
	// What a substitution holds doesn't end it: a quoted `<`, a `#` inside a word, a `$`, a subshell in a `case` arm.
	for (const line of [
		"t=$(grep '<title>' a.html); cat .env",
		"n=$(grep -c ^#include main.c); cat .env",
		"x=$(echo $HOME); cat .env",
		"x=$(case $1 in a) (cd /tmp && ls);; esac); cat .env",
	])
		assert.equal(read(line).length, 2, line);
	// Blanks are spaces, tabs and a CRLF's carriage return; a comment ends at its line's end.
	assert.deepEqual(read("cat .env\r\necho\tx # note\ncat a"), [
		[["cat", ".env"], [], "\n"],
		[["echo", "x"], [], "\n"],
		[["cat", "a"], [], ""],
	]);
	// A redirection needs no blank before it; `>(…)` and `<(…)` are words, process substitutions.
	assert.deepEqual(read("cmd | tee >(sha256sum) 2>err>out"), [
		[["cmd"], [], "|"],
		[["tee", ">(sha256sum)"], [">err", ">out"], ""],
	]);
	assert.ok(printsSecretFile("sort < <(cat .env)"));
	// A command of redirections alone (`> app.log` empties the file) is a command.
	assert.deepEqual(read("> app.log"), [[[], [">app.log"], ""]]);
});

test("with backslashes off (Windows), a backslash is a character in quotes and substitutions too", () => {
	const win = (line: string) => shellCommands(line, 0, { backslash: false }).map((c) => c.words.map((w) => w.text));
	assert.deepEqual(win('cd "C:\\Program Files\\" && type .env'), [
		["cd", "C:\\Program Files\\"],
		["type", ".env"],
	]);
	assert.deepEqual(win("cd \\\ntype .env"), [
		["cd", "\\"],
		["type", ".env"],
	]);
	assert.deepEqual(win("echo $(dir C:\\) & type .env"), [
		["echo", "$(dir C:\\)"],
		["type", ".env"],
	]);
	assert.deepEqual(win('echo "C:\\logs\\\nb"'), [["echo", "C:\\logs\\\nb"]]);
	// (`$'…'` is bash's, and its escapes are read in either dialect.)
	assert.deepEqual(win("echo $'it\\'s' C:\\x"), [["echo", "it's", "C:\\x"]]);
});

test("one line read out of other text: a quote on it runs on for four more lines at most", () => {
	const line = (text: string) => shellCommands(text, 0, { oneLine: true }).map((c) => c.words.map((w) => w.text));
	assert.deepEqual(line("echo a\necho b"), [["echo", "a"]]);
	assert.deepEqual(line("echo a\nb\nc\nd\ne"), [["echo", "a"]]);
	assert.deepEqual(line("echo don't\na\nb\nc\nd\ne\nf'g"), [["echo", "dont\na\nb\nc\nd"]]);
});

test("groups: case arms, a function's body, closers, and reserved words only unquoted and first", () => {
	// A pattern's `|` is no pipe, in the first arm and after `;;`; an arm's own pipes are.
	assert.deepEqual(read("case $1 in start|stop) systemctl $1 app;; esac"), [[["systemctl", "$1", "app"], [], ""]]);
	assert.deepEqual(read("case $1 in start) run;; stop|kill) halt;; esac"), [
		[["run"], [], ";"],
		[["halt"], [], ""],
	]);
	for (const arm of ["cd /tmp; ls | wc -l", "echo logged in | wc -l", "echo case x 'in' | wc -l"])
		assert.equal(read(`case $1 in a) ${arm};; esac`).at(-2)?.[2], "|", arm);
	assert.equal(read("echo case x in | wc -l")[0][2], "|");
	// A group's redirection is its commands', `fi`'s too; a function's body is read.
	const [, inIf] = shellCommands("if a; then b; fi > out");
	assert.equal(inIf.groups[0].redirects[0].target?.text, "out");
	assert.deepEqual(read("deploy() { cat .env; }")[1][0], ["cat", ".env"]);
	// Quoted, or after a redirection, a reserved word is a command's word.
	for (const line of ["'{' a; '}'", "'!' { a; }", ">x { a; }"]) assert.equal(read(line).length, 2, line);
	assert.deepEqual(
		simpleCommand(shellCommands("'do' cat .env")[0].words).map((w) => w.text),
		["do", "cat", ".env"],
	);
});

test("a process substitution is a redirection's target, piped into the command that reads it", () => {
	assert.deepEqual(read("tee out.log < <(cat .env)"), [[["tee", "out.log"], ["<<(cat .env)"], ""]]);
	assert.ok(printsSecretFile("tee out.log < <(cat .env)"));
	assert.ok(!printsSecretFile("wc -l < <(cat .env)"));
});

test("a line that ends in a pipe or a list's operator goes on to the next, read as one line", () => {
	const first = (line: string) => shellCommands(line, 0, { oneLine: true }).map((c) => c.words[0].text);
	assert.deepEqual(first('echo "$PW" |\n  docker login --password-stdin\nls'), ["echo", "docker"]);
	assert.deepEqual(first("make &&\n  make install\nls"), ["make", "make"]);
	assert.deepEqual(first("make\nls"), ["make"]);
	const out = new Redactor().redact('echo "Plover7Tango" |\n  docker login -u me --password-stdin').text;
	assert.ok(!out.includes("Plover7Tango"), out);
});

test("heredocs: quoted delimiters, exact terminators, `<<-` tabs", () => {
	const [c] = shellCommands("cat > .env <<\\EOF\nA=1\n  EOF\nEOF\necho done");
	assert.equal(c.heredocs[0].quoted, true);
	assert.equal(
		"cat > .env <<\\EOF\nA=1\n  EOF\nEOF\necho done".slice(c.heredocs[0].start, c.heredocs[0].end),
		"A=1\n  EOF\n",
	);
	const [d] = shellCommands("tee .env <<-END\n\tA=1\n\tEND\nls");
	assert.equal(d.heredocs[0].terminated, true);
	// A second heredoc with the same delimiter ends at its own terminator.
	assert.deepEqual(read("cat <<EOF\na\nEOF\ncat <<EOF\nb\nEOF\necho x").at(-1), [["echo", "x"], [], ""]);
});

test("a password's span when quotes or escapes sit inside it", () => {
	const r = new Redactor();
	assert.equal(
		r.redact("mysql -u root --password='Xk9'\"mQ2pLw7v\" -h db").text.replace(/#\w+/, "#"),
		"mysql -u root --password=[REDACTED password #] -h db",
	);
	assert.equal(
		r.redact("mysql -u root -p'Xk9'\\''mQ2pLw7v' -h db").text.replace(/#\w+/, "#"),
		"mysql -u root -p'[REDACTED password #]' -h db",
	);
	// (Its quotes stay about it, as the word wrote them: `'admin:<it>'` keeps its closing quote.)
	assert.equal(
		r.redact("curl -u 'admin:Tr0ub4dor'\\''3xK9mQx7' https://x.io/api").text.replace(/#\w+/, "#"),
		"curl -u 'admin:[REDACTED password #]' https://x.io/api",
	);
	assert.equal(
		r.redact("sshpass -p Xk9\\ mQ2pLw7v ssh host").text.replace(/#\w+/, "#"),
		"sshpass -p [REDACTED password #] ssh host",
	);
	assert.equal(
		r.redact("export DB_PASSWORD='Xk9'\\''mQ2pLw7v'").text.replace(/#\w+/, "#"),
		"export DB_PASSWORD='[REDACTED password #]'",
	);
	const [w] = shellCommands("--password='pw9xQ2'")[0].words;
	assert.deepEqual(wordSpan(w, 11), { start: 12, end: 18 });
	// Not the `\`-newline after the quotes; and, for an empty value, nothing at the word's end.
	assert.deepEqual(wordSpan(shellCommands("a 'Xk9'\"mQ2\"\\\n b")[0].words[1]), { start: 2, end: 12 });
	assert.deepEqual(wordSpan(shellCommands("a --password=")[0].words[1], 11), { start: 13, end: 13 });
});

test("commands are read through wrappers, reserved words and revisions", () => {
	for (const c of [
		"sudo -u app cat .vault_pass",
		"sudo --user app cat .vault_pass",
		"timeout 5 cat .vault_pass",
		"{ cat .vault_pass; }",
		"if [ -f .env ]; then cat .env; fi",
		"git show HEAD:.env",
		"ssh host -- cat .env",
		"docker-compose exec app cat .env",
		"docker exec app \\\n  cat .env",
		"bash -lc 'cd /app && cat .env'",
		"docker exec app sh -c 'cat .env'",
		"cmd /c type .env",
		"kubectl run debug --rm -i --image=alpine -- cat /app/.env",
		"/usr/bin/grep -n KEY .env",
		"cat < .env",
		"declare -p",
	])
		assert.ok(printsSecretFile(c), c);
	for (const c of [
		"grep .env notes.txt",
		"/usr/bin/grep .env notes.txt",
		"echo x > .env",
		"cat ~/.ssh/config",
		"git show HEAD:src/config.ts",
		// (A job created runs its command later, where its output isn't shown.)
		"kubectl create job backup --image=alpine -- cat /app/.env",
	])
		assert.ok(!printsSecretFile(c), c);
	for (const c of [
		"echo $DB_PASSWORD 2>&1",
		'echo "$API_TOKEN" | tee /dev/stderr',
		"printf '%s\\n' \"$GITHUB_TOKEN\"",
		"echo $(gh auth token)",
		"sudo -E printenv OPENAI_API_KEY",
	])
		assert.ok(printsSecret(c), c);
	for (const c of ["echo '$DB_PASSWORD'", "echo $DB_HOST", "printf '%d' $TOKEN_COUNT"]) assert.ok(!printsSecret(c), c);
});

test("what a command line writes into a secret file is read as that file", () => {
	const r = new Redactor();
	for (const line of [
		"printf '%s' 'Harbor#2291x' > ~/.vault_pass",
		"echo 'Harbor#2291x' | tee ~/.vault_pass",
		"echo Harbor#2291x > ~/.vault_pass",
		"sudo tee .env > /dev/null <<EOF\nSTRIPE=Harbor#2291x\nEOF",
		"cat <<EOF | tee .env\nSTRIPE=Harbor#2291x\nEOF",
		"cat > .env <<\\EOF\nSTRIPE=Harbor#2291x\nEOF",
		"cat > .vault_pass <<EOF\n  EOF\nHarbor#2291x\nEOF",
		"if true; then echo 'Harbor#2291x'; fi > ~/.vault_pass",
	]) {
		assert.ok(!r.redact(line).text.includes("Harbor#2291x"), line);
	}
	// (An appended line is part of a file, not all of it.)
	assert.equal(
		r.redact("echo 'unixsocket /var/run/redis/redis.sock' | sudo tee -a /etc/redis/redis.conf").text,
		"echo 'unixsocket /var/run/redis/redis.sock' | sudo tee -a /etc/redis/redis.conf",
	);
});

test("groups, scripts, substitutions, Windows paths and wrappers are read through", () => {
	const r = new Redactor();
	for (const line of [
		"{ echo 'STRIPE=Harbor#2291x'; echo 'B=1'; } > .env",
		"(echo 'Harbor#2291x') > .vault_pass",
		"for v in a; do echo 'Harbor#2291x'; done > .vault_pass",
		"sudo sh -c \"echo 'Harbor#2291x' > /root/.vault_pass\"",
		"ssh prod \"echo 'Harbor#2291x' > ~/.vault_pass\"",
		"cat > .vault_pass <<< 'Harbor#2291x'",
		"echo 'Harbor#2291x' >& .vault_pass",
		"$ echo 'Harbor#2291x' > ~/.vault_pass",
		"const MB = 1 << 20;\ncat > .env <<'EOF'\nSTRIPE=Harbor#2291x\nEOF",
	]) {
		assert.ok(!r.redact(line).text.includes("Harbor#2291x"), line);
	}
	for (const c of [
		"ssh prod <<'EOF'\ncat /app/.env\nEOF",
		"docker exec -i app sh <<'EOF'\ncat .env\nEOF",
		'echo "$(cat .env)"',
		"git --no-pager show HEAD:.env",
		"docker container exec app cat .env",
		"Get-Content .\\.env",
		"type C:\\Users\\me\\.aws\\credentials",
		"sudo -iu app cat .vault_pass",
		"watch -d cat .vault_pass",
		"/usr/bin/time -f %e cat .vault_pass",
		"env -0",
	])
		assert.ok(printsSecretFile(c), c);
	for (const c of [
		"(gh auth token) | wc -c",
		"kubectl get secret db -o jsonpath='{.data.password}' | base64 -d | wc -c",
		"git commit -m 'explain gh auth token'",
	])
		assert.ok(!printsSecret(c), c);
	assert.ok(printsSecret("kubectl get secret db -o jsonpath='{.data.password}' | base64 -d"));
	assert.ok(!printsSecretFile("git commit -m 'docs: explain sops -d usage'"));
	// A hinted file's output isn't cut at an option file's `!include` or a value that starts with `!`.
	assert.ok(
		!r
			.redact("[auth]\npassword = Harbor#2291x\n!include extra.conf\nTOKEN=Tiger#7781yQ\n", {
				hint: { command: "cat ~/.my.cnf" },
			})
			.text.includes("Tiger#7781yQ"),
	);
	assert.equal(shellCommands("mysql --password=$'Xk9\\101mQ2pLw7v'")[0].words[1].text, "--password=Xk9AmQ2pLw7v");
});

test("a heredoc inside a substitution is text: an apostrophe in a commit message opens no quote", () => {
	const out = "SESSION=q8Zm2Lk\nHOOK=Kx9mQ2vLp7\n";
	for (const message of ["fix: do not leak", "fix: don't leak", "fix: # not a comment's 'quote"]) {
		const command = `git commit -m "$(cat <<'EOF'\n${message}\nEOF\n)" && cat .env`;
		assert.ok(!new Redactor().redact(out, { hint: { command } }).text.includes("Kx9mQ2vLp7"), message);
	}
	assert.equal(shellCommands("echo \"$(cat <<'EOF'\ndon't\nEOF\n)\"\ncurl -u a:b http://x").length, 2);
});

test("a prompt is read in the shapes terminals print it, and a comment or a heading is none", () => {
	const r = new Redactor();
	const body = "cat .env\nPORT=8080\nACMEPAY=Hx7mQ2pLw9zK\n";
	for (const prompt of [
		"bash-5.1$ ",
		"sh-4.2# ",
		"[ec2-user@ip-10-0-1-5 app]$ ",
		"[root@web01 ~]# ",
		"(venv) user@host:~/app$ ",
		"(base) $ ",
		"user@host app % ",
		"/app # ",
		"~ # ",
		"PS> ",
		"C:\\app>",
		"C:\\Users\\bob\\app> ",
	])
		assert.ok(!r.redact(`${prompt}${body}${prompt}ls\n`).text.includes("Hx7mQ2pLw9zK"), prompt);
	for (const line of ["# cat .env", "# Setup", "/dist # build output", "C:\\app>"])
		assert.ok(r.redact(`${line}\nACMEPAY=Hx7mQ2pLw9zK\n`).text.includes("Hx7mQ2pLw9zK"), line);
	// (cmd's prompt is cmd's line: its backslashes are a path's, and the command after it is read.)
	assert.ok(!r.redact('C:\\> sqlcmd -S db01 -U sa -P "G4rd3n!23" -Q "select 1"\n').text.includes("G4rd3n!23"));
	assert.ok(!r.redact("C:\\app>type config\\.env\nACMEPAY=Hx7mQ2pLw9zK\n\nC:\\app>").text.includes("Hx7mQ2pLw9zK"));
});

test("a heredoc or a here-string given to a wrapper is the stdin of the command it runs", () => {
	const r = new Redactor();
	for (const line of [
		"sudo sh -c 'cat > /etc/app/db_password' <<EOF\nHarbor#2291x\nEOF",
		"ssh deploy@10.0.0.5 'cat > ~/.vault_pass' <<'EOF'\nHarbor#2291x\nEOF",
		"docker exec -i app sh -c 'cat > /run/secrets/db_password' <<EOF\nHarbor#2291x\nEOF",
		"bash -c 'tee .env > /dev/null' <<EOF\nACMEPAY=Harbor#2291x\nEOF",
		"ssh host 'cat > ~/.vault_pass' <<< 'Harbor#2291x'",
	])
		assert.ok(!r.redact(line).text.includes("Harbor#2291x"), line);
	// (A file that is no secret file keeps what it is given; a heredoc that is the script is read as the script.)
	assert.ok(r.redact("ssh host 'cat > notes.txt' <<EOF\nACMEPAY=Hx7mQ2pLw9zK\nEOF").text.includes("Hx7mQ2pLw9zK"));
	assert.ok(r.redact("ssh prod <<'EOF'\ncat > notes.txt\nEOF").text.includes("cat > notes.txt"));
});

test("a group's pipe takes what every command in it prints", () => {
	const r = new Redactor();
	for (const line of [
		"{ echo A=1; echo 'STRIPE=Harbor#2291x'; } | tee .env",
		"{ echo 'STRIPE=Harbor#2291x'; echo A=1; } | tee .env",
		"bash -c \"echo 'STRIPE=Harbor#2291x'; echo A=1\" | tee .env",
	])
		assert.ok(!r.redact(line).text.includes("Harbor#2291x"), line);
});
