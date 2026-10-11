/**
 * The shell lexer (src/shell.ts) and what is read through it: the commands a line runs, through wrappers and
 * reserved words; what a command writes into a secret file; and where a quoted or escaped password was written.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { printsSecret, printsSecretFile } from "../src/commands.ts";
import { Redactor } from "../src/index.ts";
import { shellCommands, wordSpan } from "../src/shell.ts";

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

test("heredocs: quoted delimiters, exact terminators, `<<-` tabs", () => {
	const [c] = shellCommands("cat > .env <<\\EOF\nA=1\n  EOF\nEOF\necho done");
	assert.equal(c.heredocs[0].quoted, true);
	assert.equal(
		"cat > .env <<\\EOF\nA=1\n  EOF\nEOF\necho done".slice(c.heredocs[0].start, c.heredocs[0].end),
		"A=1\n  EOF\n",
	);
	const [d] = shellCommands("tee .env <<-END\n\tA=1\n\tEND\nls");
	assert.equal(d.heredocs[0].terminated, true);
});

test("a password's span when quotes or escapes sit inside it", () => {
	const r = new Redactor();
	assert.equal(
		r.redact("mysql -u root --password='Xk9'\"mQ2pLw7v\" -h db").text.replace(/#\w+/, "#"),
		"mysql -u root --password=[REDACTED password #] -h db",
	);
	assert.equal(
		r.redact("mysql -u root -p'Xk9'\\''mQ2pLw7v' -h db").text.replace(/#\w+/, "#"),
		"mysql -u root -p[REDACTED password #] -h db",
	);
	assert.equal(
		r.redact("sshpass -p Xk9\\ mQ2pLw7v ssh host").text.replace(/#\w+/, "#"),
		"sshpass -p [REDACTED password #] ssh host",
	);
	const [w] = shellCommands("--password='pw9xQ2'")[0].words;
	assert.deepEqual(wordSpan(w, 11), { start: 12, end: 18 });
});

test("commands are read through wrappers, reserved words and revisions", () => {
	for (const c of [
		"sudo -u app cat .vault_pass",
		"timeout 5 cat .vault_pass",
		"{ cat .vault_pass; }",
		"if [ -f .env ]; then cat .env; fi",
		"git show HEAD:.env",
		"ssh host -- cat .env",
		"docker-compose exec app cat .env",
		"docker exec app \\\n  cat .env",
		"bash -lc 'cd /app && cat .env'",
		"/usr/bin/grep -n KEY .env",
		"cat < .env",
	])
		assert.ok(printsSecretFile(c), c);
	for (const c of ["grep .env notes.txt", "/usr/bin/grep .env notes.txt", "echo x > .env", "cat ~/.ssh/config"])
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
