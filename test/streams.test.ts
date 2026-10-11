/**
 * stream(): the same findings as redact() at every cut, far context kept across the holdback, and nothing released
 * half-read.
 *
 *   node --test test/streams.test.ts
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { b62, r } from "./helpers.ts";

test("a stream equals whole-text redaction at every cut and never leaks a key across chunks", () => {
	const tok = `ghp_${b62(36)}`;
	const text = `line one\nexport GITHUB_TOKEN=${tok}\n${"filler line\n".repeat(50)}`;
	for (let cut = 1; cut < 60; cut += 3) {
		const s = r().stream({ holdback: 64 });
		const out = s.write(text.slice(0, cut + 20)) + s.write(text.slice(cut + 20)) + s.end();
		assert.ok(!out.includes(tok.slice(4, 20)), `leak at cut ${cut}`);
		assert.equal(out, r().redact(text).text);
	}
});

test("a stream reads far context as redact() does: open prompts, heredocs, fences and manifests", () => {
	const streamed = (text: string) => {
		const s = r().stream();
		let out = "";
		for (let i = 0; i < text.length; i += 4096) out += s.write(text.slice(i, i + 4096));
		return out + s.end();
	};
	const b64 = (v: string) => Buffer.from(v).toString("base64");
	const env = Array.from({ length: 4000 }, (_, i) => `STRIPE=Harbor${1000 + i}#q`).join("\n");
	const prose = Array.from({ length: 2000 }, (_, i) =>
		i % 50 === 30 ? `Kx9mQ2pLw7vR${i}` : `Paragraph ${i}: the deployment notes describe how the service is configured.`,
	).join("\n");
	for (const text of [
		// kubectl prints `data:` before `kind: Secret`.
		`apiVersion: v1\ndata:\n${Array.from({ length: 3000 }, (_, i) => `  setting${i}: ${b64(`Harbor${1000 + i}#q`)}`).join("\n")}\nkind: Secret\nmetadata:\n  name: app\n`,
		`!cat .env\n${env}\n`,
		`cat > .env <<'EOF'\n${env}\nEOF\n`,
		// A diff that adds `.env`, a coloured prompt, two heredocs on one line, and one JSONL line holding a session.
		`diff --git a/.env b/.env\n--- /dev/null\n+++ b/.env\n@@ -0,0 +1,4000 @@\n${env
			.split("\n")
			.map((l) => `+${l}`)
			.join("\n")}\n`,
		`\x1b[1;32muser@box\x1b[0m:~$ cat .env\n${env}\n`,
		`cat <<A > notes.txt; cat <<B > .env\n${prose}\nA\n${env}\nB\n`,
		`${JSON.stringify({ type: "tool_result", content: `$ cat .env\n${env}` })}\n`,
		// A fence closes the session it shows.
		`\`\`\`\n$ cat .env\nLOG=info\n\`\`\`\n${prose}\n`,
	]) {
		assert.ok(text.length > 40_000);
		assert.equal(streamed(text), r().redact(text).text, text.slice(0, 40));
	}
});

test("a stream keeps left context across its holdback", () => {
	const pad = Array.from({ length: 400 }, (_, i) => `filler line number ${i} with ordinary words`).join("\n") + "\n";
	const text = `${pad}Here's your new API key:\nXq7Lm2Vb9Rt4Np8KwZ3cAb\n${pad}`;
	const s = r().stream({ holdback: 8192 });
	const at = pad.length + 26 + 8192 - 30;
	const out = s.write(text.slice(0, at)) + s.write(text.slice(at)) + s.end();
	assert.ok(!out.includes("Xq7Lm2Vb9Rt4Np8KwZ3cAb"));
});

test("a long cat .env streamed in chunks keeps its prompt", () => {
	let t = "$ cat .env\n";
	for (let i = 0; i < 3000; i++) t += `SETTING_${i}=v${i % 7}x\n`;
	t += "APP_SECRET=hello\n";
	const s = r().stream();
	let out = "";
	for (let i = 0; i < t.length; i += 2000) out += s.write(t.slice(i, i + 2000));
	out += s.end();
	assert.ok(!out.includes("APP_SECRET=hello"));
});

test("a value named long before is hidden in a stream as in redact()", () => {
	const R = r();
	const pw = "Wint3r!Sky-42x";
	let text = `DB_PASSWORD=${pw}\n`;
	for (let i = 0; i < 1500; i++) text += `commit message ${i}: fix the build on the main branch\n`;
	text += `deploy used ${pw} yesterday\n`;
	const s = R.stream();
	let out = "";
	for (let i = 0; i < text.length; i += 4000) out += s.write(text.slice(i, i + 4000));
	out += s.end();
	assert.ok(!out.includes(pw));
});

test("a stream cut between a JSON key and its number hides the number", () => {
	const text = `{"x":"${"a".repeat(20000)}","pin": 4821}${"b".repeat(30000)}`;
	const s = r().stream({ holdback: 8192 });
	assert.ok(/"pin": "\[REDACTED/.test(s.write(text) + s.end()));
});

test("a stream never releases half a surrogate pair", () => {
	const out = r()
		.stream()
		.write(`x${"\u{1F600}".repeat(40000)}y`);
	assert.equal(Buffer.from(out).toString(), out);
});
