/**
 * redactValue: what is sent, keys, ids, attached documents, the findings cache, what is learned, tool calls and
 * results that carry their hints, and values that are deep, shared or cyclic.
 *
 *   node --test test/transcripts.test.ts
 *
 * (A fake key's vendor prefix is written with an escape, `"ghp\x5f…"`: written whole, the repository would hold text
 * that secret scanners, GitHub's push protection among them, take for a live key.)
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { fromEnvironment } from "../src/index.ts";
import { b62, hidden, r } from "./helpers.ts";

const sent = (v: unknown) => JSON.stringify(r().redactValue(v).value);
const b64 = (s: string) => Buffer.from(s).toString("base64");

test("redactValue redacts the value as JSON.stringify sends it", () => {
	const gh = `ghp_${b62(36)}`;
	assert.ok(!sent({ toJSON: () => ({ content: `token ${gh}` }) }).includes(gh));
	class Holder {
		#hidden = gh;
		toJSON() {
			return { content: `key ${this.#hidden}` };
		}
	}
	assert.ok(!sent([new Holder()]).includes(gh));
	class Plain {
		content = `x ${gh}`;
	}
	assert.ok(!sent(new Plain()).includes(gh));
	assert.ok(!sent(new Map([["a", gh]]).entries()).includes(gh));
	assert.ok(!sent({ when: new Date(0), content: `k ${gh}` }).includes(gh));
	assert.throws(() => r().redactValue({ n: 1n }));
	// Plain data is returned as a copy of itself, with no round trip.
	const plain = { content: "hi", n: 1, list: [null, true] };
	assert.deepEqual(r().redactValue(plain).value, plain);
	assert.equal(r().redactValue(undefined).value, undefined);
});

test("object keys that hold a secret are renamed, in order", () => {
	const gh = `ghp_${b62(36)}`;
	const out = r().redactValue({ first: 1, [gh]: "v", last: 2 });
	assert.ok(!JSON.stringify(out.value).includes(gh));
	const keys = Object.keys(out.value);
	assert.equal(keys.length, 3);
	assert.ok(keys[0] === "first" && keys[2] === "last" && keys[1].startsWith("[REDACTED"));
	assert.ok(out.findings.some((f) => f.inKey));
	// Inside tool arguments sent as a JSON string, too.
	const call = {
		role: "assistant",
		tool_calls: [{ id: "c1", type: "function", function: { name: "f", arguments: JSON.stringify({ [gh]: "v" }) } }],
	};
	assert.ok(!sent(call).includes(gh));
	// Arguments JSON.parse refuses (a raw tab in a string) are scanned as text.
	const tab = {
		role: "assistant",
		tool_calls: [{ id: "c1", type: "function", function: { name: "sh", arguments: `{"command": "echo\thi ${gh}"}` } }],
	};
	assert.ok(!sent(tab).includes(gh));
	// So are arguments cut off mid-string (a stream that stopped).
	const cut = {
		role: "assistant",
		tool_calls: [
			{ id: "c1", type: "function", function: { name: "sh", arguments: `{"command": "psql -h db.internal ${gh}` } },
		],
	};
	assert.ok(!sent(cut).includes(gh) && sent(cut).includes("psql -h db.internal"));
	// Envelope keys stay.
	const msg = [
		{ role: "user", content: [{ type: "text", text: "hello there", cache_control: { type: "ephemeral" } }] },
	];
	assert.deepEqual(r().redactValue(msg).value, msg);
});

test("ids holding a vendor token are scanned, other ids kept", () => {
	const gh = `ghp_${b62(36)}`;
	assert.ok(!sent({ role: "assistant", id: gh, content: "hi" }).includes(gh));
	assert.ok(!sent({ role: "assistant", id: `toolu_${gh}`, content: "hi" }).includes(gh));
	const token = b62(30);
	assert.ok(!sent({ role: "user", id: `token=${token}` }).includes(token));
	const id = `toolu_01${b62(22)}`;
	assert.ok(
		sent([
			{ type: "tool_use", id, name: "x", input: {} },
			{ type: "tool_result", tool_use_id: id, content: "ok" },
		]).split(id).length === 3,
	);
});

test("base64 documents of text media are decoded and redacted", () => {
	const key = `sk_live_${b62(24)}`;
	const env = `STRIPE_KEY=${key}\nDEBUG=1\n`;
	const doc = (media_type: string, data: string, extra = {}) => ({
		role: "user",
		content: [{ type: "document", ...extra, source: { type: "base64", media_type, data } }],
	});
	const out = sent(doc("text/plain", b64(env)));
	assert.ok(!out.includes(key) && !out.includes(b64(env)));
	const back = JSON.parse(out).content[0].source.data;
	assert.ok(Buffer.from(back, "base64").toString().includes("DEBUG=1"));
	// A file name is the path hint: a bare value in a `.env` document.
	const bare = `${b62(40)}\n`;
	assert.ok(
		!sent(doc("text/plain", b64(`SESSION_SECRET=${bare}`), { title: ".env" })).includes(b64(`SESSION_SECRET=${bare}`)),
	);
	// SVG and JSON data URIs.
	const svg = `<svg><!-- AWS_SECRET_ACCESS_KEY=${b62(40)} --></svg>`;
	assert.ok(
		!sent({
			role: "user",
			content: [{ type: "image_url", image_url: { url: `data:image/svg+xml;base64,${b64(svg)}` } }],
		}).includes(b64(svg)),
	);
	// Binary media and clean text stay as they are.
	const png = {
		role: "user",
		content: [
			{ type: "image", source: { type: "base64", media_type: "image/png", data: b64("\u0089PNG\r\n\u001a\n" + env) } },
		],
	};
	assert.deepEqual(r().redactValue(png).value, png);
	const clean = doc("text/plain", b64("hello world, nothing here"));
	assert.deepEqual(r().redactValue(clean).value, clean);
	const binary = {
		role: "user",
		content: [
			{
				type: "file",
				file: { filename: ".env", file_data: `data:application/octet-stream;base64,${b64(`\u0000\u0001${env}`)}` },
			},
		],
	};
	assert.deepEqual(r().redactValue(binary).value, binary);
});

test("a redactor remembers findings of texts it has detected, until the known values change", () => {
	const red = r();
	const gh = `ghp_${b62(36)}`;
	const text = `nothing in this ${b62(30)} text but later ${gh}`;
	const first = red.detect(text);
	assert.deepEqual(red.detect(text), first);
	// A different hint or guessing is a different question.
	assert.notDeepEqual(
		red.detect("PASSWORD=Hx7#mQ2pLw9z\n", {}),
		red.detect("Hx7#mQ2pLw9z\n", { hint: { path: ".env" } }),
	);
	// A value learned later is found in a text that was clean before.
	const secret = "maple-orbit-427x";
	const plain = `see ${secret} here`;
	assert.equal(red.detect(plain).length, 0);
	red.addKnown(secret);
	assert.equal(red.detect(plain).length, 1);
	// learn-then-redact in one call, then the same history again.
	const history = [
		{ role: "user", content: `API_KEY=${gh}` },
		{ role: "assistant", content: `using ${gh} now` },
	];
	const once = JSON.stringify(red.redactValue(history).value);
	assert.ok(!once.includes(gh));
	assert.equal(JSON.stringify(red.redactValue(history).value), once);
});

test("learning refuses values no secret has the shape of", () => {
	const sha = "9fceb02d0ae598e95dc970b74767f19372d61af8";
	for (const text of [
		`AWS_SECRET_ACCESS_KEY=arn:aws:iam::483920176654:role/x`,
		`API_TOKEN=arn:aws:iam::483920176654:role/x`,
		"password=db-main.cluster-cx8k2.us-west-2.rds.amazonaws.com",
		"API_TOKEN=/etc/ssl/private/server-name.pem",
		"API_TOKEN=https://registry.example.org/v2/team",
	]) {
		const red = r();
		red.learn(text);
		const value = text.split("=")[1];
		assert.ok(red.redact(`later: ${value} again`).text.includes(value), text);
	}
	// Hex is still learned (real hex keys exist), and so is a webhook URL.
	const red = r();
	red.learn(`AWS_SECRET_ACCESS_KEY=${sha}`);
	assert.ok(!red.redact(`later ${sha} again`).text.includes(sha));
	const hook = `https://hooks.slack.com/services/T0${b62(8)}/B0${b62(8)}/${b62(24)}`;
	const hooks = r();
	hooks.learn(`SLACK_WEBHOOK_URL=${hook}`);
	assert.ok(!hooks.redact(`curl ${hook}`).text.includes(hook));
	// Transcripts learn the same way.
	const t = r();
	t.redactValue([{ role: "user", content: "API_TOKEN=arn:aws:iam::483920176654:role/x" }]);
	assert.ok(t.redact("role arn:aws:iam::483920176654:role/x").text.includes("arn:aws:iam::483920176654:role/x"));
});

test("fromEnvironment returns only what a Redactor accepts as known", () => {
	const env = fromEnvironment({ JWT_SECRET: "devsecret", API_TOKEN: `Xk9mQ2pLrTvB7nWz${b62(6)}` });
	assert.ok(env.length > 0);
	const red = r();
	for (const { value } of env) assert.ok(red.addKnown(value), value);
	assert.ok(!env.some((e) => e.value === "devsecret"));
});

test("a value found in a tool result is hidden in every later message", () => {
	const red = r();
	const msgs = [
		{ role: "assistant", content: [{ type: "tool_use", id: "t1", name: "bash", input: { command: "cat .env" } }] },
		{ role: "user", content: [{ type: "tool_result", tool_use_id: "t1", content: "LUMEN_KEY=Qz8vL2mX7pN4tR9w\n" }] },
		{ role: "assistant", content: "I'll call it with Qz8vL2mX7pN4tR9w now." },
	];
	const out = JSON.stringify(red.redactValue(msgs).value);
	assert.ok(!out.includes("Qz8vL2mX7pN4tR9w"));
	assert.ok(out.includes('"tool_use_id":"t1"'));
});

test("envelope ids are kept, a tool input's keys are not, and image data is left alone", () => {
	const red = r();
	const more = JSON.stringify(
		red.redactValue([
			{
				type: "tool_use",
				id: "t2",
				name: "vault_put",
				input: { id: "Wm4kT8vQ2nZ6xR1p", format: { password: "Zk3Pw9Lm2Qx8Vb4N" } },
			},
			{
				role: "user",
				content: [{ type: "tool_result", tool_use_id: "t2", content: 'data: {"password": "Xq7Lm2Vb9Rt4Np8K"}' }],
			},
			{
				role: "user",
				content: [
					{ type: "image", source: { type: "base64", media_type: "image/png", data: "iVBORw0KGgoAAAANSUhEUg==" } },
				],
			},
		]).value,
	);
	for (const s of ["Zk3Pw9Lm2Qx8Vb4N", "Xq7Lm2Vb9Rt4Np8K"]) assert.ok(!more.includes(s), s);
	assert.ok(more.includes('"id":"t2"') && more.includes("iVBORw0KGgoAAAANSUhEUg=="));
});

test("a patch that adds a secret file is read as that file, in Anthropic and OpenAI shapes", () => {
	const patch = "*** Begin Patch\n*** Add File: config/.env\n+NODE_ENV=production\n+MY_TOKEN=simple99\n*** End Patch";
	const v = r().redactValue([
		{ type: "tool_use", id: "t1", name: "apply_patch", input: { input: patch } },
		{ type: "function_call", call_id: "c1", name: "apply_patch", arguments: JSON.stringify({ input: patch }) },
		{ type: "function_call", call_id: "c2", name: "shell", arguments: '{"cmd": ["ls", "-la"]}' },
	]).value as any[];
	assert.ok(!JSON.stringify(v).includes("simple99"));
	assert.equal(v[2].arguments, '{"cmd": ["ls", "-la"]}');
});

test("an OpenAI chat tool call's command reaches its result", () => {
	const chat = r().redactValue([
		{
			role: "assistant",
			content: null,
			tool_calls: [{ id: "call_1", type: "function", function: { name: "shell", arguments: '{"cmd": "cat .env"}' } }],
		},
		{ role: "tool", tool_call_id: "call_1", content: "NODE_ENV=production\nhunter2hunter2\n" },
	]).value;
	assert.ok(!JSON.stringify(chat).includes("hunter2hunter2"));
});

test("a Bearer token in one message is hidden when a later message repeats it bare", () => {
	const H = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b";
	const v = JSON.stringify(
		r().redactValue([
			{ role: "user", content: `{"Authorization": "Bearer ${H}"}` },
			{ role: "assistant", content: `I'll reuse ${H} next.` },
		]).value,
	);
	assert.ok(!v.includes(H) && v.includes("Bearer [REDACTED"));
});

test("an edit of a secret file hides both the old and the new string", () => {
	const pw = "Winter2024pass";
	const v = JSON.stringify(
		r().redactValue([
			{
				type: "tool_use",
				id: "u",
				name: "MultiEdit",
				input: {
					file_path: "/app/.env",
					edits: [{ old_string: `SESSION_SECRET=${pw}`, new_string: "SESSION_SECRET=green-cat-lake" }],
				},
			},
		]).value,
	);
	assert.ok(!v.includes(pw) && !v.includes("green-cat-lake"));
});

test("thinking blocks are kept on request", () => {
	const pw = "Winter2024pass";
	const thinking = [{ type: "thinking", thinking: `the password is ${pw}`, signature: "sig" }];
	assert.equal(JSON.stringify(r().redactValue(thinking, { thinking: "keep" }).value), JSON.stringify(thinking));
});

test("a credential named inside a longer leaf keeps its own name", () => {
	const leaf = r().redactValue({
		role: "tool",
		content: 'docsearch({\n  appId: "BH4D9OD16A",\n  password: "Hx7mQ2pLw9RtV3nK8cJ6hF1bY5gZ0dS2",\n});',
	}).value;
	assert.ok(!JSON.stringify(leaf).includes("Hx7mQ2pLw9RtV3nK8"));
});

test("a learned value is the text that was read, joints and all", () => {
	// A value is what was read (not a regex's guess at joints), and an escaped backslash before it isn't trimmed off.
	const learner = r();
	learner.learn("DB_PASSWORD=Xk9'.'Lm2#qZw", { hint: { path: ".env" } });
	assert.ok(!learner.redact("psql: connecting with Xk9'.'Lm2#qZw").text.includes("Lm2#qZw"));
});

test("thinking is kept at any depth when asked", () => {
	const thinking = {
		type: "thinking",
		thinking: "the key is ghp\x5fZr8vK2mQ9xW4tB7nL1pH6jF3dS5aG0cE8uYi",
		signature: "sig",
	};
	let deep: unknown = thinking;
	for (let i = 0; i < 300; i++) deep = [deep];
	assert.ok(JSON.stringify(r().redactValue(deep, { thinking: "keep" }).value).includes("ghp_Zr8v"));
});

test("an envelope's id stays and is not learned", () => {
	const envelope = { type: "bridge-session", bridgeSessionId: "cse_011cvfXT6fNcQ51hCv1ZVraX" };
	assert.deepEqual(r().redactValue(envelope).value, envelope);
});

test("redactValue reads a leaf where it sits: a name/value pair and an argv", () => {
	for (const obj of [
		{ env: [{ name: "DB_PASSWORD", value: "Harbor2291!" }] },
		{
			type: "local_shell_call",
			action: { command: ["docker", "login", "-u", "ci", "-p", "Harbor2291!", "registry.example.com"] },
		},
		{ action: { command: ["curl", "-u", "admin:Harbor2291!", "https://api.example.com"] } },
	]) {
		assert.ok(!JSON.stringify(r().redactValue(obj).value).includes("Harbor2291!"), JSON.stringify(obj));
		hidden(JSON.stringify(obj, null, 2), "Harbor2291!");
	}
	// A value JSON writes escaped, a quote, a backslash or a tab in it, is read where it sits too.
	for (const pw of ['Tr0ub4dor"x9Qm2Lp', "Tr0ub4dor\\x9Qm2Lp", "Tr0ub4dor\tx9Qm2Lp", '\u{1F600}Tr0ub"4dor9Qm2Lp']) {
		for (const obj of [
			{ env: [{ name: "DB_PASSWORD", value: pw }] },
			{ env: [{ key: "MYSQL_PWD", value: pw }] },
			{ action: { command: ["docker", "login", "-u", "ci", "-p", pw, "registry.example.com"] } },
		]) {
			const out = r().redactValue(obj).value;
			assert.ok(!JSON.stringify(out).includes(JSON.stringify(pw).slice(1, -1)), JSON.stringify(out));
		}
	}
	// Its neighbours stay.
	const kept = { env: [{ name: "DB_HOST", value: 'db"main.internal' }] };
	assert.deepEqual(r().redactValue(kept).value, kept);
});

test("envelope fields are skipped by place, not by name", () => {
	const errorBody = {
		role: "user",
		content: [
			{
				type: "tool_result",
				tool_use_id: "t1",
				content: "ok",
				structuredContent: { detail: "Invalid key: ghp\x5fZr8vK2mQ9xW4tB7nL1pH6jF3dS5aG0cE8uYi" },
			},
		],
	};
	assert.ok(!JSON.stringify(r().redactValue(errorBody).value).includes("ghp\x5fZr8vK2mQ9xW4tB7nL1pH6jF3dS5aG0cE8uYi"));
});

test("learn: false still hides a value across the same transcript", () => {
	const session = [
		{ role: "assistant", content: [{ type: "tool_use", id: "t2", name: "Bash", input: { command: "cat .env" } }] },
		{
			role: "user",
			content: [
				{ type: "tool_result", tool_use_id: "t2", content: "UPSTREAM=Copper7781#x\nAPI_KEY=Hf7vT2kLp9RxN4wZ8bYc" },
			],
		},
		{ role: "assistant", content: [{ type: "text", text: "I will call the upstream with Copper7781#x." }] },
	];
	assert.ok(!JSON.stringify(r().redactValue(session, { learn: false }).value).includes("Copper7781#x"));
});

test("a Codex result's output carries its call's hint", () => {
	const codex = [
		{
			type: "function_call",
			call_id: "c1",
			name: "shell",
			arguments: JSON.stringify({ command: ["bash", "-lc", "cat .env"] }),
		},
		{
			type: "function_call_output",
			call_id: "c1",
			output: JSON.stringify({ output: "RELAY_HOST=relay\nUPSTREAM=Copper7781#x\n", metadata: { exit_code: 0 } }),
		},
	];
	assert.ok(!JSON.stringify(r().redactValue(codex, { learn: false }).value).includes("Copper7781#x"));
});

test("a Claude Code record's toolUseResult carries its call's hint", () => {
	const record = [
		{
			type: "assistant",
			message: {
				role: "assistant",
				content: [{ type: "tool_use", id: "t3", name: "Bash", input: { command: "cat .env" } }],
			},
		},
		{
			type: "user",
			message: {
				role: "user",
				content: [{ type: "tool_result", tool_use_id: "t3", content: "UPSTREAM=Copper7781#x" }],
			},
			toolUseResult: { stdout: "UPSTREAM=Copper7781#x", stderr: "" },
		},
	];
	assert.ok(!JSON.stringify(r().redactValue(record, { learn: false }).value).includes("Copper7781#x"));
});

test("a Gemini functionResponse carries its call's hint, by the call's id", () => {
	const env = "APP_PORT=3000\nJWT_KEY=hello-world-service-key\nENC_KEY=kitchen-sink-moon-47\n";
	const gemini = (call: object, response: object) => ({
		contents: [
			{ role: "model", parts: [{ functionCall: call }] },
			{ role: "user", parts: [{ functionResponse: response }] },
		],
	});
	const id = `run_shell_command-1726000000000-${b62(12)}`;
	const shapes = [
		// Gemini, paired by id (Gemini CLI's ids; pydantic-ai's are `pyd_ai_…`); `read_file`'s `absolute_path`.
		gemini(
			{ id, name: "run_shell_command", args: { command: "cat .env" } },
			{ id, name: "run_shell_command", response: { output: env } },
		),
		gemini(
			{ id: "pyd_ai_7f3a9c", name: "read_file", args: { absolute_path: "/app/.env" } },
			{ id: "pyd_ai_7f3a9c", name: "read_file", response: { output: env } },
		),
	];
	for (const v of shapes) {
		const out = JSON.stringify(r().redactValue(v).value);
		for (const s of ["hello-world-service-key", "kitchen-sink-moon-47"]) assert.ok(!out.includes(s), out);
		// The envelope stays: ids and names.
		for (const s of ['"read_file"', id, "pyd_ai_7f3a9c"])
			if (JSON.stringify(v).includes(s)) assert.ok(out.includes(s), `${s} in ${out}`);
	}
	// Each response by its own call's id, whatever the order: the result of `ls` is not the `.env`.
	const crossed = {
		contents: [
			{
				role: "model",
				parts: [
					{ functionCall: { id: "c2", name: "run_shell_command", args: { command: "cat .env" } } },
					{ functionCall: { id: "c1", name: "run_shell_command", args: { command: "ls" } } },
				],
			},
			{
				role: "user",
				parts: [
					{ functionResponse: { id: "c1", name: "run_shell_command", response: { output: "plain-words-here-42\n" } } },
					{ functionResponse: { id: "c2", name: "run_shell_command", response: { output: env } } },
				],
			},
		],
	};
	const out = r().redactValue(crossed, { learn: false }).value as any;
	assert.equal(out.contents[1].parts[0].functionResponse.response.output, "plain-words-here-42\n");
	assert.ok(!JSON.stringify(out.contents[1].parts[1]).includes("hello-world-service-key"));
});

test("a block keeps its type and ids under a secret file's hint, whatever the type", () => {
	const call = (input: object) => ({ type: "tool_use", id: "t1", name: "x", input });
	const result = (content: unknown) => ({ type: "tool_result", tool_use_id: "t1", content });
	const env = "PORT=3000\nJWT_KEY=hello-world-service-key\n";
	for (const blocks of [
		// MCP's resource blocks, from a filesystem server reading `.env`.
		[
			call({ path: "/app/.env" }),
			result([{ type: "resource", resource: { uri: "file:///app/.env", mimeType: "text/plain", text: env } }]),
		],
		// A server tool's result, its content an object of its own type.
		[
			{ type: "server_tool_use", id: "t1", name: "bash_code_execution", input: { command: "cat .env" } },
			{
				type: "bash_code_execution_tool_result",
				tool_use_id: "t1",
				content: { type: "bash_code_execution_result", stdout: env, stderr: "", return_code: 0 },
			},
		],
	]) {
		const out = JSON.stringify(r().redactValue({ messages: [{ role: "assistant", content: blocks }] }).value);
		assert.ok(!out.includes("hello-world-service-key"), out);
		for (const s of ['"resource"', '"text/plain"', '"bash_code_execution_result"', '"bash_code_execution"'])
			if (JSON.stringify(blocks).includes(s)) assert.ok(out.includes(s), `${s} in ${out}`);
	}
	// A Responses request's `input` is its items, not a tool's input: the output's type and the call's id stay paired.
	const callId = `call_${b62(24)}`;
	const responses = {
		model: "gpt-5",
		input: [
			{ type: "function_call", call_id: callId, name: "shell", arguments: '{"command":["bash","-lc","cat .env"]}' },
			{ type: "function_call_output", call_id: callId, output: "PORT=3000\nNODE_ENV=development\n" },
		],
	};
	const red = r();
	assert.deepEqual(red.redactValue(responses).value, responses);
	assert.equal(red.redact("type function_call_output").text, "type function_call_output");
	// A document of a secret file's name sent by its file id, or as content blocks.
	for (const source of [
		{ type: "file", file_id: `file_011C${b62(20)}` },
		{ type: "content", content: [{ type: "text", text: "PORT=3000" }] },
	]) {
		const doc = { role: "user", content: [{ type: "document", title: ".env", source }] };
		assert.deepEqual(r().redactValue(doc).value, doc);
	}
});

test("a serialized tool call and the parsed one hide the same values under every tool-input key", () => {
	for (const key of ["new_string", "new_text", "old_text", "contents", "edits", "content"]) {
		const call = {
			type: "tool_use",
			name: "Edit",
			input: { file_path: "config.yml", [key]: "  db_password: correct horse battery staple" },
		};
		assert.ok(!r().redact(JSON.stringify(call)).text.includes("battery"), key);
	}
});

test("a secret 300 levels deep is hidden", () => {
	const R = r();
	const gh = "ghp\x5faB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zA4";
	let v: unknown = `token ${gh}`;
	for (let i = 0; i < 300; i++) v = { c: v };
	assert.ok(!JSON.stringify(R.redactValue(v).value).includes(gh));
});

test("a secret 4000 levels deep is hidden", () => {
	let deep: unknown = { content: "API_KEY=ghp\x5f16C7e42F292c6912E7710c838347Ae178B4b" };
	for (let i = 0; i < 4000; i++) deep = { a: deep };
	assert.ok(!JSON.stringify(r().redactValue(deep).value).includes("ghp_16C7"));
});

test("a value 20000 levels deep and a cyclic conversation are redacted", () => {
	let deep: unknown = { content: "API_KEY=ghp\x5f16C7e42F292c6912E7710c838347Ae178B4b" };
	for (let i = 0; i < 20000; i++) deep = { a: deep, s: `note ${i}` };
	assert.equal(r().redactValue(deep).findings.length, 1);
	const msg: Record<string, unknown> = { role: "user", content: "API_KEY=ghp\x5f16C7e42F292c6912E7710c838347Ae178B4b" };
	const conv = { messages: [msg] };
	msg.parent = conv;
	assert.ok(!String((r().redactValue(conv).value as typeof conv).messages[0].content).includes("ghp_16C7"));
});

test("shared references are redacted at every depth", () => {
	let shared: unknown = { text: "ghp\x5fZr8vK2mQ9xW4tB7nL1pH6jF3dS5aG0cE8uYi" };
	for (let i = 0; i < 40; i++) shared = { a: shared, b: shared };
	let leaf = r().redactValue(shared).value as { a?: unknown; text?: string };
	for (let i = 0; i < 40; i++) leaf = leaf.a as typeof leaf;
	assert.ok(!leaf.text!.includes("ghp_Zr8v"));
});

test("a cyclic value is redacted without looping", () => {
	const cyclic: Record<string, unknown> = { content: "hello there" };
	cyclic.a = cyclic;
	cyclic.b = cyclic;
	r().redactValue(cyclic);
});

test("fromEnvironment reads the caller's environment widely", () => {
	const env = fromEnvironment({
		MATCH_PASSWORD: "Harbor2291!",
		BW_SESSION: "Xk9mQ2pLrTvB7nWz",
		TF_TOKEN_app_terraform_io: "Xk9mQ2pLrTvB7nWzQ4",
		CI_DEPLOY: "ghp\x5fZr8vK2mQ9xW4tB7nL1pH6jF3dS5aG0cE8uYi",
		NODE_ENV: "production",
		AWS_KEY_ID: "AKI\x41IOSFODNN7EXAMPLE",
	});
	assert.deepEqual(
		env.map((e) => e.value).sort(),
		["Harbor2291!", "Xk9mQ2pLrTvB7nWz", "Xk9mQ2pLrTvB7nWzQ4", "ghp\x5fZr8vK2mQ9xW4tB7nL1pH6jF3dS5aG0cE8uYi"].sort(),
	);
});

test("fromEnvironment takes a generated value with symbols under a session's or a credential's name", () => {
	const env = fromEnvironment({ APP_PEPPER: "Pq7!zR2@xW9#kL4m", MY_SESSION: "Xk9#mQ2$vL8nRt4W" });
	assert.deepEqual(env.map((e) => e.value).sort(), ["Pq7!zR2@xW9#kL4m", "Xk9#mQ2$vL8nRt4W"]);
});

test("the environment's settings stay settings, whatever credential word their name holds", () => {
	assert.deepEqual(
		fromEnvironment({
			TOKEN_ENDPOINT: "https://auth.example.com/oauth/token",
			SECRET_MANAGER_PROJECT: "acme-prod-123",
			COOKIE_DOMAIN: ".example.com",
			DESKTOP_SESSION: "ubuntu-wayland",
			PASSWORD_POLICY: "strong-v2",
			GPG_KEY: "7169605F62C751356D054A26A821E680E5FA6305",
			KEY_FILE_PATTERN: "*.pem,*.key,*.p12",
		}),
		[],
	);
});

test("an environment URL with a reference holds no password", () => {
	assert.deepEqual(
		fromEnvironment({
			DATABASE_URL: "postgres://app:${DB_PASSWORD}@db/app",
			REDIS_URL: "redis://:<password>@cache:6379",
		}),
		[],
	);
});

test("fromEnvironment takes the password a connection string or a URL's query gives, under any name", () => {
	for (const value of [
		"postgres://h:5432/db?user=app&password=Hx7mQ2pL9vRt",
		"jdbc:postgresql://h/db?user=app&password=Hx7mQ2pL9vRt",
		"Server=h;User Id=sa;Password=Hx7mQ2pL9vRt;",
		"host=h user=app password=Hx7mQ2pL9vRt",
		"postgres://app:Hx7mQ2pL9vRt@h/db",
	])
		assert.deepEqual(
			fromEnvironment({ DATABASE_URL: value }).map((e) => e.value),
			["Hx7mQ2pL9vRt"],
			value,
		);
	assert.deepEqual(
		fromEnvironment({
			DATABASE_URL: "postgres://h:5432/db?user=app&password=${DB_PASSWORD}",
			DB_DSN: "host=h user=app password=%DB_PASSWORD%",
			REDIS_URL: "redis://h:6379/0",
			APP_NAME: "shop",
		}),
		[],
	);
});

test("fromEnvironment keeps what is public by design: a publishable key, a key under a browser's prefix", () => {
	assert.deepEqual(
		fromEnvironment({
			NEXT_PUBLIC_STRIPE_KEY: "pk_live_51Hx9mQ2pLrTvB7nWz4aBcDeHq",
			NEXT_PUBLIC_FIREBASE_API_KEY: "AIzaSyA-Xk9mQ2pLrTvB7nWz4aBcDeHq7zR2x",
			VITE_API_KEY: "Hx7mQ2pLrTvB7nWz",
			STRIPE_PUBLISHABLE_KEY: "pk_live_51Hx9mQ2pLrTvB7nWz4aBcDeHq",
		}),
		[],
	);
	// (A vendor's secret key says what it is under any name; a server's Google key and a password are hidden.)
	assert.deepEqual(
		fromEnvironment({
			VITE_OPENAI_API_KEY: `sk-proj-${"Xk9mQ2pLrTvB7nWz4aBcDeHq7zR2x".repeat(3)}`,
			GOOGLE_MAPS_API_KEY: "AIzaSyA-Xk9mQ2pLrTvB7nWz4aBcDeHq7zR2x",
			NEXT_PUBLIC_DB_PASSWORD: "Hx7mQ2pLrTvB7nWz",
		}).map((e) => e.label),
		["OpenAI API key in $VITE_OPENAI_API_KEY", "$GOOGLE_MAPS_API_KEY", "$NEXT_PUBLIC_DB_PASSWORD"],
	);
});
