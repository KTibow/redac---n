/**
 * Keys of known vendors are hidden by their own format: bare, named, glued to punctuation or in a URL.
 *
 *   node --test test/vendor-keys.test.ts
 *
 * (A fake key's vendor prefix is written with an escape, `"ghp\x5f…"`: written whole, the repository would hold text
 * that secret scanners, GitHub's push protection among them, take for a live key.)
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { Redactor } from "../src/index.ts";
import { b62, hidden, kept } from "./helpers.ts";

test("a vendor key is hidden by its own format, bare, named or inside a URL", () => {
	const gh = `ghp_${b62(36)}`;
	hidden(`token: ${gh}`, gh);
	hidden(`git push https://x-access-token:${gh}@github.com/a/b`, gh);
	const ant = `sk-ant-api03-${b62(93)}AA`;
	hidden(`ANTHROPIC_API_KEY=${ant}`, ant);
	const aws = `AKIA${b62(16)
		.toUpperCase()
		.replace(/[^A-Z0-9]/g, "Q")}`;
	hidden(aws, aws);
});

test("Slack and Langfuse keys are hidden by their formats", () => {
	hidden(
		`slack: xox\x70-2706183456-2706234567-4813572690183-a1b2c3d4e5f60718293a4b5c6d7e8f90`,
		"a1b2c3d4e5f60718293a4b5c6d7e8f90",
	);
	hidden("LANGFUSE_SECRET_KEY=\x73k-lf-7c1e0f3a-2b4d-4e6f-9a8b-1c2d3e4f5a6b", "7c1e0f3a-2b4d");
});

test("an OpenAI session token is hidden", () => {
	hidden("sess-aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5bC7d", "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9");
});

test("an imported format's token ends at any punctuation, not only a quote", () => {
	// The gitleaks terminator only allowed a quote, a blank, `;` or the end after a key.
	const fio = `fio-u-${b62(64)}`;
	for (const t of [
		`f(${fio})`,
		`[${fio}]`,
		`${fio},x`,
		`?t=${fio}&y=1`,
		`${fio}|base64`,
		`<${fio}>`,
		`The key is ${fio}.`,
	])
		hidden(t, fio.slice(6, 40));
	const azure = `aB3${4}Q~${b62(32)}`;
	for (const t of [`[${azure}]`, `<${azure}>`, `\${${azure}}`, `is it ${azure}?`]) hidden(t, azure.slice(6));
});

test("regional providers' keys are hidden by format", () => {
	hidden(
		"MP_ACCESS_TOKEN=\x41PP_USR-8718029008646724-558422-d9d6902c4b4e8ea6c975c9e6332dda1a-403403192",
		"d9d6902c4b4e8ea6c975c9e6332dda1a",
	);
	hidden(
		"export LANGCHAIN_KEY=\x6csv2_pt_2cddc068fd56e2dcd359eace78d983a2_4b1c9e0f3a",
		"2cddc068fd56e2dcd359eace78d983a2",
	);
	hidden("server = \x53B-\x4did-server-Axa8R32_v1NgbjKeNOFdubu4", "Axa8R32_v1NgbjKeNOFdubu4");
});

test("a long hyphenated Anthropic key under a plain name is hidden", () => {
	hidden(
		'ANTHROPIC_KEY="\x61ws-external-anthropic-api-key-6MrOFaF656Iga0OgzXhem75N-b3-Ga0Hzn7TEIxikWfUlscIQuXChw"',
		"6MrOFaF656Iga0OgzXhem75N",
	);
});

test("GitLab's example tokens are hidden under a plain name", () => {
	for (const k of [
		"\x48RKU-4f65f6ec-a4bb-48e5-b3f7-c4298ebd2fd6",
		"\x31/13463204581647:56953768dc7859ec12fd169490ecc7cb",
		"\x43CIPRJ_TY7q8z5XL6a8opU7rWXtnC_a9a4c4614efeb6c67f62f91a9f351d292160d2fe",
		"\x3309fe248df0ecc5cee6767160cede8c7-us8",
		"\x70rtapi_71eb2292be6a4fe41dede15dec4770f1",
		"\x73qu_8315454426eef9beae2c0af90e5cfab2d2977bf2",
		"\x4eRRA-4f4ecfc711efc4f2f8cba576b00cc817b191ff279e",
	])
		hidden(`key: ${k}`, k.slice(-16));
});

test("a base32 seed and a Gemini key beside a Firebase config are hidden", () => {
	hidden(
		"    UH5LZX46AEY4LP3MM5SNDUIYIKYZGI3N4YNPYO5OZRNFQQQVLUHJWYFT",
		"UH5LZX46AEY4LP3MM5SNDUIYIKYZGI3N4YNPYO5OZRNFQQQVLUHJWYFT",
	);
	hidden(
		'const firebaseConfig = {\n  apiKey: "AIz\x61X7c4lsgg386vsnKo5j5zoobiOPt2wwdjOhe",\n  authDomain: "myapp.firebaseapp.com",\n};\nconst GEMINI_API_KEY = "AIz\x61SyD2kP9xW4vR7tN1mQ8zL3cH6jF0bY5gU2e";',
		"AIz\x61SyD2kP9xW4vR7tN1mQ8zL3cH6jF0bY5gU2e",
	);
});

test("Yandex IAM and Akamai EdgeGrid tokens are hidden", () => {
	hidden(
		"$ yc iam create-token\nt1.9euelZvE8-vLIdtXuekszEH9_7mytASJh5wwuEZLuk1k9U5pPYzp6gooMAIngd8ncEzaZqobCwbBvtSmjTooxZlhurRCSX3BrnOhlOMv6yf_-8Ti",
		"9euelZvE8-vLIdtXuekszEH9",
	);
	hidden('  "client_token": "\x61kab-wnthgqttzeloisjzhcixzbmzcu0557370",', "\x61kab-wnthgqttzeloisjzhcixzbmzcu0557370"); // Akamai EdgeGrid
});

test("a Gemini key is hidden in a constructor and under its name", () => {
	hidden(
		'admin.initializeApp();\nconst genAI = new GoogleGenerativeAI("AIz\x61SyD2kP9xW4vR7tN1mQ8zL3cH6jF0bY5gU2e");',
		"AIz\x61SyD2kP9xW4vR7tN1mQ8zL3cH6jF0bY5gU2e",
	);
	hidden('GEMINI_WEB_KEY = "AIz\x61SyD2kP9xW4vR7tN1mQ8zL3cH6jF0bY5gU2e"', "AIz\x61SyD2kP9xW4vR7tN1mQ8zL3cH6jF0bY5gU2e");
});

test("a Nostr nsec is hidden", () => {
	hidden(
		"Import your account with nsec: nsec1a9nmenm6pyms37cwjrl6xgwyjkzxcw9p82w8gl8erzm9leuckd0jplvfhn",
		"nsec1a9nmenm6pyms37cwjrl6xgwyjkzxcw9p82w8gl8erzm9leuckd0jplvfhn",
	);
});

test("Resend and Airtable keys are hidden without a name", () => {
	hidden(
		"[notifier] email    -> resend rejected \x72e_eUHltDEE_BZY6WxgFtvq8IOSBcBG5pbu0",
		"\x72e_eUHltDEE_BZY6WxgFtvq8IOSBcBG5pbu0",
	);
	hidden(
		"base appNQ4812 read with pat9hFN0dPSG1vNp5\x2e33bb336051f085611955857d086347a5f59ed4bb56d139d10332ff0dd6700a46",
		"pat9hFN0dPSG1vNp5",
	);
});

test("a Meta Model API key is hidden bare, with pipes or underscores, and its docs' elided example is kept", () => {
	// Bare, the app ID's digits make the whole read as an ID to the random layer.
	const under = "LLM\x5f2914177763170669__a-4nj0GXstW7v5nuAxAfjwtMyv";
	hidden(under, under);
	const pipes = "LLM\x7c607358788850350|nx9Kd8sLq2PzW7vB4mYtR5LJY";
	hidden(pipes, pipes);
	hidden(`https://api.example.com/?access_token=${encodeURIComponent(pipes)}`, "nx9Kd8sLq2PzW7vB4mYtR5LJY");
	kept("LLM\x7c607358788850350|nx9.....LJY", "607358788850350|nx9");
	kept("LLM_202401011200001_add_column_to_users_table", "add_column");
});

test("Baseten, Moonshot and Zhipu keys are hidden whole in prose", () => {
	for (const key of [
		"b10\x5fbEICjvuD.fSmj7gsdzguoneJQGGgx0S3tgwNUVENr",
		"\x73k-by1cJvdvsMjDgstzAU4nyJqG0axgSmT0Wn7VXbr3nuPatxjb",
		"\x73k-kyIOJdUVSMj706D9gFUo3y1qg0axa6fMTG8nuV83RNNUpgD8",
		"b9a417dd63ad0669a74391c0aaf806fb\x2e6GEN7vEncNnuCGT8",
		"291417d763a7066ea74391500a8adfb6\x2eGwn7v83RbNU4GDXj",
	])
		hidden(`here is my key ${key} try it`, key);
	kept("b10\x5fabcd1234.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef", "abcd1234");
});

test("an Elasticsearch encoded API key is hidden", () => {
	hidden(
		'{"id":"VuaCfGcBCdbkQm-e5aOx","name":"filebeat-edge","api_key":"9895ofo_JwQ36cFgBMoWCM","encoded":"VnVhQ2ZHY0JDZGJrUW0tZTVhT3g6OTg5NW9mb19Kd1EzNmNGZ0JNb1dDTQ=="}',
		"VnVhQ2ZHY0JDZGJr",
	);
});

test("a Telegram bot token, a bootstrap token and a bare Deepgram key are hidden", () => {
	for (const [t, v] of [
		["4839574813\x3aAAFD39kkdpWt3ywyRZergyOLMaJhac61qcQ", "AAFD39kkdpWt3ywyRZergyOLMaJhac61qcQ"],
		['BOOTSTRAP_TOKEN: "\x62e8dfd.da8a689a46edc282"', "da8a689a46edc282"],
		["deepgram = 12e217f37eb173f0c8f1b7309f4207c7dca20186", "12e217f37eb173f0c8f1b7309f4207c7dca20186"],
	])
		hidden(t, v);
});

test("a Slack webhook shown with its secret cut off is kept", () => {
	kept("SLACK_WEBHOOK=https://hooks.slack.com/services/TP5A3FB2W/BG8EFGY9UV3/... (truncated)", "BG8EFGY9UV3/...");
	hidden(
		"SLACK_WEBHOOK=https://hooks.slack\x2ecom/services/TP5A3FB2W/BG8EFGY9UV3/Xk9mQv2Lp7Rt4Wz8Bn3Cd6Fh",
		"Xk9mQv2Lp7Rt4Wz8Bn3Cd6Fh",
	);
});

test("a key found by its vendor's word is hidden after an assignment, and a hash or an ID under that word is kept", () => {
	const off = new Redactor({ guessing: "off" });
	const key = `G${b62(31)}`;
	for (const t of [`algolia: ${key}`, `ALGOLIA = "${key}"`]) assert.ok(!off.redact(t).text.includes(key), t);
	kept("datadog_api_key_hash: 9f86d081884c7d659a2feaa0c55ad015", "9f86d081884c7d659a2feaa0c55ad015");
	kept("heroku_dyno: 2b0c6a4e-8f1d-4c3b-9a7e-5d2f1e0c9b8a", "2b0c6a4e-8f1d-4c3b-9a7e-5d2f1e0c9b8a");
});

test("keys from 2025's AI and developer tools are hidden by their format alone", () => {
	const hex = (n: number) => Array.from({ length: n }, (_, i) => "0123456789abcdef"[(i * 7 + 3) % 16]).join("");
	const uuid = "895a83c6-d274-4e15-a9d7-1f25f2f37f8e";
	for (const key of [
		`fc-${hex(32)}`,
		`ctx7sk-${uuid}`,
		`xaat-${uuid}`,
		`signkey-prod-${hex(64)}`,
		`ABSKQmVkcm9ja0FQSUtleS1lYmpkLWF0LTEyMzQ1Njc4OTAxMjpQOWVDMUlEYk5odmNhT0NwUDE0TW5iUUphWDll`,
		// Cloudflare Tunnel's token, as `cloudflared service install` takes it.
		"eyJhIjoiMDA1MTE0ZWRhZTc2YWEyNjcyNTM1NzVjODhlMWJjMTAiLCJ0IjoiNTY4NTdhZWUtMzUyYi0wMzFmLTQ4NTItNTQxYzQzMzM3Yzk2IiwicyI6IlZVRTBNalJ1WTJRMFFUQnBORU0xYWxoTWJXMXdRM2M1U0ZwdVR6bHdPWFU9In0=",
	])
		hidden(`$ tool login ${key}\nok`, key);
});

test("a bech32 key whose prefix says private is no address, however its checksum reads", () => {
	const key = "suiprivkey1qq7dnjukgjs2n9ss7e59rkwpsafc3qwpr0vhanl3zxrda2fpt58jvst4585";
	hidden(`SUI_PRIVATE_KEY=${key}`, key);
});
