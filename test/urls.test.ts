/**
 * The URL reader across the userinfo shapes clients accept and the places an `@` turns up after the authority: every
 * user and password comes back whole, and an `@` in a path, query or fragment is never read as the end of a userinfo.
 * And the random tokens a path or query holds.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { queryParams, urlAround, urls } from "../src/urls.ts";
import { hidden, kept, r } from "./helpers.ts";

const USERINFO: [string, string | undefined, string | undefined][] = [
	["", undefined, undefined],
	["deploy@", "deploy", undefined],
	["app:Xk9mQ2pLrT@", "app", "Xk9mQ2pLrT"],
	["app:Hq3n@T8wZ5rK2@", "app", "Hq3n@T8wZ5rK2"],
	["app:Xk9/mQ2pLrT@", "app", "Xk9/mQ2pLrT"],
	["app:Hq3n:T8wZ5rK2@", "app", "Hq3n:T8wZ5rK2"],
	["app:Sparrow2024?@", "app", "Sparrow2024?"],
	["app:Vq8#Lm2!Rz7@", "app", "Vq8#Lm2!Rz7"],
	["postgres.xkqzvbnmlpoiuytr:Xk9/mQ2@", "postgres.xkqzvbnmlpoiuytr", "Xk9/mQ2"],
	["app:Maple/Orbit42@", "app", "Maple/Orbit42"],
	["writer@proj.iam.gserviceaccount.com:pw9x@", "writer@proj.iam.gserviceaccount.com", "pw9x"],
];
const AFTER = [
	"",
	"/react@18.3.1/umd/react.js",
	"/reset/8f3a9c1e?email=bob@example.com",
	"/docs#ops@example.com",
	"?contact=ops@example.com",
	"/@babel/core",
];

test("userinfo × an @ after the authority", () => {
	for (const [info, user, password] of USERINFO) {
		for (const after of AFTER) {
			const text = `see https://${info}db.example.com:5432${after} now`;
			const found = [...urls(text)];
			assert.equal(found.length, 1, text);
			const url = found[0]!;
			assert.equal(text.slice(url.start, url.end), `https://${info}db.example.com:5432${after}`, text);
			assert.equal(url.user?.value, user, text);
			assert.equal(url.password?.value, password, text);
			assert.equal(url.host?.value, "db.example.com:5432", text);
		}
	}
});

test("no userinfo in a host with a port and a path", () => {
	for (const text of [
		"http://localhost:4873/@babel/core",
		"https://host:443/docs?contact=ops@x.com",
		"http://[::1]:5173/@vite/client",
		"https://unpkg.com/react@18.3.1",
		"https://git.example.com:org/repo@v1.2",
	]) {
		const [url] = [...urls(text)];
		assert.equal(url!.password, undefined, text);
	}
});

test("the URL around a token, and parameters after & and &amp;", () => {
	const text = `<a href="https://x.com/go?next=https://y.com/reset/TOKEN&amp;key=VALUE">`;
	const token = text.indexOf("TOKEN");
	assert.equal(urlAround(text, token, token + 5), text.indexOf("https://y.com"));
	assert.equal(urlAround(`plain TOKEN https://x.com/`, 6), -1);
	assert.deepEqual(
		[...queryParams(text)].map((p) => [p.name, p.value.value]),
		[
			["next", "https://y.com/reset/TOKEN"],
			["key", "VALUE"],
		],
	);
	// (A value's own parentheses are its; a Markdown link's closing one isn't.)
	assert.deepEqual(
		[...queryParams("[x](https://a.io/?k=Xk9(mP2)vQ7&y=1) and (https://a.io/?t=abc)")].map((p) => p.value.value),
		["Xk9(mP2)vQ7", "1", "abc"],
	);
});

test("a key query parameter is hidden and the service id in the path kept", () => {
	hidden("curl -X POST https://api.render.com/deploy/srv-ylqty4zymq3c6yknj67b?key=\x4eOwD3P5eU2K", "NOwD3P5eU2K");
	kept(
		"curl -X POST https://api.render.com/deploy/srv-ylqty4zymq3c6yknj67b?key=\x4eOwD3P5eU2K",
		"srv-ylqty4zymq3c6yknj67b",
	);
});

test("a random segment of a URL path is hidden", () => {
	for (const [t, v] of [
		[
			"curl -X POST https://api.example.com/api/v1/8f2KqL9mXp3RtV7wZb4cN6dY1hJs5aE0/send",
			"8f2KqL9mXp3RtV7wZb4cN6dY1hJs5aE0",
		],
		["WEBHOOK=https://hooks.example.com/services/Xq7Lp2Nz9Kb4Rt8Wm3Yc6Vd1Hf5Js0Ae", "Xq7Lp2Nz9Kb4Rt8Wm3Yc6Vd1Hf5Js0Ae"],
	])
		hidden(t, v);
});

test("an image path and a feed URL are kept", () => {
	for (const t of [
		"https://p3.douyinpic.com/tos-cn-p-0015/oQEVkAcIgBfhAEDhABMeCflQAIgAUeAbzLgCYA~noop.jpeg",
		"<link>https://www.infoq.cn/article/6czPjR8fUGrtSJeIUxTM?utm_source=rss</link>",
	])
		assert.equal(r().redact(t).text, t);
});

test("a random token in a URL's path or query is hidden", () => {
	// A token is random by its characters, digits or none; a URL under a key that names a secret is one.
	hidden(
		"https://app.example.com/users/password/edit?reset_password_token=HeCyNZaswaFJeXfywkHbZg",
		"HeCyNZaswaFJeXfywkHbZg",
	);
	hidden("ZAPIER_HOOK=https://hooks.zapier.com/hooks/catch/23808906/\x37c06jvh/", "7c06jvh");
});

test("a camel-case file name in a URL's path is kept", () => {
	kept("see https://github.com/acme/web/blob/main/app/verify/VerifyEmailPage2024.tsx#L10", "VerifyEmailPage2024");
});

test("an ID-shaped token in a query parameter is hidden", () => {
	const text = "https://x.io/hook?k=k3j9x7q2m8p4w6z1v5t0r2nc";
	hidden(text, "k3j9x7q2m8p4w6z1v5t0r2nc");
});

test("a URL ends where the URL reader ends it, for every rule: a base64 key after one in minified JSON is not its path", () => {
	hidden(
		'{"url":"https://acme.dev","x":"Kx9m/Q2vL+7pZrTq8Wn3Xc4Yb5Va6Ud7Te8Sf9Rg+Hh0Ij1Kk2=="}',
		"Q2vL+7pZrTq8Wn3Xc4Yb5",
	);
});

test("a -u URL is the URL reader's", () => {
	kept("redis-cli -u redis://default:Kx9mQv2Lp7Rt@cache.internal:6379/0 PING", "cache.internal:6379/0");
});
