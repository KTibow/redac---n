/**
 * The URL reader across the userinfo shapes clients accept and the places an `@` turns up after the authority: every
 * user and password comes back whole, and an `@` in a path, query or fragment is never read as the end of a userinfo.
 * And the random tokens a path or query holds.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { isPasswordlessUrl, percentEncoded, queryParams, urlAround, urls } from "../src/urls.ts";
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
	// After `&` as a JSON encoder or JS writes it: `&` (Go's encoding/json), `\x26`.
	assert.deepEqual(
		[...queryParams(String.raw`https://x.io/?x=1&password=Xk9mQv2Lp8Zr\x26y=2`)].map((p) => [p.name, p.value.value]),
		[
			["x", "1"],
			["password", "Xk9mQv2Lp8Zr"],
			["y", "2"],
		],
	);
	for (const name of ["password", "client_secret", "token"]) {
		hidden(String.raw`{"u":"https://x.io/?x=1&${name}=Xk9mQv2Lp8Zr&y=2"}`, "Xk9mQv2Lp8Zr");
		kept(String.raw`{"u":"https://x.io/?x=1&${name}=Xk9mQv2Lp8Zr&y=2"}`, String.raw`&y=2"}`);
	}
});

test("a query parameter's value ends where the URL reader ends it, at an angle bracket, under any rule", () => {
	for (const [text, rest] of [
		["<a href=https://x.io/cb?token=Xk9mQv2Lp8ZrTt7Wq>reset</a>", ">reset</a>"],
		['Link: <https://api.x.io/items?page=2&access_token=Xk9mQv2Lp8ZrTt7Wq>; rel="next"', '>; rel="next"'],
		["See <https://x.io/cb?token=Xk9mQv2Lp8ZrTt7Wq>.", ">."],
	]) {
		hidden(text, "Xk9mQv2Lp8ZrTt7Wq");
		kept(text, rest);
	}
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

test("a scheme of any length with a driver's _ is a URL's: SQLAlchemy's dialect+driver", () => {
	for (const scheme of ["redshift+redshift_connector", "oracle+cx_oracle", "ibm_db_sa", "postgresql+psycopg2"]) {
		hidden(`engine = create_engine("${scheme}://admin:Hq3mT8wZ5rK2@db.example.com:5439/dev")`, "Hq3mT8wZ5rK2");
		const text = `${scheme}://db.example.com/x?token=TOKEN`;
		assert.equal(urlAround(text, text.indexOf("TOKEN")), 0, scheme);
	}
});

test("an apostrophe in a query string's value is the value's, unless a quote before it opened a string", () => {
	// (encodeURIComponent leaves `'` as it is.)
	const line = "GET /login?user=bob&password=Tr0ub4dor'3xK9mQ!x7&next=/home";
	hidden(line, "3xK9mQ!x7");
	kept(line, "]&next=/home");
	kept("echo 'https://x.io/cb?password=Tr0ub4dorx3xK9mQ' && ls -la", "' && ls -la");
});

test("a quote in a password is the password's, and a quote that ends a URL isn't", () => {
	const password = (text: string) => [...urls(text)][0]?.password?.value;
	assert.equal(password("postgres://app:Kx9m'Qv2@db/x"), "Kx9m'Qv2");
	assert.equal(password('postgres://app:Kx9m"Qv2@db/x'), 'Kx9m"Qv2');
	assert.equal(password("mysql://root:#1'Kx9mQv@db/app"), "#1'Kx9mQv");
	// So are the other characters that end a URL, before the `@` that ends the password.
	for (const pw of ["Qv2Lp8Zr>Kx9m", "Kx9m<Qv2Lp8Zr", String.raw`Qv2Lp8Zr\Kx9m`, "Qv2Lp8`Zr"]) {
		assert.equal(password(`DATABASE_URL=postgres://app:${pw}@db/x`), pw);
		hidden(`DATABASE_URL=postgres://app:${pw}@db/x`, pw.slice(-5));
	}
	hidden(String.raw`{"dsn":"postgres://app:Kx9m&Qv2Lp8Zr@db:5432/x"}`, "Qv2Lp8Zr");
	// (An autolink's `>` with an `@` later in the sentence ends it.)
	kept("<postgres://app:Qv2Lp8Zr@db/x> or mail ops@x.com", "> or mail ops@x.com");
	hidden(String.raw`{"stdout": "DB_URL=postgres://app:Kx9m\"Qv2@db/x\nOK"}`, "Qv2");
	// (Not a placeholder's port, nor pieces joined into a URL.)
	const code = 'const base = "http://localhost:${PORT}";';
	const [base] = urls(code);
	assert.equal(code.slice(base!.start, base!.end), "http://localhost:${PORT}");
	assert.equal(password("url = 'https://'+user+':'+pw+'@'+host"), undefined);
});

test("a URL's brackets: an IPv6 host's, and a closing one it didn't open", () => {
	const whole = (text: string) => [...urls(text)].map((u) => text.slice(u.start, u.end));
	assert.deepEqual(whole("open http://[::1]:5173/@vite/client now"), ["http://[::1]:5173/@vite/client"]);
	assert.deepEqual(whole("[https://x.io/a] and (https://y.io/b)"), ["https://x.io/a", "https://y.io/b"]);
});

test("a password after a placeholder port or a dotted user", () => {
	const [placeholder] = urls("fetch(`https://localhost:${PORT}/api?email=ops@example.com`)");
	assert.equal(placeholder!.password, undefined);
	const [bare] = urls("http://localhost:${PORT}/api");
	assert.equal(bare!.user, undefined);
	const [dotted] = urls("postgres://first.last:Kx9mQ2@localhost/app");
	assert.equal(dotted!.password?.value, "Kx9mQ2");
	hidden(`dsn := "root:Kx/9@m?Q2v@tcp(127.0.0.1:3306)/db"`, "Q2v");
});

test("a passwordless URL is one whole URL with no password", () => {
	assert.ok(isPasswordlessUrl("postgres://db.internal/app"));
	assert.ok(!isPasswordlessUrl("postgres://app:Kx9mQ2@db.internal/app"));
	assert.ok(!isPasswordlessUrl("postgres://db.internal/app Kx9mQ2vL"));
});

test("percent-encoded text of its own is decoded, a single encoded token isn't", () => {
	const decoded = (text: string) => [...percentEncoded(text)].map((d) => d.decoded);
	assert.deepEqual(decoded("next=https%3A%2F%2Fx.io%2Fcb%3Fcode%3Dabc"), ["https://x.io/cb?code=abc"]);
	assert.deepEqual(decoded("sig=Kx9mQ2vLpR7tZz%2BAbCd%3D"), []);
	assert.deepEqual(decoded("q=a%20b"), []);
	assert.deepEqual(decoded("100% of a+long+file+name.txt"), []);
});

test("a sign-in link's token follows its segment and a word that qualifies it; a record's id and a commit are no token", () => {
	hidden("https://example.com/confirm/account/a8f3k2m9x7q4w1e6r5t0", "a8f3k2m9x7q4w1e6r5t0");
	kept("GET /verify/3f2b8c1e-9a4d-4e6f-8b2a-1c3d5e7f9a0b 200", "3f2b8c1e-9a4d-4e6f-8b2a-1c3d5e7f9a0b");
	kept(
		"https://github.com/acme/login/commit/3f9a2c1e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a39",
		"3f9a2c1e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a39",
	);
	// (A web link's: a file's path is no link anyone opens.)
	kept("file:///srv/app/reset/Xk9mQ2pLrT7vW3nB8yZ4cD6f.txt", "Xk9mQ2pLrT7vW3nB8yZ4cD6f.txt");
});

test("a long random token is hidden under a collection's plural and before a feed's or a download's extension", () => {
	const token = "RDawDeMmwBAfIonz1nwZvmbIQgys7bwF";
	for (const text of [
		`SLACK_WEBHOOK=https://chat.example.com/integrations/${token}`,
		`curl -X POST -d 'content=Deploy finished' https://3.basecamp.com/3180705/integrations/${token}/buckets/1/chats/2/lines`,
		`WEBHOOK_URL=https://api.example.com/v2/endpoints/${token}`,
		`{"webhook": "https://api.example.com/v2/relays/${token}"}`,
		...["ics", "xml", "rss", "zip", "pdf"].map(
			(ext) => `curl -fsS https://calendar.example.com/subscribe/${token}.${ext} -o out`,
		),
	])
		hidden(text, token);
	// IDs services generate are shorter (Spotify's 22, Firestore's 20), and an image or a page
	// asset is named by its ID on any host.
	for (const [text, id] of [
		["https://api.spotify.com/v1/tracks/4uLU6hMCjMI75M1A2tKUQC", "4uLU6hMCjMI75M1A2tKUQC"],
		[
			"https://firestore.googleapis.com/v1/projects/p/databases/x/documents/users/aB3dE5fG7hI9jK1lM3nO",
			"aB3dE5fG7hI9jK1lM3nO",
		],
		...["png", "jpg", "webp", "css"].map((ext) => [`https://example.com/u/${token}.${ext}`, token]),
	])
		kept(text, id);
});
