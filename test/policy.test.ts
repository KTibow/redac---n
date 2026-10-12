/**
 * The decision stage: context never overrides what a value says it is, public keys stay public in every layer, and
 * what a name keeps or hides.
 *
 *   node --test test/policy.test.ts
 *
 * (A fake key's vendor prefix is written with an escape, `"ghp\x5f…"`: written whole, the repository would hold text
 * that secret scanners, GitHub's push protection among them, take for a live key.)
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { Redactor } from "../src/index.ts";
import { keepReason } from "../src/policy.ts";
import type { Finding } from "../src/types.ts";
import { b62, hidden, kept, privateKeyLines, r } from "./helpers.ts";

test("a signing secret is hidden and a long public signature is kept", () => {
	const sec = b62(40);
	hidden(`HOOK_SIG="${sec}"`, sec);
	const pubsig = b62(88);
	kept(`{"keyid": "SHA256:abc", "sig": "${pubsig}"}`, pubsig);
});

test("a public Mapbox token is kept in every guessing mode", () => {
	for (const guessing of ["confident", "eager"] as const) {
		const mapbox = "\x70k.eyJ1IjoiZXhhbXBsZXVzZXIiLCJhIjoiY2x4eXo3OGFiMDFxMjJqcXR2Zm5nbGhpNyJ9.Xq7Lm2Vb9Rt4Np8KwZ3cAb";
		assert.ok(
			new Redactor({ fingerprintKey: "t", guessing })
				.redact(`mapboxgl.accessToken = '${mapbox}';`)
				.text.includes(mapbox),
		);
	}
});

test("known and learned values are never judged by their context", () => {
	const oai = "sk-proj\x2dQ7mT2vX9pL4wR8nK3cJ6hF1bY5gZ0dS2aE7uV4iO9tN3kM8xW1qP6rL5jH2gD0fB";
	assert.ok(
		!new Redactor({ known: ["Q7mT2vX9pL4wR8nK3cJ6hF1bY5gZ0dS2"] })
			.redact("public key: Q7mT2vX9pL4wR8nK3cJ6hF1bY5gZ0dS2")
			.text.includes("Q7mT2vX9"),
	);
	const l = r();
	l.learn(`OPENAI_API_KEY=${oai}\n`, { hint: { path: ".env" } });
	assert.ok(!l.redact(`docker run -e PUBLIC_KEY=x -e OPENAI_API_KEY=${oai} img`).text.includes(oai));
});

test("a public key earlier on the line labels only the value it labels", () => {
	const skl = "sk\x5flive_51Hx7mQ2pLw9RtV3nK8cJ6hF1bY5gZ0dS2aE7uV4iO9tN3kM8xW1qP";
	hidden(
		'{"publicKey":"BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8QcYP7DkM","privateKey":"Hx7mQ2pLw9RtV3nK8cJ6hF1bY5gZ0dS2aE7uV4iO9tN"}',
		"Hx7mQ2pLw9RtV3nK8cJ6hF1bY5gZ0dS2aE7uV4iO9tN",
	);
	hidden(
		"docker run -e PUBLIC_KEY=abc -e AWS_SECRET_ACCESS_KEY=\x77JalrXUtnFEMQ7mT2vX9pL4wR8nK3cJ6hF1bY5gZ app",
		"wJalrXUtnFEMQ7mT2vX9pL4wR8nK3cJ6hF1bY5gZ",
	);
	hidden(`{"public_key":"pk_live_51Hx7mQ2pLw9RtV3nK8cJ6hF1bY","secret_key":"${skl}"}`, skl);
});

test("a public-sounding name does not keep a value whose prefix says secret", () => {
	const oai = "sk-proj\x2dQ7mT2vX9pL4wR8nK3cJ6hF1bY5gZ0dS2aE7uV4iO9tN3kM8xW1qP6rL5jH2gD0fB";
	const skl = "sk\x5flive_51Hx7mQ2pLw9RtV3nK8cJ6hF1bY5gZ0dS2aE7uV4iO9tN3kM8xW1qP";
	const ghp = "ghp\x5fQ7mT2vX9pL4wR8nK3cJ6hF1bY5gZ0dS2aE7u";
	for (const t of [
		`VITE_OPENAI_API_KEY=${oai}`,
		`NEXT_PUBLIC_OPENAI_API_KEY=${oai}`,
		`REACT_APP_GITHUB_TOKEN=${ghp}`,
		`EXPO_PUBLIC_STRIPE_SECRET_KEY=${skl}`,
	])
		hidden(t, t.slice(t.indexOf("=") + 1), { command: "cat .env.local" });
});

test("a name with a secret word does not keep its value", () => {
	for (const t of [
		"SITE_DB_PASSWORD=Hx7mQ2pLw9Rt",
		"VAPID_SECRET=Hx7mQ2pLw9RtV3nK8cJ6hF1bY5gZ0dS2aE7uV4iO9tN",
		"POSTHOG_API_KEY=\x70hx_Q7mT2vX9pL4wR8nK3cJ6hF1bY5gZ0dS2aE7uV4iO9tN3kM",
	])
		hidden(t, t.slice(t.indexOf("=") + 1));
});

test("a reCAPTCHA secret key is hidden and its site key kept", () => {
	hidden("RECAPTCHA_SECRET_KEY=6LdQ8xkUAAAAAJ3mR7vT9pW2qZ5nK8cY1bH4fG6e", "6LdQ8xkUAAAAAJ3mR7vT9pW2qZ5nK8cY1bH4fG6e");
	kept(
		'<div class="g-recaptcha" data-sitekey="6LdQ8xkUAAAAAJ3mR7vT9pW2qZ5nK8cY1bH4fG6e"></div>',
		"6LdQ8xkUAAAAAJ3mR7vT9pW2qZ5nK8cY1bH4fG6e",
	);
});

test("a JWE session cookie is a bearer credential", () => {
	const jwe = `${Buffer.from('{"alg":"dir","enc":"A256GCM"}').toString("base64url")}..Q_jBWH6Jycv12cSm.jwhNAfFKd1D7g2DKLnCqvVgAwucRFAXEaFurOjlUnNsM0Zhq-qcAZpiE1xnbwgxIUKUa48RVyhbzkuBT.y1Esc07bSPdam5MNfMf9eg`;
	assert.ok(
		!new Redactor({ guessing: "off" })
			.redact(`Cookie: next-auth.session-token=${jwe}; Path=/`)
			.text.includes("jwhNAfFKd1D7"),
	);
});

test("a Nix signing key is hidden and a Nix signature kept", () => {
	hidden(
		"cache.example.org-1:\x37aSQO4z9fGFx+8zuxDslUtcJO3Yao4TxZBg/xs4NdUF6Yf9NerzZG+Azjmeu2t243hvdFb0fwu1syzjLhroghA==",
		"7aSQO4z9fGFx",
	);
	kept(
		'"signatures": [\n  "cache.nixos.org-1:\x32qhYb5osDpAM+3lwQF1Za4GCvg2Yj1WL7NJUSVfyc9fhN2zxjtmoaUZGvVaDMg6O4svE7Kgd5MtsbjvegumTBM=="\n]',
		"2qhYb5osDpAM",
	);
});

test("Firebase words, JWK-like keys and a SHA256: prefix nearby do not make a key public", () => {
	const skl = "sk\x5flive_51Hx7mQ2pLw9RtV3nK8cJ6hF1bY5gZ0dS2aE7uV4iO9tN3kM8xW1qP";
	hidden(
		'firebase functions:config:set maps.key="AIz\x61SyD2kP9xW4vR7tN1mQ8zL3cH6jF0bY5gU2e"',
		"AIz\x61SyD2kP9xW4vR7tN1mQ8zL3cH6jF0bY5gU2e",
	);
	hidden(`{"keys":[{"kty":"EC","x":"abc"}],"billing":{"e":"${skl}"}}`, skl);
	hidden("API_TOKEN=SHA256:Q7mT2vX9pL4wR8nK3cJ6hF1bY5gZ0dS2aE7uV4iO9tN", "Q7mT2vX9pL4wR8nK3cJ6hF1bY5gZ0dS2aE7uV4iO9tN");
});

test("a public key stays public whichever layer proposes it and however it is written", () => {
	const aiza = "AIz\x61SyD2kP9xW4vR7tN1mQ8zL3cH6jF0bY5gU2e";
	for (const t of [
		`const NEXT_PUBLIC_MAPS_KEY: string = "${aiza}";`,
		`NEXT_PUBLIC_MAPS_KEY="\x1b[33m${aiza}\x1b[0m"`,
		`export VITE_MAPS_KEY=${aiza}`,
	])
		kept(t, aiza);
	kept(
		'const pusher = new Pusher({ appId: "1234567", key: "9f3c1e7a2b8d4f6e0c5a", cluster: "eu" });',
		"9f3c1e7a2b8d4f6e0c5a",
	);
	kept(
		"Public Key:\nBNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8QcYP7DkM\n",
		"BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA",
	);
	const v = r().redactValue({
		firebaseConfig: { apiKey: aiza, authDomain: "demo.firebaseapp.com", messagingSenderId: "123456789012" },
		jwk: { kty: "OKP", crv: "Ed25519", x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" },
	}).value;
	assert.ok(JSON.stringify(v).includes(aiza) && JSON.stringify(v).includes("11qYAYKxCrfVS"));
});

test("a private key under a public key's name is still a private key", () => {
	const pem = privateKeyLines().join("\n");
	hidden(`{"publicKey": ${JSON.stringify(pem)}}`, privateKeyLines()[1]);
	hidden(`PUBLIC_KEY="${pem}"`, privateKeyLines()[1]);
});

test("a context's public signs keep only what they describe", () => {
	// (A Sealed Secret's ciphertext only in a SealedSecret: a random base64 key starts with `Ag` too.)
	const ag = `Ag${b62(126)}`;
	hidden(`PRIVATE_KEY_B64=${ag}`, ag);
	// (A DocSearch key only beside a DocSearch config's app ID.)
	hidden('{"indexName": "products", "apiKey": "7f3c9a1e8b2d4f6a0c5e9b7d3a1f8e2c"}', "7f3c9a1e8b2d4f6a0c5e9b7d3a1f8e2c");
	// (A client SDK's public key by its parameter's name, not a name that says server: `"server key"`.)
	hidden(
		'new Pusher({ appId: "1234567", "server key": "7f3c9a1e8b2d4f6a0c5e9b7d3a1f8e2c" });',
		"7f3c9a1e8b2d4f6a0c5e9b7d3a1f8e2c",
	);
});

test("a number a rule read as a password is one, wherever it was read", () => {
	for (const text of [
		"mysql -u root -p4821-7730",
		"sshpass -p 4821-7730 ssh deploy@host",
		"curl -u admin:4821-7730 https://api.example.com",
		"psql postgres://admin:4821-7730@db/app",
	])
		hidden(text, "4821-7730");
	kept("single-pass: 3.52x", "3.52x");
	kept("mysql -u root -p2024-05-01", "2024-05-01");
});

test("a word named in prose or SQL is a value, whatever it ends in, unless code marks it", () => {
	hidden("The password is: HarborConfig", "HarborConfig");
	hidden("UPDATE users SET password = Hunter2x WHERE id = 1", "Hunter2x");
	// (The name the layer read, `key`, not another word the line has before it: `user:` names no key.)
	hidden("user: api key=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b");
});

test("the decision reads a proposal's code shapes from the proposal itself, whatever a layer took in", () => {
	const sig = `cache.example.org-1:${"Q7mT2vX9pL4wR8nK3cJ6hF1bY5gZ0dS2aE7uV4iO9tN3kM8xW1qP6rL5jH2gD0fBQ7mT2vX9pL4wR8nK3cJ6hF"}==`;
	// [text, the span (its last occurrence), how the decision reads it]
	const cases: [string, string, string | undefined, Partial<Finding>?][] = [
		// A span that took its literal's quotes is that literal, never a type, an identifier or a bind parameter.
		['password: "SunnyData?",', '"SunnyData?"', undefined],
		['token: "Uint8Array";', '"Uint8Array"', undefined],
		['password: "String!"', '"String!"', undefined],
		['  Password: "rotateKeyNow",', '"rotateKeyNow"', undefined],
		["UPDATE users SET password = ':Hunter2x' WHERE id = 1", "':Hunter2x'", undefined],
		['"passwd": "account.password",', "account.password", undefined],
		// A type needs its mark and a declaration's end: one word before `?`, or words after it, are a password.
		["The password is: Tiger?", "Tiger", undefined, { rule: "named:prose" }],
		["password: SunnyData? is what I use", "SunnyData", undefined],
		["password: SunnyData?,", "SunnyData", "a type"],
		["password: Uint8Array", "Uint8Array", undefined, { literal: true }],
		// An identifier ending a struct's line has an identifier's letters, lower case and an upper-case hump or `_`.
		["  password: Sunny-Day77,\n", "Sunny-Day77", undefined],
		["  password: SUNNY_DAY,\n", "SUNNY_DAY", undefined],
		["  password: sunshine,\n", "sunshine", undefined],
		["  password: sunshineMain,\n", "sunshineMain", "identifier"],
		// A call or subscript cut at its argument is one by its name: `md5(`, not a password's own bracket.
		['password=md5("x")', "md5(", "call or subscript"],
		["pwd: Rq8zTn3w[0]", "Rq8zTn3w[0", undefined],
		// A vendor's token at a token's start is that token, whatever runs on after it.
		[
			"token: AKIAIOSFODNN7EXAMPLEabcdefghijklmnop",
			"AKIAIOSFODNN7EXAMPLE",
			undefined,
			{ rule: "format:AWS access key ID" },
		],
		// A public name of key-like words, not a sentence that has "public" in it; the name, not a type read for it.
		[
			"Token for the public API: Kx9mQv2Lp7RtWz4nKx9mQv2Lp7RtWz4n",
			"Kx9mQv2Lp7RtWz4nKx9mQv2Lp7RtWz4n",
			undefined,
			{ rule: "unnamed", name: undefined },
		],
		[
			'const NEXT_PUBLIC_RC_KEY: string = "Kx9mQv2Lp7RtWz4nKx9mQv2Lp7RtWz4n";',
			"Kx9mQv2Lp7RtWz4nKx9mQv2Lp7RtWz4n",
			"public by its name",
			{ rule: "unnamed", name: "string" },
		],
		// A narinfo's `Sig:` is a signature; a Nix secret key named so inside a signatures list isn't.
		[`StorePath: /nix/store/abc-hello\nSig: ${sig}`, sig, "signature", { rule: "unnamed", name: "Sig" }],
		[`{"signatures": [{"secretKey": "${sig}"`, sig, undefined, { name: "secretKey" }],
	];
	for (const [text, span, reason, o] of cases) {
		const start = text.lastIndexOf(span);
		const f: Finding = {
			start,
			end: start + span.length,
			kind: "password",
			rule: "named:assign",
			name: "password",
			confidence: 0.9,
			...o,
		};
		assert.equal(keepReason(text, f), reason, text);
	}
});

test("a service_role JWT is hidden under any name", () => {
	const svc = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${Buffer.from('{"iss":"supabase","ref":"qwertyuiopasdfghjkl","role":"service_role","iat":1700000000,"exp":2015576000}').toString("base64url")}.Q7mT2vX9pL4wR8nK3cJ6hF1bY5gZ0dS2aE7uV4iO9tN`;
	hidden(`{"publicKey": "${svc}"}`, svc.split(".")[2]);
});
