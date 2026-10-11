/**
 * Private keys in PEM and other armor: wrapped, flattened, prefixed, cut, quoted in source or packed in base64, and
 * the public keys that stay.
 *
 *   node --test test/private-keys.test.ts
 */
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { b62, hidden, kept, privateKeyLines, r } from "./helpers.ts";
import { randomBytes } from "./random.ts";

test("a PEM private key is hidden bare and inside a JSON string", () => {
	const pem = `-----BEGIN RSA PRIVATE KEY-----\n${randomBytes(600)
		.toString("base64")
		.match(/.{1,64}/g)!
		.join("\n")}\n-----END RSA PRIVATE KEY-----`;
	const out = r().redact(`key:\n${pem}\n`).text;
	assert.ok(!out.includes(pem.split("\n")[3]));
	const json = JSON.stringify({ private_key: pem });
	assert.ok(
		!r()
			.redact(json)
			.text.includes(JSON.stringify(pem.split("\n")[3]).slice(1, -1)),
	);
});

test("an encrypted PEM key and a key flattened onto one line are hidden", () => {
	const body = `${b62(64)}\n${b62(64)}\n`;
	hidden(
		`-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0A1B2C3D4E5F\n\n${body}-----END RSA PRIVATE KEY-----`,
		body.slice(0, 40),
	);
	hidden(
		`KEY=-----BEGIN RSA PRIVATE KEY----- ${body.replace(/\n/g, " ")}-----END RSA PRIVATE KEY-----`,
		body.slice(0, 40),
	);
});

test("a PEM key is hidden under line numbers and grep prefixes", () => {
	const pem = ["-----BEGIN PRIVATE KEY-----", ...Array.from({ length: 6 }, () => b62(64)), "-----END PRIVATE KEY-----"];
	for (const shape of [
		(l: string, i: number) => `${String(i + 1).padStart(6)}→${l}`,
		(l: string, i: number) => `${String(i + 1).padStart(6)}\t${l}`,
		(l: string) => `certs/server.key:${l}`,
	]) {
		const out = r().redact(pem.map(shape).join("\n")).text;
		for (const l of pem.slice(1, -1)) assert.ok(!out.includes(l.slice(10, 40)), out.slice(0, 200));
	}
});

test("the tail of a key without its BEGIN line is hidden", () => {
	const pem = ["-----BEGIN PRIVATE KEY-----", ...Array.from({ length: 6 }, () => b62(64)), "-----END PRIVATE KEY-----"];
	hidden(pem.slice(-4).join("\n"), pem[5].slice(10, 40)); // `tail` of a key: no BEGIN line
});

test("an OpenVPN static key is hidden", () => {
	hidden(
		"-----BEGIN OpenVPN Static key V1-----\n" +
			"78e572acd23b19a3c10c7362ffe57dd6\n".repeat(16) +
			"-----END OpenVPN Static key V1-----",
		"78e572acd23b19a3c10c7362ffe57dd6",
	);
});

test("a PEM key quoted as a JSON string is hidden", () => {
	hidden(
		'        "\x4dIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQMKNw/hiP4hMCK9cpE/1ZvYEDpiZ6nzCNxSmuABnq5zaVTVf+egKGNQ8BY8UCkf/Ha+eG5piNHYiScapUk4SEO5cTgJDBZXVo3opQzXcV6uRoCbvtdpXGNNni6pv3f4++Z6RINanFII/Tzmjt+FexKYu21sFdF5RoHAqr5bDeaajakY0zN"',
		"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQMKNw",
	);
});

test("the tail of a key is read up from its END line, also through \\n escapes", () => {
	const key = privateKeyLines();
	const tail = key.slice(-5);
	for (const text of [tail.join("\n"), JSON.stringify({ log: `out=${tail.join("\n")}` })]) hidden(text, key.at(-3)!);
});

test("a cut certificate ends where its material does, not at the headers after a blank line", () => {
	hidden(
		"-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ\n\nX-Lumen: kX9mQ2vR7tL4pW8nZ3bY6cD1aF5eHq3n\nAccept: */*",
		"kX9mQ2vR7tL4pW8nZ3bY6cD1aF5eHq3n",
	);
});

test("a key written a line at a time in source is hidden, cut at either end", () => {
	const pem = privateKeyLines();
	const body = pem.slice(1, -1);
	hidden(`KEY = (\n${pem.map((l) => `    "${l}\\n"`).join("\n")}\n)`, body[10]);
	hidden(
		pem
			.slice(-6)
			.map((l) => `    "${l}\\n" +`)
			.join("\n"),
		body.at(-3)!,
	);
});

test("a key joined by blanks whose lines start with + is hidden", () => {
	const pem = privateKeyLines();
	const body = pem.slice(1, -1);
	const plus = [...body.slice(0, 5), `+${body[5].slice(1)}`, ...body.slice(6)];
	hidden(`PRIVATE_KEY=${[pem[0], ...plus, pem.at(-1)].join(" ")}`, plus[5]);
});

test("base64 of a bundle that holds an OpenVPN key is hidden", () => {
	const ovpn = `-----BEGIN OpenVPN Static key V1-----\n${Array.from({ length: 16 }, () => randomBytes(16).toString("hex")).join("\n")}\n-----END OpenVPN Static key V1-----\n`;
	const bundle = Buffer.from(
		`-----BEGIN CERTIFICATE-----\n${randomBytes(48).toString("base64")}\n-----END CERTIFICATE-----\n${ovpn}`,
	).toString("base64");
	hidden(`TLS_AUTH_BUNDLE=${bundle}`, bundle.slice(-40));
});

test("a key stored unwrapped with its front cut off is hidden", () => {
	const key = privateKeyLines();
	const unwrapped = key.slice(1, -1).join("");
	hidden(`  "private_key": "${unwrapped.slice(-400)}\\n-----END PRIVATE KEY-----\\n",`, unwrapped.slice(-200, -150));
});

test("a key with a log's prefix on every line, or in ssh.com's armor, is hidden", () => {
	const key = privateKeyLines();
	const logged = [...key.slice(0, 1), ...key.slice(1, -1), key.at(-1)!]
		.map((l, i) => `2026-10-10T08:00:${String(i % 60).padStart(2, "0")}.1234567Z ${l}`)
		.join("\n");
	hidden(logged, key[5]);
	hidden(
		`---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\nComment: "rsa-key-20240101"\n${key.slice(1, -1).join("\n")}\n---- END SSH2 ENCRYPTED PRIVATE KEY ----`,
		key[5],
	);
});

test("a private key's DER is a private key under any armor; a public key's stays", () => {
	for (const [type, options] of [
		["rsa", { modulusLength: 2048 }],
		["ec", { namedCurve: "P-256" }],
		["ed25519", {}],
	] as const) {
		const { privateKey, publicKey } = generateKeyPairSync(type as "rsa", options as { modulusLength: number });
		const pkcs8 = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
		const body = pkcs8.split("\n")[1];
		for (const label of ["PUBLIC KEY", "CERTIFICATE"]) hidden(pkcs8.replace(/PRIVATE KEY/g, label), body);
		const spki = publicKey.export({ type: "spki", format: "pem" }) as string;
		kept(spki, spki.split("\n")[1]);
	}
});

test("SEC 1's explicit EC parameters start as an EC key does and are public", () => {
	const params =
		"-----BEGIN EC PARAMETERS-----\nMIG3AgEBMCUGByqGSM49AQIwGgICAKMGCSqGSM49AQIDAzAJAgEBAgECAgEIMEQE\nFQclRrVDUjSkIuB4lnX0MsiUNd5SQgQUyVF9BtUkDTz/OMdLILbNTW+d1NkDFQDS\nwPsVdghg3vHu9NaW5naHVhUXVAQrBAevaZiVRhA9eTKfzD10iA8zu+gDywHsIyEb\nWWat6h0/h/fqWEiu8LfKnwIVBAAAAAAAAAAAAAHmD8iCHMdNrq/BAgEC\n-----END EC PARAMETERS-----";
	kept(params, "MIG3AgEBMCUGByqGSM49AQIwGgICAKMGCSqGSM49AQIDAzAJAgEBAgECAgEIMEQE");
});
