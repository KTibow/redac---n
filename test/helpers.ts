/**
 * Helpers shared by the behaviour tests: a redactor with a fixed fingerprint key, `hidden` and `kept` (a value is gone
 * from the output, or still there), random strings and a private key.
 */
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { Redactor } from "../src/index.ts";
import { randomBytes } from "./random.ts";

/** A redactor whose tags are the same on every run. */
export const r = () => new Redactor({ fingerprintKey: "test" });

/** `n` random base-62 characters. */
export const b62 = (n: number) => {
	const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	return Array.from(randomBytes(n), (b) => a[b % 62]).join("");
};

/** Fails if `secret` survives redaction of `text`; the message names the text. */
export const hidden = (text: string, secret: string, hint = {}) => {
	const out = r().redact(text, { hint }).text;
	assert.ok(!out.includes(secret), `leaked ${secret.slice(0, 60)} in ${JSON.stringify(text.slice(0, 200))}`);
};

/** Fails if `value` does not survive redaction of `text`; the message shows what came out. */
export const kept = (text: string, value: string, hint = {}) => {
	const out = r().redact(text, { hint }).text;
	assert.ok(out.includes(value), `lost ${value.slice(0, 60)} in ${JSON.stringify(out.slice(0, 200))}`);
};

let privateKey: string[] | undefined;
/** The lines of a 2048-bit RSA private key in PKCS#8 PEM, generated once per process (generating takes a moment). */
export const privateKeyLines = (): string[] =>
	(privateKey ??= generateKeyPairSync("rsa", {
		modulusLength: 2048,
		privateKeyEncoding: { type: "pkcs8", format: "pem" },
		publicKeyEncoding: { type: "spki", format: "pem" },
	})
		.privateKey.trim()
		.split("\n"));
