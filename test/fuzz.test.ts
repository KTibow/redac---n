/**
 * The recall gate (eval/fuzz-secrets.ts): seeded random passwords and keys, from generators with full symbol
 * sets, in every context the name and structure layers read, secret files included. A keep that a random
 * value can satisfy by resembling part of a shape (an unclosed brace, a leading `$` or `<`, `%v` inside it)
 * leaks here. Every one must be hidden.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { fuzz } from "../eval/fuzz-secrets.ts";
import { Redactor } from "../src/index.ts";

test("random passwords and keys are hidden in every context", () => {
	const cells = fuzz(60, 1);
	assert.ok(cells.reduce((n, c) => n + c.total, 0) > 4000);
	const leaks = cells
		.filter((c) => c.leaks)
		.map((c) => `${c.gen} in ${c.ctx}: ${c.leaks}/${c.total} ${c.examples.join(" | ")}`);
	assert.equal(leaks.length, 0, `leaked:\n${leaks.join("\n")}`);
});

test("a `/` in a base64 key doesn't split it where the key stands as a value", () => {
	let state = 3;
	const random = () => {
		state = (state + 0x6d2b79f5) >>> 0;
		let t = Math.imul(state ^ (state >>> 15), state | 1);
		t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
	const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	const r = new Redactor();
	const rates: string[] = [];
	for (const ctx of [
		'client = Client("%")',
		'headers = {"X-Lumen": "%"}',
		"token: %",
		'fetch(url, { auth: "%" })',
		"$ ./notify.sh prod %",
		"Your new API key:\n%",
	]) {
		const leaked = { slash: [0, 0], none: [0, 0] };
		for (let i = 0; i < 400; i++) {
			const key = Array.from({ length: 24 + (i % 3) * 8 }, () => B64[Math.floor(random() * 64)]).join("");
			const out = r.redact(ctx.replace("%", key)).text;
			const row = key.includes("/") ? leaked.slash : leaked.none;
			row[0]++;
			if (out.includes(key.slice(4, 16)) || out.includes(key.slice(-12))) row[1]++;
		}
		const [slash, none] = [leaked.slash[1] / leaked.slash[0], leaked.none[1] / leaked.none[0]];
		if (slash > none + 0.03)
			rates.push(`${ctx}: ${(slash * 100).toFixed(1)}% with '/', ${(none * 100).toFixed(1)}% without`);
	}
	assert.deepEqual(rates, []);
});
