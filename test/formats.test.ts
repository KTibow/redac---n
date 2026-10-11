/**
 * The core format rules (src/formats.ts): each reports one span, ends where its token ends, and finds a token it
 * describes; every rule compiles. Each rule's token is generated from its own pattern at run time (regex-example.ts),
 * so no secret-shaped string is stored here, and a rule that can no longer fire (a keyword its index can't see, a
 * rejection that rules out its own shape) fails by name.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { IMPORTED_FORMATS } from "../src/formats-data.ts";
import { CORE_FORMATS, findFormats } from "../src/formats.ts";
import { example } from "./regex-example.ts";

function random(seed: number): () => number {
	let s = seed >>> 0;
	return () => {
		s = (s + 0x6d2b79f5) >>> 0;
		let t = Math.imul(s ^ (s >>> 15), s | 1);
		t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
}

test("every core format rule reports one span and ends where its token ends", () => {
	for (const [name, rule] of CORE_FORMATS) {
		// One capture group: the secret (findFormats reports group 1).
		assert.equal(new RegExp(`${rule.source}|`).exec("")!.length - 1, 1, `${name}: ${rule.source}`);
		// A rule of fixed length stops at a token boundary, so a longer token isn't cut with its tail left in clear.
		if (/\{\d+\}\)*$/.test(rule.source)) assert.fail(`${name} has no right boundary: ${rule.source}`);
	}
});

test("every core format rule finds a token of its own shape", () => {
	const dead: string[] = [];
	for (const [name, rule] of CORE_FORMATS) {
		const next = random(name.length * 7919 + name.charCodeAt(0));
		let found = false;
		for (let n = 0; n < 5 && !found; n++) {
			const token = example(rule, next);
			if (token === undefined) break;
			found = findFormats(`value: ${token}\n`).some((f) => f.rule === `format:${name}`);
		}
		if (!found) dead.push(name);
	}
	assert.deepEqual(dead, []);
});

test("every imported format compiles without ES2025 regex modifiers (Node 20 and 22)", async () => {
	const { IMPORTED_FORMATS } = await import("../src/formats-data.ts");
	for (const [name, source, flags] of IMPORTED_FORMATS) {
		assert.doesNotMatch(source, /\(\?-?[is]+(?:-[is]+)?:/, name);
		assert.doesNotThrow(() => new RegExp(source, `${flags}gd`), name);
	}
});

test("every format compiles as a global indices regex and rule names are unique", () => {
	for (const [name, source, flags] of IMPORTED_FORMATS)
		assert.doesNotThrow(() => new RegExp(source, `${flags}gd`), name);
	for (const [name, rule] of CORE_FORMATS)
		assert.doesNotThrow(() => new RegExp(rule.source, `${rule.flags.replace(/[gd]/g, "")}gd`), name);
	const names = CORE_FORMATS.map(([name]) => name);
	assert.deepEqual(
		names.filter((name, i) => names.indexOf(name) !== i),
		[],
	);
});
