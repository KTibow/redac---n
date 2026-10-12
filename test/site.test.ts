/**
 * The demo page's examples (site/examples.ts) show what they say: each one's secrets hidden and its look-alikes kept,
 * with its hint and the default guessing; the bare token is the one only guessing hides.
 *
 *   node --test test/site.test.ts
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { examples } from "../site/examples.ts";
import { hidden, kept, r } from "./helpers.ts";

test("each example hides its secrets and keeps its look-alikes", () => {
	for (const e of examples) {
		for (const secret of e.secrets) hidden(e.text, secret, e.hint);
		for (const value of e.kept) kept(e.text, value, e.hint);
	}
});

test("the bare token in a log is hidden only by guessing", () => {
	const e = examples.find((e) => e.label === "Bare token in a log")!;
	assert.ok(r().redact(e.text, { hint: e.hint, guessing: "off" }).text.includes(e.secrets[0]));
});
