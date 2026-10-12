/**
 * The repository's own text holds no fake credential written out in full: GitHub's push protection, and every secret
 * scanner a reader runs, would take it for a real one. Tests write a vendor's token with one character escaped
 * (`"ghp\x5f…"`, `"4839574813\x3aAA…"`): the string's value is the token, the source text matches no vendor's pattern.
 *
 *   node --test test/hygiene.test.ts
 */
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { findFormats } from "../src/formats.ts";

const root = join(import.meta.dirname, "..");

test("no test, script or document writes a vendor's token out in full", () => {
	const files = [
		...["test", "eval", "scripts", "docs", "site"].flatMap((dir) =>
			readdirSync(join(root, dir))
				.filter((f) => /\.(?:ts|py|md|html)$/.test(f) && !/holdout/.test(f))
				.map((f) => join(dir, f)),
		),
		"README.md",
	];
	const found: string[] = [];
	for (const file of files) {
		const text = readFileSync(join(root, file), "utf8");
		for (const f of findFormats(text)) found.push(`${file}:${text.slice(0, f.start).split("\n").length} ${f.kind}`);
	}
	assert.deepEqual(found, []);
});
