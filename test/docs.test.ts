/**
 * The source's own documentation stays on what it documents: a doc comment followed directly by another one (code
 * inserted between a doc and its declaration) leaves the first on the wrong code. Module headers, which may sit above a
 * first declaration's doc, are exempt.
 */
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

const src = join(import.meta.dirname, "..", "src");

test("no doc comment is orphaned above another", () => {
	const orphaned: string[] = [];
	for (const file of readdirSync(src).filter((f) => f.endsWith(".ts") && !f.endsWith("-data.ts"))) {
		const text = readFileSync(join(src, file), "utf8");
		const header = text.startsWith("/**") ? text.indexOf("*/") + 2 : 0;
		for (const m of text.matchAll(/\*\/\n(?:[ \t]*\n)*[ \t]*\/\*\*/g))
			if (m.index > header) orphaned.push(`${file}:${text.slice(0, m.index).split("\n").length}`);
	}
	assert.deepEqual(orphaned, []);
});
