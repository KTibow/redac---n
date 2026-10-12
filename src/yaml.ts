/**
 * YAML read line by line, the way block mappings and lists are written: each line's indentation, list marker, key and
 * value, the block scalars (`key: |`) whose lines belong to a key, and a key's siblings in its mapping. Enough for the
 * shapes secrets sit in (Kubernetes manifests, Compose files, CI configs); not a YAML parser: no flow collections,
 * anchors, tags or multi-line plain scalars.
 */
import { lastText, lineEnd as lineEndAt, lowerBound } from "./lines.ts";
import { type Span, stringEnd } from "./syntax.ts";

export interface YamlLine {
	/** Where the line starts and ends in the text (its end before the line break and a `\r`). */
	start: number;
	end: number;
	/** The column the line's content starts at, after indentation and `- ` list markers. */
	indent: number;
	/** The line starts a list item: `- name: x`. */
	item: boolean;
	/** A document separator: `---` or `...`. */
	separator: boolean;
	/** Nothing but blanks, or a comment: at any column, it neither ends a mapping nor belongs to one. */
	blank: boolean;
	/** A mapping entry's key, and its value: without quotes or a trailing comment, absent when empty. */
	key?: string;
	value?: Span;
	/** The value was quoted. */
	quoted: boolean;
	/** The value is a block scalar's indicator (`|`, `>-`, `|2`): its lines follow. */
	block: boolean;
}

const ENTRY =
	/^([ \t]*(?:-[ \t]+)*)(?:"([^"\n]{1,200})"|'([^'\n]{1,200})'|([^\s"'#:{}[\],&*!|>%@`-][^:#\n]{0,200}?|-[^\s:#][^:#\n]{0,200}?)(?<![ \t]))[ \t]*:(?=[ \t]|$)[ \t]*/;

/** The lines of `text`. */
export function yamlLines(text: string): YamlLine[] {
	const lines: YamlLine[] = [];
	for (let start = 0; ;) {
		lines.push(readLine(text, start, contentEnd(text, start)));
		const next = text.indexOf("\n", start);
		if (next < 0) break;
		start = next + 1;
	}
	return lines;
}

/** A block scalar's indicator, with its chomping and indentation indicators in either order: `|`, `>-`, `|2-`, `>+1`. */
export function isBlockIndicator(rest: string): boolean {
	return /^[|>](?:[-+]?\d?|\d[-+])[ \t]*(?:#.*)?$/.test(rest.replace(/\r$/, ""));
}

function readLine(text: string, start: number, end: number): YamlLine {
	const line = text.slice(start, end);
	const lead = /^[ \t]*(?:-[ \t]+)*/.exec(line)![0];
	const base = {
		start,
		end,
		indent: lead.length,
		item: lead.includes("-"),
		separator: /^(?:---|\.\.\.)(?:[ \t]|$)/.test(line),
		blank: /^[ \t]*(?:#.*)?$/.test(line),
		quoted: false,
		block: false,
	};
	const m = ENTRY.exec(line);
	if (!m || base.separator) return base;
	const key = (m[2] ?? m[3] ?? m[4]).trim();
	let at = m[0].length;
	const rest = line.slice(at);
	if (isBlockIndicator(rest)) return { ...base, key, block: true };
	// A double-quoted scalar escapes with a backslash, a single-quoted one by doubling its quote; a plain one ends at a
	// comment (` #`).
	const close =
		rest[0] === '"' || rest[0] === "'"
			? stringEnd(rest, 0, { escapes: rest[0] === '"' ? "backslash" : "doubled" })
			: -1;
	if (close > 0)
		return {
			...base,
			key,
			quoted: true,
			value: { value: rest.slice(1, close), start: start + at + 1, end: start + at + close },
		};
	const comment = rest.search(/(?:^|[ \t])#/);
	const value = (comment < 0 ? rest : rest.slice(0, comment)).trimEnd();
	return { ...base, key, value: value ? { value, start: start + at, end: start + at + value.length } : undefined };
}

/**
 * A text's lines for block scalars, read once per text (the last text is kept): where each starts, its indent (-1 for
 * a line of blanks; a `#` line is content inside a block), and the next line no deeper than it, found with a stack.
 */
const blocks = lastText((text) => {
	const lines = yamlLines(text);
	const indent = new Int32Array(lines.length);
	lines.forEach((l, k) => (indent[k] = text.slice(l.start, l.end).trim() ? l.indent : -1));
	const next = new Int32Array(lines.length);
	const deeper: number[] = [];
	for (let k = lines.length - 1; k >= 0; k--) {
		// (A line of blanks ends no block: it neither answers nor clears what's below it.)
		if (indent[k] < 0) continue;
		while (deeper.length && indent[deeper.at(-1)!] > indent[k]) deeper.pop();
		next[k] = deeper.at(-1) ?? lines.length;
		deeper.push(k);
	}
	return { lines, starts: lines.map((l) => l.start), indent, next };
});

/**
 * The content of the block scalar whose indicator ends the line starting at `keyLine` (`password: |`): the lines below
 * it indented further, each without the blanks around it.
 */
export function blockLines(text: string, keyLine: number): Span[] {
	const { lines, starts, indent, next } = blocks(text);
	const k = lowerBound(starts, keyLine);
	const out: Span[] = [];
	for (let j = k + 1; j < next[k]; j++) {
		if (indent[j] < 0) continue;
		const line = text.slice(lines[j].start, lines[j].end);
		const value = line.trim();
		const at = lines[j].start + line.indexOf(value);
		out.push({ value, start: at, end: at + value.length });
	}
	return out;
}

/** The content of a block scalar (see blockLines) as one span, from its first line's text to its last's; undefined if empty. */
export function blockExtent(text: string, keyLine: number): Span | undefined {
	const { lines, starts, indent, next } = blocks(text);
	const k = lowerBound(starts, keyLine);
	let first = k + 1;
	while (first < next[k] && indent[first] < 0) first++;
	let last = next[k] - 1;
	while (last > first && indent[last] < 0) last--;
	if (first >= next[k]) return undefined;
	const head = text.slice(lines[first].start, lines[first].end);
	const start = lines[first].start + head.length - head.trimStart().length;
	const tail = text.slice(lines[last].start, lines[last].end);
	const end = lines[last].start + tail.trimEnd().length;
	return { value: text.slice(start, end), start, end };
}

/** Where the content of the line that starts at `start` ends: before its line break and a `\r`, however long the line. */
function contentEnd(text: string, start: number): number {
	const end = lineEndAt(text, start, Infinity);
	return text[end - 1] === "\r" ? end - 1 : end;
}

/**
 * The value of `key` in the mapping line `i`'s key belongs to: the lines whose key starts in the same column, from the
 * line one indented less (the parent), a list item starting there (the next resource of a `kind: List`), a key the
 * mapping already has (the next resource, printed after another with no separator), a document separator, or a line
 * that is no mapping's entry at or left of the column (a shell's prompt between two commands' outputs) to the next such
 * line. Read once per text: each line's mapping, and each mapping's keys.
 */
export function siblingValue(lines: YamlLine[], i: number, key: string): string | undefined {
	const { mapping, keys } = mappingsOf(lines);
	return mapping[i] < 0 ? undefined : keys[mapping[i]].get(key);
}

const MAPPINGS = new WeakMap<YamlLine[], { mapping: Int32Array; keys: Map<string, string | undefined>[] }>();

/** Each line's mapping (-1 for none), and each mapping's keys and their values. */
function mappingsOf(lines: YamlLine[]) {
	const known = MAPPINGS.get(lines);
	if (known) return known;
	const mapping = new Int32Array(lines.length).fill(-1);
	const keys: Map<string, string | undefined>[] = [];
	// The mappings open at each column, outermost first.
	const open: { col: number; id: number }[] = [];
	lines.forEach((l, k) => {
		if (l.blank) return;
		// (A line that is no entry ends the mappings at or right of its column: a document separator, a shell's prompt
		// (`$ kubectl get secret …`), a list's item with no key (`- foo`).)
		if (l.key === undefined) {
			while (open.length && open.at(-1)!.col >= l.indent) open.pop();
			return;
		}
		while (open.length && open.at(-1)!.col > l.indent) open.pop();
		// (A list item starts a mapping of its own, the next resource of a `kind: List`; so does a key the mapping has
		// already, the next resource printed with nothing between: `kubectl get configmap -o yaml; kubectl get secret …`.)
		const top = open.at(-1);
		if (top?.col === l.indent && (l.item || keys[top.id].has(l.key))) open.pop();
		if (open.at(-1)?.col !== l.indent) {
			open.push({ col: l.indent, id: keys.length });
			keys.push(new Map());
		}
		const id = open.at(-1)!.id;
		mapping[k] = id;
		keys[id].set(l.key, l.value?.value);
	});
	const out = { mapping, keys };
	MAPPINGS.set(lines, out);
	return out;
}
