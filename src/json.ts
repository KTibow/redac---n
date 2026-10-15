/**
 * JSON inside a text: string literals decoded and mapped back (tool calls, serialized requests, logs of JSON), whole
 * documents parsed with where their values are (API responses, `kubectl … -o json`), and the object around a position
 * (a JSON Web Key's members).
 */

/**
 * The keys of agents' tool inputs, one vocabulary for the readers of a serialized tool call (here) and of a parsed one
 * (transcript.ts): the shell command a tool runs, the path it reads or writes, and the text it writes there.
 */
export const TOOL_COMMAND_KEYS = ["command", "cmd", "script", "shell_command", "run"];
export const TOOL_PATH_KEYS = ["file_path", "path", "filePath", "filename", "file", "target_file", "notebook_path"];
export const TOOL_CONTENT_KEYS = [
	"content",
	"contents",
	"file_text",
	"new_string",
	"new_str",
	"old_string",
	"old_str",
	"old_text",
	"new_text",
	"search",
	"replace",
	"insert_text",
	"new_source",
	"text",
	"code",
	"edits",
];

/**
 * A key that names a command line by its last word, in any case and joining (`CommandLine`, Windsurf's run_command
 * input; `commandLine`, `bash_command`, `COMMAND_LINE`, `shellCmd`), or one of the tool keys.
 */
const COMMAND_KEY = String.raw`(?:(?:[A-Za-z\d]*[a-z\d](?=[A-Z])|[\w-]*[_-])?(?:command|Command|COMMAND|cmd|Cmd|CMD)(?:[_-]?(?:line|Line|LINE))?|${TOOL_COMMAND_KEYS.join("|")})`;
/** Whether a tool input's key names the command line it runs: TOOL_COMMAND_KEYS, or a key COMMAND_KEY reads as one. */
export const isCommandKey = (key: string): boolean => new RegExp(String.raw`^${COMMAND_KEY}$`).test(key);
/** The keys tools take text under: an editor's `new_string`, a writer's `content`, a shell's `command`, a tool's `input`. */
const TOOL_TEXT_KEY = String.raw`(?:${[...TOOL_CONTENT_KEYS, COMMAND_KEY, "input"].join("|")})`;
const TOOL_TEXT_ARGUMENT = new RegExp(String.raw`"${TOOL_TEXT_KEY}"[ \t]*:[ \t]*"`);
/** A literal's opening quote right after a tool's text key (`"new_string": "`, escaped any number of times). */
const AFTER_TOOL_TEXT_KEY = new RegExp(String.raw`(?<![\w$-])${TOOL_TEXT_KEY}\\*"[ \t]*:[ \t]*$`);
/** A literal's opening quote right after a shell command's key (`"command": "`, `"cmd": "`): a command line, read as one. */
const AFTER_COMMAND_KEY = new RegExp(String.raw`(?<![\w$-])${COMMAND_KEY}\\*"[ \t]*:[ \t]*$`);

/**
 * Whether a text may hold JSON string literals worth decoding: escapes a document's literals carry (a line break,
 * a tab, a quote, a slash, a Unicode escape), or a tool's text argument, decoded even without escapes (a one-line
 * Edit's `"new_string":"  password: a b c"`). The same escapes jsonStringLiterals decodes.
 */
export function mayHoldJsonText(text: string): boolean {
	return /\\[nrtbf"/u\\]/.test(text) || TOOL_TEXT_ARGUMENT.test(text);
}

/** The longest string literal decoded: 4 MB, past any tool result an agent reads whole. */
const MAX_LITERAL = 4_000_000;

/** JSON's one-character escapes, by the character after the backslash. */
const JSON_ESCAPES: Record<string, string | undefined> = {
	n: "\n",
	t: "\t",
	r: "\r",
	'"': '"',
	"\\": "\\",
	"/": "/",
	b: "\b",
	f: "\f",
};

/**
 * The JSON escape whose backslash is at `at`: what it decodes to and how many characters it takes; undefined for one
 * JSON doesn't have (`\x41`, `\'`), which a lenient reader keeps as written and a strict one rejects.
 */
function jsonEscape(text: string, at: number): [decoded: string, length: number] | undefined {
	const simple = JSON_ESCAPES[text[at + 1]];
	if (simple !== undefined) return [simple, 2];
	if (text[at + 1] === "u" && /^[0-9a-fA-F]{4}$/.test(text.slice(at + 2, at + 6)))
		return [String.fromCharCode(parseInt(text.slice(at + 2, at + 6), 16)), 6];
	return undefined;
}

/**
 * Each JSON string literal of a text that closes on its line: its content decoded, a map from decoded positions to
 * positions in the text (one per decoded character, plus one for the end), its escapes, and its opening quote. With
 * `quote` `'`, a Python repr's literals, whose escapes are JSON's and `\'`, `\xHH`.
 */
function* stringLiterals(
	text: string,
	quote = '"',
): Generator<{ decoded: string; map: number[]; escapes: number; open: number }> {
	const escape = quote === "'" ? pythonEscape : jsonEscape;
	for (let i = text.indexOf(quote); i >= 0; i = text.indexOf(quote, i + 1)) {
		let j = i + 1;
		let decoded = "";
		const map: number[] = [];
		let escapes = 0;
		let ok = false;
		while (j < text.length) {
			const c = text[j];
			if (c === quote) {
				ok = true;
				break;
			}
			// (A literal ends at a raw line break, which JSON doesn't allow in one, or past MAX_LITERAL.)
			if (c === "\n" || j - i > MAX_LITERAL) break;
			if (c === "\\") {
				const decodedEscape = escape(text, j);
				if (decodedEscape) {
					map.push(j);
					decoded += decodedEscape[0];
					j += decodedEscape[1];
					escapes++;
					continue;
				}
				const n = text[j + 1];
				// An escape JSON doesn't have (`\x41`, `\'`, `\0`: a source file's string) stays as written, and the
				// literal goes on: its closing quote is still the one that closes it.
				if (n === undefined || n === "\n") break;
				map.push(j, j + 1);
				decoded += c + n;
				j += 2;
				continue;
			}
			map.push(j);
			decoded += c;
			j++;
		}
		// A literal that doesn't close resumes after where it stopped: the quotes inside it were escaped.
		if (!ok) {
			i = j;
			continue;
		}
		map.push(j);
		yield { decoded, map, escapes, open: i };
		i = j;
	}
}

/** A Python string's escape at `at`: JSON's, and `\'` and `\xHH`, as `repr()` writes them. */
function pythonEscape(text: string, at: number): [decoded: string, length: number] | undefined {
	if (text[at + 1] === "'") return ["'", 2];
	if (text[at + 1] === "x" && /^[0-9a-fA-F]{2}$/.test(text.slice(at + 2, at + 4)))
		return [String.fromCharCode(parseInt(text.slice(at + 2, at + 4), 16)), 4];
	return jsonEscape(text, at);
}

/** Whether a decoded literal is a document of its own: several lines, or a tab's columns. */
function isOutputText(decoded: string): boolean {
	return /\n.*\S/.test(decoded) || decoded.includes("\t");
}

/**
 * The single-quoted literals of a Python repr (`{'stdout': 'PGPASSWORD=…\n…', 'returncode': 0}`, a subprocess
 * result printed whole) that are documents of their own, as jsonStringLiterals reads them: decoded and mapped as
 * those are.
 */
export function* pythonReprLiterals(text: string): Generator<{ decoded: string; map: number[] }> {
	if (!/['\]][ \t]*:[ \t]*'|\('|, '/.test(text) || !/\\[nt]/.test(text)) return;
	for (const { decoded, map, escapes } of stringLiterals(text, "'"))
		if (escapes > 0 && isOutputText(decoded)) yield { decoded, map };
}

/**
 * JSON string literals worth scanning as the text they encode, decoded, each with a map from decoded positions to
 * positions in the text (one entry per decoded character, plus one for the end): documents (several lines, a tab's
 * columns, quoted text inside), and a single config line under a tool's text key or a command line under a shell's,
 * escapes or not.
 */
export function jsonStringLiterals(text: string): { decoded: string; map: number[] }[] {
	const out: { decoded: string; map: number[] }[] = [];
	for (const { decoded, map, escapes, open } of stringLiterals(text)) {
		// Only literals that are documents themselves: several lines, a tab's columns, or quoted text inside. A code string
		// ending in one `\n` (a line of a C or Python array) is judged in place, with its neighbours. (Terminal output's
		// colour codes, `\u001b[32m`, normalize.ts reads where they are written.)
		// Also a single config line quoted on its own (an Edit tool's `old_string`): `      private_key_passphrase: a b c`.
		// (Only under a tool's input key: an i18n file's `"pwd_hint": "Password: 8-64 characters"` is text.)
		const configLine =
			decoded.length >= 12 &&
			/^[ \t]*[\w.-]{1,80}[ \t]*[:=][ \t]*\S[^\n]*\s/.test(decoded) &&
			/pass|secret|token|key|cred|auth|pwd/i.test(decoded) &&
			AFTER_TOOL_TEXT_KEY.test(text.slice(Math.max(0, open - 40), open));
		// (And a command line under a shell's key, `{"command": "mysql -u root -pV shop"}`: read as the command it is, with
		// or without flags, `{"command": "argocd-k8s-auth"}`.)
		const commandLine = decoded.length >= 8 && AFTER_COMMAND_KEY.test(text.slice(Math.max(0, open - 40), open));
		if (configLine || commandLine) out.push({ decoded, map });
		else if (
			escapes > 0 &&
			decoded.length >= 20 &&
			(isOutputText(decoded) ||
				decoded.includes('"') ||
				// (A character escaped as a code or a doubled backslash, Go's `\u0026` for `&`, Python's `\u00e9`, a path's
				// `\\`: read raw, `-pQm7v\u0026Tx2…` or `postgres://app:Qm7v\u0026Tx2…@db` isn't the value the program saw.
				// Only where JSON's syntax stands around it, as for the slash: a shell's `"s/\\(token=\\).*/\\1…/"` is no JSON.)
				(/\\(?:u[0-9a-fA-F]{4}|\\)/.test(text.slice(map[0], map[map.length - 1])) &&
					isJsonPlaced(text, open, map[map.length - 1])) ||
				// (An escaped slash, PHP's `"https:\/\/…"`, only where JSON's syntax stands around the literal: in a sed
				// script in a shell's string, `"s/^DB_PASSWORD=.*/DB_PASSWORD=a\/b/"`, it escapes the script's delimiter.)
				(decoded.includes("/") &&
					/\\\//.test(text.slice(map[0], map[map.length - 1])) &&
					isJsonPlaced(text, open, map[map.length - 1])))
		)
			out.push({ decoded, map });
	}
	return out;
}

/** The most characters before a literal's quote looked at for what opens it. */
const OPENER_WINDOW = 40;

/** Whether the 40 characters before `at` end in `{`, `[`, `,` or `:` and blanks, or are all blanks. */
function followsJsonOpener(text: string, at: number): boolean {
	const from = Math.max(0, at - OPENER_WINDOW);
	let i = at;
	while (i > from && (text[i - 1] === " " || text[i - 1] === "\t" || text[i - 1] === "\r" || text[i - 1] === "\n")) i--;
	return i === from || "{[,:".includes(text[i - 1]);
}

/** Whether JSON's syntax stands around the literal whose quotes are at `open` and `close`: `{`, `[`, `,` or `:` before; `:`, `,`, `}` or `]` after, or the text's ends. */
function isJsonPlaced(text: string, open: number, close: number): boolean {
	return followsJsonOpener(text, open) && /^[ \t\r\n]*(?:[:,}\]]|$)/.test(text.slice(close + 1, close + 41));
}

/**
 * Where each JSON string literal's content is, between its quotes: what no finding's span should cross. Only the
 * literals JSON's syntax stands around (isJsonPlaced): a `"` inside another language's single-quoted string
 * (`-p'Kx"9…' -e "SELECT 1"`) opens no JSON literal.
 */
export function jsonLiteralSpans(text: string): [start: number, end: number][] {
	const out: [number, number][] = [];
	for (const { map, open } of stringLiterals(text)) {
		const close = map[map.length - 1];
		if (isJsonPlaced(text, open, close)) out.push([open + 1, close]);
	}
	return out;
}

/** A JSON literal as JSON's grammar has it (no leading zeros: `02` in `[02:39]` isn't one), read where it starts. */
const LITERAL = /(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][-+]?\d+)?)(?![\w.])/y;
const KEYWORDS: Record<string, boolean | null> = { true: true, false: false, null: null };

/** A JSON value parsed with where its scalars are in the source: a string's span is its content, quotes excluded. */
export type JsonNode =
	| { kind: "object"; entries: [key: string, value: JsonNode][] }
	| { kind: "array"; items: JsonNode[] }
	| { kind: "string"; value: string; start: number; end: number }
	| { kind: "literal"; value: number | boolean | null; start: number; end: number };

/**
 * The JSON value starting at `at` (after blanks), with each scalar's source span, and where the value ends; undefined
 * if the text there isn't JSON, and then `progress.reached` says how far it was read. Nesting deeper than `maxDepth`
 * counts as not JSON.
 */
export function parseJson(
	text: string,
	at: number,
	maxDepth = 100,
	progress?: { reached: number },
): { node: JsonNode; end: number } | undefined {
	let i = at;
	const blanks = () => {
		while (i < text.length && (text[i] === " " || text[i] === "\t" || text[i] === "\n" || text[i] === "\r")) i++;
	};
	const string = (): JsonNode | undefined => {
		const start = ++i;
		let value = "";
		while (i < text.length && text[i] !== '"') {
			const c = text[i];
			if (c === "\n") return undefined;
			if (c !== "\\") {
				value += c;
				i++;
				continue;
			}
			const escape = jsonEscape(text, i);
			if (!escape) return undefined;
			value += escape[0];
			i += escape[1];
		}
		if (i >= text.length) return undefined;
		return { kind: "string", value, start, end: i++ };
	};
	const value = (depth: number): JsonNode | undefined => {
		if (depth > maxDepth) return undefined;
		blanks();
		const c = text[i];
		if (c === '"') return string();
		if (c === "{" || c === "[") {
			const object = c === "{";
			const entries: [string, JsonNode][] = [];
			const items: JsonNode[] = [];
			i++;
			blanks();
			if (text[i] === (object ? "}" : "]")) {
				i++;
				return object ? { kind: "object", entries } : { kind: "array", items };
			}
			for (;;) {
				let key = "";
				if (object) {
					blanks();
					if (text[i] !== '"') return undefined;
					const k = string();
					if (!k || k.kind !== "string") return undefined;
					key = k.value;
					blanks();
					if (text[i++] !== ":") return undefined;
				}
				const v = value(depth + 1);
				if (!v) return undefined;
				if (object) entries.push([key, v]);
				else items.push(v);
				blanks();
				if (text[i] === ",") {
					i++;
					continue;
				}
				if (text[i] !== (object ? "}" : "]")) return undefined;
				i++;
				return object ? { kind: "object", entries } : { kind: "array", items };
			}
		}
		LITERAL.lastIndex = i;
		const literal = LITERAL.exec(text);
		if (!literal) return undefined;
		i += literal[0].length;
		return {
			kind: "literal",
			value: literal[0] in KEYWORDS ? KEYWORDS[literal[0]] : Number(literal[0]),
			start: i - literal[0].length,
			end: i,
		};
	};
	const node = value(0);
	if (!node && progress) progress.reached = i;
	return node ? { node, end: i } : undefined;
}

/**
 * The JSON documents in a text (API responses, `kubectl … -o json`, `terraform output -json`): values that start a
 * line. A parsed document's nested objects aren't tried again. (What the starts that aren't JSON read is bounded, four
 * times the text, so the scan stays linear: a log's `[INFO] …` lines fail at once, and any number of them is tried.
 * Past the bound, a start inside what a failed one read is skipped, and the ones after it are tried: `[\n` repeated
 * hides no document after it.)
 */
export function* jsonDocuments(text: string): Generator<JsonNode> {
	let budget = 4 * text.length + 4096;
	let resume = 0;
	const progress = { reached: 0 };
	for (const m of text.matchAll(/(?:^|\n)[ \t]*([{[])/dg)) {
		const [start] = m.indices![1]!;
		if (start < resume) continue;
		const doc = parseJson(text, start, 100, progress);
		if (!doc) {
			budget -= progress.reached - start + 1;
			if (budget < 0) resume = Math.max(resume, progress.reached);
			continue;
		}
		resume = doc.end;
		yield doc.node;
	}
}

/** The `{…}` object around [start, end), braces balanced (braces inside its strings too), within `max` characters on each side; "" if none. */
function enclosingObject(text: string, start: number, end: number, max = 2000): string {
	let depth = 0;
	let open = -1;
	for (let i = start - 1; i >= Math.max(0, start - max); i--) {
		if (text[i] === "}") depth++;
		else if (text[i] === "{") {
			if (depth === 0) {
				open = i;
				break;
			}
			depth--;
		}
	}
	if (open < 0) return "";
	depth = 0;
	for (let i = end; i < Math.min(text.length, end + max); i++) {
		if (text[i] === "{") depth++;
		else if (text[i] === "}") {
			if (depth === 0) return text.slice(open, i + 1);
			depth--;
		}
	}
	return "";
}

/** A string literal, an identifier, or a bracket: what an object literal's keys and nesting are read from. */
const OBJECT_TOKEN = /"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[A-Za-z_$][\w$]*|[{[(]|[}\])]/g;

/** Whether `object` (a `{…}` literal, JSON or a JS or Python one) has a member named `key` of its own: not in a child, not in a string. */
function hasOwnKey(object: string, key: string): boolean {
	const colon = /\s*:/y;
	let depth = 0;
	for (const m of object.matchAll(OBJECT_TOKEN)) {
		if (m[0].length === 1 && "{[(".includes(m[0])) depth++;
		else if (m[0].length === 1 && "}])".includes(m[0])) depth--;
		else if (depth === 1 && m[0].replace(/^["']|["']$/g, "") === key) {
			colon.lastIndex = m.index + m[0].length;
			if (colon.test(object)) return true;
		}
	}
	return false;
}

/** Whether [start, end) is a member of a JSON Web Key: its innermost object has a `kty` of its own (JSON, or a JS or Python literal). */
export function inJwk(text: string, start: number, end: number): boolean {
	return hasOwnKey(enclosingObject(text, start, end), "kty");
}
