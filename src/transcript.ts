/**
 * Redacting a whole transcript or request body: any JSON value, typically a list of chat messages in
 * the Anthropic or OpenAI format. Two passes:
 *
 * 1. Every string is scanned, with the command or path of the tool call that produced it as a hint
 *    (a `tool_result` is matched to its `tool_use` by id), and every confident finding is learned as a
 *    known value.
 * 2. Every string is redacted, so a secret found once (`API_KEY=…` in a `cat .env`) is also hidden where
 *    it appears with no context at all (the model echoing it, a later `curl` using it).
 *
 * The value is redacted as it will be sent: what `JSON.stringify` makes of it (jsonShape). Object keys are scanned like
 * strings, and a key that holds a secret is renamed to its redacted text. The envelope's IDs (unless one holds a vendor
 * token), roles, model names and signatures (not a tool's payload's: isEnvelope), and binary base64 media are left
 * alone; base64 of text (a `text/plain` document, an SVG) is decoded and redacted as text. Values under a
 * credential-named key (`{"api_key": "…"}`) are judged by that name. With `learn: false`, what pass 1 finds is hidden
 * across this value only, not remembered for later calls.
 */
import { isSecretFile } from "./commands.ts";
import { base64Binary } from "./base64.ts";
import { findFormats } from "./formats.ts";
import { type JsonNode, parseJson, TOOL_COMMAND_KEYS, TOOL_CONTENT_KEYS, TOOL_PATH_KEYS } from "./json.ts";
import { shellLine } from "./shell.ts";
import type { Redactor } from "./index.ts";
import { isLearnable, isNeverSecretShape, merge, secretValue } from "./spans.ts";
import { occurrences } from "./repeats.ts";
import { isCredentialName } from "./names.ts";
import { isNamedSecret } from "./named.ts";
import type { Finding, Guessing, Hint } from "./types.ts";

/** Keys whose values are IDs the provider minted (`toolu_01Ab…`, `chatcmpl-B9…`): one token, no spaces. */
const ID_KEYS = new Set(["id", "tool_use_id", "tool_call_id", "call_id"]);
/** Keys whose values are opaque blobs the provider signed or encrypted, which no one reads. */
const OPAQUE_KEYS = new Set(["signature", "thoughtSignature", "thought_signature", "encrypted_content"]);
/** Keys whose values are a short enum or a model name (`assistant`, `end_turn`, `image/png`, `claude-sonnet-4-5-20250929`). */
const ENUM_KEYS = new Set([
	"type",
	"role",
	"model",
	"stop_reason",
	"finish_reason",
	"media_type",
	"object",
	"status",
	"mime_type",
	"detail",
	"format",
]);
/** Other keys of an envelope whose scalars are bookkeeping (`created`, `index`). */
const COUNTER_KEYS = new Set(["created", "index", "logprobs"]);
/** An ID's shape: no spaces, no quotes or other punctuation a sentence or a `name=value` pair has. */
const ID_VALUE = /^[\w.:@/+-]{1,256}={0,2}$/;
/** An enum's shape: words of at most 20 characters, joined by `-`, `_`, `.`, `:`, `/`, `@` or a space (a token pasted in is one long word). */
const ENUM_VALUE = /^[A-Za-z][A-Za-z0-9]{0,19}(?:[-_.:/@ ][A-Za-z0-9]{1,20}){0,8}$/;
/** Base64 or base64url, padded or not. */
const BASE64_VALUE = /^[A-Za-z0-9+/_-]*={0,2}$/;

/**
 * Whether the scalar `x` under `key` on an envelope is structure that no secret sits in: the key says what it is and the
 * value has that shape (a `status` holding `ghp_…`, or an `id` holding `password=…`, is scanned). An ID is also scanned for
 * vendor token formats (`toolu_ghp_…`), but never by the random-token layer, which would break the pairing of a tool call
 * and its result on a provider's ID.
 */
function isStructure(key: string, x: unknown): boolean {
	if (x === null || x === undefined || typeof x === "number")
		return ID_KEYS.has(key) || ENUM_KEYS.has(key) || OPAQUE_KEYS.has(key) || COUNTER_KEYS.has(key);
	if (typeof x !== "string") return false;
	return (
		(ID_KEYS.has(key) && ID_VALUE.test(x) && findFormats(x).length === 0) ||
		(OPAQUE_KEYS.has(key) && BASE64_VALUE.test(x)) ||
		(ENUM_KEYS.has(key) && ENUM_VALUE.test(x)) ||
		(COUNTER_KEYS.has(key) && x.length <= 20)
	);
}
/** The `type`s of messages and content blocks, Anthropic's, OpenAI's (Chat and Responses) and Claude Code's session lines. */
const BLOCK_TYPES = new Set([
	"message",
	"text",
	"tool_use",
	"tool_result",
	"server_tool_use",
	"web_search_tool_result",
	"mcp_tool_use",
	"mcp_tool_result",
	"thinking",
	"redacted_thinking",
	"image",
	"document",
	"image_url",
	"input_image",
	"input_text",
	"output_text",
	"refusal",
	"reasoning",
	"function",
	"function_call",
	"function_call_output",
	"local_shell_call",
	"local_shell_call_output",
	"computer_call",
	"computer_call_output",
	"file_search_call",
	"web_search_call",
	"user",
	"assistant",
	"system",
	"summary",
	"result",
]);

/**
 * Whether an object is part of the envelope a transcript is carried in, a message, a content block or an API response,
 * whose `id`, `type`, `status` or `detail` are structure; not a payload (a tool's structured result, an error body), where
 * the same keys hold content (`"detail": "Invalid API key: sk-…"`).
 */
function isEnvelope(o: Record<string, unknown>): boolean {
	return (
		typeof o.role === "string" ||
		(typeof o.type === "string" && BLOCK_TYPES.has(o.type)) ||
		typeof o.tool_call_id === "string" ||
		typeof o.tool_use_id === "string" ||
		(typeof o.object === "string" && typeof o.model === "string")
	);
}

/** Keys of tool inputs that hold what a tool writes to the file at its path (`Write`, `create_file`, `str_replace`). */
const CONTENT_KEYS = new Set(TOOL_CONTENT_KEYS);
/** Files a patch adds or changes: `*** Add File: x` (apply_patch), `+++ b/x` (unified diff). */
const PATCH_FILE = /^(?:\*\*\* (?:Add|Update) File: |\+\+\+ (?:b\/)?)(\S+)/gm;

export interface TranscriptFinding extends Finding {
	/** JSON path of the string the finding is in. */
	path: (string | number)[];
	/** The text the finding covered, the secret itself: strip it before logging. */
	value: string;
	/** Set when the finding is in the object key that `path` ends with, not in its value. */
	inKey?: boolean;
}

export interface TranscriptOptions {
	/** How hard to guess at unnamed random-looking tokens, for this call (RedactOptions.guessing). */
	guessing?: Guessing;
	/**
	 * true (default): confident findings are learned as known values, hidden throughout this value and in what this
	 * Redactor redacts later. false: hidden throughout this value only.
	 */
	learn?: boolean;
	/**
	 * Anthropic `thinking` blocks carry a signature over their text, so a redacted one no longer verifies
	 * and the API rejects a request whose turn it continues. "redact" (default) redacts them like any text; "keep" leaves them alone
	 * (for a provider you trust with them, or strip them yourself before sending).
	 */
	thinking?: "redact" | "keep";
}

/** A step on the way to a node: its key, and the step before it. (Paths are built only when a finding needs one.) */
interface Step {
	parent: Step | undefined;
	key: string | number;
}

function pathOf(step: Step | undefined): (string | number)[] {
	const keys: (string | number)[] = [];
	for (let s = step; s; s = s.parent) keys.push(s.key);
	return keys.reverse();
}

/** What a walk knows about the value it is at: how it was reached, and what the walk carries down to it. */
interface At<S> {
	readonly value: unknown;
	/** The way here (undefined at the root). */
	readonly step: Step | undefined;
	readonly scope: S;
	/** The object key the value sits under, if any: an array's items keep the key the array sits under. */
	readonly key: string | undefined;
	/** The object or array the value is in. */
	readonly parent: object | undefined;
	/** Set on an object already walked at an earlier path (shared, or a cycle): its members are not walked again. */
	repeat: boolean;
}

/**
 * What a visitor answers: nothing, to walk on into the value's members with the scope it was visited with; "skip", to
 * leave this value's members out; "stop", to end the walk; or a function from each member's key (an index, for an array) and
 * value to the scope that member is visited with (undefined leaves the member out). Without one, members keep the scope.
 */
type Next<S> = void | "skip" | "stop" | ((key: string | number, member: unknown) => S | undefined);

/**
 * Walks a JSON value without recursion (any depth), calling `visit` on every value in document order, each object's
 * members once: a shared object, or a cycle, is visited at every path but walked into at its first. The members are read
 * after `visit` returns, so it may rewrite its object. `scope` is what the walk carries down, starting as `root`'s.
 */
function walk<S>(root: unknown, scope: S, visit: (at: At<S>) => Next<S>): void {
	const walked = new WeakSet<object>();
	const stack: At<S>[] = [{ value: root, step: undefined, scope, key: undefined, parent: undefined, repeat: false }];
	while (stack.length) {
		const at = stack.pop()!;
		const v = at.value;
		const isObject = !!v && typeof v === "object";
		at.repeat = isObject && walked.has(v);
		const next = visit(at);
		if (next === "stop") return;
		if (!isObject || at.repeat) continue;
		walked.add(v);
		if (next === "skip") continue;
		const isArray = Array.isArray(v);
		const entries = Object.entries(v);
		for (let i = entries.length - 1; i >= 0; i--) {
			const [name, member] = entries[i];
			const k = isArray && String(+name) === name ? +name : name;
			const into = typeof next === "function" ? next(k, member) : at.scope;
			if (into !== undefined)
				stack.push({
					value: member,
					step: { parent: at.step, key: k },
					scope: into,
					key: isArray ? at.key : name,
					parent: v,
					repeat: false,
				});
		}
	}
}

interface Leaf {
	/** JSON path of the string. */
	readonly path: (string | number)[];
	text: string;
	hint: Hint;
	/** The object key the string sits under, if any, and the object itself. */
	key?: string;
	parent?: object;
	/** Set for an object key: `text` is the key, and `path` ends with it. */
	isKey?: boolean;
	/** For text decoded from base64: the encoding of its redacted form back. */
	encode?: (redacted: string) => string;
}

/** Hints for tool results, from the tool calls that produced them, by tool call id. */
function toolHints(value: unknown): Map<string, Hint> {
	const hints = new Map<string, Hint>();
	walk(value, null, ({ value: v }) => {
		if (!v || typeof v !== "object" || Array.isArray(v)) return;
		const o = v as Record<string, unknown>;
		// Anthropic: {type: "tool_use", id, input: {...}}. OpenAI: {id, type: "function", function: {arguments: "<json>"}}.
		// OpenAI Responses: {type: "function_call", call_id, arguments}; {type: "local_shell_call", call_id, action: {command: [...]}}.
		let input: unknown = o.input ?? o.action ?? o.arguments;
		const fn =
			o.function && typeof o.function === "object" ? (o.function as Record<string, unknown>).arguments : undefined;
		if (fn !== undefined && fn !== null) input = fn;
		if (typeof input === "string") {
			try {
				input = JSON.parse(input);
			} catch {}
		}
		const id = (typeof o.call_id === "string" ? o.call_id : undefined) ?? (typeof o.id === "string" ? o.id : undefined);
		if (!id || !input || typeof input !== "object") return;
		const i = input as Record<string, unknown>;
		const asText = (x: unknown) =>
			typeof x === "string" ? x : Array.isArray(x) && x.every((y) => typeof y === "string") ? shellLine(x) : undefined;
		const command = TOOL_COMMAND_KEYS.map((k) => asText(i[k])).find((x) => x !== undefined);
		// (A call that writes a file, its content in its input, returns a status line, not the file: no path hint.)
		const writes = Object.keys(i).some((k) => CONTENT_KEYS.has(k));
		const path = writes
			? undefined
			: (TOOL_PATH_KEYS.map((k) => i[k]).find((x) => typeof x === "string") as string | undefined);
		if (command || path) hints.set(id, { command, path });
	});
	return hints;
}

/** A base64 data URI of binary media. Other strings that start with `data:` (SSE lines, text data URIs) are scanned. */
const MEDIA_URI =
	/^data:(?:image|audio|video|font)\/[\w.+-]+(?:;[\w.+-]+=[^;,]*)*;base64,[\sA-Za-z0-9+/=_-]*$|^data:application\/(?:pdf|octet-stream|zip)(?:;[\w.+-]+=[^;,]*)*;base64,[\sA-Za-z0-9+/=_-]*$/;

/** Media types that are text: `text/*`, JSON, XML (SVG included), YAML, TOML and other languages, with a `+json`, `+xml` or `+yaml` suffix. */
const TEXT_MEDIA_TYPE =
	/^(?:text\/[\w.+-]+|application\/(?:json|xml|ya?ml|x-ya?ml|toml|javascript|x-sh|sql|x-ndjson|x-www-form-urlencoded)|[\w.-]+\/[\w.-]+\+(?:json|xml|ya?ml))$/i;
/** A base64 data URI: its media type (group 1), its parameters and `;base64,` (group 2), its payload (group 3). */
const BASE64_URI = /^data:([\w.+-]+\/[\w.+-]+)((?:;[\w.+-]+=[^;,]*)*;base64,)([\sA-Za-z0-9+/=_-]*)$/;
/** How many bytes are turned into characters at a time when encoding (a spread of more arguments overflows the stack). */
const ENCODE_CHUNK = 8192;

/** The text base64 `payload` encodes, or undefined if it isn't base64 of UTF-8 text. */
function decodeBase64Text(payload: string): string | undefined {
	const binary = base64Binary(payload.replace(/\s/g, ""));
	if (binary === undefined) return undefined;
	try {
		return new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(binary, (c) => c.charCodeAt(0)));
	} catch {
		return undefined;
	}
}

/** `text` as base64, in the alphabet and padding `like` (the payload it replaces) was written in. */
function encodeBase64Text(text: string, like: string): string {
	const bytes = new TextEncoder().encode(text);
	let binary = "";
	for (let i = 0; i < bytes.length; i += ENCODE_CHUNK)
		binary += String.fromCharCode(...bytes.subarray(i, i + ENCODE_CHUNK));
	let b64 = btoa(binary);
	if (/[-_]/.test(like)) b64 = b64.replace(/\+/g, "-").replace(/\//g, "_");
	return /=\s*$/.test(like) ? b64 : b64.replace(/=+$/, "");
}

/**
 * The text a base64 string holds, when its media type says text: `data` under a `media_type` of its object
 * (`{type: "base64", media_type: "text/plain", data}`), or the payload of a text data URI (`data:image/svg+xml;base64,…`).
 * `encode` writes the redacted text back the way it was written. Undefined for binary media.
 */
function base64Text(
	o: Record<string, unknown>,
	key: string,
	x: string,
): { text: string; encode: (redacted: string) => string } | undefined {
	const uri = BASE64_URI.exec(x);
	const textual = uri
		? TEXT_MEDIA_TYPE.test(uri[1])
		: key === "data" && typeof o.media_type === "string" && TEXT_MEDIA_TYPE.test(o.media_type.split(";")[0].trim());
	const payload = uri ? uri[3] : x;
	const text = textual ? decodeBase64Text(payload) : undefined;
	return text === undefined
		? undefined
		: { text, encode: (redacted) => (uri ? `data:${uri[1]}${uri[2]}` : "") + encodeBase64Text(redacted, payload) };
}

/** A document block's file name, from its title or file name: the path hint its content is judged with. */
function documentName(o: Record<string, unknown>): string | undefined {
	return [o.title, o.filename, o.file_name].find(
		(x): x is string => typeof x === "string" && x.length > 0 && x.length <= 4096 && !x.includes("\n"),
	);
}

/** Keys whose values are a tool's own input: everything inside is scanned, whatever its key. */
const TOOL_INPUT_KEYS = new Set(["input", "arguments", "parameters", "args", "action"]);

/** What `collect` carries down to a node: the hint its text is judged with, whether it is inside a tool's input, and, for base64 of text, the text it decodes to. */
interface Scope {
	hint: Hint;
	free: boolean;
	decoded?: { text: string; encode: (redacted: string) => string };
}

/**
 * The strings of a value worth scanning, each with the hint its text is judged with: a tool result inherits its
 * call's; a tool input that writes a file has its content judged as that file. Envelope fields (ids, roles,
 * signatures), base64 media and, with `keepThinking`, thinking blocks are left out.
 */
function collect(value: unknown, hints: Map<string, Hint>, keepThinking: boolean): Leaf[] {
	const leaves: Leaf[] = [];
	walk<Scope>(value, { hint: {}, free: false }, ({ value: v, step, scope, key, parent, repeat }) => {
		// (A number under a credential's name is one too: `"db_password": 98127734`, `"pin": 4821`. Only a safe integer
		// prints as its digits; a larger one, JSON.parse has already rounded.)
		if (typeof v === "number" && key && Number.isSafeInteger(v) && isCredentialName(key)) {
			leaves.push({
				get path() {
					return pathOf(step);
				},
				text: String(v),
				hint: scope.hint,
				key,
				parent,
			});
			return;
		}
		if (typeof v === "string") {
			const { decoded } = scope;
			// (Under four characters is no secret anywhere: looksSecret's floor, so no name makes one.)
			if ((decoded ? decoded.text.length : v.length) < 4) return;
			if (decoded) {
				leaves.push({
					get path() {
						return pathOf(step);
					},
					text: decoded.text,
					hint: scope.hint,
					encode: decoded.encode,
				});
				return;
			}
			let hint = scope.hint;
			// A patch inside a tool's input that writes a secret file is read as that file.
			if (scope.free && !hint.path && /^(?:\*\*\* (?:Add|Update) File: |\+\+\+ )/m.test(v)) {
				const file = [...v.matchAll(PATCH_FILE)].map((m) => m[1]).find((f) => isSecretFile(f));
				if (file) hint = { path: file };
			}
			leaves.push({
				get path() {
					return pathOf(step);
				},
				text: v,
				hint,
				key,
				parent,
			});
			return;
		}
		if (!v || typeof v !== "object" || repeat || Array.isArray(v)) return;
		const o = v as Record<string, unknown>;
		if (keepThinking && (o.type === "thinking" || o.type === "redacted_thinking")) return "skip";
		// A tool result inherits the hint of its call; OpenAI tool messages carry `tool_call_id`.
		const id = (o.tool_use_id ??
			o.tool_call_id ??
			(o.type === "function_call_output" || o.type === "local_shell_call_output" ? o.call_id : undefined)) as
			string | undefined;
		const hint = typeof id === "string" && hints.has(id) ? hints.get(id)! : scope.hint;
		// Base64 media: `{type: "base64", media_type, data}`, `image_url: {url: "data:…"}`.
		const media =
			o.type === "base64" ||
			o.type === "image" ||
			o.type === "image_url" ||
			o.type === "input_image" ||
			o.type === "document";
		// A tool input that writes a file: its content is judged as that file (`.env` content as a secret file).
		const writes = TOOL_PATH_KEYS.map((k) => o[k]).find((x) => typeof x === "string") as string | undefined;
		const envelope = !scope.free && isEnvelope(o);
		const name = o.type === "document" && !hint.path ? documentName(o) : undefined;
		return (field, x) => {
			const k = field as string;
			// A key is scanned like a string (under four characters is no secret), whatever its value is.
			if (k.length >= 4)
				leaves.push({
					get path() {
						return pathOf({ parent: step, key: k });
					},
					text: k,
					hint: {},
					isKey: true,
				});
			// Envelope fields (ids, roles, signatures) are skipped; inside a tool's input, or a payload, every string is data.
			if (envelope && isStructure(k, x)) return undefined;
			// Base64 of text is decoded and scanned as text; other base64 payloads are skipped; URLs are scanned (a presigned URL
			// carries a credential) unless they're data: URIs.
			const decoded = typeof x === "string" && (media || BASE64_URI.test(x)) ? base64Text(o, k, x) : undefined;
			if (decoded) return { hint, free: scope.free, decoded };
			if (
				(media && k === "data" && typeof x === "string" && BASE64_VALUE.test(x.replace(/\s/g, ""))) ||
				(typeof x === "string" && MEDIA_URI.test(x))
			)
				return undefined;
			// (`edits` of a MultiEdit call: each edit's strings are judged as the file too. A Claude Code record's
			// `toolUseResult` is a second copy of the result in its `message`, and has that result's call's hint.)
			const childHint =
				name && k === "source"
					? { ...hint, path: name }
					: writes && CONTENT_KEYS.has(k)
						? { path: writes }
						: k === "toolUseResult"
							? (recordHint(o, hints) ?? hint)
							: hint;
			return { hint: childHint, free: scope.free || TOOL_INPUT_KEYS.has(k) };
		};
	});
	return leaves;
}

/** The hint of the tool call whose result a Claude Code record's `message` holds (`content[].tool_use_id`). */
function recordHint(record: Record<string, unknown>, hints: Map<string, Hint>): Hint | undefined {
	const content = (record.message as { content?: unknown } | undefined)?.content;
	if (!Array.isArray(content)) return undefined;
	for (const block of content) {
		const id = (block as { tool_use_id?: unknown } | null)?.tool_use_id;
		if (typeof id === "string" && hints.has(id)) return hints.get(id);
	}
	return undefined;
}

/** A deep copy of a JSON value, without recursion, so any depth works (`structuredClone` overflows the stack at a few thousand levels). */
function cloneJson<T>(value: T): T {
	if (!value || typeof value !== "object") return value;
	// Each object copied once: shared references stay shared, and a cycle is copied as a cycle. The scope is the copy of the
	// object a value is in.
	const copies = new WeakMap<object, object>();
	let root: object | undefined;
	walk<object>(value, {}, ({ value: v, step, scope }) => {
		let copy: unknown = v;
		if (v && typeof v === "object") {
			copy = copies.get(v);
			if (!copy) copies.set(v, (copy = Array.isArray(v) ? [] : {}));
		}
		// (A `__proto__` key from JSON.parse stays a key.)
		if (step)
			Object.defineProperty(scope, step.key, { value: copy, writable: true, enumerable: true, configurable: true });
		else root = copy as object;
		return () => copy as object;
	});
	return root as T;
}

/** Sets a string inside a value already cloned for this purpose. */
function setAt(root: unknown, path: (string | number)[], value: unknown): unknown {
	if (!path.length) return value;
	let node: any = root;
	for (let i = 0; i < path.length - 1; i++) node = node[path[i]];
	node[path[path.length - 1]] = value;
	return root;
}

/** Whether a leaf's whole text is a secret by the key it sits under (`{"api_key": "…"}`), as the decision stage judges it there. */
function isNamedKeySecret(leaf: Leaf, keep: (f: Finding) => boolean): leaf is Leaf & { key: string } {
	return (
		!!leaf.key &&
		isCredentialName(leaf.key) &&
		isNamedSecret(leaf.key, JSON.stringify(leaf.text), true) &&
		keep({ start: 0, end: leaf.text.length, kind: "secret", rule: "named:key", confidence: 0.95 })
	);
}

/**
 * Whether a value is plain JSON data already, so that JSON.stringify would send exactly its strings, keys and
 * numbers: only strings, finite numbers, booleans, null, arrays and plain objects (no `toJSON`), each object once.
 */
function isPlainJson(root: unknown): boolean {
	let plain = true;
	walk(root, null, ({ value: v, repeat }) => {
		if (
			v === null ||
			typeof v === "string" ||
			typeof v === "boolean" ||
			(typeof v === "number" && Number.isFinite(v)) ||
			repeat
		)
			return;
		if (typeof v === "object") {
			const proto = Object.getPrototypeOf(v);
			if (
				(proto === (Array.isArray(v) ? Array.prototype : Object.prototype) || (proto === null && !Array.isArray(v))) &&
				typeof (v as { toJSON?: unknown }).toJSON !== "function"
			)
				return;
		}
		plain = false;
		return "stop";
	});
	return plain;
}

/**
 * The value as it will be sent: itself if it is plain JSON data, otherwise what JSON.stringify makes of it, parsed
 * (`toJSON` called, a `Map` or a class instance as its enumerable members, a `Date` as its string, `NaN` as null, a
 * function or `undefined` dropped). A BigInt throws, as it does when sent; so does a cycle in such a value. A value
 * with no JSON form (`undefined`, a function) is returned as it is.
 */
function jsonShape(value: unknown): unknown {
	if (isPlainJson(value)) return value;
	const text = JSON.stringify(value);
	return text === undefined ? value : JSON.parse(text);
}

/** `root` with every key in `renames` renamed in place, each object's keys in their order. */
function renameKeys(root: unknown, renames: Map<string, string>) {
	walk(root, null, ({ value: v }) => {
		if (!v || typeof v !== "object" || Array.isArray(v) || !Object.keys(v).some((k) => renames.has(k))) return;
		const entries = Object.entries(v);
		for (const [k] of entries) delete (v as Record<string, unknown>)[k];
		for (const [k, x] of entries) {
			let name = renames.get(k) ?? k;
			// (Two keys hidden to the same text keep both.)
			while (Object.hasOwn(v, name)) name += "'";
			Object.defineProperty(v, name, { value: x, writable: true, enumerable: true, configurable: true });
		}
	});
}

/** A copy of `value` with every secret in every string and key replaced, and the findings by JSON path. */
export function redactValue<T>(
	redactor: Redactor,
	value: T,
	options: TranscriptOptions = {},
): { value: T; findings: TranscriptFinding[] } {
	// Tool arguments sent as a JSON string (OpenAI) are scanned as the object they encode, and encoded
	// back afterwards; one with nothing redacted inside keeps its original string.
	const encoded: { path: (string | number)[]; original: string; node: JsonNode }[] = [];
	const work = decodeArguments(jsonShape(value), encoded);
	value = work as T;
	const hints = toolHints(value);
	const leaves = collect(value, hints, options.thinking === "keep");
	// A leaf is detected and judged where it sits: in its object, serialized, under its key, so every stage sees what it
	// would see in the same JSON as text (a `{name: "DB_PASSWORD", value: …}` pair, a Firebase config's siblings, a
	// JWK's `kty`, `anon_key`, an `…Id`). A leaf with a hint of its own (a tool's output) is its own text.
	const serialized = new WeakMap<object, string | undefined>();
	const inParents = new Map<string, Finding[]>();
	const found = (leaf: Leaf): Finding[] => {
		const alone = redactor.detect(leaf.text, { hint: leaf.hint, guessing: options.guessing });
		const ctx =
			leaf.hint.command === undefined && leaf.hint.path === undefined ? leafContext(leaf, serialized) : undefined;
		if (!ctx) return alone;
		let inParent = inParents.get(ctx.text);
		if (!inParent) inParents.set(ctx.text, (inParent = redactor.detect(ctx.text, { guessing: options.guessing })));
		const end = ctx.at + leaf.text.length;
		const mine = inParent
			.filter((f) => f.start >= ctx.at && f.end <= end)
			.map((f) => ({ ...f, start: f.start - ctx.at, end: f.end - ctx.at }));
		return mine.length ? merge([...alone, ...mine]) : alone;
	};
	const judged = (leaf: Leaf) => {
		const ctx = leafContext(leaf, serialized);
		// (The key names only a finding that is the whole leaf; inside a longer text, the name is the text's own.)
		return (f: Finding) => {
			const name = f.name ?? (f.start === 0 && f.end === leaf.text.length ? leaf.key : undefined);
			const g = name ? { ...f, name } : f;
			return ctx
				? redactor.judge(ctx.text, { ...g, start: f.start + ctx.at, end: f.end + ctx.at })
				: redactor.judge(leaf.text, g);
		};
	};
	// Pass 1: what's confidently secret anywhere: learned as known values, or, with `learn: false`, looked for again in
	// this value's other leaves only.
	// (Learned all at once after the pass: adding values rebuilds the short-value matcher, once per batch.)
	const learned: [string, string][] = [];
	for (const leaf of leaves) {
		const keep = judged(leaf);
		if (isNamedKeySecret(leaf, keep) && !isNeverSecretShape(leaf.text)) learned.push([leaf.text, leaf.key]);
		for (const f of found(leaf).filter(keep)) {
			const secret = secretValue(leaf.text, f);
			if (isLearnable(f, secret)) learned.push([secret, f.kind]);
		}
	}
	const remember = options.learn !== false;
	if (remember) for (const [value, label] of learned) redactor.addKnown(value, label);
	const seen = remember ? undefined : new Map(learned.map(([value, kind]) => [value, { kind, value }]));
	// Pass 2: redact, into one deep copy of the value.
	let out: unknown = leaves.length ? cloneJson(value) : value;
	const findings: TranscriptFinding[] = [];
	// (Object keys hidden: the key's text, and what it is replaced by.)
	const renames = new Map<string, string>();
	for (const leaf of leaves) {
		const keep = judged(leaf);
		if (isNamedKeySecret(leaf, keep)) {
			findings.push({
				start: 0,
				end: leaf.text.length,
				kind: "secret",
				rule: "transcript:named-key",
				confidence: 0.95,
				path: leaf.path,
				value: leaf.text,
			});
			out = setAt(
				out,
				leaf.path,
				redactor.placeholderFor(
					{ start: 0, end: leaf.text.length, kind: leaf.key, rule: "transcript:named-key", confidence: 0.95 },
					leaf.text,
				),
			);
			continue;
		}
		const here = found(leaf).filter(keep);
		const r = redactor.apply(leaf.text, seen?.size ? merge([...here, ...occurrences(leaf.text, seen, here)]) : here);
		if (!r.findings.length) continue;
		for (const f of r.findings) findings.push({ ...f, path: leaf.path, ...(leaf.isKey ? { inKey: true } : {}) });
		if (leaf.isKey) renames.set(leaf.text, r.text);
		else out = setAt(out, leaf.path, leaf.encode ? leaf.encode(r.text) : r.text);
	}
	for (const { path, original, node } of encoded.reverse()) {
		const inside = findings.filter((f) => path.every((p, i) => f.path[i] === p));
		if (!inside.length) {
			out = setAt(out, path, original);
			continue;
		}
		// (A renamed key has no place in the original's text: that string is written again from the redacted object.)
		const renamed = inside.some((f) => f.inKey);
		if (renamed) renameKeys(getAt(out, path), renames);
		out = setAt(out, path, renamed ? JSON.stringify(getAt(out, path)) : spliced(original, node, getAt(out, path)));
	}
	if (renames.size) renameKeys(out, renames);
	return { value: out as T, findings };
}

/**
 * The leaf's object serialized, or its list of strings (an argv: `["docker", "login", "-p", "…"]`), and where the leaf's
 * text starts in it; undefined when it can't be placed exactly.
 */
function leafContext(
	leaf: Leaf,
	serialized: WeakMap<object, string | undefined>,
): { text: string; at: number } | undefined {
	const parent = leaf.parent;
	if (!parent || JSON.stringify(leaf.text) !== `"${leaf.text}"`) return undefined;
	if (Array.isArray(parent)) {
		const index = leaf.path.at(-1);
		if (typeof index !== "number" || parent.length > 200 || !parent.every((x) => typeof x === "string"))
			return undefined;
		if (!serialized.has(parent)) serialized.set(parent, JSON.stringify(parent));
		const text = serialized.get(parent)!;
		const at = 1 + parent.slice(0, index).reduce((n, x) => n + JSON.stringify(x).length + 1, 0) + 1;
		return text.length <= 20_000 && text.slice(at, at + leaf.text.length) === leaf.text ? { text, at } : undefined;
	}
	if (leaf.key === undefined) return undefined;
	// (Once per object: a big object's leaves share it. Past 20,000 characters, or with a cycle, no context.)
	if (!serialized.has(parent)) {
		let s: string | undefined;
		try {
			// (Its own members only: nested objects and lists as `{}` and `[]`, so a deep value costs each level once.)
			s =
				Object.keys(parent).length <= 200
					? JSON.stringify(
							Object.fromEntries(
								Object.entries(parent).map(([k, v]) => [
									k,
									v !== null && typeof v === "object" ? (Array.isArray(v) ? [] : {}) : v,
								]),
							),
						)
					: undefined;
		} catch {
			s = undefined;
		}
		serialized.set(parent, s !== undefined && s.length <= 20_000 ? s : undefined);
	}
	const text = serialized.get(parent);
	if (text === undefined) return undefined;
	const needle = `${JSON.stringify(leaf.key)}:"${leaf.text}"`;
	const i = text.indexOf(needle);
	return i < 0 ? undefined : { text, at: i + needle.length - 1 - leaf.text.length };
}

/**
 * The `arguments` or `output` JSON string `original` with the scalars that redaction changed (`redacted` is the value it parsed
 * to, redacted) written into it in place: the rest of the string stays as sent, a 64-bit ID's digits, number
 * spellings, spacing and escapes included. (decodeArguments only decodes what parseJson reads whole.)
 */
function spliced(original: string, node: JsonNode, redacted: unknown): string {
	const edits: [start: number, end: number, text: string][] = [];
	const walk = (node: JsonNode, value: unknown) => {
		if (node.kind === "object") for (const [k, x] of node.entries) walk(x, (value as Record<string, unknown>)[k]);
		else if (node.kind === "array") node.items.forEach((x, i) => walk(x, (value as unknown[])[i]));
		// A string's span is its content; a number's, the number: the replacement is quoted either way.
		else if (node.value !== value && typeof value === "string")
			edits.push(
				node.kind === "string"
					? [node.start - 1, node.end + 1, JSON.stringify(value)]
					: [node.start, node.end, JSON.stringify(value)],
			);
	};
	walk(node, redacted);
	const pieces: string[] = [];
	let at = 0;
	for (const [start, end, text] of edits.sort((a, b) => a[0] - b[0])) {
		pieces.push(original.slice(at, start), text);
		at = end;
	}
	pieces.push(original.slice(at));
	return pieces.join("");
}

/** Whether every object in a parsed JSON value has its keys once, so the value JSON.parse gives holds all of it. */
function uniqueKeys(node: JsonNode): boolean {
	if (node.kind === "array") return node.items.every(uniqueKeys);
	if (node.kind !== "object") return true;
	return (
		new Set(node.entries.map(([k]) => k)).size === node.entries.length && node.entries.every(([, x]) => uniqueKeys(x))
	);
}

/**
 * A copy of `value` with every tool call's `arguments` and tool result's `output` sent as a JSON string parsed, and
 * where each was and its parse; `value` itself if none. A result's members then carry its call's hint (Codex's
 * `{"output": "<what cat .env printed>", …}`). Only a string parseJson reads whole and JSON.parse gives every part of
 * (no key twice, no raw control character) is decoded; another is scanned as the text it is.
 */
function decodeArguments(
	value: unknown,
	encoded: { path: (string | number)[]; original: string; node: JsonNode }[],
): unknown {
	const found: { path: (string | number)[]; original: string; node: JsonNode; parsed: unknown }[] = [];
	walk(value, null, ({ value: v, step }) => {
		// (A tool call's `arguments`; a tool result's `output` that is an object, Codex's `{"output": …, "metadata": …}`.)
		if (
			typeof v !== "string" ||
			!(step?.key === "arguments" || (step?.key === "output" && /^\s*\{/.test(v))) ||
			!/^\s*[{[]/.test(v)
		)
			return;
		const parsed = parseJson(v, 0);
		if (!parsed || v.slice(parsed.end).trim() || !uniqueKeys(parsed.node)) return;
		// (An `output` only as Codex wraps one; a command's own JSON output is its text, read whole under its hint.)
		if (
			step.key === "output" &&
			!(
				parsed.node.kind === "object" &&
				parsed.node.entries.some(([k, x]) => /^(?:output|stdout|stderr)$/.test(k) && x.kind === "string")
			)
		)
			return;
		// (parseJson reads what JSON.parse refuses: a raw tab or control character inside a string.)
		let json: unknown;
		try {
			json = JSON.parse(v);
		} catch {
			return;
		}
		found.push({ path: pathOf(step), original: v, node: parsed.node, parsed: json });
	});
	if (!found.length) return value;
	let copy = cloneJson(value);
	for (const { parsed, ...f } of found) {
		copy = setAt(copy, f.path, parsed);
		encoded.push(f);
	}
	return copy;
}

function getAt(root: unknown, path: (string | number)[]): unknown {
	let node: any = root;
	for (const p of path) node = node[p];
	return node;
}
