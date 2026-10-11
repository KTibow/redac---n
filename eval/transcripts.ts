/**
 * The transcript path: labelled dev cases wrapped as tool results in Anthropic- and OpenAI-format
 * message lists (the case's command as the tool call that produced it), redacted with redactValue()
 * and, separately, as one serialized JSON string with redact(). Secrets must not survive in the
 * output in any form; keep values must survive (in their JSON-escaped form).
 *
 *   node eval/transcripts.ts [--guessing confident] <cases.jsonl…>
 */
import { Redactor, type Guessing } from "../src/index.ts";
import { Args } from "./args.ts";
import { type Case, leaked, readCorpus } from "./score.ts";

const args = new Args();
const guessing = args.opt("guessing", "confident") as Guessing;

/** A session: the user asks, the agent runs the case's command (or reads its file), the tool returns the text. */
function anthropic(c: Case, i: number) {
	const input = c.hint?.path ? { file_path: c.hint.path } : { command: c.hint?.command ?? "cat output.log" };
	return [
		{ role: "user", content: "Can you take a look at this and fix what's broken?" },
		{
			role: "assistant",
			content: [
				{ type: "text", text: "Let me check." },
				{
					type: "tool_use",
					id: `toolu_${i.toString(36).padStart(8, "0")}`,
					name: c.hint?.path ? "read" : "bash",
					input,
				},
			],
		},
		{
			role: "user",
			content: [{ type: "tool_result", tool_use_id: `toolu_${i.toString(36).padStart(8, "0")}`, content: c.text }],
		},
		{ role: "assistant", content: [{ type: "text", text: "I see the problem; updating the config now." }] },
	];
}

function openai(c: Case, i: number) {
	const args = c.hint?.path ? { path: c.hint.path } : { cmd: c.hint?.command ?? "cat output.log" };
	return [
		{ role: "user", content: "Something's wrong with the deploy, can you check?" },
		{
			role: "assistant",
			content: null,
			tool_calls: [
				{
					id: `call_${i}`,
					type: "function",
					function: { name: c.hint?.path ? "read_file" : "shell", arguments: JSON.stringify(args) },
				},
			],
		},
		{ role: "tool", tool_call_id: `call_${i}`, content: c.text },
	];
}

let total = 0;
const caught = { value: 0, string: 0 };
const kept = { value: 0, string: 0 };
let keeps = 0;
let i = 0;
for (const file of args.rest) {
	for (const line of readCorpus(file).trim().split("\n")) {
		const c = JSON.parse(line) as Case;
		const session = i % 2 ? openai(c, i) : anthropic(c, i);
		i++;
		const viaValue = JSON.stringify(new Redactor({ guessing, fingerprintKey: "x" }).redactValue(session).value);
		const viaString = new Redactor({ guessing, fingerprintKey: "x" }).redact(JSON.stringify(session)).text;
		for (const s of c.secrets ?? []) {
			total++;
			// The secret as it sits in the serialized transcript.
			const forms = [s, JSON.stringify(s).slice(1, -1)];
			if (!forms.some((f) => leaked(f, viaValue))) caught.value++;
			if (!forms.some((f) => leaked(f, viaString))) caught.string++;
		}
		for (const k of c.keep ?? []) {
			keeps++;
			const esc = JSON.stringify(k).slice(1, -1);
			if (viaValue.includes(esc)) kept.value++;
			if (viaString.includes(esc)) kept.string++;
		}
	}
}
const pct = (a: number, b: number) => (b ? `${((a / b) * 100).toFixed(1)}%` : "-");
console.log(
	`transcripts [${guessing}] redactValue: recall ${pct(caught.value, total)} lost ${pct(keeps - kept.value, keeps)}   serialized redact(): recall ${pct(caught.string, total)} lost ${pct(keeps - kept.string, keeps)}   (${total} secrets, ${keeps} keeps)`,
);
