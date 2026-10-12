/**
 * The demo page (site/index.html): the library itself, bundled for the browser, redacting what's typed as it's typed.
 * The text never leaves the page: nothing here makes a request or stores anything.
 */
import { Redactor, type Guessing, type Hint, type RedactResult } from "../src/index.ts";
import { examples } from "./examples.ts";

const element = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const input = element<HTMLTextAreaElement>("input");
const command = element<HTMLInputElement>("command");
const path = element<HTMLInputElement>("path");
const output = element<HTMLPreElement>("output");
const status = element("status");
const findings = element<HTMLUListElement>("findings");
const explain = element("explain");
const copy = element<HTMLButtonElement>("copy");

const GUESSING: Record<Guessing, string> = {
	off: "No guesses: only names, formats, structure and the hint decide. Fewer false hits, lower recall.",
	confident: "The default: also hides random-looking tokens with no name or format, where the model is sure of them.",
	eager: "Guesses at shorter, less certain tokens too, accepting more false redactions.",
};

/** A placeholder as the library writes one by default (index.ts's PLACEHOLDER), to mark in the output. */
const PLACEHOLDER = /\[REDACTED [\w .:/-]{1,60} #[0-9a-f]{6}\]/g;

// (One Redactor for the visit: its random key keeps a value's tag the same while the text is edited. `redact` learns
// nothing, so what an earlier text held is never hidden in a later one.)
const redactor = new Redactor();
let result: RedactResult = { text: "", findings: [] };

const guessing = () =>
	(document.querySelector<HTMLInputElement>('input[name="guessing"]:checked')?.value ?? "confident") as Guessing;

function run() {
	const hint: Hint = {};
	if (command.value.trim()) hint.command = command.value;
	if (path.value.trim()) hint.path = path.value;
	explain.textContent = GUESSING[guessing()];
	const started = performance.now();
	try {
		result = redactor.redact(input.value, { hint, guessing: guessing() });
	} catch (e) {
		result = { text: "", findings: [] };
		output.replaceChildren();
		findings.replaceChildren();
		status.textContent = `Error: ${e instanceof Error ? e.message : String(e)}`;
		return;
	}
	const ms = Math.max(1, Math.round(performance.now() - started));
	render(ms);
}

function render(ms: number) {
	const text = result.text;
	const parts: Node[] = [];
	let at = 0;
	for (const m of text.matchAll(PLACEHOLDER)) {
		parts.push(document.createTextNode(text.slice(at, m.index)));
		const mark = document.createElement("mark");
		mark.textContent = m[0];
		parts.push(mark);
		at = m.index + m[0].length;
	}
	parts.push(document.createTextNode(text.slice(at)));
	output.replaceChildren(...parts);

	const n = result.findings.length;
	status.textContent = `${n ? `${n} ${n === 1 ? "secret" : "secrets"} hidden` : "Nothing hidden"} · ${ms} ms`;
	const lineStarts = [...input.value.matchAll(/\n/g)].map((m) => m.index + 1);
	const lineOf = (offset: number) => 1 + lineStarts.filter((s) => s <= offset).length;
	findings.replaceChildren(
		...result.findings.map((f) => {
			const item = document.createElement("li");
			const rule = document.createElement("code");
			rule.textContent = f.rule;
			item.append(`Line ${lineOf(f.start)}: ${f.kind}, by `, rule, ` (confidence ${f.confidence.toFixed(2)})`);
			return item;
		}),
	);
}

let timer: ReturnType<typeof setTimeout> | undefined;
/** Runs once typing pauses, so a long paste isn't redacted again at every keystroke. */
function later() {
	clearTimeout(timer);
	timer = setTimeout(run, 120);
}

function load(index: number) {
	const example = examples[index];
	input.value = example.text;
	command.value = example.hint.command ?? "";
	path.value = example.hint.path ?? "";
	run();
}

element("examples").append(
	...examples.map((example, i) => {
		const button = document.createElement("button");
		button.type = "button";
		button.textContent = example.label;
		button.addEventListener("click", () => load(i));
		return button;
	}),
);
for (const field of [input, command, path]) field.addEventListener("input", later);
for (const radio of document.querySelectorAll('input[name="guessing"]')) radio.addEventListener("change", run);
copy.addEventListener("click", async () => {
	await navigator.clipboard.writeText(result.text);
	copy.textContent = "Copied";
	setTimeout(() => (copy.textContent = "Copy"), 1200);
});
load(0);
