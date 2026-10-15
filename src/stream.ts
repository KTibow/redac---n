/**
 * Redaction of text that arrives in chunks (a tool's output, a model's response): each chunk is held until it is
 * far enough behind the newest one that no secret can still be forming across it, then released redacted.
 */
import type { Redactor } from "./index.ts";
import { occurrences, type Remembered, repeatable } from "./repeats.ts";
import { endsInBlock } from "./pem.ts";
import { firstPrompt, openScopes } from "./secretfile.ts";
import { openManifestData } from "./structure.ts";
import { needsNormalizing, normalize } from "./normalize.ts";
import { merge, secretValue } from "./spans.ts";
import type { DetectOptions } from "./types.ts";

/** Text already released kept as left context (the line naming a value, the `$ cat .env` above it), scanned again but never released again. */
const CONTEXT = 8_192;
/** Values hidden earlier in the stream that are looked for again, the most recent first. */
const REMEMBERED = 2_000;
/** How much text is held back while what it is waits on a line still to come (a manifest's `kind` after its `data:`). */
const MAX_HELD = 1_000_000;

export class RedactionStream {
	/** How far behind the newest text a release point must be: 8 KB covers the longest single secrets (a private key). */
	private readonly holdback: number;
	/** Text not released yet. */
	private buffer = "";
	/** Text released already, its last CONTEXT characters. */
	private context = "";
	/**
	 * The lines that open the scopes still open in the released text (secretfile.ts openScopes, structure.ts
	 * openManifestData): kept in front of the context however far back they are, so the text after them is read as
	 * it would be in the whole text (that command's output, that heredoc's body, that Secret's data).
	 */
	private scopes: string[] = [];
	/** While text is held (MAX_HELD), how long the buffer grows before it's looked at again. */
	private heldUntil = 0;
	/** Positions in the whole stream: where `buffer` starts, and where the last value hidden ends. */
	private released = 0;
	private hiddenUntil = 0;
	/** Values hidden earlier in the stream, looked for again however far back they were named, as `redact()` sees the whole text. */
	private remembered = new Map<string, Remembered>();

	private readonly redactor: Redactor;
	/** The options each scan runs with: the hint's command dropped once a prompt is released (see advance). */
	private options: DetectOptions;

	constructor(redactor: Redactor, options: DetectOptions & { holdback?: number }) {
		this.redactor = redactor;
		this.options = { hint: options.hint, guessing: options.guessing };
		this.holdback = Math.max(8_192, options.holdback ?? 32_768);
	}

	write(chunk: string): string {
		this.buffer += chunk;
		// Scanned once the buffer has twice the holdback, so each character is scanned about twice.
		return this.buffer.length < Math.max(this.holdback * 2, this.heldUntil) ? "" : this.flush(false);
	}

	end(): string {
		return this.flush(true);
	}

	/** What scanning sees in front of the buffer: the open scopes' lines that have scrolled out of it, and the released context. */
	private head(): string {
		// (Each scope line ends in its line break, so it matches only a whole line of the context, never the start of a longer one.)
		return this.scopes.filter((line) => !`\n${this.context}`.includes(`\n${line}`)).join("") + this.context;
	}

	/**
	 * Where to release up to: a line break at least `holdback` from the end, so a line is judged whole (a JSONL record,
	 * a base64 blob); 0 to hold an unfinished line. Past MAX_HELD, the last blank or delimiter, or the holdback itself;
	 * never inside a surrogate pair.
	 */
	private releasePoint(all: boolean): number {
		const buffer = this.buffer;
		if (all) return buffer.length;
		let cut = buffer.lastIndexOf("\n", buffer.length - this.holdback) + 1;
		if (cut <= 0 && buffer.length < MAX_HELD) return 0;
		if (cut <= 0) {
			const limit = buffer.length - this.holdback;
			cut =
				Math.max(buffer.lastIndexOf(" ", limit), buffer.lastIndexOf(",", limit), buffer.lastIndexOf(";", limit)) + 1;
			if (cut <= 0) cut = limit;
		}
		if (cut > 0 && isHighSurrogate(buffer.charCodeAt(cut - 1))) cut--;
		return cut;
	}

	private flush(all: boolean): string {
		const head = this.head();
		const left = head.length;
		// (Up to the buffer's last line break, but at the end: no detector sees a line cut short that the whole text wouldn't.
		// Unless that break is inside a private key whose END line has no break after it, `…-----END RSA PRIVATE KEY----- {"a":…`:
		// the key is read to its END, and what follows on that line, cut short, is held back with it.)
		let lineEnd = all ? -1 : this.buffer.lastIndexOf("\n");
		let whole = head + (lineEnd < 0 ? this.buffer : this.buffer.slice(0, lineEnd + 1));
		if (lineEnd >= 0 && endsInBlock(whole)) {
			lineEnd = -1;
			whole = head + this.buffer;
		}
		// An unfinished line, and a Secret's data whose `kind` hasn't come yet, are held until they are whole.
		let cut = this.releasePoint(all);
		if (cut <= 0 || (!all && this.buffer.length < MAX_HELD && openManifestData(whole)?.pending)) {
			this.heldUntil = this.buffer.length + this.holdback;
			return "";
		}
		this.heldUntil = 0;
		const detected = this.redactor.detect(whole, this.options);
		const findings = (
			this.remembered.size ? merge([...detected, ...occurrences(whole, this.remembered, detected)], whole) : detected
		)
			.filter((f) => f.end > left)
			.map((f) => ({ ...f, start: f.start - left, end: f.end - left, value: secretValue(whole, f) }));
		// A finding across the cut is released whole later, unless it started before this buffer (a blob longer than
		// the holdback): that one is hidden now, and its continuation dropped as it arrives, while its start is still in
		// the context read before the buffer (CONTEXT; a single secret longer than that, which no key is, shows its tail).
		for (const f of findings) if (f.start < cut && f.end > cut && f.start > 0) cut = f.start;
		let out = "";
		let at = 0;
		for (const f of findings) {
			if (f.start >= cut) break;
			// (What replaces it may be wider than the finding: a JSON number's whole token, quoted.)
			const r = this.redactor.replacement(whole, { ...f, start: f.start + left, end: f.end + left }, f.value);
			const end = Math.max(f.end, r.end - left);
			out += this.buffer.slice(at, Math.max(at, r.start - left));
			// The rest of a value already replaced by a placeholder adds nothing; a value that began in text already
			// released, found only now, is hidden from here on. (Judged in the whole scanned text, so a JSON key
			// released before still counts.)
			if (this.released + f.start >= this.hiddenUntil) out += r.text;
			this.hiddenUntil = Math.max(this.hiddenUntil, this.released + end);
			at = Math.min(end, cut);
		}
		out += this.buffer.slice(at, cut);
		this.remember(
			repeatable(
				whole,
				detected.filter((f) => f.start >= left && f.start - left < cut),
			),
		);
		this.advance(cut);
		return out;
	}

	private remember(values: ReadonlyMap<string, Remembered>): void {
		for (const [form, r] of values) {
			this.remembered.delete(form);
			this.remembered.set(form, r);
			if (this.remembered.size > REMEMBERED) this.remembered.delete(this.remembered.keys().next().value!);
		}
	}

	/** Moves the first `cut` characters of the buffer into the released context. */
	private advance(cut: number): void {
		const out = this.buffer.slice(0, cut);
		// (Read as detection reads it: normalized, colours and line continuations gone, a diff's markers too.)
		const raw = this.head() + out;
		const seen = needsNormalizing(raw) ? normalize(raw).text : raw;
		this.scopes = [...openScopes(seen), ...(openManifestData(seen)?.lines ?? [])];
		// A command's output runs to the next prompt in it, as `redact()` reads the whole text (secretfile.ts firstPrompt):
		// once one is released, what comes after is another command's, and the hint's command no longer says what it is,
		// however far behind the prompt has scrolled.
		const hint = this.options.hint;
		if (hint?.command !== undefined && firstPrompt(seen) < seen.length)
			this.options = { ...this.options, hint: { ...hint, command: undefined } };
		// The context starts at a line's start, as the whole text's lines do (a piece of a line would read as one).
		const joined = this.context + out;
		this.context = joined.slice(-CONTEXT);
		if (joined.length > CONTEXT && joined[joined.length - CONTEXT - 1] !== "\n") {
			const nl = this.context.indexOf("\n");
			if (nl >= 0) this.context = this.context.slice(nl + 1);
		}
		if (isLowSurrogate(this.context.charCodeAt(0))) this.context = this.context.slice(1);
		this.buffer = this.buffer.slice(cut);
		this.released += cut;
	}
}

const isHighSurrogate = (c: number) => c >= 0xd800 && c <= 0xdbff;
const isLowSurrogate = (c: number) => c >= 0xdc00 && c <= 0xdfff;
