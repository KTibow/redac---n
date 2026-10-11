import type { Finding } from "./types.ts";

/** The most characters of text (and per-entry overhead) a Redactor remembers findings for; the cache is cleared when it is full. */
const CACHE_CHARS = 16_777_216;
/** What an entry of the cache costs besides its text, in characters: its maps, its key and its findings. */
const CACHE_ENTRY_OVERHEAD = 128;

/**
 * Findings of texts already detected, by text and then by what else decides them (guessing, hint), for one version of the
 * known values: a conversation sent again with a turn added is detected once. Cleared when the known values change
 * and when CACHE_CHARS is reached (a text longer than that isn't kept).
 */
export class FindingsCache {
	private byText = new Map<string, Map<string, Finding[]>>();
	private chars = 0;
	private version = 0;

	private sync(version: number) {
		if (version === this.version) return;
		this.byText.clear();
		this.chars = 0;
		this.version = version;
	}

	get(version: number, text: string, context: string): Finding[] | undefined {
		this.sync(version);
		return this.byText.get(text)?.get(context);
	}

	set(version: number, text: string, context: string, found: Finding[]) {
		this.sync(version);
		const cost = text.length + context.length + CACHE_ENTRY_OVERHEAD;
		if (cost > CACHE_CHARS) return;
		if (this.chars + cost > CACHE_CHARS) {
			this.byText.clear();
			this.chars = 0;
		}
		let contexts = this.byText.get(text);
		if (!contexts) this.byText.set(text, (contexts = new Map()));
		contexts.set(context, found);
		this.chars += cost;
	}
}
