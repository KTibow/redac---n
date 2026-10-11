/** Values found once with confidence, hidden wherever else they appear in the same text. */
import { KeywordSet } from "./aho.ts";
import { continuesToken } from "./syntax.ts";
import { isBenignValue } from "./values.ts";
import { covered, secretValue } from "./spans.ts";
import { isGuess, layerOf, PLACEHOLDER_RULE, REPEATED_GUESS } from "./rules.ts";
import type { Finding } from "./types.ts";

/**
 * Other occurrences of confidently found values: a webhook token found in its URL is also hidden in
 * the `POST /api/webhooks/…/<token>` line below it, a password found under its name also where it's
 * echoed without one.
 */
export function repeats(text: string, found: Finding[]): Finding[] {
	return occurrences(text, repeatable(text, found), found);
}

/** A value worth looking for elsewhere: what its finding called it, and the secret it is (for the placeholder's tag). */
export interface Remembered {
	kind: string;
	value: string;
	/** Whether the random layer guessed it: its other occurrences are proposed, not vouched for (rules.ts). */
	guess?: boolean;
}

/** The values of confident findings worth looking for elsewhere, each as written (one secret may be written two ways). */
export function repeatable(text: string, found: Finding[]): Map<string, Remembered> {
	const values = new Map<string, Remembered>();
	for (const f of found) {
		if (f.confidence < 0.9 || f.end - f.start < 10 || f.end - f.start > 4096 || f.rule === PLACEHOLDER_RULE) continue;
		const v = secretValue(text, f);
		// (A hash's shape, a commit SHA or a SHA-256, spreads only from a rule that knows what it hid: one read by its
		// name alone (`'key': '<sha>/dist/…'`) would otherwise hide that commit in every line of a CI log.)
		if (
			/^[0-9a-f]{40}$|^[0-9a-f]{64}$/.test(v) &&
			!["format", "known", "file", "command", "structure"].includes(layerOf(f.rule)) &&
			!(layerOf(f.rule) === "named" && f.name && !/^(?:key|keys|hash|sha|etag|id|value|data)$/i.test(f.name))
		)
			continue;
		// (Only a value that can be a secret wherever it is: not a version range, a date, a count.)
		if (isBenignValue(v)) continue;
		const remembered = { kind: f.kind, value: v, ...(isGuess(f.rule) ? { guess: true } : {}) };
		values.set(v, remembered);
		// (As it is written here too, when that's another form of it: `Delta2018%26` in a URL, `Delta2018&` in prose.)
		const raw = text.slice(f.start, f.end);
		if (raw !== v && /^[!-~]{8,}$/.test(v)) values.set(raw, remembered);
	}
	return values;
}

/**
 * Where `values` occur in `text` as whole tokens, outside what `found` covers: each under its first finding's kind and
 * with its secret, so it has the placeholder that finding has.
 */
export function occurrences(text: string, values: ReadonlyMap<string, Remembered>, found: Finding[]): Finding[] {
	const out: Finding[] = [];
	// (The most recent 50,000 values, past any secrets dump: an automaton over more grows without bound.)
	const list = [...values.keys()].filter((v) => !(/\s/.test(v) && v.length < 16)).slice(-50_000);
	if (!list.length) return out;
	const add = (at: number, v: string) => {
		// Whole tokens only: not a prefix or suffix of a longer run.
		const dash = v.includes("-");
		if (
			continuesToken(text, at - 1, dash) ||
			continuesToken(text, at + v.length, dash) ||
			covered(found, at, at + v.length)
		)
			return;
		const { kind, value, guess } = values.get(v)!;
		out.push({ start: at, end: at + v.length, kind, rule: guess ? REPEATED_GUESS : "repeat", confidence: 0.9, value });
	};
	// A few values: a scan each. Many in a long text: every value in one pass.
	// (Overlapping occurrences too, as the automaton finds them. Each scan is a fast `indexOf`; past about 8 M character comparisons the automaton's one pass is cheaper.)
	if (list.length * text.length <= 8_000_000) {
		for (const v of list) for (let at = text.indexOf(v); at >= 0; at = text.indexOf(v, at + 1)) add(at, v);
	} else {
		const set = new KeywordSet(list, true);
		for (const [at, k] of set.matches(text)) add(at, list[k]);
	}
	return out;
}
