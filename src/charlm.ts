/**
 * How much more likely a string is under a model of ordinary identifiers and words than as random
 * characters. Names, words and their abbreviations score well above zero; random strings score near
 * or below it.
 */
import { CHARLM } from "./charlm-data.ts";

const A = 37;
let table: Uint8Array | undefined;

function load(): Uint8Array {
	if (table) return table;
	const bin = atob(CHARLM);
	table = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) table[i] = bin.charCodeAt(i);
	return table;
}

function idx(k: number): number {
	if (k >= 97 && k <= 122) return k - 96;
	if (k >= 65 && k <= 90) return k - 64;
	if (k >= 48 && k <= 57) return k - 48 + 27;
	return 0;
}

/**
 * Mean log2-likelihood ratio per scored term under the identifier model versus uniform over 36 characters: each
 * letter and digit (lowercased), and each camelCase break (how likely the word was to end there), so `fooBar` has
 * seven terms and `foo_bar` six. (The model was trained on this mean: the rule is not changed.) A symbol only resets
 * the context, unscored.
 */
export function naturalness(token: string): number {
	const t = load();
	let a = 0;
	let b = 0;
	let sum = 0;
	let n = 0;
	const uniform = Math.log2(36);
	for (let i = 0; i < token.length; i++) {
		const code = token.charCodeAt(i);
		// camelCase: an upper-case letter after a lower-case one starts a new word.
		if (code >= 65 && code <= 90) {
			// (Before the first, `charCodeAt(-1)` is NaN: no letter.)
			const p = token.charCodeAt(i - 1);
			if (p >= 97 && p <= 122) {
				sum += uniform - t[a * A * A + b * A] / 16;
				n++;
				a = 0;
				b = 0;
			}
		}
		const c = idx(code);
		if (c === 0) {
			a = 0;
			b = 0;
			continue;
		}
		sum += uniform - t[a * A * A + b * A + c] / 16;
		n++;
		a = b;
		b = c;
	}
	return n ? sum / n : 0;
}
