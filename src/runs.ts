/**
 * Long runs of a character set, found without looking at every character: any `min` characters in a row hold exactly one
 * position that is a multiple of `min` (less one), so only those are read until one is in the set, and the run around it
 * is walked. A regex like `[A-Za-z0-9+/=_-]{16,}` tries every position; in prose, logs and pretty-printed JSON, where the
 * runs are short, this reads a sixteenth of the text.
 */

/** A table of the ASCII characters in `chars`, for `longRuns`. */
export function asciiSet(chars: string): Uint8Array {
	const set = new Uint8Array(128);
	for (let i = 0; i < chars.length; i++) set[chars.charCodeAt(i)] = 1;
	return set;
}

/** The maximal runs of `set`'s characters at least `min` long, in order, as [start, end]. */
export function* longRuns(text: string, set: Uint8Array, min: number): Generator<[start: number, end: number]> {
	const inSet = (i: number) => text.charCodeAt(i) < 128 && set[text.charCodeAt(i)] === 1;
	let from = 0;
	let i = min - 1;
	while (i < text.length) {
		if (!inSet(i)) {
			i += min;
			continue;
		}
		let start = i;
		while (start > from && inSet(start - 1)) start--;
		let end = i + 1;
		while (end < text.length && inSet(end)) end++;
		if (end - start >= min) yield [start, end];
		// (The next position to read: the first one past the run that is a multiple of `min`, less one.)
		from = end;
		i = end + ((((min - 1 - end) % min) + min) % min);
	}
}
