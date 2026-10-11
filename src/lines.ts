/**
 * A text's lines, where a position's line starts and ends, the run of text a position ends (read leftward), and where
 * a position falls among sorted offsets. Each bound scans no further than a fixed distance (2,000 characters unless
 * the caller asks for more), so lookups per match stay linear on text with very long lines or none at all.
 */

/** A text's lines (split at `\n`) and where each starts. */
export function splitLines(text: string): { lines: string[]; starts: number[] } {
	const lines = text.split("\n");
	const starts: number[] = [];
	let at = 0;
	for (const l of lines) {
		starts.push(at);
		at += l.length + 1;
	}
	return { lines, starts };
}

/** Where the line `at` is on starts, looking back no further than `max` characters. */
export function lineStart(text: string, at: number, max = 2000): number {
	const from = Math.max(0, at - max);
	for (let i = at - 1; i >= from; i--) if (text.charCodeAt(i) === 10) return i + 1;
	return from;
}

/** Where the line `at` is on ends (its line break), looking ahead no further than `max` characters. */
export function lineEnd(text: string, at: number, max = 2000): number {
	const limit = Math.min(text.length, at + max);
	for (let i = at; i < limit; i++) if (text.charCodeAt(i) === 10) return i;
	return limit;
}

/**
 * The end of `text` after the last character that `stop` matches (the token a value continues, read leftward): a
 * backward scan, where `/[^…]*$/` tries again from every position.
 */
export function trailingRun(text: string, stop: RegExp): string {
	let i = text.length;
	while (i > 0 && !stop.test(text[i - 1])) i--;
	return text.slice(i);
}

/**
 * `build` for the last text it was asked about, kept until it is asked about another: the per-text indexes readers
 * build (line starts, bracket closes, a line's commands, value stops, YAML blocks), shared by every rule that reads one
 * text and rebuilt when detection moves on to another (a decoded literal, the next text). The last text and its index
 * stay alive until then.
 */
export function lastText<T>(build: (text: string) => T): (text: string) => T {
	let last: { text: string; value: T } | undefined;
	return (text) => {
		if (last?.text !== text) last = { text, value: build(text) };
		return last.value;
	};
}

/** The first index of a sorted array whose value is at least `value`. */
export function lowerBound(sorted: ArrayLike<number>, value: number): number {
	let lo = 0;
	let hi = sorted.length;
	while (lo < hi) {
		const mid = (lo + hi) >> 1;
		if (sorted[mid] < value) lo = mid + 1;
		else hi = mid;
	}
	return lo;
}
