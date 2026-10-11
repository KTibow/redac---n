/**
 * Linear time, asserted the way scripts/fuzz-perf.ts measures it: an input four times longer must cost under eight
 * times as much. Quadratic work costs sixteen times as much, so eight tells the two apart with room for noise. A fixed
 * time budget would fail on a busy machine; a ratio doesn't.
 */
import assert from "node:assert/strict";

/** The fastest of three runs, in milliseconds. */
function time(run: () => void): number {
	let best = Infinity;
	for (let i = 0; i < 3; i++) {
		const t = performance.now();
		run();
		best = Math.min(best, performance.now() - t);
	}
	return best;
}

/** Fails if `run(4n)` costs more than eight times `run(n)`: quadratic work in `n`. (Under 20 ms either way is too fast to tell, and too fast to matter.) */
export function assertLinear(what: string, run: (n: number) => void, n: number): void {
	const small = time(() => run(n));
	const big = time(() => run(4 * n));
	if (big < 20) return;
	assert.ok(big < 8 * Math.max(small, 1), `${what}: ${small.toFixed(0)} ms at ${n}, ${big.toFixed(0)} ms at ${4 * n}`);
}
