/**
 * The one seeded random generator (mulberry32) for eval/, scripts/ and test/: a corpus, a fuzz run or a test of
 * random keys must not pass or fail by the draw, and two runs of one seed must agree.
 */

/** A generator of 32 random bits per call, from `seed`. */
export function mulberry32Bits(seed: number): () => number {
	let state = seed >>> 0;
	return () => {
		state = (state + 0x6d2b79f5) >>> 0;
		let t = state;
		t = Math.imul(t ^ (t >>> 15), t | 1);
		t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
		return (t ^ (t >>> 14)) >>> 0;
	};
}

/** A generator of numbers in [0, 1), from `seed`. */
export function mulberry32(seed: number): () => number {
	const bits = mulberry32Bits(seed);
	return () => bits() / 4294967296;
}

/** A generator of integers in [0, n), from `seed`. */
export function randomInts(seed: number): (n: number) => number {
	const next = mulberry32(seed);
	return (n) => Math.floor(next() * n);
}
