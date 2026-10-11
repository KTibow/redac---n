/**
 * Seeded random bytes for the tests, in place of `node:crypto`'s: a test of random keys must not pass or fail by the
 * draw (one in a few hundred random tokens reads as words). `node --test` runs each file in a process of its own, so
 * each file's draws are the same every run. (eval/random.ts's mulberry32.)
 */
import { mulberry32Bits } from "../eval/random.ts";

const next = mulberry32Bits(0x2545f491);

/** `n` random bytes, as a Buffer (so `.toString("hex")` and `"base64"` work as crypto's do). */
export function randomBytes(n: number): Buffer {
	const out = Buffer.alloc(n);
	for (let i = 0; i < n; i++) out[i] = next() & 0xff;
	return out;
}

/** A random number in [0, 1), in place of `Math.random()`. */
export function random(): number {
	return next() / 4294967296;
}
