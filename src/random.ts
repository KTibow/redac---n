/**
 * Measures of how random a token looks, from the token alone, for the random layer's model (unnamed.ts): the
 * alphabet it is drawn from, its entropy as a z-score against a uniformly random string of the same length over that
 * alphabet (so a 20-character hex string and a 60-character base64 one are judged on one scale), and its character
 * classes and how often they switch. A random key, a hash and an encrypted blob all look random here; telling them
 * apart is the context's job.
 */

export type Alphabet = "hex" | "HEX" | "b32" | "b36" | "B36" | "b62" | "b64" | "b64url" | "other";

/** Sizes of the alphabets a token is drawn from. (`other` is the 62 letters and digits and about 8 of the symbols keys use; the model's features depend on it.) */
const ALPHABET_SIZE: Record<Alphabet, number> = {
	hex: 16,
	HEX: 16,
	b32: 32,
	b36: 36,
	B36: 36,
	b62: 62,
	b64: 64,
	b64url: 64,
	other: 70,
};

/** The smallest common alphabet that contains every character of the token. (`=` is base64's padding, in none.) */
export function alphabetOf(token: string): Alphabet {
	let lower = false;
	let upper = false;
	let digit = false;
	let hexOnly = true;
	let b64 = false;
	let url = false;
	let other = false;
	let b32 = true;
	for (let i = 0; i < token.length; i++) {
		const c = token.charCodeAt(i);
		if (c >= 97 && c <= 122) {
			lower = true;
			if (c > 102) hexOnly = false;
		} else if (c >= 65 && c <= 90) {
			upper = true;
			if (c > 70) hexOnly = false;
		} else if (c >= 48 && c <= 57) {
			digit = true;
			if (c < 50 || c > 55) b32 = false;
		} else if (c === 43 || c === 47) b64 = true;
		else if (c === 45 || c === 95) url = true;
		else if (c !== 61) other = true;
	}
	if (other || (b64 && url)) return "other";
	if (b64) return "b64";
	if (url) return "b64url";
	if (hexOnly && !(lower && upper)) return upper ? "HEX" : "hex";
	if (upper && !lower && b32) return "b32";
	if (lower && upper) return "b62";
	if (upper) return "B36";
	return digit || lower ? "b36" : "other";
}

/** Shannon entropy of the characters, in bits per character. */
export function entropy(token: string): number {
	const counts = new Map<number, number>();
	for (let i = 0; i < token.length; i++) {
		const c = token.charCodeAt(i);
		counts.set(c, (counts.get(c) ?? 0) + 1);
	}
	let bits = 0;
	for (const n of counts.values()) {
		const p = n / token.length;
		bits -= p * Math.log2(p);
	}
	return bits;
}

/**
 * The expected entropy and its standard deviation for a uniformly random string of length `n` (at most 512) over
 * `k` characters, estimated once by simulation and cached. Lets a threshold be a z-score instead of a
 * fixed number of bits, which is too strict for short tokens and too loose for long ones.
 */
const entropyStats = new Map<number, [number, number]>();
function randomEntropy(k: number, n: number): [number, number] {
	const key = k * 10_000 + Math.min(n, 512);
	let s = entropyStats.get(key);
	if (s) return s;
	n = Math.min(n, 512);
	// Fixed seed, so results never vary between runs.
	let seed = key;
	const next = () => {
		seed = (seed + 0x6d2b79f5) | 0;
		let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
		t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
	const trials = 400;
	const counts = new Uint16Array(k);
	let sum = 0;
	let sumSq = 0;
	for (let t = 0; t < trials; t++) {
		counts.fill(0);
		for (let i = 0; i < n; i++) counts[Math.floor(next() * k)]++;
		let bits = 0;
		for (let j = 0; j < k; j++) if (counts[j]) bits -= (counts[j] / n) * Math.log2(counts[j] / n);
		sum += bits;
		sumSq += bits * bits;
	}
	const mean = sum / trials;
	s = [mean, Math.sqrt(Math.max(1e-6, sumSq / trials - mean * mean))];
	entropyStats.set(key, s);
	return s;
}

/**
 * How many standard deviations the token's entropy sits from a random string's. Random strings score near 0.
 * (Measured over the first 512 characters, the longest string randomEntropy simulates.)
 */
export function entropyZ(token: string, alphabet = alphabetOf(token)): number {
	const t = token.slice(0, 512);
	const [mean, sd] = randomEntropy(ALPHABET_SIZE[alphabet], t.length);
	return (entropy(t) - mean) / sd;
}

type Class = 0 | 1 | 2 | 3; // lower, upper, digit, symbol
function classOf(c: number): Class {
	if (c >= 97 && c <= 122) return 0;
	if (c >= 65 && c <= 90) return 1;
	if (c >= 48 && c <= 57) return 2;
	return 3;
}

/** A token's character classes: how many of each, and how often the class changes. */
export interface Shape {
	length: number;
	lower: number;
	upper: number;
	digit: number;
	/** Changes between letter case, digit and symbol, per character boundary. */
	switches: number;
	/** What `switches` would be for a random string with these class proportions. */
	expectedSwitches: number;
}

export function shape(token: string): Shape {
	const n = token.length;
	const cls = [0, 0, 0, 0];
	let switches = 0;
	let prev = -1;
	for (let i = 0; i < n; i++) {
		const c = classOf(token.charCodeAt(i));
		cls[c]++;
		if (prev >= 0 && c !== prev) switches++;
		prev = c;
	}
	let same = 0;
	for (const k of cls) same += (k / n) ** 2;
	return {
		length: n,
		lower: cls[0],
		upper: cls[1],
		digit: cls[2],
		switches: switches / Math.max(1, n - 1),
		expectedSwitches: n === 0 ? 0 : 1 - same,
	};
}
