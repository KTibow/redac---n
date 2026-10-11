/**
 * What leaks, what is lost and what is slow across the labelled sets: the one measurement behind `scripts/snap.ts`
 * (snapshots, diffed by hand) and `eval/check.ts` (the gate, diffed against eval/baseline.json.gz).
 */
import { Redactor } from "../src/index.ts";
import type { CorpusSet } from "./sets.ts";
import { loadCases, scoreCase } from "./score.ts";

/** A case that takes longer than this to redact is listed as slow. */
export const SLOW_MS = 1000;

/** Case-level findings. An entry is `set:id` (slow) or `set:id:value` (leak: a secret that survives; lost: a keep that doesn't). */
export interface Measure {
	leak: string[];
	lost: string[];
	slow: string[];
}

/**
 * Redacts every case of `sets` (a fresh redactor per case, `known` as the case gives it) and lists the leaks, losses
 * and slow cases. A case that is slow is run once more, so a busy machine's one slow run is not listed.
 */
export function measureSets(sets: readonly CorpusSet[]): Measure {
	const m: Measure = { leak: [], lost: [], slow: [] };
	for (const { name, file } of sets) {
		for (const c of loadCases(file)) {
			const run = () => {
				const started = performance.now();
				const out = new Redactor({ known: c.known, fingerprintKey: "x" }).redact(c.text, { hint: c.hint }).text;
				return { out, ms: performance.now() - started };
			};
			let { out, ms } = run();
			if (ms > SLOW_MS) ms = Math.min(ms, run().ms);
			if (ms > SLOW_MS) m.slow.push(`${name}:${c.id}`);
			const r = scoreCase(c, out, ms);
			for (const s of r.leaked) m.leak.push(`${name}:${c.id}:${s}`);
			for (const k of r.lost) m.lost.push(`${name}:${c.id}:${k}`);
		}
	}
	return m;
}

/** An entry as the snapshots and the baseline show it: long values cut. */
export const clip = (entry: string) => entry.slice(0, 160);
