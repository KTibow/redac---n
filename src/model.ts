/**
 * The unnamed-token scorer: boosted trees over the features in unnamed.ts, trained by
 * scripts/train-unnamed.py on real public text (negatives) and synthetic keys in context (positives).
 */
import { FEATURE_COUNT, TREES } from "./model-data.ts";

/** The probability that a feature vector is a secret. */
export function predict(x: number[]): number {
	if (x.length !== FEATURE_COUNT) throw new Error(`model expects ${FEATURE_COUNT} features, got ${x.length}`);
	let z = 0;
	for (const [feat, thr, left, right, vals] of TREES) {
		// (A tree of one leaf has no nodes: its root is that leaf.)
		let i = feat.length ? 0 : -1;
		while (i >= 0) i = x[feat[i]] <= thr[i] ? left[i] : right[i];
		z += vals[-i - 1];
	}
	return 1 / (1 + Math.exp(-z));
}
