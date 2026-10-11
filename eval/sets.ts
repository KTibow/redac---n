/**
 * The labelled corpora in eval/corpora, by category. This is the one place that lists them, and the one place that
 * keeps the held-out sets (`holdout*`) out: every list below matches by name pattern, and no pattern matches a
 * held-out set, so a script that takes its sets from here cannot read one. (`isHeldOut` is for the scripts that take
 * a file from the command line and must not print its failures.)
 */
import { readdirSync } from "node:fs";
import { basename, join } from "node:path";
import { CORPUS_FILE } from "./score.ts";

export const CORPUS_DIR = join(import.meta.dirname, "corpora");

export interface CorpusSet {
	/** The set's name, gzipped or not: `dev_b.jsonl`, `regress/r15a-argv.jsonl`. */
	name: string;
	file: string;
}

/** The sets in `dir` (relative to the corpora directory) whose name, without `.jsonl[.gz]`, matches `pattern`, sorted. */
function list(dir: string, pattern: RegExp): CorpusSet[] {
	return readdirSync(join(CORPUS_DIR, dir))
		.filter((f) => CORPUS_FILE.test(f) && pattern.test(f.replace(CORPUS_FILE, "$1")))
		.sort()
		.map((f) => ({ name: (dir ? `${dir}/` : "") + f.replace(/\.gz$/, ""), file: join(CORPUS_DIR, dir, f) }));
}

/** The development sets: `dev`, `dev_b`, … */
export const devSets = () => list("", /^dev(?:_\w+)?$/);
/** The adversarial false-positive sets: `adv1-fp`, `adv2-fp`. */
export const advSets = () => list("", /^adv\d+-fp$/);
/** The adversarial robustness sets (cases that also name an API and a chunking): `adv1-robust`. */
export const robustSets = () => list("", /^adv\d+-robust$/);
/** The regression sets in eval/corpora/regress. */
export const regressSets = () => list("regress", /^/);

/** Every set the quality gate and the snapshots score: all of the above, nothing held out. */
export const labelledSets = () => [...advSets(), ...robustSets(), ...devSets(), ...regressSets()];

/** Whether a corpus file's name is a held-out set's. */
export const isHeldOut = (file: string) => basename(file).startsWith("holdout");
