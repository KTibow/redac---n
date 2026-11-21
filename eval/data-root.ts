/**
 * Where the corpora that aren't in the repository are read from (third-party sets whose licences differ from this
 * one's, some allowing evaluation only, and samples of public text): `$REDACT_CORPORA`, or `~/.cache/redac---n`
 * (under `$XDG_CACHE_HOME`, where that is set).
 * It is a cache of what eval/data.lock.json lists: `node scripts/data.ts pull` fills it, and deleting it loses nothing
 * (eval/DATA.md).
 */
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export const CORPORA =
	process.env.REDACT_CORPORA ?? join(process.env.XDG_CACHE_HOME || join(homedir(), ".cache"), "redac---n");

/** What a script says when it skips a part whose data is not here. */
export const notHere = (path: string) => `skipped (no ${join(CORPORA, path)}: node scripts/data.ts pull ${path})`;

/** The file or directory at `path` under the data root. A script that needs one that is not here ends, saying how to fetch it. */
export function dataFile(path: string): string {
	const file = join(CORPORA, path);
	if (!existsSync(file)) {
		console.error(`${file} is not here: node scripts/data.ts pull ${path}`);
		process.exit(1);
	}
	return file;
}
