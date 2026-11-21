/**
 * Where the raw downloads behind the corpora came from, and getting one back. `eval/sources.tsv` has a row for each
 * repository, dataset shard and archive that was fetched into the data root (eval/data-root.ts): its URL, the commit
 * where one was pinned, the SHA-256 of a downloaded file, its licence as its host tags it, and the day it was fetched. The sets built from them are in
 * the store (scripts/data.ts), so the raw downloads are only wanted to build something new or to read a project's
 * source; they are not kept.
 *
 *   node scripts/sources.ts [PATH…]            the rows at or under those paths (none named: a count by kind)
 *   node scripts/sources.ts --fetch PATH…      download them into the data root
 *
 * What comes back is exact for a `git` row with a commit and for a `file` whose hash still matches. A `git` row with
 * no commit was a clone of the default branch on its `fetched` day, and is cloned as the branch stands now; a `file`
 * whose source has changed since is kept and said to differ. `gh-run-log` and `derived` rows cannot be fetched: the
 * first are GitHub Actions logs, which GitHub deletes after 90 days (the copies are in the store, `ci-logs`), the
 * second were made here from other rows, as their notes say.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createWriteStream, existsSync, mkdirSync, readFileSync, renameSync } from "node:fs";
import { dirname, join } from "node:path";
import { Readable, Transform, type TransformCallback } from "node:stream";
import { pipeline } from "node:stream/promises";
import type { ReadableStream as WebReadableStream } from "node:stream/web";
import { Args } from "../eval/args.ts";
import { CORPORA } from "../eval/data-root.ts";

interface Source {
	path: string;
	kind: "git" | "file" | "gh-run-log" | "derived";
	url: string;
	/** A `git` row's commit; empty where the default branch was cloned unpinned. */
	ref: string;
	/** A `file` row's hash, as it was downloaded. */
	sha256: string;
	/** The licence its host publishes for it, as an SPDX name or the host's tag; `none` where it publishes none. */
	licence: string;
	fetched: string;
	notes: string;
}

const [header, ...lines] = readFileSync(join(import.meta.dirname, "../eval/sources.tsv"), "utf8")
	.trimEnd()
	.split("\n");
const columns = header.split("\t");
const sources = lines.map((line) => {
	const cells = line.split("\t");
	return Object.fromEntries(columns.map((c, i) => [c, cells[i] ?? ""])) as unknown as Source;
});

function git(...args: string[]): void {
	execFileSync("git", args, { stdio: ["ignore", "ignore", "inherit"] });
}

/** Clones `source` at its commit (one commit deep), or at its default branch where none was pinned. */
function fetchGit(source: Source, dest: string): string {
	if (!source.ref) {
		git("clone", "--quiet", "--depth", "1", source.url, dest);
		return `the default branch as it is now (fetched ${source.fetched || "at an unrecorded time"} originally, no commit pinned)`;
	}
	git("init", "--quiet", dest);
	git("-C", dest, "fetch", "--quiet", "--depth", "1", source.url, source.ref);
	git("-C", dest, "checkout", "--quiet", "FETCH_HEAD");
	return `commit ${source.ref.slice(0, 12)}`;
}

/** Downloads `source` and says whether it is what was downloaded before. */
async function fetchFile(source: Source, dest: string): Promise<string> {
	const res = await fetch(source.url);
	if (!res.ok || !res.body) throw new Error(`${res.status} for ${source.url}`);
	const hash = createHash("sha256");
	const hashing = new Transform({
		transform(chunk: Buffer, _encoding: BufferEncoding, done: TransformCallback) {
			hash.update(chunk);
			done(null, chunk);
		},
	});
	await pipeline(Readable.fromWeb(res.body as WebReadableStream), hashing, createWriteStream(dest + ".part"));
	renameSync(dest + ".part", dest);
	const sha256 = hash.digest("hex");
	return !source.sha256
		? "no hash was recorded to compare it with"
		: sha256 === source.sha256
			? "the same bytes as before"
			: `DIFFERS from what was fetched ${source.fetched}: the source has changed`;
}

const args = new Args();
const fetching = args.flag("fetch");
const wanted = args.rest.map((p) => p.replace(/\/+$/, ""));
const chosen = sources.filter((s) => wanted.some((p) => s.path === p || s.path.startsWith(p + "/")));
if (!wanted.length) {
	const count = new Map<string, number>();
	for (const s of sources) count.set(s.kind, (count.get(s.kind) ?? 0) + 1);
	console.log([...count].map(([kind, n]) => `${n} ${kind}`).join(", "));
	const tops = new Set(sources.map((s) => s.path.split("/")[0]));
	console.log([...tops].join(" "));
} else if (!chosen.length) {
	console.error(`no source at or under ${wanted.join(", ")}`);
	process.exitCode = 1;
} else if (!fetching) {
	for (const s of chosen)
		console.log([s.path, s.kind, s.url, s.ref || s.sha256.slice(0, 12), s.licence, s.fetched, s.notes].join("\t"));
} else {
	for (const source of chosen) {
		const dest = join(CORPORA, source.path);
		if (source.kind !== "git" && source.kind !== "file")
			console.log(`${source.path}: not fetched (${source.kind}): ${source.notes}`);
		else if (existsSync(dest)) console.log(`${source.path}: here already`);
		else {
			mkdirSync(dirname(dest), { recursive: true });
			try {
				console.log(
					`${source.path}: ${source.kind === "git" ? fetchGit(source, dest) : await fetchFile(source, dest)}`,
				);
			} catch (e) {
				console.log(`${source.path}: FAILED, ${(e as Error).message.split("\n")[0]}`);
				process.exitCode = 1;
			}
		}
	}
}
