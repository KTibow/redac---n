/**
 * The corpora that aren't in the repository, fetched when they are wanted. `eval/data.lock.json` lists every file and
 * directory the scripts read under the data root (eval/data-root.ts), each with the SHA-256 of its content. The
 * content sits in a store outside the repository, one zstd-compressed blob per entry, named by that hash: a blob never
 * changes, so any commit's lock fetches exactly the data that commit was measured on. The data root is then a cache:
 * delete it, or any part of it, and `pull` brings it back.
 *
 *   node scripts/data.ts status                      what the lock lists, and what is here
 *   node scripts/data.ts pull [PATH…] [--all]        fetch entries (none named: the everyday ones)
 *   node scripts/data.ts push PATH… [--everyday] [--private] [--note TEXT]
 *                                                    add or replace entries from what is in the data root
 *   node scripts/data.ts forget PATH…                take entries out of the lock (their blobs stay in the store)
 *
 * A PATH names an entry or a directory of entries (`built` is every entry under built/). `pull` leaves alone a local
 * copy that differs from the lock (one rebuilt here and not yet pushed) unless `--force` is given. A directory entry is
 * stored as a tar of its contents and is taken on trust once unpacked: `status` says where it came from, not whether a
 * file inside has since changed.
 *
 * The lock names two stores, each `hf:USER/NAME` (a Hugging Face dataset repository) or a directory: a public one,
 * read without credentials, and a private one for the entries pushed with `--private`, which are not for publishing
 * (working notes). `pull` needs Node and, for directory entries, `tar`; `push` also needs the `zstd` and `hf`
 * commands, and a Hugging Face login.
 */
import { type ChildProcess, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
	copyFileSync,
	createReadStream,
	createWriteStream,
	existsSync,
	mkdirSync,
	readFileSync,
	renameSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { availableParallelism, homedir } from "node:os";
import { dirname, join } from "node:path";
import { Readable, Transform, type TransformCallback, Writable } from "node:stream";
import { pipeline } from "node:stream/promises";
import type { ReadableStream as WebReadableStream } from "node:stream/web";
import { createZstdDecompress } from "node:zlib";
import { Args } from "../eval/args.ts";
import { CORPORA } from "../eval/data-root.ts";

// ---------------------------------------------------------------- the lock, and what is known of the local copies

interface Entry {
	/** Of the content: the file's bytes, or for a directory the tar of its contents. Also the blob's name in the store. */
	sha256: string;
	/** The content's size. */
	bytes: number;
	/** The blob's size: what a pull downloads. */
	packed: number;
	/** A directory, stored as a tar. */
	dir?: true;
	/** Fetched by a plain `pull`: what `pnpm eval`, scripts/snap.ts and the model's rebuild read. */
	everyday?: true;
	/** In the private store. */
	private?: true;
	/** What it is and what reads it. */
	note?: string;
}

interface Lock {
	stores: { public: string; private: string };
	entries: Record<string, Entry>;
}

const LOCK_FILE = join(import.meta.dirname, "../eval/data.lock.json");

function readLock(): Lock {
	const lock = JSON.parse(readFileSync(LOCK_FILE, "utf8")) as Lock;
	for (const path of Object.keys(lock.entries)) checkPath(path);
	return lock;
}

function writeLock(lock: Lock): void {
	lock.entries = Object.fromEntries(Object.entries(lock.entries).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
	writeFileSync(LOCK_FILE, JSON.stringify(lock, null, "\t") + "\n");
}

/** An entry's path is relative and stays inside the data root: nothing a lock says can write outside it. */
function checkPath(path: string): void {
	const parts = path.split("/");
	if (!path || path.startsWith("/") || parts.some((p) => !p || p === "." || p === ".." || p.includes("\\")))
		throw new Error(`not a path inside the data root: ${JSON.stringify(path)}`);
}

/** The entries a command-line PATH names: the entry itself, or every entry under that directory. */
function select(lock: Lock, paths: string[]): string[] {
	const all = Object.keys(lock.entries);
	const chosen = new Set<string>();
	for (const raw of paths) {
		const path = raw.replace(/\/+$/, "");
		const hits = all.filter((p) => p === path || p.startsWith(path + "/"));
		if (!hits.length) throw new Error(`no entry at or under ${raw} (node scripts/data.ts status lists them)`);
		for (const p of hits) chosen.add(p);
	}
	return [...chosen];
}

/**
 * What each local copy was last seen to be: a file's hash with the size and modification time it had (so an unchanged
 * file is not hashed again), a directory's the blob it was unpacked from or packed into.
 */
interface Seen {
	sha256: string;
	bytes?: number;
	mtimeMs?: number;
}

const SEEN_FILE = join(CORPORA, ".data-state.json");
const seen: Record<string, Seen> = existsSync(SEEN_FILE) ? JSON.parse(readFileSync(SEEN_FILE, "utf8")) : {};

function saveSeen(): void {
	mkdirSync(CORPORA, { recursive: true });
	writeFileSync(SEEN_FILE, JSON.stringify(seen, null, "\t") + "\n");
}

async function hashFile(file: string): Promise<string> {
	const hash = createHash("sha256");
	await pipeline(createReadStream(file), hash);
	return hash.digest("hex");
}

/** The hash of the local file at `path`, from what was seen of it if its size and time are the same. */
async function localFileHash(path: string): Promise<string> {
	const stat = statSync(join(CORPORA, path));
	const was = seen[path];
	if (was && was.bytes === stat.size && was.mtimeMs === stat.mtimeMs) return was.sha256;
	const sha256 = await hashFile(join(CORPORA, path));
	seen[path] = { sha256, bytes: stat.size, mtimeMs: stat.mtimeMs };
	saveSeen();
	return sha256;
}

/**
 * How the local copy of an entry stands against the lock: `ok`; `missing`; `differs` (a file with other content, or a
 * directory unpacked from another blob); `unknown` (a directory that did not come from the store: nothing says what
 * is in it).
 */
type Local = "ok" | "missing" | "differs" | "unknown";

async function local(path: string, entry: Entry): Promise<Local> {
	const file = join(CORPORA, path);
	if (!existsSync(file)) return "missing";
	if (statSync(file).isDirectory() !== !!entry.dir) return "differs";
	if (entry.dir) return !seen[path] ? "unknown" : seen[path].sha256 === entry.sha256 ? "ok" : "differs";
	return (await localFileHash(path)) === entry.sha256 ? "ok" : "differs";
}

// ---------------------------------------------------------------- stores

/** Where the blobs are: named, immutable, written once. */
interface Store {
	has(name: string): Promise<boolean>;
	read(name: string): Promise<Readable>;
	write(name: string, file: string): Promise<void>;
}

class DirectoryStore implements Store {
	readonly dir: string;
	constructor(dir: string) {
		this.dir = dir;
	}
	async has(name: string): Promise<boolean> {
		return existsSync(join(this.dir, name));
	}
	async read(name: string): Promise<Readable> {
		if (!(await this.has(name))) throw new Error(`${this.dir} has no ${name}`);
		return createReadStream(join(this.dir, name));
	}
	async write(name: string, file: string): Promise<void> {
		mkdirSync(this.dir, { recursive: true });
		copyFileSync(file, join(this.dir, name + ".part"));
		renameSync(join(this.dir, name + ".part"), join(this.dir, name));
	}
}

/**
 * A Hugging Face dataset repository, the blobs under its blobs/. A public one is read without a token; a private one
 * is read, and either is written, with `$HF_TOKEN` or the token `hf auth login` saved. Writing goes through the `hf`
 * command (the huggingface_hub package: scripts/tools.ts installs it into the data root's tools/venv), which creates
 * the repository on the first write.
 */
class HuggingFaceStore implements Store {
	readonly repo: string;
	readonly isPrivate: boolean;

	constructor(repo: string, isPrivate: boolean) {
		// (The Hub refuses a name with `--` or `..` in it.)
		if (!/^[\w.-]+\/[\w.-]+$/.test(repo) || /--|\.\./.test(repo))
			throw new Error(`not a Hugging Face repository: ${repo}`);
		this.repo = repo;
		this.isPrivate = isPrivate;
	}

	/** The blob's response, or undefined if the repository has no such blob. */
	async #request(name: string, method: "GET" | "HEAD"): Promise<Response | undefined> {
		const token = hfToken();
		// (A stored blob redirects to a signed URL on another host; fetch drops the token on the way there.)
		const res = await fetch(`https://huggingface.co/datasets/${this.repo}/resolve/main/blobs/${name}`, {
			method,
			headers: token ? { authorization: `Bearer ${token}` } : {},
		});
		if (res.ok) return res;
		await res.body?.cancel();
		if (res.status === 404) return undefined;
		// (To a reader it may not see, the Hub answers 401 for a repository whether or not it exists.)
		if (res.status === 401 || res.status === 403)
			throw new Error(
				`${this.repo} on Hugging Face is private, or not there: ` +
					(token ? "this token cannot read it" : "set HF_TOKEN, or log in with `hf auth login`"),
			);
		throw new Error(`Hugging Face ${res.status} for ${name} in ${this.repo}`);
	}

	async has(name: string): Promise<boolean> {
		return !!(await this.#request(name, "HEAD"));
	}

	async read(name: string): Promise<Readable> {
		const res = await this.#request(name, "GET");
		if (!res?.body) throw new Error(`${this.repo} has no ${name}`);
		// (fetch's stream type and node:stream's are the same object, declared twice.)
		return Readable.fromWeb(res.body as WebReadableStream);
	}

	async write(name: string, file: string): Promise<void> {
		const inVenv = join(CORPORA, "tools/venv/bin/hf");
		const upload = sink(existsSync(inVenv) ? inVenv : "hf", [
			"upload",
			this.repo,
			file,
			`blobs/${name}`,
			"--repo-type=dataset",
			this.isPrivate ? "--private" : "--no-private",
			`--commit-message=Add ${name}`,
			"--quiet",
		]);
		upload.stdin.end();
		await upload.done;
	}
}

/** The Hugging Face token of this environment or of a logged-in `hf`, if there is one. */
function hfToken(): string | undefined {
	if (process.env.HF_TOKEN) return process.env.HF_TOKEN;
	const saved =
		process.env.HF_TOKEN_PATH || join(process.env.HF_HOME || join(homedir(), ".cache/huggingface"), "token");
	return existsSync(saved) ? readFileSync(saved, "utf8").trim() : undefined;
}

const opened = new Map<string, Store>();

/**
 * The store an entry's blob is in: the lock's public one, or its private one for an entry marked `private`.
 * `$REDACT_STORE` names one store to use for both (a directory holding a copy of everything, say).
 */
function storeOf(lock: Lock, entry: Pick<Entry, "private">): Store {
	const kind = entry.private ? "private" : "public";
	const spec = process.env.REDACT_STORE || lock.stores[kind];
	if (!spec) throw new Error(`no ${kind} store: set "stores" in ${LOCK_FILE}, or $REDACT_STORE`);
	let store = opened.get(`${kind} ${spec}`);
	if (!store) {
		store = spec.startsWith("hf:")
			? new HuggingFaceStore(spec.slice("hf:".length), !!entry.private)
			: new DirectoryStore(spec);
		opened.set(`${kind} ${spec}`, store);
	}
	return store;
}

const blobName = (entry: Pick<Entry, "sha256">) => `${entry.sha256}.zst`;

// ---------------------------------------------------------------- pull

/** Passes its input through, hashing and counting it. */
class Meter extends Transform {
	readonly hash = createHash("sha256");
	bytes = 0;
	override _transform(chunk: Buffer, _encoding: BufferEncoding, done: TransformCallback): void {
		this.hash.update(chunk);
		this.bytes += chunk.length;
		done(null, chunk);
	}
}

/** A child process's end: rejects if it cannot start or exits with an error. */
function exit(child: ChildProcess, command: string): Promise<void> {
	return new Promise<void>((resolve, reject) => {
		child.on("error", (e) => reject(new Error(`${command}: ${e.message}`)));
		child.on("close", (code) => (code === 0 ? resolve() : reject(new Error(`${command} exited with ${code}`))));
	});
}

/**
 * A stream into a child's input that goes on taking what it is given after the child has stopped reading. (tar stops
 * at an archive's end marker, before the padding that follows it; whether the child did its work is its exit's to say.)
 */
function feed(stdin: Writable): Writable {
	let reading = true;
	const stopped = () => void (reading = false);
	stdin.on("error", stopped).on("close", stopped);
	return new Writable({
		write(chunk: Buffer, _encoding: BufferEncoding, done: () => void) {
			if (reading) stdin.write(chunk, () => done());
			else done();
		},
		final(done: () => void) {
			// (Its end may be answered with an error, when the child goes before the last of its input is flushed.)
			if (reading) stdin.end(() => done());
			else done();
		},
	});
}

/** A child process to pipe into, and its end. */
function sink(command: string, args: string[]): { stdin: Writable; done: Promise<void> } {
	const child = spawn(command, args, { stdio: ["pipe", "inherit", "inherit"] });
	return { stdin: child.stdin, done: exit(child, command) };
}

/**
 * Fetches one entry into the data root. The content is written beside its place and moved there only once its hash
 * is the lock's, so a failed or forged download leaves what was there.
 */
async function fetchEntry(lock: Lock, path: string, entry: Entry): Promise<void> {
	const dest = join(CORPORA, path);
	const part = dest + ".part";
	rmSync(part, { recursive: true, force: true });
	mkdirSync(entry.dir ? part : dirname(dest), { recursive: true });
	const meter = new Meter();
	const blob = await storeOf(lock, entry).read(blobName(entry));
	try {
		// (The window: `push` compresses with one of 128 MB, the most a decoder takes without being told.)
		const content = [blob, createZstdDecompress(), meter] as const;
		if (entry.dir) {
			const tar = sink("tar", ["-xf", "-", "-C", part]);
			await Promise.all([pipeline(...content, feed(tar.stdin)), tar.done]);
		} else await pipeline(...content, createWriteStream(part));
		const sha256 = meter.hash.digest("hex");
		if (sha256 !== entry.sha256)
			throw new Error(`${path}: the store's content has hash ${sha256}, the lock ${entry.sha256}`);
	} catch (e) {
		rmSync(part, { recursive: true, force: true });
		throw e;
	}
	rmSync(dest, { recursive: true, force: true });
	renameSync(part, dest);
	if (entry.dir) seen[path] = { sha256: entry.sha256 };
	else {
		const stat = statSync(dest);
		seen[path] = { sha256: entry.sha256, bytes: stat.size, mtimeMs: stat.mtimeMs };
	}
	saveSeen();
}

async function pull(lock: Lock, paths: string[], all: boolean, force: boolean): Promise<void> {
	const chosen = all
		? Object.keys(lock.entries)
		: paths.length
			? select(lock, paths)
			: Object.keys(lock.entries).filter((p) => lock.entries[p].everyday);
	let here = 0;
	for (const path of chosen) {
		const entry = lock.entries[path];
		const state = await local(path, entry);
		if (state === "ok") here++;
		else if (state !== "missing" && !force) {
			const why = state === "unknown" ? "did not come from the store" : "differs from the lock";
			console.log(`${path}: kept, the local copy ${why} (--force replaces it)`);
		} else {
			process.stdout.write(`${path} (${size(entry.packed)} to fetch, ${size(entry.bytes)} here) … `);
			const t0 = performance.now();
			try {
				await fetchEntry(lock, path, entry);
				console.log(`${((performance.now() - t0) / 1000).toFixed(1)} s`);
				here++;
			} catch (e) {
				// (One entry's failure, a private store this reader has no access to above all, does not stop the rest.)
				console.log(`not fetched: ${(e as Error).message}`);
			}
		}
	}
	console.log(`${here} of ${chosen.length} entries are here as locked, under ${CORPORA}`);
	if (here < chosen.length) process.exitCode = 1;
}

// ---------------------------------------------------------------- push

/**
 * Packs the local copy of `path` into a blob file and returns the entry that describes it. (zstd level 19 with a
 * 128 MB window: these are written once and read on every fresh clone. Each thread of it holds about a gigabyte, so
 * no more than four.)
 */
async function pack(path: string, tmp: string): Promise<{ entry: Entry; blob: string }> {
	const file = join(CORPORA, path);
	const dir = statSync(file).isDirectory();
	const blob = join(tmp, "packing.zst");
	const meter = new Meter();
	const zstd = sink("zstd", ["-19", "--long=27", `-T${Math.min(4, availableParallelism())}`, "-q", "-f", "-o", blob]);
	if (dir) {
		const tar = spawn("tar", ["-cf", "-", "-C", file, "."], { stdio: ["ignore", "pipe", "inherit"] });
		await Promise.all([pipeline(tar.stdout, meter, zstd.stdin), exit(tar, "tar"), zstd.done]);
	} else await Promise.all([pipeline(createReadStream(file), meter, zstd.stdin), zstd.done]);
	const entry: Entry = { sha256: meter.hash.digest("hex"), bytes: meter.bytes, packed: statSync(blob).size };
	if (dir) entry.dir = true;
	return { entry, blob };
}

/**
 * Adds or replaces entries from the data root. An entry keeps what it was pushed as: `everyday` and `private` are only
 * ever turned on here (a push that left `--private` out must not publish what was private; `forget` it first to do
 * that on purpose).
 */
async function push(
	lock: Lock,
	paths: string[],
	flags: Pick<Entry, "everyday" | "private">,
	note?: string,
): Promise<void> {
	if (!paths.length) throw new Error("push: name the files or directories under the data root to store");
	const tmp = join(CORPORA, ".data-tmp");
	mkdirSync(tmp, { recursive: true });
	try {
		for (const raw of paths) {
			const path = raw.replace(/\/+$/, "");
			checkPath(path);
			const nested = Object.keys(lock.entries).find((p) => p.startsWith(path + "/") || path.startsWith(p + "/"));
			if (nested) throw new Error(`${path}: ${nested} is an entry already, and one entry cannot hold another`);
			if (!existsSync(join(CORPORA, path))) throw new Error(`${path}: not in ${CORPORA}`);
			const before = lock.entries[path];
			const kept: Pick<Entry, "everyday" | "private" | "note"> = {};
			if (flags.everyday || before?.everyday) kept.everyday = true;
			if (flags.private || before?.private) kept.private = true;
			if (note ?? before?.note) kept.note = note ?? before?.note;
			const store = storeOf(lock, kept);
			// (A file's content is known without packing it; a directory's only as the tar that packing makes.)
			const sameFile =
				before &&
				!before.dir &&
				statSync(join(CORPORA, path)).isFile() &&
				(await localFileHash(path)) === before.sha256;
			let entry: Entry;
			if (sameFile && (await store.has(blobName(before))))
				entry = { sha256: before.sha256, bytes: before.bytes, packed: before.packed };
			else {
				process.stdout.write(`${path} … `);
				const packed = await pack(path, tmp);
				entry = packed.entry;
				if (await store.has(blobName(entry))) console.log(`in the store already (${size(entry.packed)})`);
				else {
					await store.write(blobName(entry), packed.blob);
					console.log(`${size(entry.bytes)} stored as ${size(entry.packed)}`);
				}
				if (entry.dir) seen[path] = { sha256: entry.sha256 };
				saveSeen();
			}
			lock.entries[path] = { ...entry, ...kept };
			writeLock(lock);
		}
	} finally {
		rmSync(tmp, { recursive: true, force: true });
	}
}

// ---------------------------------------------------------------- status

function size(bytes: number): string {
	return bytes >= 1e9
		? `${(bytes / 1e9).toFixed(2)} GB`
		: bytes >= 1e6
			? `${(bytes / 1e6).toFixed(0)} MB`
			: `${Math.ceil(bytes / 1e3)} kB`;
}

async function status(lock: Lock): Promise<void> {
	const rows: string[][] = [];
	const total = { bytes: 0, packed: 0, here: 0 };
	for (const [path, entry] of Object.entries(lock.entries)) {
		const state = await local(path, entry);
		total.bytes += entry.bytes;
		total.packed += entry.packed;
		if (state !== "missing") total.here += entry.bytes;
		const what = { ok: "here", missing: "-", differs: "differs", unknown: "here, not from the store" }[state];
		const marks = (entry.everyday ? " *" : "") + (entry.private ? " (private)" : "");
		rows.push([path + (entry.dir ? "/" : ""), size(entry.bytes), size(entry.packed), what + marks, entry.note ?? ""]);
	}
	const width = [0, 1, 2, 3].map((i) => Math.max(...rows.map((r) => r[i].length), 4));
	for (const [path, bytes, packed, what, note] of rows)
		console.log(
			`${path.padEnd(width[0])}  ${bytes.padStart(width[1])}  ${packed.padStart(width[2])}  ${what.padEnd(width[3])}  ${note}`.trimEnd(),
		);
	const stores = process.env.REDACT_STORE || `${lock.stores.public}, private: ${lock.stores.private}`;
	console.log(
		`\n${rows.length} entries: ${size(total.bytes)}, ${size(total.packed)} to fetch; ${size(total.here)} here, under ${CORPORA}` +
			`\nstore: ${stores}    * fetched by a plain \`pull\``,
	);
}

// ---------------------------------------------------------------- the command line

const args = new Args();
const force = args.flag("force");
const all = args.flag("all");
const flags: Pick<Entry, "everyday" | "private"> = {};
if (args.flag("everyday")) flags.everyday = true;
if (args.flag("private")) flags.private = true;
const note = args.opt("note");
const [command, ...paths] = args.rest;
try {
	const lock = readLock();
	if (command === "status" && !paths.length) await status(lock);
	else if (command === "pull") await pull(lock, paths, all, force);
	else if (command === "push") await push(lock, paths, flags, note);
	else if (command === "forget" && paths.length) {
		for (const path of select(lock, paths)) delete lock.entries[path];
		writeLock(lock);
	} else {
		console.error(
			"usage: node scripts/data.ts status | pull [PATH…] [--all] [--force] | push PATH… [--everyday] [--private] [--note TEXT] | forget PATH…",
		);
		process.exitCode = 2;
	}
} catch (e) {
	console.error(`data: ${(e as Error).message}`);
	process.exitCode = 1;
}
