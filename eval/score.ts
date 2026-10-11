/**
 * Scoring shared by every evaluation. A secret counts as caught only if no usable part of it survives:
 * not the whole value, and (for values of 12 or more characters) not a run of it long enough to matter:
 * half of it, at least 8 characters. Text marked `keep` must survive verbatim.
 */
import { readFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";

export interface Case {
	id: string;
	/** What the case is, for per-kind breakdowns. */
	kind?: string;
	/** Where the text sits (env, code, log, chat, ...), for per-context breakdowns. */
	context?: string;
	text: string;
	/** Values that must not survive. */
	secrets?: string[];
	/** Values that must survive verbatim. */
	keep?: string[];
	/** Where the text came from, passed to the redactor as a hint. */
	hint?: { command?: string; path?: string };
	/** Values the redactor is told about up front. */
	known?: string[];
	source?: string;
}

/** The longest run of `secret` that appears in `out`. */
export function longestSurvivingRun(secret: string, out: string): number {
	if (out.includes(secret)) return secret.length;
	// Binary search on the run length: any run of length L surviving implies one of every shorter length.
	let lo = 0;
	let hi = secret.length - 1;
	while (lo < hi) {
		const mid = Math.ceil((lo + hi) / 2);
		let found = false;
		for (let i = 0; i + mid <= secret.length && !found; i++) found = out.includes(secret.slice(i, i + mid));
		if (found) lo = mid;
		else hi = mid - 1;
	}
	return lo;
}

export function leaked(secret: string, out: string): boolean {
	if (out.includes(secret)) return true;
	if (secret.length < 12) return false;
	const limit = Math.max(8, Math.ceil(secret.length / 2));
	return longestSurvivingRun(secret, out) >= limit;
}

export interface CaseResult {
	id: string;
	kind?: string;
	context?: string;
	leaked: string[];
	caught: string[];
	lost: string[];
	kept: string[];
	ms: number;
}

export function scoreCase(c: Case, out: string, ms: number): CaseResult {
	const r: CaseResult = { id: c.id, kind: c.kind, context: c.context, leaked: [], caught: [], lost: [], kept: [], ms };
	for (const s of c.secrets ?? []) (leaked(s, out) ? r.leaked : r.caught).push(s);
	for (const k of c.keep ?? []) (out.includes(k) ? r.kept : r.lost).push(k);
	return r;
}

export interface Summary {
	secrets: number;
	caught: number;
	recall: number;
	keeps: number;
	lost: number;
	lossRate: number;
}

export function summarize(results: CaseResult[]): Summary {
	let secrets = 0;
	let caught = 0;
	let keeps = 0;
	let lost = 0;
	for (const r of results) {
		secrets += r.caught.length + r.leaked.length;
		caught += r.caught.length;
		keeps += r.kept.length + r.lost.length;
		lost += r.lost.length;
	}
	return { secrets, caught, recall: secrets ? caught / secrets : 1, keeps, lost, lossRate: keeps ? lost / keeps : 0 };
}

export function breakdown(results: CaseResult[], by: (r: CaseResult) => string | undefined): Map<string, Summary> {
	const groups = new Map<string, CaseResult[]>();
	for (const r of results) {
		const k = by(r) ?? "?";
		if (!groups.has(k)) groups.set(k, []);
		groups.get(k)!.push(r);
	}
	return new Map([...groups].sort().map(([k, v]) => [k, summarize(v)]));
}

/**
 * A corpus file's text. The repository keeps corpora gzipped (`dev.jsonl.gz`): the fake credentials in them are then
 * no text a secret scanner reads, GitHub's push protection among them. A plain `.jsonl` is read as it is.
 */
export function readCorpus(file: string): string {
	const bytes = readFileSync(file);
	return (file.endsWith(".gz") ? gunzipSync(bytes) : bytes).toString("utf8");
}

/** A corpus file's name: `dev_b.jsonl.gz` (or a plain `dev_b.jsonl`). Group 1 is the corpus's name, `dev_b`. */
export const CORPUS_FILE = /^(.+)\.jsonl(?:\.gz)?$/;

/** Cases from a JSONL file (one per line, gzipped or not) or a JSON array. */
export function loadCases(file: string): Case[] {
	const text = readCorpus(file);
	if (file.endsWith(".json")) return JSON.parse(text);
	return text
		.split("\n")
		.filter((l) => l.trim())
		.map((l) => JSON.parse(l));
}
