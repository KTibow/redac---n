/** Shapes of redacted values, shared by the real-text evaluations. */
import { findFormats } from "../src/formats.ts";
import { isCredentialName } from "../src/names.ts";

/** What a redacted value looks like, to tell damage (a SHA hidden) from plausible hits. */
export function shapeOf(v: string): string {
	if (/^[0-9a-f]{40}$/i.test(v)) return "hex40-sha1";
	if (/^[0-9a-f]{64}$/i.test(v)) return "hex64-sha256";
	if (/^[0-9a-f]{32}$/i.test(v)) return "hex32-md5";
	if (/^[0-9a-f]+$/i.test(v)) return "hex-other";
	if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v)) return "uuid";
	if (v.includes("PRIVATE KEY")) return "private-key";
	if (/^eyJ/.test(v)) return "jwt";
	if (/^[A-Za-z0-9+/]+={0,2}$/.test(v) && v.length >= 40 && /[+/]/.test(v)) return "base64";
	if (/^[A-Za-z0-9_-]+$/.test(v) && /\d/.test(v) && /[a-z]/.test(v) && /[A-Z]/.test(v)) return "b62ish";
	if (/^[a-z0-9]+$/.test(v)) return "lower-alnum";
	if (/\s/.test(v)) return "spaced";
	return "other";
}
export const DAMAGE = new Set(["hex40-sha1", "hex64-sha256", "uuid"]);

/** What a redaction on ordinary text is, for every tool alike: the bars of docs/real-text.svg. */
export const REDACTION_KINDS = ["credential-shaped", "hex", "word or placeholder", "other"] as const;
export type RedactionKind = (typeof REDACTION_KINDS)[number];

const HEX =
	/(?:^|[^A-Za-z0-9+/])(?:[0-9a-f]{32}(?:[0-9a-f]{8}|[0-9a-f]{32}|[0-9a-f]{96})?|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?![A-Za-z0-9+/])/i;
const WORD = /^(?:[A-Za-z]{1,12}|[a-z]+[-_][a-z]+|x{3,}|\*{3,}|<[^<>]{1,40}>|\$\{?\w+\}?|[a-z]{3,10}\d{1,4})$/;
const ASSIGNED = /([A-Za-z_][\w.-]{0,60})["']?\s*(?:=|:|=>|:=)\s*["'`]?([^\s"'`,;]{1,200})/g;

/**
 * A redacted value by what it is, judged from itself and the text before it on its line, so that no tool is described
 * by its own rule names: credential-shaped (a private key, a vendor's format, a value under a credential's name or a
 * URL's password, a random-looking token), hex (32, 40, 64 or 128 digits: a digest, an ID or a key) or a UUID, a word or
 * a placeholder, or other. A redacted whole
 * line (detect-secrets reports lines) or a name with its value is judged by what's in it.
 */
export function redactionKind(value: string, before: string): RedactionKind {
	const v = value.trim();
	if (/PRIVATE KEY|^-----BEGIN /.test(v)) return "credential-shaped";
	if (findFormats(v).some((f) => f.end - f.start >= Math.min(v.length / 2, 20))) return "credential-shaped";
	if (/:\/\/[^\s/@:]*:$/.test(before) || /[a-z][\w+.-]*:\/\/[^\s/@:]*:[^\s/@]+@/i.test(v)) return "credential-shaped";
	if (/\s/.test(v) || (v.length > 40 && /[=:]/.test(v))) {
		if (HEX.test(v)) return "hex";
		for (const m of v.matchAll(ASSIGNED))
			if (isCredentialName(m[1].split(".").at(-1)!)) return redactionKind(m[2], `${m[1]}=`);
		return "other";
	}
	if (HEX.test(v) && v.replace(HEX, "").replace(/^[^A-Za-z0-9]+|[^A-Za-z0-9]+$/g, "").length < 4) return "hex";
	if (WORD.test(v)) return "word or placeholder";
	const name = /([A-Za-z_][\w.-]{0,60})["']?\s*(?:=|:|=>|:=)\s*["'`]?$/.exec(before)?.[1];
	if (name && isCredentialName(name.split(".").at(-1)!)) return "credential-shaped";
	if (/^[A-Za-z0-9+/=_.-]{16,}$/.test(v) && /\d/.test(v) && /[A-Za-z]/.test(v)) return "credential-shaped";
	return "other";
}
