/** Shapes of redacted values, shared by the real-text evaluations. */

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
