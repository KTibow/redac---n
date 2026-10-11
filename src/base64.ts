/** Base64 and base64url (padded or not) decoding, without throwing. */

/** The bytes base64 or base64url encodes, or undefined if it isn't base64. */
export function base64Bytes(b64: string): Uint8Array | undefined {
	const binary = base64Binary(b64);
	return binary === undefined ? undefined : Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

/** `b64` without its trailing `=` padding (a backward scan: `/=+$/` retries from every `=` of a long run). */
function withoutPadding(b64: string): string {
	let end = b64.length;
	while (end > 0 && b64[end - 1] === "=") end--;
	return b64.slice(0, end);
}

/** The bytes base64 or base64url encodes, one character each (Latin-1), or undefined if it isn't base64. */
export function base64Binary(b64: string): string | undefined {
	const t = withoutPadding(b64.replace(/-/g, "+").replace(/_/g, "/"));
	// (atob accepts the rest: it ignores blanks, which the test refuses, and nonzero bits left over at the end.)
	if (t.length % 4 === 1 || !/^[A-Za-z0-9+/]*$/.test(t)) return undefined;
	return atob(t.padEnd(Math.ceil(t.length / 4) * 4, "="));
}

/**
 * The bytes base64 text decodes to, for reading what it holds: as base64Bytes, but text cut one character past a whole
 * group (tool output cut short, `head -c`) has that character left off rather than failing whole.
 */
export function base64Prefix(b64: string): Uint8Array | undefined {
	const t = withoutPadding(b64);
	return base64Bytes(t.length % 4 === 1 ? t.slice(0, -1) : t);
}
