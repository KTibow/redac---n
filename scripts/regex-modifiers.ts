/**
 * Rewrites a regex without inline modifiers (`(?i:…)`, `(?-i:…)`, `(?s:…)`, ES2025, missing before V8
 * 12.5, so Node 20 and 22 can't compile them) and without the `i` and `s` flags: case-insensitive parts
 * spell out both cases (`a` → `[aA]`, `[a-f]` → `[a-fA-F]`), dot-all dots become `[\s\S]`.
 *
 * Exact for everything it accepts; it throws on what it can't express (a back-reference inside a
 * case-insensitive part, which would compare case-sensitively after the rewrite), so a catalog update
 * fails loudly instead of changing a rule.
 */
export function withoutModifiers(src: string, flags: string): [string, string] {
	if (!/\(\?-?[is]+(?:-[is]+)?:/.test(src) && !/[is]/.test(flags)) return [src, flags];
	const unicode = flags.includes("u") || flags.includes("v");
	const stack: { ci: boolean; dot: boolean }[] = [];
	let ci = flags.includes("i");
	let dot = flags.includes("s");
	let out = "";
	let i = 0;

	/** The escape at `i`: its source, and the character it stands for if it's one character. */
	const escape = (): { raw: string; char?: number } => {
		const rest = src.slice(i);
		const m =
			/^\\(?:x([0-9a-fA-F]{2})|u\{([0-9a-fA-F]+)\}|u([0-9a-fA-F]{4})|c([A-Za-z])|([0-7]{1,3})|k<[^>]*>|[pP]\{[^}]*\}|([\s\S]))/.exec(
				rest,
			)!;
		i += m[0].length;
		const raw = m[0];
		const hex = m[1] ?? m[2] ?? m[3];
		if (hex) return { raw, char: parseInt(hex, 16) };
		if (m[4]) return { raw, char: m[4].toUpperCase().charCodeAt(0) % 32 };
		const c = m[6];
		if (c === undefined) return { raw }; // `\k<…>`, `\p{…}`, an octal or a back-reference
		if (/[dDwWsSbB]/.test(c)) return { raw };
		if (/[1-9]/.test(c)) return { raw };
		const control: Record<string, number> = { n: 10, r: 13, t: 9, f: 12, v: 11, "0": 0 };
		if (c in control) return { raw, char: control[c] };
		if ((c === "p" || c === "P") && unicode) return { raw };
		return { raw, char: c.charCodeAt(0) };
	};
	const lit = (code: number) =>
		code < 0x10000 || !unicode ? `\\u${code.toString(16).padStart(4, "0")}` : `\\u{${code.toString(16)}}`;
	const isBackReference = (raw: string) => /^\\(?:[1-9]|k<)/.test(raw);

	while (i < src.length) {
		const c = src[i];
		if (c === "\\") {
			const e = escape();
			if (ci && isBackReference(e.raw)) throw new Error(`back-reference in a case-insensitive part: ${src}`);
			const ch = e.char === undefined ? "" : String.fromCodePoint(e.char);
			out += ci && /^[A-Za-z]$/.test(ch) ? `[${ch.toLowerCase()}${ch.toUpperCase()}]` : e.raw;
		} else if (c === "[") {
			// A class, rebuilt from its items with every character escaped, plus the other case of its letters.
			i++;
			const negated = src[i] === "^";
			if (negated) i++;
			const items: string[] = [];
			const ranges: [number, number][] = [];
			while (i < src.length && src[i] !== "]") {
				let lo: number | undefined;
				let raw: string;
				if (src[i] === "\\") {
					const e = escape();
					raw = e.raw;
					lo = e.char;
				} else {
					// Code points with the u/v flags, UTF-16 units without (as the engine reads them).
					lo = unicode ? src.codePointAt(i)! : src.charCodeAt(i);
					raw = unicode ? String.fromCodePoint(lo) : src[i];
					i += raw.length;
				}
				if (lo === undefined) {
					items.push(raw); // `\d`, `\w`, `\p{…}`
					continue;
				}
				let hi = lo;
				if (src[i] === "-" && src[i + 1] !== "]" && i + 1 < src.length) {
					i++;
					if (src[i] === "\\") {
						const e = escape();
						if (e.char === undefined) {
							// `[a-\d]` isn't a range: the `-` is a character.
							items.push(lit(lo), lit(45), e.raw);
							continue;
						}
						hi = e.char;
					} else {
						hi = unicode ? src.codePointAt(i)! : src.charCodeAt(i);
						i += unicode ? String.fromCodePoint(hi).length : 1;
					}
				}
				items.push(lo === hi ? lit(lo) : `${lit(lo)}-${lit(hi)}`);
				ranges.push([lo, hi]);
			}
			i++;
			if (ci) {
				// For each range, the letters it holds, in the other case.
				for (const [lo, hi] of ranges) {
					for (const [a, z, shift] of [
						[65, 90, 32],
						[97, 122, -32],
					]) {
						const from = Math.max(lo, a);
						const to = Math.min(hi, z);
						if (from <= to) items.push(from === to ? lit(from + shift) : `${lit(from + shift)}-${lit(to + shift)}`);
					}
				}
			}
			out += `[${negated ? "^" : ""}${items.join("")}]`;
		} else if (c === "(") {
			stack.push({ ci, dot });
			const mod = /^\(\?([is]*)(?:-([is]+))?:/.exec(src.slice(i));
			if (mod && (mod[1] || mod[2])) {
				if (mod[1].includes("i")) ci = true;
				if (mod[1].includes("s")) dot = true;
				if (mod[2]?.includes("i")) ci = false;
				if (mod[2]?.includes("s")) dot = false;
				out += "(?:";
				i += mod[0].length;
			} else {
				// `(?:`, `(?=`, `(?!`, `(?<=`, `(?<!`, `(?<name>`: copied as they are.
				const head = /^\((?:\?(?:<[A-Za-z_]\w*>|<[=!]|[:=!]))?/.exec(src.slice(i))![0];
				out += head;
				i += head.length;
			}
		} else if (c === ")") {
			({ ci, dot } = stack.pop() ?? { ci, dot });
			out += c;
			i++;
		} else if (c === "{" && /^\{\d+(?:,\d*)?\}/.test(src.slice(i))) {
			const q = /^\{\d+(?:,\d*)?\}/.exec(src.slice(i))![0];
			out += q;
			i += q.length;
		} else if (c === "." && dot) {
			out += "[\\s\\S]";
			i++;
		} else if (ci && /[A-Za-z]/.test(c)) {
			out += `[${c.toLowerCase()}${c.toUpperCase()}]`;
			i++;
		} else {
			out += c;
			i++;
		}
	}
	return [out, flags.replace(/[is]/g, "")];
}
