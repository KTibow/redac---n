import { findFormats } from "./formats.ts";
import { isReplaceable } from "./known.ts";
import { hasCredentialWord, isCredentialName, isSettingName, namesPasswordOrPin } from "./names.ts";
import { findNamed } from "./named.ts";
import { keepReason } from "./policy.ts";
import { findStructure, isLiteralPassword } from "./structure.ts";
import { naturalness } from "./charlm.ts";
import type { Finding } from "./types.ts";
import { hasThreeClasses, isInert, isRandomToken } from "./values.ts";

/**
 * The secrets in an environment, as known values: variables whose name has a credential word (`*_API_KEY`, `*_TOKEN`,
 * `BW_SESSION`, read widely), a vendor's token under any name, and the passwords and keys inside any variable that
 * the detectors read there (a URL's, a connection string's: `DATABASE_URL`, `password=` in a DSN). Not what the
 * decision stage keeps on purpose: a key public by design, or under a browser's prefix (`NEXT_PUBLIC_STRIPE_KEY=pk_live_…`).
 * Only values a Redactor accepts as known values (the rule `addKnown` applies) are returned; a short or plain-word value
 * is left out. `new Redactor({ known: fromEnvironment(process.env) })`.
 */
export function fromEnvironment(env: Record<string, string | undefined>): { value: string; label: string }[] {
	const out: { value: string; label: string }[] = [];
	const add = (value: string, label: string) => {
		if (!out.some((o) => o.value === value)) out.push({ value, label });
	};
	for (const [name, value] of Object.entries(env)) {
		if (!value || value.length < 6 || value.length > 16_384) continue;
		// (Judged as the decision stage judges the same value on a `NAME=value` line, with the rule that read it.)
		const line = `${name}=${value}`;
		const kept = (f: Pick<Finding, "start" | "end" | "rule">) =>
			keepReason(line, {
				...f,
				start: f.start + name.length + 1,
				end: f.end + name.length + 1,
				kind: "secret",
				name,
				confidence: 1,
			}) !== undefined;
		// (Read widely: the caller's own environment, where a credential missed goes to a provider. A credential word anywhere
		// in the name or a session's at its end, `BW_SESSION`, `TF_TOKEN_app_terraform_io`, `ACTIONS_ID_TOKEN_REQUEST_TOKEN`,
		// unless the name ends as a setting's or a generator didn't make the value: `TOKEN_ENDPOINT`, `DESKTOP_SESSION=ubuntu-wayland`.
		// A password's name takes any value, `MATCH_PASSWORD`; a webhook's URL is its secret whole.)
		const widened =
			!isSettingName(name) &&
			((namesPasswordOrPin(name) && !isInert(value)) ||
				((hasCredentialWord(name) || /(?:^|_)(?:SESSION|PEPPER)$/i.test(name)) && isGenerated(value)));
		const secretName = isCredentialName(name) || /WEBHOOK/i.test(name) || widened;
		if (secretName && !isInert(value) && !kept({ start: 0, end: value.length, rule: "named:assign" }))
			add(value, `$${name}`);
		// (A vendor's token under any name, `CI_DEPLOY=ghp_…`, a Slack webhook URL; one public by design is kept, a
		// publishable key or a browser's Google key.)
		else for (const f of findFormats(value)) if (!kept(f)) add(value.slice(f.start, f.end), `${f.kind} in $${name}`);
		// (What the structure and name readers find inside the value: a URL's password, a connection string's, a DSN's
		// `password=`. A literal one, as the URL readers take it: not `${DB_PASSWORD}`, `<password>`, `%PASSWORD%`.)
		if (!/[=:]/.test(value)) continue;
		for (const f of [...findStructure(value), ...findNamed(value)]) {
			const secret = value.slice(f.start, f.end);
			if (f.confidence < 0.9 || !isLiteralPassword(secret) || kept(f)) continue;
			add(/^structure:url/.test(f.rule) ? decodeSafe(secret) : secret, `${f.kind} in $${name}`);
		}
	}
	// (Only what a Redactor takes as a known value, so the caller isn't told a `JWT_SECRET=devsecret` is protected when it isn't.)
	return out.filter((o) => isReplaceable(o.value.trim()));
}

/**
 * A value a generator made: a random token (`Xk9mQ2pLrTvB7nWz`), or one with symbols in it, of all three other classes
 * and no word (`Pq7!zR2@xW9#kL4m`); not a URL or a path.
 */
function isGenerated(value: string): boolean {
	return (
		isRandomToken(value, 12) ||
		(value.length >= 12 &&
			/^[!-~]+$/.test(value) &&
			hasThreeClasses(value) &&
			/[^A-Za-z0-9]/.test(value) &&
			!/:\/\/|^[/~.$]/.test(value) &&
			naturalness(value) < 0.3)
	);
}

function decodeSafe(v: string): string {
	try {
		return decodeURIComponent(v);
	} catch {
		return v;
	}
}
