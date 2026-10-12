import { findFormats } from "./formats.ts";
import { isReplaceable } from "./known.ts";
import { hasCredentialWord, isCredentialName, isSettingName, namesPasswordOrPin } from "./names.ts";
import { isLiteralPassword } from "./structure.ts";
import { urls } from "./urls.ts";
import { naturalness } from "./charlm.ts";
import { hasThreeClasses, isInert, isRandomToken } from "./values.ts";

/**
 * The secrets in an environment, as known values: variables whose name has a credential word (`*_API_KEY`, `*_TOKEN`,
 * `BW_SESSION`, read widely), a vendor's token under any name, and URL passwords inside any variable. Only values a
 * Redactor accepts as known values (the rule `addKnown` applies) are returned; a short or plain-word value is left out.
 * `new Redactor({ known: fromEnvironment(process.env) })`.
 */
export function fromEnvironment(env: Record<string, string | undefined>): { value: string; label: string }[] {
	const out: { value: string; label: string }[] = [];
	for (const [name, value] of Object.entries(env)) {
		if (!value || value.length < 6 || value.length > 16_384) continue;
		// (Read widely: the caller's own environment, where a credential missed goes to a provider. A credential word anywhere
		// in the name or a session's at its end, `BW_SESSION`, `TF_TOKEN_app_terraform_io`, `ACTIONS_ID_TOKEN_REQUEST_TOKEN`,
		// unless the name ends as a setting's or a generator didn't make the value: `TOKEN_ENDPOINT`, `DESKTOP_SESSION=ubuntu-wayland`.
		// A password's name takes any value, `MATCH_PASSWORD`; a webhook's URL is its secret whole.)
		const widened =
			!isSettingName(name) &&
			((namesPasswordOrPin(name) && !isInert(value)) ||
				((hasCredentialWord(name) || /(?:^|_)(?:SESSION|PEPPER)$/i.test(name)) && isGenerated(value)));
		const secretName = isCredentialName(name) || /WEBHOOK/i.test(name) || widened;
		if (secretName && !isInert(value)) out.push({ value, label: `$${name}` });
		// (A vendor's token under any name: `CI_DEPLOY=ghp_…`, a Slack webhook URL.)
		else
			for (const f of findFormats(value))
				if (!out.some((o) => o.value === value.slice(f.start, f.end)))
					out.push({ value: value.slice(f.start, f.end), label: `${f.kind} in $${name}` });
		// (A literal password, as the URL readers take one: not `${DB_PASSWORD}`, `<password>`, `%PASSWORD%`.)
		for (const url of value.includes("://") ? urls(value) : [])
			if (url.password && isLiteralPassword(url.password.value))
				out.push({ value: decodeSafe(url.password.value), label: `password in $${name}` });
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
