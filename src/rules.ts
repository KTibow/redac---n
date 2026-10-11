/**
 * What the pipeline knows about a finding's rule beyond its name. A rule is named `layer:name` (`format:GitHub
 * token`, `named:assign`, `file:opaque`), and the stages that treat findings differently by where they came from ask
 * here, by property, rather than each matching rule names of its own.
 */

/** The detectors and the other sources of findings. */
export type RuleLayer =
	| "format"
	| "structure"
	| "named"
	| "unnamed"
	| "file"
	| "command"
	| "encoded"
	| "known"
	| "repeat"
	| "safety"
	| "placeholder"
	| "transcript";

/** A placeholder of an earlier pass, found so it's replaced by itself and nothing overlapping it is hidden twice. */
export const PLACEHOLDER_RULE = "placeholder";

/** The layer a rule belongs to, its name before the colon. */
export function layerOf(rule: string): RuleLayer {
	const colon = rule.indexOf(":");
	return (colon < 0 ? rule : rule.slice(0, colon)) as RuleLayer;
}

/**
 * Whether a finding is vouched for, so the decision stage keeps it whatever it looks like: a value the caller or an
 * earlier text said is secret (`known`, `repeat`), everything in a secret file or a secret command's output, except
 * what is there under no credential's name (`file:opaque`, see needsJudging), a text a detector failed on (`safety`),
 * and an earlier pass's placeholder.
 */
export function isVouched(rule: string): boolean {
	return ["known", "repeat", "file", "command", "safety", "placeholder"].includes(layerOf(rule)) && !needsJudging(rule);
}

/**
 * Proposed, not vouched for: a secret file's value under no credential's name (isOpaqueSetting), and another occurrence
 * of a guess (a repeat of the random layer's finding), each judged in its own place like any proposal.
 */
export function needsJudging(rule: string): boolean {
	return rule === "file:opaque" || rule === REPEATED_GUESS;
}

/** Another occurrence of a value the random layer guessed (repeats.ts). */
export const REPEATED_GUESS = "repeat:guess";

/**
 * A guess about one place (the random-token layer's, and its repeats): never learned, judged again wherever it's
 * repeated, and no reason on its own to call decoded text a secret.
 */
export function isGuess(rule: string): boolean {
	return layerOf(rule) === "unnamed" || rule === REPEATED_GUESS;
}

/** Rules that take a whole line as the secret, which give way to a narrower finding inside it. */
export function isWholeLine(rule: string): boolean {
	return rule === "file:whole" || rule === "file:bare" || rule === "command:prints-secret";
}

/** A private key or a seed phrase, by its own structure: secret whatever the text around it says. */
export function isKeyMaterial(rule: string): boolean {
	return /^structure:(?:private-key|mnemonic)|^format:private key/.test(rule);
}

/**
 * Found by where the value stands (a name, a structure's slot, a guess about its place), not by what the value is: the
 * decision stage's "never a secret" values (counts, versions, words) apply. Not structures that say what the value is
 * (a private key, a CI mask, a JWK, a password hash, a seed phrase).
 */
export function readsByPlace(rule: string): boolean {
	return (
		["named", "structure", "unnamed"].includes(layerOf(rule)) &&
		!/^structure:(?:private-key|ci-mask|jwk|password-hash|mnemonic)/.test(rule)
	);
}

/** A token that a terminal wrapping at a fixed width may cut and continue on the next line: a format's, a bearer token, a URL parameter. */
export function continuesAcrossWraps(rule: string): boolean {
	return /^(?:format:|structure:(?:bearer|authorization|url-param))/.test(rule);
}
