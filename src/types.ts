/** One secret found in a text: where it is, what it is, and which rule found it. */
export interface Finding {
	/** Where the secret starts in the text passed in, in UTF-16 code units. */
	start: number;
	/** Where it ends (exclusive). */
	end: number;
	/** What the secret is, shown in the placeholder: "GitHub token", "password", "private key". */
	kind: string;
	/** The rule that found it, `layer:rule` (`format:GitHub token`, `named:assign`, `known`), for debugging and evaluation. */
	rule: string;
	/**
	 * How sure the rule is, 0 to 1. Formats and whole known values are 1; a known value found by one end, 0.95. A finding
	 * of 0.9 or more may be learned and hidden wherever its value turns up again (spans.ts isLearnable: not a guess, 8
	 * characters or more); one below is hidden only where found.
	 */
	confidence: number;
	/** The name the value sat under, when a rule read one (`DB_PASSWORD`, `apiKey`). */
	name?: string;
	/** Whether the rule read the value where only a literal can stand (an env line, YAML, XML text, a CLI flag). */
	literal?: boolean;
	/**
	 * From `detect`: the secret as the program reads it, where that differs from the text the span covers (a known
	 * value written another way, a literal split in pieces joined, `"xoxb-12" "34ab"`, invisible characters dropped,
	 * a JSON escape decoded). May be unset; then the secret is the text the span covers.
	 */
	value?: string;
}

/** Where a text came from, which changes what counts as a secret in it. */
export interface Hint {
	/** The shell command whose output this is. `cat .env` makes the whole output a secret file. */
	command?: string;
	/** The file this text was read from. `.env`, `id_rsa`, `credentials.json` are secret files. */
	path?: string;
	/**
	 * The text is a secret file's contents, whatever its path or command says: for a caller that knows by rules of its
	 * own (a configured secrets directory, `deploy/prod.conf`). Read as `cat .env` output is.
	 */
	secretFile?: boolean;
}

export type Guessing = "off" | "confident" | "eager";

/** What one call is told about its text: where it came from, and how much to guess. */
export interface DetectOptions {
	hint?: Hint;
	/** Overrides the redactor's `guessing` for this call. */
	guessing?: Guessing;
}

export interface RedactOptions {
	/**
	 * How hard to guess at random-looking tokens that have no name or format next to them, the one thing a model
	 * decides; every rule runs whatever this says (known values, formats, structure, credential names, secret files
	 * and commands, encoded secrets).
	 * - "off": no guesses. (In a secret file, the hint's or one written inside the text, the model always sorts the
	 *   values under neutral names into generated ones, hidden, and settings, kept: the hint already says secrets are
	 *   there.)
	 * - "confident" (default): tokens the model is confident about: in a key-like context, or long ones anywhere.
	 * - "eager": shorter and less certain ones too, accepting more false redactions.
	 */
	guessing?: Guessing;
	/**
	 * Password hashes (bcrypt, argon2, crypt, SCRAM, LDAP, MySQL, Postgres): "keep" (default) leaves them,
	 * as most labelled data does; "hide" redacts them whole, since a weak password's hash can be cracked
	 * offline.
	 */
	hashes?: "keep" | "hide";
	/**
	 * Values that are secret wherever they appear, in every encoding: credentials the caller holds, each with a label
	 * for its placeholders. Values are trimmed. Empty entries are skipped, and so are values too short or ordinary to
	 * hide everywhere (under 6 characters, letters only and under 14, digits only and up to 8 digits, no letter or digit
	 * at all, one character repeated) or over 16,384 characters: `addKnown` returns false for those.
	 */
	known?: Iterable<string | { value: string; label?: string } | undefined | null>;
	/**
	 * Builds the text that replaces a secret, from its finding and its value as the program reads it (decoded where it
	 * was escaped). Default: `[REDACTED <kind> #<fingerprint>]`; `redactor.fingerprint(value)` gives the tag. Its text
	 * must not look like a secret itself.
	 */
	placeholder?: (finding: Finding, value: string) => string;
}
