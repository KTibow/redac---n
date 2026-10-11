/**
 * Where the corpora that aren't in the repository live (third-party sets whose licences differ from this one's, some
 * allowing evaluation only, and samples of public text): `$REDACT_CORPORA`, or `~/Downloads/redact-corpora`.
 */
import { homedir } from "node:os";
import { join } from "node:path";

export const CORPORA = process.env.REDACT_CORPORA ?? join(homedir(), "Downloads/redact-corpora");
