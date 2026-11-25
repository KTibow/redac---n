// Print a secret's shape without the secret: digits become 0, a-f become a, other lowercase x, other uppercase X;
// punctuation is kept. Reads stdin (e.g. `wl-paste | node scripts/genericize.ts`) so the value never lands in argv or a log.
import { readFileSync } from "node:fs";

const shape = (s: string) =>
	s.replace(/[0-9]/g, "0").replace(/[a-f]/g, "a").replace(/[g-z]/g, "x").replace(/[A-Z]/g, "X");

const text = readFileSync(0, "utf8").trim();
console.log(shape(text));
console.log(`length ${text.length}`);
