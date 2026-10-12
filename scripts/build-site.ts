/**
 * Builds the demo page into _site/: site/index.html, and site/main.ts bundled with the library for the browser. GitHub
 * Pages serves it at https://kendell.dev/redac---n/ (.github/workflows/pages.yml); its links are relative, so it
 * works under that path and from a local server alike.
 *
 *   node scripts/build-site.ts && python3 -m http.server -d _site
 */
import { copyFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { build } from "rolldown";

const root = join(import.meta.dirname, "..");
const out = join(root, "_site");

rmSync(out, { recursive: true, force: true });
mkdirSync(out);
await build({
	input: join(root, "site", "main.ts"),
	platform: "browser",
	output: { file: join(out, "main.js"), format: "esm", minify: true },
});
copyFileSync(join(root, "site", "index.html"), join(out, "index.html"));
