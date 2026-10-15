/**
 * Linear time on adversarial input, asserted as a ratio (timing.ts) so that a busy machine can't fail it.
 *
 *   node --test test/performance.test.ts
 *
 * (A fake key's vendor prefix is written with an escape, `"ghp\x5f…"`: written whole, the repository would hold text
 * that secret scanners, GitHub's push protection among them, take for a live key.)
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { KnownValues } from "../src/known.ts";
import { b62, r } from "./helpers.ts";
import { assertLinear } from "./timing.ts";

test("redaction time is linear in the length of adversarial repeated input", () => {
	for (const unit of [
		"-----BEGIN PRIVATE KEY-----\\n",
		'\\"',
		"a=",
		'"key": "',
		"password ",
		"=".repeat(10),
		"https://a:b@",
		"AAAA",
	]) {
		assertLinear(JSON.stringify(unit), (n) => r().redact(unit.repeat(n)), 2_500);
	}
});

test("a stream releases text while it reads a long base64 finding", () => {
	assertLinear(
		"a stream over a wrapped base64 .env",
		(n) => {
			let env = `STRIPE_SECRET=sk\x5flive_51${b62(40)}\n`;
			while (env.length < n) env += `SOME_SETTING_${env.length}=value${env.length}\n`;
			const blob =
				Buffer.from(env)
					.toString("base64")
					.match(/.{1,76}/g)!
					.join("\n") + "\n";
			const st = r().stream({ holdback: 8192 }); // nothing is released before twice the holdback is buffered
			let released = 0;
			for (let i = 0; i < blob.length; i += 3850) released += st.write(blob.slice(i, i + 3850)).length;
			st.end();
			assert.ok(released > 0, "nothing released before end()");
		},
		14_000,
	);
});

test("values learned one at a time, each found after, cost about what they cost learned all at once", () => {
	// (A long session learns from each tool result and redacts the next: its index isn't built again whole every few
	// values, which made 2,000 values cost some 80 times what they cost at once.)
	const values = Array.from({ length: 2000 }, (_, i) => `Pw${i.toString(36)}#x9qLm2Zk`);
	const time = (findEach: boolean) => {
		const t = performance.now();
		const known = new KnownValues();
		for (const v of values) {
			known.add(v);
			if (findEach) known.find("ok");
		}
		known.find("ok");
		return performance.now() - t;
	};
	const atOnce = Math.min(time(false), time(false));
	const inTurn = time(true);
	assert.ok(inTurn < 20 * Math.max(atOnce, 20), `${inTurn.toFixed(0)} ms in turn, ${atOnce.toFixed(0)} ms at once`);
});

test("a long run of blanks before a block scalar costs linear time", () => {
	assertLinear("blanks before a block scalar", (n) => r().redact(`${" ".repeat(n)}k: |`), 20_000);
});

test("heredocs in heredocs' bodies cost linear time", () => {
	// (A body is read on its own once; a body inside it is its text.)
	const nested = (n: number) => {
		let open = "";
		let close = "";
		for (let i = 0; i < n; i++) {
			open += `cat > f${i}.sh <<'D${i}'\necho 'x${i}' > ~/.vault_pass\n`;
			close = `D${i}\n${close}`;
		}
		return open + close;
	};
	assertLinear("nested heredocs", (n) => r().redact(nested(n)), 500);
});

test("a long camel-case name costs what a short one does", () => {
	// A name rule that reads a name two ways backtracks exponentially in its parts.
	assertLinear("a camel-case name", (n) => r().redact(`is${"PasswordStrengthIndicator".repeat(n)}Visible: false`), 2);
});

test("a large state file read as a secret file costs about what its text costs read plainly", () => {
	// (Each line a name and a setting's value: the secret-file readers judge the name first.)
	const records = Array.from(
		{ length: 1500 },
		(_, i) =>
			`    {\n      "name": "svc_${i}",\n      "fqdn": "svc-${i}.internal.acme.io",\n      "id": "Z0123456789ABCDEFGHIJ_svc-${i}.internal.acme.io_CNAME",\n      "ttl": 300,\n      "type": "CNAME"\n    }`,
	);
	const state = `{\n  "version": 4,\n  "resources": [\n${records.join(",\n")}\n  ]\n}\n`;
	const best = (run: () => void) => {
		let t = Infinity;
		for (let i = 0; i < 3; i++) {
			const start = performance.now();
			run();
			t = Math.min(t, performance.now() - start);
		}
		return t;
	};
	const plain = best(() => r().detect(state));
	const file = best(() => r().detect(state, { hint: { path: "infra/terraform.tfstate", secretFile: true } }));
	assert.ok(file < 1.5 * plain, `${file.toFixed(0)} ms as a secret file, ${plain.toFixed(0)} ms plainly`);
});

test("a value repeated on many lines costs no more than as many different values", () => {
	// (Each repeat is looked at for a client SDK it's passed to; a text that calls none needs no look.)
	const lines = (value: (i: number) => string) =>
		"kind: Secret\ndata:\n" + Array.from({ length: 100 }, (_, i) => `  a: ${value(i)}\n`).join("");
	const time = (text: string) => {
		let best = Infinity;
		for (let i = 0; i < 3; i++) {
			const t = performance.now();
			r().redact(text);
			best = Math.min(best, performance.now() - t);
		}
		return best;
	};
	const same = time(lines(() => ")".repeat(1000)));
	const different = time(lines((i) => String.fromCharCode(33 + (i % 90)).repeat(1000)));
	assert.ok(same < 3 * Math.max(different, 20), `${same.toFixed(0)} ms repeated, ${different.toFixed(0)} ms different`);
});

test("a line of URLs with no blank between them costs linear time", () => {
	// (Each URL's reader reads, as one URL, to the line's end: asked whether a URL reaches a token, it stops once it does.)
	for (const separator of [",", ";", "|"])
		assertLinear(
			`URLs joined by ${separator}`,
			(n) => r().redact(`http://elasticsearch-node-01.prod.example.com:9200${separator}`.repeat(n)),
			300,
		);
});
