/**
 * Superlinear-time fuzzing: every keyword of every format rule, plus the syntax fragments the other
 * layers look for, repeated into 25 KB and 100 KB inputs (alone, with separators, and with newlines).
 * A 4x longer input taking much more than 4x the time points at a regex or loop to fix. Then values: a prefix that
 * starts one (`?token=`, `password: `) and a long run of one character, as lines of 2 KB and of 8 KB (the longest
 * values readers take) in 100 KB: work quadratic in a value's length shows as the 8 KB lines costing far more. Then
 * names: one name of 60 characters built of one piece (`AbAbAb…`, camel case's humps) before a value, where a name
 * rule that can read a name more than one way backtracks exponentially. Last, a long run of one character with a
 * trigger after it (`%41`, `://`, `"`…): a rule that runs only when its trigger is in the text sees the whole run.
 *
 * The cases are shared among worker threads (half the cores), each timing a case's small and large input itself, so
 * load on the machine slows both alike; a case flagged there is timed again alone before it's reported.
 *
 *   node scripts/fuzz-perf.ts [maxRatio]
 */
import { availableParallelism } from "node:os";
import { isMainThread, parentPort, Worker, workerData } from "node:worker_threads";
import { IMPORTED_FORMATS } from "../src/formats-data.ts";
import { Redactor } from "../src/index.ts";

const maxRatio = Number(process.argv[2] ?? 12);
const units = new Set<string>([
	"-----BEGIN PRIVATE KEY-----\\n",
	"-----BEGIN ",
	"-----END ",
	"a=",
	"a:",
	"key=",
	"key: ",
	'"key": "',
	"password ",
	"password=",
	"--password ",
	"-p",
	"https://a:b@",
	"://",
	"Bearer ",
	"Basic ",
	"Authorization: ",
	"Cookie: ",
	"set-cookie: a=b; ",
	"AKIA",
	"sk-",
	"sk_",
	"ghp_",
	"eyJ",
	"eyJa.eyJb.",
	"\\n",
	"\\\\n",
	'"',
	"'",
	"`",
	"=",
	":",
	"/",
	"-",
	"_",
	".",
	"+",
	"%",
	"&",
	"?",
	"#",
	"|",
	"│",
	" ",
	"\t",
	"a",
	"A1",
	"0",
	"aB3",
	"AAAA",
	"==",
	"x",
	"$",
	"${",
	"{{",
	"(",
	")",
	"[",
	"]",
	"$ cat .env\n",
	"!cat .env\n",
	"In [1]: ",
	"machine a login b password ",
	"user=a password=",
	"define('A_KEY', '",
	"name: X_PASSWORD\nvalue: ",
	"| key | value |\n",
	"KEY  VALUE\n",
	"--set a.password=",
	"::add-mask::",
	"0x",
	"SG.",
	"xoxb-",
	"AIza",
	"ya29.",
	"hooks.slack.com/services/",
	"/reset/",
	"?code=",
	"&token=",
	"Password=",
	";Password=",
	"mysql -p",
	"curl -u a:",
	"docker login -p ",
	"ConvertTo-SecureString '",
	"kind: Secret\ndata:\n  a: ",
	"0123456789abcdef",
	"ABCDEFGHIJKLMNOP",
	"QUJD",
	"\r\n",
	" ",
	"\0",
	'setPassword("',
	'os.getenv("A_KEY", "',
	"os.Setenv(",
	"('a_key', '",
	"f(a, ",
	"/* ",
	"# ",
	"password: |\n  ",
	"password = <<EOF\n",
	"https://a:b@c/",
	"http://u:p)@h",
	"[::1]",
	"\\\\\\n",
	'\\"',
	"{c.Password}",
	"${A:-",
	"${A:=",
	"%{",
	"pubKey = `",
	"mQENB",
	"MIIB",
	"\x1b]",
	"\x07",
	"\x1b\\",
	"\x1b[38:5:1m",
	"##vso[task.setvariable x ",
	"Proc-Type: 4,ENCRYPTED\n",
	"redis-cli -a ",
	"htpasswd -b ",
	"login a password ",
	".x\tTRUE\t/\tTRUE\t1\ta\t",
	"*** Add File: .env\n",
	"a=b; ",
	"-----BEGIN PRIVATE KEY----- ",
	"data:\n  a: |\n    ",
	"\\u001b[0m",
	"     12→",
	"     3\t",
	"IDENTIFIED BY ",
	"127.0.0.1:6379> AUTH ",
	'1) "requirepass"\n2) "',
	"-Dx.password=",
	"echo x | sudo -S ",
	"$ echo $DB_PASSWORD\n",
	"$2b$12$",
	"$6$",
	"SCRAM-SHA-256$4096:",
	"{SSHA}",
	"md5",
	"*",
	"#",
	"-----BEGIN OpenVPN Static key V1-----\n",
	': PSK "',
	"stats auth a:",
	"-passout pass:",
	"machine h password ",
	"- key: X\n  value: ",
	"EV[1:",
	"dXNlcjpwYXNz",
	"密码：",
	'> GET k\n"',
	"senha dele é ",
	"mot de passe est ",
	"A_KEY lautet ",
	"パスワードは",
	'"ab" ',
	'" + "',
	"' . '",
	"passwd (",
	'process.env.X ?? "',
	'secure_compare(password, "',
	'token == "',
	"║ A_KEY │ ",
	"cookie  ",
	'#define A_PASS "',
	'os.getenv("A_TOKEN", "',
	'<string name="a_secret">',
	"-PA_PASSWORD=",
	"steamcmd +login a ",
	"sqlplus a/",
	"| buildkite-agent redactor add",
	"<<< ",
	"http -a a:",
	"mosquitto_pub -P ",
	"net ads join -U a%",
	"appid=",
	"HRKU-",
	"1/",
	"sl.",
	"v1.",
	// A log with a token on every line and no URL: a look-back for a URL must not scan to the start each time.
	"GET /api/v1/orders/1 status=200 traceId=9f3a1c7e92b04d65a1f8\n",
]);
for (const [, , , keywords] of IMPORTED_FORMATS) for (const k of keywords) units.add(k);

// (A Redactor per run: a second run on one Redactor would be answered from its cache.)
const time = (s: string) => {
	let best = Infinity;
	for (let i = 0; i < 2; i++) {
		const r = new Redactor({ fingerprintKey: "x" });
		const t = performance.now();
		r.redact(s);
		best = Math.min(best, performance.now() - t);
	}
	return best;
};

/**
 * One check: its label, its inputs (made when it runs: all of them at once would take gigabytes), and what it reports
 * given the time of each (ms), or nothing.
 */
interface Case {
	label: string;
	inputs: () => string[];
	judge: (times: number[]) => string | undefined;
}
const cases: Case[] = [];
/** A 4x longer input taking more than `limit` times as long (and over `floor` ms), or over a second for 100 KB. */
const scaling = (label: string, small: () => string, big: () => string, kind: string, limit: number, floor: number) =>
	cases.push({
		label,
		inputs: () => [small(), big()],
		judge: ([a, b]) =>
			b / Math.max(a, 1) > limit && b > floor
				? `SUPERLINEAR${kind} ${label}: ${a.toFixed(0)}ms -> ${b.toFixed(0)}ms`
				: b > 1000
					? `SLOW${kind} ${label}: ${b.toFixed(0)}ms for 100 KB`
					: undefined,
	});
for (const u of units) {
	for (const sep of ["", " ", "\n", "x", "=", "\\n"]) {
		const unit = u + sep;
		scaling(
			JSON.stringify(unit),
			() => unit.repeat(Math.ceil(25_000 / unit.length)),
			() => unit.repeat(Math.ceil(100_000 / unit.length)),
			"",
			maxRatio,
			100,
		);
	}
}
// (Lines of 2 KB, then of 8 KB, in 100 KB: the same amount of text, so any growth is work quadratic in a value's length.)
const PREFIXES = [
	"https://x.io/?token=",
	"password: ",
	"the password: ",
	"密码：",
	"DB_PASSWORD=",
	'{"password": "',
	"Authorization: Bearer ",
	"-p",
	"kind: Secret\ndata:\n  a: ",
];
const FILLERS = [")", "]", "}", "(", "a", "aB3", '"', "\\", "%2F", "-", "=", " ", ":", "@", "/", "'", "`", "*"];
for (const prefix of PREFIXES) {
	for (const filler of FILLERS) {
		const lines = (size: number) =>
			`${prefix}${filler.repeat(Math.ceil(size / filler.length))}\n`.repeat(Math.ceil(100_000 / size));
		scaling(
			`${JSON.stringify(prefix + filler)}…`,
			() => lines(2_000),
			() => lines(8_000),
			" VALUE",
			3,
			300,
		);
	}
}
for (const piece of ["Ab", "aB", "Abc", "A_b", "ab_", "ab-", "a.b", "A1", "Key", "Pass", "Sid", "_"]) {
	const name = `${piece.repeat(Math.ceil(60 / piece.length)).slice(0, 60)}Password`;
	for (const line of [
		`${name}: Kx9mQ2vL7p`,
		`${name}=Kx9mQ2vL7p`,
		`"${name}": "Kx9mQ2vL7p"`,
		`--${name} Kx9mQ2vL7p`,
		`${name}                : 30`,
	]) {
		cases.push({
			label: JSON.stringify(line),
			inputs: () => [line],
			judge: ([t]) => (t > 200 ? `SLOW NAME ${JSON.stringify(line)}: ${t.toFixed(0)}ms` : undefined),
		});
	}
}
for (const filler of ["a", "aB3", "-", ".", "/", "=", " ", "_", "+", "0"]) {
	for (const trigger of [
		"%41",
		"://",
		'"',
		"=",
		"BEGIN ",
		"password ",
		"\\n",
		"\x1b[",
		"@",
		"INSERT INTO t (a) VALUES (",
	]) {
		const run = (n: number) => `${filler.repeat(Math.ceil(n / filler.length))} ${trigger}`;
		scaling(
			`${JSON.stringify(filler)}… ${JSON.stringify(trigger)}`,
			() => run(25_000),
			() => run(100_000),
			" RUN",
			maxRatio,
			100,
		);
	}
}

/** Times case `k`: its inputs' times, and what its judge reports. */
const run = (k: number) => {
	const times = cases[k].inputs().map(time);
	return { k, times, report: cases[k].judge(times) };
};

if (!isMainThread) {
	const { shard, shards } = workerData as { shard: number; shards: number };
	for (let k = shard; k < cases.length; k += shards) parentPort!.postMessage(run(k));
} else {
	const shards = Math.max(1, Math.floor(availableParallelism() / 2));
	const results: ReturnType<typeof run>[] = [];
	await Promise.all(
		Array.from(
			{ length: shards },
			(_, shard) =>
				new Promise<void>((done, fail) => {
					const w = new Worker(new URL(import.meta.url), { workerData: { shard, shards } });
					w.on("message", (r: ReturnType<typeof run>) => results.push(r));
					w.on("error", fail);
					w.on("exit", () => done());
				}),
		),
	);
	// (Flagged under load: timed again alone, and reported only if it still is.)
	for (const r of results.filter((r) => r.report)) {
		const alone = run(r.k);
		if (alone.report) console.log(alone.report);
		Object.assign(r, alone);
	}
	const big = results.map((r) => ({
		label: cases[r.k].label,
		t: r.times.at(-1)!,
		ratio: r.times.length > 1 ? r.times[1] / Math.max(r.times[0], 1) : 1,
	}));
	big.sort((x, y) => y.t - x.t);
	console.log(
		`${results.length} cases on ${shards} threads; slowest:`,
		big
			.slice(0, 8)
			.map((x) => `${x.label} ${x.t.toFixed(0)}ms x${x.ratio.toFixed(1)}`)
			.join("; "),
	);
}
