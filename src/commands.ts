/**
 * Where a text came from, told by the command that printed it or the path it was read from: a secret file
 * (`.env`, `id_rsa`, `cat .env`, `grep KEY .env.local`, `sops -d`), or a command whose output is a credential
 * (`gh auth token`, `openssl rand -hex 32`, `echo $DB_PASSWORD`). Commands are read through the wrappers that run
 * them (`bash -lc`, `docker exec`, `kubectl exec`, `ssh`).
 */
import { lookup } from "./lookup.ts";
import { isCredentialName } from "./names.ts";
import { lastText, lineEnd, lowerBound } from "./lines.ts";
import { CONTRACTION } from "./syntax.ts";
import {
	allRedirects,
	type LineIndex,
	programName,
	PROMPT,
	redirectsStdout,
	type ShellCommand,
	shellCommands,
	type ShellGroup,
	type ShellRedirect,
	type ShellWord,
	simpleCommand,
} from "./shell.ts";

const EXAMPLE_FILE =
	/\.(example|sample|template|defaults?|dist|tmpl|tpl)$|^(example|sample|template)[._-]|\.(example|sample|template)\./i;
const SECRET_FILE = [
	/^\.env([.-].+)?$/,
	/^[^.].*\.env$/,
	/^\.envrc$/,
	/^\.dev\.vars$/,
	/^\.secrets?$/,
	/^id_(rsa|dsa|ecdsa|ed25519)(_sk)?$/,
	/\.(key|p12|pfx|jks|keystore|ppk|keytab|pem)$/i,
	/^credentials(\.(json|ya?ml|toml|ini|csv))?$/,
	/^\.(git-credentials|netrc|npmrc|pypirc|vault-token|pgpass|my\.cnf|s3cfg|boto|dockercfg|htpasswd|terraformrc)$/,
	// Password and PIN files: Ansible's vault_pass, `db_password.txt`, `~/.pin`, Docker and Compose secret files, pppd's.
	/^\.?vault[_-]?pass(?:word)?(?:\.txt)?$/i,
	/(?:^|[_.-])(?:pass(?:word|wd|phrase|code)?|secret|token|pin(?:[_-]?code)?)(?:\.txt)?$/i,
	// (A key's file, `secret_key.txt`, `api-key`; not a jq filter's `.private_key`.)
	/^(?:\w[\w-]*[_-])?(?:secret|api|private|access|auth|master|signing|encryption)[_-]?key(?:\.txt)?$/i,
	/^(?:pap|chap)-secrets(?:[-_.][\w-]+)?$/,
	/^(_netrc|rclone\.conf|cookies\.txt|keystore\.properties|wp-config\.php|\.?htpasswd|redis\.conf|sentinel\.conf|users\.acl|keyfile|userlist\.txt)$/i,
	/(^|[-_.])secrets?(\.[\w-]{1,40})?\.(json|ya?ml|toml|env|ini|properties)$/i,
	/\.(tfvars|tfstate)(\.json|\.backup)?$/,
	/^kubeconfig(\..+)?$|\.kubeconfig$/,
	/^(service[-_]?account|client[-_]secret|application_default_credentials).*\.json$/i,
	/^(auth|mcp-auth|hosts)\.(json|yml)$/,
	/^(?:auth|creds?|login|userpass|user-pass)(?:[_-]file)?\.txt$/i,
	/^\.credentials\.json$/,
	/realm\.properties$/,
];
const SECRET_DIR =
	/(^|\/)\.(aws|ssh|gnupg|docker|kube|azure)\/|(^|\/)\.config\/(gcloud|gh|rclone|sops)\/|(^|\/)\.?secrets\//;
/** Secret files by their directory and name: Bundler's config, which holds gem servers' credentials (names.ts isBundlerHostName). */
const SECRET_PATH = /(^|\/)\.bundle\/config$/;
// (Also a key's public half by its name, `cache-pub-key.pem`, `server.pub.pem`, `public.key`; and a certificate's,
// `fullchain.pem`, `cert.pem`, but not a private key's container named for its certificate, `cert.key`, `server.crt.p12`,
// `cert-key.pem`.
// A private key in a certificate's file anyway is found by its DER.)
const NOT_SECRET_PATH =
	/\.pub$|(?:^|[/._-])(?:pub|public|pubkey)(?=[._-][^/]*$)|(?:^|[/._-])(?:cert|certs|certificate|crt|chain|fullchain|cacert|ca-bundle)(?=[._-][^/]*$)(?![^/]*(?:\.(?:key|p12|pfx|jks|keystore|ppk)|[-_.]key\.pem)$)|known_hosts|authorized_keys|(?:^|\/)\.ssh\/config$|\.(md|ts|tsx|js|py|go|rs|rb|java)$|(?:^|\/)etc\/(?:passwd|group)-?$/;

/** Whether a path names a file whose whole content is secret material (`.env`, `id_rsa`, `credentials.json`). */
export function isSecretFile(path: string): boolean {
	path = path.replace(/\\/g, "/"); // Windows paths
	const name = path.slice(path.lastIndexOf("/") + 1);
	if (!name || EXAMPLE_FILE.test(name) || NOT_SECRET_PATH.test(path)) return false;
	return SECRET_FILE.some((r) => r.test(name)) || SECRET_DIR.test(path) || SECRET_PATH.test(path);
}

/**
 * Whether a value is the name of a file that is a secret file or its template, not a password: `.env.example`, `.env.local`,
 * `.npmrc` (a dotfile, or a template's name, in lower case; `Env.Local9` is a password).
 */
export function isConfigFileName(value: string): boolean {
	return (
		/^\.?[a-z][a-z0-9_-]*(?:\.[a-z0-9_-]+)*$/.test(value) &&
		((value.startsWith(".") && isSecretFile(value)) || (value.includes(".") && EXAMPLE_FILE.test(value)))
	);
}

/** Whether a path names a file that holds nothing but secrets, by its name or its directory's: `config/secrets.staging.yml`, `credentials.json`, `secrets/db`; not `.env`, which holds settings too. */
export function holdsOnlySecrets(path: string): boolean {
	return (
		isSecretFile(path) &&
		(/secret|credential|^auth\.json$|^\.(?:netrc|_netrc|pgpass|vault-token)$/i.test(
			path.slice(path.lastIndexOf("/") + 1),
		) ||
			/(^|\/)\.?secrets\//.test(path))
	);
}

const CONTENT_COMMANDS =
	/^(cat|tac|head|tail|less|more|bat|batcat|nl|sed|awk|grep|egrep|fgrep|zgrep|rg|ag|ack|Select-String|sls|cut|sort|uniq|strings|xxd|od|base64|tr|column|jq|yq|type|Get-Content|gc|findstr|diff|sops|op|dotenv|printenv|env|set|export|declare)$/;
/**
 * Commands whose whole output is a credential, by tool: each read from the program on (a commit message that mentions
 * `gh auth token` isn't one).
 */
const SECRET_TOOLS = new RegExp(
	`^(?:${[
		// Cloud and platform CLIs.
		/gh\s+auth\s+token\b/,
		/heroku\s+auth:token\b/,
		/heroku\s+config:get\b/,
		/fly\s+tokens\s+create\b/,
		/netlify\s+env:get\b/,
		/vercel\s+env\s+pull\b/,
		/supabase\s+.*token\b(?!-)/,
		/firebase\s+login:ci\b/,
		/yc\s+iam\s+create-token\b/,
		/npm\s+token\s+create\b/,
		/gcloud\s+auth\s+(?:application-default\s+)?print-(?:access|identity)-token\b/,
		/gcloud\s+secrets\s+versions\s+access\b/,
		/aws\s+ecr(?:-public)?\s+get-login-password\b/,
		/aws\s+codeartifact\s+get-authorization-token\b/,
		/aws\s+iam\s+create-access-key\b/,
		/aws\s+ssm\s+get-parameters?\b.*--with-decryption\b.*--output\s+text\b/,
		// (Or its default JSON output, `--query SecretString`'s `"…"`: findPrintedSecret reads a JSON string as its value.)
		/aws\s+secretsmanager\s+get-secret-value\b.*(?:--output\s+text\b|--query\s+["']?SecretString\b)/,
		/aws\s+configure\s+get\s+\S*(?:secret|token|key)\b/,
		/az\s+account\s+get-access-token\b/,
		/az\s+storage\s+account\s+keys\s+list\b/,
		/az\s+keyvault\s+secret\s+show\b.*(?:(?:-o|--output)\s+tsv\b|--query\s+["']?value\b)/,
		/az\s+\S+\s+.*\b(?:keys|credential)\s+list\b/,
		/kubectl\b.*\bget\s+secrets?\b.*-o\s*=?\s*(?:jsonpath|go-template)/,
		/kubectl\s+create\s+token\b/,
		/terraform\b.*\boutput\s+(?:-raw|-json)\s+\S*(?:[Pp]ass|[Ss]ecret|[Tt]oken|[Kk]ey|[Cc]red)/,
		/wp\s+config\s+get\s+\S*(?:PASSWORD|KEY|SALT|SECRET|TOKEN)\b/i,
		// Secret managers and password stores.
		/op\s+read\b/,
		/op\s+item\s+get\b.*--(?:fields|reveal)\b/,
		/op\s+signin\b.*--raw\b/,
		/doppler\s+secrets\s+get\b/,
		/vault\s+(?:kv\s+get|read|print\s+token)\b.*-field\b/,
		/vault\s+write\b.*-field\b/,
		/security\s+find-(?:generic|internet)-password\b.*\s-w\b/,
		/pass\s+(?:show\s+)?(?!(?:ls|list|version|init|help|git|tree|find|grep|edit|insert|generate|rm|mv|cp|otp|show)\b|-)[\w/.-]+\s*$/,
		/bw\s+get\s+(?:password|totp)\b/,
		/gopass\s+(?:show|cat)\b/,
		/secret-tool\s+lookup\b/,
		/lpass\s+show\b.*--password\b/,
		/keepassxc-cli\s+show\b.*(?:-a|--attributes)\s+Password\b/,
		// (PowerShell's SecretManagement; without `-AsPlainText` it prints `System.Security.SecureString`.)
		/Get-Secret\b.*-AsPlainText\b/,
		// Generators.
		/openssl\s+rand\b/,
		/pwgen\b/,
		/wg\s+(?:genkey|genpsk)\b/,
		/wg\s+show\b.*\bprivate-key\b/,
		/rails\s+secret\b/,
		/rake\s+secret\b/,
	]
		.map((r) => r.source)
		.join("|")})`,
);
/** What a command reads or calls that is a secret, wherever it sits in the command: a random device, a language's generator. */
const SECRET_SOURCES =
	/\/dev\/u?random\b|get_random_secret_key|secrets\.token_(?:hex|urlsafe|bytes)|SecureRandom\.(?:hex|base64|urlsafe_base64)|crypto(?:["']\))?\.randomBytes|os\.urandom\(|\brandom_bytes\(|openssl_random_pseudo_bytes/;

/** A shell's name: `bash`, `sh`, `zsh`. */
export const SHELL = /^(?:ba|z|da|k)?sh$/;

/** Commands whose whole output is a set of secrets, read like a secret file; each read from the program on. */
const SECRET_DUMPS = new RegExp(
	String.raw`^(?:\bdoppler\s+secrets(?:\s+download)?\b(?![^\n]*\b(?:set|delete)\b)|\bsops\s+(?:-d|--decrypt)\b|\bansible-vault\s+(?:view|decrypt)\b|\b(?:bin\/)?rails\s+credentials:show\b|\binfisical\s+export\b|\bchamber\s+(?:export|read)\b|\bheroku\s+config(?:\s|$)(?!:)|\bvault\s+kv\s+get\b|\bop\s+inject\b|\baws\s+sts\s+(?:get-session-token|assume-role\S*|get-federation-token)\b|\baws\s+configure\s+export-credentials\b|\baz\s+ad\s+sp\s+(?:create-for-rbac|credential\s+reset)\b|\bkubectl\s+config\s+view\b[^\n]*--raw\b|\bterraform\s+output\s+-json\b|\bgit\s+credential\s+fill\b|\b(?:gh|glab)\s+auth\s+status\b[^\n]*(?:--show-token|\s-t\b))`,
);

/** A command a line runs. One that a substitution runs has its `host`: the command whose words take its output. */
export interface CommandRun extends ShellCommand {
	host?: ShellCommand;
}

/**
 * A line written for PowerShell or cmd, where a backslash separates a path (`.\.env`, `C:\Users\me\.aws\credentials`,
 * `$env:USERPROFILE\.ssh\id_rsa`, `%USERPROFILE%\.ssh`): read without POSIX escapes.
 */
const WINDOWS_LINE =
	/(?:^|[\s'"=(])(?:[A-Za-z]:\\|\.{1,2}\\[\w.$-]|~\\|\$(?:HOME|env:\w+)\\|%\w+%\\)|^[ \t]*(?:Get-\w+|Select-String|gc|type|findstr|pwsh|powershell|cmd)(?:\.exe)?[ \t]/i;

/**
 * The simple commands a command line runs, in order, read through what runs a command of its own: a shell (`bash -lc
 * "cat .env"`, `sudo sh -c '…'`, a heredoc or here-string fed to one: `ssh host <<'EOF'`), PowerShell (`pwsh -Command
 * …`) and cmd (`cmd /c …`), a container (`docker exec app cat .env`, `docker compose exec`, `kubectl exec pod -- cat
 * .env`), a remote host (`ssh host -- cat .env`), and substitutions (`echo "$(cat .env)"`), nested ones too. A prompt
 * before the line (a pasted session's `$ `, a notebook's `!`, a trace's `+ `, a quote's `> `) is left out. Positions are in `text`, however deep the
 * command was; an unwrapped command takes the wrapper's place in its pipeline and its redirections as a group's.
 */
export function commandsRun(
	text: string,
	{
		at = 0,
		oneLine = false,
		lines,
		depth = 0,
	}: { at?: number; oneLine?: boolean; lines?: LineIndex; depth?: number } = {},
): CommandRun[] {
	const out: CommandRun[] = [];
	for (const c of commandLine(text, at, { oneLine, lines })) {
		if (depth < 4) {
			for (const s of c.words.flatMap((w) => w.substitutions))
				out.push(
					...commandsRun(text.slice(s.start, s.end), { depth: depth + 1 }).map((r) =>
						remap(r, textSource(text, s.start, s.end), text, c),
					),
				);
			// A process substitution the command's input is redirected from is piped into it (`tee out.log < <(cat .env)`
			// runs as `cat .env | tee out.log`); one its output goes to is run by it, as a word's is.
			for (const r of c.redirects) {
				for (const s of r.target?.substitutions ?? []) {
					const feeds = r.op === "<";
					const run = commandsRun(text.slice(s.start, s.end), { depth: depth + 1 }).map((x) =>
						remap(x, textSource(text, s.start, s.end), text, feeds ? undefined : c),
					);
					if (feeds && run.length) run[run.length - 1].then = "|";
					out.push(...run);
				}
			}
		}
		const inner = depth < 4 ? innerCommand(c, text) : undefined;
		const run = inner ? commandsRun(inner.text, { depth: depth + 1 }).map((r) => remap(r, inner, text)) : [];
		if (!run.length) {
			out.push(c);
			continue;
		}
		const wrapper: ShellGroup = { kind: programName(simpleCommand(c.words)[0]), redirects: c.redirects, then: c.then };
		for (const r of run) r.groups = [...r.groups, wrapper, ...c.groups];
		run[run.length - 1].then = c.then;
		// A heredoc or a here-string the wrapper is given, when it isn't the script it runs, is the stdin of the command it
		// runs: `sudo sh -c 'cat > /etc/app/db_password' <<EOF`, `ssh host 'cat > ~/.vault_pass' <<<"…"`.
		const script = (start: number, end: number) => inner!.at(0) >= start && inner!.at(0) < end;
		const heredocs = c.heredocs.filter((h) => !script(h.start, h.end));
		const herestrings = c.redirects.filter((r) => r.op === "<<<" && r.target && !script(r.target.start, r.target.end));
		if (heredocs.length || herestrings.length)
			run[0] = {
				...run[0],
				heredocs: [...run[0].heredocs, ...heredocs],
				redirects: [...run[0].redirects, ...herestrings],
			};
		out.push(...run);
	}
	return out;
}

/**
 * A line's prose before the command it shows: words and ordinary punctuation, with a contraction in them (`Here's`,
 * `You'll`, `Don't`; a list's `- ` before them), up to the inline code that holds the command (the backtick, group 1)
 * or the colon after which it follows. (Case-insensitive, as CONTRACTION is: `DON'T`.)
 */
const PROSE_BEFORE_COMMAND = new RegExp(
	String.raw`^[ \t]*(?:[-*>][ \t]+)?[A-Za-z][A-Za-z ,.!?()-]{0,80}?${CONTRACTION.source}[A-Za-z0-9 ,.!?()-]{0,120}?(?:(\x60)|:[ \t]+(?=\S))`,
	"i",
);

/**
 * The commands of the command line at `at` as written, in its dialect (POSIX, or Windows' backslashes), from where
 * the command starts: past a prompt; on a line of prose, at its inline code (`` You'll need `mysql …` ``) or after its
 * colon (`Here's how: mysql …`), since a contraction's apostrophe is no quote a shell would close.
 */
function commandLine(
	text: string,
	at: number,
	{ oneLine = false, lines }: { oneLine?: boolean; lines?: LineIndex } = {},
): ShellCommand[] {
	// (Or a trace's `+ ` and a quote's `> `, before a command that a log or a message shows.)
	const head = text.slice(at, at + 2400);
	const prompt = PROMPT.exec(head) ?? /^[ \t]*(?:\++|>) (\S[^\n]{0,2000})/.exec(head);
	const prose = prompt ? undefined : PROSE_BEFORE_COMMAND.exec(head);
	const from = prompt
		? at + prompt[0].length - prompt[1].length
		: prose
			? at + prose[0].length - (prose[1] ? 1 : 0)
			: at;
	// (After PowerShell's prompt or cmd's, `PS C:\app> `, `C:\app>`, the line is theirs.)
	const backslash =
		!(prompt && /^[ \t]*(?:PS\b|[A-Za-z]:\\)/.test(prompt[0])) &&
		!WINDOWS_LINE.test(text.slice(from, lineEnd(text, from, 4000)));
	return shellCommands(text, 0, { at: from, oneLine, lines, backslash });
}

/** A command read out of `source`'s string, with its positions where the source puts them in `text`. */
function remap(c: CommandRun, source: Source, text: string, host?: ShellCommand): CommandRun {
	const { at, endAt } = source;
	const word = (w: ShellWord): ShellWord => {
		const [start, end] = [at(w.start), endAt(w.end)];
		return {
			...w,
			start,
			end,
			raw: text.slice(start, end),
			map: w.map.map(at),
			ends: w.ends.map(endAt),
			substitutions: w.substitutions.map((s) => ({ start: at(s.start), end: endAt(s.end) })),
		};
	};
	const redirect = (r: ShellRedirect): ShellRedirect => ({
		...r,
		start: at(r.start),
		end: endAt(r.end),
		...(r.target ? { target: word(r.target) } : {}),
	});
	const [start, end] = [at(c.start), endAt(c.end)];
	return {
		...c,
		text: text.slice(start, end),
		start,
		end,
		words: c.words.map(word),
		redirects: c.redirects.map(redirect),
		heredocs: c.heredocs.map((h) => ({ ...h, start: at(h.start), end: endAt(h.end) })),
		groups: c.groups.map((g) => ({ ...g, redirects: g.redirects.map(redirect) })),
		...(c.host ? { host: remap(c.host, source, text) } : host ? { host } : {}),
	};
}

/**
 * A string in `text` read as a command: a word's text (where each character was written is its map and ends), or a stretch
 * of `text`. `at` is where the character at a position starts in `text`; `endAt`, where what ends at a position (the end of
 * the character before it) does.
 */
type Source = { text: string; at: (p: number) => number; endAt: (p: number) => number };
const wordSource = (w: ShellWord): Source => ({
	text: w.text,
	at: (p) => (p < w.map.length ? w.map[p] : w.end),
	endAt: (p) => (p > 0 ? w.ends[p - 1] : w.start),
});
const textSource = (text: string, start: number, end: number): Source => ({
	text: text.slice(start, end),
	at: (p) => p + start,
	endAt: (p) => p + start,
});

/** The options of a CLI before its subcommand that take a value: `git -C app show`, `docker --context prod exec`. */
const GLOBAL_OPTIONS = lookup<RegExp>({
	git: /^(?:-C|-c|--git-dir|--work-tree|--namespace|--exec-path|--config-env)$/,
	docker: /^(?:-c|--context|-H|--host|--config|-l|--log-level|--tlscacert|--tlscert|--tlskey)$/,
	podman: /^(?:-c|--connection|--url|--identity|--log-level|--root|--runroot)$/,
	nerdctl: /^(?:-n|--namespace|-H|--host|--address)$/,
	kubectl: /^(?:-n|--namespace|--context|--kubeconfig|--cluster|--user|-s|--server|--token)$/,
	oc: /^(?:-n|--namespace|--context|--kubeconfig|--cluster|--user|-s|--server|--token)$/,
});

/** A CLI's words from its subcommand on, past its global options and their values and a management group (`docker container exec`). */
function subcommand(words: ShellWord[]): ShellWord[] {
	const program = programName(words[0]);
	let k = 1;
	while (k < words.length && words[k].text.startsWith("-"))
		k += !words[k].text.includes("=") && GLOBAL_OPTIONS[program]?.test(words[k].text) ? 2 : 1;
	if (/^(?:docker|podman|nerdctl)$/.test(program) && words[k]?.text === "container") k++;
	return words.slice(k);
}

/** The command a wrapper runs, as a string in `text`, or undefined if `c` runs none. */
function innerCommand(c: ShellCommand, text: string): Source | undefined {
	const words = simpleCommand(c.words);
	const program = programName(words[0]);
	// The rest of the command from `rest[k]`: one word is the command it quotes, several words are as written. With none,
	// the script a heredoc or a here-string feeds it (`ssh host <<'EOF'`, `docker exec -i app sh <<EOF`).
	// (The tool's name, then the text from `start` on, positions mapped back into `text`.)
	const entrypoint = (tool: string, start: number): Source => {
		const head = `${tool} `;
		return {
			text: head + text.slice(start, c.end),
			at: (p) => (p < head.length ? start : p - head.length + start),
			endAt: (p) => (p <= head.length ? start : p - head.length + start),
		};
	};
	const from = (rest: ShellWord[], k: number): Source | undefined => {
		const runs = rest.slice(k);
		// (A shell with no command string reads its script from stdin: `docker exec -i app sh <<EOF`.)
		if (!runs.length || (SHELL.test(programName(runs[0])) && !runs.some((w) => /^-\w*c\w*$/.test(w.text))))
			return script();
		return runs.length === 1 ? wordSource(runs[0]) : textSource(text, runs[0].start, c.end);
	};
	const script = (): Source | undefined => {
		const heredoc = c.heredocs[0];
		if (heredoc) return textSource(text, heredoc.start, heredoc.end);
		const herestring = c.redirects.find((r) => r.op === "<<<")?.target;
		return herestring && wordSource(herestring);
	};
	if (SHELL.test(program)) {
		// Its options, `-c` among them (`-lc`, `-o pipefail -c`), then the command string; with no `-c` and no script
		// file after the options, a script on stdin.
		for (let k = 1; k < words.length && words[k].text.startsWith("-"); k++) {
			if (VALUE_OPTIONS.shell!.test(words[k].text)) k++;
			else if (/^-\w*c\w*$/.test(words[k].text)) return words[k + 1] && wordSource(words[k + 1]);
		}
		return afterOptions(words, 1, VALUE_OPTIONS.shell) < words.length ? undefined : script();
	}
	if (/^(?:pwsh|powershell)(?:\.exe)?$/i.test(program)) {
		const k = words.findIndex((w) => /^-(?:c|command)$/i.test(w.text));
		return k > 0 ? from(words, k + 1) : undefined;
	}
	if (/^cmd(?:\.exe)?$/i.test(program)) {
		const k = words.findIndex((w) => /^\/[ck]$/i.test(w.text));
		return k > 0 ? from(words, k + 1) : undefined;
	}
	// `su - app -c 'cat .env'`, and runuser's twin of it, `runuser -l app -c …` (no `-u`, so no wrapper): the command
	// string `-c` (`--command`) gives, as a shell's.
	const runuser = programName(c.words.find((w) => !/^[A-Za-z_]\w*=/.test(w.text))) === "runuser";
	if (program === "su" || runuser) {
		const own = program === "su" ? words : c.words;
		const k = own.findIndex((w) => /^(?:-c|--command)$/.test(w.text));
		return k > 0 ? own[k + 1] && wordSource(own[k + 1]) : undefined;
	}
	const sub = subcommand(words);
	if (/^(?:kubectl|oc)$/.test(program) && sub[0]?.text === "exec") {
		const dashes = sub.findIndex((w) => w.text === "--");
		return dashes > 0 ? from(sub, dashes + 1) : undefined;
	}
	// `docker exec`, `docker compose exec`, `docker-compose exec`: options (with the value of those that take one), then
	// the container or the service, then its command.
	const exec =
		program === "docker-compose"
			? words.slice(afterOptions(words, 1, VALUE_OPTIONS["docker compose"]))
			: /^(?:docker|podman|nerdctl)$/.test(program)
				? sub[0]?.text === "compose"
					? sub.slice(afterOptions(sub, 1, VALUE_OPTIONS["docker compose"]))
					: sub
				: undefined;
	if (exec?.[0]?.text === "exec") return from(exec, afterOptions(exec, 1, VALUE_OPTIONS["docker exec"]) + 1);
	// `docker compose run [options] SERVICE [COMMAND…]`, a one-off container of the service.
	if (exec?.[0]?.text === "run" && exec !== sub)
		return from(exec, afterOptions(exec, 1, VALUE_OPTIONS["docker run"]) + 1);
	// `docker run [options] IMAGE [COMMAND…]`, `kubectl run NAME --image=IMAGE [--command] -- …`: the command after the
	// image; with none, the arguments go to the image's entrypoint, a tool's for a tool's image (`curlimages/curl -b …`).
	if (/^(?:docker|podman|nerdctl)$/.test(program) && sub[0]?.text === "run") {
		const k = afterOptions(sub, 1, VALUE_OPTIONS["docker run"]);
		const tool = ENTRYPOINT_TOOLS[imageName(sub[k]?.text ?? "")];
		if (!tool || (k + 1 < sub.length && !sub[k + 1].text.startsWith("-"))) return from(sub, k + 1);
		return k + 1 < sub.length ? entrypoint(tool, sub[k + 1].start) : undefined;
	}
	if (/^(?:kubectl|oc)$/.test(program) && sub[0]?.text === "run") {
		const dashes = sub.findIndex((w) => w.text === "--");
		if (dashes < 0 || dashes + 1 >= sub.length) return undefined;
		const image = sub.find((w) => w.text.startsWith("--image="))?.text.slice(8) ?? "";
		const tool = ENTRYPOINT_TOOLS[imageName(image)];
		return tool && !sub.some((w) => w.text === "--command")
			? entrypoint(tool, sub[dashes + 1].start)
			: from(sub, dashes + 1);
	}
	if (program === "ssh") {
		// The host, then the command, after a `--` if there is one.
		let k = afterOptions(words, 1, VALUE_OPTIONS.ssh) + 1;
		if (words[k]?.text === "--") k++;
		return from(words, k);
	}
	return undefined;
}

/**
 * The options that take their value as the next word, by program or program and subcommand: `docker run -e X`,
 * `docker compose -f x.yml`, `docker exec --detach-keys k`, `ssh -i key`, `bash -o pipefail`. One table, so every
 * reader that steps over a command's options finds its operands at the same word.
 */
const VALUE_OPTIONS = lookup<RegExp>({
	// (Every option of `docker run` that takes a value, as its reference lists them.)
	"docker run":
		/^(?:-[acehlmpuvw]|--(?:add-host|annotation|attach|blkio-weight(?:-device)?|cap-add|cap-drop|cgroup-parent|cgroupns|cidfile|cpu-period|cpu-quota|cpu-rt-period|cpu-rt-runtime|cpu-shares|cpus|cpuset-cpus|cpuset-mems|detach-keys|device|device-cgroup-rule|device-(?:read|write)-(?:bps|iops)|dns|dns-option|dns-search|domainname|entrypoint|env|env-file|expose|gpus|group-add|health-(?:cmd|interval|retries|start-period|start-interval|timeout)|hostname|ip|ip6|ipc|isolation|kernel-memory|label|label-file|link|link-local-ip|log-driver|log-opt|mac-address|memory|memory-reservation|memory-swap|memory-swappiness|mount|name|net|net-alias|network|network-alias|oom-score-adj|pid|pids-limit|platform|publish|pull|restart|runtime|security-opt|shm-size|stop-signal|stop-timeout|storage-opt|sysctl|tmpfs|ulimit|user|userns|uts|volume|volume-driver|volumes-from|workdir))$/,
	"docker exec": /^(?:-[uewU]|--user|--env|--workdir|--env-file|--index|--detach-keys)$/,
	"docker compose":
		/^(?:-f|--file|-p|--project-name|--profile|--env-file|--project-directory|--ansi|--progress|--parallel)$/,
	ssh: /^-[iplJFoLRDbcemSwWBEOQ]$/,
	shell: /^-[a-bd-z]*o$|^--(?:rcfile|init-file)$/,
	// (grep's, and ripgrep's, ag's and ack's alike: context, a count, a pattern or the file of them, which files to read.)
	grep: /^-[ABCDdefm]$|^--(?:after-context|before-context|context|max-count|regexp|file|include|exclude|exclude-dir|label|devices|directories|binary-files)$/,
});

/** Where a command's operands start: past its options from `k`, and the values of those `options` takes as a next word. */
function afterOptions(words: ShellWord[], k: number, options: RegExp | undefined): number {
	while (k < words.length && words[k].text.startsWith("-") && words[k].text !== "--")
		k += !words[k].text.includes("=") && options?.test(words[k].text) ? 2 : 1;
	return k;
}

/** Images whose entrypoint is a tool, by the image's name (`curlimages/curl:8.5.0` → `curl`). */
const ENTRYPOINT_TOOLS = lookup<string>({
	curl: "curl",
	kubectl: "kubectl",
	"aws-cli": "aws",
	httpie: "http",
	"redis-cli": "redis-cli",
});

/** An image reference's name: its last path segment, without the tag or digest. */
function imageName(image: string): string {
	return (
		image
			.replace(/[@:][^/]*$/, "")
			.split("/")
			.at(-1) ?? ""
	);
}

/** Programs whose output is their arguments, so a substitution in them prints what it runs: `echo "$(cat .env)"`. */
const ECHOES = /^(?:echo|printf|Write-Output|Write-Host)$/;

/** Whether a command prints the contents of a secret file (`cat .env`, `grep KEY .env.local`, `cat < .env`, `git show HEAD:.env`). */
export function printsSecretFile(command: string): boolean {
	// (A member of what a command gives prints that member, not the file or the listing: `(Get-Item Env:HOM*).Name`.)
	if (
		EXPRESSION.test(command) &&
		/\)(?:\.[A-Za-z_]\w*(?:\(\))?)*\.(?!value\b)[A-Za-z_]\w*(?:\(\))?[ \t]*$/i.test(command)
	)
		return false;
	return printsWhatItReads(command, readsSecretFile, isSecretFile) || printsIndirectly(command);
}

/**
 * A file printed by a name the pipeline reader doesn't see: `find … -exec cat {}`, `xargs cat`, a printer given a
 * variable or a substitution (`cat "$f"`, `cat $(find …)`, `echo "$line"`), a script's `open(…).read()`.
 */
const PRINTER =
	/(?:-exec|\bxargs\b[^|&\n]*?|\bfd(?:find)?\b[^|;&\n]*[ \t]-[xX])[ \t'"]+(?:cat|tac|head|tail|less|more|bat|nl|grep|egrep|rg|sed|awk|sort|strings)\b|(?:^|[\s;|&(])(?:cat|tac|head|tail|less|more|bat|nl|echo|printf|print)\b[^;|&\n]*\$[{(\w"]|\.read\(\)|readlines\(\)|readFileSync\(|\.read_text\(|\bFile\.read\(|file_get_contents\(/;

/**
 * A secret file printed by a route the pipeline reader doesn't follow: named to `find … -exec cat {}`, `xargs cat`, a
 * loop's variable, a substitution, a script's `open('.env').read()`, a `while read` loop's `< .env`. Taken as printed
 * when the command line names the file, has a printer, and ends in no stage that prints none of its input and no
 * redirect to a file.
 */
function printsIndirectly(command: string): boolean {
	if (command.length > 8192 || !PRINTER.test(command)) return false;
	// (A file named as a path, `.env`, `config/secrets.yml`, `$HOME/.env`: a bare word or a variable, `token`, `$TOKEN`, is
	// no file's name here.)
	const named = command
		.split(/[\s'"`;|&()<>{}=,]+/)
		.some((w) => /[./]/.test(w) && isSecretFile(w.replace(/^\.\//, "").replace(/[*?]+$/, "")));
	if (!named) return false;
	const run = commandsRun(command);
	const last = run.at(-1);
	return !!last && passesThrough(last) && stdoutFile(last) === undefined;
}

/** The value of an option given as `-d X`, `-dX`, `--delimiter X` or `--delimiter=X`; `short` is `-d`, `long` is `--delimiter`. */
function optionValue(args: string[], short: string, long: string): string | undefined {
	for (let k = 0; k < args.length; k++) {
		const a = args[k];
		if (a === short || a === long) return args[k + 1];
		if (a.startsWith(long + "=")) return a.slice(long.length + 1);
		if (a.startsWith(short)) return a.slice(short.length);
	}
	return undefined;
}

/** Whether a command rewrites its files and prints nothing of them: `sed -i`, `sed -i.bak`, `sed -ni`, `sed --in-place`, `awk -i inplace`. */
function editsInPlace(words: ShellWord[]): boolean {
	const program = programName(words[0]);
	const args = words.slice(1).map((w) => w.text);
	if (program === "sed") return args.some((a) => /^-[a-zA-Z]*i|^--in-place/.test(a));
	return program === "awk" && args.some((a, k) => a === "-i" && args[k + 1] === "inplace");
}

/** What separates a name from its value in a settings file: `NAME=value`, `name: value`. */
const NAME_SEPARATOR = /^[=:]$/;

/**
 * Whether a command cuts each line of a settings file down to its name, so what it prints holds no value: `cut -d= -f1`,
 * `awk -F= '{print $1}'`, or a `sed` that deletes from the `=` to the line's end.
 */
function printsNamesOnly(words: ShellWord[]): boolean {
	const program = programName(words[0]);
	const args = words.slice(1).map((w) => w.text);
	if (program === "cut")
		return (
			NAME_SEPARATOR.test(optionValue(args, "-d", "--delimiter") ?? "") && optionValue(args, "-f", "--fields") === "1"
		);
	if (program === "awk")
		return (
			NAME_SEPARATOR.test(optionValue(args, "-F", "--field-separator") ?? "") &&
			args.some((a) => /^\{\s*print\s+\$1\s*\}$/.test(a))
		);
	if (program === "sed") return args.some((a) => /^s(.)\[?[=:]\]?\.\*\$?\1\1[gp]?$/.test(a));
	return false;
}

/**
 * Whether a command reads a secret file but cuts what it prints to the names (`cat .env | cut -d= -f1`): its output
 * holds a value only where the cut didn't happen, a `NAME=value` line in it.
 */
export function printsSecretFileNames(command: string): boolean {
	const runs = commandsRun(command);
	return (
		runs.some((c) => printsNamesOnly(simpleCommand(c.words))) &&
		runs.some((c) => c.words.some((w) => isSecretFile(w.text)))
	);
}

/** Whether one command reads a secret file's content: `cat .env`, `grep KEY .env`, `git show HEAD:.env`, `env`, `cat < .env`. */
function readsSecretFile(c: ShellCommand): boolean {
	const words = simpleCommand(c.words);
	const program = programName(words[0]);
	const rest = words.slice(1).map((w) => w.text);
	if (SECRET_DUMPS.test(words.map((w) => w.text).join(" "))) return true;
	// `git show HEAD:.env`, `git --no-pager cat-file -p main:config/.env`: a file at a revision.
	if (program === "git") {
		const sub = subcommand(words).map((w) => w.text);
		return (
			/^(?:show|cat-file)$/.test(sub[0] ?? "") &&
			sub.some((t) => /^[^:\s]*:./.test(t) && isSecretFile(t.slice(t.indexOf(":") + 1)))
		);
	}
	// (xargs hands what it reads to the command it runs as words, so echo, its default command, prints it: `xargs -a .env
	// echo`, `xargs < .env`; `xargs -a hosts.txt ping` prints no file.)
	const xargs = xargsInput(c, words);
	if (xargs !== undefined && (program === "xargs" || ECHOES.test(program))) return isSecretFile(xargs);
	// (PowerShell's `Get-ChildItem Env:` and `Get-Item Env:NAME` print the variables as a table of names and values: all
	// of them, or those a wildcard matches; one variable named in full is judged by its name, `Env:AZURE_TENANT_ID`.)
	const drive = /^(?:Get-ChildItem|gci|dir|ls|Get-Item|gi)$/.test(program)
		? rest.find((t) => /^env:/i.test(t))
		: undefined;
	if (drive !== undefined) return !/^env:\\?\w+$/i.test(drive) || isCredentialName(drive.replace(/^env:\\?/i, ""));
	if (!CONTENT_COMMANDS.test(program) || printsNamesOnly(words) || editsInPlace(words)) return false;
	// (`env` here runs no command: simpleCommand reads past it to the one it runs. `env -0` prints the environment too;
	// `printenv NAME` prints one variable, judged by its name: printsSecret.)
	if (
		program === "env" ||
		(/^(printenv|export|declare|set)$/.test(program) &&
			(rest.length === 0 ||
				(program === "printenv" && rest.every((t) => t.startsWith("-"))) ||
				(program === "declare" && rest[0] === "-p") ||
				(program === "export" && rest[0] === "-p")))
	)
		return true;
	// (A redirection's target is read when it is `<`'s: `cat < .env`; `echo x > .env` prints nothing.)
	if (allRedirects(c).some((r) => r.op === "<" && r.target && isSecretFile(r.target.text))) return true;
	// (Counting, listing and testing print none of what grep reads: `grep -c`, `grep -l`, `grep -q`.)
	if (/^(?:grep|egrep|fgrep|rg|ag|ack|zgrep)$/.test(program) && rest.some((t) => countsMatches(program, t)))
		return false;
	// (A word with backslashes is read as written, a Windows path whatever else the line holds: PowerShell's `cat
	// apps\web\.env.local`.)
	const args = words.slice(1).map((w) => (/\\/.test(w.raw) && !/['"$`]/.test(w.raw) ? w.raw : w.text));
	const files = /^(?:grep|egrep|fgrep|rg|ag|ack|zgrep|Select-String|sls)$/.test(program)
		? searchedFiles(args)
		: args.filter((t) => !t.startsWith("-"));
	// (A glob's trailing wildcard, `cat .env*`, takes in the file it starts with.)
	return files.some((t) => isSecretFile(t.replace(/[*?]+$/, "")));
}

/**
 * The files a search reads (grep, ripgrep, Select-String), from its words after the program: its operands but the
 * pattern, which is the first unless an option gives it (`grep -rn password src/`, `grep -e KEY .env`, `grep -ePASS
 * .env`, `Select-String -Pattern KEY -Path .env`). An option's value is no operand: `grep -m 1 token src/`.
 */
function searchedFiles(rest: string[]): string[] {
	const operands: string[] = [];
	let pattern = false;
	for (let k = 0; k < rest.length; k++) {
		const t = rest[k];
		if (/^-[ef]|^--(?:regexp|file)(?:=|$)/.test(t) || /^-Pattern$/i.test(t)) pattern = true;
		if (VALUE_OPTIONS.grep!.test(t) || /^-(?:Pattern|Context)$/i.test(t)) k++;
		else if (!t.startsWith("-")) operands.push(t);
	}
	return operands.slice(pattern ? 0 : 1);
}

/**
 * The file a command's xargs (a wrapper before `words`, its simple command, or that command) reads its words from: its
 * `-a FILE` (`-aFILE`, `--arg-file=FILE`), or else its input's `< FILE`.
 */
function xargsInput(c: ShellCommand, words: ShellWord[]): string | undefined {
	const k = c.words.findIndex((w) => programName(w) === "xargs");
	if (k < 0 || k > c.words.length - words.length) return undefined;
	// (Its options and their values run up to the command it runs, which simpleCommand found past them: `xargs -n 1 -a
	// .env echo`, `xargs -d '\n' -a .env`.)
	const end = words.length && programName(words[0]) !== "xargs" ? c.words.length - words.length : c.words.length;
	for (let i = k + 1; i < end; i++) {
		const w = c.words[i].text;
		if (!w.startsWith("-") || w === "--") continue;
		if (w === "-a" || w === "--arg-file") return c.words[i + 1]?.text;
		if (w.startsWith("--arg-file=")) return w.slice(11);
		if (w.startsWith("-a")) return w.slice(2);
	}
	return allRedirects(c).find((r) => r.op === "<")?.target?.text;
}

/**
 * Whether what a command reads (`reads`: a secret file, a credential) reaches what it prints: in some pipeline of it, the
 * stage that reads it, then no stage that prints none of its input (`| wc -l`, `| sha256sum`, `| wl-copy`, `grep -c`;
 * any other program is taken to print what it reads: `| nl`, `| xargs`, `| python3 -c …`), and the last stage's output
 * not redirected to a file (`> /tmp/backup`), unless a later command reads that copy (`> /tmp/x; cat /tmp/x`). Run by
 * a substitution, it is printed only by a command that prints its arguments (`echo "$(cat .env)"`; not `export $(grep
 * … .env)`) or reads it as a file (`diff <(…)`).
 */
function printsWhatItReads(
	command: string,
	reads: (c: CommandRun) => boolean,
	source?: (path: string) => boolean,
): boolean {
	const run = commandsRun(command);
	// The files a pipeline wrote what it read to, or that `cp`/`mv` made of a `source`: a later command that reads one
	// reads it too.
	const copies = new Set<string>();
	const readsCopy = (c: ShellCommand) =>
		copies.size > 0 &&
		CONTENT_COMMANDS.test(programName(simpleCommand(c.words)[0])) &&
		[
			...simpleCommand(c.words)
				.slice(1)
				.map((w) => w.text),
			...allRedirects(c)
				.filter((r) => r.op === "<")
				.map((r) => r.target?.text ?? ""),
		].some((t) => copies.has(t));
	// (Pipelines are read among the commands that share a host: the line's, or one substitution's.)
	let pipeline: CommandRun[] = [];
	for (let k = 0; k < run.length; k++) {
		const c = run[k];
		const words = simpleCommand(c.words).map((w) => w.text);
		if (
			source &&
			/^(?:cp|mv|install|ln)$/.test(programName(simpleCommand(c.words)[0])) &&
			words.slice(1, -1).some((t) => !t.startsWith("-") && (source(t) || copies.has(t)))
		)
			copies.add(words.at(-1)!);
		pipeline.push(c);
		if ((c.then === "|" || c.then === "|&") && run[k + 1]?.host === c.host) continue;
		const stages = pipeline;
		pipeline = [];
		const at = stages.findIndex((s) => reads(s) || readsCopy(s));
		if (at < 0) continue;
		const host = stages[at].host && programName(simpleCommand(stages[at].host.words)[0]);
		// (`export`, `declare`, `set`, `env` given words assign them; they print the environment only alone.)
		// (A content command reads a process substitution as a file, `diff <(…) x`; what `$(…)` gives it is an argument,
		// like `sed "s/^KEY=.*/KEY=$(openssl rand -hex 32)/" .env`'s script.)
		const readAsFile = command.slice(Math.max(0, stages[at].start - 2), stages[at].start) === "<(";
		if (
			host &&
			!ECHOES.test(host) &&
			!(CONTENT_COMMANDS.test(host) && !/^(?:export|declare|set|env|printenv)$/.test(host) && readAsFile)
		)
			continue;
		if (!stages.slice(at + 1).every(passesThrough)) continue;
		const file = stdoutFile(stages.at(-1)!);
		if (file === undefined) return true;
		copies.add(file);
	}
	return false;
}

/**
 * Whether what a command prints goes into the next command's input: by its own `|`, or by a group's around it, whatever
 * follows it inside the group (`{ echo A=1; echo B=2; } | tee .env`).
 */
export function pipes(c: ShellCommand): boolean {
	return [c.then, ...c.groups.map((g) => g.then)].some((then) => then === "|" || then === "|&");
}

/** Devices that are what's shown: a tool's captured output holds stdout and stderr, and a terminal shows both. */
const SHOWN = /^\/dev\/(?:stdout|stderr|tty|fd\/[12])$/;

/** The file a command's output goes to, not to what's shown: `> out`, `>> log`, `&> /dev/null`, `>& out` (not `2>`, `>&2`, `> /dev/stderr`). */
function stdoutFile(c: ShellCommand): string | undefined {
	const r = allRedirects(c).find((r) => redirectsStdout(r) && !SHOWN.test(r.target?.text ?? ""));
	return r ? (r.target?.text ?? "") : undefined;
}

/**
 * Whether a grep's option prints a count, a file list or nothing instead of the lines: `-c`, `-l`, `-L`, `-q`,
 * `--count`. (ripgrep's `-L` follows links and prints the lines.)
 */
function countsMatches(program: string, option: string): boolean {
	return (
		(program === "rg" ? /^-[a-zA-Z]*[clq][a-zA-Z]*$/ : /^-[a-zA-Z]*[clLq][a-zA-Z]*$/).test(option) ||
		/^--(?:count|files-with(?:out)?-matches|quiet|silent)$/.test(option)
	);
}

/**
 * Programs that print none of their input: counts, checksums, a clipboard's tools, tests, compressors and encrypters
 * (their output is the input made unreadable). Any other stage of a pipeline is taken to pass on what it reads (`nl`,
 * `xargs`, `perl -pe`, `python3 -c …`, `bat`): what it prints can't be known.
 */
const PRINTS_NONE_OF_INPUT =
	/^(?:wc|md5sum|sha\d*sum|b2sum|shasum|cksum|sum|pbcopy|xclip|xsel|wl-copy|clip|clip\.exe|true|false|test|\[|cmp|gzip|bzip2|xz|zstd|lz4|age|ssh-add)$/;

/**
 * A stage that takes its input as a secret to store or use, printing only its own messages: `docker login
 * --password-stdin`, `gh auth login --with-token`, `gh secret set`, `kubectl create secret … --from-file=/dev/stdin`,
 * `vault kv put … -`, `gpg -c`, `openssl enc`, `tar`. (Not one that decrypts, `openssl enc -d`, nor gpg's `--clearsign`,
 * which prints its input signed but in the clear; nor `vault login -`, which prints the token it logged in with.)
 */
function consumesInput(command: ShellWord[]): boolean {
	const program = programName(command[0]);
	const words = command.map((w) => w.text);
	const sub = words[1] ?? "";
	return (
		words.some((w) =>
			/^--(?:password|token|identity-token)-stdin$|^--(?:from-file|data-file|body-file)=(?:-|\/dev\/stdin)$/.test(w),
		) ||
		(program === "gh" && ((sub === "auth" && words.includes("--with-token")) || sub === "secret")) ||
		(program === "kubectl" && /^(?:create|apply|replace)$/.test(sub)) ||
		(program === "vault" && /^(?:kv|write)$/.test(sub)) ||
		(program === "openssl" &&
			/^(?:enc|dgst|pkeyutl|rsautl|smime|cms)$/.test(sub) &&
			!words.some((w) => /^-(?:d|decrypt)$/.test(w))) ||
		(program === "gpg" && words.some((w) => /^-[a-z]*[ec][a-z]*$|^--(?:encrypt|symmetric|sign)$/.test(w))) ||
		program === "tar"
	);
}

/** Whether a command prints a credential: any of its pipelines (`openssl rand -hex 32 && echo ok`) whose stage that makes one reaches its output. */
export function printsSecret(command: string): boolean {
	return printsExpression(command) || printsWhatItReads(command, printsCredential);
}

/**
 * A command line that is one expression, which PowerShell prints (as a REPL does; a POSIX shell runs a variable's value
 * as a command and prints it in its error): a variable, `$env:NAME`, its members (`$cred.GetNetworkCredential().Password`),
 * or a command's in parentheses (`(Get-Item Env:TOKEN).Value`).
 */
const EXPRESSION = /^[ \t]*(?:\$\{?(?:env:)?[A-Za-z_]\w*\}?|\([^()\n]{1,200}\))(?:\.[A-Za-z_]\w*(?:\(\))?)*[ \t]*$/i;

/**
 * Whether a command line is an expression (EXPRESSION) that prints a credential: by its last member's name, or with
 * none, or a `Value` (an entry's), by its variables' (`$cred.UserName` is a name; `$env:TOKEN`, `(Get-Item
 * Env:TOKEN).Value` are the token).
 */
function printsExpression(command: string): boolean {
	if (!EXPRESSION.test(command)) return false;
	const member = /\.([A-Za-z_]\w*)(?:\(\))?[ \t]*$/.exec(command)?.[1];
	// (A dictionary's keys are its names, `$hash.Keys`, `(Get-Command x).Parameters.Keys`, and an entry's `$_.Key`.)
	if (member !== undefined && !/^value$/i.test(member))
		return !/^(?:all)?keys?$/i.test(member) && isCredentialName(member);
	return variablesIn(command).some(isCredentialName);
}

/**
 * The variables a text reads, by their names, in any shell's syntax: `$NAME`, `${NAME}`, PowerShell's `$env:NAME`,
 * `${env:NAME}` and its drive's `Env:NAME`, cmd's `%NAME%`.
 */
function variablesIn(text: string): string[] {
	return [...text.matchAll(/\$\{?(?:env:)?([A-Za-z_]\w*)|%([A-Za-z_]\w*)%|\benv:([A-Za-z_]\w*)/gi)].map(
		(m) => m[1] ?? m[2] ?? m[3],
	);
}

function passesThrough(c: ShellCommand): boolean {
	const words = simpleCommand(c.words);
	const program = programName(words[0]);
	// (A grep passes the lines it matches; counting, listing or testing them passes none: `grep -c`, `-l`, `-q`.)
	if (/^(?:grep|egrep|fgrep|rg|ag|ack)$/.test(program))
		return !words.slice(1).some((w) => countsMatches(program, w.text));
	// (Nor a stage that prints the public key of the private key it reads: `wg pubkey`, `openssl pkey -pubout`.)
	const publicOfInput =
		(program === "wg" && words[1]?.text === "pubkey") ||
		(program === "openssl" && words.some((w) => w.text === "-pubout"));
	return !printsNamesOnly(words) && !PRINTS_NONE_OF_INPUT.test(program) && !consumesInput(words) && !publicOfInput;
}

/** How much of a command SECRET_TOOLS reads: its patterns have several `.*`, quadratic on a very long line. */
const MAX_TOOL_LINE = 4000;

/**
 * Whether one command prints a credential: a tool that prints one (SECRET_TOOLS), a secret source it reads or calls
 * (`head -c 32 /dev/urandom`, `python -c 'print(secrets.token_hex())'`), or a credential variable printed on its own
 * (`echo $DB_PASSWORD`, `printf 'Token: %s\n' "$TOKEN"`, `printenv OPENAI_API_KEY`).
 */
function printsCredential(c: ShellCommand): boolean {
	const words = simpleCommand(c.words);
	// (Read from the program's own name on: `/usr/bin/gh auth token` is `gh auth token`.)
	const line = [programName(words[0]), ...words.slice(1).map((w) => w.text)].join(" ").slice(0, MAX_TOOL_LINE);
	if (SECRET_TOOLS.test(line) || SECRET_SOURCES.test(line)) return true;
	const program = programName(words[0]);
	const args = words.slice(1);
	if (program === "printenv") return args.length === 1 && isCredentialName(args[0].text);
	// (A script given on the command line that prints a credential's variable: `python3 -c "print(os.environ['TOKEN'])"`,
	// `node -e "console.log(process.env.TOKEN)"`.)
	if (INTERPRETER.test(program) && PRINTS.test(line))
		return [...line.matchAll(ENV_READ)].some((m) => isCredentialName(m[1] ?? m[2]));
	if (program !== "echo" && program !== "printf" && !/^write-(?:host|output)$/i.test(program)) return false;
	// (printf prints its format and its operands alike, `printf "Token: %s\n" "$TOKEN"`, `printf "$TOKEN"`; but `-v NAME`
	// assigns what it would print and prints nothing.)
	const values =
		program === "echo"
			? args.filter((w) => !/^-[neE]+$/.test(w.text))
			: args[0]?.text === "-v"
				? []
				: args.filter((w) => w.text !== "--");
	// (A credential's variable printed alone, `echo $DB_PASSWORD`, `echo %DB_PASSWORD%`, or inside its words, `echo
	// "token: $GITHUB_TOKEN"`.)
	return values.some((v) => !v.literalEnd && variablesIn(v.text).some(isCredentialName));
}

/** Interpreters that run a script given on their command line. */
const INTERPRETER = /^(?:python[\d.]*|node|deno|bun|ruby|perl|php)$/;
/** What prints in those scripts. */
const PRINTS = /\b(?:print|puts|console\.log|echo|say|process\.stdout\.write)\b/;
/** A read of an environment variable in those scripts, by its name. */
const ENV_READ =
	/(?:os\.environ(?:\.get)?|os\.getenv|\bENV(?:\.fetch)?|\bgetenv|\$_ENV|\$ENV)\s*[[({]\s*["']([A-Za-z_]\w*)["']|process\.env\.([A-Za-z_]\w*)/g;

/** How a command-line tool takes a password. */
export interface ToolSpec {
	/** Options whose value is a password: `-p pw`, `--password pw`, `--password=pw`. */
	flags: Set<string>;
	/**
	 * How an option takes its value when it isn't attached: the next word, whatever it is (getopt's required argument:
	 * `-a '-Xk9…'`); the next word unless it is an option (an optional one: `mongosh -p` alone prompts); or never
	 * (mysql's `--password` alone prompts, and the next word is the database).
	 */
	next: "always" | "unless an option" | "never";
	/** Whether a one-letter option may carry its value attached (`-pPW`); not for tools with one-dash long options (`influx -precision`). */
	attached: boolean;
	/** Whether only a subcommand takes it (`docker login -p pw`; `docker run -p 443:443` is a port). */
	subcommand?: string;
	/** A wrapper that runs another command after its own options (`sshpass -p pw ssh -p 2222 host`). */
	wraps?: boolean;
}

/** Tools by name, and how each takes a password (structure.ts reads them). */
const TOOLS: [RegExp, ToolSpec][] = [
	[
		/^(?:docker|podman|helm|oras|crane|skopeo|buildah|nerdctl|regctl|cosign)$/,
		{ flags: new Set(["-p", "--password"]), next: "always", attached: false, subcommand: "login" },
	],
	[/^sshpass$/, { flags: new Set(["-p"]), next: "always", attached: true, wraps: true }],
	[/^(?:redis|valkey|keydb)-cli$/, { flags: new Set(["-a", "--pass"]), next: "always", attached: true }],
	[
		/^ldap(?:search|modify|add|delete|passwd|whoami|compare|modrdn)$/,
		{ flags: new Set(["-w"]), next: "always", attached: true },
	],
	[/^(?:smbclient|svn|rpcclient|net)$/, { flags: new Set(["--password"]), next: "always", attached: false }],
	[
		/^mongo(?:sh|dump|restore|export|import|stat|top)?$/,
		{ flags: new Set(["-p", "--password"]), next: "unless an option", attached: false },
	],
	[/^influx$/, { flags: new Set(["-p", "--password", "-password"]), next: "always", attached: false }],
	[/^(?:sqlcmd|bcp|sqlpackage)$/, { flags: new Set(["-P"]), next: "always", attached: false }],
	[/^(?:supabase|altool)$/, { flags: new Set(["-p", "--password"]), next: "always", attached: false }],
	[/^mosquitto_(?:pub|sub|rr)$/, { flags: new Set(["-P", "--pw"]), next: "always", attached: false }],
	[/^beeline$/, { flags: new Set(["-p"]), next: "always", attached: false }],
	[/^cypher-shell$/, { flags: new Set(["-p", "--password"]), next: "always", attached: false }],
	[/^az$/, { flags: new Set(["-p", "--password"]), next: "always", attached: false, subcommand: "login" }],
	[/^gh$/, { flags: new Set(["-b", "--body"]), next: "always", attached: false, subcommand: "secret" }],
	[/^(?:zip|unzip|zipcloak)$/, { flags: new Set(["-P", "--password"]), next: "always", attached: false }],
	// (`7z x f.7z -pPW`: attached only; `-p` alone prompts.)
	[/^(?:7z|7za|7zr)$/, { flags: new Set(["-p"]), next: "never", attached: true }],
	[
		/^keytool$/,
		{
			flags: new Set([
				"-storepass",
				"-keypass",
				"-srcstorepass",
				"-deststorepass",
				"-srckeypass",
				"-destkeypass",
				"-new",
			]),
			next: "always",
			attached: false,
		},
	],
	// MySQL's and MariaDB's clients, which share one option parser. (`-p` alone prompts; the password is attached, `-pPW`,
	// or given as `--password=PW`.)
	[
		/^(?:mysql(?:admin|binlog|check|dump|import|pump|show|slap|sh|_upgrade|_secure_installation)?|mariadb(?:-(?:admin|binlog|check|dump|import|show|slap|upgrade|secure-installation))?)$/,
		{ flags: new Set(["--password"]), next: "never", attached: true },
	],
];

/** How the tool a program names takes a password, if it takes one by an option. */
export function passwordOptions(program: string): ToolSpec | undefined {
	return TOOLS.find(([re]) => re.test(program))?.[1];
}

/**
 * The simple command (shell.ts simpleCommand: past wrappers and assignments) whose words hold `at`, and the word at
 * `at`: among the commands its line runs (`mysql` in `docker exec db mysql --password …`), or else among the line's
 * commands as written (`docker` in `docker exec -u www-data:www-data app …`, which runs `app …`'s command).
 */
export function commandAt(text: string, at: number): { command: ShellWord[]; word: ShellWord } | undefined {
	for (const commands of lineCommands(text, at)) {
		for (const c of commands) {
			const word = c.words.find((w) => w.start <= at && at < w.end);
			if (word) return { command: simpleCommand(c.words), word };
		}
	}
	return undefined;
}

/**
 * The commands that the line holding `at` runs, and the line's commands as written: read once per line of the last
 * text asked about (its line starts found once too, so a long line's many options cost one reading).
 */
const readLines = lastText((text) => {
	const starts = [0];
	for (let i = text.indexOf("\n"); i >= 0; i = text.indexOf("\n", i + 1)) starts.push(i + 1);
	return { starts, lines: new Map<number, ShellCommand[][]>() };
});
function lineCommands(text: string, at: number): ShellCommand[][] {
	const { starts, lines } = readLines(text);
	const start = starts[lowerBound(starts, at + 1) - 1];
	let both = lines.get(start);
	if (!both)
		lines.set(
			start,
			(both = [commandsRun(text, { at: start, oneLine: true }), commandLine(text, start, { oneLine: true })]),
		);
	return both;
}

/**
 * Whether the word after the option at `at` is not its value, because the option takes one only attached:
 * `mysql -u root --password mydb` prompts, and `mydb` is the database.
 */
export function promptsForValue(text: string, at: number): boolean {
	const found = commandAt(text, at);
	const spec = found?.command.length ? passwordOptions(programName(found.command[0])) : undefined;
	return spec?.next === "never" && spec.flags.has(found!.word.text);
}
