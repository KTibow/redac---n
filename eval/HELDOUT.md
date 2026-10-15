# Held-out sets and their blind scores

Each set is scored once, blind, before anything about its cases is looked at; after that it becomes development
data and a fresh set takes its place (scores after fixes are in the second table). Scores are recall (secrets caught) / loss (look-alike values
destroyed) on labelled sets, and redactions per million characters on real text. The first held-out set is the
exception: it was scored three times (twice during development, once for the README), aggregates only, and is
never inspected or used as development data.

The redac---n columns are its three settings of `guessing`, `"off"` / `"confident"` (the default) / `"eager"`
(called `precise` / `balanced` / `aggressive` when these runs were made). The sets live in `eval/corpora/`, gzipped (`holdout2.jsonl` below is `holdout2.jsonl.gz` there): the fake credentials
in them would otherwise read as real ones to secret scanners.

| date | set | how it was made | redac---n (precise / balanced / aggressive) | best other (gitleaks+Betterleaks+Kingfisher) |
|---|---|---|---|---|
| 2026-10-08 | holdout.jsonl, 1,112 cases | blind agent, seeded generator | 88.7/0.6 · 91.7/1.9 · 91.8/2.0 | 70.6/2.2 |
| 2026-10-09 | final, 243 M chars of real text | 12 new repos, unused trajectory shards | 3.8 · 5.0 · 5.2 per M chars | (60 M sample) 17.3 |
| 2026-10-09 | final2, 279 M chars of real text | 12 more repos, more unused shards | 4.8 · 5.5 · 5.6 per M chars | not run |
| 2026-10-09 | final3, 254 M chars of real text | 12 more repos (vite, loki, kind, black, fiber, channels, sqlmodel, remix, chi, cobra, kratos, packer), Kwai-Klear train-00030/00040, nebius train-00011 | 3.3 · 4.1 · 4.3 per M chars (SHA/UUID 0.11 · 0.13 · 0.16) | not run |
| 2026-10-09 | holdout2.jsonl, 848 cases, 1,551 secrets, 3,025 keeps, 563 contexts | blind template writers + seeded filler (templates/, fill_templates.py) | 78.3/3.7 · 86.8/5.7 · 87.9/6.0 | 60.3/5.1 |
| 2026-10-09 | holdout3.jsonl, 450 cases, 712 secrets, 1,672 keeps, 434 contexts | blind template writer (mobile, ML, IoT, enterprise, other CI vendors, SaaS exports, devtools, agent transcripts) + seeded filler | 78.5/3.2 · 85.5/7.4 · 85.8/8.7 | 64.0/4.8 |
| 2026-10-09 | SlotGuard credentials.json (Apache-2.0), 200 multi-turn sessions, 852 planted secrets, 1,007 task anchors kept | third-party benchmark, never seen | 53.1/0.0 · 62.6/0.0 · 62.6/0.0 (balanced: 533 of the 652 credentials; 119 were string literals split in two (`"xoxb-…" "…"`) with one half left, and the other 200 misses are planted email addresses, which this library leaves alone) | 29.2/0.0 (best single: CredSweeper 46.9/0.0) |
| 2026-10-09 | ProwlBench (PolyForm NC, eval only), 14,866 snippets without the CredData-derived rows: 7,491 secrets, 7,375 secret-free snippets (any redaction is a loss) | third-party benchmark, never seen | 78.6/7.8 · 89.4/12.5 · 90.1/13.5 | 59.1/8.7 (best single by recall: detect-secrets 63.8/19.1, then CredSweeper 60.8/13.7, Nosey Parker 59.9/5.4) |
| 2026-10-09 | crossvault/redact-transcripts vectors (CC0), 113 vectors | third-party test vectors, never seen | 9.9/0.0 in every mode: every value contains `FAKE` or `EXAMPLE`, which this library treats as a published placeholder by design | — |
| 2026-10-09 | holdout4.jsonl, 478 cases, 625 secrets, 1,613 keeps, 440 contexts | two blind template writers (everyday agent sessions across web stacks and clouds; issue and PR threads, Q&A) + seeded filler (seed 4040). The prose writer was stopped by a safety classifier after 44 templates and wasn't retried | 86.7/0.7 · 90.4/1.9 · 90.6/2.0 | 66.2/3.6 (best single: CredSweeper 74.1/20.4) |
| 2026-10-09 | final4, 184 M chars of real text | 12 more repos (k6, prisma, redis-py, sinatra, symfony/console, viper, nats-server, ktor, phoenix, vitest, httpie, eShop), Kwai-Klear train-00045, nebius train-00003, and Trace Commons (30 real donated agent sessions, messages as JSON) | 4.1 · 5.6 · 5.8 per M chars (SHA/UUID 0.23 · 0.29 · 0.29) | not run |
| 2026-10-09 | holdout5.jsonl, 352 cases, 486 secrets, 4,682 keeps, 352 contexts | blind template writer: agent session logs as stored or sent (Claude Code JSONL, Codex rollouts, Anthropic/OpenAI/Gemini request bodies, Responses items, terminal copies), values reused across turns + seeded filler (seed 5050) | 90.7/0.1 · 95.3/1.7 · 95.3/1.8 | 69.5/1.1 (best single: CredSweeper 84.4/28.7) |
| 2026-10-09 | final5, 321 M chars of real text | 12 more repos (mattermost, discourse_docker, zulip, outline, appwrite, pocketbase, directus, keycloak-quickstarts, harbor, woodpecker, coder, supabase/auth), Kwai-Klear train-00035, nebius train-00007, and AIDev (agent-written pull requests and review comments with diff hunks) | 5.4 · 22.5 · 23.1 per M chars (SHA/UUID 0.68 · 0.70 · 0.71) | not run |
| 2026-10-09 | holdout6.jsonl, 112 cases, 133 secrets, 259 keeps | blind template writer (regional clouds: Alibaba, Tencent, Huawei, Yandex, Naver, OVH, Scaleway, Hetzner, IONOS, Exoscale; regional payment and messaging APIs) + seeded filler (seed 6060); the writer was stopped by a safety classifier after 112 of ~400 templates and wasn't retried | 78.9/5.8 · 93.2/9.3 · 93.2/11.6 | 61.7/3.1 (best single: CredSweeper 73.7/18.1) |
| 2026-10-09 | holdout7.jsonl, 305 cases, 289 secrets, 586 keeps, 305 contexts | blind template writer (databases and queues, observability, access tooling, build and package tooling, self-hosted Compose stacks) + seeded filler (seed 7070) | 85.1/3.8 · 93.4/8.5 · 93.8/9.4 | 69.6/3.1 (best single: CredSweeper 67.5/19.8) |
| 2026-10-09 | ICSME 2026 three-class credential set, public "no leak" class (Apache-2.0, Zenodo 22942243): 5,903 code snippets in 10 languages that handle credentials but contain none (2.8 M chars) | third-party benchmark, never seen | snippets with any redaction: 4.5% · 4.6% · 4.7% (322 · 337 · 340 spans; 114 · 120 · 121 per M chars) | 211 per M chars (best single: Kingfisher 1.1, gitleaks 4.6, CredSweeper 24.9) |
| 2026-10-09 | levainbot/fp-corpus (MIT): 116 sections of ordinary log and build output with no credentials (866 lines), and 45 sections with 85 planted credentials (82 ordinary, 3 marked hard) | third-party set, never seen | secret-free sections hit: 1 · 3 · 4 of 116 (1 · 4 · 6 spans); planted caught: 90.2% · 92.7% · 92.7% (hard: 2 · 3 · 3 of 3); all 85: 89.4% · 92.9% · 92.9% | 64.7% of 85; spans on the secret-free half: 3 + 5 + 1 (best single: CredSweeper 80.0%, 21 findings on the secret-free half) |
| 2026-10-09 | LLM-Redactor wl2_secrets (MIT, arXiv 2604.12064): 300 config and log snippets, 516 secrets (API keys, passwords, bearer tokens, AWS keys, PEM keys), 214 hostnames, emails and IPs to keep | third-party set, never seen | 87.2/0.0 · 94.8/0.0 · 94.8/0.0 | 61.2/0.9 (best single: CredSweeper 87.0/0.0; all seven combined 95.9/0.9) |
| 2026-10-09 | final6, 190 M chars of real text | 12 repositories that handle credentials (authelia, ory/hydra, django-allauth, next-auth, passport, lucia, awx, open-webui, kong, dex, authentik, oauth2-proxy), Kwai-Klear train-00025, nebius train-00004 | 9.8 · 17.0 · 18.7 per M chars (SHA/UUID 0.33 · 0.35 · 0.35) | not run |
| 2026-10-09 | holdout8.jsonl, 261 cases, 246 secrets, 610 keeps, 261 contexts | blind template writer (data and analytics engineering: dbt, Airflow, Dagster, Spark/Databricks, warehouse CLIs, Kafka, notebooks, ELT tools, BI, MLflow/W&B) + seeded filler (seed 8080) | 83.7/0.8 · 89.0/1.5 · 89.0/1.6 | 67.9/1.8 (best single: CredSweeper 72.4/16.7) |
| 2026-10-09 | Nemotron-PII (NVIDIA, CC-BY-4.0): 5,000 business documents, 4,458 password, API-key and session-cookie spans, 13,027 IDs to keep | data agent | balanced 44.7/0.3 (precise 28.9/0.2) | 14.1/0.4 (best single: CredSweeper 15.5/1.4) |
| 2026-10-09 | OpenHands feedback (MIT): 275 real user sessions, 61 M chars | data agent | 10.15 per M chars balanced, about 30 of 623 true | 2.4 spans per M |
| 2026-10-09 | Titus rule examples (Apache-2.0): 542 rules, 1,142 secrets, 584 negatives | data agent | balanced 60.5/10.8 | 60.7/15.2 |
| 2026-10-09 | Loghub (eval only): 92 M chars of system logs | data agent | 0.56 per M chars balanced | 0 |
| 2026-10-09 | 53 RFCs' examples and test vectors, 5.3 M chars | data agent | 312.8 per M chars balanced (mostly line-wrapped JOSE examples) | 51.8 spans per M |
| 2026-10-09 | Claude Code session files (MIT): 73 M chars of real sessions | data agent | 1.77 per M chars balanced, about 63 of 130 real keys | 0.56 spans per M |
| 2026-10-09 | LLM-SecDB (CC-BY-4.0): 46 secrets in arXiv LaTeX comments | data agent | balanced 78.3/0.0 | 43.5/0.0 (CredSweeper 50.0) |
| 2026-10-09 | Stack Exchange (Server Fault, Security, DevOps; eval only): 66.5 M chars | data agent | 28.6 per M chars balanced (43% nginx `proxy_pass`) | 12.4 spans per M |
| 2026-10-09 | Gretel finance + nym multilingual PII (Apache-2.0, MIT): 3,226 password and API-key spans in 22 languages, 8,226 values to keep | data agent | balanced 48.3/0.0 (passwords about 5%) | CredSweeper 40.9/0.3 |
| 2026-10-09 | leak-museum + leaky-repo (MIT): 186 secrets in committed dotfiles and app configs, read whole | data agent | balanced 37.1 pasted, 41.9 after `cat` (65.1 and 70.8 without placeholders and hashes) | detect-secrets 34.4 |
| 2026-10-09 | Qiita + Habr (MIT, eval only): 60.1 M chars of Japanese and Russian developer articles | data agent | 9.94 per M chars balanced (about 270 false) | 8.62 per M (g+B+K) |
| 2026-10-09 | Kaggle notebooks with outputs (eval only), raw .ipynb: 21.7 M chars | data agent | 1.56 per M chars balanced | 0.09 per M |
| 2026-10-09 | Terraform, Helm and Ansible repositories (eval only): 35.3 M chars | data agent | 5.18 per M chars balanced (about 70 false) | 9.91 per M |
| 2026-10-09 | Android, iOS and Flutter repositories (eval only): 53.5 M chars | data agent | 6.70 per M chars balanced (about 290 false) | 10.93 per M |
| 2026-10-09 | Unity, Godot, Bevy, OpenRA, Minetest repositories (eval only): 48.4 M chars | data agent | 2.19 per M chars balanced (all false) | 0.25 per M |
| 2026-10-09 | OSV advisories (CC-BY-4.0, CC0, Apache-2.0): 60.0 M chars of advisory JSON | data agent | 11.00 per M chars balanced (about 280 false) | 3.73 per M |
| 2026-10-09 | GitHub Actions logs of 36 repositories and LCA failed-build logs (eval only): 53.0 M chars | data agent | 16.21 per M chars balanced, 9.41 of them one SHA repeated (3.0 without that run) | 1.15 per M |
| 2026-10-09 | TermGrade terminal-agent trajectories (Apache-2.0): 60.3 M chars | data agent | 6.14 per M chars balanced (all false) | 0.00 per M |
| 2026-10-09 | CTF writeups and solve scripts (CC0, MIT, eval only): 22.7 M chars | data agent | 33.97 per M chars balanced | 5.64 per M |
| 2026-10-09 | PyPI READMEs and release metadata (MIT): 60.0 M chars | data agent | 8.76 per M chars balanced (about 275 false) | 11.12 per M |
| 2026-10-09 | "Hiding in Plain Sight" obfuscation benchmark (MIT): 12,150 obfuscated credentials | data agent | balanced 79.3 (90.4 without encoded AWS key IDs; zero-width-separated: 0 of 810) | detect-secrets 71.3 |
| 2026-10-15 | holdout9.jsonl, 300 cases, 518 secrets, 530 keeps, 300 contexts | three blind template writers (the 2026 AI and agent ecosystem: MCP client configs, model providers, vector stores, inference platforms; JVM and .NET business applications; SaaS integrations: commerce, payments, messaging, auth, CMS) + seeded filler (seed 9090). The JVM/.NET writer was stopped by a safety classifier after 60 of 120 templates, and a fourth writer (one tool's output in many presentations) before writing any; neither was retried | 89.8/4.0 · 94.0/7.9 · 94.2/8.1 | not run |
| 2026-10-15 | final7, 205 M chars of real text | 12 more repositories (litellm, dify, n8n, rails, django, spring-boot, jellyfin, prometheus, vault, sentry-javascript, nextcloud, esphome), Kwai-Klear train-00017, nebius train-00006; scored after the code-fence fix and before any other change of this round | 4.09 · 4.83 · not run per M chars (SHA/UUID 0.14 · 0.19) | not run |

## What each set became after its blind run

| held-out set | development copy |
|---|---|
| holdout.jsonl (held-out 1) | none: still held out |
| holdout2.jsonl | dev_d.jsonl |
| holdout3.jsonl | dev_e.jsonl |
| holdout4.jsonl | dev_f.jsonl |
| holdout5.jsonl | dev_g.jsonl |
| holdout6.jsonl | dev_h.jsonl |
| holdout7.jsonl | dev_i.jsonl |
| holdout8.jsonl | dev_j.jsonl |
| holdout9.jsonl | dev_k.jsonl |
| final2–final6 | real-text sets used to find false positives |
| levainbot/fp-corpus | ~/Downloads/redact-corpora/levain (outside the repository); its misses drove the Resend, Airtable and email-user URL fixes and the protobuf veto |
| ICSME 2026 "no leak" snippets | ~/Downloads/redact-corpora/icsme (outside the repository); its hits drove the code-shape rules in src/policy.ts and the guard in test/benign.test.ts |
| SlotGuard, ProwlBench, GitLab rule examples | converted by scripts/build-external.py into ~/Downloads/redact-corpora/built/external/ (outside the repository); their failures were inspected and drove fixes. ProwlBench's licence (PolyForm Noncommercial) was used for that analysis only; none of its data is redistributed |

## Scores after fixes (not blind)

| date | set | result (balanced unless noted) |
|---|---|---|
| 2026-10-09 | final5 | 6.6 redactions per M characters (from 22.5 blind) |
| 2026-10-09 | SlotGuard | 652 of 652 credentials (76.5% of all planted values; the rest are email addresses) |
| 2026-10-09 | ProwlBench | 93.1 / 12.0 |
| 2026-10-09 | GitLab rule examples (2,038 examples, 168 negatives) | 81.4% caught / 23% of negatives hit before the vendor formats they showed missing were added; 88.5% / 16.1% after |
| 2026-10-09 | ICSME 2026 "no leak" snippets | 1.3% of snippets hit, 31.6 per M chars (from 4.6%, 120 blind); the CredData dev split's false lines fell from 846 to 779 with the same fixes, recall unchanged |
| 2026-10-09 | levainbot/fp-corpus | 82 of 85 planted (96.5%; the three left are an email address and two card numbers, which this library leaves alone, so every credential); 1 secret-free section hit (`::add-mask::supersecretvalue`, which hides what Actions was told to mask) |
| 2026-10-09 | LLM-Redactor wl2_secrets | 91.9 · 95.5 · 95.5 (0.0 lost); of the 23 balanced misses, 21 are the `-----BEGIN RSA PRIVATE KEY-----` line of a key cut short with `...` in a comment (a placeholder here), 2 are AWS secret keys with `=` inside, a shape real ones never have |
| 2026-10-09 | final6 | 16.2 per M chars (from 17.0 blind). 1,871 of the 3,073 are in ory/hydra's OpenID conformance-test logs (1.65 M chars of recorded runs with their access tokens, ID tokens and client secrets); the other 188 M chars: 6.4 per M. Fixed from it: RFC example tokens (6749, 6750, 7636, 5849) and the TOTP docs secret, OAuth endpoints under `authorization:`, code after a closed string literal, chained assignments, identifiers ending a struct literal, Python regexes, AWX's `$encrypted$` |
| 2026-10-09 | data agent sets, after fixes | Nemotron-PII 67.7/0.3; Titus 63.7/10.6. Real text, per M chars: Toucan 79.3 → 4.0, SWE-rebench PRs 35.9 → 4.95, Stack Exchange 28.6 → 13.6, OpenHands 10.15 → 6.5, Claude Code sessions 1.77 → 1.24, Loghub 0.56 → 0.26; RFCs unchanged at 303 (line-wrapped JOSE examples, not fixed) |
| 2026-10-09 | CredData test split | 82.8% of secrets, 3.2% of non-secret lines (dev split 90.1%, 2.9%); on 2026-10-10, 83.2% and 3.9% (dev split 91.5%, 2.8%) |
| 2026-10-09 | issue-report sets (Zenodo), test / wild | 76.6% caught, 2.7% lost / 24 of 29 caught (82.8%), 2.0% lost |
| 2026-10-11 | rescored after the ablation and understanding reviews | held-out 1 (aggregates): 93.0/3.2, off 90.7/1.2, eager 93.2/3.4; real text 4.45 per M chars (off 3.64); CredData test 83.2/3.9 (dev split 91.1/2.9); GitLab examples 88.0/15.5; ICSME 2.0% of snippets hit; levainbot 81 of 85, 4 of 116 clean sections hit; issue reports 76.6/3.1 |
| 2026-10-11 | rescored after the non-guessing misfire fixes | held-out 1 (aggregates) unchanged: 93.0/3.2, off 90.7/1.2; real text 4.31 per M chars (off 3.57); dev 95.4/1.4 |
| 2026-10-11 | rescored after the guessing-off precision fixes (code read as values, found in 577 M characters of public text) | held-out 1 (aggregates) unchanged: 93.0/3.2, off 90.7/1.2; real text 4.14 per M chars (off 3.41); dev unchanged |
| 2026-10-11 | rescored after fixes for the false hits on CredData's dev split that Claude Haiku and jev agreed were mistakes | held-out 1 (aggregates) unchanged: 93.0/3.2, off 90.7/1.2; real text 4.11 per M chars (off 3.37); CredData dev 91.1/2.6 (off 53.1/1.8), test 83.2/3.7 (off 74.5/3.4): the test split, not looked at, lost 32 false lines in each mode and no true one |
| 2026-10-11 | rescored after fixes for code read as CredData dev passwords (`typeof`, function heads, references in prose, `$RANDOM***$RANDOM`, an empty `NAME=`) | held-out 1 (aggregates) and real text unchanged; CredData dev 91.1/2.5 (off 53.1/1.8, 561 false lines to 546), test 83.2/3.6 (off 74.5/3.4), one false line fewer in each mode |
| 2026-10-11 | rescored after fixes for CredData dev's remaining false hits: a PEM block's label on the line above it (OpenSSL's test files), a placeholder naming its own variable, a password hashing scheme's name | held-out 1 (aggregates) unchanged: 93.0/3.2, off 90.7/1.2; real text 4.07 per M chars (off 3.34); CredData dev 91.1/1.9 (off 53.1/1.7; 768 false lines to 579, 546 to 504 off; no true line lost), test 83.2/3.6 (off 74.5/3.4): the test split, not looked at, lost 4 false lines in each mode and no true one |
| 2026-10-11 | rescored after fixes for CredData dev's false hits in each kind of value (curve labels above PEM blocks; references, code and translated labels; checksum manifests, XRP addresses, hex fillers) | held-out 1 (aggregates) unchanged: 93.0/3.2, off 90.7/1.2; real text 4.04 per M chars (off 3.31); CredData dev 91.1/1.7 (off 53.1/1.5; false lines 579 to 511, 504 to 471 off), test 83.2/3.5 (off 74.5/3.3): the test split, not looked at, lost 12 false lines in each mode and no true one |
| 2026-10-11 | rescored after fixes for leaks the CredData review turned up (a conditional's or a fallback's literal branch, a password given to a hasher, a Kubernetes Secret's file-named keys, INSERT rows in a program's string) | held-out 1 (aggregates) and real text unchanged; CredData dev 91.1/1.7 (one more true line caught in each mode; 14 more false lines, 13 of them test passwords given to hashers or fallbacks, which the policy hides), test unchanged |
| 2026-10-12 | rescored after fixing what a block-by-block review of src/ confirmed (74 findings: leaks in CLI options, printed JSON strings, accented password names, Secret files, SQL, shell heredocs, transcripts' attached files; false hits on SQL binds, rotated key IDs, Maps keys; comments made true) | held-out 1 (aggregates) unchanged: 93.0/3.2, off 90.7/1.2; real text 4.07 per M chars (off 3.34); CredData dev 91.1/1.8 (off 53.1/1.7), test 83.2/3.6 (off 74.5/3.3); 253 regression cases newly caught, none newly lost |
| 2026-10-12 | rescored after a second look driven by a mutation sweep: every executed `if` body, `\|\|` alternative and `&&` guard mutated one at a time, and the 1,500 sites that neither the dev data nor a test told apart reviewed in 18 groups, then 95 follow-ups they turned up (fixed: types read as values, grep's options read as files, Markdown and SQL columns, box-drawn tables, percent-encoded and `_`-scheme URL passwords, keys cut short or written as arrays, shell quoting and continued pipes, lists of secrets, length rules read as passwords; most of the sites now pinned by tests, about a hundred checks dropped as dead) | held-out 1 (aggregates): 93.0/3.0, off 90.9/1.1; real text 4.02 per M chars (off 3.29); CredData dev 91.1/1.8 (off 53.2/1.7; false lines 552 to 546), test 83.5/3.5 (off 74.9/3.3; false lines 488 to 483, true lines 1,702 to 1,709); 1,508 regression cases newly caught, 1 newly lost (a stand-in, `hunter2`, hidden before only by a cut call) |
| 2026-10-12 | rescored after fixes for what pi-safety's secret files leaked (Symfony's vault key, Redis ACL passwords, Bundler's host credentials, a session's ID under a service's name, a login's password learned alone, cypher-shell's `-p` and a tool's path after `ps` columns) | held-out 1 (aggregates) unchanged: 93.0/3.0, off 90.9/1.1; real text unchanged: 4.02 per M chars (off 3.29); CredData dev and test unchanged; no regression case newly caught or lost. A first run hid 19 more values in one real-text file (a signature's `abc:<id>` split as a login); the split now needs a name that says login |

## Notes


Labelling disagreements found in holdout2 afterwards (left as written, so they count against us):
the infrastructure writer labelled password hashes as secrets and the application writer labelled them
as values to keep; Firebase `AIza` browser keys and Supabase anon keys under credential names were
labelled keep, where redac---n hides them by policy; AWS access key IDs were labelled keep in some cases.
CredData also labels hashes as non-secrets, so hashes stay by default; `hashes: "hide"` hides them.

A template writer for a set on enterprise, Windows, legacy, scientific, game and firmware tooling (would-be
holdout8) was stopped by a safety classifier before writing anything, and wasn't retried; holdout8 was then
written on data and analytics tooling instead.

From cycle 7 on, a data agent finds, converts and scores new sets in parallel; its blind scores are copied above
unchanged. (Its notes, which quote the sets' text, stay out of the repository with the sets.) Converted sets live under ~/Downloads/redact-corpora/built/, never in the repository.
