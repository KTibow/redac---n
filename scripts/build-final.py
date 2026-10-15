"""
Builds a fresh real-text set, ~/Downloads/redact-corpora/<set>/<set>.jsonl (default set: final): public
text that no part of development touched, scored before any of it is looked at. Sources, fetched
beforehand into <set>/:

- hf/: unused shards of the trajectory datasets the dev and test sets sample (Kwai-Klear SWE-smith
  train-00010, nebius SWE-agent train-00009, SWE-Gym OpenHands raw-00001); the first 3,000 rows each.
- repos/: shallow clones of airflow, gh cli, consul, fastapi, gitea, laravel/framework, minio, pip,
  rustup, svelte, astro and traefik; up to 6 MB of text files each, in a fixed shuffled order.

final2 (built 2026-10-09): Kwai-Klear train-00020, nebius train-00010, SWE-Gym raw-00002; nest,
pydantic, caddy, httpx, fastify, axum, sqlalchemy, hono, celery, nomad, strapi and temporal.

final3: Kwai-Klear train-00030/00040, nebius train-00011; vite, loki, kind, black, fiber, channels,
sqlmodel, remix, chi, cobra, kratos and packer.

final4: Kwai-Klear train-00045, nebius train-00003; k6, prisma, redis-py, sinatra, symfony/console,
viper, nats-server, ktor, phoenix, vitest, httpie and eShop; and tracecommons/: the Trace Commons
dataset (trace-commons/agent-traces, CC-BY-4.0, real donated sessions from several agent harnesses),
each message serialized as JSON, the way a request body carries it.

final5: Kwai-Klear train-00035, nebius train-00007; mattermost, discourse_docker, zulip, outline,
appwrite, pocketbase, directus, keycloak-quickstarts, harbor, woodpecker, coder and supabase/auth; and
aidev/: AIDev (hao-li/AIDev, CC-BY-4.0), pull requests written by coding agents: titles and bodies, and
review comments with their diff hunks (the first 40,000 rows of each).

final7 (built 2026-10-15): Kwai-Klear train-00017, nebius train-00006; litellm, dify, n8n, rails, django,
spring-boot, jellyfin, prometheus, vault, sentry-javascript, nextcloud and esphome.

Records are {src, text} chunks of at most 8,000 characters, deduplicated by their first 300.

    python3 -I scripts/build-final.py [set]
"""
import pyarrow.parquet as pq, glob, json, os, sys

# Corpora outside the repository: $REDACT_CORPORA, or ~/Downloads/redact-corpora (eval/data-root.ts).
CORPORA_ROOT = os.environ.get("REDACT_CORPORA", os.path.expanduser("~/Downloads/redact-corpora"))
NAME = sys.argv[1] if len(sys.argv) > 1 else 'final'
F = os.path.join(CORPORA_ROOT, NAME)
out = open(os.path.join(F, NAME + '.jsonl'), 'w')
seen = set(); n = 0; size = 0
def emit(src, text):
    global n, size
    if not isinstance(text, str) or len(text) < 20: return
    key = text[:300]
    if key in seen: return
    seen.add(key)
    for i in range(0, len(text), 8000):
        out.write(json.dumps({'src': src, 'text': text[i:i+8000]}, ensure_ascii=True) + '\n'); n += 1
    size += len(text)
def content_text(c):
    if isinstance(c, str): return c
    if isinstance(c, list): return '\n'.join(x.get('text', '') for x in c if isinstance(x, dict))
    return ''
for f in sorted(glob.glob(os.path.join(F, 'hf/*.parquet'))):
    src = 'traj:' + f.split('/')[-1].split('_resolve')[0]
    for row in pq.read_table(f).slice(0, 3000).to_pylist():
        if 'trajectory' in row:
            tr = row['trajectory']
            if isinstance(tr, str): tr = json.loads(tr)
            for step in tr:
                if isinstance(step, dict): emit(src, step.get('text') or step.get('content'))
        else:
            msgs = row['messages']
            if isinstance(msgs, str): msgs = json.loads(msgs)
            for m in msgs: emit(src, content_text(m.get('content')))
for f in sorted(glob.glob(os.path.join(F, 'tracecommons/*.parquet'))):
    for row in pq.read_table(f).to_pylist():
        for m in row['messages'] or []:
            emit('trace:tracecommons:' + (row.get('harness') or ''), m if isinstance(m, str) else json.dumps(m))
for f in sorted(glob.glob(os.path.join(F, 'aidev/*.parquet'))):
    for row in pq.read_table(f).slice(0, 40000).to_pylist():
        if 'diff_hunk' in row:
            emit('aidev:review', (row.get('diff_hunk') or '') + '\n\n' + (row.get('body') or ''))
        else:
            emit('aidev:pr:' + (row.get('agent') or ''), (row.get('title') or '') + '\n\n' + (row.get('body') or ''))
exts = {'.go','.py','.ts','.tsx','.js','.jsx','.mjs','.rb','.java','.rs','.c','.h','.php','.sh','.md','.rst','.txt','.yaml','.yml','.json','.toml','.ini','.cfg','.conf','.env','.properties','.xml','.html','.css','.sql','.lock','.sum','.mod','.tf','.hcl','.log','.csv','.svelte','.astro','.vue','.blade.php',''}
names = {'Dockerfile','Makefile','go.sum','Cargo.lock','package-lock.json','yarn.lock','pnpm-lock.yaml','composer.lock','poetry.lock'}
import random
for repo in sorted(os.listdir(os.path.join(F, 'repos'))):
    root = os.path.join(F, 'repos', repo)
    files = []
    for d, dirs, fs in os.walk(root):
        dirs[:] = [x for x in dirs if x not in ('.git', 'node_modules')]
        for x in fs:
            p = os.path.join(d, x)
            if x in names or os.path.splitext(x)[1].lower() in exts: files.append(p)
    random.Random(repo).shuffle(files)
    used = 0
    for p in files:
        if used > 6_000_000: break
        try:
            if os.path.getsize(p) > 2_000_000: continue
            b = open(p, 'rb').read()
        except OSError: continue
        if b'\0' in b[:8000]: continue
        t = b.decode('utf8', 'replace')
        emit('repo:' + os.path.relpath(p, os.path.join(F, 'repos')), t)
        used += len(t)
print(n, size)
