#!/usr/bin/env python3
"""
Baselines: how well existing open-source secret scanners would do as a secret *redactor*, alone and
pipelined, scored the same way as eval/score.ts.

Each case is written to its own file, every scanner runs over the directory (no network verification),
findings are mapped back to case files, and every reported secret string is replaced with [REDACTED]
everywhere it occurs in that case (detect-secrets only reports hashes and line numbers, so its whole
reported line is redacted). When a reported string is not present verbatim (decoded base64 etc.), the
reported line(s) are redacted instead.

Scoring (as score.ts): a secret is caught if neither the full value nor any contiguous run of length
>= max(8, ceil(len/2)) survives (runs only count for secrets >= 12 chars); keep values must survive
verbatim. Two file-naming variants: every case as .txt, and an extension chosen from the case context
(.env for dotenv/env-dump, .py for python-code, ...).

Real text: the first N MB (default 30) of `traj:` records from ~/Downloads/redact-corpora/built/dev.jsonl,
one file per record, reporting findings per MB.

  python3 -I eval/baselines.py --bin DIR --venv DIR [--scratch DIR] [--corpora dev,dev_c] [--real FILE] [--real-src traj:]
                               [--real-mb 30] [--tools a,b] [--variants txt,ctx] [--out FILE] [--json FILE]

--corpora names files in eval/corpora/ (or gives paths to .jsonl files); --real-src "" takes every record of --real. --json writes the numbers for
eval/report.ts.

Stdlib only.
"""
import argparse
import base64
import gzip
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import defaultdict

# Corpora outside the repository: $REDACT_CORPORA, or ~/Downloads/redact-corpora (eval/data-root.ts).
CORPORA_ROOT = os.environ.get("REDACT_CORPORA", os.path.expanduser("~/Downloads/redact-corpora"))

HERE = os.path.dirname(os.path.abspath(__file__))
REAL = os.path.join(CORPORA_ROOT, "built/dev.jsonl")
ALL_TOOLS = ["gitleaks", "betterleaks", "kingfisher", "trufflehog", "noseyparker", "detect-secrets", "credsweeper"]
PIPELINES = {
    "union(all 7)": ALL_TOOLS,
    "union(all but detect-secrets)": [t for t in ALL_TOOLS if t != "detect-secrets"],
    "gitleaks+betterleaks+kingfisher": ["gitleaks", "betterleaks", "kingfisher"],
}
CTX_EXT = {
    "dotenv": ".env", "env-dump": ".env", "python-code": ".py", "js-code": ".js", "go-code": ".go",
    "shell-script": ".sh", "rust-code": ".rs", "java-code": ".java", "powershell": ".ps1", "php-code": ".php",
    "json-config": ".json", "java-properties": ".properties", "csharp-code": ".cs", "ruby-code": ".rb",
    "chat": ".txt", "stack-trace": ".log", "jupyter": ".py", "token-output": ".txt", "agent-transcript": ".txt",
    "url": ".txt", "app-log": ".log", "markdown": ".md", "pem-key": ".pem", "api-response": ".json",
}


# ---------------------------------------------------------------- scoring (mirrors eval/score.ts)

def longest_surviving_run(secret, out):
    if secret in out:
        return len(secret)
    lo, hi = 0, len(secret) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if any(secret[i:i + mid] in out for i in range(len(secret) - mid + 1)):
            lo = mid
        else:
            hi = mid - 1
    return lo


def leaked(secret, out):
    if secret in out:
        return True
    if len(secret) < 12:
        return False
    return longest_surviving_run(secret, out) >= max(8, math.ceil(len(secret) / 2))


# ---------------------------------------------------------------- spans

class Spans:
    """Character spans to redact in one file's text, from one tool."""

    def __init__(self, text):
        self.text = text
        self.spans = []
        self.findings = 0
        self.fallbacks = 0
        self.values = []  # reported strings, for shape stats
        self._line_starts = None

    def string(self, s):
        """Redact every occurrence of s. Returns False if s does not occur."""
        if not s:
            return False
        i = self.text.find(s)
        if i < 0:
            return False
        while i >= 0:
            self.spans.append((i, i + len(s)))
            i = self.text.find(s, i + len(s))
        self.values.append(s)
        return True

    def lines(self, first, last=None):
        """Redact lines first..last (1-based, inclusive), without the trailing newline."""
        if self._line_starts is None:
            self._line_starts = [0] + [m.end() for m in re.finditer("\n", self.text)]
        ls = self._line_starts
        last = last or first
        if first < 1 or first > len(ls):
            return
        a = ls[first - 1]
        b = ls[last] - 1 if last < len(ls) else len(self.text)
        if b > a:
            self.spans.append((a, b))
            self.values.append(self.text[a:b])

    def finding(self, strings, line=None, last_line=None):
        self.findings += 1
        hit = False
        for s in strings:
            if s and self.string(s):
                hit = True
                break
        if not hit and line:
            self.fallbacks += 1
            self.lines(line, last_line)


def merge(spans):
    out = []
    for a, b in sorted(spans):
        if out and a <= out[-1][1]:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return out


def apply(text, spans):
    parts, pos = [], 0
    for a, b in merge(spans):
        parts.append(text[pos:a])
        parts.append("[REDACTED]")
        pos = b
    parts.append(text[pos:])
    return "".join(parts)


# ---------------------------------------------------------------- tools

def fid_of(path):
    base = os.path.basename(path)
    return base.split(".", 1)[0]


def run(cmd, cwd, stdout=None):
    return subprocess.run(cmd, cwd=cwd, stdout=stdout or subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def tool_gitleaks(binary, cwd, out):
    def go(texts):
        rep = os.path.join(out, os.path.basename(binary) + ".json")
        run([binary, "dir", "files", "-f", "json", "-r", rep, "--no-banner", "--exit-code", "0", "-l", "error"], cwd)
        for f in json.load(open(rep)) or []:
            yield fid_of(f["File"]), [f.get("Secret"), f.get("Match")], f.get("StartLine"), f.get("EndLine")
    return go


def tool_kingfisher(binary, cwd, out):
    def go(texts):
        rep = os.path.join(out, "kingfisher.json")
        run([binary, "scan", "files", "--no-validate", "--no-update-check", "--no-dedup", "--git-history", "none",
             "-f", "json", "-o", rep, "-q"], cwd)
        for f in json.load(open(rep)).get("findings", []):
            x = f["finding"]
            yield fid_of(x["path"]), [x.get("snippet")], x.get("line"), None
    return go


TH_NON_SECRET_PARTS = {"host", "hostname", "database", "db", "user", "username", "account_name", "account", "port",
                       "url", "endpoint", "region", "email", "id", "client_id", "org", "domain"}


def tool_trufflehog(binary, cwd, out):
    def go(texts):
        rep = os.path.join(out, "trufflehog.jsonl")
        with open(rep, "w") as fh:
            run([binary, "filesystem", "files", "--no-verification", "--no-update", "-j", "--no-color",
                 "--deduplication-cache-size=0"], cwd, stdout=fh)
        for line in open(rep):
            line = line.strip()
            if not line.startswith("{"):
                continue
            f = json.loads(line)
            fs = (f.get("SourceMetadata") or {}).get("Data", {}).get("Filesystem")
            if not fs:
                continue
            cands = [f.get("Raw"), f.get("RawV2")]
            parts = f.get("SecretParts") or {}
            fid = fid_of(fs["file"])
            # A multi-part secret: also redact its secret-bearing parts (not host/user/database names).
            yield fid, cands, fs.get("line"), None
            for k, v in parts.items():
                if k not in TH_NON_SECRET_PARTS and isinstance(v, str) and v not in cands:
                    yield fid, [v], None, None, "extra"
    return go


def tool_noseyparker(binary, cwd, out):
    def go(texts):
        db = os.path.join(out, "np.db")
        shutil.rmtree(db, ignore_errors=True)
        run([binary, "scan", "-d", db, "files", "-q", "--progress", "never"], cwd)
        rep = os.path.join(out, "noseyparker.json")
        run([binary, "report", "-d", db, "-f", "json", "-o", rep, "--max-matches", "0", "--max-provenance", "0",
             "--suppress-redundant", "false", "--progress", "never"], cwd)
        for f in json.load(open(rep)):
            for m in f.get("matches", []):
                groups = []
                for g in m.get("groups") or []:
                    try:
                        groups.append(base64.b64decode(g).decode("utf-8"))
                    except Exception:
                        pass
                matching = (m.get("snippet") or {}).get("matching")
                ss = ((m.get("location") or {}).get("source_span") or {})
                l1 = (ss.get("start") or {}).get("line")
                l2 = (ss.get("end") or {}).get("line")
                for p in m.get("provenance", []):
                    if p.get("kind") == "file":
                        # Redact the capture group(s); fall back to the whole match, then the lines.
                        g = [x for x in groups if x]
                        if g:
                            yield fid_of(p["path"]), [g[0], matching], l1, l2
                            for x in g[1:]:
                                yield fid_of(p["path"]), [x], None, None, "extra"
                        else:
                            yield fid_of(p["path"]), [matching], l1, l2
    return go


def tool_detect_secrets(binary, cwd, out):
    def go(texts):
        rep = os.path.join(out, "detect-secrets.json")
        with open(rep, "w") as fh:
            run([binary, "scan", "--all-files", "-n", "files"], cwd, stdout=fh)
        for path, items in json.load(open(rep)).get("results", {}).items():
            for it in items:
                yield fid_of(path), [], it["line_number"], None
    return go


def tool_credsweeper(binary, cwd, out):
    def go(texts):
        rep = os.path.join(out, "credsweeper.json")
        run([binary, "--path", "files", "--save-json", rep, "--no-stdout", "--no-color", "-j", str(os.cpu_count() or 4),
             "--log", "error"], cwd)
        for f in json.load(open(rep)) if os.path.exists(rep) else []:
            for ld in f.get("line_data_list", []):
                yield fid_of(ld["path"]), [ld.get("value")], ld.get("line_num"), None
    return go


def make_tools(bindir, venv):
    b = lambda n: os.path.join(bindir, n)
    v = lambda n: os.path.join(venv, "bin", n)
    return {
        "gitleaks": lambda cwd, out: tool_gitleaks(b("gitleaks"), cwd, out),
        "betterleaks": lambda cwd, out: tool_gitleaks(b("betterleaks"), cwd, out),
        "kingfisher": lambda cwd, out: tool_kingfisher(b("kingfisher"), cwd, out),
        "trufflehog": lambda cwd, out: tool_trufflehog(b("trufflehog"), cwd, out),
        "noseyparker": lambda cwd, out: tool_noseyparker(b("noseyparker"), cwd, out),
        "detect-secrets": lambda cwd, out: tool_detect_secrets(v("detect-secrets"), cwd, out),
        "credsweeper": lambda cwd, out: tool_credsweeper(v("credsweeper"), cwd, out),
    }


def scan_dataset(name, files, tools, tool_names, scratch, log):
    """files: {fid: (filename, text)}. Returns {tool: {fid: Spans}}, {tool: seconds}."""
    d = os.path.join(scratch, name)
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(os.path.join(d, "files"))
    os.makedirs(os.path.join(d, "out"))
    for fid, (fn, text) in files.items():
        with open(os.path.join(d, "files", fn), "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
    texts = {fid: t for fid, (_, t) in files.items()}
    res, secs = {}, {}
    for t in tool_names:
        t0 = time.time()
        per = {}
        unknown = 0
        for item in tools[t](d, os.path.join(d, "out"))(texts):
            fid, strings, l1, l2 = item[:4]
            if fid not in texts:
                unknown += 1
                continue
            sp = per.setdefault(fid, Spans(texts[fid]))
            if len(item) > 4:  # extra part of a multi-part finding, not counted separately
                for s in strings:
                    sp.string(s)
                continue
            sp.finding(strings, l1, l2)
        secs[t] = time.time() - t0
        res[t] = per
        nf = sum(s.findings for s in per.values())
        fb = sum(s.fallbacks for s in per.values())
        log(f"  [{name}] {t:15s} {secs[t]:7.1f}s  findings={nf} line-fallbacks={fb} unmapped={unknown}")
    return res, secs


# ---------------------------------------------------------------- reports

def score(cases, spans_by_fid):
    caught = total = lost = keeps = 0
    per_ctx = defaultdict(lambda: [0, 0, 0, 0])
    for c in cases:
        sp = []
        for s in spans_by_fid:
            if c["fid"] in s:
                sp += s[c["fid"]].spans
        out = apply(c["text"], sp) if sp else c["text"]
        pc = per_ctx[c.get("context") or "?"]
        for s in c.get("secrets") or []:
            ok = not leaked(s, out)
            caught += ok
            total += 1
            pc[0] += ok
            pc[1] += 1
        for k in c.get("keep") or []:
            bad = k not in out
            lost += bad
            keeps += 1
            pc[2] += bad
            pc[3] += 1
    return (caught, total, lost, keeps), per_ctx


def pct(a, b):
    return f"{100 * a / b:5.1f}%" if b else "   n/a"


def shape_of(v):
    if re.fullmatch(r"[0-9a-f]{40}", v, re.I): return "hex40-sha1"
    if re.fullmatch(r"[0-9a-f]{64}", v, re.I): return "hex64-sha256"
    if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", v, re.I): return "uuid"
    return "other"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True, help="dir with gitleaks, betterleaks, kingfisher, trufflehog, noseyparker")
    ap.add_argument("--venv", required=True, help="venv with detect-secrets and credsweeper")
    ap.add_argument("--scratch", default=None)
    ap.add_argument("--corpora", default="dev,dev_c")
    ap.add_argument("--real", default=REAL)
    ap.add_argument("--real-src", default="traj:")
    ap.add_argument("--real-mb", type=float, default=30)
    ap.add_argument("--json", default=None)
    ap.add_argument("--tools", default=",".join(ALL_TOOLS))
    ap.add_argument("--variants", default="txt,ctx")
    ap.add_argument("--out", default=os.path.join(HERE, "out", "baselines.txt"))
    a = ap.parse_args()
    tool_names = a.tools.split(",")
    tools = make_tools(a.bin, a.venv)
    scratch = tempfile.mkdtemp(prefix="baselines-", dir=a.scratch)
    lines = []

    def log(s=""):
        print(s, flush=True)
        lines.append(s)

    log(f"# Secret scanners as redactors (scratch: {scratch})")
    log("# no network verification: trufflehog --no-verification --no-update, kingfisher --no-validate --no-update-check,")
    log("# betterleaks without --validation, detect-secrets -n; scanner defaults otherwise (no custom rules)")
    summary = {"corpora": {}, "real": {}}
    versions = {}
    for t in tool_names:
        exe = os.path.join(a.venv, "bin", t) if t in ("detect-secrets", "credsweeper") else os.path.join(a.bin, t)
        try:
            v = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=60)
            versions[t] = ((v.stdout or v.stderr).strip().splitlines() or ["?"])[-1]
        except Exception as e:
            versions[t] = f"? ({e.__class__.__name__})"
    log("# versions: " + "; ".join(f"{t} {v}" for t, v in versions.items()))
    summary["versions"] = versions

    # (A corpus by its name, `holdout`, is eval/corpora's gzipped file; a path is read gzipped or not.)
    CORPORA = [(os.path.basename(n).removesuffix(".gz").removesuffix(".jsonl"), n) if n.endswith((".jsonl", ".jsonl.gz")) else (n, os.path.join(HERE, "corpora", n + ".jsonl.gz")) for n in a.corpora.split(",") if n]
    cases = []
    for cname, path in CORPORA:
        for line in (gzip.open(path, "rt", encoding="utf-8") if path.endswith(".gz") else open(path, encoding="utf-8")):
            c = json.loads(line)
            c["corpus"] = cname
            c["fid"] = f"{cname}__{c['id']}".replace(".", "_")
            cases.append(c)

    runtimes = defaultdict(dict)
    for variant in a.variants.split(","):
        files = {}
        for c in cases:
            ext = ".txt" if variant == "txt" else CTX_EXT.get(c.get("context"), ".txt")
            files[c["fid"]] = (c["fid"] + ext, c["text"])
        log(f"\n## variant {variant}: {len(files)} case files ({'all .txt' if variant == 'txt' else 'extension from context, .env for dotenv/env-dump'})")
        res, secs = scan_dataset(f"cases-{variant}", files, tools, tool_names, scratch, log)
        for t, s in secs.items():
            runtimes[t][f"cases-{variant}"] = s
        rows = [(t, [res[t]]) for t in tool_names]
        rows += [(p, [res[t] for t in ts if t in res]) for p, ts in PIPELINES.items() if all(t in res for t in ts)]
        corp = [("both", cases)] + [(cn, [c for c in cases if c["corpus"] == cn]) for cn, _ in CORPORA]
        hdr = f"{'tool':34s}" + "".join(f" | {cn:>6s} recall  loss" for cn, _ in corp)
        log(hdr)
        log("-" * len(hdr))
        ctx_tables = {}
        for name, sp in rows:
            cells = []
            for cn, cs in corp:
                (caught, total, lost, keeps), per_ctx = score(cs, sp)
                cells.append(f" | {pct(caught, total):>13s} {pct(lost, keeps)}")
                summary["corpora"].setdefault(variant, {}).setdefault(name, {})[cn] = {"caught": caught, "secrets": total, "lost": lost, "keeps": keeps}
                if cn == "both":
                    ctx_tables[name] = per_ctx
            log(f"{name:34s}" + "".join(cells))
        log(f"\n### variant {variant}: recall by context (loss in parentheses)")
        ctxs = sorted({k for v in ctx_tables.values() for k in v})
        short = {"union(all 7)": "U7", "union(all but detect-secrets)": "U6", "gitleaks+betterleaks+kingfisher": "GBK"}
        names = list(ctx_tables)
        log(f"{'context':17s}" + "".join(f"{short.get(n, n[:11]):>15s}" for n in names))
        for k in ctxs:
            log(f"{k:17s}" + "".join(
                f"{(pct(ctx_tables[n][k][0], ctx_tables[n][k][1]).strip() + '(' + pct(ctx_tables[n][k][2], ctx_tables[n][k][3]).strip().rstrip('%') + ')'):>15s}"
                for n in names))

    # real text
    if a.real_mb > 0:
        files, nchars, limit = {}, 0, a.real_mb * 1e6
        with open(a.real, encoding="utf-8") as fh:
            for line in fh:
                r = json.loads(line)
                if not r.get("src", "").startswith(a.real_src):
                    continue
                text = r["text"].encode("utf-8", "replace").decode("utf-8")
                fid = f"r{len(files):06d}"
                files[fid] = (fid + ".txt", text)
                nchars += len(text)
                if nchars >= limit:
                    break
        mb = nchars / 1e6
        log(f"\n## real text: first {mb:.1f} MB of {a.real_src or 'all'} records in {a.real} ({len(files)} files, .txt) — false redactions")
        res, secs = scan_dataset("real-traj", files, tools, tool_names, scratch, log)
        for t, s in secs.items():
            runtimes[t]["real-traj"] = s
        log(f"{'tool':34s} {'findings/MB':>12s} {'spans/MB':>10s} {'%chars':>8s} {'sha/digest/uuid/MB':>19s}")
        rows = [(t, [res[t]]) for t in tool_names]
        rows += [(p, [res[t] for t in ts if t in res]) for p, ts in PIPELINES.items() if all(t in res for t in ts)]
        for name, sp in rows:
            nf = sum(s.findings for r in sp for s in r.values())
            spans = 0
            chars = 0
            damage = 0
            # Each redaction's value and the text before it on its line, for report.ts to sort by what was redacted.
            redactions = []
            for fid in files:
                ss = [x for r in sp if fid in r for x in r[fid].spans]
                m = merge(ss)
                spans += len(m)
                chars += sum(b - a for a, b in m)
                text = files[fid][1]
                for x, y in m:
                    line_start = text.rfind("\n", 0, x) + 1
                    redactions.append([text[x:y][:500], text[max(line_start, x - 200):x]])
            for r in sp:
                for s in r.values():
                    damage += sum(shape_of(v) != "other" for v in s.values)
            log(f"{name:34s} {nf / mb:12.2f} {spans / mb:10.2f} {100 * chars / nchars:7.3f}% {damage / mb:19.3f}")
            summary["real"][name] = {"mb": mb, "findings": nf, "spans": spans, "chars": chars, "damage": damage, "redactions": redactions}

    log("\n## runtime (wall seconds, includes process start and result parsing)")
    cols = sorted({k for v in runtimes.values() for k in v})
    log(f"{'tool':16s}" + "".join(f"{c:>14s}" for c in cols))
    for t in tool_names:
        log(f"{t:16s}" + "".join(f"{runtimes[t].get(c, float('nan')):14.1f}" for c in cols))

    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"\nwrote {a.out}")
    if a.json:
        summary["runtimes"] = runtimes
        with open(a.json, "w") as fh:
            json.dump(summary, fh, indent=1)
        print(f"wrote {a.json}")


if __name__ == "__main__":
    main()
