"""
Converts fresh public downloads into eval cases for one blind run each (the sets eval/HELDOUT.md lists).
Inputs live in ~/Downloads/redact-corpora/<name>/, outputs in ~/Downloads/redact-corpora/built/<name>/
(outside the repository: their licences differ from ours, and some allow evaluation only).

Labelled sets become {id, kind, context, text, secrets, keep} for eval/run.ts; unlabelled text becomes
{src, text} records for eval/realtext.ts --file.

    python3 -I scripts/build-datasets.py <set> <input dir> <output dir>

Stdlib only, except pyarrow for parquet inputs (run with the tools venv).
"""
import ast
import json
import os
import random
import re
import sys

SET, SRC, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
os.makedirs(OUT, exist_ok=True)


def write(name, rows):
    with open(os.path.join(OUT, name), "w") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=True) + "\n")  # ASCII: Node's readline also splits on U+2028/2029
    print(name, len(rows), file=sys.stderr)


PLACEHOLDER = re.compile(r"example|xxxx|\*\*\*|redacted|your[_-]|<[^>]*>|\.\.\.|changeme|placeholder|dummy", re.I)
# jwt.io's demo token ("John Doe", signed with "your-256-bit-secret"): a published example, kept here.
JWT_IO_SIG = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"


def nemotron_pii():
    """nvidia/Nemotron-PII test split (CC-BY-4.0): synthetic documents with PII span labels.

    secrets: `password` and `api_key` spans, and the value of an `http_cookie` span whose cookie name
    says session/auth/token (tracking and preference cookies are left out). Dropped: placeholder-looking
    values, values under 6 characters, all-digit passwords (mostly mislabelled IDs), jwt.io's demo token.
    PIN and CVV spans are left out entirely (neither secret nor keep).
    keep: ID-like spans (IDs, account and card numbers, SSNs, usernames, emails, URLs, IPs, MACs) of 6+
    characters that don't overlap a secret. This library leaves personal data alone by design.
    """
    import pyarrow.parquet as pq
    KEEP = {"customer_id", "account_number", "employee_id", "medical_record_number", "health_plan_beneficiary_number",
            "unique_id", "device_identifier", "certificate_license_number", "vehicle_identifier", "license_plate",
            "user_name", "url", "email", "mac_address", "ipv4", "ipv6", "swift_bic", "bank_routing_number",
            "national_id", "tax_id", "ssn", "credit_debit_card", "biometric_identifier"}
    AUTH_COOKIE = re.compile(r"sess|auth|token|jwt|sid|login|remember|csrf|xsrf|access|refresh|id_token|connect\.sid", re.I)
    rows = pq.read_table(os.path.join(SRC, "test.parquet")).to_pylist()
    pos, neg = [], []
    for r in rows:
        spans = r["spans"]
        if isinstance(spans, str):
            spans = ast.literal_eval(spans)
        secrets, keep, kinds, dropped = [], [], [], False
        for s in spans:
            v, lab = s["text"], s["label"]
            if lab in ("password", "api_key", "http_cookie"):
                if lab == "http_cookie":
                    m = re.match(r"\s*([A-Za-z0-9_.\-]+)=([^;\s]+)", v)
                    if not m or not AUTH_COOKIE.search(m.group(1)):
                        dropped = True
                        continue
                    v = m.group(2)
                if len(v) < 6 or PLACEHOLDER.search(v) or JWT_IO_SIG in v or (lab == "password" and v.isdigit()):
                    dropped = True
                    continue
                secrets.append(v)
                kinds.append(lab)
            elif lab in KEEP and len(v) >= 6:
                keep.append(v)
        secrets = sorted(set(secrets))
        keep = sorted({k for k in set(keep) if not any(k in s or s in k for s in secrets)})
        kind = next((k for k in ("api_key", "password", "http_cookie") if k in kinds), "none")
        case = {"id": f"nemotron-{r['uid']}", "kind": kind, "context": f"{r['document_format']}:{r['document_type']}",
                "text": r["text"], "secrets": secrets, "keep": keep}
        if secrets:
            pos.append(case)
        elif not dropped and keep and not any(s["label"] in ("password", "api_key", "http_cookie", "pin", "cvv") for s in spans):
            neg.append(case)
    rnd = random.Random(1)
    rnd.shuffle(pos)
    rnd.shuffle(neg)
    write("nemotron-pii.jsonl", pos[:4000] + neg[:1000])


def emit_chunks(rows, src, text, seen):
    """{src, text} records of at most 8,000 chars, deduplicated by their first 300 (as build-final.py)."""
    if not isinstance(text, str) or len(text) < 20 or text[:300] in seen:
        return
    seen.add(text[:300])
    for i in range(0, len(text), 8000):
        rows.append({"src": src, "text": text[i:i + 8000]})


def openhands_feedback():
    """OpenHands/openhands-feedback (MIT): 275 real user sessions with OpenHands, shared publicly by their users.

    Each event's message and content become records; its extras (the action's arguments: command, code, path,
    thought) become a JSON record with browser screenshots, accessibility trees and DOM dumps removed.
    """
    import pyarrow.parquet as pq
    DROP = {"screenshot", "axtree_object", "dom_object", "extra_element_properties", "set_of_marks", "focused_element_bid"}
    rows, seen = [], set()
    for n, r in enumerate(pq.read_table(os.path.join(SRC, "train.parquet")).to_pylist()):
        for s in r["trajectory"]:
            kind = f"oh:{n}:{s['source']}:{s['action'] or s['observation']}"
            for k in ("message", "content"):
                emit_chunks(rows, kind, s[k], seen)
            try:
                ex = json.loads(s["extras"] or "null")
            except ValueError:
                ex = None
            if isinstance(ex, dict):
                ex = {k: v for k, v in ex.items() if k not in DROP and not (isinstance(v, str) and v.startswith("data:image"))}
                if ex and set(ex) - {"agent_state", "reason"}:
                    emit_chunks(rows, kind + ":extras", json.dumps(ex, ensure_ascii=False), seen)
    write("openhands-feedback.jsonl", rows)


def titus_rules():
    """praetorian-inc/titus rule examples (Apache-2.0): 542 rules (Nosey Parker's and more), each with example
    snippets that its pattern must match and, for 169, negative examples it must not.

    secrets: in each example, every match of the rule's own pattern (compiled by Python `re`; Go/Rust-only syntax
    patched or the rule skipped), taking the capture groups that hold the credential (`token`, `key`, `secret`,
    `password`, ...; unnamed groups of 8+ chars; else the whole match). Host, domain and username groups are keeps.
    Client IDs, key IDs and card numbers are neither. Negative examples: the whole snippet is a keep (any
    redaction counts as a loss, so this is an upper bound: a negative for one rule can hold another's secret).
    """
    import glob
    import yaml
    SECRET = {"token", "key", "secret", "password", "client_secret", "secret_key", "api_key", "account_key",
              "access_token", "access_key", "webhook_token", "token_secret", "webhook", "body", "privkey", "private_key"}
    KEEPG = {"host", "domain", "site_domain", "username", "user", "account_name"}
    cases, bad, nomatch = [], 0, 0
    for path in sorted(glob.glob(os.path.join(SRC, "pkg/rule/rules/*.yml"))):
        fname = os.path.basename(path)[:-4]
        for rule in (yaml.safe_load(open(path)) or {}).get("rules") or []:
            pat = rule["pattern"].replace(r"\z", r"\Z").replace(r"\x{", r"\u{")
            try:
                rx = re.compile(pat)
            except re.error:
                bad += 1
                continue
            for i, ex in enumerate(rule.get("examples") or []):
                secrets, keep = [], []
                for m in rx.finditer(ex):
                    named = {k: v for k, v in m.groupdict().items() if v}
                    if named:
                        secrets += [v for k, v in named.items() if k in SECRET or k.endswith(("_secret", "_token", "_password", "_key")) and k not in ("key_id",)]
                        keep += [v for k, v in named.items() if k in KEEPG and len(v) >= 4]
                    elif m.groups():
                        secrets += [g for g in m.groups() if g and len(g) >= 8]
                    else:
                        secrets.append(m.group(0))
                secrets = sorted({s for s in secrets if len(s) >= 6})
                keep = sorted({k for k in keep if not any(k in s or s in k for s in secrets)})
                if not secrets:
                    nomatch += 1
                    continue
                cases.append({"id": f"titus-{rule['id']}-{i}", "kind": rule["id"], "context": fname, "text": ex,
                              "secrets": secrets, "keep": keep})
            for i, ex in enumerate(rule.get("negative_examples") or []):
                if ex.strip():
                    cases.append({"id": f"titus-{rule['id']}-neg{i}", "kind": rule["id"] + ":neg", "context": fname + ":neg",
                                  "text": ex, "secrets": [], "keep": [ex]})
    print("rules that don't compile in Python:", bad, "examples without a match:", nomatch, file=sys.stderr)
    write("titus-rules.jsonl", cases)


def line_chunks(text, size=8000):
    """Chunks of about `size` chars, cut at line ends."""
    out, cur, n = [], [], 0
    for ln in text.splitlines(keepends=True):
        if n + len(ln) > size and cur:
            out.append("".join(cur))
            cur, n = [], 0
        cur.append(ln[:size])
        n += len(ln[:size])
    if cur:
        out.append("".join(cur))
    return out


def loghub():
    """Loghub (logpai; Zenodo 8196385): full system logs of SSH, OpenStack, HPC, HealthApp, Mac, Zookeeper,
    Hadoop, Apache, Proxifier and Linux. Up to 12 M chars per system, cut at line ends into ~8,000-char records.
    Licence: CC-BY-4.0 on Zenodo; the GitHub repository says "freely available for research or academic work",
    so it is used for evaluation only and nothing is copied into the repository.
    """
    import glob
    rows = []
    for system in sorted(os.listdir(SRC)):
        used = 0
        for p in sorted(glob.glob(os.path.join(SRC, system, "**", "*.log"), recursive=True)):
            if used >= 12_000_000:
                break
            text = open(p, "rb").read().decode("utf8", "replace")[: 12_000_000 - used]
            used += len(text)
            for ch in line_chunks(text):
                rows.append({"src": f"log:{system}:{os.path.relpath(p, os.path.join(SRC, system))}", "text": ch})
    write("loghub.jsonl", rows)


def rfc():
    """53 RFCs whose examples are published test credentials (rfc-editor.org plain text): HTTP auth, cookies,
    OAuth 2.0 and its extensions, JOSE/JWT (incl. RFC 7520's cookbook keys), SCRAM, HOTP/TOTP, PKCS#1, TLS 1.3
    traces (8448), HPKE vectors (9180), HTTP message signatures (9421), and RFC 9500's standard test keys.
    Everything here is an example meant to be printed, so every redaction is counted as a false one.
    Licence: IETF Trust Legal Provisions (RFC text may be copied and reproduced with attribution).
    """
    import glob
    rows = []
    for p in sorted(glob.glob(os.path.join(SRC, "rfc*.txt"))):
        name = os.path.basename(p)[:-4]
        for ch in line_chunks(open(p, encoding="utf8", errors="replace").read()):
            rows.append({"src": f"rfc:{name}", "text": ch})
    write("rfc.jsonl", rows)


def claude_code():
    """Claude Code session files as stored (~/.claude/projects/*/<session>.jsonl), one record per JSON line:
    crispwisp/wisp-claude-code-sessions (MIT; real sessions on one Arch/Hyprland workstation, plus computer-use
    benchmark runs) and armand0e/claude-fable-5-claude-code (MIT; anonymized raw sessions pooled by users).
    SRC holds one subdirectory per dataset. Base64 image data is replaced by "[image]" (redactValue skips media).
    """
    import glob

    def strip(o):
        if isinstance(o, dict):
            if o.get("type") == "base64" and isinstance(o.get("data"), str):
                return {**o, "data": "[image]"}
            return {k: strip(v) for k, v in o.items()}
        if isinstance(o, list):
            return [strip(v) for v in o]
        return o
    rows, seen = [], set()
    for ds in sorted(os.listdir(SRC)):
        for p in sorted(glob.glob(os.path.join(SRC, ds, "**", "*.jsonl"), recursive=True)):
            sess = os.path.basename(p)[:8]
            for line in open(p, encoding="utf8", errors="replace"):
                try:
                    rec = strip(json.loads(line))
                except ValueError:
                    continue
                if rec.get("type") in ("user", "assistant", "system", "attachment", "queue-operation", "summary"):
                    emit_chunks(rows, f"cc:{ds}:{sess}:{rec.get('type')}", json.dumps(rec, ensure_ascii=False), seen)
    write("claude-code.jsonl", rows)


def llm_secdb():
    """LLM-SecDB (Zenodo 20035860, CC-BY-4.0; "You Have Been LaTeXpOsEd", USENIX WOOT 2026): 300 LaTeX comments
    from arXiv sources, some with planted or real leaked credentials, PII and network identifiers.

    secrets: `password`, `passsword`, `api_key`, `jwt_token`, `access_token`, `refresh_token`, `session_id`,
    `session_token`, `oauth_code`, `base64_credential`, `private_key`, `HF_TOKEN` values present in the text.
    keep: usernames, IPs, hostnames, emails, workstation/terminal/transaction/logon IDs, SIDs, ORCIDs, paths, card
    numbers (this library leaves personal data alone). Comments with no credential label also keep their whole
    text. Whole connection strings and URLs with credentials are neither (their password is a secret already).
    """
    SECRET = {"password", "passsword", "api_key", "jwt_token", "access_token", "refresh_token", "session_id",
              "session_token", "oauth_code", "base64_credential", "private_key", "HF_TOKEN"}
    KEEPL = {"ip_address", "username", "workstation ID", "pii_email", "transaction_id", "card_number", "internal_ip",
             "external_ip", "email_address", "internal filesystem_path", "terminal_id", "target_server",
             "security_identifier", "orcid", "logon_id", "hostname", "general_email", "file_path", "login_id", "pii_id"}
    cases = []
    for r in json.load(open(os.path.join(SRC, "LLM-SecDB.json"))):
        t = r["comments"]
        secrets = sorted({x["value"].strip() for x in r["extracted_data"] if x["label"] in SECRET and x["value"].strip() in t})
        keep = sorted({x["value"].strip() for x in r["extracted_data"] if x["label"] in KEEPL and len(x["value"].strip()) >= 4
                       and x["value"].strip() in t and not any(x["value"].strip() in s or s in x["value"].strip() for s in secrets)})
        if not any(x["label"] in SECRET | {"db_connection_string", "url_with_credentials", "cvv"} for x in r["extracted_data"]):
            keep = sorted(set(keep) | {t})
        cases.append({"id": f"secdb-{r['id']}", "kind": r["classification"].lower(), "context": "latex-comment",
                      "text": t, "secrets": secrets, "keep": keep})
    write("llm-secdb.jsonl", cases)


def stackexchange():
    """Stack Exchange question + best-voted answer pairs (flax-sentence-embeddings/stackexchange_titlebody_best_voted_answer_jsonl;
    content CC-BY-SA, the HF copy is tagged CC-BY-NC-SA-4.0, so evaluation only): all of devops.stackexchange,
    a seeded sample of 20 M chars of security.stackexchange and 40 M chars of serverfault. People paste configs,
    commands and logs into questions, usually with credentials masked or made up.
    """
    import gzip
    rows, seen = [], set()
    for site, cap in (("devops.stackexchange.com", 10**9), ("security.stackexchange.com", 20_000_000), ("serverfault.com", 40_000_000)):
        recs = [json.loads(l) for l in gzip.open(os.path.join(SRC, site + ".jsonl.gz"), "rt", encoding="utf8")]
        random.Random(site).shuffle(recs)
        used = 0
        for q, a in recs:
            if used >= cap:
                break
            t = q + "\n\n" + a
            used += len(t)
            emit_chunks(rows, "se:" + site.split(".")[0], t, seen)
    write("stackexchange.jsonl", rows)


def toucan():
    """Toucan-1.5M (Agent-Ark, Apache-2.0), Kimi-K2 shard 00007: synthetic tasks run against ~500 real MCP servers,
    so the tool results are real server output (weather, search, finance, GitHub, databases, ...). Every message but
    the system tool declarations becomes a JSON record, the way a request body carries it; up to 60 M chars.
    """
    import pyarrow.parquet as pq
    rows, seen, used = [], set(), 0
    tbl = pq.read_table(os.path.join(SRC, "kimi-00007.parquet"), columns=["messages", "subset_name"])
    for r in tbl.to_pylist():
        if used >= 60_000_000:
            break
        for m in json.loads(r["messages"]):
            if m.get("role") == "system":
                continue
            t = json.dumps(m, ensure_ascii=False)
            n = len(rows)
            emit_chunks(rows, f"toucan:{r['subset_name']}:{m.get('role')}:{m.get('name') or ''}", t, seen)
            used += sum(len(x["text"]) for x in rows[n:])
    write("toucan.jsonl", rows)


def swe_rebench_prs():
    """nebius/SWE-rebench-V2-PRs (CC-BY-4.0), shard train-00001 (42,100 merged PRs from ~3,000 repositories in many
    languages): issue text with its comments (problem_statement + hints_text), PR descriptions, and the PR's diff
    (first 20,000 chars). Seeded shuffle; caps of 30 M, 10 M and 30 M chars.
    """
    import pyarrow.parquet as pq
    t = pq.read_table(os.path.join(SRC, "train-00001.parquet"), columns=["repo", "problem_statement", "hints_text", "pr_description", "patch"]).to_pylist()
    random.Random(7).shuffle(t)
    rows, seen = [], set()
    used = {"issue": 0, "pr": 0, "diff": 0}
    cap = {"issue": 30_000_000, "pr": 10_000_000, "diff": 30_000_000}
    for r in t:
        for kind, text in (("issue", (r["problem_statement"] or "") + "\n\n" + (r["hints_text"] or "")),
                           ("pr", r["pr_description"] or ""), ("diff", (r["patch"] or "")[:20000])):
            if used[kind] < cap[kind] and len(text.strip()) > 20:
                used[kind] += len(text)
                emit_chunks(rows, f"swe:{kind}:{r['repo']}", text, seen)
    write("swe-rebench-prs.jsonl", rows)


def _script(text):
    """Rough writing-system tag for a context label (not a language ID model)."""
    counts = {"cjk": len(re.findall(r"[\u4e00-\u9fff]", text)), "kana": len(re.findall(r"[\u3040-\u30ff]", text)),
              "hangul": len(re.findall(r"[\uac00-\ud7af]", text)), "cyrillic": len(re.findall(r"[\u0400-\u04ff]", text)),
              "greek": len(re.findall(r"[\u0370-\u03ff]", text)), "arabic": len(re.findall(r"[\u0600-\u06ff]", text)),
              "devanagari": len(re.findall(r"[\u0900-\u097f]", text))}
    if counts["kana"]:
        return "ja"
    best = max(counts, key=counts.get)
    return best if counts[best] >= 5 else "latin"


ID_KEEP = {"customer_id", "account_number", "employee_id", "medical_record_number", "user_name", "username", "url", "email",
           "mac_address", "ipv4", "ipv6", "swift_bic", "swift_bic_code", "bank_routing_number", "routing_number", "iban", "bban",
           "ssn", "credit_card_number", "credit_debit_card", "passport", "passport_number", "drivers_license",
           "driver_license_number", "tax_id", "government_id", "license_plate", "ip_address"}


def _pii_case(cid, ctx, text, spans, secret_labels, rnd_keep=None):
    """{id, kind, context, text, secrets, keep} from (start, end, label) spans, labelled as nemotron_pii():
    secrets are password/API-key spans of 6+ chars that don't look like placeholders and aren't all digits;
    keeps are ID-like spans of 6+ chars that don't overlap a secret. None if a secret span was dropped and
    nothing is left (so the case can't count as secret-free)."""
    secrets, keep, kinds, dropped = [], [], [], False
    for a, b, lab in spans:
        v, lab = text[a:b], lab.lower()
        if lab in secret_labels:
            if len(v) < 6 or PLACEHOLDER.search(v) or v.isdigit() or JWT_IO_SIG in v:
                dropped = True
                continue
            secrets.append(v)
            kinds.append(lab)
        elif lab in ("pin", "cvv", "account_pin", "credit_card_security_code"):
            dropped = True
        elif lab in ID_KEEP and len(v) >= 6:
            keep.append(v)
    secrets = sorted(set(secrets))
    keep = sorted({k for k in set(keep) if not any(k in s or s in k for s in secrets)})
    if not secrets and (dropped or not keep):
        return None
    kind = "api_key" if "api_key" in kinds else "password" if kinds else "none"
    return {"id": cid, "kind": kind, "context": ctx, "text": text, "secrets": secrets, "keep": keep}


def multilingual_pii():
    """Two multilingual PII sets with password and API-key spans (labelled as nemotron_pii()):
    gretelai/synthetic_pii_finance_multilingual test splits (Apache-2.0; finance documents in 7 languages) and
    Wismut/nym-pii-multilingual-data test.jsonl (MIT; incident reports, tickets, chats and logs in 22 languages,
    with injected typos). Every case with a secret, plus up to 1,500 secret-free cases with ID keeps (seed 11).
    """
    import pyarrow.parquet as pq
    pos, neg = [], []
    for fn in sorted(os.listdir(os.path.join(SRC, "gretel-multi"))):
        if not fn.endswith(".parquet"):
            continue
        for i, r in enumerate(pq.read_table(os.path.join(SRC, "gretel-multi", fn)).to_pylist()):
            spans = [(s["start"], s["end"], s["label"]) for s in json.loads(r["pii_spans"])]
            c = _pii_case(f"gretel-{fn.split('_')[0]}-{i}", f"gretel:{r['language']}:{r['document_type']}", r["generated_text"],
                          spans, {"password", "api_key"})
            if c:
                (pos if c["secrets"] else neg).append(c)
    with open(os.path.join(SRC, "nym-pii", "test.jsonl")) as f:
        for i, line in enumerate(f):
            r = json.loads(line)
            spans = [(e["start"], e["end"], e["label"]) for e in r["entities"]]
            c = _pii_case(f"nym-{i}", f"nym:{_script(r['text'])}", r["text"], spans, {"password", "api_key"})
            if c:
                (pos if c["secrets"] else neg).append(c)
    rnd = random.Random(11)
    rnd.shuffle(neg)
    write("multilingual-pii.jsonl", pos + neg[:1500])


def leak_files():
    """Committed-secret files: printemps-tokyo/leak-museum (MIT, 6b1483a, 2026-07; 27 exhibits: .env, k8s Secret, tfstate,
    .npmrc, .pgpass, HAR, Postman, .mcp.json, wp-config, ...) and Plazmaz/leaky-repo (MIT, 2e95135; dotfiles and app
    configs: FileZilla, .netrc, .s3cfg, robomongo, DBeaver, PuTTY, wp-config, .htpasswd, shadow, ...). Secret spans are
    PII Arena's frozen annotations (Quakeer444/pii-arena benchmark/corpus_offsets.json, MIT), checked against each
    file's sha256. One case per annotated text file, twice: as pasted text, and as the output of `cat <path>`.
    """
    import hashlib
    spec = json.load(open(os.path.join(SRC, "pii-arena", "benchmark", "corpus_offsets.json")))
    plain, cat = [], []
    for name in ("leak-museum", "leaky-repo"):
        for rel, e in sorted(spec[name]["files"].items()):
            raw = open(os.path.join(SRC, name, rel), "rb").read()
            if hashlib.sha256(raw).hexdigest() != e["sha256"]:
                raise SystemExit(f"{name}/{rel}: fingerprint mismatch")
            text = raw.decode()
            secrets = sorted({text[a:b] for a, b in e["spans"]})
            base = {"kind": name, "context": rel.rsplit("/", 1)[-1], "text": text, "secrets": secrets, "keep": []}
            cid = f"{name}:" + rel.replace("/", "~")  # no "/": eval/baselines.py names files after ids
            plain.append({"id": cid, **base})
            cat.append({"id": cid + ":cat", **base, "hint": {"command": f"cat {rel}"}})
    write("leak-files.jsonl", plain)
    write("leak-files-cat.jsonl", cat)


def dev_articles():
    """Non-English developer articles: Qiita (OmniAICreator/Qiita-1.07M, MIT; Japanese, shards 00010 and 00031:
    markdown bodies) and Habr (volosati/habr, a re-upload of IlyaGusev/habr with no licence tag, so evaluation only;
    Russian, shards 00007 and 00023: markdown article text, then its comments). 30 M chars each, seeded shuffle.
    """
    import ast
    import pyarrow.parquet as pq
    rows, seen = [], set()
    for name, cols in (("qiita", ["body", "url"]), ("habr", ["text_markdown", "comments", "url", "language"])):
        recs = []
        for fn in sorted(os.listdir(os.path.join(SRC, name))):
            if fn.endswith(".parquet"):
                recs += pq.read_table(os.path.join(SRC, name, fn), columns=cols).to_pylist()
        random.Random(13).shuffle(recs)
        used = 0
        for r in recs:
            if used >= 30_000_000:
                break
            if name == "qiita":
                texts = [("article", r["body"])]
            else:
                texts = [("article", r["text_markdown"])]
                try:
                    cs = ast.literal_eval(r["comments"]) if isinstance(r["comments"], str) else (r["comments"] or [])
                except (ValueError, SyntaxError):
                    cs = []
                flat, stack = [], list(cs)
                while stack:
                    c = stack.pop(0)
                    if isinstance(c, dict):
                        flat.append(c.get("message_markdown") or "")
                        stack.extend(c.get("children") or [])
                if flat:
                    texts.append(("comments", "\n\n".join(flat)))
            for kind, t in texts:
                if not t:
                    continue
                n = len(rows)
                for ch in line_chunks(t):
                    if ch[:300] not in seen:
                        seen.add(ch[:300])
                        rows.append({"src": f"{name}:{kind}:{r['url']}", "text": ch})
                used += sum(len(x["text"]) for x in rows[n:])
    write("dev-articles.jsonl", rows)


def kaggle_notebooks():
    """Kaggle notebooks with their outputs, as raw .ipynb JSON (what an agent reading the file sees):
    bigcomputer/kaggle-notebooks-outputs-filtered-57 shard train-00003 (376 notebooks; no licence tag, so evaluation
    only). Up to 400,000 chars per notebook (outputs carry base64 PNGs and long tables), 60 M chars in all, seeded order.
    """
    import pyarrow.parquet as pq
    t = pq.read_table(os.path.join(SRC, "train-00003.parquet"), columns=["text", "id"]).to_pylist()
    random.Random(14).shuffle(t)
    rows, seen, used = [], set(), 0
    for r in t:
        if used >= 60_000_000:
            break
        n = len(rows)
        for ch in line_chunks(r["text"][:400_000]):
            if ch[:300] not in seen:
                seen.add(ch[:300])
                rows.append({"src": f"kaggle:{r['id']}", "text": ch})
        used += sum(len(x["text"]) for x in rows[n:])
    write("kaggle-notebooks.jsonl", rows)


SKIP_DIRS = {".git", "node_modules", "vendor", "Pods", "build", "dist", ".gradle", "Library", "Temp", "obj", "bin"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".pdf", ".zip", ".gz", ".tgz", ".jar", ".so", ".dylib",
            ".dll", ".exe", ".a", ".o", ".class", ".ttf", ".otf", ".woff", ".woff2", ".mp3", ".mp4", ".wav", ".ogg",
            ".psd", ".fbx", ".blend", ".bin", ".dat", ".keystore", ".jks", ".apk", ".ipa", ".car", ".bundle"}


def repo_files(prefix, cap_per_repo=15_000_000, max_file=1_000_000):
    """{src, text} records from every text file of every repository directory under SRC (one directory per clone,
    named owner_repo), cut at line ends; binary files, files over max_file bytes and build/vendor directories are
    skipped; at most cap_per_repo chars per repository, files in sorted path order."""
    rows, seen = [], set()
    for repo in sorted(os.listdir(SRC)):
        root = os.path.join(SRC, repo)
        if not os.path.isdir(root):
            continue
        used = 0
        for dp, dns, fns in os.walk(root):
            dns[:] = sorted(d for d in dns if d not in SKIP_DIRS)
            for fn in sorted(fns):
                path = os.path.join(dp, fn)
                if os.path.splitext(fn)[1].lower() in SKIP_EXT or os.path.islink(path) or os.path.getsize(path) > max_file:
                    continue
                raw = open(path, "rb").read()
                if b"\0" in raw:
                    continue
                try:
                    text = raw.decode("utf-8")
                except UnicodeDecodeError:
                    continue
                if used >= cap_per_repo or len(text) < 20:
                    continue
                rel = os.path.relpath(path, root)
                for ch in line_chunks(text):
                    if ch[:300] not in seen:
                        seen.add(ch[:300])
                        rows.append({"src": f"{prefix}:{repo}:{rel}", "text": ch})
                        used += len(ch)
    return rows


def iac():
    """Infrastructure as code: Terraform modules (terraform-aws-modules vpc, eks, rds, rds-aurora, iam, lambda;
    terraform-google-modules kubernetes-engine, sql-db; Azure terraform-azurerm-aks), Helm charts (bitnami/charts,
    prometheus-community, grafana) and Ansible (geerlingguy roles mysql, postgresql, jenkins, gitlab; community.mysql,
    community.postgresql, community.hashi_vault collections; ansible/ansible-examples). Apache-2.0, MIT and GPL-3.0
    (the collections); ansible-examples has no licence file, so the set as a whole is evaluation only.
    """
    write("iac.jsonl", repo_files("iac"))


def mobile():
    """Mobile apps: Android (thunderbird-android, AntennaPod, home-assistant/android, nextcloud/android, bitwarden/android,
    firebase/quickstart-android), iOS (wikipedia-ios, mastodon-ios, element-x-ios, firebase/quickstart-ios) and Flutter
    (flutter/samples). Apache-2.0, MIT, BSD, GPL-3.0, AGPL-3.0: evaluation only as a set. ≤6 M chars per repository."""
    write("mobile.jsonl", repo_files("mobile", cap_per_repo=6_000_000))


def gamedev():
    """Game development: Godot (godot-demo-projects, tps-demo; MIT), Unity (open-project-1 "Chop Chop", Apache-2.0;
    ml-agents, Apache-2.0; EntityComponentSystemSamples, Unity Companion Licence), Bevy (MIT/Apache-2.0), OpenRA
    (GPL-3.0), minetest_game (LGPL-2.1). Evaluation only as a set. ≤8 M chars per repository."""
    write("gamedev.jsonl", repo_files("gamedev", cap_per_repo=8_000_000))


def osv():
    """Security advisories as OSV JSON (https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip, fetched
    2026-10-09) for npm, PyPI, Go, Maven, crates.io, Packagist, RubyGems, NuGet: GHSA (CC-BY-4.0), PYSEC (CC-BY-4.0),
    GO (CC-BY-4.0), RUSTSEC (CC0), and OpenSSF malicious-package reports (MAL, Apache-2.0). Each advisory is one JSON
    document, as an agent fetching it sees it. Seeded sample: every non-MAL advisory in random order and one MAL per
    ten, up to 60 M chars.
    """
    import zipfile
    docs = []
    for fn in sorted(os.listdir(SRC)):
        if fn.endswith(".zip"):
            z = zipfile.ZipFile(os.path.join(SRC, fn))
            docs += [(fn[:-4], name, z) for name in z.namelist() if name.endswith(".json")]
    rnd = random.Random(19)
    rnd.shuffle(docs)
    rows, seen, used, mal = [], set(), 0, 0
    for eco, name, z in docs:
        if used >= 60_000_000:
            break
        if name.startswith("MAL-"):
            mal += 1
            if mal % 10:
                continue
        text = z.read(name).decode("utf-8", "replace")
        n = len(rows)
        for ch in line_chunks(text):
            if ch[:300] not in seen:
                seen.add(ch[:300])
                rows.append({"src": f"osv:{eco}:{name[:-5]}", "text": ch})
        used += sum(len(x["text"]) for x in rows[n:])
    write("osv.jsonl", rows)


def termgrade():
    """ai-and/termgrade-trajectories (Apache-2.0, 2026-10-08): Terminus-2 terminal-agent episodes on 1,004 executable
    tasks, as chat messages (data/messages/{deepseek,glm,kimi,qwen}.parquet): the model's JSON command batches and the
    raw terminal output that came back. Every message but the system prompt becomes a JSON record; trials in seeded
    order across the four models, up to 60 M chars.
    """
    import pyarrow.parquet as pq
    trials = []
    for fn in sorted(os.listdir(SRC)):
        if fn.startswith("messages-") and fn.endswith(".parquet"):
            trials += pq.read_table(os.path.join(SRC, fn), columns=["trial", "model", "messages"]).to_pylist()
    random.Random(20).shuffle(trials)
    rows, seen, used = [], set(), 0
    for r in trials:
        if used >= 60_000_000:
            break
        msgs = json.loads(r["messages"]) if isinstance(r["messages"], str) else (r["messages"] or [])
        for m in msgs:
            if m.get("role") == "system":
                continue
            n = len(rows)
            emit_chunks(rows, f"termgrade:{r['model']}:{r['trial']}:{m.get('role')}", json.dumps(m, ensure_ascii=False), seen)
            used += sum(len(x["text"]) for x in rows[n:])
    write("termgrade.jsonl", rows)


def ci_logs():
    """CI logs: `gh run view <id> --log` output of up to six recent completed GitHub Actions runs in each of 36 public
    repositories (fetched 2026-10-09 into gha/, ≤3 MB each; 114 non-empty), and the failed-build logs of
    JetBrains-Research/lca-ci-builds-repair (lca/test.parquet, 68 Python builds; permissive-licence repositories).
    Evaluation only (logs carry no licence of their own). ≤1.5 M chars per run log.
    """
    import pyarrow.parquet as pq
    rows, seen = [], set()
    for fn in sorted(os.listdir(os.path.join(SRC, "gha"))):
        text = open(os.path.join(SRC, "gha", fn), encoding="utf-8", errors="replace").read()[:1_500_000]
        for ch in line_chunks(text):
            if ch[:300] not in seen:
                seen.add(ch[:300])
                rows.append({"src": "gha:" + fn[:-4], "text": ch})
    for r in pq.read_table(os.path.join(SRC, "lca", "test.parquet"), columns=["repo_owner", "repo_name", "logs"]).to_pylist():
        for step in r["logs"] or []:
            for ch in line_chunks(step.get("log") or ""):
                if ch[:300] not in seen:
                    seen.add(ch[:300])
                    rows.append({"src": f"lca:{r['repo_owner']}/{r['repo_name']}:{step.get('step_name')}", "text": ch})
    write("ci-logs.jsonl", rows)


def ctf():
    """CTF writeups and solve scripts: Lo4pca/NoobCTF (CC0-1.0; Chinese notes and writeups collected from many teams),
    welchbj/ctf (MIT), Nautilus-Institute/finals-2024 (MIT; DEF CON CTF finals challenges), p4-team/ctf (no licence, so
    evaluation only; English and Polish writeups 2015–2024). ≤20 M chars per repository. Flags (`flag{…}`) are not
    secrets.
    """
    write("ctf.jsonl", repo_files("ctf", cap_per_repo=20_000_000))


def pypi_readmes():
    """PyPI package metadata (labofsahil/pypi-packages-metadata-dataset, MIT; PyPI's public BigQuery distribution
    metadata), five parquet parts: for each distinct package, its long description (the README shown on pypi.org),
    and for its first file a JSON metadata record as the PyPI JSON API shows it (name, version, summary, URLs,
    requirements, md5/sha256/blake2 digests, upload path). Seeded order, up to 60 M chars.
    """
    import pyarrow.parquet as pq
    recs = []
    for fn in sorted(os.listdir(SRC)):
        if fn.endswith(".parquet"):
            recs += pq.read_table(os.path.join(SRC, fn)).to_pylist()
    random.Random(22).shuffle(recs)
    rows, seen, names, used = [], set(), set(), 0
    META = ("name", "version", "summary", "author", "author_email", "home_page", "project_urls", "requires_dist",
            "upload_time", "filename", "path", "md5_digest", "sha256_digest", "blake2_256_digest")
    for r in recs:
        if used >= 60_000_000:
            break
        if r["name"] in names:
            continue
        names.add(r["name"])
        n = len(rows)
        meta = json.dumps({k: (str(r[k]) if r[k] is not None else None) for k in META}, ensure_ascii=False)
        for kind, t in (("readme", r["description"]), ("meta", meta)):
            if t and t != "None":
                for ch in line_chunks(t):
                    if ch[:300] not in seen:
                        seen.add(ch[:300])
                        rows.append({"src": f"pypi:{kind}:{r['name']}", "text": ch})
        used += sum(len(x["text"]) for x in rows[n:])
    write("pypi-readmes.jsonl", rows)


def obfuscation():
    """umashankarak/secret-scanner-obfuscation-benchmark (MIT, 42b0aeb, 2026-09; "Hiding in Plain Sight"): its released
    corpus.zip (unzipped under SRC/corpus/x): 14,040 synthetic, format-valid credentials of 9 types in .py, .env and
    .yaml files, each under one of 24 obfuscations. Kept: the 16 single-token transformations (plaintext, Base64/32/85,
    hex, URL-encoding, ROT13, gzip+Base64, Base64 x2/x3, Base64->hex, hex escapes, zero-width insertion, reversed
    string, reverse+Base64, no keyword, benign variable name); dropped: splitting, XOR and split+Base64 (no single
    token to score). The secret is the token as written on the manifest's expected line (the first quoted literal, else
    the value after `=` or `:`), since leaking the encoded form leaks the credential. No keeps.
    """
    root = os.path.join(SRC, "corpus", "x")
    keep_t = {"T0.0", "T1.1", "T1.2", "T1.3", "T1.4", "T1.5", "T1.6", "T1.7", "T2.1", "T2.2", "T2.3", "T4.3", "T4.5",
              "T5.1", "T6.1", "T6.4", "T7.2"}
    cases = []
    for x in json.load(open(os.path.join(root, "manifest.json"))):
        if x["transformation_id"] not in keep_t:
            continue
        text = open(os.path.join(root, "corpus", x["file"]), encoding="utf-8").read()
        line = text.split("\n")[x["expected_line"] - 1]
        m = re.search(r'"([^"]+)"', line) or re.search(r"'([^']+)'", line) or re.search(r"^[^=:#]+[=:]\s*(\S+)\s*$", line)
        if not m:
            continue
        cases.append({"id": x["id"], "kind": f"{x['transformation_id']} {x['transformation_name']}",
                      "context": f"{x['carrier']}:{x['secret_type']}", "text": text, "secrets": [m.group(1)], "keep": []})
    write("obfuscation.jsonl", cases)


{"nemotron-pii": nemotron_pii, "openhands-feedback": openhands_feedback, "titus-rules": titus_rules, "loghub": loghub,
 "rfc": rfc, "claude-code": claude_code, "llm-secdb": llm_secdb, "stackexchange": stackexchange, "toucan": toucan,
 "swe-rebench-prs": swe_rebench_prs, "multilingual-pii": multilingual_pii,
 "leak-files": leak_files, "dev-articles": dev_articles,
 "kaggle-notebooks": kaggle_notebooks, "iac": iac,
 "mobile": mobile, "gamedev": gamedev, "osv": osv,
 "termgrade": termgrade, "ci-logs": ci_logs, "ctf": ctf, "pypi-readmes": pypi_readmes,
 "obfuscation": obfuscation}[SET]()
