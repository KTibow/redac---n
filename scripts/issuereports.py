"""
Converts the issue-report secret dataset (Zenodo 10.5281/zenodo.17430335, CC-BY-4.0) into eval cases:
one case per issue text, true candidates as `secrets`, false candidates as `keep`. The train split is
for diagnostics; test and test_wild are only reported.

    python3 -I scripts/issuereports.py <Data dir> <out dir>
"""
import csv, json, sys, os
csv.field_size_limit(1 << 30)
src, out = sys.argv[1], sys.argv[2]
for name in ["train", "test", "test_wild"]:
    cases = {}
    with open(os.path.join(src, f"{name}.csv"), newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            text = row["text"]
            cand = row["candidate_string"]
            if not cand or cand not in text:
                continue
            c = cases.setdefault(text, {"id": f"{name}-{len(cases)}", "kind": row.get("secret_type") or "issue", "context": "issue-report", "text": text, "secrets": [], "keep": []})
            (c["secrets"] if row["label"] in ("1", "1.0", "True") else c["keep"]).append(cand)
    with open(os.path.join(out, f"issues-{name}.jsonl"), "w") as f:
        for c in cases.values():
            # A value labelled both ways (rare) is dropped from keep.
            c["keep"] = [k for k in dict.fromkeys(c["keep"]) if k not in c["secrets"] and not any(k in s or s in k for s in c["secrets"])]
            c["secrets"] = list(dict.fromkeys(c["secrets"]))
            f.write(json.dumps(c) + "\n")
    print(name, len(cases), sum(len(c["secrets"]) for c in cases.values()), sum(len(c["keep"]) for c in cases.values()))
