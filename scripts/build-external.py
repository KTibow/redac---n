"""
Converts third-party labelled sets into eval cases ({id, text, secrets, keep}), for scoring once blind
and then as extra dev data. Inputs are fresh public clones; outputs stay outside the repo (their
licences differ from ours).

  SlotGuard experiments/data/credentials.json (Apache-2.0): 200 multi-turn sessions with planted
    credentials; the "anchors" are task tokens a model needs, so they are keeps.
  ProwlBench (PolyForm Noncommercial, eval only): see below.
  crossvault/redact-transcripts vectors/ (CC0): positive, split and encoded vectors (their `absent`
    strings must not survive) and negative vectors (byte-identical, so the whole input is a keep).
    Known misses and third-party (people's names) vectors are out of scope.

    python3 -I scripts/build-external.py <priorart dir> <out dir>
"""
import json
import os
import sys

src, out = sys.argv[1], sys.argv[2]
os.makedirs(out, exist_ok=True)

cases = []
data = json.load(open(os.path.join(src, "SlotGuard/experiments/data/credentials.json")))
for s in data["sessions"]:
    text = "\n\n".join(f"{t['role']}: {t['content']}" for t in s["turns"])
    secrets = sorted({c["raw"] for c in s["credentials"]})
    keep = [a for a in s["anchors"] if a in text and not any(a in x or x in a for x in secrets)]
    cases.append({"id": f"slotguard-{s['id']}", "context": "slotguard", "text": text, "secrets": secrets, "keep": keep})
with open(os.path.join(out, "slotguard.jsonl"), "w") as f:
    for c in cases:
        f.write(json.dumps(c, ensure_ascii=False) + "\n")
print(len(cases), "slotguard cases", sum(len(c["secrets"]) for c in cases), "secrets", file=sys.stderr)

cases = []
for name in ["positive", "split", "encoded", "negative"]:
    for v in json.load(open(os.path.join(src, "crossvault_redact-transcripts/vectors", f"{name}.json")))["vectors"]:
        if v.get("options") or v["expect"] == "known_miss":
            continue
        text = "".join(v["chunks"]) if "chunks" in v else v["input"]
        case = {"id": f"crossvault-{name}-{v['id']}", "context": f"crossvault-{name}", "text": text}
        if v["expect"] == "redacted":
            case["secrets"] = v.get("absent", [])
        elif v["expect"] == "unchanged":
            case["keep"] = [text]
        cases.append(case)
with open(os.path.join(out, "crossvault.jsonl"), "w") as f:
    for c in cases:
        f.write(json.dumps(c, ensure_ascii=False) + "\n")
print(len(cases), "crossvault cases", file=sys.stderr)

# ProwlBench (PolyForm Noncommercial: evaluation only, never redistributed): snippets with one secret
# span (label 1) or none (label 0, where any redaction is a loss). Rows from Samsung CredData
# (origin "real") are dropped: they overlap our CredData splits.
path = os.path.join(src, "prowlbench/prowlbench.jsonl")
if os.path.exists(path):
    cases = []
    for line in open(path):
        r = json.loads(line)
        if r["origin"] == "real":
            continue
        case = {"id": f"prowl-{r['id']}", "context": f"prowl-{r['tier']}-{r['source']}-{r['lang']}", "text": r["text"]}
        if r["label"] == 1 and r["span"]:
            case["secrets"] = [r["text"][r["span"][0]:r["span"][1]]]
        elif r["label"] == 0:
            case["keep"] = [r["text"]]
        else:
            continue
        cases.append(case)
    with open(os.path.join(out, "prowlbench.jsonl"), "w") as f:
        for c in cases:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")
    print(len(cases), "prowlbench cases", file=sys.stderr)
