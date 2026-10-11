"""
The 60 MB sample of the final real-text set that every scanner is run on for the README's comparison:
every 6th trajectory record and every 2nd repository record of final.jsonl (see build-final.py).

    python3 -I scripts/build-sample.py
"""
import json, os

# Corpora outside the repository: $REDACT_CORPORA, or ~/Downloads/redact-corpora (eval/data-root.ts).
CORPORA_ROOT = os.environ.get("REDACT_CORPORA", os.path.expanduser("~/Downloads/redact-corpora"))

F = os.path.join(CORPORA_ROOT, "final")
traj = repo = size = 0
with open(os.path.join(F, "final.jsonl")) as src, open(os.path.join(F, "sample.jsonl"), "w") as out:
    for line in src:
        record = json.loads(line)
        if record["src"].startswith("traj"):
            traj += 1
            if traj % 6:
                continue
        else:
            repo += 1
            if repo % 2:
                continue
        out.write(line)
        size += len(record["text"])
print(f"{size / 1e6:.1f} MB")
