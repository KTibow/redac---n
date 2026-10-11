"""
Converts Betterleaks' rule catalog (MIT, https://github.com/betterleaks/betterleaks) into JS regex
sources for src/formats-data.ts. RE2 syntax is mapped to JS (flags, POSIX classes, named groups),
rules whose "secret" is an identifier (client IDs, usernames, domains) are dropped, and each rule is
classified as "prefix" (a distinctive literal starts the token) or "keyword" (a vendor name before an
assignment). Rules are re-validated on real text by scripts/check-formats.ts before use.

    python3 -I scripts/import-betterleaks.py <betterleaks.toml> > eval/out/betterleaks-rules.json
"""
import json
import re
import sys
import tomllib

cfg = tomllib.load(open(sys.argv[1], "rb"))

# Rules about values that identify rather than authenticate.
NOT_SECRET_ID = re.compile(
    r"(client-id|-client-id|app-id|-id$|-id\.|username|-user$|domain|-url|endpoint|account-name|cloud-name|tenant|"
    r"org-name|hostname|instance|subdomain|-host|project-id|email|region|bucket|curl)",
    re.I,
)
POSIX = {
    "[:alnum:]": "A-Za-z0-9", "[:alpha:]": "A-Za-z", "[:digit:]": "0-9", "[:upper:]": "A-Z", "[:lower:]": "a-z",
    "[:xdigit:]": "0-9A-Fa-f", "[:space:]": r"\s", "[:word:]": r"\w", "[:punct:]": r"!-\/:-@\[-`{-~",
}


def to_js(src: str):
    flags = ""
    if src.startswith("(?i)"):
        flags += "i"
        src = src[4:]
    if src.startswith("(?s)"):
        flags += "s"
        src = src[4:]
    for k, v in POSIX.items():
        src = src.replace(k, v)
    src = src.replace("(?P<", "(?<").replace(r"\z", "$").replace(r"\A", "^")
    # A mid-pattern (?i) applies to the rest of its group: rewrite as a (?i:...) modifier group.
    while "(?i)" in src:
        at = src.index("(?i)")
        depth = 0
        end = len(src)
        i = at + 4
        while i < len(src):
            c = src[i]
            if c == "\\":
                i += 2
                continue
            if c == "[":
                j = i + 1
                while j < len(src) and src[j] != "]":
                    j += 2 if src[j] == "\\" else 1
                i = j + 1
                continue
            if c == "(":
                depth += 1
            elif c == ")":
                if depth == 0:
                    end = i
                    break
                depth -= 1
            elif c == "|" and depth == 0:
                end = i
                break
            i += 1
        src = src[:at] + "(?i:" + src[at + 4 : end] + ")" + src[end:]
    return src, flags


def literal_prefix(src: str) -> str:
    """The literal text the secret starts with, if any: `ghp_` from `\\b(ghp_[A-Za-z0-9]{36})`."""
    s = re.sub(r"^(\\b|\(\?:\^\|\[[^\]]*\]\)|\(\?:\^\|[^)]*\))", "", src)
    s = s.lstrip("(")
    s = re.sub(r"^\?<\w+>", "", s)
    out = ""
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s) and s[i + 1] in "-._/:$":
            out += s[i + 1]
            i += 2
            continue
        if re.match(r"[A-Za-z0-9_\-:.$/~]", c):
            if c == "." :
                break
            out += c
            i += 1
            continue
        break
    # A quantifier after the last literal character makes it optional or repeated.
    if i < len(s) and s[i] in "?*{+":
        out = out[:-1]
    return out


rules = []
skipped = []
for r in cfg["rules"]:
    rid = r["id"]
    src = r.get("regex")
    if not src:
        skipped.append((rid, "no regex"))
        continue
    if NOT_SECRET_ID.search(rid) and not re.search(r"webhook|sensitive", rid):
        skipped.append((rid, "identifier"))
        continue
    if "curl" in rid or ".*" in src.replace(".*?", "") and "curl" in src:
        skipped.append((rid, "curl"))
        continue
    js, flags = to_js(src)
    prefix = literal_prefix(js) if not flags else ""
    keyword_anchored = bool(re.match(r"^\(\?i:|^\(\?:|^\\b\(\?:", js)) and ("(?:=|>|:{1,3}=" in js or "(?:.|[\\n\\r])" in js or "[\\s\\S]" in js)
    kind = "prefix" if len(prefix) >= 3 and not keyword_anchored else "keyword" if keyword_anchored else "pattern"
    flt = r.get("filter", "")
    m = re.search(r"entropy\(finding\[\"secret\"\]\)\s*<\s*([\d.]+)", flt)
    min_entropy = float(m.group(1)) if m else None
    m = re.search(r"tokenRatio\(finding\[\"secret\"\]\)\s*>=\s*([\d.]+)", flt)
    max_token_ratio = float(m.group(1)) if m else None
    rules.append({
        "id": rid,
        "description": r.get("description", ""),
        "regex": js,
        "flags": flags,
        "keywords": r.get("keywords", []),
        "prefix": prefix,
        "kind": kind,
        "confidence": r.get("confidence"),
        "minEntropy": min_entropy,
        "maxTokenRatio": max_token_ratio,
        "secretGroup": r.get("secretGroup"),
    })

json.dump({"rules": rules, "skipped": skipped}, sys.stdout, indent=1)
print(f"{len(rules)} rules, {len(skipped)} skipped", file=sys.stderr)
