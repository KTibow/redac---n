#!/usr/bin/env python3
"""
Fills case templates (eval/corpora/templates/*.jsonl.gz, format in templates/FORMAT.md) with generated values
and writes labelled cases: every S marker becomes a secret, every K marker a keep value.

Templates are written by agents that never see the library; the values come from here, so no person or
agent writes credential values. Everything is generated from a fixed seed (stdlib only), in real formats
(prefixes, alphabets, lengths); none of it is a working credential.

    python3 -I eval/corpora/fill_templates.py <templates.jsonl.gz>… --out <cases.jsonl.gz> [--seed N] [--prefix ID]
"""
import base64
import gzip
import hashlib
import io
import json
import random
import re
import sys
import urllib.parse
import uuid as uuidlib


def open_text(path, mode="r"):
    """A JSONL file as text, gzipped when its name ends in `.gz`, as the repository keeps corpora (and with no time in
    the gzip header, so the same cases give the same bytes)."""
    if not path.endswith(".gz"):
        return open(path, mode, encoding="utf-8")
    return io.TextIOWrapper(gzip.GzipFile(path, mode + "b", mtime=0), encoding="utf-8")

ALPHABETS = {
    "b62": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "hex": "0123456789abcdef",
    "HEX": "0123456789ABCDEF",
    "lower": "abcdefghijklmnopqrstuvwxyz",
    "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "lower_digits": "abcdefghijklmnopqrstuvwxyz0123456789",
    "upper_digits": "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "b64": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    "b64url": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
    "b58": "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
    "digits": "0123456789",
}
WORDS = """apple river stone cloud maple ember harbor velvet copper falcon winter summer autumn spring orange
violet silver garden meadow lantern pepper thunder canyon glacier island mango cobalt saffron willow
quartz rocket comet nebula tiger otter panda raven cedar birch lotus coral delta sierra tango kilo
marble basil cinder prairie tundra mosaic ripple sparrow badger juniper crimson indigo amber""".split()
MARKER = re.compile(r"⟦([SK])(=([^⟧]*)|(#([\w-]+))?(?::([^⟧|]*(?:\|[^⟧]*)?))?(\|(url|json|b64|basic:[^⟧]*))?)⟧")


class Filler:
    def __init__(self, seed):
        self.R = random.Random(seed)

    def rand(self, alphabet, n):
        return "".join(self.R.choice(alphabet) for _ in range(n))

    def b64(self, nbytes, url=False):
        raw = bytes(self.R.getrandbits(8) for _ in range(nbytes))
        s = base64.b64encode(raw).decode()
        return s.replace("+", "-").replace("/", "_").rstrip("=") if url else s

    def wrap(self, body):
        return "\n".join(body[i:i + 64] for i in range(0, len(body), 64))

    def pem(self, label, prefix, nbytes):
        # The usual DER opening for the key type, then random material, padded to whole base64 quads.
        body = prefix + self.rand(ALPHABETS["b64"], (nbytes * 4) // 3)
        body += "=" * (-len(body) % 4)
        return f"-----BEGIN {label}-----\n{self.wrap(body)}\n-----END {label}-----"

    def uuid(self):
        return str(uuidlib.UUID(int=self.R.getrandbits(128), version=4))

    def jwt(self, payload):
        enc = lambda o: base64.urlsafe_b64encode(json.dumps(o, separators=(",", ":")).encode()).decode().rstrip("=")
        return f"{enc({'alg': 'HS256', 'typ': 'JWT'})}.{enc(payload)}.{self.b64(32, url=True)}"

    def human(self):
        w = self.R.choice(WORDS)
        forms = [
            lambda: w.capitalize() + str(self.R.randint(1990, 2030)) + self.R.choice("!@#$%&*?"),
            lambda: w.capitalize() + self.R.choice(WORDS).capitalize() + str(self.R.randint(1, 999)),
            lambda: w.replace("a", "4").replace("e", "3").replace("o", "0").capitalize() + self.R.choice("!&#") + str(self.R.randint(1, 99)),
            lambda: self.R.choice(WORDS) + self.R.choice("-_.") + w + str(self.R.randint(10, 9999)),
            lambda: w.upper()[:4] + self.rand(ALPHABETS["lower_digits"], 6) + self.R.choice("!$%"),
        ]
        return self.R.choice(forms)()

    def value(self, kind, shape):
        """A value for an S or K marker's shape."""
        R = self.R
        special = {
            "uuid": self.uuid,
            "ulid": lambda: self.rand("0123456789ABCDEFGHJKMNPQRSTVWXYZ", 26),
            "sha1": lambda: self.rand(ALPHABETS["hex"], 40),
            "sha256": lambda: self.rand(ALPHABETS["hex"], 64),
            "sha512": lambda: self.rand(ALPHABETS["hex"], 128),
            "md5": lambda: self.rand(ALPHABETS["hex"], 32),
            "git-short": lambda: self.rand(ALPHABETS["hex"], 7),
            "sri": lambda: "sha512-" + self.b64(64),
            "docker-digest": lambda: "sha256:" + self.rand(ALPHABETS["hex"], 64),
            "ssh-pub": lambda: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" + self.b64(32)[:43] + f" {R.choice(WORDS)}@{R.choice(WORDS)}",
            "pem-cert": lambda: self.pem("CERTIFICATE", "MIIDazCCAlOgAwIBAgIU", 860),
            "pem-pub": lambda: self.pem("PUBLIC KEY", "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA", 270),
            "jwt": lambda: self.jwt({"sub": self.uuid(), "role": "authenticated", "iat": 1760000000 + R.randint(0, 10**6), "exp": 1790000000 + R.randint(0, 10**6)}),
            "jwt-public": lambda: self.jwt({"iss": "supabase", "ref": self.rand(ALPHABETS["lower"], 20), "role": "anon", "iat": 1700000000, "exp": 2000000000}),
            "pem-rsa": lambda: self.pem("PRIVATE KEY", "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ", 1160),
            "pem-ec": lambda: self.pem("EC PRIVATE KEY", "MHcCAQEEI", 110),
            "openssh": lambda: self.pem("OPENSSH PRIVATE KEY", "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW", 330),
            "human": self.human,
            "passphrase": lambda: R.choice(" -").join(R.choice(WORDS) for _ in range(R.randint(4, 6))),
            "slack-webhook": lambda: f"https://hooks.slack.com/services/T{self.rand(ALPHABETS['upper_digits'], 8)}/B{self.rand(ALPHABETS['upper_digits'], 10)}/{self.rand(ALPHABETS['b62'], 24)}",
            "discord-webhook": lambda: f"https://discord.com/api/webhooks/{self.rand(ALPHABETS['digits'], 18)}/{self.b64(51, url=True)}",
        }
        if shape in special:
            return special[shape]()
        parts = shape.split("|")
        if len(parts) < 3:
            raise ValueError(f"bad shape {shape!r}")
        prefix, alphabet, length = parts[0], parts[1], parts[2]
        suffix = parts[3] if len(parts) > 3 else ""
        if alphabet == "digits_dash":  # Slack-style `xoxb-<digits>-<digits>-<b62>`
            return prefix + f"{self.rand(ALPHABETS['digits'], 12)}-{self.rand(ALPHABETS['digits'], 13)}-{self.rand(ALPHABETS['b62'], 24)}" + suffix
        if alphabet not in ALPHABETS:
            raise ValueError(f"bad alphabet {alphabet!r}")
        return prefix + self.rand(ALPHABETS[alphabet], int(length)) + suffix


def encode(value, how):
    if not how:
        return value
    if how == "url":
        return urllib.parse.quote(value, safe="")
    if how == "json":
        return json.dumps(value)[1:-1]
    if how == "b64":
        return base64.b64encode(value.encode()).decode()
    if how.startswith("basic:"):
        return base64.b64encode(f"{how[6:]}:{value}".encode()).decode()
    raise ValueError(how)


def fill(template, filler):
    named = {}
    secrets, keeps = [], []
    errors = []

    def sub(m):
        kind, literal, name, shape, how = m.group(1), m.group(3), m.group(5), m.group(6), m.group(8)
        if m.group(2).startswith("="):
            value = literal
        elif name and not shape:
            if name not in named:
                errors.append(f"#{name} used before it's defined")
                return ""
            value = named[name]
        else:
            try:
                value = filler.value(kind, (shape or "").strip())
            except ValueError as e:
                errors.append(str(e))
                return ""
            if name:
                named[name] = value
        out = encode(value, how)
        (secrets if kind == "S" else keeps).append(out)
        return out

    text = MARKER.sub(sub, template["text"])
    if "⟦" in text or "⟧" in text:
        errors.append("stray marker")
    secrets = [s for s in dict.fromkeys(secrets) if s]
    # A keep value that overlaps a secret can't both survive and be hidden: dropped.
    keeps = [k for k in dict.fromkeys(keeps) if k and not any(k in s or s in k for s in secrets)]
    for v in secrets + keeps:
        if v not in text:
            errors.append(f"label not in text: {v[:40]!r}")
    case = {"id": template["id"], "kind": template.get("context", "?"), "context": template.get("context", "?"), "text": text, "secrets": secrets, "keep": keeps}
    if template.get("hint"):
        case["hint"] = template["hint"]
    return case, errors


def main():
    args = sys.argv[1:]
    out = args[args.index("--out") + 1]
    seed = int(args[args.index("--seed") + 1]) if "--seed" in args else 20261009
    prefix = args[args.index("--prefix") + 1] if "--prefix" in args else ""
    files = [a for i, a in enumerate(args) if not a.startswith("--") and (i == 0 or args[i - 1] not in ("--out", "--seed", "--prefix"))]
    filler = Filler(seed)
    cases, bad, ids = [], 0, set()
    for path in files:
        for n, line in enumerate(open_text(path), 1):
            if not line.strip():
                continue
            try:
                t = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"{path}:{n}: not JSON ({e})", file=sys.stderr)
                bad += 1
                continue
            case, errors = fill(t, filler)
            if errors:
                print(f"{path}:{n} {t.get('id')}: " + "; ".join(errors[:3]), file=sys.stderr)
                bad += 1
                continue
            case["id"] = prefix + case["id"]
            if case["id"] in ids:
                case["id"] += f"-{n}"
            ids.add(case["id"])
            cases.append(case)
    with open_text(out, "w") as fh:
        for c in cases:
            # U+2028/2029 and U+0085 escaped, so line-based readers don't split a case.
            fh.write(json.dumps(c, ensure_ascii=False).replace("\u2028", "\\u2028").replace("\u2029", "\\u2029").replace("\u0085", "\\u0085") + "\n")
    secrets = sum(len(c["secrets"]) for c in cases)
    keeps = sum(len(c["keep"]) for c in cases)
    print(f"{len(cases)} cases ({bad} templates skipped), {secrets} secrets, {keeps} keep values, {len({c['context'] for c in cases})} contexts, {sum(not c['secrets'] for c in cases)} without secrets")


if __name__ == "__main__":
    main()
