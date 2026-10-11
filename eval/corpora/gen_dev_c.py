#!/usr/bin/env python3
"""Generate the dev_c evaluation corpus for the secret-redaction library.

Deterministic (seed 777), stdlib only.  Run with:

    python3 -I eval/corpora/gen_dev_c.py

Writes dev_c.jsonl.gz next to this file, same schema as dev.jsonl:
  {"id", "kind", "context", "text", "secrets", "keep", "secret_kinds", "hint"?}

Contexts: chat, app-log, stack-trace, jupyter, api-response, url, markdown,
agent-transcript, pem-key, token-output.

The value generators (vendor formats, passwords, hard negatives) are copied
verbatim from gen_dev.py so this file is self-contained and frozen.  All secret
material is produced by a seeded PRNG; none of it is a live credential.
"""
import base64
import collections
import datetime
import gzip
import hashlib
import io
import json
import os
import random
import string
import struct
import sys
import urllib.parse
import uuid
import zlib

SEED = 777
R = random.Random(SEED)
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dev_c.jsonl.gz")

# ===== copied verbatim from gen_dev.py (value generators + hard negatives) =====
# --------------------------------------------------------------------------- alphabets / primitives
DIG = string.digits
UP = string.ascii_uppercase
LO = string.ascii_lowercase
B62 = DIG + UP + LO
B64 = UP + LO + DIG + "+/"
B64U = UP + LO + DIG + "-_"
HEX = "0123456789abcdef"
HEXU = HEX.upper()
B32 = UP + "234567"
CROCK = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
LALNUM = LO + DIG
UALNUM = UP + DIG
BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
K8S = "bcdfghjklmnpqrstvwxz2456789"


def rs(alpha, n):
    return "".join(R.choice(alpha) for _ in range(n))


def rb(n):
    return bytes(R.getrandbits(8) for _ in range(n))


def pick(seq):
    return R.choice(seq)


def chance(p):
    return R.random() < p


def b64(b):
    return base64.b64encode(b).decode()


def b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def b64s(s):
    return b64(s.encode())


def enc(s):
    return urllib.parse.quote(s, safe="")


def wrapw(s, w):
    return "\n".join(s[i:i + w] for i in range(0, len(s), w))


def L(*lines):
    return "\n".join(lines)


def ind(text, n):
    pad = " " * n
    return "\n".join(pad + l if l else l for l in text.split("\n"))


def rtok(alpha, n):
    """Random token that actually looks random (mixed classes)."""
    has_digit = any(ch.isdigit() for ch in alpha)
    has_up = any(ch.isupper() for ch in alpha)
    has_lo = any(ch.islower() for ch in alpha)
    for _ in range(1000):
        s = rs(alpha, n)
        d = sum(ch.isdigit() for ch in s)
        if has_digit and d < 2:
            continue
        if has_up and has_lo and not (any(ch.isupper() for ch in s) and any(ch.islower() for ch in s)):
            continue
        if sum(ch.isalpha() for ch in s) < 3:
            continue
        return s
    return s


def b62num(n, w):
    s = ""
    while n:
        n, r = divmod(n, 62)
        s = B62[r] + s
    return s.rjust(w, "0")


# --------------------------------------------------------------------------- time / names
T0 = datetime.datetime(2025, 1, 6, tzinfo=datetime.timezone.utc)


def dt():
    return T0 + datetime.timedelta(seconds=R.randint(0, 640 * 86400))


def iso(d=None):
    return (d or dt()).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_ms(d=None):
    d = d or dt()
    return d.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % R.randint(0, 999)


def epoch(d=None):
    return int((d or dt()).timestamp())


def hhmmss():
    return "%02d:%02d:%02d" % (R.randint(0, 23), R.randint(0, 59), R.randint(0, 59))


WORDS = """amber anchor apple arrow aspen atlas autumn badger bamboo banjo basil beacon birch bison blossom
bramble breeze bronze cactus canyon carbon cedar cherry cinder citrus clover cobalt comet copper coral cosmic
cotton crane crimson crystal cypress dahlia desert dolphin dragon drift dune eagle ember emerald falcon fern
fiesta flint forest fossil frost galaxy garnet gecko ginger glacier granite grape gravel harbor hazel heron
hickory honey horizon indigo iris ivory jade jasper jungle juniper kayak kettle kiwi lagoon lantern lava lemon
lilac linen lotus lunar magnet mango maple marble meadow mesa meteor mint mocha monsoon mosaic nectar nimbus
nova nutmeg oasis obsidian ocean olive onyx opal orbit orchid otter oyster panda papaya pebble pepper pine
plasma plum polar poppy prairie prism pumpkin quartz quill radar raven reef ripple river robin ruby saffron
sage salmon sapphire sequoia sierra sparrow spruce squall summit sunset tango thistle thunder tiger timber
topaz tulip tundra velvet violet walnut willow zephyr zinc""".split()
SVC = ["billing", "orders", "auth", "search", "inventory", "notify", "ledger", "payments", "catalog", "gateway",
       "reports", "ingest", "users", "media", "scheduler", "checkout", "analytics", "webhooks", "profile", "export"]
DOMS = ["acme-corp.io", "example.com", "internal.lan", "corp.example.net", "northwind.dev", "contoso.cloud",
        "initech.io", "globex.app", "umbrella-labs.com", "hooli.xyz", "piedpiper.net", "stark-ind.com"]
USERS = ["admin", "deploy", "svc_billing", "app_user", "postgres", "root", "ci-bot", "jenkins", "grafana", "alice",
         "bob.nguyen", "m.okafor", "priya", "dkim", "svc-reporting", "readonly", "etl_writer", "webapp", "rabbit",
         "analytics_ro", "sa_ingest", "kfischer", "tvaldez"]
PEOPLE = ["priya", "dkim", "marcus", "jen", "tomás", "aiko", "sam", "lena", "olu", "raj", "chris", "mei",
          "noah", "fatima", "jo", "viktor"]
REGIONS = ["us-east-1", "us-east-2", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-2", "ap-northeast-1"]
GCP_REGIONS = ["us-central1", "europe-west1", "asia-east1", "us-east4"]
PROJECTS = ["orion", "atlas", "nebula", "hydra", "phoenix", "kraken", "zephyr", "mercury", "falcon", "tundra"]
ENVS = ["prod", "production", "staging", "stg", "dev", "qa", "sandbox"]
SEASONS = ["Summer", "Winter", "Spring", "Autumn", "Fall", "January", "March", "October", "Welcome", "Password",
           "Company", "Football", "Dragon", "Monkey", "Sunshine", "Letmein"]
SYMS = "!#?*@%&+=^~"


def dom():
    return pick(DOMS)


def svc():
    return pick(SVC)


def host():
    r = R.random()
    if r < 0.3:
        return "%s-db.%s" % (svc(), dom())
    if r < 0.5:
        return "%s-%s.c%s.%s.rds.amazonaws.com" % (svc(), pick(["prod", "stg"]), rs(LALNUM, 12), pick(REGIONS))
    if r < 0.65:
        return "%s.%s.svc.cluster.local" % (svc(), pick(["default", "prod", "data", "platform"]))
    if r < 0.8:
        return "10.%d.%d.%d" % (R.randint(0, 255), R.randint(0, 255), R.randint(2, 254))
    return "%s-%s.%s" % (svc(), pick(ENVS), dom())


def user():
    return pick(USERS)


def email(name=None):
    return "%s@%s" % (name or pick(PEOPLE).replace("á", "a"), dom())


def proj():
    return pick(PROJECTS) + pick(["", "-prod", "-staging", "-%d" % R.randint(100000, 999999)])


def version():
    return "%d.%d.%d" % (R.randint(0, 9), R.randint(0, 30), R.randint(0, 20))


def acct():
    return str(R.randint(100000000000, 999999999999))


# --------------------------------------------------------------------------- secret generators
def gh_token(prefix, checksum=None):
    """GitHub token: prefix + 30 base62 + 6-char base62 CRC32 checksum of the 30-char body."""
    if checksum is None:
        checksum = chance(0.6)
    body = rs(B62, 30)
    tail = b62num(zlib.crc32(body.encode()) & 0xFFFFFFFF, 6) if checksum else rs(B62, 6)
    return prefix + body + tail


def g_jwt(alg=None, payload=None):
    alg = alg or pick(["HS256", "HS256", "RS256", "ES256"])
    h = {"alg": alg, "typ": "JWT"}
    if alg != "HS256" and chance(0.7):
        h = {"alg": alg, "kid": rs(B64U, pick([16, 27, 43])), "typ": "JWT"}
    now = epoch()
    if payload is None:
        k = R.randint(0, 4)
        if k == 0:
            payload = {"iss": "https://%s.us.auth0.com/" % pick(PROJECTS), "sub": "auth0|" + rs(HEX, 24),
                       "aud": ["https://api.%s" % dom()], "iat": now, "exp": now + 86400,
                       "scope": "openid profile email offline_access"}
        elif k == 1:
            payload = {"iss": "supabase", "ref": rs(LO, 20), "role": pick(["service_role", "anon"]),
                       "iat": now, "exp": now + 10 * 365 * 86400}
        elif k == 2:
            ns = pick(["default", "kube-system", "ci", "monitoring"])
            payload = {"aud": ["https://kubernetes.default.svc.cluster.local"], "exp": now + 3600, "iat": now,
                       "iss": "https://kubernetes.default.svc.cluster.local",
                       "kubernetes.io": {"namespace": ns, "serviceaccount": {"name": pick(["deployer", "default", "argocd"]), "uid": n_uuid()}},
                       "nbf": now, "sub": "system:serviceaccount:%s:deployer" % ns}
        elif k == 3:
            payload = {"user_id": R.randint(1, 99999), "email": email(), "roles": pick([["admin"], ["user"], ["user", "billing"]]),
                       "iat": now, "exp": now + 900, "jti": n_uuid()}
        else:
            payload = {"sub": n_uuid(), "tenant": pick(PROJECTS), "scope": "read:orders write:orders", "iat": now,
                       "exp": now + 3600, "iss": "https://auth.%s" % dom()}
    sl = {"HS256": 32, "RS256": 256, "ES256": 64}[alg]
    seg = lambda o: b64u(json.dumps(o, separators=(",", ":")).encode())
    return seg(h) + "." + seg(payload) + "." + b64u(rb(sl))


def pw_human():
    w1, w2 = pick(WORDS).capitalize(), pick(WORDS).capitalize()
    k = R.randint(0, 5)
    n = R.randint(10, 99)
    s = pick(SYMS)
    if k == 0:
        return "%s-%s-%d%s" % (w1, w2, n, s)
    if k == 1:
        return "%s%d%s" % (w1, R.randint(100, 9999), s)
    if k == 2:
        return "%s%s%d" % (w1.lower(), w2, R.randint(1000, 9999))
    if k == 3:
        return "%s%s%s%d" % (w1, s, w2, n)
    if k == 4:
        return "%s.%s.%d" % (w1, w2.lower(), n)
    return "%s_%s%d%s" % (w1.lower(), w2.lower(), n, s)


def pw_season():
    return "%s%d%s" % (pick(SEASONS), pick([2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026, 123, 1, 99]), pick(["!", "!", "#", "?", "@", "", "!!"]))


def pw_random():
    a = UP + LO + DIG + "!#%*+-=?^_~@&.,:"
    for _ in range(100):
        s = rs(a, R.randint(12, 24))
        if any(c.isdigit() for c in s) and any(c in "!#%*+-=?^_~@&.,:" for c in s) and any(c.isupper() for c in s):
            return s
    return s


def passphrase():
    sep = pick([" ", "-", "-", ".", "_"])
    return sep.join(pick(WORDS) for _ in range(R.randint(4, 6)))


def any_password():
    return pick([pw_human, pw_human, pw_season, pw_random, pw_random, passphrase])()


def pem(label, der, width=64):
    return "-----BEGIN %s-----\n%s\n-----END %s-----" % (label, wrapw(b64(der), width), label)


def der_rsa_pkcs1():
    pre = bytes.fromhex("308204a40201000282010100")
    return pre + rb(1192 - len(pre))


def der_pkcs8():
    pre = bytes.fromhex("308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100")
    return pre + rb(1217 - len(pre))


def der_ec():
    return (bytes.fromhex("30770201010420") + rb(32) + bytes.fromhex("a00a06082a8648ce3d030107a144034200") +
            b"\x04" + rb(64))


def sstr(b):
    if isinstance(b, str):
        b = b.encode()
    return struct.pack(">I", len(b)) + b


def openssh_key(comment, rsa=False):
    """Returns (pem_text, body, public_line)."""
    if rsa:
        pubblob = sstr("ssh-rsa") + sstr(b"\x01\x00\x01") + sstr(b"\x00\xc1" + rb(383))
        chk = rb(4)
        priv = chk + chk + sstr("ssh-rsa") + rb(1500) + sstr(comment)
        kt = "ssh-rsa"
    else:
        pub, seed = rb(32), rb(32)
        pubblob = sstr("ssh-ed25519") + sstr(pub)
        chk = rb(4)
        priv = chk + chk + sstr("ssh-ed25519") + sstr(pub) + sstr(seed + pub) + sstr(comment)
        kt = "ssh-ed25519"
    i = 1
    while len(priv) % 8:
        priv += bytes([i])
        i += 1
    blob = (b"openssh-key-v1\x00" + sstr("none") + sstr("none") + sstr(b"") + struct.pack(">I", 1) +
            sstr(pubblob) + sstr(priv))
    body = wrapw(b64(blob), 70)
    text = "-----BEGIN OPENSSH PRIVATE KEY-----\n%s\n-----END OPENSSH PRIVATE KEY-----" % body
    return text, body, "%s %s %s" % (kt, b64(pubblob), comment)


def pgp_private():
    body = wrapw(b64(b"\x95\x05\x86\x04" + rb(R.randint(900, 1400))), 64)
    crc = "=" + b64(rb(3))
    text = ("-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n%s\n%s\n-----END PGP PRIVATE KEY BLOCK-----" % (body, crc))
    return text, body


def private_key_any():
    """Returns (full_pem, secret_body, kind)."""
    k = R.randint(0, 3)
    if k == 0:
        t = pem("RSA PRIVATE KEY", der_rsa_pkcs1())
        kind = "pem_rsa_private_key"
    elif k == 1:
        t = pem("PRIVATE KEY", der_pkcs8())
        kind = "pem_pkcs8_private_key"
    elif k == 2:
        t = pem("EC PRIVATE KEY", der_ec())
        kind = "pem_ec_private_key"
    else:
        t, body, _ = openssh_key(pick(PEOPLE) + "@" + pick(["laptop", "build-01", "bastion", "mbp"]))
        return t, body, "openssh_private_key"
    body = t.split("\n", 1)[1].rsplit("\n", 1)[0]
    return t, body, kind


def g_dburl(scheme=None, pw=None):
    scheme = scheme or pick(["postgres", "postgresql", "postgresql+asyncpg", "mysql", "mysql+pymysql", "mongodb",
                             "mongodb+srv", "redis", "rediss", "amqp", "amqps"])
    pw = pw or any_password().replace(" ", "-")
    pwe = enc(pw)
    u = user()
    h = host()
    keep = [h]
    if scheme.startswith("postgres"):
        url = "%s://%s:%s@%s:5432/%s" % (scheme, u, pwe, h, pick(["app", svc(), "postgres", svc() + "_prod"]))
    elif scheme.startswith("mysql"):
        url = "%s://%s:%s@%s:3306/%s" % (scheme, u, pwe, h, svc())
    elif scheme == "mongodb+srv":
        h = "cluster0.%s.mongodb.net" % rs(LALNUM, 5)
        keep = [h]
        url = "mongodb+srv://%s:%s@%s/%s?retryWrites=true&w=majority" % (u, pwe, h, svc())
    elif scheme == "mongodb":
        url = "mongodb://%s:%s@%s:27017/%s?authSource=admin" % (u, pwe, h, svc())
    elif scheme.startswith("redis"):
        u = "default"
        if chance(0.5):
            url = "%s://:%s@%s:6379/%d" % (scheme, pwe, h, R.randint(0, 3))
        else:
            url = "%s://default:%s@%s:6380/0" % (scheme, pwe, h)
    else:
        url = "%s://%s:%s@%s:5672/%s" % (scheme, u, pwe, h, pick(["%2F", "vhost", svc()]))
    if chance(0.5) and u not in ("default",):
        keep.append(u)
    return {"d": url, "s": [("url_password", pwe)], "k": keep}


def s3_presigned():
    bucket = "%s-%s-%s" % (pick(PROJECTS), pick(["uploads", "exports", "artifacts", "backups", "media"]), pick(ENVS))
    region = pick(REGIONS)
    key = "%s/%s/%s.%s" % (pick(["reports", "tmp", "u", "exports"]), n_uuid(), pick(["invoice", "dump", "avatar", "export"]),
                           pick(["pdf", "csv", "png", "tar.gz", "json"]))
    d = dt()
    ak = pick(["ASIA", "AKIA"]) + rs(UALNUM, 16)
    sig = rs(HEX, 64)
    secrets = [("s3_presigned_signature", sig)]
    tokpart = ""
    if ak.startswith("ASIA"):
        tok = "IQoJb3JpZ2luX2VjE" + rs(B64, R.randint(300, 520))
        tokpart = "&X-Amz-Security-Token=" + enc(tok)
        secrets.append(("aws_session_token", enc(tok)))
    url = ("https://%s.s3.%s.amazonaws.com/%s?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=%s%%2F%s%%2F%s%%2Fs3%%2Faws4_request"
           "&X-Amz-Date=%s&X-Amz-Expires=%d%s&X-Amz-SignedHeaders=host&X-Amz-Signature=%s") % (
        bucket, region, key, ak, d.strftime("%Y%m%d"), region, d.strftime("%Y%m%dT%H%M%SZ"),
        pick([300, 900, 3600, 604800]), tokpart, sig)
    return {"d": url, "s": secrets, "k": [bucket + ".s3." + region + ".amazonaws.com"]}


def gcs_signed():
    bucket = "%s-%s" % (pick(PROJECTS), pick(["assets", "exports", "ml-data"]))
    d = dt()
    sa = "%s@%s.iam.gserviceaccount.com" % (pick(["signer", "uploader", "svc-export"]), proj())
    sig = rs(HEX, 512)
    url = ("https://storage.googleapis.com/%s/%s?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Credential=%s%%2F%s%%2Fauto%%2Fstorage%%2Fgoog4_request"
           "&X-Goog-Date=%s&X-Goog-Expires=900&X-Goog-SignedHeaders=host&X-Goog-Signature=%s") % (
        bucket, "%s/%s.parquet" % (pick(["daily", "raw"]), d.strftime("%Y-%m-%d")), enc(sa), d.strftime("%Y%m%d"),
        d.strftime("%Y%m%dT%H%M%SZ"), sig)
    return {"d": url, "s": [("gcs_signed_url_signature", sig)], "k": [bucket]}


def azure_sas():
    acc = pick(PROJECTS).replace("-", "") + pick(["store", "blob", "data"]) + str(R.randint(1, 99))
    sig = enc(b64(rb(32)))
    se = dt()
    url = ("https://%s.blob.core.windows.net/%s/%s?sv=2022-11-02&ss=b&srt=co&sp=%s&se=%s&st=%s&spr=https&sig=%s") % (
        acc, pick(["uploads", "backups", "exports"]), pick(["data.csv", "dump.bak", "report.pdf"]), pick(["r", "rl", "racwdl"]),
        enc(iso(se)), enc(iso(se - datetime.timedelta(hours=1))), sig)
    return {"d": url, "s": [("azure_sas_signature", sig)], "k": [acc + ".blob.core.windows.net"]}


def azure_conn():
    acc = pick(PROJECTS).replace("-", "") + pick(["store", "sa", "logs"]) + str(R.randint(1, 99))
    key = b64(rb(64))
    s = "DefaultEndpointsProtocol=https;AccountName=%s;AccountKey=%s;EndpointSuffix=core.windows.net" % (acc, key)
    return {"d": s, "s": [("azure_storage_key", key)], "k": ["AccountName=" + acc]}


def slack_webhook():
    tok = rtok(B62, 24)
    return {"d": "https://hooks.slack.com/services/T%s/B%s/%s" % (rs(UALNUM, R.choice([8, 10])), rs(UALNUM, R.choice([8, 10, 11])), tok),
            "s": [("slack_webhook", tok)]}


def discord_webhook():
    tok = rtok(B64U, 68)
    return {"d": "https://discord.com/api/webhooks/%d/%s" % (R.randint(10 ** 17, 10 ** 19 - 1), tok), "s": [("discord_webhook", tok)]}


def teams_webhook():
    tok = rs(HEX, 32)
    org = pick(PROJECTS)
    url = "https://%s.webhook.office.com/webhookb2/%s@%s/IncomingWebhook/%s/%s" % (org, n_uuid(), n_uuid(), tok, n_uuid())
    if chance(0.5):
        url += "/V2" + rtok(B64U, 43)
    return {"d": url, "s": [("teams_webhook", tok)]}


def zapier_webhook():
    url = "https://hooks.zapier.com/hooks/catch/%d/%s/" % (R.randint(1000000, 29999999), rtok(LALNUM, 7))
    return {"d": url, "s": [("zapier_webhook", url)]}


def generic_webhook():
    tok = rtok(pick([B62, B64U, LALNUM]), R.randint(24, 48))
    url = pick(["https://hooks.%s/in/%s", "https://%s/api/v1/hooks/%s", "https://events.%s/ingest/%s",
                "https://%s/webhook/%s"]) % (dom(), tok)
    return {"d": url, "s": [("generic_webhook_token", tok)]}


def totp():
    seed = rs(B32, pick([16, 32, 32, 26]))
    return seed


# kind -> (generator, env names).  Generators return str or {"d": display, "s": [(kind, secret)], "k": [keep]}
V = {}


def vend(kind, names, fn):
    V[kind] = (fn, names)


vend("github_pat", ["GITHUB_TOKEN", "GH_TOKEN", "GITHUB_PAT", "HOMEBREW_GITHUB_API_TOKEN", "GH_ENTERPRISE_TOKEN"], lambda: gh_token("ghp_"))
vend("github_oauth", ["GITHUB_OAUTH_TOKEN", "GH_OAUTH_TOKEN"], lambda: gh_token("gho_"))
vend("github_app_token", ["GITHUB_APP_TOKEN", "GH_INSTALLATION_TOKEN"], lambda: gh_token("ghs_"))
vend("github_user_to_server", ["GITHUB_USER_TOKEN"], lambda: gh_token("ghu_"))
vend("github_fine_grained", ["GITHUB_TOKEN", "GH_PAT", "RENOVATE_TOKEN", "RELEASE_PLEASE_TOKEN"],
     lambda: "github_pat_" + rs(UALNUM, 2) + rs(B62, 20) + "_" + rs(B62, 59))
vend("gitlab_pat", ["GITLAB_TOKEN", "GITLAB_PRIVATE_TOKEN", "GL_TOKEN", "DANGER_GITLAB_API_TOKEN"], lambda: "glpat-" + rtok(B62 + "-_", 20))
vend("gitlab_runner_token", ["RUNNER_TOKEN", "CI_SERVER_TOKEN"], lambda: "glrt-" + rtok(B62 + "-_", 20))
vend("openai_key", ["OPENAI_API_KEY", "OPENAI_KEY"], lambda: pick([
    lambda: "sk-proj-" + rs(B64U, 74) + "T3BlbkFJ" + rs(B64U, 74),
    lambda: "sk-proj-" + rs(B64U, 58) + "T3BlbkFJ" + rs(B64U, 58),
    lambda: "sk-" + rs(B62, 20) + "T3BlbkFJ" + rs(B62, 20),
    lambda: "sk-svcacct-" + rs(B64U, 74) + "T3BlbkFJ" + rs(B64U, 74)])())
vend("anthropic_key", ["ANTHROPIC_API_KEY", "CLAUDE_API_KEY"], lambda: "sk-ant-api03-" + rs(B64U, 93) + "AA")
vend("anthropic_admin_key", ["ANTHROPIC_ADMIN_KEY"], lambda: "sk-ant-admin01-" + rs(B64U, 93) + "AA")
vend("stripe_secret_key", ["STRIPE_SECRET_KEY", "STRIPE_API_KEY", "STRIPE_SK"],
     lambda: pick(["sk_live_51" + rs(B62, 97), "sk_live_" + rtok(B62, 24)]))
vend("stripe_test_key", ["STRIPE_SECRET_KEY", "STRIPE_TEST_SECRET_KEY"], lambda: "sk_test_51" + rs(B62, 97))
vend("stripe_restricted_key", ["STRIPE_RESTRICTED_KEY", "STRIPE_RK"], lambda: "rk_live_51" + rs(B62, 97))
vend("stripe_webhook_secret", ["STRIPE_WEBHOOK_SECRET", "STRIPE_ENDPOINT_SECRET"], lambda: "whsec_" + rtok(B62, 32))
vend("slack_bot_token", ["SLACK_BOT_TOKEN", "SLACK_TOKEN"],
     lambda: "xoxb-%s-%s-%s" % (rs(DIG, 12), rs(DIG, 13), rtok(B62, 24)))
vend("slack_user_token", ["SLACK_USER_TOKEN"], lambda: "xoxp-%s-%s-%s-%s" % (rs(DIG, 12), rs(DIG, 12), rs(DIG, 13), rs(HEX, 32)))
vend("slack_app_token", ["SLACK_APP_TOKEN"], lambda: "xapp-1-A%s-%s-%s" % (rs(UALNUM, 10), rs(DIG, 13), rs(HEX, 64)))
vend("slack_webhook", ["SLACK_WEBHOOK_URL", "SLACK_WEBHOOK", "SLACK_ALERTS_URL"], slack_webhook)
vend("aws_access_key_id", ["AWS_ACCESS_KEY_ID"], lambda: "AKIA" + rs(B32, 16))
vend("aws_secret_access_key", ["AWS_SECRET_ACCESS_KEY"], lambda: rtok(B62 + "+/", 40))
vend("aws_session_token", ["AWS_SESSION_TOKEN"], lambda: "IQoJb3JpZ2luX2VjE" + rs(B64, R.randint(300, 600)))
vend("google_api_key", ["GOOGLE_API_KEY", "GOOGLE_MAPS_API_KEY", "GEMINI_API_KEY", "YOUTUBE_API_KEY", "GOOGLE_PLACES_KEY"],
     lambda: "AIza" + rs(B64U, 35))
vend("google_oauth_client_secret", ["GOOGLE_CLIENT_SECRET", "GOOGLE_OAUTH_CLIENT_SECRET"], lambda: "GOCSPX-" + rtok(B64U, 28))
vend("google_oauth_access_token", ["GOOGLE_ACCESS_TOKEN"], lambda: "ya29.a0" + rs(B64U, R.randint(150, 210)))
vend("google_refresh_token", ["GOOGLE_REFRESH_TOKEN"], lambda: "1//0" + rs(B64U, 99))
vend("twilio_api_key", ["TWILIO_API_KEY", "TWILIO_API_KEY_SID"], lambda: "SK" + rs(HEX, 32))
vend("twilio_auth_token", ["TWILIO_AUTH_TOKEN"], lambda: rs(HEX, 32))
vend("sendgrid_key", ["SENDGRID_API_KEY", "SG_API_KEY"], lambda: "SG." + rtok(B64U, 22) + "." + rtok(B64U, 43))
vend("mailgun_key", ["MAILGUN_API_KEY"], lambda: pick(["key-" + rs(HEX, 32), "%s-%s-%s" % (rs(HEX, 32), rs(HEX, 8), rs(HEX, 8))]))
vend("mailchimp_key", ["MAILCHIMP_API_KEY"], lambda: rs(HEX, 32) + "-us" + str(R.randint(1, 21)))
vend("npm_token", ["NPM_TOKEN", "NODE_AUTH_TOKEN"], lambda: "npm_" + rtok(B62, 36))
vend("pypi_token", ["PYPI_TOKEN", "TWINE_PASSWORD", "UV_PUBLISH_TOKEN", "PYPI_API_TOKEN"],
     lambda: "pypi-AgEIcHlwaS5vcmc" + rs(B64U, R.randint(150, 190)))
vend("docker_pat", ["DOCKERHUB_TOKEN", "DOCKER_PASSWORD", "DOCKER_HUB_PAT"], lambda: "dckr_pat_" + rtok(B64U, 27))
vend("huggingface_token", ["HF_TOKEN", "HUGGING_FACE_HUB_TOKEN", "HUGGINGFACEHUB_API_TOKEN"], lambda: "hf_" + rtok(UP + LO, 34))
vend("shopify_access_token", ["SHOPIFY_ACCESS_TOKEN", "SHOPIFY_ADMIN_API_TOKEN"], lambda: "shpat_" + rs(HEX, 32))
vend("shopify_shared_secret", ["SHOPIFY_API_SECRET", "SHOPIFY_WEBHOOK_SECRET"], lambda: "shpss_" + rs(HEX, 32))
vend("databricks_token", ["DATABRICKS_TOKEN"], lambda: "dapi" + rs(HEX, 32) + pick(["", "-2", "-3"]))
vend("datadog_api_key", ["DD_API_KEY", "DATADOG_API_KEY"], lambda: rs(HEX, 32))
vend("datadog_app_key", ["DD_APP_KEY", "DATADOG_APP_KEY", "DD_APPLICATION_KEY"], lambda: rs(HEX, 40))
vend("heroku_api_key", ["HEROKU_API_KEY"], lambda: pick([n_uuid(), "HRKU-AA" + rs(B64U, 58)]))
vend("azure_storage_key", ["AZURE_STORAGE_KEY", "AZURE_STORAGE_ACCOUNT_KEY", "STORAGE_ACCOUNT_KEY"], lambda: b64(rb(64)))
vend("azure_storage_conn", ["AZURE_STORAGE_CONNECTION_STRING", "AzureWebJobsStorage"], azure_conn)
vend("azure_client_secret", ["AZURE_CLIENT_SECRET", "ARM_CLIENT_SECRET"], lambda: rs(B62, 3) + "8Q~" + rs(B62 + "_.~-", 34))
vend("azure_sas", ["AZURE_SAS_URL", "BLOB_SAS_URL"], azure_sas)
vend("digitalocean_token", ["DIGITALOCEAN_TOKEN", "DIGITALOCEAN_ACCESS_TOKEN"], lambda: "dop_v1_" + rs(HEX, 64))
vend("cloudflare_api_token", ["CLOUDFLARE_API_TOKEN", "CF_API_TOKEN"], lambda: rtok(B64U, 40))
vend("linear_key", ["LINEAR_API_KEY"], lambda: "lin_api_" + rtok(B62, 40))
vend("notion_token", ["NOTION_TOKEN", "NOTION_API_KEY"], lambda: pick(["secret_" + rtok(B62, 43), "ntn_" + rs(DIG, 11) + rtok(B62, 35)]))
vend("atlassian_token", ["JIRA_API_TOKEN", "CONFLUENCE_API_TOKEN", "ATLASSIAN_API_TOKEN"],
     lambda: "ATATT3xFfGF0" + rs(B64U, 170) + "=" + rs(HEXU, 8))
vend("postman_key", ["POSTMAN_API_KEY"], lambda: "PMAK-%s-%s" % (rs(HEX, 24), rs(HEX, 34)))
vend("grafana_sa_token", ["GRAFANA_TOKEN", "GRAFANA_SERVICE_ACCOUNT_TOKEN"], lambda: "glsa_" + rtok(B62, 32) + "_" + rs(HEX, 8))
vend("terraform_cloud_token", ["TFE_TOKEN", "TF_TOKEN_app_terraform_io", "ATLAS_TOKEN"], lambda: rtok(B62, 14) + ".atlasv1." + rtok(B62, 67))
vend("vault_token", ["VAULT_TOKEN"], lambda: "hvs." + rtok(B62 + "_-", 90))
vend("telegram_bot_token", ["TELEGRAM_BOT_TOKEN", "TG_BOT_TOKEN"], lambda: "%d:AA%s" % (R.randint(10 ** 9, 8 * 10 ** 9), rtok(B64U, 33)))
vend("newrelic_key", ["NEW_RELIC_API_KEY", "NEW_RELIC_USER_KEY"], lambda: "NRAK-" + rs(UALNUM, 27))
vend("groq_key", ["GROQ_API_KEY"], lambda: "gsk_" + rtok(B62, 52))
vend("replicate_token", ["REPLICATE_API_TOKEN"], lambda: "r8_" + rtok(B62, 37))
vend("perplexity_key", ["PERPLEXITY_API_KEY", "PPLX_API_KEY"], lambda: "pplx-" + rtok(B62, 48))
vend("xai_key", ["XAI_API_KEY", "GROK_API_KEY"], lambda: "xai-" + rtok(B62, 80))
vend("pulumi_token", ["PULUMI_ACCESS_TOKEN"], lambda: "pul-" + rs(HEX, 40))
vend("doppler_token", ["DOPPLER_TOKEN"], lambda: "dp.st.%s.%s" % (pick(["prd", "dev", "stg"]), rtok(B62, 40)))
vend("age_secret_key", ["SOPS_AGE_KEY"], lambda: "AGE-SECRET-KEY-1" + rs(BECH32, 58).upper())
vend("square_token", ["SQUARE_ACCESS_TOKEN"], lambda: "EAAA" + rtok(B64U, 60))
vend("bitbucket_app_password", ["BITBUCKET_APP_PASSWORD", "BITBUCKET_TOKEN"], lambda: "ATBB" + rtok(B62, 32) + rs(HEXU, 8))
vend("discord_bot_token", ["DISCORD_BOT_TOKEN", "DISCORD_TOKEN"],
     lambda: b64(str(R.randint(10 ** 17, 10 ** 18)).encode()).rstrip("=") + "." + rtok(B64U, 6) + "." + rtok(B64U, 38))
vend("discord_webhook", ["DISCORD_WEBHOOK_URL"], discord_webhook)
vend("teams_webhook", ["TEAMS_WEBHOOK_URL", "MS_TEAMS_WEBHOOK"], teams_webhook)
vend("zapier_webhook", ["ZAPIER_HOOK_URL", "ZAPIER_WEBHOOK"], zapier_webhook)
vend("resend_key", ["RESEND_API_KEY"], lambda: "re_" + rtok(B62, 8) + "_" + rtok(B62, 24))
vend("sentry_auth_token", ["SENTRY_AUTH_TOKEN"], lambda: "sntryu_" + rs(HEX, 64))
vend("okta_token", ["OKTA_API_TOKEN", "OKTA_TOKEN"], lambda: "00" + rtok(B64U, 40))
vend("airtable_pat", ["AIRTABLE_API_KEY", "AIRTABLE_TOKEN"], lambda: "pat" + rtok(B62, 14) + "." + rs(HEX, 64))
vend("figma_token", ["FIGMA_TOKEN", "FIGMA_ACCESS_TOKEN"], lambda: "figd_" + rtok(B64U, 40))
vend("netlify_token", ["NETLIFY_AUTH_TOKEN"], lambda: "nfp_" + rtok(B62, 36))
vend("facebook_token", ["FB_ACCESS_TOKEN", "META_ACCESS_TOKEN", "WHATSAPP_TOKEN"], lambda: "EAAG" + rtok(B62, R.randint(160, 200)))
vend("jwt", ["JWT", "ACCESS_TOKEN", "ID_TOKEN", "SUPABASE_SERVICE_ROLE_KEY", "AUTH_TOKEN", "BEARER_TOKEN"], g_jwt)
vend("fcm_server_key", ["FCM_SERVER_KEY"], lambda: "AAAA" + rtok(B64U, 7) + ":APA91b" + rtok(B64U, 134))
vend("rails_master_key", ["RAILS_MASTER_KEY"], lambda: rs(HEX, 32))
vend("django_secret_key", ["DJANGO_SECRET_KEY", "SECRET_KEY"],
     lambda: pick(["django-insecure-", ""]) + rs(LO + DIG + "!@#%^&*(-_=+)", 50))
vend("laravel_app_key", ["APP_KEY"], lambda: "base64:" + b64(rb(32)))
vend("db_url", ["DATABASE_URL", "POSTGRES_URL", "DB_URL", "SQLALCHEMY_DATABASE_URI", "MYSQL_URL"],
     lambda: g_dburl(pick(["postgres", "postgresql", "postgresql+asyncpg", "mysql", "mysql+pymysql"])))
vend("redis_url", ["REDIS_URL", "CACHE_URL"], lambda: g_dburl(pick(["redis", "rediss"])))
vend("amqp_url", ["RABBITMQ_URL", "CELERY_BROKER_URL", "AMQP_URL"], lambda: g_dburl(pick(["amqp", "amqps"])))
vend("mongodb_uri", ["MONGODB_URI", "MONGO_URL"], lambda: g_dburl(pick(["mongodb", "mongodb+srv"])))
vend("totp_seed", ["TOTP_SECRET", "MFA_SEED", "OTP_SECRET", "TWO_FACTOR_SECRET"], totp)
vend("s3_presigned_url", ["EXPORT_URL", "DOWNLOAD_URL", "ARTIFACT_URL"], s3_presigned)

GENERIC = {
    "generic_b62": lambda: rtok(B62, R.choice([16, 20, 24, 24, 32, 32, 32, 40, 48, 64])),
    "generic_hex": lambda: rtok(HEX, R.choice([32, 32, 40, 48, 64, 64])),
    "generic_b64": lambda: b64(rb(R.choice([24, 32, 32, 48, 64]))),
    "generic_b64url": lambda: b64u(rb(R.choice([16, 24, 32, 32, 48, 66]))),
    "generic_lower": lambda: rtok(LALNUM, R.randint(20, 40)),
}
PASSWORDS = {
    "password_human": pw_human,
    "password_seasonal": pw_season,
    "password_random": pw_random,
    "passphrase": passphrase,
}
GENERIC_CRED_NAMES = ["API_KEY", "SECRET_KEY", "APP_SECRET", "AUTH_TOKEN", "ACCESS_TOKEN", "CLIENT_SECRET", "SIGNING_KEY",
                      "ENCRYPTION_KEY", "JWT_SECRET", "SESSION_SECRET", "HMAC_SECRET", "WEBHOOK_SECRET", "MASTER_KEY",
                      "PRIVATE_TOKEN", "INTERNAL_API_KEY", "SERVICE_TOKEN", "REFRESH_TOKEN", "COOKIE_SECRET",
                      "NEXTAUTH_SECRET", "PARTNER_API_KEY", "MAPBOX_SECRET", "ALGOLIA_ADMIN_KEY", "SEGMENT_WRITE_KEY",
                      "MISTRAL_API_KEY", "COHERE_API_KEY", "PINECONE_API_KEY", "VERCEL_TOKEN", "CIRCLECI_TOKEN",
                      "SONAR_TOKEN", "CODECOV_TOKEN", "BUILDKITE_AGENT_TOKEN", "ENCRYPTION_PASSPHRASE_KEY"]
GENERIC_NEUTRAL_NAMES = ["LUMEN_VALUE", "ENDPOINT_AUTH", "RELAY_DATA", "UPSTREAM_CREDS", "ORBIT_SIG", "BOOTSTRAP_MATERIAL",
                         "HANDSHAKE_BLOB", "PASS_THROUGH", "BRIDGE_AUTH", "FEED_ACCESS", "X_MAGIC", "INGEST_AUTH",
                         "SYNC_SEED", "EDGE_CREDS", "HOOK_SIG", "TENANT_MATERIAL", "LICENSE_BLOB", "GATEWAY_PASS",
                         "UPLINK", "VENDOR_AUTH"]
PASSWORD_NAMES = ["DB_PASSWORD", "POSTGRES_PASSWORD", "MYSQL_ROOT_PASSWORD", "MYSQL_PASSWORD", "REDIS_PASSWORD",
                  "ADMIN_PASSWORD", "SMTP_PASSWORD", "PGPASSWORD", "RABBITMQ_DEFAULT_PASS", "KEYSTORE_PASSWORD",
                  "LDAP_BIND_PASSWORD", "MONGO_INITDB_ROOT_PASSWORD", "ELASTIC_PASSWORD", "GF_SECURITY_ADMIN_PASSWORD",
                  "MAIL_PASSWORD", "SA_PASSWORD", "BASIC_AUTH_PASS", "KAFKA_SASL_PASSWORD", "SFTP_PASS"]

GEN = {}
for _k, (_f, _n) in V.items():
    GEN[_k] = _f
GEN.update(GENERIC)
GEN.update(PASSWORDS)
VENDOR_KINDS = sorted(V)
GENERIC_KINDS = sorted(GENERIC)
PASSWORD_KINDS = sorted(PASSWORDS)
URLISH = {"slack_webhook", "discord_webhook", "teams_webhook", "zapier_webhook", "azure_sas", "db_url", "redis_url",
          "amqp_url", "mongodb_uri", "s3_presigned_url", "azure_storage_conn"}


def pick_kind(generic=0.40, password=0.12, allow_url=True):
    r = R.random()
    if r < generic:
        return pick(GENERIC_KINDS)
    if r < generic + password:
        return pick(PASSWORD_KINDS)
    while True:
        k = pick(VENDOR_KINDS)
        if allow_url or k not in URLISH:
            return k


def env_name(kind, neutral_p=0.45):
    if kind in V:
        return pick(V[kind][1])
    if kind in GENERIC:
        return pick(GENERIC_NEUTRAL_NAMES) if chance(neutral_p) else pick(GENERIC_CRED_NAMES)
    if kind in PASSWORDS:
        return pick(PASSWORD_NAMES)
    return "SECRET"


def snake(name):
    return name.lower()


def camel(name):
    parts = name.lower().split("_")
    return parts[0] + "".join(p.capitalize() for p in parts[1:])


def pascal(name):
    return "".join(p.capitalize() for p in name.lower().split("_"))


def kebab(name):
    return name.lower().replace("_", "-")


# --------------------------------------------------------------------------- negative (keep) generators
def n_git_sha():
    return hashlib.sha1(rb(40)).hexdigest()


def n_short_sha():
    return n_git_sha()[:pick([7, 7, 8, 10, 12])]


def n_sha256():
    return hashlib.sha256(rb(40)).hexdigest()


def n_docker_digest():
    return "sha256:" + n_sha256()


def n_npm_integrity():
    return "sha512-" + b64(rb(64))


def n_gosum():
    return "h1:" + b64(rb(32))


def n_uuid():
    return str(uuid.UUID(int=R.getrandbits(128), version=4))


def n_ulid():
    t = int(dt().timestamp() * 1000)
    s = ""
    for _ in range(10):
        s = CROCK[t % 32] + s
        t //= 32
    return s + rs(CROCK, 16)


def n_ksuid():
    return pick("23") + rs(B62, 26)


def n_nanoid():
    return rtok(B64U, 21)


def n_objectid():
    return "%08x" % epoch() + rs(HEX, 16)


def n_trace():
    return rs(HEX, 32)


def n_span():
    return rs(HEX, 16)


def n_traceparent():
    return "00-%s-%s-01" % (n_trace(), n_span())


def n_xray():
    return "Root=1-%08x-%s" % (epoch(), rs(HEX, 24))


def n_req_id():
    return pick([lambda: "req_" + rtok(B62, 14), n_uuid, lambda: rs(HEXU, 8) + ":" + rs(HEXU, 4) + ":" + rs(HEXU, 6),
                 lambda: rs(UALNUM, 16) + "-" + rs(UALNUM, 4), n_ulid])()


def n_etag():
    return pick(['"%s"' % rs(HEX, 32), 'W/"%x-%s"' % (R.randint(200, 90000), rs(B64U, 27)), '"%s"' % rs(HEX, 40)])


def n_cursor():
    return b64(json.dumps({"id": R.randint(1000, 9999999), "created_at": iso()}, separators=(",", ":")).encode()).rstrip("=")


def n_stripe_obj():
    p = pick(["cus_", "pi_", "ch_", "in_", "sub_", "price_", "prod_", "evt_", "pm_", "txn_", "seti_", "acct_", "cs_live_a1"])
    return p + rtok(B62, 14 if p in ("cus_", "prod_", "sub_", "acct_") else 24)


def n_stripe_pk():
    return pick(["pk_live_51", "pk_test_51"]) + rs(B62, 97)


def n_anth_id():
    return pick(["msg_01", "toolu_01", "msgbatch_01", "srvtoolu_01"]) + rtok(B62, 22)


def n_openai_id():
    p, n = pick([("chatcmpl-", 29), ("call_", 24), ("file-", 22), ("asst_", 24), ("thread_", 24), ("run_", 24),
                 ("batch_", 32), ("ft:gpt-4o-mini-2024-07-18:%s::" % pick(PROJECTS), 8)])
    return p + rtok(B62, n)


def n_aws_res():
    return pick(["i-0", "vol-0", "eni-0", "subnet-0", "vpc-0", "sg-0", "ami-0", "snap-0", "rtb-0", "igw-0", "nat-0"]) + rs(HEX, 16)


def n_arn():
    a = acct()
    r = pick(REGIONS)
    return pick([
        "arn:aws:iam::%s:role/%s-%s-role" % (a, svc(), pick(ENVS)),
        "arn:aws:s3:::%s-%s" % (pick(PROJECTS), pick(["logs", "assets", "tfstate"])),
        "arn:aws:lambda:%s:%s:function:%s-handler" % (r, a, svc()),
        "arn:aws:secretsmanager:%s:%s:secret:%s/%s/db-%s" % (r, a, pick(ENVS), svc(), rs(B62, 6)),
        "arn:aws:kms:%s:%s:key/%s" % (r, a, n_uuid()),
        "arn:aws:sqs:%s:%s:%s-queue" % (r, a, svc()),
        "arn:aws:ecs:%s:%s:task/%s-cluster/%s" % (r, a, pick(PROJECTS), rs(HEX, 32)),
    ])


def n_pod():
    return "%s-%s-%s-%s" % (svc(), pick(["api", "worker", "web", "consumer", "cron"]), rs(K8S, pick([9, 10])), rs(K8S, 5))


def n_chunk():
    return pick([lambda: "main.%s.js" % rs(HEX, 8), lambda: "%d.%s.chunk.js" % (R.randint(1, 999), rs(HEX, 20)),
                 lambda: "vendors~main.%s.chunk.js" % rs(HEX, 8), lambda: "index-%s.js" % rtok(B64U, 8),
                 lambda: "app.%s.css" % rs(HEX, 20), lambda: "_next/static/chunks/pages/_app-%s.js" % rs(HEX, 16),
                 lambda: "runtime.%s.bundle.js" % rs(HEX, 20)])()


def n_cssmod():
    return "%s_%s__%s" % (pick(["Button", "Card", "Header", "Modal", "Nav", "Sidebar", "Table"]),
                          pick(["root", "primary", "active", "title", "wrapper", "row"]), rtok(B64U, 5))


def n_data_uri():
    return "data:image/png;base64," + b64(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + rb(R.randint(40, 140)))


def n_ssh_pub():
    if chance(0.6):
        return "ssh-ed25519 " + b64(sstr("ssh-ed25519") + sstr(rb(32))) + " " + email()
    return "ssh-rsa " + b64(sstr("ssh-rsa") + sstr(b"\x01\x00\x01") + sstr(b"\x00\xc1" + rb(383))) + " " + email()


def n_cert():
    pre = bytes.fromhex("308203c5308202ada003020102021412")
    return pem("CERTIFICATE", pre + rb(969 - len(pre)))


def n_pubkey():
    der = bytes.fromhex("30820122300d06092a864886f70d01010105000382010f003082010a0282010100") + rb(256) + bytes.fromhex("0203010001")
    return pem("PUBLIC KEY", der)


PLACEHOLDERS = ["sk-...", "your-api-key-here", "xxxxxxxxxxxxxxxxxxxxxxxx", "<API_KEY>", "${API_KEY}",
                "{{ secrets.OPENAI_API_KEY }}", "process.env.STRIPE_SECRET_KEY", 'os.environ["GITHUB_TOKEN"]',
                "changeme", "REPLACE_ME", "<your-token>", "sk_test\x5fXXXXXXXXXXXXXXXXXXXXXXXX",
                "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "AKIAXXXXXXXXXXXXXXXX", "********", "[REDACTED]",
                "$(cat /run/secrets/db_password)", "${{ secrets.NPM_TOKEN }}", "{{ .Values.apiKey }}", "<password>",
                "your_password_here", "YOUR_SECRET_KEY", "sk-ant-xxxxx", "<redacted>", "${DB_PASSWORD}",
                "$SLACK_BOT_TOKEN", "%(DB_PASSWORD)s", "env(DATABASE_URL)", "TODO", "dummy-token", "<insert-key>",
                "ENC[AES256_GCM,data:...,type:str]", "!vault |", "${{ secrets.GITHUB_TOKEN }}", "op://Engineering/Stripe/credential"]
AWS_EXAMPLES = ["AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "AKIAI44QH8DHBEXAMPLE",
                "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY"]


def n_placeholder():
    return pick(PLACEHOLDERS)


def n_google_client_id():
    return "%d-%s.apps.googleusercontent.com" % (R.randint(10 ** 11, 10 ** 12 - 1), rs(LALNUM, 32))


def n_sri():
    return "sha384-" + b64(rb(48))


def n_slack_id():
    return pick(["C0", "U0", "T0", "D0"]) + rs(UALNUM, pick([8, 9, 10]))


NEG = {
    "git_sha": n_git_sha, "short_sha": n_short_sha, "sha256": n_sha256, "docker_digest": n_docker_digest,
    "npm_integrity": n_npm_integrity, "gosum": n_gosum, "uuid": n_uuid, "ulid": n_ulid, "ksuid": n_ksuid,
    "nanoid": n_nanoid, "objectid": n_objectid, "trace_id": n_trace, "span_id": n_span, "request_id": n_req_id,
    "etag": n_etag, "cursor": n_cursor, "stripe_obj": n_stripe_obj, "stripe_pk": n_stripe_pk, "anth_id": n_anth_id,
    "openai_id": n_openai_id, "aws_res": n_aws_res, "arn": n_arn, "pod": n_pod, "chunk": n_chunk, "cssmod": n_cssmod,
    "data_uri": n_data_uri, "ssh_pub": n_ssh_pub, "cert": n_cert, "pubkey": n_pubkey, "placeholder": n_placeholder,
    "aws_example": lambda: pick(AWS_EXAMPLES), "google_client_id": n_google_client_id, "sri": n_sri,
    "traceparent": n_traceparent, "xray": n_xray, "slack_id": n_slack_id, "version": version,
}
ID_NEGS = ["git_sha", "short_sha", "sha256", "docker_digest", "uuid", "ulid", "ksuid", "nanoid", "objectid", "trace_id",
           "span_id", "request_id", "stripe_obj", "anth_id", "openai_id", "aws_res", "arn", "pod", "etag", "cursor"]


def env_secret(c, kind=None, allow_url=True, quote=None, keep_name_p=0.35):
    kind = kind or pick_kind(allow_url=allow_url)
    name = env_name(kind)
    v = c.S(kind)
    if chance(keep_name_p):
        c.K(name)
    return name, v


def env_neg(c):
    """Return (NAME, value) for a realistic non-secret env var; records keep values."""
    k = R.randint(0, 33)
    if k == 0:
        return pick(["GIT_COMMIT", "GITHUB_SHA", "CI_COMMIT_SHA", "SOURCE_VERSION", "COMMIT_SHA"]), c.N("git_sha")
    if k == 1:
        return pick(["BUILD_ID", "DEPLOYMENT_ID", "RELEASE_ID", "INSTANCE_ID"]), c.N("uuid")
    if k == 2:
        return pick(["IMAGE_DIGEST", "BASE_IMAGE_DIGEST"]), c.N("docker_digest")
    if k == 3:
        return "PASSWORD_MIN_LENGTH", c.K(str(pick([8, 10, 12, 14, 16])))
    if k == 4:
        n = pick(["TOKEN_URL", "OAUTH_TOKEN_URL", "TOKEN_ENDPOINT", "JWKS_URL", "AUTH_URL"])
        return n, c.K("https://%s/oauth2/%s" % (pick(["auth.", "login.", "sso.", "id."]) + dom(), pick(["token", "v1/token", "jwks.json", "authorize"])))
    if k == 5:
        return pick(["AWS_REGION", "AWS_DEFAULT_REGION"]), pick(REGIONS)
    if k == 6:
        return "AWS_ACCOUNT_ID", c.K(acct())
    if k == 7:
        return pick(["GOOGLE_CLIENT_ID", "OAUTH_CLIENT_ID"]), c.N("google_client_id")
    if k == 8:
        return pick(["STRIPE_PUBLISHABLE_KEY", "NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY", "VITE_STRIPE_PK"]), c.N("stripe_pk")
    if k == 9:
        return pick(["SENTRY_RELEASE", "APP_VERSION", "VERSION"]), c.K(version())
    if k == 10:
        return pick(["PRIVATE_KEY_PATH", "JWT_PRIVATE_KEY_FILE", "TLS_KEY_FILE", "SSL_KEY_PATH"]), c.K(
            pick(["/run/secrets/jwt.key", "/etc/ssl/private/server.key", "/var/run/keys/signing.pem", "./certs/dev-key.pem"]))
    if k == 11:
        return pick(["DB_PASSWORD_FILE", "POSTGRES_PASSWORD_FILE", "PASSWORD_FILE"]), c.K("/run/secrets/" + pick(["db_password", "pg_pass", "postgres-password"]))
    if k == 12:
        return pick(["DB_SECRET_ARN", "SECRET_ARN"]), c.K(pick([n_arn() for _ in range(1)]))
    if k == 13:
        return "VAULT_ADDR", c.K("https://vault.%s:8200" % dom())
    if k == 14:
        return pick(["TOKEN_TTL", "TOKEN_EXPIRY_SECONDS", "SESSION_TTL", "JWT_EXPIRES_IN"]), pick(["3600", "900", "86400", "15m", "7d"])
    if k == 15:
        return pick(["SESSION_COOKIE_NAME", "AUTH_HEADER", "API_KEY_HEADER", "CSRF_HEADER_NAME"]), c.K(pick(["sessionid", "X-API-Key", "Authorization", "X-CSRF-Token", "__Host-sid"]))
    if k == 16:
        return pick(["DB_HOST", "DATABASE_HOST", "PGHOST", "REDIS_HOST"]), c.K(host())
    if k == 17:
        return pick(["DB_USER", "PGUSER", "DATABASE_USER", "MYSQL_USER"]), c.K(user())
    if k == 18:
        return pick(["HOSTNAME", "POD_NAME"]), c.N("pod")
    if k == 19:
        return pick(["REQUEST_ID", "TRACE_ID", "OTEL_TRACE_ID"]), c.N("trace_id")
    if k == 20:
        return pick(["NODE_VERSION", "PYTHON_VERSION", "GOLANG_VERSION", "RUBY_VERSION"]), c.K(version())
    if k == 21:
        n = pick(["OPENAI_API_KEY", "STRIPE_SECRET_KEY", "GITHUB_TOKEN", "API_KEY", "SECRET_KEY"])
        return n, c.N("placeholder")
    if k == 22:
        return pick(["KMS_KEY_ID", "SOPS_KMS_ARN"]), c.K("arn:aws:kms:%s:%s:key/%s" % (pick(REGIONS), acct(), n_uuid()))
    if k == 23:
        return pick(["SECRET_NAME", "SECRETS_PATH", "VAULT_PATH"]), c.K(pick(["prod/%s/credentials" % svc(), "secret/data/%s/%s" % (pick(ENVS), svc()), "kv/%s" % svc()]))
    if k == 24:
        return pick(["CACHE_KEY_PREFIX", "REDIS_KEY_PREFIX"]), c.K(pick(["v3:sessions:", "app:%s:" % svc(), "rl:" + svc()]))
    if k == 25:
        return pick(["PUBLIC_KEY", "JWT_PUBLIC_KEY_ID", "KEY_ID"]), c.K(pick(["kid-" + rs(HEX, 8), n_uuid(), "2025-" + rs(DIG, 2)]))
    if k == 26:
        return pick(["MAX_LOGIN_ATTEMPTS", "PASSWORD_HASH_ROUNDS", "BCRYPT_ROUNDS", "TOKEN_LENGTH"]), str(pick([5, 10, 12, 32]))
    if k == 27:
        return pick(["CI_PIPELINE_ID", "GITHUB_RUN_ID", "BUILD_NUMBER"]), c.K(str(R.randint(1000000, 9999999999)))
    if k == 28:
        return pick(["SENTRY_DSN_PUBLIC_HOST", "OTEL_EXPORTER_OTLP_ENDPOINT", "API_BASE_URL"]), c.K("https://%s.%s" % (pick(["otel", "api", "ingest"]), dom()))
    if k == 29:
        return pick(["CLIENT_ID", "AZURE_CLIENT_ID", "ARM_TENANT_ID", "AZURE_SUBSCRIPTION_ID"]), c.N("uuid")
    if k == 30:
        return pick(["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]), c.N("aws_example")
    if k == 31:
        return "GIT_SHORT_SHA", c.N("short_sha")
    if k == 32:
        return pick(["LOCKFILE_HASH", "CACHE_KEY"]), c.K("%s-%s" % (pick(["node-modules", "pip", "gradle"]), n_sha256()))
    return pick(["S3_BUCKET", "BUCKET_NAME", "GCS_BUCKET"]), c.K("%s-%s-%s" % (pick(PROJECTS), pick(["uploads", "assets"]), pick(ENVS)))


BASE_ENV = [
    lambda: "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    lambda: "HOME=/" + pick(["root", "home/app", "home/node", "home/runner"]),
    lambda: "LANG=" + pick(["C.UTF-8", "en_US.UTF-8"]),
    lambda: "TERM=" + pick(["xterm", "xterm-256color"]),
    lambda: "SHLVL=1",
    lambda: "PWD=/" + pick(["app", "srv/app", "workspace", "usr/src/app"]),
    lambda: "TZ=" + pick(["UTC", "Europe/Berlin", "America/New_York"]),
    lambda: "NODE_ENV=" + pick(["production", "development"]),
    lambda: "PYTHONUNBUFFERED=1",
    lambda: "LOG_LEVEL=" + pick(["info", "debug", "warn"]),
    lambda: "PORT=" + str(pick([3000, 8000, 8080, 5000])),
    lambda: "KUBERNETES_SERVICE_HOST=10.%d.0.1" % R.randint(0, 200),
    lambda: "KUBERNETES_SERVICE_PORT=443",
    lambda: "GOMAXPROCS=%d" % pick([2, 4, 8]),
    lambda: "_=/usr/bin/env",
    lambda: "USER=" + pick(["app", "node", "root", "runner"]),
    lambda: "SHELL=/bin/" + pick(["bash", "zsh", "sh"]),
    lambda: "APP_ENV=" + pick(ENVS),
    lambda: "FEATURE_FLAGS=" + ",".join(R.sample(["new_checkout", "dark_mode", "beta_api", "async_export", "v2_search"], 2)),
]


def base_env_lines(n):
    fs = R.sample(BASE_ENV, n)
    return [f() for f in fs]



# ======================================================================= dev_c: extra generators / hard negatives
def toolu_id():
    return "toolu_01" + rtok(B62, 22)


def msg_id():
    return "msg_01" + rtok(B62, 22)


def call_id():
    return "call_" + rtok(B62, 24)


def chatcmpl_id():
    return "chatcmpl-" + rtok(B62, 29)


def fc_id():
    return "fc_" + rs(HEX, 48)


def n_pw_policy():
    n = pick([8, 10, 12, 14, 16])
    return pick([
        "Passwords must be at least %d characters long and contain one uppercase letter, one number and one symbol." % n,
        "Your password must be %d-%d characters and cannot reuse any of your last %d passwords." % (n, pick([64, 72, 128]), pick([3, 5, 10])),
        "Password requirements: minimum %d characters, at least %d character classes, no dictionary words." % (n, pick([3, 4])),
        "Passwords expire every %d days; API tokens must be rotated every %d days." % (pick([60, 90, 180]), pick([30, 90])),
        "Use a passphrase of at least %d random words instead of a short password." % pick([4, 5, 6]),
        "Passwords are hashed with bcrypt (cost %d) and never logged." % pick([10, 12, 14]),
        "After %d failed login attempts the account is locked for %d minutes." % (pick([5, 10]), pick([15, 30])),
        "Password must not contain your username or email address.",
        "Admin accounts require a %d+ character password and hardware 2FA." % n,
    ])


# (A published example's vendor prefix is escaped, `"ey\x4a…"`, so this source isn't taken for a live key.)
JWT_IO_EXAMPLE = ("ey\x4ahbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
                  "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")


def n_example_key():
    k = R.randint(0, 6)
    if k == 0:
        return pick(AWS_EXAMPLES)
    if k == 1:
        return JWT_IO_EXAMPLE
    if k == 2:
        p = pick(["sk-proj-", "ghp_", "sk_live_", "glpat-", "hf_", "npm_", "sk-ant-api03-", "xoxb-", "AIza"])
        return p + pick(["EXAMPLE", "EXAMPLEKEY", "YOUR_KEY_HERE_", "XXXX"]) + pick(["x", "0", "X"]) * R.randint(8, 24)
    if k == 3:
        return pick(["0123456789abcdef0123456789abcdef", "1234567890abcdef1234567890abcdef", "abcdef0123456789abcdef0123456789",
                     "deadbeefdeadbeefdeadbeefdeadbeef", "00000000000000000000000000000000"])
    if k == 4:
        return pick(["your-32-character-secret-key-here", "my-super-secret-key", "supersecret", "s3cr3t-example-value",
                     "this-is-not-a-real-secret", "insecure-dev-only-key"])
    if k == 5:
        return pick(["AKIA" + "X" * 16, "xoxb-000000000000-0000000000000-" + "x" * 24, "sk_test_" + "x" * 24,
                     "ghp_" + "0" * 36, "sk-ant-api03-" + "x" * 20])
    return pick(["xox\x62-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx", "sk-1234567890abcdef1234567890abcdef",
                 "ghp_1234567890abcdefghijklmnopqrstuvwxyz", "AIzaSyDUMMY-KEY-FOR-DOCS-0000000000000"])


def n_data_uri2():
    k = R.randint(0, 3)
    if k == 0:
        return n_data_uri()
    if k == 1:
        svg = '<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="20"><rect width="%d" height="20" fill="#%s"/></svg>' % (
            R.randint(60, 120), R.randint(30, 60), rs(HEX, 6))
        return "data:image/svg+xml;base64," + b64s(svg)
    if k == 2:
        return "data:font/woff2;base64,d09GMgABAAAA" + b64(rb(R.randint(60, 160)))
    return "data:image/gif;base64,R0lGODlhAQABAIAAAP///wAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw=="


def n_fingerprint():
    return "SHA256:" + b64(rb(32)).rstrip("=")


def n_snowflake():
    return str(R.randint(1100000000000000000, 1400000000000000000))


def n_cursor2():
    return pick([n_cursor, lambda: b64s("cursor:v1:%d" % R.randint(10 ** 6, 10 ** 9)),
                 lambda: b64(json.dumps({"after": n_uuid(), "ts": epoch()}).encode()).rstrip("=")])()


NEG.update({"pw_policy": n_pw_policy, "example_key": n_example_key, "data_uri2": n_data_uri2, "fingerprint": n_fingerprint,
            "toolu": toolu_id, "msg": msg_id, "call": call_id, "chatcmpl": chatcmpl_id, "snowflake": n_snowflake,
            "cursor2": n_cursor2})


def pem_private(kind=None):
    """Returns (full_pem, body, kind)."""
    kind = kind or pick(["pem_rsa_private_key", "pem_ec_private_key", "openssh_private_key", "pem_pkcs8_private_key"])
    if kind == "pem_rsa_private_key":
        t = pem("RSA PRIVATE KEY", der_rsa_pkcs1())
    elif kind == "pem_ec_private_key":
        t = pem("EC PRIVATE KEY", der_ec())
    elif kind == "pem_pkcs8_private_key":
        t = pem("PRIVATE KEY", der_pkcs8())
    elif kind == "pem_encrypted_private_key":
        pre = bytes.fromhex("30820509305b06092a864886f70d01050d304e302d06092a864886f70d01050c3020")
        t = pem("ENCRYPTED PRIVATE KEY", pre + rb(1293 - len(pre)))
    else:
        t, body, _ = openssh_key(pick(PEOPLE).replace("á", "a") + "@" + pick(["laptop", "build-01", "bastion", "mbp", "deploy"]),
                                 rsa=chance(0.3))
        return t, body, "openssh_private_key"
    return t, t.split("\n", 1)[1].rsplit("\n", 1)[0], kind


# --------------------------------------------------------------------------- case object (depth-aware)
class Case:
    """Values are recorded raw together with a JSON-escape depth; finalize() escapes them
    `depth` times so that the labelled string is exactly what appears in the text."""

    def __init__(self, context):
        self.context = context
        self.hint = None
        self.depth = 0
        self.sec = []
        self.kp = []

    def S(self, kind=None, value=None, rel=0):
        d = self.depth + rel
        if kind is None:
            kind = pick_kind()
        if value is not None:
            self.sec.append((value, kind, d))
            return value
        r = GEN[kind]()
        if isinstance(r, dict):
            for k, s in r["s"]:
                self.sec.append((s, k, d))
            for k in r.get("k", []):
                if chance(0.7):
                    self.kp.append((k, d))
            return r["d"]
        self.sec.append((r, kind, d))
        return r

    def K(self, v, rel=0):
        self.kp.append((v, self.depth + rel))
        return v

    def N(self, nk, rel=0):
        return self.K(NEG[nk](), rel)


def jesc(s):
    return json.dumps(s, ensure_ascii=False)[1:-1]


def esc(v, d):
    for _ in range(d):
        v = jesc(v)
    return v


def jd(o, indent=None):
    return json.dumps(o, indent=indent, ensure_ascii=False)


TEMPLATES = []


def T(context, n):
    def deco(fn):
        TEMPLATES.append((context, fn, n))
        return fn
    return deco


def sec_any(c, generic=0.66, password=0.10, allow_url=False, rel=0):
    k = pick_kind(generic=generic, password=password, allow_url=allow_url)
    return k, c.S(k, rel=rel)


def label(kind):
    if kind in GENERIC:
        return pick(["key", "api key", "token", "secret", "staging key", "service token", "signing secret", "access key", "new key"])
    if kind in PASSWORDS:
        return "password"
    return kind.replace("_", " ")


def app_host():
    return pick(["app.", "api.", "dashboard.", "console.", "portal.", ""]) + dom()


def pyrepr_dict(d, indent=1):
    pad = " " * indent
    return "{" + (",\n" + pad).join("%r: %r" % kv for kv in d.items()) + "}"


# ======================================================================= chat
FILLER = ["lgtm", "on it", "thx!", "ok trying now", "nope, still 401", "works now :tada:", "ty", "brb", "which env?",
          "ack", "can someone review my PR?", "is staging down?", "nvm found it", "ping me if it breaks again",
          "ugh", "👀", "kk", "deploying in 5", "who owns the %s service?" % "billing", "rolled back"]

PROSE_SECRET = [
    "here's the staging key: {v}", "try this token {v}", "try this token: {v}", "new {label} is {v} - please don't commit it",
    "ok rotated it, the new one is `{v}`", "use {v} for now, I'll move it into vault later", "{label}: {v}",
    "DMs are broken so pasting here: {v}", "fwiw the prod one is\n```\n{v}\n```", "can you try with {v}? the old one got revoked",
    "token -> {v}", "just put {v} in the Authorization header as a Bearer token", "here you go {v}", "lmk if this works: {v}",
    "{v}", "sorry wrong channel, but the key for the {svc} sandbox is {v}", "@{who2} the {label} you asked for: {v} (expires friday)",
    "> {v}\nthat one is dead now, rotated", "```{v}```", "can't find it in 1password, here: {v}",
]
PROSE_PW = [
    "pw is {v}", "password for the {svc} admin panel is {v}", "login is {user} / {v}", "creds: user `{user}` pass `{v}`",
    "the jumpbox root pw is {v} (yes really)", "it's {v} - capital first letter", "wifi: {ssid} / {v}", "{user} / {v}",
    "temp password: {v} - you'll be asked to change it on first login", "db password got reset to {v}",
    "the zip is encrypted, password is {v}", "pass: {v}",
]


def chat_neg_msg(c):
    k = R.randint(0, 13)
    if k == 0:
        return "merged in %s" % c.N("git_sha")
    if k == 1:
        return "deploy %s is on staging now" % c.N("short_sha")
    if k == 2:
        return "trace id %s if anyone wants to look" % c.N("trace_id")
    if k == 3:
        return "request %s 500'd again" % c.N("uuid")
    if k == 4:
        return "set %s=%s in your .env, the real one is in 1Password" % (pick(GENERIC_CRED_NAMES), c.N("placeholder"))
    if k == 5:
        return "reminder from security: " + c.N("pw_policy")
    if k == 6:
        return "the docs example uses %s, that's not a real key" % c.N("example_key")
    if k == 7:
        return "my pubkey for the bastion: %s" % c.N("ssh_pub")
    if k == 8:
        return "next page cursor was %s" % c.N("cursor2")
    if k == 9:
        return "the agent died on tool call %s" % c.N("toolu")
    if k == 10:
        return "job id %s" % c.N("ulid")
    if k == 11:
        return "image is %s" % c.N("docker_digest")
    if k == 12:
        return "please don't paste keys in here, use `op read` or the vault"
    return "run %s failed, see %s" % (c.N("call"), c.N("traceparent"))


def chat_secret_msg(c):
    if chance(0.28):
        kind = pick(PASSWORD_KINDS)
        v = c.S(kind)
        return pick(PROSE_PW).format(v=v, user=user(), svc=svc(), ssid=pick(["Office-5G", "guest", "AcmeCorp", "lab-net"]))
    kind = pick_kind(generic=0.66, password=0, allow_url=False)
    v = c.S(kind)
    return pick(PROSE_SECRET).format(v=v, label=label(kind), svc=svc(), who2=pick(PEOPLE))


@T("chat", 50)
def t_chat(c):
    fmt = pick(["slack", "slack", "bracket", "discord", "irc", "slack_json", "discord_json"])
    if fmt.endswith("json"):
        c.depth = 1
    n_sec = 0 if chance(0.14) else pick([1, 1, 1, 2])
    msgs = [chat_neg_msg(c) if chance(0.55) else pick(FILLER) for _ in range(R.randint(2, 6))]
    for _ in range(n_sec):
        msgs.insert(R.randint(0, len(msgs)), chat_secret_msg(c))
    crew = R.sample(PEOPLE, 4)
    d0 = dt()
    if fmt == "slack_json":
        out = []
        for i, m in enumerate(msgs):
            out.append({"type": "message", "user": c.N("slack_id"), "text": m,
                        "ts": "%d.%06d" % (epoch(d0) + 30 * i, R.randint(0, 999999)), "client_msg_id": c.N("uuid")})
        o = {"ok": True, "messages": out, "has_more": chance(0.5)}
        if o["has_more"]:
            o["response_metadata"] = {"next_cursor": c.N("cursor2")}
        return jd(o, pick([None, 2]))
    if fmt == "discord_json":
        ch = n_snowflake()
        out = [{"id": c.N("snowflake"), "type": 0, "content": m, "channel_id": ch,
                "author": {"id": n_snowflake(), "username": pick(crew), "global_name": None},
                "timestamp": iso(d0 + datetime.timedelta(seconds=40 * i))} for i, m in enumerate(msgs)]
        return jd(out, pick([None, 2]))
    lines = []
    for i, m in enumerate(msgs):
        who = pick(crew)
        t = d0 + datetime.timedelta(minutes=i)
        if fmt == "slack":
            lines.append("%s  %s\n%s" % (who, t.strftime("%I:%M %p").lstrip("0"), m))
        elif fmt == "bracket":
            lines.append("[%s] %s: %s" % (t.strftime("%H:%M"), who, m))
        elif fmt == "discord":
            lines.append("%s — Today at %s\n%s" % (who, t.strftime("%I:%M %p").lstrip("0"), m))
        else:
            lines.append("<%s> %s" % (who, m))
    return ("\n\n" if fmt in ("slack", "discord") else "\n").join(lines) + "\n"


# ======================================================================= app-log
def log_ts():
    d = dt()
    return pick([iso_ms(d), d.strftime("%Y-%m-%d %H:%M:%S,") + "%03d" % R.randint(0, 999), d.strftime("%Y/%m/%d %H:%M:%S")])


LOGGERS = ["http.client", "app.api", "uvicorn.access", "com.acme.auth.AuthFilter", "requests", "httpx", "worker",
           "gateway", "o.s.web.client.RestTemplate", "sync.job"]


def bearer_or_key(c, rel=0, generic=0.66):
    k = pick_kind(generic=generic, password=0, allow_url=False)
    return c.S(k, rel=rel)


def jlog_neg(c):
    o = {"ts": iso_ms(), "level": pick(["info", "info", "debug", "warn"]), "logger": pick(LOGGERS)}
    k = R.randint(0, 6)
    if k == 0:
        o.update(msg="request completed", method=pick(["GET", "POST"]), path="/v1/%s/%s" % (svc(), c.N("uuid", 1)), status=200,
                 duration_ms=R.randint(2, 900))
    elif k == 1:
        o.update(msg="deployed", commit=c.N("git_sha", 1), image=c.N("docker_digest", 1))
    elif k == 2:
        o.update(msg="list page", next_cursor=c.N("cursor2", 1), count=R.randint(1, 100))
    elif k == 3:
        o.update(msg="outbound request", headers={"Authorization": "Bearer " + c.N("placeholder", 1), "X-Request-Id": c.N("uuid", 1)})
    elif k == 4:
        o.update(msg="tool call finished", tool_use_id=c.N("toolu", 1), message_id=c.N("msg", 1))
    elif k == 5:
        o.update(msg="policy loaded", password_policy=c.N("pw_policy", 1))
    else:
        o.update(msg="job enqueued", job_id=c.N("ulid", 1), traceparent=c.N("traceparent", 1))
    o["trace_id"] = c.N("trace_id", 1)
    if chance(0.5):
        o["span_id"] = c.N("span_id", 1)
    return jd(o)


def jlog_secret(c):
    o = {"ts": iso_ms(), "level": pick(["debug", "debug", "info", "warn", "error"]), "logger": pick(LOGGERS)}
    k = R.randint(0, 7)
    if k == 0:
        o.update(msg="outbound request", method="POST", url="https://api.%s/v1/%s" % (dom(), svc()),
                 headers={"Content-Type": "application/json", "Authorization": "Bearer " + bearer_or_key(c, 1),
                          "X-Request-Id": c.N("uuid", 1)})
    elif k == 1:
        o.update(msg="proxying request", headers={pick(["x-api-key", "X-API-Key", "apikey", "X-Auth-Token"]): bearer_or_key(c, 1),
                                                   "user-agent": "python-httpx/0.27.0"})
    elif k == 2:
        o.update(msg="HTTP %d" % pick([200, 401, 403, 429]), url="https://api.%s/v2/%s?%s=%s&page=%d" % (
            dom(), svc(), pick(["api_key", "access_token", "key", "token", "apikey"]), bearer_or_key(c, 1), R.randint(1, 9)))
    elif k == 3:
        o.update(msg="token exchange", params={"grant_type": "client_credentials", "client_id": c.N("uuid", 1),
                                               "client_secret": bearer_or_key(c, 1)})
    elif k == 4:
        o.update(msg="incoming request", cookie="session=%s; Path=/; HttpOnly" % c.S(pick(GENERIC_KINDS), rel=1))
    elif k == 5:
        body = {"username": user(), "password": c.S(pick(PASSWORD_KINDS), rel=2)}
        o.update(msg="request body", body=jd(body))
    elif k == 6:
        o.update(msg="connecting", dsn=c.S(pick(["db_url", "redis_url", "amqp_url", "mongodb_uri"]), rel=1))
    else:
        o.update(msg="auth failed", error="invalid credentials for token=%s" % bearer_or_key(c, 1))
    o["trace_id"] = c.N("trace_id", 1)
    return jd(o)


def plog_neg(c):
    ts = log_ts()
    k = R.randint(0, 8)
    if k == 0:
        return "%s INFO  request completed trace_id=%s span_id=%s status=200 dur=%dms" % (ts, c.N("trace_id"), c.N("span_id"), R.randint(1, 500))
    if k == 1:
        return "%s DEBUG > Authorization: Bearer %s" % (ts, c.K(pick(["[REDACTED]", "***", "<redacted>", "********"])))
    if k == 2:
        return "%s INFO  deployed revision %s" % (ts, c.N("git_sha"))
    if k == 3:
        return '%s INFO  "GET /v1/orders?cursor=%s HTTP/1.1" 200' % (ts, c.N("cursor2"))
    if k == 4:
        return "%s INFO  cache warm key=%s" % (ts, c.N("sha256"))
    if k == 5:
        return "%s INFO  auth: %s" % (ts, c.N("pw_policy"))
    if k == 6:
        return "%s INFO  agent tool_use %s completed (%s)" % (ts, c.N("toolu"), c.N("call"))
    if k == 7:
        return "%s INFO  X-Amzn-Trace-Id: %s" % (ts, c.N("xray"))
    return "%s INFO  traceparent=%s request_id=%s" % (ts, c.N("traceparent"), c.N("uuid"))


def plog_secret(c):
    ts = log_ts()
    k = R.randint(0, 8)
    if k == 0:
        return '%s DEBUG urllib3.connectionpool: https://api.%s:443 "GET /v1/%s?%s=%s HTTP/1.1" %d %d' % (
            ts, dom(), svc(), pick(["api_key", "token", "access_token", "key"]), bearer_or_key(c), pick([200, 401]), R.randint(80, 9000))
    if k == 1:
        return "%s DEBUG [%s] c.a.a.AuthFilter - Incoming request headers: {authorization=Bearer %s, x-request-id=%s, accept=*/*}" % (
            ts, pick(["http-nio-8080-exec-3", "main", "reactor-http-epoll-2"]), bearer_or_key(c), c.N("uuid"))
    if k == 2:
        return '10.%d.%d.%d - - [%s +0000] "GET /%s?%s=%s HTTP/1.1" 302 0 "-" "Mozilla/5.0"' % (
            R.randint(0, 255), R.randint(0, 255), R.randint(1, 254), dt().strftime("%d/%b/%Y:%H:%M:%S"),
            pick(["auth/callback", "login/magic", "verify", "sso/return"]), pick(["code", "token", "magic"]),
            c.S(pick(["generic_b62", "generic_hex", "generic_b64url", "generic_lower"])))
    if k == 3:
        pw = pick([pw_human, pw_random, pw_season])()
        b = b64(("%s:%s" % (user(), pw)).encode())
        return '%s level=debug msg="sending request" url=https://registry.%s/v2/ header.Authorization="Basic %s"' % (
            ts, dom(), c.S("basic_auth", b))
    if k == 4:
        return "%s WARN  login failed user=%s password=%s ip=10.0.%d.%d" % (
            ts, user(), c.S(pick(PASSWORD_KINDS)), R.randint(0, 255), R.randint(1, 254))
    if k == 5:
        hv = pick(["X-Api-Key: %s", "Authorization: Bearer %s", "PRIVATE-TOKEN: %s", "X-Auth-Token: %s"]) % bearer_or_key(c)
        return "%s DEBUG > GET /api/v1/%s HTTP/2\n> Host: api.%s\n> %s\n> Accept: */*" % (ts, svc(), dom(), hv)
    if k == 6:
        return "%s INFO  Connecting to %s" % (ts, c.S(pick(["db_url", "amqp_url", "redis_url", "mongodb_uri"])))
    if k == 7:
        return "%s DEBUG http: request headers map[Authorization:[Bearer %s] Content-Type:[application/json] X-Request-Id:[%s]]" % (
            ts, bearer_or_key(c), c.N("uuid"))
    return ('%s INFO -- : Parameters: {"user"=>{"email"=>"%s", "password"=>"%s"}, "api_token"=>"%s"}' % (
        ts, email(), c.K("[FILTERED]"), bearer_or_key(c)))


@T("app-log", 50)
def t_applog(c):
    style = pick(["json", "json", "plain", "plain", "compose"])
    n = R.randint(4, 10)
    n_sec = 0 if chance(0.12) else pick([1, 1, 2])
    pos = set(R.sample(range(n), n_sec))
    lines = []
    for i in range(n):
        if style == "json":
            lines.append(jlog_secret(c) if i in pos else jlog_neg(c))
        else:
            lines.append(plog_secret(c) if i in pos else plog_neg(c))
    if style == "compose":
        pre = "%s-%s-1  | " % (pick(PROJECTS), svc())
        lines = [pre + l.replace("\n", "\n" + pre) for l in lines]
        c.hint = {"command": "docker compose logs --tail=50"}
    elif style == "json" and chance(0.5):
        c.hint = {"command": "kubectl logs deploy/%s-api --since=10m" % svc()}
    return "\n".join(lines) + "\n"


# ======================================================================= stack-trace
def loc_negs(c, n):
    out = []
    pool = [("request_id", lambda: c.N("uuid")), ("commit", lambda: c.N("git_sha")), ("trace_id", lambda: c.N("trace_id")),
            ("cursor", lambda: c.N("cursor2")), ("timeout", lambda: 30), ("retries", lambda: R.randint(0, 5)),
            ("base_url", lambda: "https://api.%s/v1" % dom()), ("tool_use_id", lambda: c.N("toolu")),
            ("user_id", lambda: R.randint(1000, 99999)), ("region", lambda: pick(REGIONS))]
    for name, f in R.sample(pool, n):
        out.append((name, f()))
    return out


def fmt_locals(pairs, indent=4, width=None):
    w = width or max(len(k) for k, _ in pairs)
    return "\n".join(" " * indent + "%s = %r" % (k.ljust(w) if width != 0 else k, v) for k, v in pairs)


def sec_var(c):
    if chance(0.25):
        return pick(["password", "db_password", "passwd", "admin_pass"]), c.S(pick(PASSWORD_KINDS))
    k = pick_kind(generic=0.66, password=0, allow_url=False)
    nm = pick(["api_key", "token", "secret", "auth_token", "key", "access_token", "client_secret", "creds", "bearer", "k"])
    if k in V and chance(0.5):
        nm = snake(pick(V[k][1]))
    return nm, c.S(k)


@T("stack-trace", 50)
def t_trace(c):
    k = R.randint(0, 8)
    sv = svc()
    if k == 0:  # python traceback, secret in exception message url
        v = bearer_or_key(c)
        return L("Traceback (most recent call last):",
                 '  File "/app/%s/client.py", line %d, in fetch' % (sv, R.randint(20, 300)),
                 "    resp.raise_for_status()",
                 '  File "/usr/local/lib/python3.12/site-packages/requests/models.py", line 1024, in raise_for_status',
                 "    raise HTTPError(http_error_msg, response=self)",
                 "requests.exceptions.HTTPError: %d Client Error: Unauthorized for url: https://api.%s/v1/%s?%s=%s&request_id=%s" % (
                     pick([401, 403]), dom(), sv, pick(["api_key", "key", "token"]), v, c.N("uuid"))) + "\n"
    if k == 1:  # traceback with capture_locals
        nm, v = sec_var(c)
        pairs = loc_negs(c, R.randint(1, 3)) + [(nm, v)]
        R.shuffle(pairs)
        return L("Traceback (most recent call last):",
                 '  File "/srv/%s/worker.py", line %d, in run' % (sv, R.randint(10, 200)),
                 "    result = self.sync(batch)",
                 "    self = <%sWorker object at 0x7f%s>" % (sv.capitalize(), rs(HEX, 10)),
                 "    batch = [%d, %d]" % (R.randint(1, 99), R.randint(100, 999)),
                 '  File "/srv/%s/sync.py", line %d, in sync' % (sv, R.randint(10, 200)),
                 "    client = Client(%s=%s)" % (nm, nm),
                 fmt_locals(pairs, 4, 0),
                 "%s: %s" % (pick(["ConnectionError", "PermissionError", "RuntimeError"]), pick(["upstream refused connection", "403 Forbidden", "token rejected"]))) + "\n"
    if k == 2 or k == 3:  # pytest --showlocals
        nm, v = sec_var(c)
        pairs = loc_negs(c, R.randint(1, 4)) + [(nm, v), ("client", "<Client base_url='https://api.%s'>" % dom())]
        R.shuffle(pairs)
        w = max(len(a) for a, _ in pairs)
        tn = "test_%s_%s" % (sv, pick(["roundtrip", "auth", "create", "refresh_token", "sync"]))
        loc = "\n".join("%s = %s" % (a.ljust(w), b if a == "client" else repr(b)) for a, b in pairs)
        out = L("=" * 20 + " FAILURES " + "=" * 20,
                "_" * 15 + " %s " % tn + "_" * 15, "",
                "    def %s():" % tn,
                "        client = make_client(%s=%s)" % (nm, nm.upper() if chance(0.5) else nm),
                ">       assert client.ping() == \"pong\"",
                "E       AssertionError: assert 'unauthorized' == 'pong'",
                "E         - pong", "E         + unauthorized", "",
                loc, "",
                "tests/test_%s.py:%d: AssertionError" % (sv, R.randint(10, 200)),
                "=" * 10 + " short test summary info " + "=" * 10,
                "FAILED tests/test_%s.py::%s - AssertionError: assert 'unauthorized' == 'pong'" % (sv, tn),
                "%s 1 failed, %d passed in %.2fs %s" % ("=" * 8, R.randint(3, 80), R.random() * 9, "=" * 8))
        c.hint = {"command": "pytest -l tests/test_%s.py" % sv}
        return out + "\n"
    if k == 4:  # pytest assert diff with headers dict
        v = bearer_or_key(c)
        rid = c.N("uuid")
        return L("    def test_headers():",
                 "        h = build_headers()",
                 ">       assert h == {'Authorization': 'Bearer ***', 'X-Request-Id': ANY}",
                 "E       AssertionError: assert {'Authorization': 'Bearer %s', 'X-Request-Id': '%s'} == {'Authorization': 'Bearer ***', 'X-Request-Id': ANY}" % (v, rid),
                 "E         Differing items:",
                 "E         {'Authorization': 'Bearer %s'} != {'Authorization': 'Bearer ***'}" % v,
                 "E         Use -v to get more diff", "",
                 "tests/test_headers.py:%d: AssertionError" % R.randint(5, 60)) + "\n"
    if k == 5:  # node axios
        v = bearer_or_key(c)
        return L("AxiosError: Request failed with status code %d" % pick([401, 403]),
                 "    at settle (/app/node_modules/axios/lib/core/settle.js:19:12)",
                 "    at IncomingMessage.handleStreamEnd (/app/node_modules/axios/lib/adapters/http.js:589:11)",
                 "    at IncomingMessage.emit (node:events:531:35)",
                 "    at endReadableNT (node:internal/streams/readable:1696:12) {",
                 "  code: 'ERR_BAD_REQUEST',",
                 "  config: {",
                 "    headers: Object [AxiosHeaders] {",
                 "      Accept: 'application/json, text/plain, */*',",
                 "      Authorization: 'Bearer %s'," % v,
                 "      'User-Agent': 'axios/1.7.2',",
                 "      'X-Request-Id': '%s'" % c.N("uuid"),
                 "    },",
                 "    method: 'get',",
                 "    url: 'https://api.%s/v1/%s'," % (dom(), sv),
                 "  },",
                 "  request: <ref *1> ClientRequest { ... }",
                 "}", "", "Node.js v20.12.2") + "\n"
    if k == 6:  # node pg
        pw = c.S(pick(PASSWORD_KINDS))
        return L("Error: connect ECONNREFUSED 10.0.%d.%d:5432" % (R.randint(0, 255), R.randint(1, 254)),
                 "    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1555:16) {",
                 "  errno: -111,", "  code: 'ECONNREFUSED',", "  syscall: 'connect',",
                 "  connectionParameters: ConnectionParameters {",
                 "    user: '%s'," % user(), "    database: '%s'," % sv, "    port: 5432,",
                 "    host: '%s'," % host(), "    password: '%s'," % pw, "    ssl: false,",
                 "    application_name: '%s-%s'" % (sv, c.N("short_sha")), "  }", "}") + "\n"
    if k == 7:  # java
        v = bearer_or_key(c)
        return L('Exception in thread "main" java.lang.IllegalStateException: Invalid API key: %s' % v,
                 "\tat com.%s.%s.client.ApiClient.authenticate(ApiClient.java:%d)" % (pick(PROJECTS), sv, R.randint(30, 300)),
                 "\tat com.%s.%s.Main.main(Main.java:%d)" % (pick(PROJECTS), sv, R.randint(10, 60)),
                 "Caused by: org.springframework.web.client.HttpClientErrorException$Unauthorized: 401 Unauthorized: [no body]",
                 "\t... 2 more") + "\n"
    # negative-only traceback
    return L("Traceback (most recent call last):",
             '  File "/app/%s/jobs.py", line %d, in handle' % (sv, R.randint(10, 300)),
             "    order = orders[order_id]",
             fmt_locals(loc_negs(c, 3) + [("order_id", c.N("uuid"))], 4, 0),
             "KeyError: '%s'" % c.N("uuid"),
             "", "During handling of the above exception, another exception occurred:", "",
             "RuntimeError: checksum mismatch: expected %s got %s" % (c.N("sha256"), c.N("sha256"))) + "\n"


# ======================================================================= jupyter
@T("jupyter", 50)
def t_jupyter(c):
    k = R.randint(0, 8)
    n = R.randint(1, 40)
    if k == 0:
        kind, v = sec_any(c)
        nm = pick(V[kind][1]) if kind in V else env_name(kind)
        return "In [%d]: os.environ[%r]\nOut[%d]: %r\n" % (n, nm, n, v)
    if k == 1:
        d = {"endpoint": "https://api.%s/v1" % dom(), "run_id": c.N("uuid"), "timeout": 30}
        for _ in range(R.randint(1, 2)):
            kind, v = sec_any(c)
            d[pick(["api_key", "token", "secret", "auth", "key", "password"]) + ("_%d" % R.randint(2, 9) if pick([0, 1]) else "")] = v
        d["commit"] = c.N("git_sha")
        return "In [%d]: config\nOut[%d]:\n%s\n" % (n, n, pyrepr_dict(d))
    if k == 2:
        kind, v = sec_any(c)
        return "In [%d]: print(f\"Using key: {client.api_key}\")\nUsing key: %s\n" % (n, v) if chance(0.5) else \
            "Connected to %s as %s\ntoken=%s\nsession %s\n" % (dom(), user(), v, c.N("uuid"))
    if k == 3:
        lines = ["%s=%s" % env_secret(c, allow_url=True) if chance(0.5) else "%s=%s" % env_neg(c) for _ in range(R.randint(3, 7))]
        if not any(True for _ in c.sec):
            lines.append("%s=%s" % env_secret(c))
        return "In [%d]: !cat .env\n%s\n" % (n, "\n".join(lines))
    if k == 4:
        kind, v = sec_any(c)
        nm = pick(V[kind][1]) if kind in V else env_name(kind)
        d = {"HOME": "/home/jovyan", "JUPYTER_SERVER_ROOT": "/home/jovyan/work", nm: v, "CONDA_DIR": "/opt/conda",
             "GIT_COMMIT": c.N("git_sha")}
        return "In [%d]: %%env\nOut[%d]:\n%s\n" % (n, n, pyrepr_dict(d))
    if k == 5:
        rows = []
        for i in range(R.randint(2, 4)):
            kind, v = sec_any(c, generic=0.6)
            rows.append((i, pick(SVC), v, iso()[:10]))
        w = max(len(r[2]) for r in rows)
        hdr = "   %-10s %s  %s" % ("service", "api_key".rjust(w), "created")
        body = "\n".join("%d  %-10s %s  %s" % (r[0], r[1], r[2].rjust(w), r[3]) for r in rows)
        return "In [%d]: keys_df\nOut[%d]:\n%s\n%s\n" % (n, n, hdr, body)
    if k == 6 or k == 7:  # ipynb JSON
        c.depth = 1
        outs = []
        src = pick(['print(resp.json())', 'client = make_client()\nprint(client.config)', 'print(os.environ["%s"])' % pick(GENERIC_CRED_NAMES),
                    '!cat ~/.netrc'])
        if "netrc" in src:
            txt = "machine api.%s\n  login %s\n  password %s\n" % (dom(), user(), c.S(pick(PASSWORD_KINDS + GENERIC_KINDS)))
        elif "resp" in src:
            kind, v = sec_any(c)
            txt = "{'access_token': '%s', 'token_type': 'Bearer', 'expires_in': 3600, 'request_id': '%s'}\n" % (v, c.N("uuid"))
        else:
            kind, v = sec_any(c)
            txt = "%s\n" % v if "environ" in src else "Config(base_url='https://api.%s', api_key='%s', run='%s')\n" % (dom(), v, c.N("uuid"))
        outs.append({"name": "stdout", "output_type": "stream", "text": [l + "\n" for l in txt.rstrip("\n").split("\n")]})
        if chance(0.5):
            outs.append({"data": {"image/png": c.K(b64(b"\x89PNG\r\n\x1a\n" + rb(R.randint(120, 300)))), "text/plain": ["<Figure size 640x480 with 1 Axes>"]},
                         "metadata": {}, "output_type": "display_data"})
        cell = {"cell_type": "code", "execution_count": n, "id": rs(HEX, 8), "metadata": {}, "outputs": outs,
                "source": [l + "\n" for l in src.split("\n")]}
        c.hint = {"path": pick(["analysis.ipynb", "notebooks/explore.ipynb", "eval.ipynb"])}
        return jd({"cells": [cell], "metadata": {"kernelspec": {"name": "python3", "display_name": "Python 3"}}, "nbformat": 4, "nbformat_minor": 5}, 1)
    # negative
    j = R.randint(0, 2)
    if j == 0:
        d = {"run_id": c.N("uuid"), "commit": c.N("git_sha"), "trace_id": c.N("trace_id"), "next_cursor": c.N("cursor2"),
             "api_key": c.N("placeholder")}
        return "In [%d]: meta\nOut[%d]:\n%s\n" % (n, n, pyrepr_dict(d))
    if j == 1:
        return "In [%d]: display(HTML(logo))\n<img src=\"%s\"/>\nOut[%d]: <IPython.core.display.HTML object>\n" % (n, c.N("data_uri2"), n)
    return "In [%d]: df.head(3)\nOut[%d]:\n                                     id    sha\n0  %s  %s\n1  %s  %s\n" % (
        n, n, c.N("uuid"), c.N("short_sha"), c.N("uuid"), c.N("short_sha"))


# ======================================================================= api-response
def http_prefix(c):
    return "HTTP/2 200\ndate: %s\ncontent-type: application/json\nx-request-id: %s\n\n" % (
        dt().strftime("%a, %d %b %Y %H:%M:%S GMT"), c.N(pick(["uuid", "request_id"])))


@T("api-response", 50)
def t_api(c):
    c.depth = 1  # values live inside JSON strings
    k = R.randint(0, 9)
    if k <= 1:  # OAuth token response
        ak = pick(["jwt", "google_oauth_access_token", "generic_b64url", "generic_b62", "generic_b64url", "generic_hex"])
        o = {"access_token": c.S(ak), "token_type": "Bearer", "expires_in": pick([3599, 3600, 7200, 86400])}
        if chance(0.7):
            o["refresh_token"] = c.S(pick(["generic_b64url", "generic_b62", "google_refresh_token", "generic_lower"]))
        if chance(0.4):
            o["id_token"] = c.S("jwt")
        o["scope"] = pick(["openid profile email", "read write", "repo user", "offline_access api"])
    elif k == 2:  # API key creation
        kk = pick(["generic_b62", "openai_key", "anthropic_key", "generic_hex", "stripe_restricted_key", "generic_b64url", "datadog_api_key"])
        v = c.S(kk)
        o = {"id": c.K("key_" + rtok(B62, 24)), "object": "api_key", "name": pick(["ci-deploy", "local-dev", "zapier", "prod-worker"]),
             "created_at": epoch(), "redacted_value": c.K(v[:3] + "..." + rs(B62, 4)), pick(["key", "secret", "value", "api_key"]): v,
             "owner": {"id": c.N("uuid"), "type": "service_account"}}
    elif k == 3:  # github installation token
        o = {"token": c.S("github_app_token"), "expires_at": iso(), "permissions": {"contents": "read", "metadata": "read"},
             "repository_selection": "selected"}
    elif k == 4:  # STS
        ak = c.S(value="ASIA" + rs(B32, 16), kind="aws_access_key_id")
        o = {"Credentials": {"AccessKeyId": ak, "SecretAccessKey": c.S("aws_secret_access_key"),
                             "SessionToken": c.S("aws_session_token"), "Expiration": iso()},
             "AssumedRoleUser": {"AssumedRoleId": "AROA%s:%s" % (rs(B32, 17), pick(["ci", "deploy", "botocore-session-%d" % epoch()])),
                                 "Arn": c.N("arn")}}
    elif k == 5:  # vault login
        o = {"request_id": c.N("uuid"), "lease_id": "", "renewable": False, "lease_duration": 0, "data": None,
             "auth": {"client_token": c.S("vault_token"), "policies": ["default", svc()], "lease_duration": 2764800, "renewable": True}}
    elif k == 6:  # supabase/firebase style
        o = {"access_token": c.S("jwt"), "token_type": "bearer", "expires_in": 3600, "refresh_token": c.S(pick(["generic_lower", "generic_b62"])),
             "user": {"id": c.N("uuid"), "email": email(), "created_at": iso()}}
    elif k == 7:  # webhook endpoint / client creds
        if chance(0.5):
            o = {"id": c.K("we_" + rtok(B62, 24)), "object": "webhook_endpoint", "secret": c.S("stripe_webhook_secret"),
                 "url": "https://%s/webhooks/stripe" % app_host(), "enabled_events": ["invoice.paid"]}
        else:
            o = {"client_id": c.N("uuid"), "client_secret": c.S(pick(GENERIC_KINDS)), "client_name": svc() + "-integration",
                 "client_secret_expires_at": 0, "registration_access_token": c.S(pick(GENERIC_KINDS))}
    elif k == 8:  # negative: list with cursor
        o = {"data": [{"id": c.N(pick(["uuid", "stripe_obj"])), "created": epoch(), "sha": c.N("git_sha")} for _ in range(R.randint(2, 4))],
             "has_more": True, "next_cursor": c.N("cursor2"), "request_id": c.N("request_id")}
        if chance(0.5):
            o["data"][0]["api_key"] = c.N("placeholder")
    else:  # negative: JWKS / key metadata
        if chance(0.6):
            o = {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": c.K(rtok(B64U, 43)), "n": c.K(b64u(rb(256))), "e": "AQAB"}
                          for _ in range(R.randint(1, 2))]}
        else:
            o = {"keys": [{"id": c.K("key_" + rtok(B62, 24)), "name": pick(["ci", "prod"]), "redacted_value": c.K("sk-..." + rs(B62, 4)),
                           "last_used_at": iso()} for _ in range(R.randint(1, 3))], "trace_id": c.N("trace_id")}
    body = jd(o, pick([None, 2]))
    if chance(0.35):
        c.depth = 0
        pre = http_prefix(c)
        c.hint = {"command": "curl -si https://api.%s/v1/%s" % (dom(), pick(["oauth/token", "keys", "auth/login", "tokens"]))}
        return pre + body + "\n"
    return body + "\n"


# ======================================================================= url
def u_oauth_code(c):
    code = c.S("oauth_code", pick([lambda: rtok(B64U, R.randint(20, 43)), lambda: "4/0A" + rtok(B64U, 70), lambda: rtok(LALNUM, 20),
                                   lambda: n_uuid().replace("-", "") + "." + rtok(B64U, 20)])())
    return "https://%s/%s?code=%s&state=%s" % (app_host(), pick(["auth/callback", "oauth2/callback", "api/auth/callback/github", "login/oauth"]),
                                             code, rtok(B64U, 22))


URLSAFE_GENERIC = ["generic_b62", "generic_hex", "generic_b64url", "generic_lower"]


def u_magic(c):
    tok = c.S(pick(URLSAFE_GENERIC))
    return pick(["https://%s/auth/magic?token=%s&email=%s" % (app_host(), enc(tok), enc(email())),
                 "https://%s/login/verify/%s" % (app_host(), tok),
                 "https://%s/auth/v1/verify?token=%s&type=magiclink&redirect_to=https://%s" % (app_host(), tok, app_host())])


def u_reset(c):
    k = R.randint(0, 2)
    if k == 0:
        uid = b64u(str(R.randint(1, 99999)).encode())
        tok = c.S("password_reset_token", b62num(epoch(), 6).lower()[:6] + "-" + rs(HEX, 32))
        return "https://%s/accounts/reset/%s/%s/" % (app_host(), uid, tok)
    if k == 1:
        return "https://%s/users/password/edit?reset_password_token=%s" % (app_host(), c.S("password_reset_token", rtok(B62 + "-_", 20)))
    return "https://%s/reset-password?token=%s" % (app_host(), c.S(pick(URLSAFE_GENERIC)))


def u_userpw(c):
    k = R.randint(0, 3)
    if k == 0:
        return c.S(pick(["db_url", "redis_url", "amqp_url", "mongodb_uri"]))
    pw = enc(any_password().replace(" ", "-"))
    if k == 1:
        return "https://%s:%s@git.%s/%s/%s.git" % (user(), c.S("url_password", pw), dom(), pick(PROJECTS), svc())
    if k == 2:
        return "ftp://%s:%s@files.%s/incoming/" % (user(), c.S("url_password", pw), dom())
    return "http://admin:%s@10.0.%d.%d:8080/manager/html" % (c.S("url_password", pw), R.randint(0, 255), R.randint(1, 254))


def u_secret(c):
    k = R.randint(0, 8)
    if k == 0:
        return c.S("s3_presigned_url")
    if k == 1:
        return _gcs(c)
    if k == 2:
        return c.S(pick(["slack_webhook", "discord_webhook", "teams_webhook", "azure_sas"]))
    if k == 3:
        return _generic_hook(c)
    if k == 4:
        return u_oauth_code(c)
    if k == 5:
        return u_magic(c)
    if k == 6:
        return u_reset(c)
    if k == 7:
        return u_userpw(c)
    return pick([lambda: "https://%s/#access_token=%s&token_type=Bearer&expires_in=3600" % (app_host(), c.S(pick(["jwt", "generic_b64url"]))),
                 lambda: "https://maps.googleapis.com/maps/api/geocode/json?address=%s&key=%s" % (enc("1 Main St"), c.S("google_api_key")),
                 lambda: "https://api.%s/v1/export?api_key=%s&format=csv" % (dom(), c.S(pick(URLSAFE_GENERIC))),
                 lambda: "https://api.telegram.org/bot%s/sendMessage" % c.S("telegram_bot_token")])()


def _gcs(c):
    r = gcs_signed()
    for k, s in r["s"]:
        c.S(k, s)
    return r["d"]


def _generic_hook(c):
    tok = rtok(pick([B62, B64U, LALNUM]), R.randint(24, 48))
    c.S(pick(GENERIC_KINDS), tok)
    return pick(["https://hooks.%s/in/%s", "https://%s/api/v1/hooks/%s", "https://events.%s/ingest/%s", "https://%s/webhook/%s"]) % (dom(), tok)


def u_neg(c):
    k = R.randint(0, 8)
    if k == 0:
        return "https://github.com/%s/%s/commit/%s" % (pick(PROJECTS), svc(), c.N("git_sha"))
    if k == 1:
        return "https://%s/orders/%s?utm_source=newsletter&utm_campaign=%s" % (app_host(), c.N("uuid"), pick(["spring", "launch"]))
    if k == 2:
        return "https://api.%s/v1/events?cursor=%s&limit=50" % (dom(), c.K(enc(n_cursor2())))
    if k == 3:
        return "https://accounts.google.com/o/oauth2/v2/auth?client_id=%s&redirect_uri=%s&response_type=code&scope=openid%%20email&state=%s" % (
            c.N("google_client_id"), enc("https://%s/auth/callback" % app_host()), rtok(B64U, 22))
    if k == 4:
        return "https://%s-assets-%s.s3.amazonaws.com/public/logo.png" % (pick(PROJECTS), pick(ENVS))
    if k == 5:
        return "https://%s/traces/%s" % (pick(["grafana.", "jaeger.", "honeycomb."]) + dom(), c.N("trace_id"))
    if k == 6:
        return "https://%s@git.%s/%s.git" % (user(), dom(), pick(PROJECTS))
    if k == 7:
        return "https://%s/reset-password?token=%s" % (app_host(), c.N("placeholder"))
    return "https://hub.docker.com/layers/%s/%s/%s" % (pick(PROJECTS), svc(), c.N("docker_digest"))


@T("url", 50)
def t_url(c):
    n_sec = 0 if chance(0.12) else pick([1, 1, 1, 2])
    urls = [u_secret(c) for _ in range(n_sec)] + [u_neg(c) for _ in range(R.randint(0 if n_sec else 2, 3))]
    R.shuffle(urls)
    style = R.randint(0, 5)
    if style == 0:
        return "\n".join(urls) + "\n"
    if style == 1:
        c.hint = {"command": "grep -ho 'https\\?://[^ \"]*' logs/*.log | sort -u"}
        return "\n".join(urls) + "\n"
    if style == 2:
        return "".join("$ curl -sSL '%s' -o /tmp/out.%d\n" % (u, i) for i, u in enumerate(urls))
    if style == 3:
        return ("Hi %s,\n\nWe received a request to sign in to your account. Use the link below:\n\n%s\n\n"
                "This link expires in 30 minutes. If you didn't request this, you can ignore this email.\n") % (
            pick(PEOPLE).capitalize(), "\n\n".join(urls))
    if style == 4:
        return "".join('%s INFO  redirect location="%s"\n' % (log_ts(), u) for u in urls)
    return "Visited:\n" + "".join("  %d. %s\n" % (i + 1, u) for i, u in enumerate(urls))


# ======================================================================= markdown
def md_neg_section(c, k):
    if k == 0:
        lines = ["## Configuration", "", "Copy `.env.example` to `.env` and fill in:", "", "```bash"]
        for _ in range(R.randint(2, 4)):
            lines.append("%s=%s" % (pick(GENERIC_CRED_NAMES + ["OPENAI_API_KEY", "STRIPE_SECRET_KEY", "GITHUB_TOKEN"]), c.N("placeholder")))
        return "\n".join(lines + ["```"])
    if k == 1:
        return "## Password policy\n\n- %s\n- %s\n" % (c.N("pw_policy"), c.N("pw_policy"))
    if k == 2:
        return ("## AWS setup\n\nThe examples below use the documentation keys `%s` and `%s`; replace them with your own.\n" % (
            c.K(AWS_EXAMPLES[0]), c.K(AWS_EXAMPLES[1])))
    if k == 3:
        return "## SSH access\n\nAdd your public key to `authorized_keys`, e.g.:\n\n```\n%s\n```" % c.N("ssh_pub")
    if k == 4:
        return "## TLS\n\nPin the following CA certificate:\n\n```\n%s\n```" % c.N(pick(["cert", "pubkey"]))
    if k == 5:
        return "![build](%s) ![coverage](%s)" % (c.N("data_uri2"), c.N("data_uri2"))
    if k == 6:
        return ("## Usage\n\n```bash\ncurl https://api.%s/v1/%s \\\n  -H \"Authorization: Bearer $API_TOKEN\"\n```\n\nExample response:\n\n```json\n"
                "{\"id\": \"%s\", \"request_id\": \"%s\", \"next_cursor\": \"%s\"}\n```" % (dom(), svc(), c.N("uuid"), c.N("request_id"), c.N("cursor2")))
    if k == 7:
        return "## Example tokens\n\nA JWT looks like `%s`. Never commit real keys like `%s`." % (c.K(JWT_IO_EXAMPLE), c.N("example_key"))
    if k == 8:
        return "## Changelog\n\n- %s fix token refresh\n- %s bump deps (%s)" % (c.N("short_sha"), c.N("short_sha"), c.N("docker_digest"))
    return "## Agents\n\nTool calls are logged with ids like `%s` and `%s`." % (c.N("toolu"), c.N("call"))


def md_leak_section(c):
    k = R.randint(0, 4)
    if k == 3:
        pw = c.S(pick(PASSWORD_KINDS))
        return "## Local admin\n\nDefault login: `admin` / `%s`" % pw
    kind, v = sec_any(c, generic=0.45)
    if k == 0:
        return "## Quickstart\n\n```bash\nexport %s=%s\npython main.py\n```" % (pick(V[kind][1]) if kind in V else env_name(kind), v)
    if k == 1:
        return "## Testing\n\nUse the shared staging key `%s` (ask #platform before rotating)." % v
    if k == 2:
        return "## Example\n\n```bash\ncurl -H 'X-Api-Key: %s' https://api.%s/v1/%s\n```" % (v, dom(), svc())
    return "| name | value |\n|---|---|\n| endpoint | https://api.%s |\n| key | `%s` |\n| region | %s |" % (dom(), v, pick(REGIONS))


@T("markdown", 50)
def t_md(c):
    title = "# %s-%s\n\n%s" % (pick(PROJECTS), svc(), pick(["Internal service for %s." % svc(), "A small CLI.", "Handles webhooks and exports."]))
    secs = [md_neg_section(c, k) for k in R.sample(range(10), R.randint(2, 4))]
    if chance(0.3):
        secs.insert(R.randint(0, len(secs)), md_leak_section(c))
    c.hint = {"command": "cat " + pick(["README.md", "docs/setup.md", "CONTRIBUTING.md", "docs/api.md"])}
    return title + "\n\n" + "\n\n".join(secs) + "\n"


# ======================================================================= tool outputs (shared by transcripts)
def tout_env(c):
    lines = ["%s=%s" % env_neg(c) for _ in range(R.randint(1, 4))]
    for _ in range(R.randint(1, 2)):
        lines.insert(R.randint(0, len(lines)), "%s=%s" % env_secret(c))
    return pick(["cat .env", "cat .env.local", "cat config/.env.production"]), "\n".join(lines) + "\n"


def tout_config_json(c):
    d = {"service": svc(), "env": pick(ENVS), "buildSha": c.N("git_sha", 1)}
    kind, v = sec_any(c, rel=1)
    d[pick(["apiKey", "token", "secret", "auth"])] = v
    if chance(0.4):
        d["db"] = {"host": host(), "user": user(), "password": c.S(pick(PASSWORD_KINDS), rel=1)}
    d["requestIdHeader"] = "X-Request-Id"
    return "cat config/%s.json" % pick(ENVS), jd(d, 2) + "\n"


def tout_pem(c):
    full, body, kind = pem_private()
    c.S(kind, body)
    return pick(["cat ~/.ssh/id_ed25519", "cat certs/server.key", "cat deploy_key", "cat secrets/jwt-signing.pem"]), full + "\n"


def tout_sa(c):
    full, body, kind = pem_private("pem_pkcs8_private_key")
    c.S(kind, body, rel=1)
    p = proj()
    sa = {"type": "service_account", "project_id": p, "private_key_id": rs(HEX, 40), "private_key": full + "\n",
          "client_email": c.K("%s@%s.iam.gserviceaccount.com" % (pick(["deployer", "ci", "exporter"]), p), 1),
          "client_id": c.K(rs(DIG, 21), 1), "token_uri": "https://oauth2.googleapis.com/token"}
    return "cat gcp-sa.json", jd(sa, 2) + "\n"


def tout_token_resp(c):
    o = {"access_token": c.S(pick(["jwt", "generic_b64url", "generic_b62"]), rel=1), "token_type": "Bearer", "expires_in": 3600,
         "request_id": c.N("uuid", 1)}
    return "curl -s -X POST https://auth.%s/oauth/token -d grant_type=client_credentials" % dom(), jd(o) + "\n"


def tout_gitlog(c):
    lines = ["%s %s" % (c.N("short_sha"), pick(["fix: retry on 429", "feat: add export", "chore: bump deps", "refactor auth client"]))
             for _ in range(R.randint(3, 6))]
    return "git log --oneline -n %d" % len(lines), "\n".join(lines) + "\n"


def tout_grep(c):
    lines = []
    for _ in range(R.randint(1, 2)):
        kind, v = sec_any(c)
        lines.append("src/%s/settings.py:%d:API_KEY = \"%s\"" % (svc(), R.randint(3, 90), v))
    lines.append("src/%s/client.py:%d:    api_key = os.environ[\"API_KEY\"]" % (svc(), R.randint(3, 90)))
    lines.append("README.md:%d:export API_KEY=%s" % (R.randint(3, 90), c.N("placeholder")))
    R.shuffle(lines)
    return "grep -rn API_KEY .", "\n".join(lines) + "\n"


def tout_k8s(c):
    data = {}
    for _ in range(R.randint(1, 2)):
        raw = GEN[pick_kind(generic=0.48, password=0.15, allow_url=False)]()  # only the base64 form appears
        data[pick(["API_KEY", "TOKEN", "DB_PASSWORD", "SECRET"]) + "_%d" % R.randint(1, 9)] = c.S("k8s_secret_b64", b64s(raw))
    o = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": svc() + "-secrets", "uid": c.N("uuid", 1)}, "data": data, "type": "Opaque"}
    return "kubectl get secret %s-secrets -o json" % svc(), jd(o, 2) + "\n"


def tout_logs(c):
    lines = [plog_neg(c) for _ in range(R.randint(2, 4))]
    lines.insert(R.randint(0, len(lines)), plog_secret(c))
    return "docker logs --tail 20 %s-api" % svc(), "\n".join(lines) + "\n"


def tout_neg(c):
    k = R.randint(0, 2)
    if k == 0:
        return tout_gitlog(c)
    if k == 1:
        return "npm test", "PASS src/%s.test.ts\nTests: %d passed\nrun %s\n" % (svc(), R.randint(3, 90), c.N("uuid"))
    return "cat ~/.ssh/id_ed25519.pub", c.N("ssh_pub") + "\n"


SEC_TOOLS = [tout_env, tout_env, tout_config_json, tout_pem, tout_sa, tout_token_resp, tout_grep, tout_k8s, tout_logs]


def tool_input_secret(c):
    """A tool call whose *input* carries the secret. Returns (shell_cmd or None, write_path, write_content)."""
    if chance(0.5):
        v = bearer_or_key(c)
        return ('curl -s https://api.%s/v1/%s -H "Authorization: Bearer %s"' % (dom(), svc(), v), None, None)
    name, v = env_secret(c)
    return (None, ".env", "%s=%s\nLOG_LEVEL=debug\n" % (name, v))


@T("agent-transcript", 50)
def t_agent(c):
    fmt = pick(["anthropic", "anthropic", "claude_code_jsonl", "openai_chat", "openai_chat", "openai_responses"])
    steps = []
    has_sec = not chance(0.1)
    n = R.randint(1, 3)
    for i in range(n):
        if has_sec and (i == 0 or chance(0.3)):
            if chance(0.25):
                steps.append(("input",))
            else:
                steps.append(("output", pick(SEC_TOOLS)))
        else:
            steps.append(("output", tout_neg))
    R.shuffle(steps)
    msgs = []
    sess = n_uuid()
    parent = None
    for st in steps:
        tid = c.K(toolu_id()) if fmt in ("anthropic", "claude_code_jsonl") else c.K(call_id())
        in_depth = 2 if fmt.startswith("openai") else 1
        if fmt == "claude_code_jsonl":
            in_depth = 1
        # build call
        c.depth = in_depth
        if st[0] == "input":
            cmd, path, content = tool_input_secret(c)
            out_txt = jd({"ok": True, "id": n_uuid()}) if cmd else "File created successfully at: %s" % path
        else:
            c.depth = 1
            cmd, out_txt = st[1](c)
            c.depth = in_depth
            path = content = None
        if fmt in ("anthropic", "claude_code_jsonl"):
            if cmd:
                call = {"type": "tool_use", "id": tid, "name": "Bash", "input": {"command": cmd, "description": "Run command"}}
            else:
                call = {"type": "tool_use", "id": tid, "name": "Write", "input": {"file_path": "/workspace/" + path, "content": content}}
            am = {"id": c.K(msg_id()), "type": "message", "role": "assistant", "model": "claude-sonnet-4-5",
                  "content": [{"type": "text", "text": "Let me check that."}, call], "stop_reason": "tool_use"}
            um = {"role": "user", "content": [{"type": "tool_result", "tool_use_id": tid, "content": out_txt}]}
            if fmt == "claude_code_jsonl":
                u1, u2 = c.K(n_uuid()), c.K(n_uuid())
                msgs.append({"parentUuid": parent, "sessionId": sess, "type": "assistant", "uuid": u1, "timestamp": iso_ms(), "message": am})
                msgs.append({"parentUuid": u1, "sessionId": sess, "type": "user", "uuid": u2, "timestamp": iso_ms(), "message": um})
                parent = u2
            else:
                msgs.extend([am, um])
        else:
            args = jd({"command": ["bash", "-lc", cmd]} if cmd else {"path": path, "content": content})
            fname = "shell" if cmd else "write_file"
            if fmt == "openai_chat":
                msgs.append({"role": "assistant", "content": None,
                             "tool_calls": [{"id": tid, "type": "function", "function": {"name": fname, "arguments": args}}]})
                msgs.append({"role": "tool", "tool_call_id": tid, "content": out_txt})
            else:
                msgs.append({"type": "function_call", "id": c.K(fc_id()), "call_id": tid, "name": fname, "arguments": args})
                msgs.append({"type": "function_call_output", "call_id": tid, "output": out_txt})
    c.depth = 0
    if fmt == "claude_code_jsonl":
        c.hint = {"path": "~/.claude/projects/-workspace/%s.jsonl" % sess}
        return "\n".join(jd(m) for m in msgs) + "\n"
    if fmt == "openai_chat":
        return jd({"id": c.K(chatcmpl_id()), "model": "gpt-4.1", "messages": [{"role": "system", "content": "You are a coding agent."}] + msgs},
                  pick([None, 2])) + "\n"
    if fmt == "openai_responses":
        return jd({"model": "gpt-5", "input": msgs}, pick([None, 2])) + "\n"
    return jd({"model": "claude-sonnet-4-5", "max_tokens": 8192, "messages": [{"role": "user", "content": "fix the failing deploy"}] + msgs},
              pick([None, 2])) + "\n"


# ======================================================================= pem-key
PEM_KINDS = ["pem_rsa_private_key", "pem_ec_private_key", "openssh_private_key", "pem_pkcs8_private_key"]


def pem_kind():
    return pick(PEM_KINDS) if chance(0.94) else "pem_encrypted_private_key"


@T("pem-key", 50)
def t_pem(c):
    k = R.randint(0, 11)
    if k <= 3:  # plain files
        full, body, kind = pem_private(pem_kind())
        c.S(kind, body)
        path = pick(["~/.ssh/id_rsa", "~/.ssh/id_ed25519", "certs/server.key", "keys/jwt-private.pem", "deploy/key.pem", "tls.key"])
        c.hint = {"command": "cat " + path, "path": path}
        if k == 0:  # pkcs12 export style
            pre = "Bag Attributes\n    localKeyID: %s \n    friendlyName: %s\nKey Attributes: <No Attributes>\n" % (
                " ".join(rs(HEXU, 2) for _ in range(20)), svc())
            return pre + full + "\n" + (c.N("cert") + "\n" if chance(0.6) else "")
        if k == 1:  # key + cert bundle
            return c.N("cert") + "\n" + full + "\n"
        return full + "\n"
    if k <= 6:  # JSON with \n escapes
        if k == 4:
            return tout_sa(c)[1]
        full, body, kind = pem_private(pem_kind())
        if k == 5:
            c.S(kind, body, rel=1)
            o = {"issuer": "https://auth.%s" % dom(), "kid": c.K(n_uuid()), "signingKey": full, "publicKey": c.N("pubkey", 1)}
        else:  # AWS Secrets Manager: PEM inside a JSON string inside JSON (double-escaped)
            c.S(kind, body, rel=2)
            o = {"Name": "%s/tls" % pick(ENVS), "ARN": c.N("arn", 1), "SecretString": jd({"private_key": full})}
        return jd(o, 2) + "\n"
    if k <= 10:  # env vars
        full, body, kind = pem_private(pem_kind())
        nm = pick(["JWT_PRIVATE_KEY", "SSH_PRIVATE_KEY", "PRIVATE_KEY", "GITHUB_APP_PRIVATE_KEY", "SIGNING_KEY", "APNS_KEY", "TLS_KEY"])
        if k == 7:  # .env with literal \n
            c.S(kind, body, rel=1)
            c.hint = {"command": "cat .env"}
            pre = ["%s=%s" % env_neg(c) for _ in range(R.randint(1, 3))]
            return "\n".join(pre + ['%s="%s"' % (nm, jesc(full))]) + "\n"
        if k == 8:  # printenv multi-line
            c.S(kind, body)
            c.hint = {"command": "printenv"}
            return "\n".join(base_env_lines(3) + ["%s=%s" % (nm, full)] + ["%s=%s" % env_neg(c)]) + "\n"
        if k == 9:  # base64-encoded pem
            c.S("pem_private_key_b64", b64s(full + "\n"))
            c.hint = {"command": "env | grep KEY"}
            return "%s_B64=%s\nJWT_PUBLIC_KEY_B64=%s\n" % (nm, b64s(full + "\n"), c.K(b64s(n_pubkey() + "\n")))
        # k8s / compose yaml block scalar
        c.S(kind, ind(body, 4).lstrip())
        return "apiVersion: v1\nkind: Secret\nmetadata:\n  name: %s-tls\n  uid: %s\nstringData:\n  %s: |\n%s\n" % (
            svc(), c.N("uuid"), nm.lower(), ind(full, 4))
    # negatives
    j = R.randint(0, 3)
    if j == 0:
        c.hint = {"command": "cat ~/.ssh/id_ed25519.pub"}
        return c.N("ssh_pub") + "\n"
    if j == 1:
        c.hint = {"command": "cat certs/chain.pem"}
        return c.N("cert") + "\n" + c.N("cert") + "\n"
    if j == 2:
        c.hint = {"command": "ssh-keygen -lf ~/.ssh/id_ed25519.pub"}
        return "256 %s %s (ED25519)\n" % (c.N("fingerprint"), email())
    return "%s\n" % c.N("pubkey")


# ======================================================================= token-output
def _gcloud_id_jwt():
    now = epoch()
    return g_jwt("RS256", {"iss": "https://accounts.google.com", "azp": "32555940559.apps.googleusercontent.com",
                           "aud": "32555940559.apps.googleusercontent.com", "sub": rs(DIG, 21), "email": email(),
                           "email_verified": True, "iat": now, "exp": now + 3600})


def _az_jwt():
    now = epoch()
    t = n_uuid()
    return g_jwt("RS256", {"aud": "https://management.azure.com/", "iss": "https://sts.windows.net/%s/" % t, "iat": now,
                           "nbf": now, "exp": now + 4000, "oid": n_uuid(), "tid": t, "upn": email()})


def _ecr():
    return b64(jd({"payload": b64(rb(R.randint(500, 800))), "datakey": b64(rb(180)), "version": "2", "type": "DATA_KEY",
                   "expiration": epoch()}).encode())


TOKEN_CMDS = [
    ("gh auth token", lambda: ("github_oauth", gh_token("gho_"))),
    ("gh auth token --hostname github.%s" % "acme-corp.io", lambda: ("github_pat", gh_token("ghp_"))),
    ("gcloud auth print-access-token", lambda: ("google_oauth_access_token", GEN["google_oauth_access_token"]())),
    ("gcloud auth print-identity-token", lambda: ("jwt", _gcloud_id_jwt())),
    ("cat ~/.vault-token", lambda: ("vault_token", GEN["vault_token"]())),
    ("vault print token", lambda: ("vault_token", GEN["vault_token"]())),
    ("aws ecr get-login-password --region us-east-1", lambda: ("aws_ecr_password", _ecr())),
    ("aws configure get aws_secret_access_key", lambda: ("aws_secret_access_key", GEN["aws_secret_access_key"]())),
    ("heroku auth:token", lambda: ("heroku_api_key", GEN["heroku_api_key"]())),
    ("az account get-access-token --query accessToken -o tsv", lambda: ("jwt", _az_jwt())),
    ("kubectl create token deployer -n ci", lambda: ("jwt", g_jwt("RS256"))),
    ("op read 'op://Engineering/Partner API/credential'", lambda: (lambda k: (k, GEN[k]()))(pick(GENERIC_KINDS))),
    ("pass show prod/postgres", lambda: (lambda k: (k, GEN[k]()))(pick(PASSWORD_KINDS))),
    ("security find-generic-password -s deploy -w", lambda: (lambda k: (k, GEN[k]()))(pick(PASSWORD_KINDS))),
    ("openssl rand -hex 32", lambda: ("generic_hex", rs(HEX, 64))),
    ("openssl rand -base64 32", lambda: ("generic_b64", b64(rb(32)))),
    ("python3 -c 'import secrets; print(secrets.token_urlsafe(32))'", lambda: ("generic_b64url", b64u(rb(32)))),
    ("head -c 48 /dev/urandom | base64", lambda: ("generic_b64", b64(rb(48)))),
    ("pwgen -s 32 1", lambda: ("generic_b62", rtok(B62, 32))),
    ("terraform output -raw db_password", lambda: ("password_random", pw_random())),
    ("kubectl get secret app-secrets -o jsonpath='{.data.API_KEY}' | base64 -d", lambda: (lambda k: (k, GEN[k]()))(pick(GENERIC_KINDS))),
    ("cat /run/secrets/api_token", lambda: (lambda k: (k, GEN[k]()))(pick(GENERIC_KINDS))),
    ("doppler secrets get STRIPE_SECRET_KEY --plain", lambda: ("stripe_secret_key", GEN["stripe_secret_key"]())),
    ("gh api -X POST /app/installations/%d/access_tokens --jq .token" % 41872210, lambda: ("github_app_token", gh_token("ghs_"))),
    ("echo $ANTHROPIC_API_KEY", lambda: ("anthropic_key", GEN["anthropic_key"]())),
    ("printenv OPENAI_API_KEY", lambda: ("openai_key", GEN["openai_key"]())),
    ("az storage account keys list -n %sstore --query '[0].value' -o tsv" % "orion", lambda: ("azure_storage_key", GEN["azure_storage_key"]())),
    ("jq -r '.auths[\"ghcr.io\"].auth' ~/.docker/config.json", lambda: ("basic_auth", b64(("%s:%s" % (user(), gh_token("ghp_"))).encode()))),
    ("npm config get //registry.npmjs.org/:_authToken", lambda: ("npm_token", GEN["npm_token"]())),
    ("cat ~/.config/%s/token" % "lumen", lambda: (lambda k: (k, GEN[k]()))(pick(GENERIC_KINDS))),
    ("vault kv get -field=api_key secret/%s" % "billing", lambda: (lambda k: (k, GEN[k]()))(pick(GENERIC_KINDS))),
]

TOKEN_NEG_CMDS = [
    ("git rev-parse HEAD", "git_sha"), ("uuidgen | tr A-Z a-z", "uuid"), ("docker inspect --format '{{.Id}}' web", "docker_digest"),
    ("kubectl get ns default -o jsonpath='{.metadata.uid}'", "uuid"), ("echo $OPENAI_API_KEY", "placeholder"),
    ("cat ~/.ssh/id_ed25519.pub", "ssh_pub"), ("git log -1 --format=%h", "short_sha"), ("openssl x509 -in ca.pem -noout -pubkey", "pubkey"),
]


@T("token-output", 50)
def t_token(c):
    if chance(0.14):
        cmd, nk = pick(TOKEN_NEG_CMDS)
        c.hint = {"command": cmd}
        return c.N(nk) + "\n"
    cmd, f = pick(TOKEN_CMDS)
    kind, v = f()
    c.S(kind, v)
    c.hint = {"command": cmd}
    pre = ""
    if cmd.startswith("heroku") and chance(0.5):
        pre = " ›   Warning: token will expire %s\n ›   Use heroku authorizations:create to generate a long-term token\n" % dt().strftime("%m/%d/%Y")
    return pre + v + pick(["\n", "\n", ""])


# ======================================================================= main
def family(kind):
    if kind in GENERIC:
        return "generic"
    if kind in PASSWORDS or kind in ("url_password", "basic_auth", "k8s_secret_b64", "password_reset_token"):
        return "password"
    if "private_key" in kind:
        return "keymat"
    if kind in V or kind in ("aws_session_token", "s3_presigned_signature", "gcs_signed_url_signature", "azure_sas_signature",
                             "slack_webhook", "discord_webhook", "teams_webhook", "zapier_webhook"):
        return "vendor"
    return "other"


def finalize(c, text, idx):
    seen = set()
    secrets, kinds = [], []
    for v, k, d in c.sec:
        s = esc(v, d)
        if s in seen:
            continue
        seen.add(s)
        secrets.append(s)
        kinds.append(k)
    keep = []
    for v, d in c.kp:
        k = esc(v, d)
        if not k or k in keep or k in seen:
            continue
        if any(k in s or s in k for s in secrets):
            continue
        keep.append(k)
    for v in secrets + keep:
        if v not in text:
            raise AssertionError("value not in text: ctx=%s val=%r\n---\n%s" % (c.context, v[:120], text[:3000]))
    for s in secrets:
        assert len(s) >= 5, (c.context, s)
        for k in keep:
            assert k not in s and s not in k, (c.context, k, s)
    rec = {"id": "devc-%04d" % idx, "kind": kinds[0] if kinds else "negative", "context": c.context,
           "text": text, "secrets": secrets, "keep": keep, "secret_kinds": kinds}
    if c.hint:
        rec["hint"] = c.hint
    return rec


def main():
    built = []
    for ctx, fn, n in TEMPLATES:
        for _ in range(n):
            c = Case(ctx)
            text = fn(c)
            built.append((c, text))
    R.shuffle(built)
    recs = [finalize(c, t, i + 1) for i, (c, t) in enumerate(built)]
    with io.TextIOWrapper(gzip.GzipFile(OUT, "wb", mtime=0), encoding="utf-8") as f:
        for r in recs:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    n_sec = sum(len(r["secrets"]) for r in recs)
    n_keep = sum(len(r["keep"]) for r in recs)
    n_neg = sum(1 for r in recs if not r["secrets"])
    kinds = collections.Counter(k for r in recs for k in r["secret_kinds"])
    fams = ["vendor", "generic", "password", "keymat", "other"]
    fam_tot = collections.Counter(family(k) for r in recs for k in r["secret_kinds"])
    print("wrote %s" % OUT)
    print("cases=%d  negative_cases=%d  secrets=%d  keep=%d  secret_kinds=%d" % (len(recs), n_neg, n_sec, n_keep, len(kinds)))
    print("secret families: " + ", ".join("%s=%d (%.0f%%)" % (f, fam_tot[f], 100.0 * fam_tot[f] / max(1, n_sec)) for f in fams))
    ctxs = collections.OrderedDict()
    for r in sorted(recs, key=lambda r: r["context"]):
        d = ctxs.setdefault(r["context"], collections.Counter())
        d["cases"] += 1
        d["neg"] += 0 if r["secrets"] else 1
        d["keep"] += len(r["keep"])
        for k in r["secret_kinds"]:
            d[family(k)] += 1
            d["secrets"] += 1
    hdr = "%-17s %5s %4s %6s %5s " % ("context", "cases", "neg", "secr", "keep") + " ".join("%8s" % f for f in fams)
    print(hdr)
    print("-" * len(hdr))
    for ctx, d in ctxs.items():
        print("%-17s %5d %4d %6d %5d " % (ctx, d["cases"], d["neg"], d["secrets"], d["keep"]) + " ".join("%8d" % d[f] for f in fams))
    if "--kinds" in sys.argv:
        for k, n in sorted(kinds.items(), key=lambda kv: (-kv[1], kv[0])):
            print("  %-30s %d" % (k, n))


if __name__ == "__main__":
    main()
