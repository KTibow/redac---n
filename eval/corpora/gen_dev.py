#!/usr/bin/env python3
"""Generate the dev evaluation corpus for the secret-redaction library.

Deterministic (seeded), stdlib only.  Run with:

    python3 -I eval/corpora/gen_dev.py

Writes dev.jsonl.gz next to this file.  Each line:
  {"id", "kind", "context", "text", "secrets", "keep", "secret_kinds", "hint"?}

All secret material is generated here with a seeded PRNG in realistic vendor
formats; none of it is a live credential.
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

SEED = 0x5EC12E7
R = random.Random(SEED)
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dev.jsonl.gz")

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


# --------------------------------------------------------------------------- case object
class Case:
    def __init__(self, context):
        self.context = context
        self.hint = None
        self.secrets = []
        self.kinds = []
        self.keep = []

    def S(self, kind=None, value=None):
        """Generate (or record) a secret.  Returns the display string to put in text."""
        if kind is None:
            kind = pick_kind()
        if value is not None:
            self.secrets.append(value)
            self.kinds.append(kind)
            return value
        r = GEN[kind]()
        if isinstance(r, dict):
            for k, s in r["s"]:
                self.secrets.append(s)
                self.kinds.append(k)
            for k in r.get("k", []):
                if chance(0.7):
                    self.keep.append(k)
            return r["d"]
        self.secrets.append(r)
        self.kinds.append(kind)
        return r

    def K(self, v):
        self.keep.append(v)
        return v

    def N(self, nk):
        return self.K(NEG[nk]())

    def escape_all(self, fn):
        self.secrets = [fn(s) for s in self.secrets]
        self.keep = [fn(k) for k in self.keep]


def jesc(s):
    return json.dumps(s)[1:-1]


TEMPLATES = []


def T(context, n):
    def deco(fn):
        TEMPLATES.append((context, fn, n))
        return fn
    return deco


# --------------------------------------------------------------------------- shared building blocks
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


def qv(v, q=None):
    q = q if q is not None else pick(["", "", '"', "'"])
    return q + v + q


# ======================================================================= TEMPLATES
def dq(v, p=0.3):
    if " " in v or "#" in v or "&" in v or chance(p):
        return '"%s"' % v
    return v


# ----------------------------------------------------------------------- env-dump
@T("env-dump", 50)
def t_printenv(c):
    cmd = pick(["printenv", "env", "env | sort", "docker exec %s-api env" % svc(), "kubectl exec deploy/%s -- env" % svc(),
                "heroku run env -a %s" % proj(), "export -p", "cat /proc/1/environ | tr '\\0' '\\n'"])
    c.hint = {"command": cmd}
    pairs = [tuple(l.split("=", 1)) for l in base_env_lines(R.randint(4, 9))]
    for _ in range(R.randint(1, 3)):
        pairs.append(env_secret(c))
    for _ in range(R.randint(2, 5)):
        pairs.append(env_neg(c))
    if chance(0.5) or "sort" in cmd:
        pairs.sort()
    else:
        R.shuffle(pairs)
    if cmd == "export -p":
        return L(*['declare -x %s="%s"' % (n, v) for n, v in pairs])
    return L(*["%s=%s" % p for p in pairs])


@T("env-dump", 16)
def t_printenv_neg(c):
    c.hint = {"command": pick(["printenv", "env", "env | sort", "docker exec web env"])}
    pairs = [tuple(l.split("=", 1)) for l in base_env_lines(R.randint(5, 10))]
    for _ in range(R.randint(3, 7)):
        pairs.append(env_neg(c))
    pairs.sort()
    return L(*["%s=%s" % p for p in pairs])


@T("env-dump", 12)
def t_env_grep(c):
    pat = pick(["KEY", "TOKEN", "SECRET", "PASS", "AWS", "API"])
    c.hint = {"command": "env | grep -i %s" % pat.lower()}
    lines = []
    for _ in range(R.randint(1, 3)):
        n, v = env_secret(c)
        lines.append("%s=%s" % (n, v))
    if chance(0.6):
        n, v = env_neg(c)
        lines.append("%s=%s" % (n, v))
    lines.append(pick(["PASSWORD_MIN_LENGTH=12", "TOKEN_TTL=3600", "API_KEY_HEADER=X-API-Key", "SECRET_NAME=prod/api/keys"]))
    c.K(lines[-1])
    R.shuffle(lines)
    return L(*lines)


# ----------------------------------------------------------------------- dotenv
DOTENV_SECTIONS = ["# --- Database ---", "# Third-party APIs", "# Payments", "## Auth", "# Observability",
                   "# Email", "# AWS", "# Feature flags", "# --- Storage ---", "# LLM providers"]


@T("dotenv", 48)
def t_dotenv(c):
    path = pick([".env", ".env", ".env.local", ".env.production", "config/.env", "apps/api/.env", ".envrc", "docker/.env"])
    c.hint = {"command": pick(["cat ", "bat --plain ", "head -50 "]) + path, "path": path}
    exp = "export " if (path == ".envrc" or chance(0.12)) else ""
    lines = []
    if chance(0.5):
        lines.append(pick(["# Local development settings", "# DO NOT COMMIT", "# generated by scripts/bootstrap.sh",
                           "# copy of staging values - rotate after demo", "# see docs/configuration.md"]))
    blocks = R.randint(2, 4)
    for b in range(blocks):
        if chance(0.6):
            if lines:
                lines.append("")
            lines.append(pick(DOTENV_SECTIONS))
        for _ in range(R.randint(1, 2)):
            n, v = env_secret(c)
            lines.append("%s%s=%s" % (exp, n, dq(v)))
        for _ in range(R.randint(1, 3)):
            n, v = env_neg(c)
            lines.append("%s%s=%s" % (exp, n, dq(v, 0.1)))
        if chance(0.3):
            lines.append(pick(["DEBUG=false", "LOG_FORMAT=json", "PORT=8080", "WORKERS=4", "# TODO: move to vault",
                               "#OLD_KEY=revoked", "ENABLE_SIGNUP=true", "TOKEN_URL_PATH=/oauth/token"]))
    return L(*lines) + "\n"


@T("dotenv", 20)
def t_dotenv_example(c):
    path = pick([".env.example", ".env.sample", ".env.template", "example.env"])
    c.hint = {"command": "cat " + path, "path": path}
    lines = ["# Copy this file to .env and fill in the values", ""]
    names = R.sample(["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "STRIPE_SECRET_KEY", "GITHUB_TOKEN", "DATABASE_URL",
                      "SLACK_BOT_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "JWT_SECRET", "SESSION_SECRET",
                      "SENDGRID_API_KEY", "REDIS_URL", "DB_PASSWORD"], R.randint(4, 7))
    for n in names:
        r = R.random()
        if r < 0.45:
            v = c.N("placeholder")
        elif r < 0.6:
            v = ""
        elif r < 0.75 and n.startswith("AWS"):
            v = c.N("aws_example")
        elif n in ("DATABASE_URL", "REDIS_URL"):
            v = c.K(pick(["postgres://user:password@localhost:5432/app", "postgresql://postgres:postgres@localhost/dev",
                          "redis://localhost:6379/0", "postgres://USER:PASS@HOST:5432/DB"]))
        else:
            v = c.K(pick(["your-%s-here" % kebab(n), "<%s>" % n.lower(), "replace-me", "xxxx"]))
        lines.append("%s=%s" % (n, v))
    for _ in range(R.randint(1, 3)):
        n, v = env_neg(c)
        lines.append("%s=%s" % (n, v))
    lines.append(pick(["PASSWORD_MIN_LENGTH=12", "# Password must be at least 12 characters", "TOKEN_URL=https://auth.%s/oauth/token" % dom()]))
    c.K(lines[-1])
    return L(*lines)


# ----------------------------------------------------------------------- python
PY_INIT = {
    "openai_key": ['client = OpenAI(api_key="{v}")', 'openai.api_key = "{v}"'],
    "anthropic_key": ['client = anthropic.Anthropic(api_key="{v}")', 'client = Anthropic(api_key="{v}", max_retries=3)'],
    "stripe_secret_key": ['stripe.api_key = "{v}"'],
    "stripe_test_key": ['stripe.api_key = "{v}"'],
    "slack_bot_token": ['client = WebClient(token="{v}")', 'app = App(token="{v}", signing_secret=os.environ["SLACK_SIGNING_SECRET"])'],
    "github_pat": ['gh = Github("{v}")', 'g = Github(auth=Auth.Token("{v}"))'],
    "github_fine_grained": ['gh = Github("{v}")'],
    "sendgrid_key": ['sg = SendGridAPIClient("{v}")'],
    "huggingface_token": ['login(token="{v}")', 'api = HfApi(token="{v}")'],
    "aws_secret_access_key": ['s3 = boto3.client("s3", aws_secret_access_key="{v}")'],
    "google_api_key": ['genai.configure(api_key="{v}")', 'gmaps = googlemaps.Client(key="{v}")'],
    "telegram_bot_token": ['bot = telebot.TeleBot("{v}")', 'application = ApplicationBuilder().token("{v}").build()'],
    "discord_bot_token": ['bot.run("{v}")'],
    "groq_key": ['client = Groq(api_key="{v}")'],
    "replicate_token": ['client = replicate.Client(api_token="{v}")'],
    "databricks_token": ['w = WorkspaceClient(host="https://dbc-{h}.cloud.databricks.com", token="{v}")'],
    "notion_token": ['notion = Client(auth="{v}")'],
    "linear_key": ['headers = {{"Authorization": "{v}"}}'],
}
PY_POS = ['client = LumenClient("{v}")', 'sdk.init("{v}")', 'configure("{v}", region="eu-west-1")',
          'api = Orbit("{v}", timeout=30)', 'tracker = Tracker.from_key("{v}")', 'signer = HMACSigner(b"{v}")',
          'conn = relay.connect("wss://relay.example.net/v2", "{v}")', 'cipher = Fernet(b"{v}")',
          'session.headers["X-Lumen"] = "{v}"', 'payload = {{"value": "{v}", "region": "eu"}}',
          'feed = FeedReader(endpoint, "{v}")', 'client.set_auth("{v}")']


def fmt(t, **kw):
    return t.replace("{{", "\x00").replace("}}", "\x01").format(**kw).replace("\x00", "{").replace("\x01", "}")


def py_secret_line(c, kind=None):
    kind = kind or pick_kind(allow_url=False)
    v = c.S(kind)
    if kind in PY_INIT and chance(0.75):
        return fmt(pick(PY_INIT[kind]), v=v, h=rs(HEX, 8))
    if kind in GENERIC and chance(0.6):
        return fmt(pick(PY_POS), v=v)
    q = pick(['"', "'"])
    name = snake(env_name(kind))
    if chance(0.2):
        return "%s = os.environ.get(%s%s%s, %s%s%s)" % (name, q, name.upper(), q, q, v, q)
    return "%s = %s%s%s" % (name.upper() if chance(0.5) else name, q, v, q)


def py_neg_line(c):
    k = R.randint(0, 11)
    if k == 0:
        return 'API_KEY = os.environ["%s"]' % c.K(pick(["OPENAI_API_KEY", "STRIPE_SECRET_KEY", "LUMEN_API_KEY"]))
    if k == 1:
        return 'EXPECTED_DIGEST = "%s"' % c.N("sha256")
    if k == 2:
        return 'DEFAULT_ORG_ID = "%s"' % c.N("uuid")
    if k == 3:
        return 'REVISION = "%s"  # pinned commit' % c.N("git_sha")
    if k == 4:
        return 'token = os.getenv("GITHUB_TOKEN", "%s")' % c.N("placeholder")
    if k == 5:
        return 'PASSWORD_MIN_LENGTH = %d' % pick([8, 12, 16])
    if k == 6:
        return 'TOKEN_URL = "%s"' % c.K("https://oauth2.%s/token" % dom())
    if k == 7:
        return 'customer_id = "%s"' % c.N("stripe_obj")
    if k == 8:
        return 'MODEL = "%s"' % c.K(pick(["claude-sonnet-4-5", "gpt-4o-mini", "claude-opus-4-1", "text-embedding-3-small"]))
    if k == 9:
        return 'key = hashlib.sha256(payload).hexdigest()'
    if k == 10:
        return 'aws_access_key_id = "%s"  # from the AWS docs' % c.N("aws_example")
    return 'trace_id = "%s"' % c.N("trace_id")


PY_IMPORTS = ["import os", "import json", "import logging", "import requests", "import boto3", "from openai import OpenAI",
              "import anthropic", "import stripe", "from slack_sdk import WebClient", "import hashlib", "from github import Github",
              "from datetime import datetime, timezone", "import httpx"]


@T("python-code", 34)
def t_py_script(c):
    path = pick(["scripts/sync_%s.py" % svc(), "app/clients.py", "notebooks/explore.py", "tools/backfill.py", "%s/config.py" % pick(PROJECTS), "main.py"])
    c.hint = {"command": "cat " + path, "path": path}
    lines = sorted(R.sample(PY_IMPORTS, R.randint(2, 5)))
    lines += ["", "log = logging.getLogger(__name__)" if chance(0.4) else "BASE_URL = \"%s\"" % c.K("https://api.%s/v1" % dom()), ""]
    body = []
    for _ in range(R.randint(1, 3)):
        body.append(py_secret_line(c))
    for _ in range(R.randint(1, 3)):
        body.append(py_neg_line(c))
    R.shuffle(body)
    lines += body
    lines += ["", "", "def %s():" % pick(["main", "sync", "run", "fetch_all"]),
              '    resp = requests.get(f"{BASE_URL}/%s", timeout=10)' % pick(["orders", "items", "users"]) if "BASE_URL" in "\n".join(lines) else "    pass",
              "    resp.raise_for_status()" if "BASE_URL" in "\n".join(lines) else "",
              "", 'if __name__ == "__main__":', "    main()" if chance(0.5) else "    sync()"]
    return L(*lines)


@T("python-code", 14)
def t_py_django_settings(c):
    c.hint = {"command": "cat %s/settings/%s.py" % (pick(PROJECTS), pick(["prod", "base", "local"]))}
    sk = c.S("django_secret_key")
    pw = c.S(pick(PASSWORD_KINDS))
    h = c.K(host())
    u = c.K(user())
    lines = ["from .base import *  # noqa", "", "DEBUG = False",
             "ALLOWED_HOSTS = [\"%s\"]" % c.K("%s.%s" % (pick(["app", "www", "api"]), dom())), "",
             "SECRET_KEY = '%s'" % sk, "",
             "DATABASES = {", "    'default': {", "        'ENGINE': 'django.db.backends.postgresql',",
             "        'NAME': '%s'," % svc(), "        'USER': '%s'," % u, "        'PASSWORD': '%s'," % pw,
             "        'HOST': '%s'," % h, "        'PORT': '5432',", "    }", "}", "",
             "AUTH_PASSWORD_VALIDATORS = [",
             "    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 12}},",
             "]", "SESSION_COOKIE_AGE = 1209600"]
    if chance(0.6):
        k = pick(["sendgrid_key", "generic_b62", "mailgun_key", "password_human"])
        lines += ["", "EMAIL_HOST = 'smtp.%s'" % pick(["sendgrid.net", "mailgun.org", dom()]), "EMAIL_HOST_USER = 'apikey'",
                  "EMAIL_HOST_PASSWORD = '%s'" % c.S(k)]
    if chance(0.5):
        lines += ["AWS_STORAGE_BUCKET_NAME = '%s'" % c.K("%s-static" % pick(PROJECTS)),
                  "AWS_S3_CUSTOM_DOMAIN = '%s.cloudfront.net'" % rs(LALNUM, 14)]
    return L(*lines)


@T("python-code", 18)
def t_py_requests(c):
    c.hint = {"command": "sed -n '1,40p' %s" % pick(["client.py", "integrations/partner.py", "src/api.py"])}
    url = c.K("https://%s.%s/api/%s" % (pick(["partner", "api", "data", "feeds"]), dom(), pick(["v1/events", "v2/report", "items"])))
    k = pick_kind(allow_url=False)
    v = c.S(k)
    hdr = pick(["X-Lumen", "X-Api-Key", "Authorization", "X-Auth", "X-Partner-Sig", "X-Orbit", "Api-Key"])
    if hdr == "Authorization":
        v = pick(["Bearer ", "Token ", "token "]) + v
    lines = ["import requests", "", "HEADERS = {", '    "%s": "%s",' % (hdr, v),
             '    "Content-Type": "application/json",', '    "X-Request-Id": "%s",' % c.N("uuid"), "}", "",
             "def push(events):", '    r = requests.post("%s", headers=HEADERS, json={"events": events}, timeout=5)' % url,
             "    r.raise_for_status()", "    return r.json()"]
    if chance(0.5):
        lines += ["", "", "def lookup(id_):",
                  '    return requests.get("%s/" + id_, params={"key": "%s"}).json()' % (url, c.S())]
    return L(*lines)


@T("python-code", 10)
def t_py_boto(c):
    c.hint = {"command": "cat upload.py", "path": "upload.py"}
    ak = c.S("aws_access_key_id")
    sk = c.S("aws_secret_access_key")
    b = c.K("%s-%s" % (pick(PROJECTS), pick(["uploads", "backups", "exports"])))
    r = pick(REGIONS)
    lines = ["import boto3", "", "session = boto3.Session(", '    aws_access_key_id="%s",' % ak,
             '    aws_secret_access_key="%s",' % sk, '    region_name="%s",' % r, ")",
             's3 = session.client("s3")', 's3.upload_file("out/report.csv", "%s", "reports/%s.csv")' % (b, c.N("ulid")),
             '# last upload ETag: %s' % c.N("etag")]
    return L(*lines)


@T("python-code", 14)
def t_py_neg(c):
    c.hint = {"command": "cat %s" % pick(["settings.py", "app/config.py", "utils/ids.py"])}
    lines = ["import os", "import hashlib", "import uuid", "", "# all secrets come from the environment",
             'OPENAI_API_KEY = os.environ["OPENAI_API_KEY"]',
             'DB_PASSWORD = os.environ.get("DB_PASSWORD", "")']
    for _ in range(R.randint(3, 6)):
        lines.append(py_neg_line(c))
    lines += ["", "def new_id() -> str:", "    return uuid.uuid4().hex", "",
              "def fingerprint(data: bytes) -> str:", "    return hashlib.sha1(data).hexdigest()"]
    return L(*lines)


# ----------------------------------------------------------------------- javascript / typescript
JS_INIT = {
    "stripe_secret_key": ["const stripe = new Stripe('{v}', {{ apiVersion: '2024-06-20' }});", "const stripe = require('stripe')('{v}');"],
    "stripe_test_key": ["const stripe = require('stripe')('{v}');"],
    "openai_key": ["const openai = new OpenAI({{ apiKey: '{v}' }});"],
    "anthropic_key": ["const anthropic = new Anthropic({{ apiKey: \"{v}\" }});"],
    "github_pat": ["const octokit = new Octokit({{ auth: '{v}' }});"],
    "github_fine_grained": ["const octokit = new Octokit({{ auth: \"{v}\" }});"],
    "slack_bot_token": ["const web = new WebClient('{v}');"],
    "sendgrid_key": ["sgMail.setApiKey('{v}');"],
    "twilio_auth_token": ["const client = twilio(accountSid, '{v}');"],
    "mailgun_key": ["const mg = mailgun.client({{ username: 'api', key: '{v}' }});"],
    "discord_bot_token": ["client.login('{v}');"],
    "jwt": ["axios.defaults.headers.common['Authorization'] = 'Bearer {v}';"],
    "resend_key": ["const resend = new Resend('{v}');"],
    "npm_token": ["// npm token for publish: {v}"],
}
JS_POS = ["const client = createClient('{v}');", "lumen.init('{v}');", "sdk.configure(\"{v}\");",
          "const api = new Orbit('{v}', {{ region: 'eu' }});", "headers: {{ 'X-Lumen': '{v}' }},",
          "const sig = crypto.createHmac('sha256', '{v}').update(body).digest('hex');",
          "analytics.load(\"{v}\");", "export const relay = connect(`wss://relay.example.net`, '{v}');"]


def js_secret_line(c, kind=None, ts=False):
    kind = kind or pick_kind(allow_url=False)
    v = c.S(kind)
    if kind in JS_INIT and chance(0.75):
        return fmt(pick(JS_INIT[kind]), v=v)
    if kind in GENERIC and chance(0.6):
        return fmt(pick(JS_POS), v=v)
    name = camel(env_name(kind)) if chance(0.6) else env_name(kind)
    q = pick(["'", '"', "`"])
    return "%s %s%s = %s%s%s;" % (pick(["const", "export const", "let"]), name, ": string" if ts and chance(0.5) else "", q, v, q)


def js_neg_line(c):
    k = R.randint(0, 9)
    if k == 0:
        return "const apiKey = process.env.%s;" % c.K(pick(["OPENAI_API_KEY", "STRIPE_SECRET_KEY", "LUMEN_KEY"]))
    if k == 1:
        return "const publishableKey = '%s';" % c.N("stripe_pk")
    if k == 2:
        return "const GOOGLE_CLIENT_ID = '%s';" % c.N("google_client_id")
    if k == 3:
        return "const BUILD_SHA = '%s';" % c.N("git_sha")
    if k == 4:
        return "const DEFAULT_TENANT = '%s';" % c.N("uuid")
    if k == 5:
        return "const TOKEN_URL = '%s';" % c.K("https://auth.%s/oauth/token" % dom())
    if k == 6:
        return "const PASSWORD_MIN_LENGTH = %d;" % pick([8, 12])
    if k == 7:
        return "// e.g. sk_live_... (never commit real keys)"
    if k == 8:
        return "const placeholder = '%s';" % c.N("placeholder")
    return "const requestId = '%s';" % c.N("request_id")


@T("js-code", 28)
def t_js_module(c):
    ext = pick(["js", "mjs", "ts", "ts", "tsx"])
    ts = ext.startswith("ts")
    path = pick(["src/lib/clients.", "server/config.", "src/index.", "lib/payments.", "api/handler."]) + ext
    c.hint = {"command": "cat " + path, "path": path}
    imports = R.sample(["import Stripe from 'stripe';", "import OpenAI from 'openai';", "import axios from 'axios';",
                        "import { WebClient } from '@slack/web-api';", "import crypto from 'node:crypto';",
                        "import { Octokit } from '@octokit/rest';", "import express from 'express';"], R.randint(2, 4))
    body = [js_secret_line(c, ts=ts) for _ in range(R.randint(1, 3))] + [js_neg_line(c) for _ in range(R.randint(1, 3))]
    R.shuffle(body)
    tail = pick([["", "export async function handler(req, res) {", "  const { id } = req.query;",
                  "  const data = await fetchOrder(id);", "  res.json(data);", "}"],
                 ["", "app.listen(process.env.PORT ?? 3000, () => console.log('listening'));"],
                 ["", "export default { stripe, openai };"], []])
    return L(*(imports + [""] + body + tail))


@T("js-code", 12)
def t_js_config_obj(c):
    path = pick(["config/production.js", "src/config.ts", "firebase.config.js", "next.config.js"])
    c.hint = {"command": "cat " + path, "path": path}
    lines = ["module.exports = {" if path.endswith(".js") else "export const config = {"]
    entries = []
    for _ in range(R.randint(2, 3)):
        k = pick_kind(allow_url=True)
        v = c.S(k)
        entries.append("  %s: '%s'," % (camel(env_name(k)), v))
    for _ in range(R.randint(2, 4)):
        n, v = env_neg(c)
        entries.append("  %s: '%s'," % (camel(n), v))
    entries.append("  port: %d," % pick([3000, 8080]))
    R.shuffle(entries)
    lines += entries + ["};"]
    return L(*lines)


@T("js-code", 10)
def t_js_neg(c):
    path = pick(["src/api/client.ts", "lib/env.js", "src/utils/hash.ts"])
    c.hint = {"command": "cat " + path, "path": path}
    lines = ["import { z } from 'zod';", "", "const Env = z.object({", "  STRIPE_SECRET_KEY: z.string().startsWith('sk_'),",
             "  DATABASE_URL: z.string().url(),", "  JWT_SECRET: z.string().min(32),", "});", "",
             "export const env = Env.parse(process.env);", ""]
    for _ in range(R.randint(3, 5)):
        lines.append(js_neg_line(c))
    lines += ["", "export const cdnAsset = '/static/js/%s';" % c.N("chunk"),
              "export const className = '%s';" % c.N("cssmod")]
    return L(*lines)


# ----------------------------------------------------------------------- go
@T("go-code", 22)
def t_go(c):
    path = pick(["main.go", "internal/client/client.go", "cmd/worker/main.go", "pkg/notify/slack.go"])
    c.hint = {"command": "cat " + path, "path": path}
    k1 = pick_kind(allow_url=False)
    v1 = c.S(k1)
    name = pascal(env_name(k1)) if chance(0.5) else camel(env_name(k1))
    lines = ["package %s" % pick(["main", "client", "notify"]), "", "import (", '\t"context"', '\t"database/sql"',
             '\t"net/http"', '\t"os"', ")", "", "const (", '\t%s = "%s"' % (name, v1),
             '\tbaseURL = "%s"' % c.K("https://api.%s" % dom()), ")", ""]
    if chance(0.6):
        dsn = c.S("db_url") if chance(0.5) else "host=%s user=%s password=%s dbname=%s sslmode=require" % (
            c.K(host()), c.K(user()), c.S(pick(PASSWORD_KINDS)), svc())
        lines += ["func openDB() (*sql.DB, error) {", '\treturn sql.Open("pgx", "%s")' % dsn, "}", ""]
    hv = c.S(pick_kind(allow_url=False))
    lines += ["func newRequest(ctx context.Context) (*http.Request, error) {",
              '\treq, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/v1/items", nil)',
              "\tif err != nil {", "\t\treturn nil, err", "\t}",
              '\treq.Header.Set("%s", "%s")' % (pick(["X-Lumen", "X-Api-Key", "X-Edge-Auth"]), hv),
              '\treq.Header.Set("X-Request-ID", "%s")' % c.N("uuid"),
              "\treturn req, nil", "}"]
    if chance(0.3):
        lines += ["", "// fallback for local runs", 'var debugToken = os.Getenv("DEBUG_TOKEN")']
    return L(*lines)


@T("go-code", 8)
def t_go_sum(c):
    c.hint = {"command": "cat go.sum", "path": "go.sum"}
    mods = ["github.com/aws/aws-sdk-go-v2", "github.com/jackc/pgx/v5", "golang.org/x/crypto", "github.com/stretchr/testify",
            "google.golang.org/grpc", "github.com/redis/go-redis/v9", "go.uber.org/zap", "github.com/spf13/cobra"]
    lines = []
    for m in R.sample(mods, R.randint(3, 6)):
        v = "v" + version()
        lines.append("%s %s %s" % (m, v, c.N("gosum")))
        lines.append("%s %s/go.mod %s" % (m, v, c.N("gosum")))
    return L(*lines)


# ----------------------------------------------------------------------- rust
@T("rust-code", 14)
def t_rust(c):
    path = pick(["src/main.rs", "src/client.rs", "src/config.rs"])
    c.hint = {"command": "cat " + path, "path": path}
    k = pick_kind(allow_url=False)
    v = c.S(k)
    lines = ["use reqwest::Client;", "use std::time::Duration;", "",
             'const %s: &str = "%s";' % (env_name(k), v), 'const USER_AGENT: &str = "%s/%s";' % (pick(PROJECTS), version()), ""]
    v2 = c.S()
    lines += ["#[tokio::main]", "async fn main() -> Result<(), Box<dyn std::error::Error>> {",
              "    let client = Client::builder().timeout(Duration::from_secs(10)).build()?;",
              "    let resp = client", '        .get("%s")' % c.K("https://%s.%s/v2/status" % (pick(["api", "edge"]), dom())),
              '        .header("%s", "%s")' % (pick(["X-Lumen", "Authorization", "X-Relay-Auth"]), v2),
              "        .send()", "        .await?;", '    println!("{}", resp.status());', "    Ok(())", "}"]
    if chance(0.4):
        lines += ["", "#[cfg(test)]", "mod tests {", "    #[test]", "    fn digest_is_stable() {",
                  '        assert_eq!(super::digest(b"hello"), "%s");' % c.N("sha256"), "    }", "}"]
    return L(*lines)


@T("rust-code", 5)
def t_cargo_lock(c):
    c.hint = {"command": "grep -A4 'name = ' Cargo.lock | head -40", "path": "Cargo.lock"}
    out = []
    for crate in R.sample(["serde", "tokio", "reqwest", "anyhow", "clap", "tracing", "hyper", "rand"], 4):
        out += ["[[package]]", 'name = "%s"' % crate, 'version = "%s"' % version(),
                'source = "registry+https://github.com/rust-lang/crates.io-index"', 'checksum = "%s"' % c.N("sha256"), ""]
    return L(*out)


# ----------------------------------------------------------------------- java / kotlin
@T("java-code", 14)
def t_java(c):
    cls = pick(["PaymentClient", "AppConfig", "StorageService", "NotificationSender"])
    path = "src/main/java/com/%s/%s.java" % (pick(PROJECTS), cls)
    c.hint = {"command": "cat " + path, "path": path}
    k = pick_kind(allow_url=False)
    v = c.S(k)
    pw = c.S(pick(PASSWORD_KINDS))
    u = c.K(user())
    lines = ["package com.%s;" % pick(PROJECTS), "", "import com.zaxxer.hikari.HikariConfig;", "import java.net.http.HttpClient;", "",
             "public class %s {" % cls, '    private static final String %s = "%s";' % (env_name(k), v),
             '    private static final String BUILD = "%s";' % c.N("short_sha"), "",
             "    public HikariConfig dataSource() {", "        HikariConfig cfg = new HikariConfig();",
             '        cfg.setJdbcUrl("jdbc:postgresql://%s:5432/%s");' % (c.K(host()), svc()),
             '        cfg.setUsername("%s");' % u, '        cfg.setPassword("%s");' % pw, "        return cfg;", "    }"]
    if chance(0.5):
        lines += ["", "    Client client() {", '        return new Client("%s");' % c.S(), "    }"]
    lines += ["}"]
    return L(*lines)


@T("java-properties", 14)
def t_java_props(c):
    path = pick(["src/main/resources/application.properties", "src/main/resources/application-prod.properties", "gradle.properties"])
    c.hint = {"command": "cat " + path, "path": path}
    lines = ["# %s" % pick(["Spring Boot configuration", "generated", "prod overrides"]),
             "spring.application.name=%s" % svc(), "server.port=8080",
             "spring.datasource.url=jdbc:postgresql://%s:5432/%s" % (c.K(host()), svc()),
             "spring.datasource.username=%s" % c.K(user()), "spring.datasource.password=%s" % c.S(pick(PASSWORD_KINDS))]
    if chance(0.6):
        lines.append("app.security.jwt.secret=%s" % c.S(pick(GENERIC_KINDS)))
    if chance(0.5):
        lines.append("spring.security.oauth2.client.registration.google.client-id=%s" % c.N("google_client_id"))
        lines.append("spring.security.oauth2.client.registration.google.client-secret=%s" % c.S("google_oauth_client_secret"))
    if chance(0.4):
        lines.append("signing.keyId=%s" % c.K(rs(HEXU, 8)))
        lines.append("signing.password=%s" % c.S(pick(PASSWORD_KINDS)))
        lines.append("signing.secretKeyRingFile=/home/ci/.gnupg/secring.gpg")
    if chance(0.4):
        lines.append("partner.endpoint.auth=%s" % c.S(pick(GENERIC_KINDS)))
    lines += ["app.password.min-length=12", "management.endpoints.web.exposure.include=health,info"]
    c.K("app.password.min-length=12")
    return L(*lines)


# ----------------------------------------------------------------------- c#
@T("csharp-code", 12)
def t_csharp(c):
    path = pick(["Program.cs", "Services/BlobService.cs", "Startup.cs"])
    c.hint = {"command": "cat " + path, "path": path}
    lines = ["using Azure.Storage.Blobs;", "using Microsoft.Data.SqlClient;", "", "var builder = WebApplication.CreateBuilder(args);"]
    if chance(0.6):
        lines.append('var blobs = new BlobServiceClient("%s");' % c.S("azure_storage_conn"))
    srv = c.K("tcp:%s-sql.database.windows.net" % pick(PROJECTS))
    lines.append('var conn = new SqlConnection("Server=%s,1433;Initial Catalog=%s;User ID=%s;Password=%s;Encrypt=True;");' % (
        srv, svc(), c.K(user()), c.S(pick(PASSWORD_KINDS))))
    if chance(0.6):
        lines.append('builder.Services.AddSingleton(new LumenClient("%s"));' % c.S())
    lines += ['builder.Services.AddHttpClient("partner", c => c.DefaultRequestHeaders.Add("X-Correlation-Id", "%s"));' % c.N("uuid"),
              "var app = builder.Build();", 'app.MapGet("/", () => "ok");', "app.Run();"]
    return L(*lines)


@T("json-config", 14)
def t_appsettings(c):
    path = pick(["appsettings.json", "appsettings.Production.json", "config/default.json", "secrets.json", "local.settings.json"])
    c.hint = {"command": "cat " + path, "path": path}
    d = {"Logging": {"LogLevel": {"Default": "Information", "Microsoft.AspNetCore": "Warning"}}}
    d["ConnectionStrings"] = {"Default": "Server=%s;Database=%s;User Id=%s;Password=%s;" % (
        c.K(host()), svc(), user(), c.S(pick(PASSWORD_KINDS)))}
    k = pick_kind()
    d[pick(["Partner", "Lumen", "Payments", "Integrations"])] = {
        pick(["ApiKey", "Value", "Secret", "EndpointAuth", "Data"]): c.S(k),
        "BaseUrl": c.K("https://%s.%s" % (pick(["api", "partner"]), dom())),
        "TimeoutSeconds": 30}
    if chance(0.5):
        d["AzureAd"] = {"Instance": "https://login.microsoftonline.com/", "TenantId": c.N("uuid"), "ClientId": c.N("uuid"),
                        "ClientSecret": c.S("azure_client_secret")}
    d["Build"] = {"Commit": c.N("git_sha"), "Version": version()}
    return json.dumps(d, indent=2)


# ----------------------------------------------------------------------- ruby / php
@T("ruby-code", 12)
def t_ruby(c):
    path = pick(["config/initializers/stripe.rb", "lib/tasks/sync.rake", "app/services/notifier.rb", "config/initializers/octokit.rb"])
    c.hint = {"command": "cat " + path, "path": path}
    lines = ["# frozen_string_literal: true", ""]
    r = R.randint(0, 3)
    if r == 0:
        lines += ["Stripe.api_key = '%s'" % c.S(pick(["stripe_secret_key", "stripe_restricted_key"])),
                  "Stripe.api_version = '2024-06-20'"]
    elif r == 1:
        lines += ["client = Octokit::Client.new(access_token: '%s')" % c.S(pick(["github_pat", "github_fine_grained"])),
                  "client.auto_paginate = true"]
    elif r == 2:
        lines += ["Slack.configure do |config|", "  config.token = '%s'" % c.S("slack_bot_token"), "end"]
    else:
        lines += ["LUMEN = Lumen::Client.new('%s', region: :eu)" % c.S()]
    if chance(0.6):
        lines += ["", "Redis.new(url: '%s')" % c.S("redis_url")]
    lines += ["", "Rails.logger.info(\"booted rev=%s\")" % c.N("short_sha")]
    return L(*lines)


WP_SALT = string.ascii_letters + string.digits + "!@#$%^&*()-_[]{}<>~`+=,.;:/?|"


@T("php-code", 14)
def t_php(c):
    if chance(0.45):
        c.hint = {"command": "cat wp-config.php", "path": "wp-config.php"}
        lines = ["<?php", "define( 'DB_NAME', '%s' );" % c.K("wp_" + pick(PROJECTS)),
                 "define( 'DB_USER', '%s' );" % c.K(user()), "define( 'DB_PASSWORD', '%s' );" % c.S(pick(PASSWORD_KINDS)),
                 "define( 'DB_HOST', '%s' );" % c.K(host()), "define( 'DB_CHARSET', 'utf8mb4' );", ""]
        for nm in R.sample(["AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY", "AUTH_SALT", "NONCE_SALT"], R.randint(2, 4)):
            lines.append("define( '%s', %s'%s' );" % (nm, " " * (17 - len(nm)), c.S("wordpress_salt", rs(WP_SALT, 64))))
        lines += ["", "$table_prefix = 'wp_';", "define( 'WP_DEBUG', false );"]
        return L(*lines)
    path = pick(["src/Service/PartnerClient.php", "app/Http/Controllers/WebhookController.php", "config/services.php"])
    c.hint = {"command": "cat " + path, "path": path}
    v = c.S()
    lines = ["<?php", "", "namespace App\\Service;", "", "use GuzzleHttp\\Client;", "",
             "final class PartnerClient", "{", "    private Client $http;", "", "    public function __construct()", "    {",
             "        $this->http = new Client([", "            'base_uri' => '%s'," % c.K("https://api.%s/" % dom()),
             "            'headers'  => ['%s' => '%s']," % (pick(["X-Lumen", "X-Api-Key", "Authorization"]), v),
             "        ]);", "    }", "}"]
    if chance(0.5):
        lines.insert(5, "const WEBHOOK_SECRET = '%s';" % c.S(pick(["stripe_webhook_secret", "generic_hex", "shopify_shared_secret"])))
    return L(*lines)


# ----------------------------------------------------------------------- shell / powershell
@T("shell-script", 24)
def t_shell(c):
    path = pick(["deploy.sh", "scripts/bootstrap.sh", "bin/release", "ops/rotate.sh", "run-local.sh"])
    c.hint = {"command": "cat " + path, "path": path}
    lines = ["#!/usr/bin/env bash", "set -euo pipefail", ""]
    for _ in range(R.randint(1, 2)):
        n, v = env_secret(c)
        lines.append('export %s="%s"' % (n, v))
    for _ in range(R.randint(1, 2)):
        n, v = env_neg(c)
        lines.append('export %s="%s"' % (n, v))
    lines.append("")
    r = R.randint(0, 4)
    if r == 0:
        pw = c.S(pick(PASSWORD_KINDS))
        lines.append("mysql -h %s -u %s -p'%s' %s < migrations/latest.sql" % (c.K(host()), c.K(user()), pw, svc()))
    elif r == 1:
        lines.append('curl -fsS -X POST -H "%s: %s" "%s"' % (pick(["X-Lumen", "Authorization: Bearer"]) if False else pick(["X-Lumen", "X-Api-Key"]), c.S(),
                                                              c.K("https://hooks.%s/deploy" % dom())))
    elif r == 2:
        lines.append('echo "%s" | docker login ghcr.io -u %s --password-stdin' % (c.S(pick(["github_pat", "github_fine_grained"])), c.K(pick(USERS))))
    elif r == 3:
        lines.append("PGPASSWORD='%s' psql -h %s -U %s -d %s -c 'select 1'" % (c.S(pick(PASSWORD_KINDS)), c.K(host()), c.K(user()), svc()))
    else:
        lines.append('aws s3 cp dist/ s3://%s/ --recursive' % c.K("%s-web-%s" % (pick(PROJECTS), pick(ENVS))))
    lines += ['echo "deploying $(git rev-parse --short HEAD)"', "./gradlew build -x test" if chance(0.3) else "npm run build"]
    return L(*lines)


@T("powershell", 14)
def t_powershell(c):
    path = pick(["deploy.ps1", "scripts/Setup-Dev.ps1", "Invoke-Sync.ps1"])
    c.hint = {"command": "Get-Content " + path, "path": path}
    lines = ["$ErrorActionPreference = 'Stop'", ""]
    n, v = env_secret(c, allow_url=False)
    lines.append('$env:%s = "%s"' % (n, v))
    u = c.K(pick(["CORP\\svc_deploy", "admin@%s" % dom(), "deploy"]))
    lines += ['$secure = ConvertTo-SecureString "%s" -AsPlainText -Force' % c.S(pick(PASSWORD_KINDS)),
              '$cred = New-Object System.Management.Automation.PSCredential("%s", $secure)' % u]
    if chance(0.6):
        lines.append('$headers = @{ "%s" = "%s"; "Accept" = "application/json" }' % (pick(["X-Lumen", "Authorization", "Ocp-Apim-Subscription-Key"]), c.S(pick(GENERIC_KINDS))))
        lines.append('Invoke-RestMethod -Uri "%s" -Headers $headers -Method Get' % c.K("https://%s.%s/api/status" % (svc(), dom())))
    lines += ['Enter-PSSession -ComputerName %s -Credential $cred' % c.K("%s-vm01" % svc()),
              'Write-Host "Subscription: %s"' % c.N("uuid")]
    return L(*lines)


#@@TEMPLATES@@


# ======================================================================= main

FAMILY = {}


def family(kind):
    if kind in GENERIC:
        return "generic"
    if kind in PASSWORDS or kind in ("url_password", "basic_auth", "k8s_secret_b64", "password_in_flag"):
        return "password"
    if "private_key" in kind or kind in ("kubeconfig_client_key", "gcp_service_account_key", "pgp_private_key"):
        return "keymat"
    if kind in V or kind in ("aws_session_token", "s3_presigned_signature", "gcs_signed_url_signature",
                             "azure_sas_signature", "slack_webhook", "discord_webhook", "teams_webhook",
                             "zapier_webhook"):
        return "vendor"
    return "other"


def finalize(c, text, idx):
    seen = set()
    secrets, kinds = [], []
    for s, k in zip(c.secrets, c.kinds):
        if s in seen:
            continue
        seen.add(s)
        secrets.append(s)
        kinds.append(k)
    keep = []
    for k in c.keep:
        if not k or k in keep or k in seen:
            continue
        if any(k in s or s in k for s in secrets):
            continue
        keep.append(k)
    for v in secrets + keep:
        if v not in text:
            raise AssertionError("value not in text: ctx=%s val=%r" % (c.context, v[:120]))
    for k in keep:
        for s in secrets:
            assert k not in s and s not in k
    rec = {"id": "dev-%04d" % idx, "kind": kinds[0] if kinds else "negative", "context": c.context,
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

    # ---- summary
    n_sec = sum(len(r["secrets"]) for r in recs)
    n_keep = sum(len(r["keep"]) for r in recs)
    n_neg = sum(1 for r in recs if not r["secrets"])
    kinds = collections.Counter(k for r in recs for k in r["secret_kinds"])
    ctxs = collections.OrderedDict()
    for r in sorted(recs, key=lambda r: r["context"]):
        d = ctxs.setdefault(r["context"], collections.Counter())
        d["cases"] += 1
        d["neg"] += 0 if r["secrets"] else 1
        d["keep"] += len(r["keep"])
        for k in r["secret_kinds"]:
            d[family(k)] += 1
            d["secrets"] += 1
    fams = ["vendor", "generic", "password", "keymat", "other"]
    print("wrote %s" % OUT)
    print("cases=%d  negative_cases=%d  secrets=%d  keep=%d  contexts=%d  secret_kinds=%d" % (
        len(recs), n_neg, n_sec, n_keep, len(ctxs), len(kinds)))
    fam_tot = collections.Counter(family(k) for r in recs for k in r["secret_kinds"])
    print("secret families: " + ", ".join("%s=%d (%.0f%%)" % (f, fam_tot[f], 100.0 * fam_tot[f] / max(1, n_sec)) for f in fams))
    print()
    hdr = "%-20s %5s %4s %6s %5s " % ("context", "cases", "neg", "secr", "keep") + " ".join("%7s" % f for f in fams)
    print(hdr)
    print("-" * len(hdr))
    for ctx, d in ctxs.items():
        print("%-20s %5d %4d %6d %5d " % (ctx, d["cases"], d["neg"], d["secrets"], d["keep"]) +
              " ".join("%7d" % d[f] for f in fams))
    print()
    print("secret kinds (count):")
    items = sorted(kinds.items(), key=lambda kv: (-kv[1], kv[0]))
    for i in range(0, len(items), 3):
        print("  " + "".join("%-34s" % ("%s=%d" % kv) for kv in items[i:i + 3]))
    if "--matrix" in sys.argv:
        print()
        print("context x kind matrix (nonzero cells):")
        m = collections.defaultdict(collections.Counter)
        for r in recs:
            for k in r["secret_kinds"]:
                m[r["context"]][k] += 1
        for ctx in sorted(m):
            print("  %-20s %s" % (ctx, ", ".join("%s:%d" % kv for kv in sorted(m[ctx].items()))))


if __name__ == "__main__":
    main()
