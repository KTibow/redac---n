#!/usr/bin/env python3
"""Held-out corpus generator for secret redaction (coding-agent tool output, logs, chat).

stdlib only; run with `python3 -I gen_holdout.py`. Deterministic: seed 9001.
Every secret and every random-looking keep value is produced by the seeded
generator below using the real format rules (prefixes, alphabets, lengths).
"""
import base64
import collections
import datetime
import gzip
import hashlib
import hmac
import io
import json
import os
import random
import string
import struct
import sys

SEED = 9001
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "holdout.jsonl.gz")
R = random.Random(SEED)

DIG = string.digits
LOW = string.ascii_lowercase
UP = string.ascii_uppercase
B62 = DIG + UP + LOW
HEX = "0123456789abcdef"
B64 = UP + LOW + DIG + "+/"
B64U = UP + LOW + DIG + "-_"
B32 = UP + "234567"
CROCK = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
BECH = "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L"


def rs(alpha, n):
    return "".join(R.choice(alpha) for _ in range(n))


def rhex(n):
    return rs(HEX, n)


def rbytes(n):
    return bytes(R.getrandbits(8) for _ in range(n))


def b64(b):
    return base64.b64encode(b).decode()


def b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def pick(seq):
    return R.choice(seq)


def chance(p):
    return R.random() < p


def rint(a, b):
    return R.randint(a, b)


def wrap(s, n):
    return "\n".join(s[i:i + n] for i in range(0, len(s), n))


# ---------------------------------------------------------------- flavour data
PROJ = ["billing-api", "atlas", "checkout", "ledger", "orbit", "pipeline", "harbor", "nimbus",
        "relay", "beacon", "quartz", "sparrow", "tessera", "lumen", "kestrel", "foundry",
        "acme-web", "payments-svc", "notifier", "ingest", "search-api", "auth-gateway"]
USERS = ["alice", "bob", "dmitri", "priya", "chen", "maria", "tomasz", "fatima", "kenji",
         "olu", "sam", "noor", "lucas", "ines", "raj", "hana", "diego", "yuki", "zoe", "arjun"]
FULLN = ["Alice Moreau", "Bob Okafor", "Dmitri Volkov", "Priya Raman", "Chen Wei", "Maria Lopez",
         "Tomasz Nowak", "Fatima Zahra", "Kenji Sato", "Olu Adeyemi", "Sam Carter", "Noor Haddad"]
REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-2", "ap-northeast-1"]
GREGIONS = ["us-central1", "europe-west1", "asia-east1", "us-east4"]
DOMAINS = ["acme.io", "example-corp.com", "tessera.dev", "lumenhq.com", "orbit.app", "kestrel.cloud"]
DBNAMES = ["app_production", "orders", "analytics", "core", "billing", "users_db", "warehouse"]
WORDS = ["summer", "winter", "dragon", "monkey", "sunshine", "football", "shadow", "master",
         "falcon", "tiger", "coffee", "pepper", "bailey", "charlie", "maggie", "london", "phoenix",
         "rocket", "galaxy", "hunter", "silver", "orange", "purple", "banana", "cookie", "spring",
         "autumn", "thunder", "ranger", "jordan", "harley", "matrix", "ginger", "buster", "midnight"]
NAMES = ["Jessica", "Michael", "Ashley", "Daniel", "Sophie", "Liam", "Olivia", "Mateo", "Emma",
         "Noah", "Chloe", "Ethan", "Grace", "Hugo", "Isla", "Leo"]
COMPANIES = ["Acme", "Initech", "Globex", "Umbrella", "Hooli", "Tessera", "Vandelay", "Stark"]
PHRASEW = ["maple", "orbit", "cactus", "lantern", "river", "copper", "velvet", "glacier", "ember",
           "willow", "harbor", "pixel", "tundra", "falcon", "meadow", "quartz", "saddle", "violet",
           "anchor", "breeze", "canyon", "domino", "echo", "fable", "granite", "hollow"]
# a sample of real BIP39 english words (checksum validity is irrelevant here)
BIP39 = ("abandon ability able about above absent absorb abstract absurd abuse access accident "
         "account accuse achieve acid acoustic acquire across act action actor actress actual "
         "adapt add addict address adjust admit adult advance advice aerobic affair afford afraid "
         "again age agent agree ahead aim air airport aisle alarm album alcohol alert alien all "
         "alley allow almost alone alpha already also alter always amateur amazing among amount "
         "amused analyst anchor ancient anger angle angry animal ankle announce annual another "
         "answer antenna antique anxiety any apart apology appear apple approve april arch arctic "
         "area arena argue arm armed armor army around arrange arrest arrive arrow art artefact "
         "artist artwork ask aspect assault asset assist assume asthma athlete atom attack attend "
         "attitude attract auction audit august aunt author auto autumn average avocado avoid "
         "awake aware away awesome awful awkward axis baby bachelor bacon badge bag balance "
         "balcony ball bamboo banana banner bar barely bargain barrel base basic basket battle "
         "beach bean beauty because become beef before begin behave behind believe below belt "
         "bench benefit best betray better between beyond bicycle bid bike bind biology bird "
         "birth bitter black blade blame blanket blast bleak bless blind blood blossom blouse "
         "blue blur blush board boat body boil bomb bone bonus book boost border boring borrow "
         "boss bottom bounce box boy bracket brain brand brass brave bread breeze brick bridge "
         "brief bright bring brisk broccoli broken bronze broom brother brown brush bubble buddy "
         "zebra zero zone zoo wolf woman wonder wood wool word work world worry worth wrap wreck "
         "wrestle wrist write wrong yard year yellow you young youth").split()

BASE_TIME = datetime.datetime(2026, 9, 1, 0, 0, 0)


def dt():
    return BASE_TIME + datetime.timedelta(seconds=rint(0, 40 * 86400), microseconds=rint(0, 999999))


def ts():
    return dt().strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % rint(0, 999)


def ts_plain():
    return dt().strftime("%Y-%m-%d %H:%M:%S")


def epoch():
    return int((dt() - datetime.datetime(1970, 1, 1)).total_seconds())


def ip():
    return "10.%d.%d.%d" % (rint(0, 255), rint(0, 255), rint(1, 254))


def pubip():
    return "%d.%d.%d.%d" % (pick([34, 35, 52, 54, 18, 3, 104, 151]), rint(1, 254), rint(1, 254), rint(1, 254))


def proj():
    return pick(PROJ)


def user():
    return pick(USERS)


def domain():
    return pick(DOMAINS)


def email():
    return "%s@%s" % (user(), domain())


# ---------------------------------------------------------------- case model
class Case:
    def __init__(self, ctx):
        self.ctx = ctx
        self.secrets = []
        self.keep = []
        self.cats = []      # (kind, category) per secret; category in vendor/generic/password
        self.kind = None
        self.hint = None

    def s(self, value, kind, cat="vendor"):
        if self.kind is None:
            self.kind = kind
        if value not in self.secrets:
            self.secrets.append(value)
            self.cats.append((kind, cat))
        return value

    def g(self, value, kind):
        return self.s(value, kind, "generic")

    def pw(self, value, kind="password"):
        return self.s(value, kind, "password")

    def k(self, value):
        if value not in self.keep:
            self.keep.append(value)
        return value

    def cmd(self, c):
        self.hint = {"command": c}

    def path(self, p):
        self.hint = {"path": p}


# ---------------------------------------------------------------- secret generators
def g_openai():
    v = pick(["proj", "proj", "proj", "svcacct", "admin", "legacy"])
    if v == "legacy":
        return "sk-" + rs(B62, 20) + "T3BlbkFJ" + rs(B62, 20)
    return "sk-%s-" % v + rs(B64U, rint(70, 78)) + "T3BlbkFJ" + rs(B64U, rint(70, 78))


def g_anthropic():
    if chance(0.15):
        return "sk-ant-admin01-" + rs(B64U, 93) + "AA"
    return "sk-ant-api03-" + rs(B64U, 93) + "AA"


def g_akid(temp=False):
    return ("ASIA" if temp else "AKIA") + rs(B32, 16)


def g_aws_secret():
    return rs(B62 + "+/", 40)


def g_aws_session():
    head = pick(["IQoJb3JpZ2luX2VjE", "FwoGZXIvYXdzE", "IQoJb3JpZ2luX2VjEA"])
    return head + rs(B64, rint(330, 620) // 4 * 4 - len(head))


def g_gh(prefix=None):
    p = prefix or pick(["ghp_", "ghp_", "gho_", "ghs_", "ghu_", "ghr_"])
    return p + rs(B62, 36)


def g_gh_fine():
    return "github_pat_11" + rs(UP + DIG, 20) + "_" + rs(B62, 59)


def g_gitlab():
    return pick(["glpat-", "glpat-", "gldt-", "glrt-"]) + rs(B62 + "-_", 20)


def g_slack_bot():
    return "xoxb-%d-%d-%s" % (rint(10 ** 10, 10 ** 12), rint(10 ** 12, 10 ** 13 - 1), rs(B62, 24))


def g_slack_user():
    return "xoxp-%d-%d-%d-%s" % (rint(10 ** 10, 10 ** 12), rint(10 ** 10, 10 ** 12),
                                  rint(10 ** 12, 10 ** 13 - 1), rhex(32))


def g_slack_app():
    return "xapp-1-A%s-%d-%s" % (rs(UP + DIG, 10), rint(10 ** 12, 10 ** 13 - 1), rhex(64))


def slack_hook_parts():
    return "T" + rs(UP + DIG, 10), "B" + rs(UP + DIG, 10), rs(B62, 24)


def g_stripe(kind="sk", live=True):
    env = "live" if live else "test"
    if chance(0.3):
        return "%s_%s_%s" % (kind, env, rs(B62, 24))
    return "%s_%s_51%s" % (kind, env, rs(B62, 97))


def g_whsec():
    return "whsec_" + rs(B62, 32)


def g_sendgrid():
    return "SG." + rs(B64U, 22) + "." + rs(B64U, 43)


def g_mailgun():
    return "key-" + rhex(32)


def g_google_api():
    return "AIza" + rs(B62 + "-_", 35)


def g_ya29():
    return "ya29." + rs(B64U, rint(150, 220))


def g_refresh_google():
    return "1//0" + rs(B64U, rint(95, 100))


def g_azure_secret():
    a = B62 + "~._-"
    return rs(B62, 3) + pick(["8Q~", "7Q~"]) + rs(a, 34)


def g_azure_storage():
    return b64(rbytes(64))


def g_npm():
    return "npm_" + rs(B62, 36)


def g_pypi():
    return "pypi-AgEIcHlwaS5vcmc" + rs(B64U, rint(140, 180))


def g_dockerhub():
    return "dckr_pat_" + rs(B64U, 27)


def g_hf():
    return "hf_" + rs(UP + LOW, 34)


def g_discord_bot():
    uid = str(rint(10 ** 17, 10 ** 18 * 2))
    return b64u(uid.encode()) + "." + rs(B64U, 6) + "." + rs(B64U, 38)


def g_telegram():
    return "%d:AA%s" % (rint(10 ** 8, 10 ** 10), rs(B64U, 33))


def g_shopify():
    return pick(["shpat_", "shpss_", "shpca_"]) + rhex(32)


def g_databricks():
    return "dapi" + rhex(32)


def g_sentry_auth():
    return "sntryu_" + rhex(64)


def g_linear():
    return "lin_api_" + rs(B62, 40)


def g_notion():
    return "ntn_" + rs(DIG, 11) + rs(B62, 35)


def g_postman():
    return "PMAK-" + rhex(24) + "-" + rhex(34)


def g_doppler():
    return "dp.st." + pick(["dev", "stg", "prd"]) + "." + rs(B62, 40)


def g_vault():
    return "hvs.CAESI" + rs(B64U, 86)


def g_tfc():
    return rs(B62, 14) + ".atlasv1." + rs(B62, 67)


def g_do():
    return "dop_v1_" + rhex(64)


def g_fly():
    return "fm2_" + b64(rbytes(rint(180, 260))).rstrip("=")


def g_netlify():
    return "nfp_" + rs(B62, 36)


def g_mapbox(secret=True):
    blob = b64u(json.dumps({"u": user() + str(rint(1, 99)), "a": rs(LOW + DIG, 25)},
                           separators=(",", ":")).encode())
    return ("sk." if secret else "pk.") + blob + "." + rs(B64U, 22)


def g_fcm():
    return "AAAA" + rs(B64U, 7) + ":APA91b" + rs(B64U, 134)


def g_age():
    return "AGE-SECRET-KEY-1" + rs(BECH, 58)


def g_openrouter():
    return "sk-or-v1-" + rhex(64)


def g_groq():
    return "gsk_" + rs(B62, 52)


def g_replicate():
    return "r8_" + rs(B62, 37)


def g_atlassian():
    return "ATATT3xFfGF0" + rs(B64U, 170) + "=" + rhex(8).upper()


def g_newrelic():
    return "NRAK-" + rs(UP + DIG, 27)


def g_grafana():
    return "glsa_" + rs(B62, 32) + "_" + rhex(8)


def g_pulumi():
    return "pul-" + rhex(40)


def g_square():
    return "EAAA" + rs(B64U, 60)


def g_planetscale():
    return "pscale_pw_" + rs(B64U, 43)


def g_supabase_pat():
    return "sbp_" + rhex(40)


def g_twilio_key():
    return "SK" + rhex(32)


def g_mongo_atlas_pk():
    return rs(LOW, 8)


# ---------------------------------------------------------------- generic secrets
def g_hexkey(n=None):
    return rhex(n or pick([32, 40, 48, 64]))


def g_b64key(nbytes=None):
    return b64(rbytes(nbytes or pick([24, 32, 48])))


def g_urlsafe(nbytes=None):
    return b64u(rbytes(nbytes or pick([24, 32, 32, 48])))


def g_b62key(n=None):
    return rs(B62, n or pick([24, 32, 40]))


def g_django():
    return "django-insecure-" * chance(0.3) + rs(LOW + DIG + "!@#%^&*(-_=+)", 50)


def g_rails_kb():
    return rhex(128)


def g_fernet():
    return base64.urlsafe_b64encode(rbytes(32)).decode()


def g_uuid():
    h = rhex(32)
    h = h[:12] + "4" + h[13:16] + pick("89ab") + h[17:]
    return "%s-%s-%s-%s-%s" % (h[:8], h[8:12], h[12:16], h[16:20], h[20:])


def g_generic():
    f = pick([g_hexkey, g_b64key, g_urlsafe, g_b62key, g_hexkey, g_urlsafe])
    return f()


def g_password(urlsafe=False, shell=False):
    syms = "!-_.~" if urlsafe else ("!@#%^*-_+=." if shell else "!@#$%^&*-_+=.?")
    t = R.randrange(9)
    if t == 0:
        p = pick(WORDS).capitalize() + str(rint(2015, 2026)) + pick(syms)
    elif t == 1:
        w = pick(WORDS).capitalize()
        tr = {"a": "@", "o": "0", "e": "3", "i": "1", "s": "$"}
        if urlsafe or shell:
            tr = {"a": "4", "o": "0", "e": "3", "i": "1"}
        p = "".join(tr.get(ch, ch) if chance(0.6) else ch for ch in w) + str(rint(10, 9999))
    elif t == 2:
        sep = pick(["-", ".", "_"])
        p = sep.join(pick(PHRASEW) for _ in range(rint(3, 4))) + sep + str(rint(1, 99))
    elif t == 3:
        p = rs(B62 + syms, rint(16, 28))
    elif t == 4:
        p = pick(NAMES) + str(rint(1965, 2004)) + pick(syms)
    elif t == 5:
        p = pick(COMPANIES) + pick(["@", "#", "!"] if not urlsafe else ["!", "_"]) + str(rint(2019, 2026)) + pick(syms)
    elif t == 6:
        p = rs(B62, rint(12, 16))
    elif t == 7:
        p = pick(["Qwerty", "Asdf", "Zxcv"]) + pick(syms) + pick(WORDS) + str(rint(1, 999))
    else:
        p = pick(WORDS) + pick(WORDS).capitalize() + str(rint(1, 99)) + pick(syms) * rint(1, 2)
    if len(p) < 9:
        p += str(rint(100, 999))
    return p


# ---------------------------------------------------------------- jwt / pem
def jwt_claims(**extra):
    now = epoch()
    c = {"sub": pick([g_uuid(), str(rint(1000, 999999)), "user_" + rs(B62, 10)]),
         "iat": now, "exp": now + pick([900, 3600, 86400])}
    if chance(0.6):
        c["iss"] = pick(["https://auth.%s/" % domain(), "https://%s.supabase.co/auth/v1" % rs(LOW, 20),
                         "https://securetoken.google.com/%s" % proj(), "accounts.google.com"])
    if chance(0.5):
        c["email"] = email()
    if chance(0.4):
        c["scope"] = pick(["read write", "openid profile email", "admin", "repo:read"])
    if chance(0.3):
        c["role"] = pick(["authenticated", "service_role", "admin", "member"])
    c.update(extra)
    return c


def g_jwt(alg=None, claims=None, key=None):
    alg = alg or pick(["HS256", "HS256", "RS256", "ES256"])
    hdr = {"alg": alg, "typ": "JWT"}
    if alg != "HS256" and chance(0.7):
        hdr["kid"] = rs(B64U, pick([20, 27, 40]))
    claims = claims if claims is not None else jwt_claims()
    h = b64u(json.dumps(hdr, separators=(",", ":")).encode())
    p = b64u(json.dumps(claims, separators=(",", ":")).encode())
    if alg == "HS256":
        sig = b64u(hmac.new(key or rbytes(32), (h + "." + p).encode(), hashlib.sha256).digest())
    elif alg == "RS256":
        sig = b64u(rbytes(256))
    else:
        sig = b64u(rbytes(64))
    return h + "." + p + "." + sig


def pem(label, der, width=64):
    return "-----BEGIN %s-----\n%s\n-----END %s-----" % (label, wrap(b64(der), width), label)


def der_rsa_pkcs1():
    return bytes.fromhex("308204a40201000282010100") + rbytes(rint(1178, 1184))


def der_ec():
    return (bytes.fromhex("30770201010420") + rbytes(32) + bytes.fromhex("a00a06082a8648ce3d030107a144034200")
            + b"\x04" + rbytes(64))


def der_pkcs8_rsa():
    return bytes.fromhex("308204be020100300d06092a864886f70d0101010500048204a8308204a40201000282010100") + rbytes(1176)


def der_pkcs8_ed():
    return bytes.fromhex("302e020100300506032b657004220420") + rbytes(32)


def sshstr(b):
    return struct.pack(">I", len(b)) + b


def g_rsa_pem():
    return pem("RSA PRIVATE KEY", der_rsa_pkcs1())


def g_ec_pem():
    return pem("EC PRIVATE KEY", der_ec())


def g_pkcs8_pem():
    return pem("PRIVATE KEY", pick([der_pkcs8_rsa, der_pkcs8_rsa, der_pkcs8_ed])())


def g_openssh_key(comment=None):
    pub = rbytes(32)
    pubblob = sshstr(b"ssh-ed25519") + sshstr(pub)
    chk = rbytes(4)
    priv = chk + chk + sshstr(b"ssh-ed25519") + sshstr(pub) + sshstr(rbytes(32) + pub) + sshstr(
        (comment or "%s@%s" % (user(), pick(["laptop", "build-01", "MacBook-Pro.local", "devbox"]))).encode())
    priv += bytes(range(1, 1 + (-len(priv)) % 8))
    der = b"openssh-key-v1\x00" + sshstr(b"none") + sshstr(b"none") + sshstr(b"") + struct.pack(">I", 1) + sshstr(
        pubblob) + sshstr(priv)
    return pem("OPENSSH PRIVATE KEY", der, 70)


def g_pgp_private():
    body = bytes([0x95, 0x03, 0xc6]) + rbytes(rint(900, 1300))
    return ("-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n%s\n=%s\n-----END PGP PRIVATE KEY BLOCK-----"
            % (wrap(b64(body), 64), b64(rbytes(3))))


def g_bip39(n=None):
    return " ".join(pick(BIP39) for _ in range(n or pick([12, 12, 24])))


def g_totp():
    return rs(B32, pick([16, 32]))


def g_backup_code():
    return pick([lambda: rhex(5) + "-" + rhex(5), lambda: rs(DIG, 4) + " " + rs(DIG, 4),
                 lambda: rs(LOW + DIG, 8)])()


# ---------------------------------------------------------------- harmless random-looking values
def n_sha():
    return rhex(40)


def n_short():
    return rhex(pick([7, 7, 8, 9, 10, 12]))


def n_digest():
    return "sha256:" + rhex(64)


def n_integrity():
    return pick([lambda: "sha512-" + b64(rbytes(64)), lambda: "sha1-" + b64(rbytes(20))])()


def n_ulid():
    return rs(CROCK[:8], 1) + rs(CROCK, 25)


def n_trace():
    return rhex(32)


def n_span():
    return rhex(16)


def n_etag():
    return pick(['"%s"' % rhex(32), 'W/"%x-%s"' % (rint(100, 99999), rs(B64U, 27)), '"%s"' % rhex(40)])


def n_cursor():
    d = {"id": rint(1000, 9999999), "ts": epoch()}
    if chance(0.5):
        d = {"last_id": g_uuid(), "dir": "next"}
    return b64(json.dumps(d, separators=(",", ":")).encode()).rstrip("=")


def n_pagetoken():
    return rs(B64U, rint(60, 140))


STRIPE_OBJ = ["cus", "pi", "ch", "evt", "price", "prod", "sub", "in", "pm", "seti", "txn", "acct", "re", "po"]


def n_stripe_id(p=None):
    p = p or pick(STRIPE_OBJ)
    if p in ("pi", "ch", "re", "txn", "seti", "pm"):
        return "%s_3%s" % (p, rs(B62, 23))
    if p in ("evt",):
        return "evt_1" + rs(B62, 23)
    if p == "acct":
        return "acct_1" + rs(B62, 15)
    return "%s_%s" % (p, rs(B62, 14))


def n_stripe_pk():
    return "pk_live_51" + rs(B62, 97)


K8S_A = "bcdfghjklmnpqrstvwxz2456789"


def n_pod(base=None):
    return "%s-%s-%s" % (base or pick(PROJ), rs(K8S_A, 10), rs(K8S_A, 5))


def n_awsid(p=None):
    p = p or pick(["i", "sg", "vpc", "subnet", "ami", "vol", "eni", "rtb", "igw", "nat"])
    return "%s-0%s" % (p, rhex(16))


def n_acct():
    return str(rint(10 ** 11, 10 ** 12 - 1))


def n_arn(acct=None):
    acct = acct or n_acct()
    return pick(["arn:aws:iam::%s:role/%s-%s" % (acct, proj(), pick(["deploy", "ci", "lambda-exec"])),
                 "arn:aws:lambda:%s:%s:function:%s" % (pick(REGIONS), acct, proj()),
                 "arn:aws:s3:::%s-%s" % (proj(), rhex(8))])


def n_ssh_pub(kind=None):
    kind = kind or pick(["ed25519", "ed25519", "rsa"])
    if kind == "ed25519":
        blob = sshstr(b"ssh-ed25519") + sshstr(rbytes(32))
        return "ssh-ed25519 " + b64(blob)
    blob = sshstr(b"ssh-rsa") + sshstr(b"\x01\x00\x01") + sshstr(b"\x00" + rbytes(256))
    return "ssh-rsa " + b64(blob)


def n_pubkey_pem():
    der = bytes.fromhex("30820122300d06092a864886f70d01010105000382010f003082010a0282010100") + rbytes(256) + bytes.fromhex("0203010001")
    return pem("PUBLIC KEY", der)


def n_cert_pem():
    der = bytes.fromhex("308203") + rbytes(1) + bytes.fromhex("308202") + rbytes(rint(700, 900))
    return pem("CERTIFICATE", der)


def n_png():
    return "data:image/png;base64," + b64(bytes.fromhex("89504e470d0a1a0a0000000d49484452") + rbytes(rint(60, 220)))


def n_nonce():
    return b64(rbytes(16))


def n_sri():
    return pick(["sha384-" + b64(rbytes(48)), "sha256-" + b64(rbytes(32))])


def n_yt():
    return rs(B64U, 11)


def n_short_link():
    return rs(B62, 7)


def n_gdoc():
    return "1" + rs(B64U, 43)


def n_gosum():
    return "h1:" + b64(rbytes(32))


def n_reqid():
    return pick([g_uuid, lambda: "req_" + rs(B62, 14), lambda: rs(UP + DIG, 20), lambda: rhex(32),
                 lambda: "%s-%s" % (rhex(8), rhex(16))])()


def n_cfid():
    return b64(rbytes(42)).replace("+", "-").replace("/", "_")


def n_amzreq():
    return rs(UP + DIG, 16)


def n_hashname(ext):
    return "%s.%s.%s" % (pick(["main", "vendor", "app", "runtime", "chunk", "index", "styles"]), rhex(pick([8, 16, 20])), ext)


def n_sha256sum():
    return rhex(64)


PLACEHOLDERS = ["****", "********", "[REDACTED]", "<secret>", "sk-...", "${{ secrets.%s }}", "vault:secret/data/%s",
                "changeme", "your-api-key-here", "<YOUR_TOKEN>", "REPLACE_ME", "[FILTERED]", "xxxxxxxx",
                "${%s}", "<redacted>", "${env:%s}", "{{ .Values.%s }}", "op://Engineering/%s/credential",
                "arn:aws:secretsmanager:us-east-1:000000000000:secret:%s", "*****REDACTED*****", "TODO",
                "sk_live\x5fxxxxxxxxxxxxxxxxxxxxxxxx", "ghp_" + "x" * 36, "AKI\x41XXXXXXXXXXXXXXXX", "dummy", "<password>",
                "%(DB_PASSWORD)s", "$(cat /run/secrets/%s)", "secretRef: %s", "<hidden>", "None", "null", "(sensitive value)"]

ENVN = ["DB_PASSWORD", "API_KEY", "STRIPE_SECRET_KEY", "GITHUB_TOKEN", "OPENAI_API_KEY", "SLACK_BOT_TOKEN",
        "AWS_SECRET_ACCESS_KEY", "SENTRY_AUTH_TOKEN", "NPM_TOKEN", "REDIS_PASSWORD", "JWT_SECRET", "SMTP_PASSWORD"]


def n_placeholder():
    p = pick(PLACEHOLDERS)
    if "%s" in p:
        n = pick(ENVN)
        p = p % (n if not p.startswith("vault") and not p.startswith("op:") else n.lower().replace("_", "-"))
    return p


def jwt_example():
    """The jwt.io documentation example token, computed (not pasted)."""
    h = b64u(b'{"alg":"HS256","typ":"JWT"}')
    p = b64u(b'{"sub":"1234567890","name":"John Doe","iat":1516239022}')
    s = b64u(hmac.new(b"your-256-bit-secret", (h + "." + p).encode(), hashlib.sha256).digest())
    return h + "." + p + "." + s


AWS_DOC_AKID = "AKIA" + "IOSFODNN7" + "EXAMPLE"
AWS_DOC_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY"


# ---------------------------------------------------------------- pools
SCEN = []


def scen(ctx, n):
    def deco(f):
        SCEN.append((ctx, n, f))
        return f
    return deco


VENDOR_POOL = [
    ("OPENAI_API_KEY", g_openai, "openai_api_key"),
    ("ANTHROPIC_API_KEY", g_anthropic, "anthropic_api_key"),
    ("GITHUB_TOKEN", g_gh, "github_token"),
    ("GH_TOKEN", g_gh_fine, "github_fine_grained_pat"),
    ("GITLAB_TOKEN", g_gitlab, "gitlab_token"),
    ("SLACK_BOT_TOKEN", g_slack_bot, "slack_bot_token"),
    ("SLACK_APP_TOKEN", g_slack_app, "slack_app_token"),
    ("STRIPE_SECRET_KEY", g_stripe, "stripe_secret_key"),
    ("STRIPE_WEBHOOK_SECRET", g_whsec, "stripe_webhook_secret"),
    ("SENDGRID_API_KEY", g_sendgrid, "sendgrid_api_key"),
    ("MAILGUN_API_KEY", g_mailgun, "mailgun_api_key"),
    ("GOOGLE_API_KEY", g_google_api, "google_api_key"),
    ("NPM_TOKEN", g_npm, "npm_token"),
    ("HF_TOKEN", g_hf, "huggingface_token"),
    ("DISCORD_BOT_TOKEN", g_discord_bot, "discord_bot_token"),
    ("TELEGRAM_BOT_TOKEN", g_telegram, "telegram_bot_token"),
    ("SHOPIFY_ACCESS_TOKEN", g_shopify, "shopify_token"),
    ("DATABRICKS_TOKEN", g_databricks, "databricks_token"),
    ("SENTRY_AUTH_TOKEN", g_sentry_auth, "sentry_auth_token"),
    ("LINEAR_API_KEY", g_linear, "linear_api_key"),
    ("NOTION_TOKEN", g_notion, "notion_token"),
    ("POSTMAN_API_KEY", g_postman, "postman_api_key"),
    ("DOPPLER_TOKEN", g_doppler, "doppler_token"),
    ("VAULT_TOKEN", g_vault, "vault_token"),
    ("TF_TOKEN_app_terraform_io", g_tfc, "terraform_cloud_token"),
    ("DIGITALOCEAN_TOKEN", g_do, "digitalocean_token"),
    ("NETLIFY_AUTH_TOKEN", g_netlify, "netlify_token"),
    ("MAPBOX_SECRET_TOKEN", g_mapbox, "mapbox_secret_token"),
    ("OPENROUTER_API_KEY", g_openrouter, "openrouter_api_key"),
    ("GROQ_API_KEY", g_groq, "groq_api_key"),
    ("REPLICATE_API_TOKEN", g_replicate, "replicate_token"),
    ("NEW_RELIC_API_KEY", g_newrelic, "newrelic_api_key"),
    ("GRAFANA_SA_TOKEN", g_grafana, "grafana_token"),
    ("PULUMI_ACCESS_TOKEN", g_pulumi, "pulumi_token"),
    ("DOCKERHUB_TOKEN", g_dockerhub, "dockerhub_pat"),
    ("TWILIO_API_KEY", g_twilio_key, "twilio_api_key"),
    ("SQUARE_ACCESS_TOKEN", g_square, "square_token"),
    ("SUPABASE_ACCESS_TOKEN", g_supabase_pat, "supabase_pat"),
    ("JIRA_API_TOKEN", g_atlassian, "atlassian_api_token"),
    ("PLANETSCALE_PASSWORD", g_planetscale, "planetscale_password"),
    ("AWS_ACCESS_KEY_ID", g_akid, "aws_access_key_id"),
    ("SOPS_AGE_KEY", g_age, "age_secret_key"),
    ("FCM_SERVER_KEY", g_fcm, "fcm_server_key"),
]

GENERIC_POOL = [
    ("SECRET_KEY", g_django, "django_secret_key"),
    ("SECRET_KEY_BASE", g_rails_kb, "rails_secret_key_base"),
    ("JWT_SECRET", lambda: pick([g_urlsafe, g_hexkey, g_b64key])(), "jwt_signing_secret"),
    ("SESSION_SECRET", g_b64key, "session_secret"),
    ("ENCRYPTION_KEY", g_fernet, "encryption_key"),
    ("DD_API_KEY", lambda: rhex(32), "datadog_api_key"),
    ("DD_APP_KEY", lambda: rhex(40), "datadog_app_key"),
    ("TWILIO_AUTH_TOKEN", lambda: rhex(32), "twilio_auth_token"),
    ("ALGOLIA_ADMIN_KEY", lambda: rhex(32), "algolia_admin_key"),
    ("CLOUDFLARE_API_TOKEN", lambda: rs(B64U, 40), "cloudflare_api_token"),
    ("VERCEL_TOKEN", lambda: rs(B62, 24), "vercel_token"),
    ("HEROKU_API_KEY", g_uuid, "heroku_api_key"),
    ("INTERNAL_API_KEY", g_generic, "generic_api_key"),
    ("WEBHOOK_SECRET", g_hexkey, "webhook_secret"),
    ("APP_KEY", lambda: "base64:" + b64(rbytes(32)), "laravel_app_key"),
    ("NEXTAUTH_SECRET", g_b64key, "nextauth_secret"),
    ("CRON_SECRET", g_urlsafe, "generic_secret"),
    ("MEILI_MASTER_KEY", g_urlsafe, "generic_secret"),
    ("ADMIN_TOKEN", g_b62key, "generic_api_key"),
    ("OKTA_API_TOKEN", lambda: "00" + rs(B64U, 40), "okta_api_token"),
    ("AWS_SECRET_ACCESS_KEY", g_aws_secret, "aws_secret_access_key"),
    ("PARTNER_API_KEY", g_generic, "generic_api_key"),
    ("HMAC_SIGNING_KEY", g_hexkey, "hmac_key"),
    ("COOKIE_SECRET", g_b62key, "session_secret"),
]

PASSWORD_NAMES = ["DB_PASSWORD", "POSTGRES_PASSWORD", "MYSQL_ROOT_PASSWORD", "MYSQL_PASSWORD", "REDIS_PASSWORD",
                  "SMTP_PASSWORD", "ADMIN_PASSWORD", "RABBITMQ_DEFAULT_PASS", "LDAP_BIND_PASSWORD",
                  "KEYSTORE_PASSWORD", "GF_SECURITY_ADMIN_PASSWORD", "MINIO_ROOT_PASSWORD", "MONGO_INITDB_ROOT_PASSWORD",
                  "ELASTIC_PASSWORD", "PGPASSWORD", "MQTT_PASSWORD", "SFTP_PASS", "KEYCLOAK_ADMIN_PASSWORD"]


def draw(c, cat=None, shell=False, urlsafe=False):
    """Register one named secret and return (ENV_NAME, value)."""
    if cat is None:
        x = R.random()
        cat = "vendor" if x < 0.64 else ("generic" if x < 0.84 else "password")
    if cat == "vendor":
        name, f, kind = pick(VENDOR_POOL)
        v = f()
        c.s(v, kind)
    elif cat == "generic":
        name, f, kind = pick(GENERIC_POOL)
        v = f()
        if urlsafe:
            v = v.replace("+", "-").replace("/", "_")
        c.g(v, kind)
    else:
        name = pick(PASSWORD_NAMES)
        v = g_password(urlsafe=urlsafe, shell=shell)
        c.pw(v, "db_password" if "DB" in name or "POSTGRES" in name or "MYSQL" in name or "PG" in name else "password")
    return name, v


def benign_env(c, n=None):
    """Harmless env lines, with random-looking values registered as keep."""
    out = []
    opts = [
        lambda: ("HOSTNAME", c.k(n_pod())),
        lambda: ("GIT_COMMIT", c.k(n_sha())),
        lambda: ("GITHUB_SHA", c.k(n_sha())),
        lambda: ("BUILD_ID", c.k(g_uuid())),
        lambda: ("IMAGE_DIGEST", c.k(n_digest())),
        lambda: ("OTEL_TRACE_ID", c.k(n_trace())),
        lambda: ("REQUEST_ID", c.k(n_reqid())),
        lambda: ("CI_PIPELINE_ID", str(rint(100000, 9999999))),
        lambda: ("RELEASE", c.k(proj() + "@" + n_short())),
        lambda: ("DEPLOYMENT_ID", c.k("dpl_" + rs(B62, 28))),
        lambda: ("STRIPE_PUBLISHABLE_KEY", c.k(n_stripe_pk())),
        lambda: ("SENTRY_RELEASE", c.k(n_sha())),
        lambda: ("INSTANCE_ID", c.k(n_awsid("i"))),
        lambda: ("CACHE_KEY", c.k("node-modules-" + n_sha256sum())),
        lambda: ("NODE_ENV", pick(["production", "development", "staging"])),
        lambda: ("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
        lambda: ("HOME", "/home/" + user()),
        lambda: ("LANG", "en_US.UTF-8"),
        lambda: ("TZ", "UTC"),
        lambda: ("PORT", str(pick([3000, 8000, 8080, 5000]))),
        lambda: ("LOG_LEVEL", pick(["info", "debug", "warn"])),
        lambda: ("AWS_REGION", pick(REGIONS)),
        lambda: ("SHLVL", "1"),
    ]
    for _ in range(n or rint(3, 7)):
        out.append(pick(opts)())
    return out


def kvlines(pairs, fmt="{k}={v}"):
    return "\n".join(fmt.format(k=k, v=v) for k, v in pairs)


# ---------------------------------------------------------------- positive scenarios: shell / env
@scen("env_dump", 26)
def sc_env_dump(c):
    pairs = benign_env(c)
    for _ in range(rint(3, 6)):
        pairs.append(draw(c))
    v = R.randrange(4)
    if v == 0:
        pairs.sort()
        c.cmd(pick(["env | sort", "printenv | sort"]))
        return kvlines(pairs)
    if v == 1:
        R.shuffle(pairs)
        c.cmd("env")
        return kvlines(pairs)
    if v == 2:
        c.cmd("export -p")
        return kvlines(sorted(pairs), 'declare -x {k}="{v}"')
    c.cmd("docker exec %s env" % n_pod())
    R.shuffle(pairs)
    return kvlines(pairs)


@scen("dotenv_file", 22)
def sc_dotenv(c):
    pairs = benign_env(c, rint(1, 4))
    for _ in range(rint(2, 6)):
        pairs.append(draw(c))
    R.shuffle(pairs)
    f = pick([".env", ".env.local", ".env.production", "apps/web/.env", ".env.development.local"])
    c.path(f)
    q = pick(["", '"', "'"])
    lines = ["# %s" % pick(["Local development", "DO NOT COMMIT", "copied from 1password", "generated by setup.sh"])]
    for k, v in pairs:
        lines.append("%s=%s%s%s" % (k, q, v, q))
        if chance(0.15):
            lines.append("")
    if chance(0.5):
        lines.insert(rint(1, len(lines)), "# %s=%s" % (pick(ENVN), c.k(n_placeholder())))
    return "\n".join(lines)


@scen("env_diff", 18)
def sc_env_diff(c):
    name, f, kind = pick(VENDOR_POOL + GENERIC_POOL)
    newv = f()
    is_generic = (name, f, kind) in GENERIC_POOL
    (c.g if is_generic else c.s)(newv, kind)
    old = c.k(n_placeholder()) if chance(0.5) else None
    sha1, sha2 = c.k(n_short()), c.k(n_short())
    f2 = pick([".env.local", ".env", "config/.env.staging", "docker/.env"])
    lines = ["diff --git a/%s b/%s" % (f2, f2), "index %s..%s 100644" % (sha1, sha2), "--- a/%s" % f2, "+++ b/%s" % f2,
             "@@ -%d,%d +%d,%d @@" % (rint(1, 20), 5, rint(1, 20), 6)]
    for k, v in benign_env(c, 2):
        lines.append(" %s=%s" % (k, v))
    if old:
        lines.append("-%s=%s" % (name, old))
    lines.append("+%s=%s" % (name, newv))
    if chance(0.6):
        n2, v2 = draw(c, cat=pick(["password", "generic"]))
        lines.append("+%s=%s" % (n2, v2))
    lines.append(" LOG_LEVEL=info")
    c.cmd(pick(["git diff", "git diff --cached", "git show HEAD -- %s" % f2]))
    return "\n".join(lines)


@scen("set_x_trace", 22)
def sc_setx(c):
    host = "api.%s" % domain()
    lines = ["+ set -euo pipefail", "+ cd /srv/%s" % proj()]
    v = R.randrange(4)
    if v == 0:
        tok = c.s(g_gh(), "github_token")
        lines += ["+ export GITHUB_TOKEN=%s" % tok,
                  "+ git clone https://x-access-token:%s@github.com/%s/%s.git" % (tok, user(), proj()),
                  "Cloning into '%s'..." % proj()]
    elif v == 1:
        tok = c.g(g_urlsafe(), "bearer_token")
        rid = c.k(n_reqid())
        lines += ["++ cat /run/secrets/api_token", "+ TOKEN=%s" % tok,
                  "+ curl -fsS -H 'Authorization: Bearer %s' https://%s/v1/deploy -d '{\"ref\":\"%s\"}'" % (tok, host, c.k(n_sha())),
                  '{"status":"queued","request_id":"%s"}' % rid]
    elif v == 2:
        pw = c.pw(g_password(shell=True), "db_password")
        lines += ["+ PGPASSWORD=%s" % pw, "+ psql -h db.internal -U %s -d %s -c 'select 1'" % (user(), pick(DBNAMES)),
                  " ?column? ", "----------", "        1", "(1 row)"]
    else:
        k = c.s(g_dockerhub(), "dockerhub_pat")
        dg = c.k(n_digest())
        lines += ["+ echo %s" % k, "+ docker login -u %s --password-stdin" % user(), "Login Succeeded",
                  "+ docker push %s/%s:latest" % (user(), proj()), "latest: digest: %s size: 2203" % dg]
    if chance(0.4):
        n2, v2 = draw(c, shell=True)
        lines.insert(2, "+ %s=%s" % (n2, v2))
    c.cmd("bash -x %s" % pick(["deploy.sh", "scripts/release.sh", "ci/publish.sh", "bin/bootstrap"]))
    return "\n".join(lines)


@scen("ps_auxe", 12)
def sc_ps(c):
    lines = ["USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"]
    for _ in range(rint(1, 3)):
        lines.append("root     %7d  0.0  0.1  %5d  %4d ?        Ss   %s   0:00 /usr/sbin/sshd -D" % (
            rint(1, 900), rint(10000, 99999), rint(1000, 9999), pick(["09:12", "Sep14", "10:01"])))
    envs = " ".join("%s=%s" % kv for kv in benign_env(c, 3) + [draw(c, shell=True) for _ in range(rint(2, 4))])
    lines.append("%s  %7d  2.1  4.3 %7d %6d ?        Sl   %s   1:23 node dist/server.js %s" % (
        user().ljust(8), rint(1000, 99999), rint(10 ** 6, 9 * 10 ** 6), rint(10 ** 5, 9 * 10 ** 5), "10:42", envs))
    c.cmd(pick(["ps auxe", "ps eww -o pid,command -p %d" % rint(100, 9999)]))
    return "\n".join(lines)


@scen("proc_environ", 10)
def sc_proc(c):
    pid = rint(100, 65000)
    pairs = benign_env(c, 3) + [draw(c) for _ in range(rint(2, 4))]
    R.shuffle(pairs)
    if chance(0.5):
        c.cmd("cat /proc/%d/environ | tr '\\0' '\\n'" % pid)
        return kvlines(pairs)
    c.cmd("strings /proc/%d/environ" % pid)
    return kvlines(pairs)


@scen("shell_history", 22)
def sc_history(c):
    lines = []
    n = rint(400, 2000)
    cmds = ["git status", "ls -la", "cd ~/code/%s" % proj(), "npm run dev", "docker ps", "kubectl get pods -n %s" % proj(),
            "git log --oneline -5", "make test", "code .", "clear"]
    secret_cmds = [
        lambda: "export %s=%s" % draw(c, shell=True),
        lambda: "curl -u %s:%s https://%s/api/v2/status" % (user(), c.pw(g_password(shell=True)), "jenkins." + domain()),
        lambda: "mysql -u root -p'%s' -h 127.0.0.1 %s" % (c.pw(g_password(shell=True), "db_password"), pick(DBNAMES)),
        lambda: "echo %s | gh auth login --with-token" % c.s(g_gh(), "github_token"),
        lambda: "npm config set //registry.npmjs.org/:_authToken %s" % c.s(g_npm(), "npm_token"),
        lambda: "heroku config:set STRIPE_SECRET_KEY=%s -a %s" % (c.s(g_stripe(), "stripe_secret_key"), proj()),
        lambda: "./bin/import --api-key %s --since 2026-01-01" % c.g(g_generic(), "generic_api_key"),
        lambda: "redis-cli -h cache.internal -a %s KEYS 'session:*'" % c.pw(g_password(shell=True), "redis_password"),
        lambda: "aws configure set aws_secret_access_key %s" % c.g(g_aws_secret(), "aws_secret_access_key"),
    ]
    picks = [pick(secret_cmds) for _ in range(rint(1, 3))]
    body = [pick(cmds) for _ in range(rint(4, 10))]
    for p in picks:
        body.insert(rint(0, len(body)), p())
    if chance(0.3):
        body.insert(rint(0, len(body)), "git checkout %s" % c.k(n_sha()))
    if chance(0.5):
        c.cmd("history | tail -%d" % len(body))
        return "\n".join("%5d  %s" % (n + i, b) for i, b in enumerate(body))
    c.cmd(pick(["cat ~/.bash_history", "tail -n 40 ~/.zsh_history"]))
    if chance(0.5):
        return "\n".join(": %d:0;%s" % (epoch() + i * 7, b) for i, b in enumerate(body))
    return "\n".join(body)


# ---------------------------------------------------------------- positive scenarios: cloud / infra CLIs
def pg_url(c, scheme="postgresql", port=5432, host=None, urlsafe_pw=True, user_=None):
    pw = c.pw(g_password(urlsafe=urlsafe_pw), "db_password")
    host = host or pick(["db.internal", "%s.cluster-%s.%s.rds.amazonaws.com" % (proj(), rs(LOW + DIG, 12), pick(REGIONS)),
                         "ec2-%s.compute-1.amazonaws.com" % pubip().replace(".", "-"), "localhost", "postgres"])
    return "%s://%s:%s@%s:%d/%s" % (scheme, user_ or pick([user(), "app", "postgres", "admin"]), pw, host, port, pick(DBNAMES))


@scen("docker_compose_config", 18)
def sc_compose(c):
    svc = proj()
    env = [draw(c, cat=pick(["vendor", "vendor", "generic", "password"])) for _ in range(rint(3, 5))]
    lines = ["name: %s" % svc, "services:", "  app:", "    build:", "      context: /home/%s/code/%s" % (user(), svc),
             "      dockerfile: Dockerfile", "    environment:"]
    q = pick(["", '"'])
    for k, v in env + [("NODE_ENV", "production")]:
        lines.append("      %s: %s%s%s" % (k, q, v, q))
    lines.append("      DATABASE_URL: %s" % pg_url(c, host="db"))
    lines += ["    image: %s/%s@%s" % (user(), svc, c.k(n_digest())), "    networks:", "      default: null",
              "  db:", "    environment:", "      POSTGRES_DB: %s" % pick(DBNAMES)]
    lines.append("      POSTGRES_PASSWORD: %s" % c.pw(g_password(), "db_password"))
    lines += ["    image: postgres:16-alpine", "networks:", "  default:", "    name: %s_default" % svc]
    c.cmd(pick(["docker compose config", "docker-compose config", "docker compose -f compose.prod.yml config"]))
    return "\n".join(lines)


@scen("heroku_config", 12)
def sc_heroku(c):
    app = proj() + "-" + pick(["prod", "staging", "eu"])
    pairs = [("DATABASE_URL", pg_url(c, scheme="postgres", host="ec2-%s.compute-1.amazonaws.com" % pubip().replace(".", "-")))]
    pairs.append(("REDIS_URL", "rediss://:%s@ec2-%s.compute-1.amazonaws.com:%d" % (
        c.g(rs(LOW + DIG, 65), "redis_password"), pubip().replace(".", "-"), rint(10000, 32000))))
    for _ in range(rint(2, 4)):
        pairs.append(draw(c))
    pairs.append(("HEROKU_SLUG_COMMIT", c.k(n_sha())))
    pairs.sort()
    w = max(len(k) for k, _ in pairs) + 1
    c.cmd("heroku config -a %s" % app)
    return "=== %s Config Vars\n" % app + "\n".join("%s %s" % ((k + ":").ljust(w), v) for k, v in pairs)


@scen("vercel_env_pull", 12)
def sc_vercel(c):
    oidc = c.s(g_jwt("RS256", jwt_claims(iss="https://oidc.vercel.com/%s" % user(), aud="https://vercel.com/%s" % user(),
                                          owner=user(), project=proj(), environment="development")), "vercel_oidc_token")
    pairs = [("VERCEL_OIDC_TOKEN", oidc)] + [draw(c) for _ in range(rint(2, 5))]
    pairs.append(("NEXT_PUBLIC_POSTHOG_KEY", c.k("phc_" + rs(B62, 43))))
    if chance(0.5):
        pairs.append(("POSTGRES_URL", pg_url(c, host="ep-%s-%s.us-east-1.aws.neon.tech" % (pick(WORDS), rs(LOW + DIG, 8)))))
    c.cmd("vercel env pull .env.local")
    head = "Vercel CLI 39.%d.%d\n> Downloading `development` Environment Variables for %s/%s\n" % (rint(0, 9), rint(0, 9), user(), proj())
    head += "✅  Created .env.local file  [%dms]\n\n$ cat .env.local\n# Created by Vercel CLI\n" % rint(200, 900)
    return head + "\n".join('%s="%s"' % kv for kv in pairs)


@scen("fly_secrets", 10)
def sc_fly(c):
    lines = []
    if chance(0.6):
        n, v = draw(c, shell=True)
        lines.append("$ fly secrets set %s=%s -a %s" % (n, v, proj()))
        lines.append("Updating existing machines in '%s' with rolling strategy" % proj())
        lines.append("  Machine %s [app] update succeeded" % c.k(rhex(14)))
    else:
        tok = c.s(g_fly(), "fly_token")
        lines.append("$ fly tokens create deploy -x 999999h")
        lines.append("FlyV1 " + tok)
    lines.append("$ fly secrets list")
    lines.append("NAME                 \tDIGEST          \tCREATED AT")
    for nm in sorted(pick(ENVN) for _ in range(3)):
        lines.append("%s\t%s\t%dd ago" % (nm.ljust(21), c.k(rhex(16)), rint(1, 300)))
    return "\n".join(lines)


@scen("aws_sts", 16)
def sc_sts(c):
    akid = c.s(g_akid(True), "aws_access_key_id")
    sec = c.g(g_aws_secret(), "aws_secret_access_key")
    tok = c.s(g_aws_session(), "aws_session_token")
    c.kind = "aws_session_credentials"
    acct = n_acct()
    exp = (dt() + datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    d = {"Credentials": {"AccessKeyId": akid, "SecretAccessKey": sec, "SessionToken": tok, "Expiration": exp}}
    if chance(0.6):
        role = "%s-deploy" % proj()
        sess = pick(["gha-%d" % rint(10 ** 9, 10 ** 10), "%s-cli" % user(), "botocore-session-%d" % epoch()])
        rid = c.k("AROA" + rs(B32, 17))
        d["AssumedRoleUser"] = {"AssumedRoleId": "%s:%s" % (rid, sess),
                                "Arn": c.k("arn:aws:sts::%s:assumed-role/%s/%s" % (acct, role, sess))}
        c.cmd("aws sts assume-role --role-arn arn:aws:iam::%s:role/%s --role-session-name %s" % (acct, role, sess))
    else:
        c.cmd("aws sts get-session-token --duration-seconds 3600")
    return json.dumps(d, indent=pick([4, 2]))


@scen("aws_credentials_file", 10)
def sc_awscreds(c):
    lines = []
    for prof in ["default"] + [pick(["prod", "staging", "sandbox", proj()]) for _ in range(rint(0, 2))]:
        lines.append("[%s]" % prof)
        lines.append("aws_access_key_id = %s" % c.s(g_akid(), "aws_access_key_id"))
        lines.append("aws_secret_access_key = %s" % c.g(g_aws_secret(), "aws_secret_access_key"))
        if chance(0.3):
            lines.append("region = %s" % pick(REGIONS))
        lines.append("")
    c.path("~/.aws/credentials")
    if chance(0.4):
        lines.append("$ aws configure list")
        lines.append("      Name                    Value             Type    Location")
        lines.append("   profile                <not set>             None    None")
        lines.append("access_key     %s shared-credentials-file" % c.k("*" * 16 + rs(B32, 4)))
        lines.append("secret_key     %s shared-credentials-file" % c.k("*" * 16 + rs(B62, 4)))
    return "\n".join(lines)


@scen("gcloud_auth", 14)
def sc_gcloud(c):
    v = R.randrange(3)
    if v == 0:
        c.cmd(pick(["gcloud auth print-access-token", "gcloud auth application-default print-access-token"]))
        return c.s(g_ya29(), "gcp_access_token")
    if v == 1:
        c.path("~/.config/gcloud/application_default_credentials.json")
        d = {"account": "", "client_id": c.k("%d-%s.apps.googleusercontent.com" % (rint(10 ** 11, 10 ** 12), rs(LOW + DIG, 32))),
             "client_secret": c.s("GOCSPX-" + rs(B64U, 28), "google_oauth_client_secret"),
             "quota_project_id": proj() + "-" + str(rint(100000, 999999)),
             "refresh_token": c.s(g_refresh_google(), "google_refresh_token"),
             "type": "authorized_user", "universe_domain": "googleapis.com"}
        return json.dumps(d, indent=2)
    tok = c.s(g_ya29(), "gcp_access_token")
    c.cmd("curl -sv -H \"Authorization: Bearer $(gcloud auth print-access-token)\" https://storage.googleapis.com/storage/v1/b?project=%s" % proj())
    return ("> GET /storage/v1/b?project=%s HTTP/2\n> Host: storage.googleapis.com\n> authorization: Bearer %s\n"
            "> user-agent: curl/8.5.0\n>\n< HTTP/2 200\n< x-guploader-uploadid: %s\n< etag: %s\n" % (
                proj(), tok, c.k(rs(B64U, 70)), c.k(rs(B64U, 8)) + "AA"))


@scen("az_sp_create", 10)
def sc_azsp(c):
    app = c.k(g_uuid())
    ten = c.k(g_uuid())
    pw = c.s(g_azure_secret(), "azure_client_secret")
    pre = ("Creating '%s' role assignment under scope '/subscriptions/%s'\nThe output includes credentials that you must "
           "protect. Be sure that you do not include these credentials in your code or check the credentials into your "
           "source control. For more information, see https://aka.ms/azadsp-cli\n") % (
        pick(["Contributor", "Reader", "Owner"]), c.k(g_uuid()))
    d = {"appId": app, "displayName": "%s-%s" % (proj(), pick(["ci", "sp", "github-actions"])), "password": pw, "tenant": ten}
    c.cmd("az ad sp create-for-rbac --name %s --role Contributor" % d["displayName"])
    if chance(0.4):
        c.cmd("az ad sp create-for-rbac --sdk-auth")
        d = {"clientId": app, "clientSecret": pw, "subscriptionId": c.k(g_uuid()), "tenantId": ten,
             "activeDirectoryEndpointUrl": "https://login.microsoftonline.com",
             "resourceManagerEndpointUrl": "https://management.azure.com/"}
    return pre + json.dumps(d, indent=2)


@scen("azure_storage_conn", 8)
def sc_azstor(c):
    acct = pick(PROJ).replace("-", "") + rs(LOW + DIG, 4)
    key = c.s(g_azure_storage(), "azure_storage_key")
    cs = "DefaultEndpointsProtocol=https;AccountName=%s;AccountKey=%s;EndpointSuffix=core.windows.net" % (acct, key)
    c.cmd("az storage account show-connection-string -n %s -g %s-rg" % (acct, proj()))
    if chance(0.5):
        return json.dumps({"connectionString": cs}, indent=2)
    c.path("local.settings.json")
    return json.dumps({"IsEncrypted": False, "Values": {"AzureWebJobsStorage": cs, "FUNCTIONS_WORKER_RUNTIME": "python",
                                                         "APPINSIGHTS_INSTRUMENTATIONKEY": c.k(g_uuid())}}, indent=2)


def k8s_meta(c, name, ns):
    return ["metadata:", "  creationTimestamp: \"%sZ\"" % ts()[:19], "  name: %s" % name, "  namespace: %s" % ns,
            "  resourceVersion: \"%d\"" % rint(10 ** 6, 10 ** 8), "  uid: %s" % c.k(g_uuid())]


@scen("kubectl_secret", 22)
def sc_kubesecret(c):
    ns = pick(["default", "prod", proj(), "payments", "kube-system"])
    name = pick([proj() + "-secrets", "app-env", "db-credentials", "api-keys"])
    v = R.randrange(3)
    if v == 2:
        n, val = draw(c)
        c.cmd("kubectl get secret %s -n %s -o jsonpath='{.data.%s}' | base64 -d" % (name, ns, n))
        return val
    items = []
    for _ in range(rint(2, 5)):
        n, val = draw(c)
        enc = b64(val.encode())
        items.append((n, enc))
    # register the base64-encoded form (what actually appears); drop raw forms
    raw = list(zip(c.secrets, c.cats))
    c.secrets, c.cats = [], []
    for (n, enc), (rv, (kind, cat)) in zip(items, raw):
        c.s(enc, kind, cat)
    if v == 0:
        c.cmd("kubectl get secret %s -n %s -o yaml" % (name, ns))
        lines = ["apiVersion: v1", "data:"] + ["  %s: %s" % (n, e) for n, e in items] + ["kind: Secret"] + k8s_meta(c, name, ns) + ["type: Opaque"]
        return "\n".join(lines)
    c.cmd("kubectl get secret %s -n %s -o json" % (name, ns))
    return json.dumps({"apiVersion": "v1", "data": dict(items), "kind": "Secret",
                       "metadata": {"name": name, "namespace": ns, "uid": c.k(g_uuid()),
                                    "resourceVersion": str(rint(10 ** 6, 10 ** 8))}, "type": "Opaque"}, indent=4)


@scen("helm_values", 12)
def sc_helm(c):
    rel = proj()
    lines = ["USER-SUPPLIED VALUES:", "image:", "  repository: ghcr.io/%s/%s" % (user(), rel),
             "  digest: %s" % c.k(n_digest()), "postgresql:", "  auth:", "    username: %s" % rel.replace("-", "_"),
             "    password: %s" % c.pw(g_password(), "db_password"), "    postgresPassword: %s" % c.pw(g_password(), "db_password"),
             "redis:", "  auth:", "    password: %s" % c.g(g_b62key(), "redis_password"), "secrets:"]
    for _ in range(rint(2, 4)):
        n, v = draw(c, cat=pick(["vendor", "vendor", "generic"]))
        lines.append("  %s: %s" % (n.lower().replace("_", ""), v if chance(0.6) else '"%s"' % v))
    lines.append("podAnnotations:")
    lines.append("  checksum/config: %s" % c.k(n_sha256sum()))
    c.cmd("helm get values %s -n %s -a" % (rel, pick(["prod", "default"])) if chance(0.5) else "helm get values %s" % rel)
    return "\n".join(lines)


@scen("terraform_output", 14)
def sc_tfout(c):
    d = {}
    d["db_password"] = {"sensitive": True, "type": "string", "value": c.pw(g_password(), "db_password")}
    if chance(0.7):
        d["ci_access_key_id"] = {"sensitive": False, "type": "string", "value": c.s(g_akid(), "aws_access_key_id")}
        d["ci_secret_access_key"] = {"sensitive": True, "type": "string", "value": c.g(g_aws_secret(), "aws_secret_access_key")}
    if chance(0.5):
        d["api_gateway_key"] = {"sensitive": True, "type": "string", "value": c.g(rs(B62, 40), "generic_api_key")}
    d["vpc_id"] = {"sensitive": False, "type": "string", "value": c.k(n_awsid("vpc"))}
    d["subnet_ids"] = {"sensitive": False, "type": ["list", "string"], "value": [c.k(n_awsid("subnet")) for _ in range(rint(2, 3))]}
    d["role_arn"] = {"sensitive": False, "type": "string", "value": c.k(n_arn())}
    d = dict(sorted(d.items()))
    if chance(0.25):
        c.cmd("terraform output -raw db_password")
        c.secrets, c.cats, c.keep = c.secrets[:1], c.cats[:1], []
        return d["db_password"]["value"]
    c.cmd("terraform output -json")
    return json.dumps(d, indent=2)


# ---------------------------------------------------------------- positive scenarios: package managers / git
@scen("npm_config", 14)
def sc_npm(c):
    tok = c.s(g_npm(), "npm_token")
    v = R.randrange(3)
    if v == 0:
        c.cmd("npm config list")
        lines = ["; \"user\" config from /home/%s/.npmrc" % user(), "",
                 "//registry.npmjs.org/:_authToken = (protected)" if chance(0.3) else "//registry.npmjs.org/:_authToken = \"%s\"" % tok,
                 "@%s:registry = \"https://npm.pkg.github.com/\"" % user()]
        gh = c.s(g_gh("ghp_"), "github_token")
        lines.append("//npm.pkg.github.com/:_authToken = \"%s\"" % gh)
        lines += ["", "; node bin location = /usr/local/bin/node", "; node version = v20.%d.0" % rint(5, 18),
                  "; npm local prefix = /home/%s/code/%s" % (user(), proj()), "; Run `npm config ls -l` to show all defaults."]
        if "(protected)" in lines[2]:
            c.secrets, c.cats = c.secrets[1:], c.cats[1:]
            c.kind = "github_token"
        return "\n".join(lines)
    c.path(pick(["~/.npmrc", ".npmrc", "frontend/.npmrc"]))
    lines = ["registry=https://registry.npmjs.org/", "//registry.npmjs.org/:_authToken=%s" % tok]
    if v == 2:
        auth = c.g(b64(("%s:%s" % (user(), g_password())).encode()), "basic_auth_b64")
        lines += ["@%s:registry=https://%s.jfrog.io/artifactory/api/npm/npm-virtual/" % (proj(), user()),
                  "//%s.jfrog.io/artifactory/api/npm/npm-virtual/:_auth=%s" % (user(), auth), "always-auth=true"]
    lines.append("save-exact=true")
    return "\n".join(lines)


@scen("pypirc", 10)
def sc_pypirc(c):
    tok = c.s(g_pypi(), "pypi_token")
    c.path("~/.pypirc")
    lines = ["[distutils]", "index-servers =", "    pypi", "    testpypi", "", "[pypi]", "username = __token__",
             "password = %s" % tok, "", "[testpypi]", "repository = https://test.pypi.org/legacy/"]
    if chance(0.6):
        lines += ["username = %s" % user(), "password = %s" % c.pw(g_password())]
    return "\n".join(lines)


@scen("pip_config", 10)
def sc_pip(c):
    pw = c.pw(g_password(urlsafe=True))
    host = pick(["pypi.%s" % domain(), "%s.jfrog.io" % user(), "nexus.internal"])
    v = R.randrange(3)
    if v == 0:
        c.cmd("pip config list")
        return "global.index-url='https://%s:%s@%s/simple/'\nglobal.timeout='60'" % (user(), pw, host)
    if v == 1:
        c.cmd("pip install -r requirements.txt")
        return ("Looking in indexes: https://pypi.org/simple, https://%s:****@%s/simple/\n"
                "Collecting requests==2.32.3\n  Using cached requests-2.32.3-py3-none-any.whl\n"
                "ERROR: Could not find a version that satisfies the requirement internal-sdk==%d.%d (from versions: none)\n"
                "# PIP_EXTRA_INDEX_URL=https://%s:%s@%s/simple/") % (user(), host, rint(1, 4), rint(0, 9), user(), pw, host)
    c.cmd("poetry config --list")
    tok = c.s(g_pypi(), "pypi_token")
    c.kind = "pypi_token"
    return "\n".join(["cache-dir = \"/home/%s/.cache/pypoetry\"" % user(), "experimental.system-git-client = false",
                      "http-basic.internal.password = \"%s\"" % pw, "http-basic.internal.username = \"%s\"" % user(),
                      "installer.max-workers = null", "pypi-token.pypi = \"%s\"" % tok,
                      "repositories.internal.url = \"https://%s/simple/\"" % host, "virtualenvs.in-project = true"])


@scen("git_config", 14)
def sc_gitconfig(c):
    lines = ["user.name=%s" % pick(FULLN), "user.email=%s" % email(), "core.editor=vim", "init.defaultbranch=main"]
    v = R.randrange(3)
    if v == 0:
        tok = c.s(g_gh(), "github_token")
        lines.append("url.https://%s:x-oauth-basic@github.com/.insteadof=https://github.com/" % tok)
    elif v == 1:
        tok = c.s(g_gitlab(), "gitlab_token")
        lines.append("http.https://gitlab.%s/.extraheader=PRIVATE-TOKEN: %s" % (domain(), tok))
    else:
        tok = c.g(b64(("x-access-token:" + g_gh("ghs_")).encode()), "basic_auth_b64")
        lines.append("http.https://github.com/.extraheader=AUTHORIZATION: basic %s" % tok)
    lines += ["credential.helper=store", "remote.origin.url=https://github.com/%s/%s.git" % (user(), proj()),
              "remote.origin.fetch=+refs/heads/*:refs/remotes/origin/*", "branch.main.remote=origin"]
    if chance(0.5):
        lines.append("$ cat ~/.git-credentials")
        lines.append("https://%s:%s@github.com" % (user(), c.s(g_gh_fine(), "github_fine_grained_pat")))
    c.cmd("git config --list --show-origin" if chance(0.3) else "git config --list")
    return "\n".join(lines)


@scen("git_remote", 14)
def sc_gitremote(c):
    v = R.randrange(4)
    repo = "%s/%s" % (user(), proj())
    if v == 0:
        tok = c.s(g_gh(), "github_token")
        url = "https://%s@github.com/%s.git" % (tok, repo)
    elif v == 1:
        tok = c.s(g_gitlab(), "gitlab_token")
        url = "https://oauth2:%s@gitlab.com/%s.git" % (tok, repo)
    elif v == 2:
        pw = c.pw(g_password(urlsafe=True))
        url = "https://%s:%s@bitbucket.org/%s.git" % (user(), pw, repo)
    else:
        tok = c.g(rs(B62, 52), "azure_devops_pat") if chance(0.5) else c.g(rs(LOW + DIG, 52), "azure_devops_pat")
        url = "https://%s:%s@dev.azure.com/%s/%s/_git/%s" % (user(), tok, user(), proj(), proj())
    c.cmd(pick(["git remote -v", "git push origin main", "git fetch --all"]))
    if c.hint["command"] == "git remote -v":
        return "origin\t%s (fetch)\norigin\t%s (push)\nupstream\thttps://github.com/%s.git (fetch)" % (url, url, repo)
    if c.hint["command"].startswith("git push"):
        a, b = c.k(n_short()), c.k(n_short())
        return "To %s\n   %s..%s  main -> main" % (url, a, b)
    return "Fetching origin\nfatal: unable to access '%s/': The requested URL returned error: 403" % url[:-4]


@scen("docker_config_json", 10)
def sc_dockercfg(c):
    reg = pick(["https://index.docker.io/v1/", "ghcr.io", "%s.dkr.ecr.%s.amazonaws.com" % (n_acct(), pick(REGIONS)),
                "registry.gitlab.com"])
    auth = c.g(b64(("%s:%s" % (user(), pick([g_dockerhub(), g_gh(), g_password()]))).encode()), "docker_registry_auth")
    c.path("~/.docker/config.json")
    d = {"auths": {reg: {"auth": auth}}}
    if chance(0.4):
        d["auths"]["quay.io"] = {"auth": c.g(b64(("%s+robot:%s" % (user(), rs(UP + DIG, 64))).encode()), "docker_registry_auth")}
    if chance(0.5):
        d["credsStore"] = "desktop"
    return json.dumps(d, indent="\t")


@scen("package_auth_files", 12)
def sc_pkgauth(c):
    v = R.randrange(5)
    if v == 0:
        c.path("~/.cargo/credentials.toml")
        return "[registry]\ntoken = \"%s\"" % c.s("cio" + rs(B62, 32), "crates_io_token")
    if v == 1:
        c.path("~/.gem/credentials")
        return "---\n:rubygems_api_key: %s" % c.s("rubygems_" + rhex(48), "rubygems_api_key")
    if v == 2:
        c.path("auth.json")
        return json.dumps({"http-basic": {"repo.packagist.com": {"username": "token", "password": c.g(rhex(40), "packagist_token")}},
                           "github-oauth": {"github.com": c.s(g_gh("gho_"), "github_token")}}, indent=4)
    if v == 3:
        c.path("~/.m2/settings.xml")
        return ("<settings>\n  <servers>\n    <server>\n      <id>%s-releases</id>\n      <username>%s</username>\n"
                "      <password>%s</password>\n    </server>\n  </servers>\n</settings>") % (proj(), user(), c.pw(g_password()))
    c.path("NuGet.Config")
    return ("<configuration>\n  <packageSourceCredentials>\n    <github>\n      <add key=\"Username\" value=\"%s\" />\n"
            "      <add key=\"ClearTextPassword\" value=\"%s\" />\n    </github>\n  </packageSourceCredentials>\n</configuration>") % (
        user(), c.s(g_gh("ghp_"), "github_token"))


# ---------------------------------------------------------------- positive scenarios: errors / app logs
@scen("exception_message", 22)
def sc_exc(c):
    v = R.randrange(6)
    if v == 0:
        k = c.s(g_openai(), "openai_api_key")
        rid = c.k("req_" + rhex(32))
        c.cmd("python scripts/summarize.py")
        return ("Traceback (most recent call last):\n  File \"/app/scripts/summarize.py\", line %d, in <module>\n"
                "    resp = client.chat.completions.create(model=\"gpt-4o\", messages=msgs)\n"
                "openai.AuthenticationError: Error code: 401 - {'error': {'message': 'Incorrect API key provided: %s. "
                "You can find your API key at https://platform.openai.com/account/api-keys.', 'type': 'invalid_request_error', "
                "'param': None, 'code': 'invalid_api_key'}, 'request_id': '%s'}") % (rint(10, 200), k, rid)
    if v == 1:
        k = c.s(g_stripe("rk" if chance(0.3) else "sk"), "stripe_secret_key")
        c.cmd("node scripts/backfill-invoices.js")
        return ("StripeAuthenticationError: Invalid API Key provided: %s\n    at res.toJSON.then.StripeAPIError.message "
                "(/app/node_modules/stripe/cjs/RequestSender.js:%d:31)\n  type: 'StripeAuthenticationError',\n"
                "  requestId: '%s',\n  statusCode: 401") % (k, rint(80, 140), c.k("req_" + rs(B62, 14)))
    if v == 2:
        k = c.s(g_anthropic(), "anthropic_api_key")
        c.cmd("pytest tests/integration -x")
        return ("E       anthropic.AuthenticationError: Error code: 401 - {'type': 'error', 'error': {'type': "
                "'authentication_error', 'message': 'invalid x-api-key'}, 'request_id': '%s'}\n\n"
                "client     = <anthropic.Anthropic object at 0x7f%s>\napi_key    = '%s'\n"
                "FAILED tests/integration/test_agent.py::test_tool_loop - anthropic.AuthenticationError") % (
            c.k("req_011C" + rs(B62, 20)), rhex(10), k)
    if v == 3:
        pw = c.pw(g_password(), "password")
        c.cmd("java -jar build/libs/%s.jar" % proj())
        return ("java.sql.SQLException: Access denied for user '%s'@'%s' (using password: YES)\n\tat com.mysql.cj.jdbc.exceptions."
                "SQLError.createSQLException(SQLError.java:130)\nCaused by: connection properties {user=%s, password=%s, "
                "useSSL=true, serverTimezone=UTC}") % (user(), ip(), user(), pw)
    if v == 4:
        k = c.g(g_hexkey(32), "generic_api_key")
        c.cmd("go run ./cmd/sync")
        return ("%s ERROR sync failed: GET https://api.%s/v2/accounts?api_key=%s&page=%d: 401 Unauthorized\n"
                "goroutine 1 [running]:\nmain.main()\n\t/src/cmd/sync/main.go:%d +0x%s\nexit status 2") % (
            ts_plain(), domain(), k, rint(1, 9), rint(20, 200), rhex(3))
    k = c.s(g_sendgrid(), "sendgrid_api_key")
    return ("ResponseError: Unauthorized\n    at /app/node_modules/@sendgrid/client/src/classes/client.js:%d:29 {\n"
            "  code: 401,\n  response: {\n    headers: { 'x-message-id': '%s' },\n    body: { errors: [Array] }\n  },\n"
            "  config: { headers: { Authorization: 'Bearer %s' } }\n}") % (rint(100, 200), c.k(rs(B64U, 22)), k)


@scen("psql_error", 14)
def sc_psql(c):
    v = R.randrange(3)
    url = pg_url(c)
    if v == 0:
        c.cmd("psql \"%s\"" % url)
        return "$ psql \"%s\"\n" % url + "psql: error: connection to server at \"%s\" (%s), port 5432 failed: FATAL:  password authentication failed for user \"%s\"" % (
            url.split("@")[1].split(":")[0], ip(), url.split("://")[1].split(":")[0])
    if v == 1:
        c.cmd("npx prisma migrate deploy")
        return ("Environment variables loaded from .env\nPrisma schema loaded from prisma/schema.prisma\n"
                "Datasource \"db\": PostgreSQL database \"%s\"\n\nError: P1001: Can't reach database server\n"
                "DATABASE_URL=\"%s\"") % (pick(DBNAMES), url)
    c.cmd("python manage.py migrate")
    return ("django.db.utils.OperationalError: connection to server failed\n"
            "sqlalchemy.exc.OperationalError: (psycopg2.OperationalError) could not translate host name\n"
            "(Background on this error at: https://sqlalche.me/e/20/e3q8)\n[SQL engine url: %s]") % url


@scen("debug_print_config", 22)
def sc_debugprint(c):
    v = R.randrange(4)
    host = "api." + domain()
    if v == 0:
        k = c.s(pick([g_openai, g_anthropic, g_groq, g_openrouter])(), "llm_api_key")
        c.kind = "llm_api_key"
        c.cmd("python -c 'from app.settings import settings; print(settings)'")
        return ("Settings(env='%s', debug=True, database_url=PostgresDsn('%s'), llm_api_key='%s', "
                "redis_url='redis://localhost:6379/0', request_timeout=30, build_sha='%s')") % (
            pick(["dev", "staging"]), pg_url(c), k, c.k(n_sha()))
    if v == 1:
        cfg = {"service": proj(), "port": pick([8080, 3000]), "upstream": "https://%s" % host}
        n, val = draw(c)
        cfg["auth"] = {"client_id": c.k(rs(B62, 24)), "client_secret": val}
        cfg["db"] = {"host": "db.internal", "user": user(), "password": c.pw(g_password())}
        cfg["release"] = c.k(n_short())
        c.cmd("node -e \"console.log(require('./config'))\"")
        s = json.dumps(cfg, indent=2)
        return s.replace('"', "'") if chance(0.5) else s
    if v == 2:
        n, val = draw(c)
        c.cmd("go run . --dump-config")
        return "config: &{Env:prod Port:%d APIKey:%s Timeout:30s Region:%s TraceID:%s}" % (
            rint(1000, 9000), c.g(g_b62key(), "generic_api_key"), pick(REGIONS), c.k(n_trace())) + "\n%s=%s" % (n, val)
    n, val = draw(c)
    c.cmd("rails runner 'pp Rails.application.config_for(:services)'")
    return "{:%s=>\"%s\",\n :timeout=>15,\n :base_url=>\"https://%s\",\n :webhook_secret=>\"%s\"}" % (
        n.lower(), val, host, c.g(g_hexkey(), "webhook_secret"))


@scen("django_debug_page", 12)
def sc_django(c):
    sk = c.g(g_django(), "django_secret_key")
    lines = ["OperationalError at /api/orders/%d/" % rint(1, 9999), "Request Method: POST", "Django Version: 5.0.%d" % rint(1, 9),
             "Exception Value: FATAL: password authentication failed", "", "Settings", "Setting\tValue"]
    rows = [("ALLOWED_HOSTS", "['*']"), ("SECRET_KEY", "'%s'" % sk)]
    if chance(0.5):
        rows.append(("STRIPE_API_KEY", "'%s'" % c.s(g_stripe(), "stripe_secret_key")))
    else:
        rows.append(("AWS_SECRET_ACCESS_KEY", "'%s'" % c.k("********************")))
    rows.append(("DATABASES", "{'default': {'ENGINE': 'django.db.backends.postgresql', 'HOST': 'db', 'NAME': '%s', "
                              "'PASSWORD': '%s', 'USER': '%s'}}" % (pick(DBNAMES), c.pw(g_password(), "db_password"), user())))
    rows.append(("CSRF_COOKIE_NAME", "'csrftoken'"))
    lines += ["%s\t%s" % r for r in rows]
    lines += ["", "META", "HTTP_COOKIE\t'csrftoken=%s; sessionid=%s'" % (c.g(rs(B62, 32), "csrf_token"),
                                                                        c.g(rs(LOW + DIG, 32), "session_cookie"))]
    lines.append("HTTP_X_REQUEST_ID\t'%s'" % c.k(g_uuid()))
    c.cmd("curl -s -X POST http://localhost:8000/api/orders/%d/" % rint(1, 9999))
    return "\n".join(lines)


@scen("flask_debug", 8)
def sc_flask(c):
    tok = c.g(g_urlsafe(), "bearer_token")
    c.cmd("flask run --debug")
    return (" * Debugger is active!\n * Debugger PIN: %s\n%s - - [%s] \"GET /admin HTTP/1.1\" 500 -\n"
            "Traceback (most recent call last):\n  File \"/app/app.py\", line %d, in admin\n    raise RuntimeError(f\"upstream refused token {token}\")\n"
            "RuntimeError: upstream refused token %s\n>>> request.headers\nEnvironHeaders([('Host', 'localhost:5000'), "
            "('Authorization', 'Bearer %s'), ('X-Request-Id', '%s')])") % (
        c.g("%03d-%03d-%03d" % (rint(0, 999), rint(0, 999), rint(0, 999)), "debugger_pin"), "127.0.0.1",
        dt().strftime("%d/%b/%Y %H:%M:%S"), rint(20, 90), tok, tok, c.k(g_uuid()))


@scen("rails_log", 14)
def sc_rails(c):
    rid = c.k(g_uuid())
    lines = ["Started POST \"/users/sign_in\" for %s at %s +0000" % (ip(), ts_plain()),
             "Processing by Users::SessionsController#create as HTML"]
    pw = c.pw(g_password())
    if chance(0.5):
        lines.append("  Parameters: {\"authenticity_token\"=>\"[FILTERED]\", \"user\"=>{\"email\"=>\"%s\", \"password\"=>\"%s\"}, \"commit\"=>\"Log in\"}" % (email(), pw))
        c.k("[FILTERED]")
    else:
        lines.append("  Parameters: {\"user\"=>{\"email\"=>\"%s\", \"password\"=>\"[FILTERED]\", \"otp_attempt\"=>\"%s\"}}" % (email(), rs(DIG, 6)))
        c.k("[FILTERED]")
        lines.append("  ↳ app/controllers/users/sessions_controller.rb:%d: user.valid_password?(\"%s\") => false" % (rint(10, 99), pw))
    lines.append("[%s] Completed 401 Unauthorized in %dms (ActiveRecord: %.1fms)" % (rid, rint(5, 400), R.random() * 20))
    if chance(0.5):
        n, v = draw(c)
        lines.append("[%s] Webhook dispatch failed: POST https://hooks.%s/in?token=%s" % (rid, domain(), v))
    c.cmd("tail -n 50 log/production.log")
    return "\n".join(lines)


@scen("sentry_event", 12)
def sc_sentry(c):
    tok = c.g(g_urlsafe(), "bearer_token") if chance(0.5) else c.s(g_jwt(), "jwt")
    ev = {"event_id": c.k(rhex(32)), "timestamp": ts(), "platform": "python", "level": "error",
          "release": c.k(n_sha()), "environment": "production",
          "request": {"url": "https://api.%s/v1/charges" % domain(), "method": "POST",
                      "headers": {"Authorization": "Bearer " + tok, "User-Agent": "python-requests/2.32.3",
                                  "X-Request-Id": c.k(g_uuid())},
                      "env": {"REMOTE_ADDR": ip()}},
          "contexts": {"trace": {"trace_id": c.k(n_trace()), "span_id": c.k(n_span()), "op": "http.server"}},
          "exception": {"values": [{"type": "KeyError", "value": "'customer'"}]}}
    if chance(0.6):
        ev["extra"] = {"payload": {"customer": c.k(n_stripe_id("cus")), "api_key": c.s(g_stripe(), "stripe_secret_key")}}
    c.cmd("sentry-cli events list --project %s --json" % proj() if chance(0.3) else "cat /tmp/sentry_event.json")
    return json.dumps(ev, indent=pick([None, 2]))


@scen("otel_span", 12)
def sc_otel(c):
    tid, sid = c.k(n_trace()), c.k(n_span())
    attrs = {"http.method": "GET", "http.url": "https://api.%s/v1/items?cursor=%s" % (domain(), c.k(n_cursor())),
             "http.status_code": 200, "http.request.header.x-request-id": [c.k(g_uuid())]}
    v = R.randrange(3)
    if v == 0:
        attrs["http.request.header.authorization"] = ["Bearer " + c.s(g_jwt(), "jwt")]
    elif v == 1:
        attrs["http.request.header.x-api-key"] = [c.g(g_generic(), "generic_api_key")]
    else:
        attrs["db.statement"] = "SET SESSION app.key = '%s'" % c.g(g_hexkey(64), "encryption_key")
    span = {"traceId": tid, "spanId": sid, "parentSpanId": c.k(n_span()), "name": "GET /v1/items",
            "kind": "SPAN_KIND_CLIENT", "startTimeUnixNano": str(epoch() * 10 ** 9), "attributes": attrs}
    c.cmd("docker logs otel-collector --tail 30")
    return "%s\tinfo\tTracesExporter\t%s" % (ts(), json.dumps(span))


@scen("stack_locals", 12)
def sc_locals(c):
    n, v = draw(c)
    c.cmd("pytest -l tests/test_client.py")
    lines = ["    def _request(self, method, path, **kw):", ">       resp.raise_for_status()",
             "E       requests.exceptions.HTTPError: 403 Client Error: Forbidden for url: https://api.%s%s" % (domain(), "/v3/sync"),
             "", "kw         = {'json': {'cursor': '%s'}, 'timeout': 30}" % c.k(n_pagetoken()),
             "method     = 'POST'", "path       = '/v3/sync'",
             "self       = <Client base='https://api.%s' key='%s'>" % (domain(), v),
             "headers    = {'Authorization': 'Token %s', 'Idempotency-Key': '%s'}" % (
                 c.g(g_hexkey(40), "api_token"), c.k(g_uuid()))]
    return "\n".join(lines)


@scen("python_repl", 14)
def sc_repl(c):
    v = R.randrange(3)
    if v == 0:
        c.cmd("python3")
        n, val = draw(c)
        return ">>> import os\n>>> os.environ['%s']\n'%s'\n>>> os.environ.get('HOME')\n'/home/%s'" % (n, val, user())
    if v == 1:
        c.cmd("jupyter nbconvert --to markdown --stdout analysis.ipynb")
        k = c.s(g_hf(), "huggingface_token") if chance(0.5) else c.s(g_openai(), "openai_api_key")
        return ("```python\nfrom huggingface_hub import login\nlogin(token=\"%s\")\n```\n\n    Token is valid (permission: write).\n"
                "    Your token has been saved to /home/%s/.cache/huggingface/token\n\n```python\ndf.head()\n```\n"
                "|    | id | sha |\n|---:|---|---|\n|  0 | %d | %s |") % (k, user(), rint(1, 999), c.k(n_sha()))
    c.cmd("python3 -i scripts/debug.py")
    creds = {"api_key": c.g(g_b62key(32), "generic_api_key"), "api_secret": c.g(g_b64key(32), "generic_secret"),
             "account": c.k(g_uuid())}
    return ">>> creds\n%r\n>>> client = Client(**creds)\n>>> client.ping()\n{'ok': True, 'trace': '%s'}" % (
        creds, c.k(n_trace()))


# ---------------------------------------------------------------- positive scenarios: HTTP traffic
def auth_header(c):
    v = R.randrange(6)
    if v == 0:
        return "Authorization", "Bearer " + c.s(g_jwt(), "jwt")
    if v == 1:
        return "Authorization", "Bearer " + c.g(g_urlsafe(), "bearer_token")
    if v == 2:
        return "Authorization", "Basic " + c.g(b64(("%s:%s" % (user(), g_password())).encode()), "basic_auth_b64")
    if v == 3:
        return "X-API-Key", c.g(g_generic(), "generic_api_key")
    if v == 4:
        n, f, kind = pick(VENDOR_POOL[:12])
        return "Authorization", "Bearer " + c.s(f(), kind)
    return "Cookie", "session=%s; _ga=GA1.1.%d.%d" % (c.g(g_urlsafe(48), "session_cookie"), rint(10 ** 8, 10 ** 9), epoch())


@scen("curl_verbose", 22)
def sc_curl(c):
    host = "api." + domain()
    path = pick(["/v1/users/me", "/api/v2/deployments", "/graphql", "/v1/files?limit=50"])
    hk, hv = auth_header(c)
    lines = ["*   Trying %s:443..." % pubip(), "* Connected to %s (%s) port 443" % (host, pubip()),
             "* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384", "> %s %s HTTP/2" % (pick(["GET", "POST"]), path),
             "> Host: %s" % host, "> User-Agent: curl/8.%d.0" % rint(1, 9), "> Accept: */*", "> %s: %s" % (hk, hv), ">",
             "< HTTP/2 %d" % pick([200, 201, 401, 403, 429]), "< content-type: application/json",
             "< etag: %s" % c.k(n_etag()), "< x-request-id: %s" % c.k(n_reqid())]
    if chance(0.4):
        lines.append("< x-amz-cf-id: %s" % c.k(n_cfid()))
    if chance(0.3):
        lines.append("< set-cookie: sid=%s; Path=/; HttpOnly; Secure" % c.g(rs(B62, 40), "session_cookie"))
    lines += ["<", '{"data":{"id":"%s"}}' % c.k(g_uuid())]
    c.cmd("curl -v https://%s%s" % (host, path))
    return "\n".join(lines)


@scen("har_file", 10)
def sc_har(c):
    hk, hv = auth_header(c)
    ent = {"startedDateTime": ts(), "time": round(R.random() * 300, 3),
           "request": {"method": "GET", "url": "https://app.%s/api/session?_=%d" % (domain(), epoch() * 1000),
                       "httpVersion": "h2", "headers": [{"name": ":authority", "value": "app." + domain()},
                                                       {"name": hk.lower(), "value": hv},
                                                       {"name": "if-none-match", "value": '"%s"' % c.k(rhex(32))}],
                       "cookies": [], "queryString": []},
           "response": {"status": 200, "headers": [{"name": "x-trace-id", "value": c.k(n_trace())}],
                        "content": {"mimeType": "application/json", "text": json.dumps(
                            {"user": {"id": c.k(g_uuid())}, "refresh_token": c.g(g_urlsafe(48), "refresh_token")})}}}
    c.path(pick(["app.%s.har" % proj(), "network-log.har"]))
    return json.dumps({"log": {"version": "1.2", "creator": {"name": "WebInspector", "version": "537.36"},
                               "entries": [ent]}}, indent=2)


@scen("postman_export", 10)
def sc_postman(c):
    tok = c.s(g_postman(), "postman_api_key") if chance(0.3) else None
    hk, hv = auth_header(c)
    col = {"info": {"_postman_id": c.k(g_uuid()), "name": proj() + " API",
                    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
           "item": [{"name": "List orders", "request": {"method": "GET", "header": [{"key": hk, "value": hv, "type": "text"}],
                                                       "url": {"raw": "{{baseUrl}}/orders?page_token=%s" % c.k(n_pagetoken())}}}],
           "variable": [{"key": "baseUrl", "value": "https://api.%s" % domain()}]}
    if chance(0.6):
        col["auth"] = {"type": "apikey", "apikey": [{"key": "value", "value": c.g(g_b62key(), "generic_api_key"), "type": "string"},
                                                   {"key": "key", "value": "x-api-key", "type": "string"}]}
    if tok:
        col["variable"].append({"key": "postmanApiKey", "value": tok})
    c.path("%s.postman_collection.json" % proj())
    return json.dumps(col, indent="\t")


@scen("mitmproxy_log", 8)
def sc_mitm(c):
    hk, hv = auth_header(c)
    c.cmd("mitmdump -r flows.mitm --flow-detail 2")
    return ("%s:%d: POST https://api.%s/v1/events\n    Host: api.%s\n    %s: %s\n    content-type: application/json\n"
            "    x-client-trace: %s\n\n    {\"events\":[{\"id\":\"%s\"}]}\n << 202 Accepted 18b") % (
        ip(), rint(40000, 65000), domain(), domain(), hk, hv, c.k(n_trace()), c.k(n_ulid()))


@scen("webhook_log", 14)
def sc_webhook(c):
    v = R.randrange(3)
    if v == 0:
        sec = c.s(g_whsec(), "stripe_webhook_secret")
        evt = c.k(n_stripe_id("evt"))
        c.cmd("stripe listen --forward-to localhost:3000/api/webhooks")
        return ("> Ready! You are using Stripe API Version [2024-06-20]. Your webhook signing secret is %s (^C to quit)\n"
                "%s   --> payment_intent.succeeded [%s]\n%s  <--  [200] POST http://localhost:3000/api/webhooks [%s]") % (
            sec, ts_plain(), evt, ts_plain(), evt)
    if v == 1:
        tid, bid, tok = slack_hook_parts()
        c.s(tok, "slack_webhook")
        c.cmd("grep -r hooks.slack.com logs/")
        return "logs/notifier.log:%s INFO posting alert to https://hooks.slack.com/services/%s/%s/%s status=200 id=%s" % (
            ts_plain(), tid, bid, tok, c.k(g_uuid()))
    did = str(rint(10 ** 17, 10 ** 18))
    tok = c.s(rs(B64U, 68), "discord_webhook")
    c.cmd("docker logs alertbot --since 1h")
    return "[%s] DEBUG webhook_url=https://discord.com/api/webhooks/%s/%s\n[%s] INFO delivered message %s" % (
        ts(), did, tok, ts(), c.k(str(rint(10 ** 17, 10 ** 18))))


@scen("webhook_payload", 10)
def sc_whpayload(c):
    body = {"id": c.k(n_stripe_id("evt")), "object": "event", "type": "customer.created",
            "data": {"object": {"id": c.k(n_stripe_id("cus")), "email": email(),
                                "metadata": {"internal_api_key": c.g(g_generic(), "generic_api_key")}}}}
    sig = "t=%d,v1=%s" % (epoch(), c.k(rhex(64)))
    c.cmd("tail -f logs/webhooks.log")
    return "%s received webhook Stripe-Signature: %s body=%s" % (ts(), sig, json.dumps(body))


@scen("jwt_decode", 12)
def sc_jwtdecode(c):
    claims = jwt_claims()
    tok = c.s(g_jwt(claims=claims), "jwt")
    c.cmd("jwt decode %s" % ("$TOKEN" if chance(0.5) else "-"))
    hdr = json.loads(base64.urlsafe_b64decode(tok.split(".")[0] + "==").decode())
    return ("\nToken header\n------------\n%s\n\nToken claims\n------------\n%s\n\n$ echo $TOKEN\n%s") % (
        json.dumps(hdr, indent=2), json.dumps(claims, indent=2), tok)


@scen("signed_url", 16)
def sc_signed(c):
    v = R.randrange(3)
    key = "%s/%s/%s" % (pick(["uploads", "exports", "backups"]), c.k(g_uuid()), pick(["report.pdf", "dump.sql.gz", "avatar.png"]))
    if v == 0:
        akid = c.s(g_akid(chance(0.5)), "aws_access_key_id")
        sig = c.s(rhex(64), "aws_presigned_signature", "generic")
        c.kind = "aws_presigned_url"
        url = ("https://%s.s3.%s.amazonaws.com/%s?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=%s%%2F%s%%2F%s%%2Fs3%%2Faws4_request"
               "&X-Amz-Date=%sT%sZ&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=%s") % (
            proj(), pick(REGIONS), key, akid, "20260914", pick(REGIONS), "20260914", "101500", sig)
        if akid.startswith("ASIA"):
            tok = c.s(g_aws_session(), "aws_session_token")
            url = url.replace("&X-Amz-SignedHeaders", "&X-Amz-Security-Token=%s&X-Amz-SignedHeaders" % tok.replace("+", "%2B").replace("/", "%2F"))
            c.secrets[-1] = tok.replace("+", "%2B").replace("/", "%2F")
        c.cmd("aws s3 presign s3://%s/%s --expires-in 3600" % (proj(), key))
        return url
    if v == 1:
        sig = c.g(rhex(512), "gcs_signed_url_signature")
        c.cmd("gsutil signurl -d 1h sa.json gs://%s/%s" % (proj(), key))
        return ("URL\tHTTP Method\tExpiration\tSigned URL\ngs://%s/%s\tGET\t%s\thttps://storage.googleapis.com/%s/%s?"
                "x-goog-signature=%s&x-goog-algorithm=GOOG4-RSA-SHA256&x-goog-credential=%s%%40%s.iam.gserviceaccount.com"
                "%%2F20260914%%2Fauto%%2Fstorage%%2Fgoog4_request&x-goog-date=20260914T101500Z&x-goog-expires=3600&x-goog-signedheaders=host") % (
            proj(), key, ts_plain(), proj(), key, sig, pick(["uploader", "signer"]), proj())
    sig = b64(rbytes(32))
    enc = sig.replace("+", "%2B").replace("/", "%2F").replace("=", "%3D")
    c.g(enc, "azure_sas_signature")
    c.cmd("az storage blob generate-sas --full-uri")
    return "\"https://%s.blob.core.windows.net/%s?se=2026-10-01T00%%3A00Z&sp=r&sv=2022-11-02&sr=b&sig=%s\"" % (
        proj().replace("-", ""), key, enc)


@scen("oauth_callback", 14)
def sc_oauth(c):
    code = pick([lambda: c.g(rs(B64U, 43), "oauth_code"), lambda: c.s("4/0A" + rs(B64U, 70), "google_oauth_code"),
                 lambda: c.g(rhex(20), "oauth_code")])()
    state = c.k(rs(B64U, 32))
    host = pick(["localhost:3000", "app." + domain(), "127.0.0.1:8976"])
    url = "https://%s/auth/callback?code=%s&state=%s" % (host, code, state) if not host.startswith("l") and not host.startswith("1") else \
        "http://%s/auth/callback?code=%s&state=%s" % (host, code, state)
    lines = ["%s GET /auth/callback 302" % ts(), "  url=%s" % url]
    if chance(0.6):
        at = c.g(g_urlsafe(), "oauth_access_token") if chance(0.5) else c.s(g_gh("gho_"), "github_token")
        lines.append("  token exchange ok: {\"access_token\":\"%s\",\"token_type\":\"bearer\",\"scope\":\"repo,user\"}" % at)
    c.cmd("npm run dev")
    return "\n".join(lines)


@scen("magic_link", 12)
def sc_magic(c):
    tok = pick([lambda: c.g(g_urlsafe(32), "magic_link_token"), lambda: c.g(rhex(64), "magic_link_token"),
                lambda: c.s(g_jwt("HS256", jwt_claims(purpose="login")), "jwt")])()
    c.kind = "magic_link_token"
    url = "https://app.%s/auth/verify?token=%s&email=%s" % (domain(), tok, email().replace("@", "%40"))
    c.cmd("docker compose logs mailer")
    return ("mailer-1  | [%s] DEV MODE: email not sent, printing instead\nmailer-1  | To: %s\nmailer-1  | Subject: Your sign-in link\n"
            "mailer-1  | Click to sign in (expires in 15 minutes):\nmailer-1  | %s\nmailer-1  | Message-ID: <%s@%s>") % (
        ts(), email(), url, c.k(g_uuid()), domain())


@scen("password_reset_email", 10)
def sc_reset(c):
    tok = c.g(pick([lambda: rs(B62, 40), lambda: g_urlsafe(32), lambda: rhex(40)])(), "password_reset_token")
    uidb = b64u(str(rint(1, 9999)).encode())
    mid = c.k(n_ulid())
    c.path("tmp/mails/%s.eml" % mid)
    temp = c.pw(g_password()) if chance(0.4) else None
    body = ("Message-ID: <%s@mail.%s>\n" % (mid, domain())) + ("From: no-reply@%s\nTo: %s\nSubject: Reset your password\n\nHi,\n\nSomeone requested a password reset. "
            "Use the link below:\n\nhttps://%s/reset/%s/%s/\n\n") % (domain(), email(), domain(), uidb, tok)
    if temp:
        body += "Or sign in with this temporary password: %s\n\n" % temp
    return body + "If you did not request this, ignore this email."


@scen("totp_setup", 12)
def sc_totp(c):
    sec = c.g(g_totp(), "totp_secret")
    acct = email()
    lines = ["otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30" % (
        pick(COMPANIES), acct.replace("@", "%40"), sec, pick(COMPANIES))]
    if chance(0.6):
        lines.append("\nBackup codes (each can be used once):")
        for _ in range(rint(4, 10)):
            lines.append("  " + c.g(g_backup_code(), "backup_code"))
    c.cmd(pick(["python scripts/enroll_mfa.py --user %s" % acct, "zbarimg qr.png"]))
    return "\n".join(lines)


# ---------------------------------------------------------------- positive scenarios: chat / review / CI / transcripts
CHAT_LEADS = ["here's the staging token: {s}", "use this one {s}", "try `{s}` — it's the sandbox key",
              "ok new key since the old one got rotated: {s}", "pw for the shared admin acct is {s} (pls don't share)",
              "{s}", "creds: {u} / {s}", "just DM'd you but in case: {s}", "can someone check why {s} returns 401??",
              "fwiw prod uses {s}, staging is in 1password"]


def chat_secret(c):
    x = R.random()
    if x < 0.35:
        return draw(c, cat="vendor")[1]
    if x < 0.7:
        return draw(c, cat="generic")[1]
    return c.pw(g_password())


@scen("slack_chat", 18)
def sc_slack(c):
    msgs = []
    who = [pick(USERS) for _ in range(4)]
    msgs.append("[%s] %s: anyone have creds for the %s %s?" % (dt().strftime("%H:%M"), who[0], pick(["staging", "qa", "prod"]), proj()))
    s = chat_secret(c)
    msgs.append("[%s] %s: %s" % (dt().strftime("%H:%M"), who[1], pick(CHAT_LEADS).format(s=s, u=user())))
    if chance(0.5):
        msgs.append("[%s] %s: thx! deploying %s now" % (dt().strftime("%H:%M"), who[0], c.k(n_short())))
    if chance(0.3):
        s2 = chat_secret(c)
        msgs.append("[%s] %s: also the webhook signing secret is %s" % (dt().strftime("%H:%M"), who[2], s2))
    if chance(0.4):
        msgs.append("[%s] %s: thread: https://%s.slack.com/archives/C%s/p%d" % (
            dt().strftime("%H:%M"), who[3], pick(COMPANIES).lower(), c.k(rs(UP + DIG, 10)), epoch() * 10 ** 6 + rint(0, 999999)))
    c.cmd("slack-export view #%s" % pick(["eng", "backend", "deploys", "incident-%d" % rint(100, 999)]))
    return "\n".join(msgs)


@scen("discord_chat", 8)
def sc_discord(c):
    s = chat_secret(c)
    c.path("exports/discord/%s.txt" % pick(["dev-chat", "bot-dev"]))
    return ("[%s] %s#%04d\n%s\n\n[%s] %s#%04d\nworks, ty. bot id is %s") % (
        ts_plain(), user(), rint(1, 9999), pick(CHAT_LEADS).format(s=s, u=user()), ts_plain(), user(), rint(1, 9999),
        c.k(str(rint(10 ** 17, 10 ** 18))))


@scen("pr_review", 14)
def sc_pr(c):
    sha = c.k(n_sha())
    n, v = draw(c)
    f = pick(["src/config.ts", "app/settings.py", "internal/client/client.go", "config/initializers/stripe.rb"])
    lines = ["%s commented on %s (line %d) in commit %s:" % (user(), f, rint(5, 200), sha),
             "> -const KEY = process.env.%s;" % n, "> +const KEY = \"%s\";" % v,
             "", pick(["Please don't hardcode this, move it to the secrets manager.", "Is this the prod key?? we need to rotate it",
                       "nit: this should come from env", "LGTM once the key is pulled out"])]
    c.k("process.env.%s" % n)
    c.cmd("gh pr view %d --comments" % rint(100, 4000))
    return "\n".join(lines)


@scen("gha_log", 18)
def sc_gha(c):
    lines = ["%s ##[group]Run actions/checkout@v4" % ts(), "%s ##[endgroup]" % ts(),
             "%s HEAD is now at %s %s" % (ts(), c.k(n_short()), pick(["fix: retry on 429", "chore: bump deps", "feat: add exporter"]))]
    v = R.randrange(3)
    if v == 0:
        lines.append("%s ##[group]Run ./scripts/deploy.sh" % ts())
        lines.append("%s   %s: ***" % (ts(), pick(ENVN)))
        c.k("***")
        n, val = draw(c)
        lines.append("%s Using %s=%s" % (ts(), n, val))
    elif v == 1:
        lines.append("%s Run echo \"${{ secrets.%s }}\" | base64" % (ts(), pick(ENVN)))
        c.k("${{ secrets.")
        n, val = draw(c)
        lines.append("%s %s" % (ts(), b64(val.encode())))
        c.secrets[-1] = b64(val.encode())
    else:
        tok = c.s(g_gh("ghs_"), "github_token")
        lines.append("%s [command]/usr/bin/git -c http.extraheader=\"AUTHORIZATION: bearer %s\" fetch --depth=1 origin %s" % (
            ts(), tok, c.k(n_sha())))
    lines.append("%s ##[error]Process completed with exit code %d." % (ts(), pick([1, 2, 127])))
    c.cmd("gh run view %d --log-failed" % rint(10 ** 9, 10 ** 10))
    return "\n".join(lines)


def llm_json(text_in_tool, cmd):
    style = R.randrange(2)
    tid = ("toolu_01" + rs(B62, 22)) if style == 0 else ("call_" + rs(B62, 24))
    if style == 0:
        msgs = [{"role": "assistant", "content": [{"type": "text", "text": "Let me check the environment."},
                                                  {"type": "tool_use", "id": tid, "name": "Bash", "input": {"command": cmd}}]},
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": tid, "content": text_in_tool}]}]
    else:
        msgs = [{"role": "assistant", "content": None, "tool_calls": [{"id": tid, "type": "function", "function": {
            "name": "run_shell", "arguments": json.dumps({"cmd": cmd})}}]},
                {"role": "tool", "tool_call_id": tid, "content": text_in_tool}]
    return tid, json.dumps({"messages": msgs}) if chance(0.5) else "\n".join(json.dumps(m) for m in msgs)


@scen("llm_transcript", 26)
def sc_llm(c):
    inner = Case("tmp")
    pairs = benign_env(inner, 2) + [draw(inner) for _ in range(rint(1, 3))]
    raw = "\n".join("%s=\"%s\"" % kv for kv in pairs)
    cmd = pick(["cat .env", "printenv", "grep -r KEY config/"])
    if chance(0.4):
        n, v = pick(pairs[2:])
        cmd = "curl -s -H 'Authorization: Bearer %s' https://api.%s/v1/me" % (v, domain())
        raw += "\n{\"id\": \"%s\", \"name\": \"%s\"}" % (inner.k(g_uuid()), pick(FULLN))
    tid, out = llm_json(raw, cmd)
    # secrets/keeps appear JSON-escaped in the transcript
    for s, (kind, cat) in zip(inner.secrets, inner.cats):
        e = json.dumps(s)[1:-1]
        if chance(0.5) and "\\" not in e:
            e2 = json.dumps(json.dumps(s)[1:-1])[1:-1]
            if e2 in out:
                e = e2
        c.s(e, kind, cat)
    for k in inner.keep:
        c.k(json.dumps(k)[1:-1])
    c.k(tid)
    c.path(pick(["~/.claude/projects/-home-%s-code-%s/%s.jsonl" % (user(), proj(), g_uuid()), "transcripts/run-%d.json" % rint(1, 999)]))
    return out


# ---------------------------------------------------------------- positive scenarios: connection strings / infra configs
@scen("jdbc_url", 10)
def sc_jdbc(c):
    pw = c.pw(g_password(urlsafe=True), "db_password")
    v = R.randrange(3)
    if v == 0:
        c.path("src/main/resources/application.properties")
        return ("spring.datasource.url=jdbc:postgresql://db.internal:5432/%s?user=%s&password=%s&ssl=true\n"
                "spring.jpa.hibernate.ddl-auto=validate\nmanagement.endpoints.web.exposure.include=health") % (pick(DBNAMES), user(), pw)
    if v == 1:
        c.path("application.yml")
        return "spring:\n  datasource:\n    url: jdbc:mysql://%s:3306/%s\n    username: %s\n    password: %s" % (ip(), pick(DBNAMES), user(), pw)
    c.cmd("./gradlew bootRun")
    return "HikariPool-1 - Exception during pool initialization.\njdbc:sqlserver://sql.%s:1433;databaseName=%s;user=%s;password=%s;encrypt=true" % (
        domain(), pick(DBNAMES), user(), pw)


@scen("redis_auth", 10)
def sc_redis(c):
    pw = c.pw(g_password(urlsafe=True), "redis_password") if chance(0.6) else c.g(g_hexkey(64), "redis_password")
    v = R.randrange(3)
    if v == 0:
        c.cmd("redis-cli -u redis://default:%s@cache.internal:6379 ping" % pw)
        return "$ " + c.hint["command"] + "\nWarning: Using a password with '-a' or '-u' option on the command line interface may not be safe.\nPONG"
    if v == 1:
        c.path("/etc/redis/redis.conf")
        return "bind 0.0.0.0\nport 6379\nrequirepass %s\nmasterauth %s\nmaxmemory 2gb" % (pw, pw)
    c.cmd("docker logs worker")
    return "Error: connect ECONNREFUSED; REDIS_URL=rediss://default:%s@%s.upstash.io:6379\n    at TCPConnectWrap.afterConnect" % (
        pw, pick(WORDS) + "-" + pick(WORDS) + "-" + str(rint(10000, 99999)))


@scen("mongodb_uri", 10)
def sc_mongo(c):
    pw = c.pw(g_password(urlsafe=True), "db_password")
    cl = "%s.%s.mongodb.net" % (pick(["cluster0", "prod", proj()]), rs(LOW + DIG, 5))
    uri = "mongodb+srv://%s:%s@%s/%s?retryWrites=true&w=majority&appName=%s" % (user(), pw, cl, pick(DBNAMES), proj())
    c.cmd(pick(["mongosh \"%s\"" % uri, "node scripts/seed.js"]))
    if c.hint["command"].startswith("mongosh"):
        return "Current Mongosh Log ID:\t%s\nConnecting to:\t\t%s\nMongoServerError: bad auth : authentication failed" % (c.k(rhex(24)), uri)
    return "MongoParseError: URI malformed\n    uri: '%s'\n    at new ConnectionString" % uri


@scen("amqp_url", 8)
def sc_amqp(c):
    pw = c.pw(g_password(urlsafe=True))
    host = pick(["rabbitmq", "mq.internal", "%s.rmq.cloudamqp.com" % pick(WORDS)])
    c.cmd("celery -A %s worker -l info" % proj().replace("-", "_"))
    return ("[%s: INFO/MainProcess] Connected to amqp://%s:%s@%s:5672/%s\n[%s: INFO/MainProcess] mingle: searching for neighbors\n"
            "[%s: INFO/MainProcess] celery@%s ready.") % (ts_plain(), user(), pw, host, pick(["", "vhost", proj()]), ts_plain(), ts_plain(), n_pod())


@scen("ldap_bind", 8)
def sc_ldap(c):
    pw = c.pw(g_password(shell=True))
    dc = ",".join("dc=" + p for p in domain().split("."))
    c.cmd("ldapsearch -x -H ldaps://ldap.%s -D \"cn=%s,ou=svc,%s\" -w '%s' -b \"%s\" \"(uid=%s)\"" % (domain(), user(), dc, pw, dc, user()))
    if chance(0.5):
        c.path("/etc/sssd/sssd.conf")
        return "[domain/default]\nldap_uri = ldaps://ldap.%s\nldap_default_bind_dn = cn=svc-sssd,ou=svc,%s\nldap_default_authtok = %s\nldap_search_base = %s" % (
            domain(), dc, pw, dc)
    return "# extended LDIF\n# search result\nsearch: 2\nresult: 49 Invalid credentials\ntext: 80090308: LdapErr: DSID-0C09044E\n# bound as cn=%s,ou=svc,%s using password %s" % (
        user(), dc, pw)


@scen("smtp_settings", 10)
def sc_smtp(c):
    v = R.randrange(3)
    if v == 0:
        pw = c.s(g_sendgrid(), "sendgrid_api_key")
        host, u = "smtp.sendgrid.net", "apikey"
    elif v == 1:
        pw = c.g(rs(LOW, 16), "gmail_app_password")
        pw_disp = " ".join(pw[i:i + 4] for i in range(0, 16, 4))
        c.secrets[-1] = pw_disp
        pw = pw_disp
        host, u = "smtp.gmail.com", email()
    else:
        pw = c.g(rs(B62 + "+/", 44), "aws_ses_smtp_password")
        host, u = "email-smtp.%s.amazonaws.com" % pick(REGIONS), c.s(g_akid(), "aws_access_key_id")
    c.path(pick(["config/mail.yml", "settings/local.py", "/etc/postfix/sasl_passwd"]))
    if c.hint["path"].endswith("sasl_passwd"):
        return "[%s]:587 %s:%s" % (host, u, pw)
    if c.hint["path"].endswith(".py"):
        return "EMAIL_HOST = '%s'\nEMAIL_PORT = 587\nEMAIL_HOST_USER = '%s'\nEMAIL_HOST_PASSWORD = '%s'\nEMAIL_USE_TLS = True" % (host, u, pw)
    return "smtp:\n  address: %s\n  port: 587\n  user_name: %s\n  password: \"%s\"\n  authentication: plain" % (host, u, pw)


@scen("mqtt_iot", 10)
def sc_mqtt(c):
    dev = "%s-%s" % (pick(["sensor", "gw", "thermo", "cam"]), rhex(6))
    v = R.randrange(3)
    if v == 0:
        c.path("device/config.json")
        return json.dumps({"device_id": dev, "broker": "mqtts://%s.iot.%s:8883" % (proj(), domain()), "username": dev,
                           "password": c.pw(g_password()), "topic": "devices/%s/telemetry" % dev,
                           "firmware_sha256": c.k(n_sha256sum())}, indent=2)
    if v == 1:
        hk = c.g(b64(rbytes(32)), "azure_iot_shared_access_key")
        c.path("secrets.h")
        return ("#define IOT_HUB_CONN \"HostName=%s.azure-devices.net;DeviceId=%s;SharedAccessKey=%s\"\n"
                "#define WIFI_SSID \"%s\"\n#define WIFI_PASS \"%s\"") % (proj(), dev, hk, pick(WORDS).capitalize() + "Net", c.pw(g_password(), "wifi_password"))
    c.cmd("mosquitto_sub -h broker.%s -p 8883 -u %s -P '%s' -t 'devices/#' -v" % (domain(), dev, c.pw(g_password(shell=True))))
    return "$ " + c.hint["command"] + "\n" + "devices/%s/telemetry {\"t\":%.1f,\"rh\":%d,\"msg_id\":\"%s\"}" % (dev, R.random() * 30, rint(20, 80), c.k(n_ulid()))


@scen("wifi_config", 8)
def sc_wifi(c):
    ssid = pick(WORDS).capitalize() + pick(["-5G", "_Guest", "Office", "-IoT"])
    v = R.randrange(2)
    if v == 0:
        c.path("/etc/wpa_supplicant/wpa_supplicant.conf")
        psk = c.pw(g_password(shell=True), "wifi_password")
        return "ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev\nupdate_config=1\ncountry=US\n\nnetwork={\n\tssid=\"%s\"\n\tpsk=\"%s\"\n\tkey_mgmt=WPA-PSK\n}" % (ssid, psk)
    c.cmd("nmcli -s connection show '%s' | grep -i psk" % ssid)
    psk = c.pw(g_password(shell=True), "wifi_password")
    return "802-11-wireless-security.psk:            %s\n802-11-wireless-security.psk-flags:      0 (none)" % psk


# ---------------------------------------------------------------- positive scenarios: keys / wallets / mobile
@scen("ssh_private_key", 14)
def sc_sshkey(c):
    v = R.randrange(4)
    if v == 0:
        k = c.g(g_openssh_key(), "openssh_private_key")
        c.cmd("cat ~/.ssh/id_ed25519")
        return k
    if v == 1:
        k = c.g(g_rsa_pem(), "rsa_private_key")
        c.cmd("cat deploy_key.pem")
        return k
    if v == 2:
        k = c.g(g_openssh_key(), "openssh_private_key")
        pub = c.k(n_ssh_pub("ed25519"))
        c.cmd("ls ~/.ssh && cat ~/.ssh/id_ed25519 ~/.ssh/id_ed25519.pub")
        return "config  id_ed25519  id_ed25519.pub  known_hosts\n%s\n%s %s@%s" % (k, pub, user(), pick(["laptop", "devbox"]))
    k = c.g(g_ec_pem(), "ec_private_key")
    c.cmd("openssl ecparam -name prime256v1 -genkey -noout")
    return k


@scen("pgp_private_key", 6)
def sc_pgp(c):
    fpr = c.k(rhex(40).upper())
    c.cmd("gpg --list-secret-keys --keyid-format long && gpg --export-secret-keys --armor %s" % fpr[-16:])
    head = "sec   %s %s [SC]\n      %s\nuid                 [ultimate] %s <%s>\nssb   %s %s [E]\n\n" % (
        pick(["rsa4096/" + fpr[-16:], "ed25519/" + fpr[-16:]]), dt().strftime("%Y-%m-%d"), fpr, pick(FULLN), email(),
        pick(["rsa4096", "cv25519"]) + "/" + c.k(rhex(16).upper()), dt().strftime("%Y-%m-%d"))
    return head + c.g(g_pgp_private(), "pgp_private_key")


@scen("pkcs8_in_json", 14)
def sc_pkcs8json(c):
    v = R.randrange(3)
    if v == 0:
        pkey = g_pkcs8_pem() + "\n"
        enc = json.dumps(pkey)[1:-1]
        c.g(enc, "gcp_service_account_key")
        c.path(pick(["service-account.json", "gcp-key.json", "credentials/%s-sa.json" % proj()]))
        sa = "%s@%s-%d.iam.gserviceaccount.com" % (pick(["deployer", "ci", "uploader"]), proj(), rint(100000, 999999))
        d = {"type": "service_account", "project_id": "%s-%d" % (proj(), rint(100000, 999999)),
             "private_key_id": c.g(rhex(40), "gcp_private_key_id"), "private_key": pkey,
             "client_email": sa, "client_id": c.k(str(rint(10 ** 20, 10 ** 21))),
             "auth_uri": "https://accounts.google.com/o/oauth2/auth", "token_uri": "https://oauth2.googleapis.com/token",
             "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/%s" % sa.replace("@", "%40"),
             "universe_domain": "googleapis.com"}
        return json.dumps(d, indent=2)
    if v == 1:
        pkey = g_pkcs8_pem()
        enc = json.dumps(pkey)[1:-1]
        c.g(enc, "private_key_in_json")
        c.cmd("firebase functions:config:get")
        return json.dumps({"github_app": {"app_id": str(rint(10 ** 5, 10 ** 6)), "private_key": pkey,
                                          "webhook_secret": c.g(g_hexkey(40), "webhook_secret")}}, indent=2)
    pkey = g_rsa_pem()
    enc = json.dumps(pkey)[1:-1]
    c.g(enc, "private_key_in_json")
    c.cmd("vault kv get -format=json secret/%s/tls" % proj())
    return json.dumps({"request_id": c.k(g_uuid()), "lease_duration": 0, "data": {"data": {"tls.key": pkey,
                       "tls.crt": n_cert_pem()}, "metadata": {"version": rint(1, 9)}}})


@scen("putty_key", 6)
def sc_putty(c):
    pub = b64(sshstr(b"ssh-ed25519") + sshstr(rbytes(32)))
    priv = c.g(b64(sshstr(rbytes(32))), "putty_private_key")
    c.path("%s.ppk" % user())
    return ("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: %s@%s\nPublic-Lines: 2\n%s\nPrivate-Lines: 1\n%s\nPrivate-MAC: %s" % (
        user(), pick(["win-laptop", "jumpbox"]), wrap(pub, 64), priv, c.k(rhex(64))))


@scen("seed_phrase", 12)
def sc_seed(c):
    ph = c.g(g_bip39(), "bip39_mnemonic")
    v = R.randrange(4)
    if v == 0:
        c.path(".env")
        return "RPC_URL=https://eth-mainnet.g.alchemy.com/v2/%s\nMNEMONIC=\"%s\"\nDEPLOYER=0x%s" % (
            c.g(rs(B64U, 32), "alchemy_api_key"), ph, c.k(rhex(40)))
    if v == 1:
        c.path("hardhat.config.js")
        return "module.exports = {\n  networks: {\n    sepolia: {\n      url: \"https://sepolia.infura.io/v3/%s\",\n      accounts: { mnemonic: \"%s\" },\n    },\n  },\n};" % (
            c.g(rhex(32), "infura_project_id"), ph)
    if v == 2:
        c.cmd("npx hardhat node")
        return "Started HTTP and WebSocket JSON-RPC server at http://127.0.0.1:8545/\n\nwallet seed: %s\nAccount #0: 0x%s (10000 ETH)\nPrivate Key: 0x%s" % (
            ph, c.k(rhex(40)), c.g(rhex(64), "eth_private_key"))
    return "[%s] %s: backup of my test wallet in case laptop dies: %s" % (dt().strftime("%H:%M"), user(), ph)


@scen("eth_private_key", 8)
def sc_eth(c):
    pk = c.g(rhex(64), "eth_private_key")
    c.cmd(pick(["forge script script/Deploy.s.sol --broadcast", "cast wallet new"]))
    if c.hint["command"].startswith("cast"):
        return "Successfully created new keypair.\nAddress:     0x%s\nPrivate key: 0x%s" % (c.k(rhex(40)), pk)
    return "Script ran successfully.\n## Setting up 1 EVM.\nPRIVATE_KEY=0x%s forge script ...\nTransaction hash: 0x%s\nBlock: %d" % (
        pk, c.k(rhex(64)), rint(10 ** 6, 10 ** 7))


@scen("google_services_json", 8)
def sc_gsj(c):
    key = c.s(g_google_api(), "google_api_key")
    pnum = str(rint(10 ** 11, 10 ** 12))
    d = {"project_info": {"project_number": pnum, "project_id": proj() + "-app", "storage_bucket": proj() + "-app.appspot.com"},
         "client": [{"client_info": {"mobilesdk_app_id": c.k("1:%s:android:%s" % (pnum, rhex(16))),
                                     "android_client_info": {"package_name": "com.%s.app" % proj().replace("-", "")}},
                     "oauth_client": [{"client_id": c.k("%s-%s.apps.googleusercontent.com" % (pnum, rs(LOW + DIG, 32))), "client_type": 3}],
                     "api_key": [{"current_key": key}]}], "configuration_version": "1"}
    c.path("android/app/google-services.json")
    return json.dumps(d, indent=2)


@scen("info_plist", 8)
def sc_plist(c):
    entries = [("CFBundleIdentifier", "com.%s.ios" % proj().replace("-", "")), ("API_KEY", c.s(g_google_api(), "google_api_key"))]
    if chance(0.6):
        entries.append(("REVENUECAT_SECRET", c.s("sk_" + rs(B62, 32), "revenuecat_secret_key")))
    else:
        entries.append(("BackendSharedSecret", c.g(g_hexkey(64), "generic_secret")))
    entries.append(("GOOGLE_APP_ID", c.k("1:%d:ios:%s" % (rint(10 ** 11, 10 ** 12), rhex(16)))))
    c.path(pick(["ios/Runner/GoogleService-Info.plist", "ios/App/Info.plist"]))
    body = "\n".join("\t<key>%s</key>\n\t<string>%s</string>" % kv for kv in entries)
    return '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">\n<dict>\n%s\n</dict>\n</plist>' % body


@scen("firebase_admin", 8)
def sc_firebase(c):
    v = R.randrange(2)
    if v == 0:
        c.path("functions/.runtimeconfig.json")
        return json.dumps({"fcm": {"server_key": c.s(g_fcm(), "fcm_server_key")}, "app": {"env": "prod",
                           "build": c.k(n_short())}}, indent=2)
    db = "https://%s-default-rtdb.firebaseio.com" % proj()
    sec = c.g(rs(B62, 40), "firebase_db_secret")
    c.cmd("curl '%s/users.json?auth=%s'" % (db, sec))
    return "{\"%s\":{\"email\":\"%s\",\"last\":\"%s\"}}\n# legacy database secret used: %s" % (c.k("-N" + rs(B64U, 18)), email(), ts(), sec)


@scen("positional_arg", 14)
def sc_positional(c):
    k = c.g(pick([g_hexkey, g_b62key, g_urlsafe, g_b64key])(), "unnamed_positional")
    v = R.randrange(4)
    if v == 0:
        c.cmd("./scripts/rotate.sh")
        return "+ ./bin/cli sync %s %s --region %s\nsynced %d records (batch %s)" % (proj(), k, pick(REGIONS), rint(1, 9999), c.k(n_ulid()))
    if v == 1:
        c.cmd("ps -eo pid,args | grep worker")
        return "%d /usr/bin/python3 -m worker %s %s\n%d grep --color=auto worker" % (rint(100, 9999), pick(DBNAMES), k, rint(100, 9999))
    if v == 2:
        c.cmd("cat Procfile")
        return "web: bin/server --port $PORT\nworker: bin/worker %s --queue default" % k
    pod = c.k(n_pod())
    c.cmd("kubectl describe pod %s" % pod)
    return "Name:         %s\n" % pod + "Containers:\n  app:\n    Image:      %s\n    Args:\n      --config\n      /etc/app/config.yaml\n      %s\n    State:          Running" % (
        "ghcr.io/%s/%s@%s" % (user(), proj(), c.k(n_digest())), k)


@scen("neutral_field", 14)
def sc_neutral(c):
    k = c.g(pick([g_hexkey, g_b62key, g_urlsafe])(), "unnamed_neutral_field")
    fld = pick(["value", "data", "x", "credential", "auth", "k", "param1", "blob", "code"])
    v = R.randrange(3)
    if v == 0:
        c.path("config/integrations.yaml")
        return "integrations:\n  - name: %s\n    endpoint: https://hooks.%s/in\n    %s: %s\n    id: %s" % (
            pick(["pagerduty", "crm", "billing"]), domain(), fld, k, c.k(g_uuid()))
    if v == 1:
        c.cmd("sqlite3 app.db 'select * from settings'")
        return "1|smtp_port|587\n2|%s|%s\n3|cache_bust|%s\n4|feature_flags|{\"beta\":true}" % (
            pick(["remote_auth", "sync_key", "partner"]), k, c.k(rhex(8)))
    c.cmd("aws ssm get-parameters-by-path --path /%s --with-decryption" % proj())
    return json.dumps({"Parameters": [{"Name": "/%s/%s" % (proj(), fld), "Type": "SecureString", "Value": k, "Version": rint(1, 9),
                                       "ARN": "arn:aws:ssm:%s:%s:parameter/%s/%s" % (pick(REGIONS), n_acct(), proj(), fld)}]}, indent=4)


@scen("k8s_configmap_leak", 8)
def sc_cm(c):
    n, v = draw(c)
    c.cmd("kubectl get configmap %s-config -o yaml" % proj())
    return "apiVersion: v1\ndata:\n  LOG_LEVEL: info\n  %s: %s\n  FEATURE_FLAGS: beta,new-checkout\nkind: ConfigMap\n%s" % (
        n, v, "\n".join(k8s_meta(c, proj() + "-config", "prod")))


@scen("ci_yaml_hardcoded", 10)
def sc_ciyaml(c):
    n, v = draw(c)
    c.path(pick([".github/workflows/deploy.yml", ".gitlab-ci.yml", ".circleci/config.yml"]))
    good = c.k("${{ secrets.%s }}" % pick(ENVN))
    return "jobs:\n  deploy:\n    runs-on: ubuntu-latest\n    env:\n      %s: %s\n      SAFE_ONE: %s\n    steps:\n      - uses: actions/checkout@%s" % (
        n, v, good, c.k(n_sha()))


@scen("docker_build_args", 8)
def sc_buildargs(c):
    n, v = draw(c, shell=True)
    c.cmd("docker history --no-trunc %s:latest" % proj())
    return "IMAGE          CREATED        CREATED BY\n%s   2 days ago     RUN |1 %s=%s /bin/sh -c npm ci && npm run build\n<missing>      2 days ago     ARG %s" % (
        c.k(n_digest()), n, v, n)


# ---------------------------------------------------------------- negative scenarios
MSGS = ["fix: handle empty cursor", "chore(deps): bump lodash from 4.17.20 to 4.17.21", "feat: add retry to uploader",
        "refactor auth middleware", "Merge pull request #%d from %s/fix-ci", "docs: update README", "test: flaky timeout",
        "revert \"feat: new checkout\"", "perf: cache compiled regexes", "ci: pin actions by sha"]


def commit_msg():
    m = pick(MSGS)
    return m % (rint(100, 5000), user()) if "%d" in m else m


@scen("git_log", 20)
def ng_gitlog(c):
    v = R.randrange(3)
    out = []
    if v == 0:
        c.cmd("git log --oneline -n 12")
        for _ in range(rint(6, 12)):
            out.append("%s %s" % (c.k(rhex(pick([7, 8, 9]))), commit_msg()))
    elif v == 1:
        c.cmd("git log -3")
        for _ in range(3):
            out += ["commit %s" % c.k(n_sha()), "Author: %s <%s>" % (pick(FULLN), email()),
                    "Date:   %s +0000" % dt().strftime("%a %b %d %H:%M:%S %Y"), "", "    " + commit_msg(), ""]
            if chance(0.3):
                out.insert(-1, "    Change-Id: I%s" % c.k(rhex(40)))
    else:
        c.cmd("git log --format='%H %G? %s' -5")
        for _ in range(5):
            out.append("%s %s %s" % (c.k(n_sha()), pick("GNU"), commit_msg()))
    return "\n".join(out)


@scen("git_blame_rebase", 14)
def ng_blame(c):
    if chance(0.5):
        c.cmd("git blame -L 10,20 src/client.ts")
        out = []
        for i in range(10, 10 + rint(5, 10)):
            out.append("%s (%s %s %3d) %s" % (c.k(rhex(8)), pick(FULLN).ljust(14), dt().strftime("%Y-%m-%d"), i,
                                              pick(["const apiKey = process.env.API_KEY;", "  return fetch(url, opts);", "}", "",
                                                    "import { retry } from './retry';"])))
        c.k("process.env.API_KEY") if any("process.env" in o for o in out) else None
        return "\n".join(out)
    c.cmd("git rebase -i HEAD~5")
    out = ["%s %s %s" % (pick(["pick", "pick", "squash", "fixup", "reword"]), c.k(rhex(7)), commit_msg()) for _ in range(5)]
    out += ["", "# Rebase %s..%s onto %s (5 commands)" % (c.k(rhex(7)), c.k(rhex(7)), c.k(rhex(7))), "#", "# Commands:",
            "# p, pick <commit> = use commit"]
    return "\n".join(out)


@scen("docker_output", 16)
def ng_docker(c):
    v = R.randrange(3)
    img = "%s/%s" % (user(), proj())
    if v == 0:
        c.cmd("docker pull %s:latest" % img)
        layers = ["%s: Pull complete" % c.k(rhex(12)) for _ in range(rint(3, 7))]
        return "latest: Pulling from %s\n%s\nDigest: %s\nStatus: Downloaded newer image for %s:latest" % (
            img, "\n".join(layers), c.k(n_digest()), img)
    if v == 1:
        c.cmd("docker images --digests")
        rows = ["REPOSITORY            TAG       DIGEST                                                                    IMAGE ID       CREATED       SIZE"]
        for _ in range(rint(3, 6)):
            rows.append("%-21s %-9s %s   %s   %d days ago   %dMB" % (pick([img, "postgres", "redis", "node"]), pick(["latest", "16", "7-alpine", "20-slim"]),
                                                                    c.k(n_digest()), c.k(rhex(12)), rint(1, 90), rint(30, 900)))
        return "\n".join(rows)
    c.cmd("docker buildx build --push -t %s:%s ." % (img, n_short()))
    return "#12 exporting to image\n#12 exporting layers done\n#12 writing image %s done\n#12 pushing layers 2.3s done\n#12 pushing manifest for docker.io/%s@%s" % (
        c.k(n_digest()), img, c.k(n_digest()))


@scen("lockfile", 18)
def ng_lock(c):
    v = R.randrange(4)
    pk = pick(["lodash", "react", "zod", "chalk", "semver", "debug", "ms", "uuid", "axios", "express"])
    ver = "%d.%d.%d" % (rint(1, 18), rint(0, 20), rint(0, 30))
    if v == 0:
        c.path("package-lock.json")
        return json.dumps({"node_modules/%s" % pk: {"version": ver, "resolved": "https://registry.npmjs.org/%s/-/%s-%s.tgz" % (pk, pk, ver),
                                                   "integrity": c.k(n_integrity()), "license": "MIT"},
                           "node_modules/%s" % pick(["ms", "tslib"]): {"version": "2.1.3", "integrity": c.k(n_integrity()), "dev": True}}, indent=2)
    if v == 1:
        c.path("yarn.lock")
        return "\"%s@^%s\":\n  version \"%s\"\n  resolved \"https://registry.yarnpkg.com/%s/-/%s-%s.tgz#%s\"\n  integrity %s" % (
            pk, ver, ver, pk, pk, ver, c.k(rhex(40)), c.k(n_integrity()))
    if v == 2:
        c.path("poetry.lock")
        return "[[package]]\nname = \"requests\"\nversion = \"2.32.3\"\nfiles = [\n    {file = \"requests-2.32.3-py3-none-any.whl\", hash = \"sha256:%s\"},\n    {file = \"requests-2.32.3.tar.gz\", hash = \"sha256:%s\"},\n]" % (
            c.k(n_sha256sum()), c.k(n_sha256sum()))
    c.path("Cargo.lock")
    return "[[package]]\nname = \"serde\"\nversion = \"1.0.%d\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"%s\"" % (
        rint(100, 220), c.k(n_sha256sum()))


@scen("checksums", 14)
def ng_checksums(c):
    v = R.randrange(3)
    if v == 0:
        c.cmd("sha256sum dist/*")
        return "\n".join("%s  dist/%s" % (c.k(n_sha256sum()), f) for f in ["%s-linux-amd64.tar.gz" % proj(), "%s-darwin-arm64.tar.gz" % proj(), "checksums.txt"])
    if v == 1:
        c.path("go.sum")
        return "\n".join("%s v%d.%d.%d%s %s" % (m, rint(0, 2), rint(0, 30), rint(0, 9), suf, c.k(n_gosum()))
                         for m in ["github.com/stretchr/testify", "golang.org/x/sync", "github.com/google/uuid"] for suf in ["", "/go.mod"])
    c.path("requirements.txt")
    return "django==5.0.%d \\\n    --hash=sha256:%s \\\n    --hash=sha256:%s\nasgiref==3.8.1 \\\n    --hash=sha256:%s" % (
        rint(1, 9), c.k(n_sha256sum()), c.k(n_sha256sum()), c.k(n_sha256sum()))


@scen("webpack_build", 12)
def ng_webpack(c):
    c.cmd(pick(["npm run build", "vite build", "next build"]))
    rows = []
    for ext in ["js", "js", "css", "js", "woff2"]:
        nm = n_hashname(ext)
        c.k(nm.split(".")[1])
        rows.append("dist/assets/%s   %6.2f kB │ gzip: %6.2f kB" % (nm, R.random() * 300, R.random() * 90))
    rows.append("✓ built in %.2fs" % (R.random() * 20))
    if chance(0.4):
        rows.append("Build ID: %s" % c.k(rs(B64U, 21)))
    return "\n".join(rows)


@scen("app_log_ids", 22)
def ng_applog(c):
    c.cmd(pick(["kubectl logs deploy/%s --tail 20" % proj(), "journalctl -u %s -n 20" % proj(), "docker logs api"]))
    out = []
    for _ in range(rint(4, 8)):
        f = R.randrange(5)
        if f == 0:
            out.append("%s INFO  request_id=%s method=GET path=/v1/orders status=200 dur=%dms" % (ts(), c.k(n_reqid()), rint(1, 900)))
        elif f == 1:
            out.append("%s DEBUG job %s enqueued (ulid=%s)" % (ts(), c.k(g_uuid()), c.k(n_ulid())))
        elif f == 2:
            out.append('{"level":"info","ts":"%s","msg":"cache hit","key":"user:%s","etag":%s}' % (ts(), c.k(g_uuid()), json.dumps('W/"%s"' % c.k(rs(B64U, 27)))))
        elif f == 3:
            out.append("%s WARN  upstream slow trace_id=%s span_id=%s" % (ts(), c.k(n_trace()), c.k(n_span())))
        else:
            out.append("%s INFO  aws request %s completed (x-amz-id-2: %s)" % (ts(), c.k(n_amzreq()), c.k(b64(rbytes(48)))))
    return "\n".join(out)


@scen("otel_trace_clean", 10)
def ng_otel(c):
    tid = c.k(n_trace())
    c.cmd("curl -s localhost:16686/api/traces/%s" % tid)
    spans = [{"traceID": tid, "spanID": c.k(n_span()), "operationName": pick(["GET /health", "SELECT orders", "redis GET"]),
              "tags": [{"key": "http.status_code", "value": 200}, {"key": "traceparent", "value": "00-%s-%s-01" % (tid, c.k(n_span()))}]}
             for _ in range(rint(2, 4))]
    return json.dumps({"data": [{"traceID": tid, "spans": spans}]}, indent=1)


@scen("pagination_api", 14)
def ng_pagination(c):
    v = R.randrange(3)
    if v == 0:
        c.cmd("gcloud compute instances list --format=json --page-token=...")
        return json.dumps({"items": [{"id": c.k(str(rint(10 ** 18, 10 ** 19))), "name": n_pod()}], "nextPageToken": c.k(n_pagetoken())}, indent=2)
    if v == 1:
        c.cmd("curl -s 'https://api.%s/v1/events?limit=2'" % domain())
        return json.dumps({"data": [{"id": c.k(g_uuid())}, {"id": c.k(g_uuid())}], "next_cursor": c.k(n_cursor()), "has_more": True})
    c.cmd("aws dynamodb scan --table-name %s --max-items 2" % proj())
    return json.dumps({"Items": [{"pk": {"S": c.k(n_ulid())}}], "NextToken": c.k(b64(rbytes(rint(40, 90))))}, indent=4)


@scen("stripe_objects", 14)
def ng_stripe(c):
    c.cmd(pick(["stripe customers retrieve %s" % n_stripe_id("cus"), "stripe payment_intents list --limit 1"]))
    pi = {"id": c.k(n_stripe_id("pi")), "object": "payment_intent", "amount": rint(100, 99999), "currency": "usd",
          "customer": c.k(n_stripe_id("cus")), "latest_charge": c.k(n_stripe_id("ch")), "payment_method": c.k(n_stripe_id("pm")),
          "client_secret": None, "livemode": True, "metadata": {"order_id": c.k(n_ulid())}}
    if chance(0.5):
        pi["invoice"] = c.k(n_stripe_id("in"))
    if chance(0.4):
        pi["publishable_key_used"] = c.k(n_stripe_pk())
    return json.dumps(pi, indent=2)


@scen("kubectl_get", 16)
def ng_kubectl(c):
    v = R.randrange(2)
    if v == 0:
        c.cmd("kubectl get pods -n %s -o wide" % proj())
        rows = ["NAME                                READY   STATUS    RESTARTS   AGE   IP"]
        base = proj()
        for _ in range(rint(3, 6)):
            rows.append("%-35s 1/1     Running   %d          %dd   %s" % (c.k(n_pod(base)), rint(0, 3), rint(1, 30), ip()))
        return "\n".join(rows)
    c.cmd("kubectl get events -n %s" % proj())
    return "\n".join("%dm   Normal   %s   pod/%s   %s" % (rint(1, 59), pick(["Pulled", "Created", "Started", "Scheduled"]), c.k(n_pod()),
                                                       "Successfully pulled image \"ghcr.io/%s/%s@%s\"" % (user(), proj(), c.k(n_digest())))
                     for _ in range(rint(3, 5)))


@scen("terraform_plan", 14)
def ng_tf(c):
    c.cmd(pick(["terraform plan", "terraform state show aws_instance.web", "terraform apply -auto-approve"]))
    lines = ["  # aws_instance.web will be updated in-place", "  ~ resource \"aws_instance\" \"web\" {",
             "        id                     = \"%s\"" % c.k(n_awsid("i")),
             "        ami                    = \"%s\"" % c.k(n_awsid("ami")),
             "      ~ vpc_security_group_ids = [", "          + \"%s\"," % c.k(n_awsid("sg")), "        ]",
             "        subnet_id              = \"%s\"" % c.k(n_awsid("subnet")),
             "        user_data              = (sensitive value)", "        iam_instance_profile   = \"%s\"" % c.k(n_arn()), "    }"]
    c.k("(sensitive value)")
    if chance(0.5):
        lines += ["  # random_password.db will be created", "  + resource \"random_password\" \"db\" {",
                  "      + result = (sensitive value)", "    }", "Plan: 1 to add, 1 to change, 0 to destroy."]
    return "\n".join(lines)


@scen("public_keys", 14)
def ng_pub(c):
    v = R.randrange(4)
    if v == 0:
        c.path("~/.ssh/authorized_keys")
        return "\n".join("%s %s@%s" % (c.k(n_ssh_pub()), user(), pick(["laptop", "ci", "bastion"])) for _ in range(rint(2, 4)))
    if v == 1:
        c.cmd("cat jwt_public.pem")
        return c.k(n_pubkey_pem())
    if v == 2:
        c.cmd("openssl s_client -connect api.%s:443 -showcerts </dev/null" % domain())
        return "CONNECTED(00000003)\ndepth=0 CN = api.%s\n---\nServer certificate\n%s\nsubject=CN = api.%s\n---\nSSL handshake has read 4823 bytes" % (
            domain(), c.k(n_cert_pem()), domain())
    c.cmd("curl -s https://auth.%s/.well-known/jwks.json" % domain())
    return json.dumps({"keys": [{"kty": "RSA", "use": "sig", "kid": c.k(rs(B64U, 43)), "alg": "RS256", "e": "AQAB",
                                 "n": c.k(b64u(rbytes(256)))}]}, indent=2)


@scen("html_page", 14)
def ng_html(c):
    nonce = c.k(n_nonce())
    c.cmd("curl -s https://www.%s/" % domain())
    return ("<!doctype html>\n<html><head>\n<link rel=\"stylesheet\" href=\"/static/css/app.css?v=%s\">\n"
            "<script src=\"https://cdn.jsdelivr.net/npm/htmx.org@1.9.12\" integrity=\"%s\" crossorigin=\"anonymous\"></script>\n"
            "<script nonce=\"%s\">window.__BUILD__=\"%s\";</script>\n<meta name=\"csrf-param\" content=\"authenticity_token\">\n"
            "</head><body><img alt=\"logo\" src=\"%s\">\n<iframe src=\"https://www.youtube.com/embed/%s\"></iframe>\n</body></html>") % (
        c.k(rhex(8)), c.k(n_sri()), nonce, c.k(n_short()), c.k(n_png()), c.k(n_yt()))


@scen("links_markdown", 12)
def ng_links(c):
    c.path(pick(["README.md", "docs/onboarding.md", "NOTES.md"]))
    return ("## Resources\n\n- Design doc: https://docs.google.com/document/d/%s/edit\n- Roadmap sheet: https://docs.google.com/spreadsheets/d/%s/edit#gid=0\n"
            "- Demo video: https://youtu.be/%s?t=%d\n- Short link: https://bit.ly/%s\n- Figma: https://www.figma.com/file/%s/%s\n"
            "- Loom: https://www.loom.com/share/%s") % (
        c.k(n_gdoc()), c.k(n_gdoc()), c.k(n_yt()), rint(10, 900), c.k(n_short_link()), c.k(rs(B62, 22)), proj(), c.k(rhex(32)))


@scen("docs_examples", 12)
def ng_docs(c):
    v = R.randrange(3)
    if v == 0:
        c.path("docs/aws.md")
        return ("Configure the CLI (values below are the AWS documentation examples):\n\n```\n$ aws configure\nAWS Access Key ID [None]: %s\n"
                "AWS Secret Access Key [None]: %s\nDefault region name [None]: us-west-2\n```") % (c.k(AWS_DOC_AKID), c.k(AWS_DOC_SECRET))
    if v == 1:
        c.path("docs/auth.md")
        return "Example token from jwt.io (signed with `your-256-bit-secret`):\n\n    %s\n\nNever paste real tokens here." % c.k(jwt_example())
    c.path("README.md")
    return ("Set your keys:\n\n```bash\nexport OPENAI_API_KEY=%s\nexport STRIPE_SECRET_KEY=%s\nexport GITHUB_TOKEN=%s\n```") % (
        c.k("sk-..."), c.k("sk_live\x5fxxxxxxxxxxxxxxxxxxxxxxxx"), c.k("ghp_" + "x" * 36))


@scen("placeholders", 20)
def ng_placeholders(c):
    names = R.sample(ENVN, rint(3, 6))
    v = R.randrange(3)
    vals = []
    for n in names:
        p = n_placeholder()
        while p in vals or any(p in q or q in p for q in vals):
            p = n_placeholder()
        vals.append(c.k(p))
    if v == 0:
        c.cmd("vercel env ls" if chance(0.5) else "heroku config -a %s --shell" % proj())
        return "\n".join("%s=%s" % nv for nv in zip(names, vals))
    if v == 1:
        c.path("config/secrets.example.yaml")
        return "\n".join("%s: \"%s\"" % (n.lower(), p) for n, p in zip(names, vals))
    c.cmd("fly secrets list --json" if chance(0.3) else "cat .env.example")
    return "# copy to .env and fill in\n" + "\n".join("%s=%s" % nv for nv in zip(names, vals))


@scen("password_policy", 8)
def ng_policy(c):
    n = rint(10, 16)
    c.path("docs/security/passwords.md")
    s1 = c.k("at least %d characters" % n)
    s2 = c.k("must not reuse your last %d passwords" % rint(3, 12))
    return ("# Password policy\n\nPasswords must be %s, include a number and a symbol, and %s. Do not use passwords like "
            "`password123` or your username. Rotate service account passwords every %d days via Vault (`%s`).") % (
        s1, s2, rint(30, 120), c.k("vault:secret/data/%s/db" % proj()))


@scen("code_env_reads", 16)
def ng_code(c):
    v = R.randrange(4)
    if v == 0:
        c.path("app/settings.py")
        lines = ["%s = os.environ[%s]" % (n, json.dumps(n)) for n in R.sample(ENVN, 3)]
        lines.append("DATABASE_URL = os.getenv(\"DATABASE_URL\", \"postgres://localhost/dev\")")
        for l in lines[:3]:
            c.k(l.split(" = ")[1])
        return "import os\n\n" + "\n".join(lines)
    if v == 1:
        c.path("src/config.ts")
        ns = R.sample(ENVN, 3)
        for n in ns:
            c.k("process.env.%s" % n)
        return "export const config = {\n" + "\n".join("  %s: process.env.%s!," % (n.lower(), n) for n in ns) + "\n};"
    if v == 2:
        c.path(".github/workflows/ci.yml")
        ns = R.sample(ENVN, 3)
        for n in ns:
            c.k("${{ secrets.%s }}" % n)
        return "    env:\n" + "\n".join("      %s: ${{ secrets.%s }}" % (n, n) for n in ns) + "\n    steps:\n      - uses: actions/checkout@%s" % c.k(n_sha())
    c.path("internal/config/config.go")
    n = pick(ENVN)
    c.k("os.Getenv(\"%s\")" % n)
    return "func Load() Config {\n\tkey := os.Getenv(\"%s\")\n\tif key == \"\" {\n\t\tlog.Fatal(\"%s is required\")\n\t}\n\treturn Config{APIKey: key}\n}" % (n, n)


@scen("git_misc_hashes", 10)
def ng_gitmisc(c):
    v = R.randrange(3)
    if v == 0:
        c.cmd("git rev-parse HEAD origin/main")
        return "%s\n%s" % (c.k(n_sha()), c.k(n_sha()))
    if v == 1:
        c.cmd("git stash list")
        return "\n".join("stash@{%d}: WIP on main: %s %s" % (i, c.k(rhex(7)), commit_msg()) for i in range(rint(2, 4)))
    c.cmd("git submodule status")
    return "\n".join(" %s vendor/%s (v%d.%d.%d)" % (c.k(n_sha()), pick(["proto", "ui-kit", "sdk"]), rint(0, 3), rint(0, 9), rint(0, 9)) for _ in range(rint(2, 3)))


@scen("masked_env_listing", 12)
def ng_masked(c):
    c.cmd(pick(["fly secrets list", "railway variables", "doppler secrets --only-names", "aws configure list"]))
    rows = []
    for n in R.sample(ENVN, rint(3, 6)):
        rows.append("%-22s %s" % (n, c.k(pick(["*" * rint(8, 20), "<hidden>", "[REDACTED]", "•" * 12, "*" * 16 + rhex(4)]))))
    rows.append("%-22s %s" % ("GIT_SHA", c.k(n_sha())))
    rows.append("%-22s %s" % ("DEPLOYMENT", c.k(g_uuid())))
    return "\n".join(rows)


@scen("ci_artifacts_clean", 10)
def ng_ci(c):
    c.cmd("gh run view %d" % rint(10 ** 9, 10 ** 10))
    return ("✓ main %s · %d\nTriggered via push about %d minutes ago\n\nJOBS\n✓ build in 2m%ds (ID %d)\n\nARTIFACTS\ncoverage-%s\n"
            "dist-%s (sha256: %s)\n\nCache restored from key: %s") % (
        pick(MSGS[:4]), rint(10 ** 9, 10 ** 10), rint(1, 59), rint(1, 59), rint(10 ** 10, 10 ** 11), c.k(n_sha()), c.k(n_short()),
        c.k(n_sha256sum()), c.k("Linux-node-" + n_sha256sum()))


# ---------------------------------------------------------------- more positives mixed with hard negatives
@scen("git_show_leak", 12)
def sc_gitshow(c):
    sha = c.k(n_sha())
    n, v = draw(c)
    f = pick(["scripts/seed.py", "test/fixtures/config.json", "terraform/variables.tf", "src/lib/client.rb"])
    c.cmd("git show %s" % sha[:8])
    return ("commit %s\nAuthor: %s <%s>\nDate:   %s\n\n    %s\n\ndiff --git a/%s b/%s\nindex %s..%s 100644\n--- a/%s\n+++ b/%s\n"
            "@@ -1,3 +1,4 @@\n # integration settings\n+%s = \"%s\"\n endpoint = \"https://api.%s\"") % (
        sha, pick(FULLN), email(), dt().strftime("%a %b %d %H:%M:%S %Y +0000"), commit_msg(), f, f, c.k(rhex(7)), c.k(rhex(7)),
        f, f, n.lower(), v, domain())


@scen("sql_query_output", 12)
def sc_sql(c):
    c.cmd("psql -c 'select id, name, key_prefix, key_hash, raw_key from api_keys limit 3'")
    rows = [" id |   name    | key_prefix |                             key_hash                             |  raw_key",
            "----+-----------+------------+------------------------------------------------------------------+---------"]
    for i in range(rint(1, 3)):
        raw = c.g(rs(B62, 32), "generic_api_key") if chance(0.5) else c.s("sk_" + pick(["live", "prod"]) + "_" + rs(B62, 32), "app_api_key")
        rows.append(" %2d | %-9s | %-10s | %s | %s" % (rint(1, 99), pick(["ci", "zapier", "mobile", "partner"]), raw[:6] + "…",
                                                       c.k(n_sha256sum()), raw))
    rows.append("(%d rows)" % (len(rows) - 2))
    return "\n".join(rows)


@scen("mcp_config", 14)
def sc_mcp(c):
    servers = {}
    v = R.randrange(3)
    servers["github"] = {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"],
                         "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": c.s(pick([g_gh, g_gh_fine])(), "github_token")}}
    if v >= 1:
        servers["postgres"] = {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-postgres", pg_url(c)]}
    if v == 2:
        servers["linear"] = {"url": "https://mcp.linear.app/sse", "headers": {"Authorization": "Bearer " + c.s(g_linear(), "linear_api_key")}}
    if chance(0.5):
        servers["brave"] = {"command": "npx", "args": ["-y", "brave-search-mcp"], "env": {"BRAVE_API_KEY": c.g("BSA" + rs(B62 + "_-", 28), "brave_api_key")}}
    c.path(pick([".mcp.json", "~/.cursor/mcp.json", "~/Library/Application Support/Claude/claude_desktop_config.json"]))
    return json.dumps({"mcpServers": servers}, indent=2)


@scen("ide_settings", 8)
def sc_ide(c):
    c.path(pick([".vscode/settings.json", ".idea/workspace.xml"]))
    if c.hint["path"].endswith(".json"):
        return json.dumps({"editor.formatOnSave": True, "rest-client.environmentVariables": {"staging": {
            "baseUrl": "https://staging.%s" % domain(), "token": c.g(g_urlsafe(), "bearer_token")}},
            "sqltools.connections": [{"name": "prod-ro", "server": "db.internal", "username": user(),
                                      "password": c.pw(g_password())}]}, indent=4)
    n, v = draw(c)
    return ("<component name=\"RunManager\">\n  <configuration name=\"server\" type=\"GoApplicationRunConfiguration\">\n"
            "    <envs>\n      <env name=\"%s\" value=\"%s\" />\n      <env name=\"BUILD\" value=\"%s\" />\n    </envs>\n  </configuration>\n</component>") % (
        n, v, c.k(n_sha()))


@scen("cloud_init_userdata", 8)
def sc_cloudinit(c):
    c.cmd("aws ec2 describe-instance-attribute --instance-id %s --attribute userData --query UserData.Value --output text | base64 -d" % c.k(n_awsid("i")))
    pw = c.pw(g_password(shell=True))
    n, v = draw(c, cat=pick(["vendor", "generic"]), shell=True)
    return "# instance: %s\n" % c.keep[0] + "#cloud-config\nchpasswd:\n  list: |\n    ubuntu:%s\n  expire: false\nwrite_files:\n  - path: /etc/%s.env\n    content: |\n      %s=%s\nruncmd:\n  - docker run -d --env-file /etc/%s.env ghcr.io/%s/%s@%s" % (
        pw, proj(), n, v, proj(), user(), proj(), c.k(n_digest()))


@scen("teammate_issue_comment", 10)
def sc_issue(c):
    s = chat_secret(c)
    c.cmd("gh issue view %d --comments" % rint(10, 3000))
    return ("%s commented %d days ago\n\nRepro steps:\n```\n$ ./cli login --token %s\nError: token expired (trace %s)\n```\n\n"
            "Running on commit %s.") % (user(), rint(1, 30), s, c.k(n_trace()), c.k(n_sha()))


@scen("basic_auth_url_logs", 12)
def sc_basicurl(c):
    pw = c.pw(g_password(urlsafe=True))
    host = pick(["registry.%s" % domain(), "jenkins.%s" % domain(), "nexus.internal", "elastic.%s:9200" % domain()])
    c.cmd(pick(["pip download", "docker logs logstash", "./gradlew publish"]))
    return "%s WARN  retrying (attempt %d) https://%s:%s@%s/%s -> 503 (req %s)" % (
        ts(), rint(1, 5), pick(["ci", "deploy", "elastic", user()]), pw, host, pick(["simple/", "_bulk", "repository/maven-releases/"]), c.k(n_reqid()))


# ---------------------------------------------------------------- driver
def check(c, text):
    if not isinstance(text, str) or not text:
        return "empty"
    if len(set(c.secrets)) != len(c.secrets):
        return "dup secret"
    for s in c.secrets:
        if not s or s not in text:
            return "secret missing"
        for t in c.secrets:
            if s != t and s in t:
                return "secret nested"
    for k in c.keep:
        if not k or k not in text:
            return "keep missing"
        for s in c.secrets:
            if k in s or s in k:
                return "keep/secret overlap"
    return None


HARNESS = [
    lambda c, cmd, t: "$ git rev-parse HEAD\n%s\n$ %s\n%s" % (c.k(n_sha()), cmd, t),
    lambda c, cmd, t: "Command: %s\nExit code: %d\nRequest-Id: %s\nOutput:\n%s" % (cmd, pick([0, 0, 1, 2]), c.k(n_reqid()), t),
    lambda c, cmd, t: "[%s] task %s started\n$ %s\n%s\n[%s] task %s exited %d" % (
        ts(), c.k(g_uuid()), cmd, t, ts(), c.keep[-1], pick([0, 1])),
    lambda c, cmd, t: "%s\n\n[process exited with code %d] (session %s, cwd /home/%s/code/%s @ %s)" % (
        t, pick([0, 1, 130]), c.k(n_ulid()), user(), proj(), c.k(n_short())),
    lambda c, cmd, t: "<bash-stdout>\n%s\n</bash-stdout>\n<bash-metadata trace=\"%s\" />" % (t, c.k(n_trace())),
]

# positives are scaled down to land near ~1000 cases; vendor-heavy contexts keep more weight
POS_SCALE = 0.7
POS_KEEP_FULL = {"exception_message", "gcloud_auth", "git_remote", "mcp_config", "npm_config", "aws_sts", "curl_verbose",
                 "webhook_log", "git_config", "slack_chat", "llm_transcript", "env_dump", "dotenv_file"}
NEG_CTX = set()


def build():
    cases = []
    for ctx, n, f in SCEN:
        if f.__name__.startswith("sc_") and ctx not in POS_KEEP_FULL:
            n = max(5, int(round(n * POS_SCALE)))
        made = tries = 0
        whys = collections.Counter()
        while made < n:
            tries += 1
            if tries > n * 40:
                raise SystemExit("scenario %s keeps failing: %s" % (ctx, dict(whys)))
            c = Case(ctx)
            text = f(c)
            if c.hint and "command" in c.hint and ctx != "llm_transcript" and chance(0.5):
                text = pick(HARNESS)(c, c.hint["command"], text)
            why = check(c, text)
            if why:
                whys[why] += 1
                continue
            kind = c.kind if c.secrets else "negative"
            rec = {"kind": kind, "context": ctx, "text": text, "secrets": list(c.secrets), "keep": list(c.keep)}
            if c.hint:
                rec["hint"] = c.hint
            cases.append((rec, list(c.cats)))
            made += 1
        if "-v" in sys.argv and whys:
            print("retries %s: %s" % (ctx, dict(whys)), file=sys.stderr)
    R.shuffle(cases)
    for i, (rec, _) in enumerate(cases):
        rec["id"] = "holdout-%04d" % (i + 1)
    return cases


def main():
    cases = build()
    with io.TextIOWrapper(gzip.GzipFile(OUT, "wb", mtime=0), encoding="utf-8") as fh:
        for rec, _ in cases:
            o = {"id": rec["id"], "kind": rec["kind"], "context": rec["context"], "text": rec["text"],
                 "secrets": rec["secrets"], "keep": rec["keep"]}
            if "hint" in rec:
                o["hint"] = rec["hint"]
            fh.write(json.dumps(o, ensure_ascii=False) + "\n")
    # re-verify from disk
    n_sec = n_keep = 0
    ctxs, kinds, cats, skinds = collections.Counter(), collections.Counter(), collections.Counter(), collections.Counter()
    with gzip.open(OUT, "rt", encoding="utf-8") as fh:
        for line in fh:
            o = json.loads(line)
            for s in o["secrets"]:
                assert s in o["text"], (o["id"], s)
                for k in o["keep"]:
                    assert k not in s and s not in k, (o["id"], s, k)
            for k in o["keep"]:
                assert k in o["text"], (o["id"], k)
            assert (o["kind"] == "negative") == (not o["secrets"]), o["id"]
            n_sec += len(o["secrets"])
            n_keep += len(o["keep"])
            ctxs[o["context"]] += 1
            kinds[o["kind"]] += 1
    for _, cl in cases:
        for kind, cat in cl:
            cats[cat] += 1
            skinds[kind] += 1
    tot = sum(cats.values())
    print("cases=%d secrets=%d keep=%d contexts=%d case_kinds=%d secret_kinds=%d" % (
        len(cases), n_sec, n_keep, len(ctxs), len(kinds) - 1, len(skinds)), file=sys.stderr)
    print("categories: " + ", ".join("%s=%d (%.0f%%)" % (k, v, 100.0 * v / tot) for k, v in cats.most_common()), file=sys.stderr)
    if "-v" in sys.argv:
        print("contexts: " + ", ".join("%s=%d" % kv for kv in sorted(ctxs.items())), file=sys.stderr)
        print("kinds: " + ", ".join("%s=%d" % kv for kv in kinds.most_common()), file=sys.stderr)
        print("secret kinds: " + ", ".join("%s=%d" % kv for kv in skinds.most_common()), file=sys.stderr)


if __name__ == "__main__":
    main()
