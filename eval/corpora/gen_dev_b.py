#!/usr/bin/env python3
"""Generate dev_b: a second dev corpus focused on infra / DevOps tool output.

Deterministic (seed 4242), stdlib only.  Run with:

    python3 -I eval/corpora/gen_dev_b.py

Reuses the value generators from gen_dev.py.  Writes dev_b.jsonl.gz next to this
file with the same schema as dev.jsonl.  All secret values are freshly
generated random strings; none is a live credential.  "Example keys from
vendor docs" appear only as keep (non-secret) values.
"""
import base64
import collections
import datetime
import gzip
import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gen_dev as G  # noqa: E402
from gen_dev import *  # noqa: E402,F401,F403

G.R.seed(4242)
R = G.R
OUT = os.path.join(HERE, "dev_b.jsonl.gz")

CURL, CI, DOCKER, KUBE, HELM, TF, GIT, CLOUD = (
    "curl-http", "ci-log", "docker", "kubectl", "helm", "terraform", "git-diff", "cloud-cli")

# (A published example's vendor prefix is escaped, `"ghp\x5f…"`, so this source isn't taken for a live key.)
DOC_EXAMPLES = ["AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "AKIAI44QH8DHBEXAMPLE",
                "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY", "sk\x5ftest_4eC39HqLyjWDarjtT1zdp7dc",
                "ghp\x5f16C7e42F292c6912E7710c838347Ae178B4a", "xoxb-not-a-real-token-this-will-not-work",
                "ey\x4ahbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="]
SECRET_REF_NAMES = ["NPM_TOKEN", "DEPLOY_KEY", "AWS_SECRET_ACCESS_KEY", "DOCKERHUB_TOKEN", "SLACK_WEBHOOK_URL",
                    "API_TOKEN", "SENTRY_AUTH_TOKEN", "PROD_DB_PASSWORD", "GH_PAT", "CODECOV_TOKEN", "RELAY_SEED"]


# --------------------------------------------------------------------------- case + helpers
class C(G.Case):
    def add(self, pairs):
        for k, s in pairs:
            self.secrets.append(s)
            self.kinds.append(k)

    def enc_secret(self, kind, v):
        self.secrets.append(v)
        self.kinds.append(kind)
        return v


def drop(c, v):
    i = c.secrets.index(v)
    del c.secrets[i], c.kinds[i]


def raw(kind):
    """Generate a value without recording it: (display, [(kind, secret)], keeps)."""
    r = GEN[kind]()
    if isinstance(r, dict):
        return r["d"], list(r["s"]), list(r.get("k", []))
    return r, [(kind, r)], []


def pk(gen=0.6, pw=0.13, url=False):
    return pick_kind(gen, pw, url)


def named(c, gen=0.6, pw=0.13, url=False, neutral=0.6, keepname=0.2, style=None):
    kind = pk(gen, pw, url)
    name = env_name(kind, neutral)
    if style:
        name = style(name)
    v = c.S(kind)
    if chance(keepname):
        c.K(name)
    return name, v


def gsec(c):
    return c.S(pick(GENERIC_KINDS))


def pwd(c, urlsafe=False):
    k = pick(PASSWORD_KINDS)
    v = GEN[k]()
    if urlsafe:
        v = enc(v.replace(" ", "-"))
    return c.S(k, value=v)


def shq(v):
    if re.match(r"^[A-Za-z0-9_./:=@%+-]+$", v) and chance(0.5):
        return v
    return "'%s'" % v


PLAIN = re.compile(r"^[A-Za-z0-9_/.][A-Za-z0-9_./+=:@-]*$")
RESERVED = {"true", "false", "yes", "no", "null", "on", "off", "~", "y", "n"}


def ys(v, qp=0.2):
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if v == "":
        return '""'
    if (PLAIN.match(v) and not re.match(r"^[0-9.+-]+$", v) and v.lower() not in RESERVED
            and not chance(qp)):
        return v
    if '"' in v or "\\" in v:
        return "'%s'" % v.replace("'", "''")
    return '"%s"' % v


def ydump(o, ind=0, li=True, qp=0.2):
    """Tiny YAML emitter. li=True indents list items under their key (helm style)."""
    pad = "  " * ind
    out = []
    if isinstance(o, dict):
        for k, v in o.items():
            if isinstance(v, dict) and v:
                out.append("%s%s:" % (pad, k))
                out.append(ydump(v, ind + 1, li, qp))
            elif isinstance(v, list) and v:
                out.append("%s%s:" % (pad, k))
                out.append(ydump(v, ind + (1 if li else 0), li, qp))
            elif isinstance(v, str) and "\n" in v:
                out.append("%s%s: |" % (pad, k))
                out.extend(pad + "  " + l if l else "" for l in v.rstrip("\n").split("\n"))
            else:
                out.append("%s%s: %s" % (pad, k, "{}" if v == {} else "[]" if v == [] else ys(v, qp)))
    elif isinstance(o, list):
        for v in o:
            if isinstance(v, dict) and v:
                sub = ydump(v, ind + 1, li, qp).split("\n")
                sub[0] = pad + "- " + sub[0].lstrip()
                out.extend(sub)
            else:
                out.append("%s- %s" % (pad, ys(v, qp)))
    return "\n".join(out)


def jd(o, indent=2):
    return json.dumps(o, indent=indent, ensure_ascii=False)


class Clock:
    def __init__(self):
        self.t = dt()

    def tick(self, lo=1, hi=4000):
        self.t += datetime.timedelta(microseconds=R.randint(lo * 1000, hi * 1000))
        return self.t

    def gha(self):
        t = self.tick(1, 900)
        return t.strftime("%Y-%m-%dT%H:%M:%S.") + "%06d%dZ" % (t.microsecond, R.randint(0, 9))


def http_date(d=None):
    return (d or dt()).strftime("%a, %d %b %Y %H:%M:%S GMT")


# ---- extra hard-negative generators (all record keep)
def k_cid(c):
    return c.K(rs(HEX, 64))


def k_cfray(c):
    return c.K(rs(HEX, 16) + "-" + pick(["SJC", "IAD", "FRA", "LHR", "NRT", "AMS", "ORD", "SIN"]))


def k_amzid(c):
    return c.K(rs(UALNUM, 16))


def k_amzid2(c):
    return c.K(b64(rb(57)))


def k_ghreq(c):
    return c.K(":".join([rs(HEXU, 4), rs(HEXU, 6), rs(HEXU, 6), rs(HEXU, 7), rs(HEXU, 8)]))


def k_nodeid(c):
    return c.K(pick(["U_kgDO", "R_kgDO", "PR_kwDO", "I_kwDO"]) + rs(B64U, pick([8, 10, 14])))


def k_aroa(c, p="AROA"):
    return c.K(p + rs(UALNUM, 17))


def k_doc(c):
    return c.K(pick(DOC_EXAMPLES))


def k_layer(c):
    return c.K(rs(HEX, 12))


def pod_parts():
    return rs(K8S, pick([9, 10])), rs(K8S, 5)


def resp_negs(c, n):
    opts = [lambda: "x-request-id: " + c.N("request_id"), lambda: "etag: " + c.N("etag"),
            lambda: "cf-ray: " + k_cfray(c), lambda: "x-amz-request-id: " + k_amzid(c),
            lambda: "x-amz-id-2: " + k_amzid2(c), lambda: "x-github-request-id: " + k_ghreq(c),
            lambda: "traceparent: " + c.N("traceparent"), lambda: "x-amzn-trace-id: " + c.N("xray"),
            lambda: "strict-transport-security: max-age=31536000; includeSubDomains",
            lambda: "x-ratelimit-remaining: %d" % R.randint(1, 5000), lambda: "vary: Accept-Encoding",
            lambda: "cache-control: private, max-age=%d" % pick([0, 60, 300]),
            lambda: "x-correlation-id: " + c.N("uuid"), lambda: "x-envoy-upstream-service-time: %d" % R.randint(2, 900),
            lambda: "server: " + pick(["cloudflare", "nginx", "envoy", "AmazonS3", "GitHub.com"])]
    return [f() for f in R.sample(opts, n)]


def resp_body(c):
    k = R.randint(0, 5)
    if k == 0:
        return jd({"id": c.N("stripe_obj"), "object": "list", "has_more": False, "url": "/v1/customers"})
    if k == 1:
        return jd({"login": pick(PEOPLE).replace("á", "a"), "id": R.randint(10 ** 5, 10 ** 8), "node_id": k_nodeid(c),
                   "type": "User", "site_admin": False})
    if k == 2:
        return jd({"ok": True, "request_id": c.N("uuid"), "data": {"items": [], "next_cursor": c.N("cursor")}})
    if k == 3:
        return json.dumps({"status": "ok", "version": version(), "commit": c.N("git_sha")})
    if k == 4:
        return jd({"id": c.N("uuid"), "created_at": iso(), "state": pick(["active", "pending"]), "etag": c.N("short_sha")})
    return '{"message":"accepted","trace_id":"%s"}' % c.N("trace_id")


TPL = []


def T(ctx, n):
    def deco(fn):
        TPL.append((ctx, fn, n))
        return fn
    return deco


# ======================================================================= curl / HTTP
UA = ["curl/8.5.0", "curl/7.88.1", "curl/8.7.1", "curl/8.4.0", "curl/7.81.0", "curl/8.9.1"]


def ip4():
    return "%d.%d.%d.%d" % (pick([3, 18, 34, 52, 104, 140, 151, 172, 185]), R.randint(0, 255), R.randint(0, 255), R.randint(1, 254))


def curl_v(c, method, hostn, path, hdrs, status, rhdrs, body, port=443, data_len=None):
    h2 = port == 443 and chance(0.6)
    ip = ip4()
    o = ["*   Trying %s:%d..." % (ip, port), "* Connected to %s (%s) port %d" % (hostn, ip, port)]
    if h2:
        o.append("* ALPN: curl offers h2,http/1.1")
    if chance(0.45):
        o += ["* TLSv1.3 (OUT), TLS handshake, Client hello (1):", "* TLSv1.3 (IN), TLS handshake, Server hello (2):",
              "* TLSv1.3 (IN), TLS handshake, Certificate (11):", "* TLSv1.3 (IN), TLS handshake, CERT verify (15):",
              "* TLSv1.3 (IN), TLS handshake, Finished (20):", "* TLSv1.3 (OUT), TLS handshake, Finished (20):"]
    o.append("* SSL connection using TLSv1.3 / " + pick(["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256",
                                                          "TLS_CHACHA20_POLY1305_SHA256"]))
    if h2:
        o.append("* ALPN: server accepted h2")
    if chance(0.6):
        d = dt()
        o += ["* Server certificate:", "*  subject: CN=%s" % hostn,
              "*  start date: %s" % d.strftime("%b %d %H:%M:%S %Y GMT"),
              "*  expire date: %s" % (d + datetime.timedelta(days=90)).strftime("%b %d %H:%M:%S %Y GMT"),
              "*  issuer: " + pick(["C=US; O=Let's Encrypt; CN=R11", "C=US; O=Amazon; CN=Amazon RSA 2048 M02",
                                    "C=US; O=Google Trust Services; CN=WE1",
                                    "C=US; O=DigiCert Inc; CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1"]),
              "*  SSL certificate verify ok."]
    proto = "HTTP/2" if h2 else "HTTP/1.1"
    base = [("Host", hostn if port == 443 else "%s:%d" % (hostn, port)), ("User-Agent", pick(UA)), ("Accept", "*/*")]
    allh = base + hdrs
    if h2:
        o.append("* [HTTP/2] [1] OPENED stream for https://%s%s" % (hostn, path))
        o.append("* [HTTP/2] [1] [:method: %s]" % method)
        o.append("* [HTTP/2] [1] [:path: %s]" % path)
        for k, v in allh[1:]:
            o.append("* [HTTP/2] [1] [%s: %s]" % (k.lower(), v))
    o.append("> %s %s %s" % (method, path, proto))
    o += ["> %s: %s" % kv for kv in allh]
    o.append(">")
    if data_len:
        o.append("} [%d bytes data]" % data_len)
    reason = {200: "OK", 201: "Created", 204: "No Content", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found"}
    o.append("< %s %d %s" % (proto, status, "" if h2 else reason.get(status, "OK")))
    o.append("< date: %s" % http_date())
    o.append("< content-type: application/json; charset=utf-8")
    o += ["< " + h for h in rhdrs]
    o.append("<")
    if body:
        o.append("{ [%d bytes data]" % len(body))
        o.append(body)
    o.append("* Connection #0 to host %s left intact" % hostn)
    return o


BEARER = [
    ("github_pat", "api.github.com", "/user", "Authorization", "token %s"),
    ("github_fine_grained", "api.github.com", "/repos/{o}/{r}/actions/runs?per_page=1", "Authorization", "Bearer %s"),
    ("openai_key", "api.openai.com", "/v1/models", "Authorization", "Bearer %s"),
    ("anthropic_key", "api.anthropic.com", "/v1/models", "x-api-key", "%s"),
    ("stripe_secret_key", "api.stripe.com", "/v1/customers?limit=3", "Authorization", "Bearer %s"),
    ("slack_bot_token", "slack.com", "/api/auth.test", "Authorization", "Bearer %s"),
    ("gitlab_pat", "gitlab.com", "/api/v4/projects?owned=true", "PRIVATE-TOKEN", "%s"),
    ("datadog_api_key", "api.datadoghq.com", "/api/v1/validate", "DD-API-KEY", "%s"),
    ("huggingface_token", "huggingface.co", "/api/whoami-v2", "Authorization", "Bearer %s"),
    ("digitalocean_token", "api.digitalocean.com", "/v2/account", "Authorization", "Bearer %s"),
    ("cloudflare_api_token", "api.cloudflare.com", "/client/v4/user/tokens/verify", "Authorization", "Bearer %s"),
    ("sendgrid_key", "api.sendgrid.com", "/v3/scopes", "Authorization", "Bearer %s"),
    ("linear_key", "api.linear.app", "/graphql", "Authorization", "%s"),
    ("grafana_sa_token", "grafana.{d}", "/api/search?query=", "Authorization", "Bearer %s"),
    ("npm_token", "registry.npmjs.org", "/-/whoami", "Authorization", "Bearer %s"),
    ("jwt", "api.{d}", "/v2/orders?status=open", "Authorization", "Bearer %s"),
    ("vault_token", "vault.{d}", "/v1/secret/data/{s}/config", "X-Vault-Token", "%s"),
]
GEN_HDRS = [("Authorization", "Bearer %s"), ("X-API-Key", "%s"), ("X-Auth-Token", "%s"), ("api-key", "%s"),
            ("Authorization", "Token %s"), ("X-Access-Token", "%s"), ("apikey", "%s"), ("X-Upstream-Auth", "%s")]


def fill_host(h):
    return h.replace("{d}", dom()).replace("{o}", pick(PROJECTS)).replace("{r}", svc()).replace("{s}", svc())


@T(CURL, 13)
def t_curl_bearer(c):
    if chance(0.55):
        kind = pick(GENERIC_KINDS)
        hostn = pick(["api.", "internal-api.", "partner.", "edge.", ""]) + dom()
        path = pick(["/v1/", "/api/", "/v3/"]) + pick(["events", "status", "reports/daily", "sync", "export?format=csv"])
        hn, fmt_ = pick(GEN_HDRS)
    else:
        kind, hostn, path, hn, fmt_ = pick(BEARER)
        hostn, path = fill_host(hostn), fill_host(path)
    tok = c.S(kind)
    port = 8200 if hn == "X-Vault-Token" else 443
    hdrs = [(hn, fmt_ % tok)]
    if chance(0.4):
        hdrs.append(("Content-Type", "application/json"))
    status = pick([200, 200, 200, 401, 403])
    url = "https://%s%s%s" % (hostn, "" if port == 443 else ":%d" % port, path)
    cmd = "curl -v %s-H '%s: %s' '%s'" % (pick(["", "-sS ", "--fail "]), hn, fmt_ % tok, url)
    c.hint = {"command": cmd}
    o = ["$ " + cmd] if chance(0.5) else []
    o += curl_v(c, "GET", hostn, path, hdrs, status, resp_negs(c, R.randint(2, 5)), resp_body(c) if status == 200 else
                '{"message":"Bad credentials","documentation_url":"https://docs.%s/rest"}' % dom(), port)
    return "\n".join(o)


BASIC = [
    (lambda c: (pick(USERS), pwd(c)), "{d}", "/api/v1/health/detailed", "password"),
    (lambda c: (email(), c.S("atlassian_token")), "{p}.atlassian.net", "/rest/api/3/myself", "vendor"),
    (lambda c: ("api", c.S("mailgun_key")), "api.mailgun.net", "/v3/domains", "vendor"),
    (lambda c: ("AC" + rs(HEX, 32), c.S("twilio_auth_token")), "api.twilio.com", "/2010-04-01/Accounts.json", "vendor"),
    (lambda c: (pick(USERS), gsec(c)), "registry.{d}", "/v2/_catalog", "generic"),
    (lambda c: (pick(USERS), gsec(c)), "nexus.{d}", "/service/rest/v1/repositories", "generic"),
    (lambda c: (pick(["elastic", "admin"]), pwd(c)), "es.{d}", "/_cluster/health?pretty", "password"),
]


@T(CURL, 9)
def t_curl_basic(c):
    fn, hostn, path, _ = pick(BASIC)
    u, p = fn(c)
    hostn = fill_host(hostn.replace("{p}", pick(PROJECTS)))
    if not hostn.count("."):
        hostn = "ops." + dom()
    blob = c.enc_secret("basic_auth", b64s("%s:%s" % (u, p)))
    if u.startswith("AC"):
        c.K(u)
    form = R.randint(0, 2)
    if form == 0:
        cmd = "curl -v -u %s '%s'" % (shq("%s:%s" % (u, p)), "https://%s%s" % (hostn, path))
    elif form == 1:
        cmd = "curl -v --user %s:%s https://%s%s" % (u, shq(p), hostn, path)
    else:
        cmd = "curl -v -H 'Authorization: Basic %s' https://%s%s" % (blob, hostn, path)
    c.hint = {"command": cmd}
    show = chance(0.5)
    o = ["$ " + cmd] if show else []
    if form == 2 or not show:
        drop(c, p)
    body = curl_v(c, "GET", hostn, path, [("Authorization", "Basic " + blob)], 200, resp_negs(c, R.randint(1, 4)),
                  resp_body(c))
    if form != 2:
        body.insert(2, "* Server auth using Basic with user '%s'" % u)
    o += body
    return "\n".join(o)


@T(CURL, 6)
def t_curl_query(c):
    k = R.randint(0, 4)
    if k == 0:
        tok = c.S("google_api_key")
        hostn, path = "maps.googleapis.com", "/maps/api/geocode/json?address=%s&key=%s" % (pick(["Berlin", "1600+Amphitheatre"]), tok)
    elif k == 1:
        tok = gsec(c)
        hostn = "api." + dom()
        path = "/v1/%s?%s=%s" % (pick(["metrics", "stats", "feed"]), pick(["api_key", "apikey", "token", "key", "auth"]), tok)
    elif k == 2:
        tok = c.S("facebook_token")
        hostn, path = "graph.facebook.com", "/v19.0/me?fields=id,name&access_token=" + tok
    elif k == 3:
        disp = c.S("azure_sas")
        hostn = disp.split("/")[2]
        path = "/" + disp.split("/", 3)[3]
    else:
        tok = c.S(pick(["datadog_api_key", "generic_hex"]))
        hostn, path = "http-intake.logs." + pick(["datadoghq.com", "datadoghq.eu"]), "/api/v2/logs?dd-api-key=" + tok
    cmd = "curl -v '%s'" % ("https://" + hostn + path)
    c.hint = {"command": cmd}
    o = ["$ " + cmd] if chance(0.5) else []
    o += curl_v(c, "GET", hostn, path, [], 200, resp_negs(c, R.randint(1, 4)), resp_body(c))
    return "\n".join(o)


@T(CURL, 8)
def t_curl_oauth(c):
    hostn = pick(["auth.", "login.", "sso.", "id."]) + dom()
    path = pick(["/oauth/token", "/oauth2/v1/token", "/realms/%s/protocol/openid-connect/token" % pick(PROJECTS)])
    cid = c.K(pick([n_uuid(), n_google_client_id(), rtok(LALNUM, 20)]))
    cs = c.S(pick(["generic_b62", "generic_b64url", "generic_lower", "google_oauth_client_secret", "azure_client_secret"]))
    basic = chance(0.4)
    hdrs = [("Content-Type", "application/x-www-form-urlencoded")]
    if basic:
        blob = c.enc_secret("basic_auth", b64s("%s:%s" % (cid, cs)))
        hdrs.append(("Authorization", "Basic " + blob))
        cmd = "curl -v -X POST -u '%s:%s' -d grant_type=client_credentials %s" % (cid, cs, "https://" + hostn + path)
        dlen = 29
    else:
        data = "grant_type=client_credentials&client_id=%s&client_secret=%s" % (cid, cs)
        cmd = "curl -v -X POST https://%s%s -d '%s'" % (hostn, path, data)
        dlen = len(data)
    c.hint = {"command": cmd}
    show = basic or chance(0.85)
    o = ["$ " + cmd] if show else []
    if not show:
        drop(c, cs)
        c.keep.remove(cid)
    at = c.S(pick(["jwt", "generic_b64url", "generic_b62"]))
    resp = {"access_token": at, "token_type": "Bearer", "expires_in": pick([300, 3600, 86400])}
    if chance(0.5):
        resp["refresh_token"] = c.S(pick(["generic_b64url", "generic_hex"]))
    if chance(0.3):
        resp["id_token"] = c.S("jwt")
    resp["scope"] = pick(["read write", "openid profile", "api:read"])
    o += curl_v(c, "POST", hostn, path, hdrs, 200, resp_negs(c, R.randint(1, 3)),
                json.dumps(resp, separators=(",", ":")) if chance(0.6) else jd(resp), data_len=dlen)
    return "\n".join(o)


COOKIES = [("session", lambda: b64u(rb(32))), ("sessionid", lambda: rtok(LALNUM, 32)),
           ("connect.sid", lambda: "s%3A" + rtok(B64U, 32) + "." + rtok(B64U, 43)),
           ("_%s_session" % "app", lambda: rtok(B62 + "%", 120)), ("PHPSESSID", lambda: rtok(LALNUM, 26)),
           ("JSESSIONID", lambda: rs(HEXU, 32)), ("__Host-sid", lambda: b64u(rb(48))),
           ("remember_token", lambda: rtok(B62, 64))]


@T(CURL, 5)
def t_curl_cookie(c):
    hostn = pick(["app.", "admin.", "portal.", "dash."]) + dom()
    name, gen = pick(COOKIES)
    sval = c.S("session_cookie", value=gen())
    u, p = pick(USERS), pwd(c)
    data = '{"username":"%s","password":"%s"}' % (u, p)
    cmd = "curl -v -c cookies.txt -H 'Content-Type: application/json' -d '%s' https://%s/api/login" % (data, hostn)
    c.hint = {"command": cmd}
    ga = c.K("GA1.1.%d.%d" % (R.randint(10 ** 8, 10 ** 9), epoch()))
    rh = ["set-cookie: %s=%s; Path=/; HttpOnly; Secure; SameSite=Lax" % (name, sval),
          "set-cookie: _ga=%s; Path=/; Max-Age=63072000" % ga] + resp_negs(c, R.randint(1, 3))
    o = ["$ " + cmd]
    o += curl_v(c, "POST", hostn, "/api/login", [("Content-Type", "application/json")], 200, rh,
                '{"ok":true,"user_id":"%s"}' % c.N("uuid"), data_len=len(data))
    if chance(0.5):
        o += curl_v(c, "GET", hostn, "/api/me", [("Cookie", "%s=%s; _ga=%s" % (name, sval, ga))], 200,
                    resp_negs(c, 1), resp_body(c))
    return "\n".join(o)


@T(CURL, 5)
def t_curl_webhook(c):
    kind = pick(["slack_webhook", "discord_webhook", "teams_webhook", "generic_webhook"])
    if kind == "generic_webhook":
        disp = G.generic_webhook()
        c.add(disp["s"])
        url = disp["d"]
    else:
        url = c.S(kind)
    hostn = url.split("/")[2]
    path = "/" + url.split("/", 3)[3]
    show = chance(0.6)
    payload = '{"text":"deploy %s finished (%s)"}' % (version(), c.N("short_sha") if show else n_short_sha())
    cmd = "curl -v -X POST -H 'Content-type: application/json' --data '%s' %s" % (payload, url)
    c.hint = {"command": cmd}
    o = ["$ " + cmd] if show else []
    o += curl_v(c, "POST", hostn, path, [("Content-type", "application/json")], pick([200, 204]),
                resp_negs(c, R.randint(1, 3)), "ok" if "slack" in hostn else "", data_len=len(payload))
    return "\n".join(o)


@T(CURL, 4)
def t_curl_registry(c):
    repo = "%s/%s" % (pick(PROJECTS), svc())
    if chance(0.5):
        u, p = pick(USERS), c.S(pick(["github_pat", "generic_b62"]))
        hostn, path = "ghcr.io", "/token?scope=repository:%s:pull&service=ghcr.io" % repo
        blob = c.enc_secret("basic_auth", b64s("%s:%s" % (u, p)))
        hdrs = [("Authorization", "Basic " + blob)]
        cmd = "curl -v -u %s:%s 'https://%s%s'" % (u, p, hostn, path)
        if not chance(0.6):
            drop(c, p)
            cmd = None
    else:
        hostn, path = "auth.docker.io", "/token?service=registry.docker.io&scope=repository:library/%s:pull" % pick(["nginx", "redis", "node"])
        hdrs, cmd = [], "curl -v 'https://%s%s'" % (hostn, path)
    tok = c.S("registry_token", value=G.g_jwt("RS256") if chance(0.5) else b64(rb(R.choice([48, 96]))))
    body = json.dumps({"token": tok, "access_token": tok, "expires_in": 300, "issued_at": iso()})
    o = ["$ " + cmd] if cmd else []
    c.hint = {"command": cmd or "curl -v https://%s%s" % (hostn, path)}
    o += curl_v(c, "GET", hostn, path, hdrs, 200, resp_negs(c, 2), body)
    o += curl_v(c, "HEAD", "registry-1.docker.io" if hostn == "auth.docker.io" else "ghcr.io", "/v2/%s/manifests/latest" % repo,
                [("Authorization", "Bearer " + tok)], 200,
                ["docker-content-digest: " + c.N("docker_digest"), "etag: \"%s\"" % c.N("docker_digest")], "")
    return "\n".join(o)


@T(CURL, 6)
def t_http_dump(c):
    hostn = "api." + dom()
    kind = pk(0.65, 0.0)
    tok = c.S(kind)
    hn, fmt_ = pick(GEN_HDRS + [("Authorization", "Bearer %s")])
    path = "/v1/%s" % pick([lambda: "jobs", lambda: "invoices/%s" % c.N("uuid"), lambda: "users/me", lambda: "batch"])()
    reqid = c.N("request_id")
    style = R.randint(0, 2)
    if style == 0:  # python http.client debuglevel=1
        c.hint = {"command": "python scripts/sync.py --verbose"}
        o = ["send: b'GET %s HTTP/1.1\\r\\nHost: %s\\r\\nUser-Agent: python-requests/2.32.3\\r\\nAccept-Encoding: gzip, deflate\\r\\n"
             "Accept: */*\\r\\nConnection: keep-alive\\r\\n%s: %s\\r\\n\\r\\n'" % (path, hostn, hn, fmt_ % tok),
             "reply: 'HTTP/1.1 200 OK\\r\\n'", "header: Date: %s" % http_date(), "header: Content-Type: application/json",
             "header: X-Request-Id: %s" % reqid, "header: ETag: %s" % c.N("etag")]
        o.append("DEBUG:urllib3.connectionpool:https://%s:443 \"GET %s HTTP/1.1\" 200 %d" % (hostn, path, R.randint(80, 9000)))
    elif style == 1:  # httpie -v
        c.hint = {"command": "http -v GET https://%s%s '%s:%s'" % (hostn, path, hn, fmt_ % tok)}
        o = ["GET %s HTTP/1.1" % path, "Accept: */*", "Accept-Encoding: gzip, deflate", "%s: %s" % (hn, fmt_ % tok),
             "Connection: keep-alive", "Host: %s" % hostn, "User-Agent: HTTPie/3.2.2", "", "",
             "HTTP/1.1 200 OK", "Content-Type: application/json", "Date: %s" % http_date(), "X-Request-Id: %s" % reqid,
             "", resp_body(c)]
    else:  # raw request saved from a proxy, with JSON body carrying creds
        c.hint = {"path": "captures/%s-request.txt" % svc()}
        u, p = pick(USERS), pwd(c)
        body = json.dumps({"username": u, "password": p, "client": svc()})
        o = ["POST /api/v1/auth/login HTTP/1.1", "Host: %s" % hostn, "Content-Type: application/json",
             "Content-Length: %d" % len(body), "%s: %s" % (hn, fmt_ % tok), "X-Request-Id: %s" % reqid, "", body, "",
             "HTTP/1.1 200 OK", "Content-Type: application/json", "ETag: %s" % c.N("etag"), "",
             json.dumps({"token": c.S("jwt"), "expires_in": 3600, "user": {"id": c.N("uuid")}})]
    return "\n".join(o)


@T(CURL, 7)
def t_curl_neg(c):
    hostn = pick(["api.github.com", "registry.npmjs.org", "api." + dom(), "status." + dom(), "pypi.org"])
    path = pick([lambda: "/repos/%s/%s/commits/%s" % (pick(PROJECTS), svc(), c.N("git_sha"))] +
                [(lambda x: lambda: x)(p_) for p_ in ["/v1/health", "/simple/requests/", "/-/package/react/dist-tags", "/api/v2/status.json"]])()
    hdrs = []
    k = R.randint(0, 3)
    if k == 0:
        hdrs.append(("Authorization", "Bearer " + c.K(pick(["***", "<redacted>", "[REDACTED]", "$GITHUB_TOKEN"]))))
    elif k == 1:
        hdrs.append(("Authorization", "token " + k_doc(c)))
    elif k == 2:
        hdrs.append(("If-None-Match", c.N("etag")))
    status = pick([200, 200, 304, 401, 404])
    cmd = "curl -v https://%s%s" % (hostn, path)
    c.hint = {"command": cmd}
    o = ["$ " + cmd] if chance(0.4) else []
    o += curl_v(c, "GET", hostn, path, hdrs, status, resp_negs(c, R.randint(3, 6)), resp_body(c) if status == 200 else "")
    return "\n".join(o)


# ======================================================================= CI logs (GitHub Actions / GitLab)
def sref():
    return "${{ secrets.%s }}" % pick(SECRET_REF_NAMES)


def gha_header(c):
    o = ["Current runner version: '2.%d.%d'" % (R.randint(310, 321), R.randint(0, 3)), "Operating System",
         "  Ubuntu", "  22.04.5", "  LTS", "Runner Image", "  Image: ubuntu-22.04",
         "  Version: 2025%02d%02d.1.0" % (R.randint(1, 12), R.randint(1, 28)), "GITHUB_TOKEN Permissions",
         "  Contents: read", "  Metadata: read", "  Packages: write", "Secret source: Actions",
         "Prepare workflow directory", "Prepare all required actions", "Getting action download info"]
    for a in R.sample(["actions/checkout@v4", "actions/setup-node@v4", "docker/login-action@v3",
                       "docker/build-push-action@v6", "aws-actions/configure-aws-credentials@v4",
                       "actions/cache@v4", "hashicorp/setup-terraform@v3"], R.randint(1, 3)):
        o.append("Download action repository '%s' (SHA:%s)" % (a, c.N("git_sha")))
    o.append("Complete job name: %s" % pick(["build", "deploy", "release", "test (20.x)", "publish"]))
    return o


def gha_checkout(c):
    repo = "%s/%s" % (pick(PROJECTS), svc())
    sha = c.N("git_sha")
    return ["##[group]Run actions/checkout@v4", "with:", "  repository: " + repo, "  token: " + c.K("***"),
            "  ssh-strict: true", "  persist-credentials: true", "  fetch-depth: 1", "##[endgroup]",
            "Syncing repository: " + repo, "##[group]Getting Git version info", "git version 2.47.1", "##[endgroup]",
            "/usr/bin/git -c protocol.version=2 fetch --no-tags --prune --no-recurse-submodules --depth=1 origin +%s:refs/remotes/origin/main" % sha,
            "##[group]Checking out the ref", "/usr/bin/git checkout --progress --force -B main refs/remotes/origin/main",
            "Switched to a new branch 'main'", "##[endgroup]", "/usr/bin/git log -1 --format='%H'", "'%s'" % sha]


def gha_env_block(c, n_leak):
    o = ["env:"]
    for _ in range(R.randint(1, 3)):
        o.append("  %s: %s" % (pick(SECRET_REF_NAMES), c.K("***")))
    for _ in range(n_leak):
        n, v = named(c)
        o.append("  %s: %s" % (n, v))
    for _ in range(R.randint(1, 3)):
        n, v = env_neg(c)
        o.append("  %s: %s" % (n, v))
    return o


def gha_step_env_leak(c):
    o = ["##[group]Run ./scripts/%s.sh %s" % (pick(["deploy", "release", "smoke-test", "migrate"]), pick(ENVS)),
         "./scripts/deploy.sh " + pick(ENVS), "shell: /usr/bin/bash -e {0}"]
    o += gha_env_block(c, R.randint(1, 2))
    o += ["##[endgroup]", "==> deploying %s (%s)" % (svc(), c.N("short_sha")), "done in %.1fs" % (R.random() * 40)]
    return o


def gha_step_setx(c):
    host_ = "api." + dom()
    hn, fmt_ = pick(GEN_HDRS)
    kind = pk(0.65, 0.0)
    tok = c.S(kind)
    return ["##[group]Run set -x", "set -x", 'TOKEN=$(cat "$RUNNER_TEMP/token")',
            'curl -fsS -H "%s: %s" https://%s/v1/deployments' % (hn, fmt_ % "$TOKEN", host_),
            "shell: /usr/bin/bash -e {0}", "##[endgroup]", "++ cat /home/runner/work/_temp/token", "+ TOKEN=" + tok,
            "+ curl -fsS -H '%s: %s' https://%s/v1/deployments" % (hn, fmt_ % tok, host_),
            '{"id":"%s","status":"queued"}' % c.N("uuid")]


def gha_step_addmask(c):
    tok = c.S(pk(0.7, 0.0))
    return ["##[group]Run echo \"::add-mask::%s\"" % tok, "echo \"::add-mask::%s\"" % tok,
            'echo "token=%s" >> "$GITHUB_OUTPUT"' % tok, "shell: /usr/bin/bash -e {0}", "##[endgroup]"]


def gha_step_b64(c):
    v = GEN[pk(0.5, 0.2)]()
    if isinstance(v, dict):
        v = v["d"]
    b = c.enc_secret("b64_encoded_secret", b64s(v + "\n"))
    return ["##[group]Run echo \"$%s\" | base64" % pick(SECRET_REF_NAMES), 'echo "$KEY" | base64',
            "shell: /usr/bin/bash -e {0}", "env:", "  KEY: " + c.K("***"), "##[endgroup]", b]


def gha_step_docker_login(c):
    u = pick(USERS)
    p = c.S(pick(["github_pat", "docker_pat", "generic_b62"])) if chance(0.6) else pwd(c)
    reg = pick(["ghcr.io", "docker.io", "registry.%s" % dom()])
    return ["##[group]Run docker login %s -u %s -p %s" % (reg, u, p), "docker login %s -u %s -p %s" % (reg, u, p),
            "shell: /usr/bin/bash -e {0}", "##[endgroup]",
            "WARNING! Using --password via the CLI is insecure. Use --password-stdin.",
            "WARNING! Your password will be stored unencrypted in /home/runner/.docker/config.json.",
            "Login Succeeded"]


def gha_step_git_remote(c):
    t = c.S(pick(["github_app_token", "github_pat", "github_fine_grained"]))
    repo = "%s/%s" % (pick(PROJECTS), svc())
    return ["##[group]Run git remote set-url origin https://x-access-token:%s@github.com/%s.git" % (t, repo),
            "git push origin HEAD:refs/heads/release", "shell: /usr/bin/bash -e {0}", "##[endgroup]",
            "To https://github.com/%s.git" % repo,
            " * [new branch]      HEAD -> release"]


def gha_step_npm(c):
    t = c.S("npm_token")
    pkg = "@%s/%s" % (pick(PROJECTS), svc())
    return ["##[group]Run npm config set //registry.npmjs.org/:_authToken %s" % t, "npm publish --access public",
            "shell: /usr/bin/bash -e {0}", "env:", "  NODE_AUTH_TOKEN: " + c.K("XXXXX-XXXXX-XXXXX-XXXXX"), "##[endgroup]",
            "npm notice", "npm notice package: %s@%s" % (pkg, version()), "npm notice shasum: " + c.N("git_sha"),
            "npm notice integrity: sha512-%s[...]%s" % (rs(B64, 13), rs(B64, 10)), "npm notice total files: %d" % R.randint(3, 80),
            "+ %s@%s" % (pkg, version())]


def gha_step_printenv(c):
    o = ["##[group]Run printenv | sort | grep -v '^PATH='", "printenv | sort", "shell: /usr/bin/bash -e {0}", "##[endgroup]"]
    pairs = [("CI", "true"), ("GITHUB_ACTIONS", "true"), ("GITHUB_SHA", c.N("git_sha")),
             ("GITHUB_RUN_ID", c.K(str(R.randint(10 ** 9, 10 ** 10)))), ("RUNNER_OS", "Linux")]
    for _ in range(R.randint(1, 2)):
        pairs.append(named(c))
    pairs.append((pick(SECRET_REF_NAMES), c.K("***")))
    for _ in range(R.randint(1, 3)):
        pairs.append(env_neg(c))
    return o + ["%s=%s" % kv for kv in sorted(pairs)]


def gha_step_docker_push(c):
    img = "ghcr.io/%s/%s" % (pick(PROJECTS), svc())
    return ["##[group]Run docker push %s:%s" % (img, c.N("short_sha")), "docker push --all-tags " + img, "##[endgroup]",
            "The push refers to repository [%s]" % img] + ["%s: Pushed" % k_layer(c) for _ in range(R.randint(2, 4))] + \
           ["%s: digest: %s size: %d" % (pick(["latest", version()]), c.N("docker_digest"), R.randint(900, 3000))]


def gha_step_actionlint(c):
    ref = c.K(sref())
    ln = R.randint(12, 90)
    return ["##[group]Run actionlint", "actionlint -color=false", "##[endgroup]",
            ".github/workflows/release.yml:%d:28: property \"%s\" is not defined in object type {} [expression]" % (
                ln, pick(["npm_tokn", "deploy_ky"])),
            "   |", "%d |           NODE_AUTH_TOKEN: %s" % (ln, ref), "   |                            ^~~~~~~~~~~~~~~~~~~~~~~~",
            "##[error]Process completed with exit code 1."]


def gha_step_aws(c):
    role = c.K("arn:aws:iam::%s:role/gha-%s-deploy" % (acct(), svc()))
    aroa = k_aroa(c)
    return ["##[group]Run aws-actions/configure-aws-credentials@v4", "with:", "  role-to-assume: " + role,
            "  aws-region: " + pick(REGIONS), "  role-session-name: GitHubActions", "  audience: sts.amazonaws.com",
            "##[endgroup]", "Assuming role with OIDC", "Authenticated as assumedRoleId %s:GitHubActions" % aroa,
            "##[group]Run aws sts get-caller-identity", "aws sts get-caller-identity", "##[endgroup]",
            jd({"UserId": aroa + ":GitHubActions", "Account": role.split(":")[4],
                "Arn": "arn:aws:sts::%s:assumed-role/gha-deploy/GitHubActions" % role.split(":")[4]}, 4)]


GHA_LEAKS = [gha_step_env_leak, gha_step_setx, gha_step_addmask, gha_step_b64, gha_step_docker_login,
             gha_step_git_remote, gha_step_npm, gha_step_printenv]
GHA_SAFE = [gha_step_docker_push, gha_step_actionlint, gha_step_aws]


def gha_render(c, steps):
    clk = Clock()
    lines = gha_header(c)
    for s in steps:
        lines += s(c)
    lines += ["Post job cleanup.", "Cleaning up orphan processes"]
    stamp = chance(0.65)
    c.hint = {"command": "gh run view %d --log" % R.randint(10 ** 9, 10 ** 10)} if chance(0.5) else None
    if stamp:
        return "\n".join(clk.gha() + " " + l for l in lines)
    return "\n".join(lines)


@T(CI, 28)
def t_gha(c):
    steps = [gha_checkout] + R.sample(GHA_LEAKS, pick([1, 1, 2])) + R.sample(GHA_SAFE, R.randint(0, 2))
    return gha_render(c, steps)


def gl_header(c):
    sha = c.K(n_git_sha()[:8]) if chance(0.5) else c.N("short_sha")
    img = "registry.gitlab.com/%s/ci-images/%s:%s" % (pick(PROJECTS), pick(["node", "python", "deploy"]), version())
    o = ["Running with gitlab-runner 17.%d.%d (%s)" % (R.randint(0, 9), R.randint(0, 3), c.K(n_git_sha()[:8])),
         "  on %s %s, system ID: s_%s" % (pick(["docker-runner-3", "k8s-runner", "shared-runner-%d" % R.randint(1, 9)]),
                                          c.K(rtok(B62 + "-_", 8)), c.K(rs(HEX, 12))),
         "Preparing the \"docker\" executor",
         "Using Docker executor with image %s ..." % img,
         "Using docker image %s for %s with digest %s ..." % (c.N("docker_digest"), img,
                                                           img.rsplit(":", 1)[0] + "@" + c.N("docker_digest")),
         "Preparing environment", "Running on runner-%s-project-%d-concurrent-0 via %s..." % (
             rtok(LALNUM, 8), R.randint(1000, 99999), c.N("pod")),
         "Getting source from Git repository", "Fetching changes with git depth set to 20...",
         "Initialized empty Git repository in /builds/%s/%s/.git/" % (pick(PROJECTS), svc()),
         "Created fresh repository.", "Checking out %s as detached HEAD (ref is main)..." % sha,
         "Skipping Git submodules setup", "Executing \"step_script\" stage of the job script"]
    return o


def gl_steps(c):
    k = R.randint(0, 8)
    if k == 0:
        o = ["$ export"]
        pairs = [("CI_JOB_TOKEN", c.K("[MASKED]")), ("CI_COMMIT_SHA", c.N("git_sha")), ("CI_PIPELINE_ID", c.K(str(R.randint(10 ** 8, 10 ** 10))))]
        pairs += [named(c) for _ in range(R.randint(1, 3))] + [env_neg(c) for _ in range(R.randint(1, 3))]
        return o + ["declare -x %s=\"%s\"" % kv for kv in sorted(pairs)]
    if k == 1:
        t = c.S("gitlab_pat") if chance(0.5) else gsec(c)
        return ['$ curl --fail --header "PRIVATE-TOKEN: %s" "https://gitlab.%s/api/v4/projects/%d/releases"' % (
            t, dom(), R.randint(10, 9999)), '{"tag_name":"v%s","commit":{"id":"%s"}}' % (version(), c.N("git_sha"))]
    if k == 2:
        p = pwd(c)
        return ["$ docker login -u %s -p %s %s" % (pick(USERS), shq(p), "registry." + dom()),
                "WARNING! Using --password via the CLI is insecure. Use --password-stdin.", "Login Succeeded"]
    if k == 3:
        p = pwd(c)
        return ["$ mysql -h %s -u %s -p%s -e 'SELECT COUNT(*) FROM schema_migrations'" % (host(), pick(USERS), shq(p)),
                "mysql: [Warning] Using a password on the command line interface can be insecure.",
                "COUNT(*)", str(R.randint(10, 400))]
    if k == 4:
        p = pwd(c)
        a = gsec(c)
        return ["$ helm upgrade --install %s ./chart --namespace %s --set db.password=%s --set %s=%s" % (
            svc(), pick(ENVS), shq(p), pick(["apiKey", "relay.seed", "upstream.auth", "license"]), a),
            "Release \"%s\" has been upgraded. Happy Helming!" % svc(), "REVISION: %d" % R.randint(2, 90)]
    if k == 5:
        url = c.S(pick(["db_url", "mongodb_uri", "redis_url"]))
        return ['$ psql "%s" -c "\\dt"' % url if url.startswith("postgres") else "$ ./bin/healthcheck %s" % url,
                "ok"]
    if k == 6:
        t = gsec(c)
        return ["$ ./scripts/notify.sh %s %s" % (pick(ENVS), t), "+ curl -s -X POST -d token=%s https://hooks.%s/deploy" % (t, dom()),
                '{"queued":true}']
    if k == 7:
        n, v = named(c, url=False)
        return ["$ echo \"%s=%s\" >> deploy.env" % (n, v), "$ cat deploy.env", "%s=%s" % (n, v)]
    t = c.S(pk(0.7, 0.0))
    return ['$ echo "debug: using token %s"' % t, "debug: using token " + t]


def gl_safe(c):
    k = R.randint(0, 3)
    if k == 0:
        return ['$ echo "$CI_REGISTRY_PASSWORD" | docker login -u "$CI_REGISTRY_USER" --password-stdin "$CI_REGISTRY"',
                "Login Succeeded"] if c.K("$CI_REGISTRY_PASSWORD") else []
    if k == 1:
        return ["$ docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA",
                "%s: digest: %s size: %d" % (c.N("short_sha"), c.N("docker_digest"), R.randint(900, 3000))]
    if k == 2:
        return ["$ echo \"token is ${%s}\"" % pick(["DEPLOY_TOKEN", "API_KEY"]), "token is " + c.K("[MASKED]")]
    return ["$ npm ci", "added %d packages, and audited %d packages in %ds" % (R.randint(100, 900), R.randint(900, 1200), R.randint(5, 60))]


@T(CI, 24)
def t_gitlab(c):
    o = gl_header(c)
    for _ in range(pick([1, 1, 2])):
        o += gl_steps(c)
    for _ in range(R.randint(0, 2)):
        o += gl_safe(c)
    o += ["Uploading artifacts for successful job", "Cleaning up project directory and file based variables",
          "Job succeeded"]
    if chance(0.3):
        o = ["section_start:%d:step_script\r\x1b[0K" % epoch() + l if l.startswith("Executing") else l for l in o]
    c.hint = {"command": "glab ci trace %d" % R.randint(10 ** 8, 10 ** 10)} if chance(0.4) else None
    return "\n".join(o)


@T(CI, 8)
def t_ci_neg(c):
    if chance(0.5):
        return gha_render(c, [gha_checkout] + R.sample(GHA_SAFE, R.randint(1, 3)))
    o = gl_header(c)
    for _ in range(R.randint(2, 3)):
        o += gl_safe(c)
    return "\n".join(o + ["Job succeeded"])


# ======================================================================= docker
BASE_PATH = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def img_name():
    return pick(["ghcr.io/%s/%s" % (pick(PROJECTS), svc()), "%s.dkr.ecr.%s.amazonaws.com/%s" % (acct(), pick(REGIONS), svc()),
                 "registry.%s/%s/%s" % (dom(), pick(PROJECTS), svc()), "%s/%s" % (pick(PROJECTS), svc())])


def env_list(c, n_sec, n_neg, url=True):
    env = [BASE_PATH] + base_env_lines(R.randint(1, 4))
    for _ in range(n_sec):
        env.append("%s=%s" % named(c, url=url))
    for _ in range(n_neg):
        env.append("%s=%s" % env_neg(c))
    R.shuffle(env)
    return env


@T(DOCKER, 15)
def t_docker_inspect(c):
    cid = k_cid(c)
    proj_ = pick(PROJECTS)
    s = svc()
    image = img_name() + ":" + pick([version, lambda: "latest", lambda: c.N("short_sha")])()
    args = []
    if chance(0.35):
        v = gsec(c)
        args = pick([["--token", v], ["serve", "--upstream-auth=" + v], ["worker", v]])
    nid = c.K(rs(HEX, 64))
    eid = c.K(rs(HEX, 64))
    d = {"Id": cid, "Created": iso_ms(), "Path": pick(["/docker-entrypoint.sh", "/app/server", "node"]), "Args": args,
         "State": {"Status": "running", "Running": True, "Paused": False, "Restarting": False, "OOMKilled": False,
                   "Dead": False, "Pid": R.randint(1000, 90000), "ExitCode": 0, "Error": "", "StartedAt": iso_ms(),
                   "FinishedAt": "0001-01-01T00:00:00Z"},
         "Image": c.N("docker_digest"),
         "ResolvConfPath": "/var/lib/docker/containers/%s/resolv.conf" % cid,
         "Name": "/%s-%s-1" % (proj_, s), "RestartCount": 0, "Driver": "overlay2", "Platform": "linux",
         "HostConfig": {"NetworkMode": "%s_default" % proj_, "RestartPolicy": {"Name": "unless-stopped", "MaximumRetryCount": 0}},
         "Config": {"Hostname": cid[:12], "Domainname": "", "User": pick(["", "app", "1000:1000"]),
                    "Env": env_list(c, R.randint(1, 3), R.randint(1, 3)),
                    "Cmd": args or None, "Image": image, "WorkingDir": "/app",
                    "Labels": {"com.docker.compose.config-hash": c.N("sha256"), "com.docker.compose.project": proj_,
                               "com.docker.compose.service": s, "com.docker.compose.version": "2.%d.%d" % (R.randint(20, 32), R.randint(0, 3)),
                               "org.opencontainers.image.revision": c.N("git_sha")}},
         "NetworkSettings": {"Networks": {"%s_default" % proj_: {"NetworkID": nid, "EndpointID": eid,
                                                                  "Gateway": "172.18.0.1", "IPAddress": "172.18.0.%d" % R.randint(2, 30),
                                                                  "MacAddress": "02:42:ac:12:00:%02x" % R.randint(2, 200)}}}}
    c.hint = {"command": "docker inspect %s-%s-1" % (proj_, s)}
    return json.dumps([d], indent=4, ensure_ascii=False)


@T(DOCKER, 5)
def t_docker_inspect_fmt(c):
    name = "%s-%s-1" % (pick(PROJECTS), svc())
    env = env_list(c, R.randint(1, 3), R.randint(1, 2))
    if chance(0.5):
        cmd = "docker inspect --format '{{json .Config.Env}}' %s" % name
        out = json.dumps(env)
    else:
        cmd = "docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' %s" % name
        out = "\n".join(env) + "\n"
    c.hint = {"command": cmd}
    return out if chance(0.5) else "$ %s\n%s" % (cmd, out)


@T(DOCKER, 12)
def t_compose_config(c):
    proj_ = pick(PROJECTS)
    warn = []
    api_env = {}
    for _ in range(R.randint(1, 3)):
        n, v = named(c, url=True)
        put(api_env, n, v)
    for _ in range(R.randint(1, 3)):
        n, v = env_neg(c)
        put(api_env, n, v)
    if chance(0.4):
        miss = pick(["SENTRY_DSN", "STRIPE_KEY", "OTEL_HEADERS"])
        warn.append('WARN[0000] The "%s" variable is not set. Defaulting to a blank string.' % miss)
        put(api_env, miss, "")
    api = {"build": {"context": "/home/%s/src/%s" % (pick(PEOPLE).replace("á", "a"), proj_), "dockerfile": "Dockerfile"}}
    if chance(0.4):
        api["build"]["args"] = {"NPM_TOKEN": c.S("npm_token")}
    if chance(0.35):
        api["command"] = ["sh", "-c", "exec ./server --db-pass=%s" % c.K("$$DB_PASSWORD")]
    api["depends_on"] = {"db": {"condition": "service_healthy", "required": True}}
    api["environment"] = dict(sorted(api_env.items()))
    api["image"] = img_name() + "@" + c.N("docker_digest")
    api["networks"] = {"default": None}
    api["ports"] = [{"mode": "ingress", "target": 8080, "published": "8080", "protocol": "tcp"}]
    pu = pick(USERS)
    dbp = pwd(c)
    db = {"environment": {"POSTGRES_DB": svc(), "POSTGRES_PASSWORD": dbp, "POSTGRES_USER": pu},
          "image": "postgres:16.%d" % R.randint(1, 6), "networks": {"default": None},
          "healthcheck": {"test": ["CMD-SHELL", "pg_isready -U %s" % pu], "interval": "5s"}}
    services = {"api": api, "db": db}
    if chance(0.4):
        services["redis"] = {"command": ["redis-server", "--requirepass", pwd(c)], "image": "redis:7-alpine",
                             "networks": {"default": None}}
    doc = {"name": proj_, "services": services, "networks": {"default": {"name": proj_ + "_default"}}}
    if chance(0.4):
        doc["secrets"] = {"db_password": {"name": proj_ + "_db_password", "file": "/run/secrets/db_password.txt"}}
    c.hint = {"command": "docker compose config"}
    return "\n".join(warn + [ydump(doc, li=False, qp=0.1)])


def pull_lines(c, image):
    tag = image.rsplit(":", 1)[1] if ":" in image.split("/")[-1] else "latest"
    o = ["Unable to find image '%s' locally" % image, "%s: Pulling from %s" % (tag, image.split(":")[0])]
    o += ["%s: Pull complete" % k_layer(c) for _ in range(R.randint(2, 5))]
    o += ["Digest: " + c.N("docker_digest"), "Status: Downloaded newer image for " + image]
    return o


@T(DOCKER, 10)
def t_docker_run(c):
    k = R.randint(0, 3)
    if k == 0:
        image = pick(["postgres:16", "mysql:8.4", "mariadb:11", "mongo:7"])
        envn = {"p": "POSTGRES_PASSWORD", "m": "MYSQL_ROOT_PASSWORD", "mo": "MONGO_INITDB_ROOT_PASSWORD"}
        n = envn["mo"] if image.startswith("mongo") else envn["p"] if image.startswith("post") else envn["m"]
        flags = "-e %s=%s" % (n, shq(pwd(c)))
    elif k == 1:
        image = img_name() + ":" + version()
        flags = " ".join("-e %s=%s" % (nm, shq(v)) for nm, v in [named(c) for _ in range(R.randint(1, 3))])
    elif k == 2:
        image = img_name() + ":latest"
        flags = "--rm"
        image += " migrate --database-password %s" % shq(pwd(c))
    else:
        image = img_name() + ":" + version()
        flags = "--rm"
        image += " %s %s" % (pick(["sync", "agent run", "connect"]), gsec(c))
    cmd = "docker run -d --name %s %s -p %d:%d %s" % (svc(), flags, 5432, 5432, image)
    c.hint = {"command": cmd}
    o = ["$ " + cmd]
    if chance(0.6):
        o += pull_lines(c, image.split(" ")[0])
    o.append(k_cid(c))
    return "\n".join(o)


@T(DOCKER, 7)
def t_docker_build(c):
    tok = c.S(pick(["npm_token", "github_pat", "pypi_token"]) if chance(0.55) else pick(GENERIC_KINDS))
    argn = pick(["NPM_TOKEN", "GH_TOKEN", "PIP_INDEX_TOKEN", "BUILD_SECRET", "FETCH_AUTH"])
    if chance(0.5):
        cmd = "docker build --build-arg %s=%s -t %s:%s ." % (argn, tok, svc(), version())
        c.hint = {"command": cmd}
        o = ["$ " + cmd, '#0 building with "default" instance using docker driver', "",
             "#1 [internal] load build definition from Dockerfile", "#1 transferring dockerfile: %dB done" % R.randint(400, 2000),
             "#2 [internal] load metadata for docker.io/library/node:20-alpine",
             "#5 [base 1/6] FROM docker.io/library/node:20-alpine@" + c.N("docker_digest"),
             '#8 [deps 3/6] RUN echo "//registry.npmjs.org/:_authToken=%s" > .npmrc && npm ci' % c.K("${%s}" % argn),
             "#8 %.2f added %d packages in %ds" % (R.random() * 30, R.randint(100, 900), R.randint(5, 60)),
             "#12 exporting to image", "#12 writing image %s done" % c.N("docker_digest"),
             "#12 naming to docker.io/library/%s done" % svc()]
    else:
        cmd = "docker history --no-trunc %s:latest" % svc()
        c.hint = {"command": cmd}
        o = ["IMAGE                                                                     CREATED        CREATED BY                                      SIZE      COMMENT",
             "%s   2 days ago     CMD [\"node\" \"dist/main.js\"]                    0B        buildkit.dockerfile.v0" % c.N("docker_digest"),
             "<missing>                                                                 2 days ago     RUN |1 %s=%s /bin/sh -c npm ci --omit=dev # buildkit   %dMB      buildkit.dockerfile.v0" % (argn, tok, R.randint(20, 300)),
             "<missing>                                                                 2 days ago     ARG %s                                       0B        buildkit.dockerfile.v0" % argn,
             "<missing>                                                                 3 weeks ago    /bin/sh -c #(nop)  CMD [\"node\"]                 0B"]
    return "\n".join(o)


@T(DOCKER, 4)
def t_docker_config_json(c):
    auths = {}
    for reg in R.sample(["ghcr.io", "https://index.docker.io/v1/", "registry.%s" % dom(), "%s.azurecr.io" % pick(PROJECTS)], R.randint(1, 3)):
        u = pick(USERS)
        p = GEN[pick(["github_pat", "docker_pat", "generic_b62", "password_random"])]()
        auths[reg] = {"auth": c.enc_secret("docker_auth_b64", b64s("%s:%s" % (u, p)))}
    auths["%s.dkr.ecr.%s.amazonaws.com" % (acct(), pick(REGIONS))] = {}
    c.hint = {"command": "cat ~/.docker/config.json"}
    return jd({"auths": auths, "credsStore": pick(["desktop", "osxkeychain", "pass"]), "currentContext": "default"}, 1).replace("\n ", "\n\t")


@T(DOCKER, 3)
def t_docker_ps(c):
    o = ["CONTAINER ID                                                       IMAGE              COMMAND                                         STATUS        NAMES"]
    for i in range(R.randint(2, 4)):
        if i == 0:
            cmdv = '"/app/server --api-key=%s"' % gsec(c)
        else:
            cmdv = '"docker-entrypoint.sh postgres"'
        o.append("%s   %s   %s   Up %d hours   %s" % (k_cid(c), pick(["postgres:16", svc() + ":latest", "redis:7"]),
                                                    cmdv, R.randint(1, 50), "%s-%s-1" % (pick(PROJECTS), svc())))
    c.hint = {"command": "docker ps --no-trunc"}
    return "\n".join(o)


@T(DOCKER, 6)
def t_docker_neg(c):
    k = R.randint(0, 2)
    if k == 0:
        image = img_name() + ":" + version()
        c.hint = {"command": "docker pull " + image}
        return "\n".join(["$ docker pull " + image] + pull_lines(c, image)[1:])
    if k == 1:
        c.hint = {"command": "docker images --digests"}
        o = ["REPOSITORY                TAG       DIGEST                                                                    IMAGE ID       CREATED       SIZE"]
        for _ in range(R.randint(3, 6)):
            o.append("%-25s %-9s %s   %s   %d days ago   %dMB" % (svc(), version(), c.N("docker_digest"), k_layer(c), R.randint(1, 90), R.randint(5, 900)))
        return "\n".join(o)
    env = [BASE_PATH] + ["%s=%s" % env_neg(c) for _ in range(R.randint(3, 6))]
    env.append("DB_PASSWORD=%s" % c.K(pick(["${DB_PASSWORD}", "<redacted>", "changeme", "$(cat /run/secrets/db_password)"])))
    c.hint = {"command": "docker inspect --format '{{json .Config.Env}}' %s" % svc()}
    return json.dumps(env)


# ======================================================================= kubectl
K8S_SECRET_KEYS = ["password", "api-key", "token", "client-secret", "secret-key", "auth-token", "access-token",
                   "webhook-secret", "admin-password", "redis-password", "postgres-password", "jwt-secret",
                   "signing-key", "encryption-key", "session-secret", "smtp-password"]
K8S_NEUTRAL_KEYS = ["value", "payload", "material", "bootstrap", "relay", "uplink", "edge", "handshake", "seed",
                    "blob", "data", "key", "creds"]


def k8s_key_for(kind):
    if kind in V and chance(0.5):
        return pick(V[kind][1])
    if kind in GENERIC and chance(0.6):
        return pick(K8S_NEUTRAL_KEYS + [kebab(n) for n in GENERIC_NEUTRAL_NAMES])
    if kind in PASSWORDS:
        return pick(["password", "admin-password", "postgres-password", "redis-password", "PASSWORD", "smtp-password"])
    return pick(K8S_SECRET_KEYS)


def k8s_secret_entry(c, decoded_visible, url=False):
    kind = pk(0.58, 0.15, url)
    disp, pairs, keeps = raw(kind)
    key = k8s_key_for(kind)
    b = c.enc_secret("k8s_secret_b64", b64s(disp))
    if decoded_visible:
        c.add(pairs)
    return key, b, disp, pairs


def k8s_plain_entry(c, decoded_visible=False):
    key, val = pick([("username", user()), ("host", host()), ("port", pick(["5432", "3306", "6379", "5672"])),
                     ("database", svc()), ("region", pick(REGIONS)), ("endpoint", "https://%s.%s" % (svc(), dom())),
                     ("user", user()), ("bucket", "%s-%s" % (pick(PROJECTS), pick(["assets", "exports"]))),
                     ("sslmode", "require"), ("tls-enabled", "true")])
    b = c.K(b64s(val))
    if decoded_visible and key in ("host", "endpoint", "bucket"):
        c.K(val)
    return key, b, val, None


def put(d, k, v):
    if k in d:
        raise Collide()
    d[k] = v


def uniq(ents):
    if len({e[0] for e in ents}) != len(ents):
        raise Collide()
    return ents


def k8s_meta(c, name, ns, annotations=None):
    m = {}
    if annotations:
        m["annotations"] = annotations
    m["creationTimestamp"] = iso()
    m["name"] = name
    m["namespace"] = ns
    m["resourceVersion"] = c.K(str(R.randint(10 ** 5, 10 ** 9)))
    m["uid"] = c.N("uuid")
    return m


@T(KUBE, 16)
def t_k_get_secret(c):
    name = "%s-%s" % (svc(), pick(["credentials", "secrets", "env", "db", "api-keys", "config"]))
    ns = pick(ENVS + ["default", "platform"])
    mode = R.randint(0, 2)  # 0: no decoded, 1: last-applied stringData, 2: follow-up base64 -d
    ents = [k8s_secret_entry(c, mode == 1, url=chance(0.3)) for _ in range(R.randint(1, 3))]
    ents += [k8s_plain_entry(c, mode == 1) for _ in range(R.randint(0, 3))]
    ents = sorted(uniq(ents))
    data = {e[0]: e[1] for e in ents}
    ann = None
    if mode == 1:
        la = {"apiVersion": "v1", "kind": "Secret", "metadata": {"annotations": {}, "name": name, "namespace": ns},
              "stringData": {e[0]: e[2] for e in ents}, "type": "Opaque"}
        ann = {"kubectl.kubernetes.io/last-applied-configuration": json.dumps(la, separators=(",", ":")) + "\n"}
    doc = {"apiVersion": "v1", "data": data, "kind": "Secret", "metadata": k8s_meta(c, name, ns, ann), "type": "Opaque"}
    cmd = "kubectl get secret %s -n %s -o yaml" % (name, ns)
    c.hint = {"command": cmd}
    out = ydump(doc, li=False, qp=0.0)
    if mode == 2:
        k, b, v, pairs = pick([e for e in ents if e[3]])
        out += "\n$ kubectl get secret %s -n %s -o jsonpath='{.data.%s}' | base64 -d\n%s" % (name, ns, k.replace(".", "\\."), v)
        c.add(pairs)
    return out


@T(KUBE, 6)
def t_k_get_secret_json(c):
    name = "%s-%s" % (svc(), pick(["credentials", "keys", "tokens"]))
    ns = pick(ENVS)
    ents = [k8s_secret_entry(c, False) for _ in range(R.randint(1, 3))] + [k8s_plain_entry(c) for _ in range(R.randint(0, 2))]
    ents = sorted(uniq(ents))
    jq = chance(0.4)
    if jq:
        cmd = "kubectl get secret %s -n %s -o json | jq '.data | map_values(@base64d)'" % (name, ns)
        out = {}
        for k, b, v, pairs in ents:
            out[k] = v
            if pairs:
                drop(c, b)
                c.add(pairs)
            else:
                c.keep.remove(b)
        c.hint = {"command": cmd}
        return jd(out)
    doc = {"apiVersion": "v1", "data": {e[0]: e[1] for e in ents}, "kind": "Secret",
           "metadata": k8s_meta(c, name, ns), "type": "Opaque"}
    c.hint = {"command": "kubectl get secret %s -n %s -o json" % (name, ns)}
    return json.dumps(doc, indent=4)


@T(KUBE, 5)
def t_k_tls_or_kubeconfig(c):
    if chance(0.5):
        name = "%s-tls" % svc()
        key_pem, _, _ = private_key_any()
        doc = {"apiVersion": "v1", "data": {"tls.crt": c.K(b64s(n_cert() + "\n")),
                                            "tls.key": c.enc_secret("tls_key_b64", b64s(key_pem + "\n"))},
               "kind": "Secret", "metadata": k8s_meta(c, name, pick(ENVS)), "type": "kubernetes.io/tls"}
        c.hint = {"command": "kubectl get secret %s -o yaml" % name}
        return ydump(doc, li=False, qp=0.0)
    cl = "arn:aws:eks:%s:%s:cluster/%s" % (pick(REGIONS), acct(), pick(PROJECTS))
    user_ = {"name": cl}
    if chance(0.5):
        key_pem, _, _ = private_key_any()
        user_["user"] = {"client-certificate-data": c.K(b64s(n_cert() + "\n")),
                         "client-key-data": c.enc_secret("kubeconfig_client_key", b64s(key_pem + "\n"))}
    else:
        user_["user"] = {"token": c.S(pick(["jwt", "generic_b62", "generic_b64url"]))}
    doc = {"apiVersion": "v1",
           "clusters": [{"cluster": {"certificate-authority-data": c.K(b64s(n_cert() + "\n")),
                                     "server": "https://%s.gr7.%s.eks.amazonaws.com" % (rs(HEXU, 32), pick(REGIONS))},
                         "name": cl}],
           "contexts": [{"context": {"cluster": cl, "namespace": pick(ENVS), "user": cl}, "name": cl}],
           "current-context": cl, "kind": "Config", "preferences": {}, "users": [user_]}
    c.hint = {"command": "kubectl config view --raw"}
    return ydump(doc, li=False, qp=0.0)


@T(KUBE, 5)
def t_k_dockercfg(c):
    reg = pick(["ghcr.io", "https://index.docker.io/v1/", "registry.%s" % dom()])
    u = pick(USERS)
    pw_kind = pick(["github_pat", "docker_pat", "generic_b62", "password_random"])
    p = GEN[pw_kind]()
    a = b64s("%s:%s" % (u, p))
    inner = json.dumps({"auths": {reg: {"username": u, "password": p, "auth": a}}}, separators=(",", ":"))
    outer = c.enc_secret("k8s_secret_b64", b64s(inner))
    name = "regcred-" + pick(PROJECTS)
    doc = {"apiVersion": "v1", "data": {".dockerconfigjson": outer}, "kind": "Secret",
           "metadata": k8s_meta(c, name, pick(ENVS)), "type": "kubernetes.io/dockerconfigjson"}
    out = ydump(doc, li=False, qp=0.0)
    cmd = "kubectl get secret %s -o yaml" % name
    if chance(0.5):
        out += "\n$ kubectl get secret %s -o jsonpath='{.data.\\.dockerconfigjson}' | base64 -d\n%s" % (name, inner)
        c.S(pw_kind, value=p)
        c.enc_secret("docker_auth_b64", a)
    c.hint = {"command": cmd}
    return out


@T(KUBE, 6)
def t_k_satoken(c):
    ns = pick(ENVS + ["kube-system", "ci"])
    sa = pick(["deployer", "argocd-manager", "ci-bot", "gitlab-runner"])
    payload = {"iss": "kubernetes/serviceaccount", "kubernetes.io/serviceaccount/namespace": ns,
               "kubernetes.io/serviceaccount/secret.name": sa + "-token", "kubernetes.io/serviceaccount/service-account.name": sa,
               "kubernetes.io/serviceaccount/service-account.uid": n_uuid(), "sub": "system:serviceaccount:%s:%s" % (ns, sa)}
    jwt = G.g_jwt("RS256", payload)
    k = R.randint(0, 2)
    ca = n_cert()
    if k == 0:
        c.S("k8s_sa_token", value=jwt)
        c.hint = {"command": "kubectl describe secret %s-token -n %s" % (sa, ns)}
        return "\n".join(["Name:         %s-token" % sa, "Namespace:    %s" % ns, "Labels:       <none>",
                          "Annotations:  kubernetes.io/service-account.name: %s" % sa,
                          "              kubernetes.io/service-account.uid: %s" % c.N("uuid"), "",
                          "Type:  kubernetes.io/service-account-token", "", "Data", "====",
                          "ca.crt:     %d bytes" % (len(ca) + 1), "namespace:  %d bytes" % len(ns), "token:      " + jwt])
    if k == 1:
        c.S("k8s_sa_token", value=jwt)
        cmd = "kubectl create token %s -n %s --duration=%s" % (sa, ns, pick(["1h", "24h", "8760h"]))
        c.hint = {"command": cmd}
        return jwt if chance(0.5) else "$ %s\n%s" % (cmd, jwt)
    doc = {"apiVersion": "v1", "data": {"ca.crt": c.K(b64s(ca + "\n")), "namespace": c.K(b64s(ns)),
                                        "token": c.enc_secret("k8s_secret_b64", b64s(jwt))},
           "kind": "Secret", "metadata": k8s_meta(c, sa + "-token", ns, {"kubernetes.io/service-account.name": sa}),
           "type": "kubernetes.io/service-account-token"}
    c.hint = {"command": "kubectl get secret %s-token -n %s -o yaml" % (sa, ns)}
    return ydump(doc, li=False, qp=0.0)


@T(KUBE, 9)
def t_k_describe_pod(c):
    s = svc()
    h, sfx = pod_parts()
    pod = c.K("%s-%s-%s" % (s, h, sfx))
    ns = pick(ENVS)
    img = img_name() + ":" + version()
    envl = []
    for _ in range(R.randint(1, 3)):
        n, v = env_neg(c)
        envl.append((n, v))
    sec_name = "%s-credentials" % s
    ref = c.K("<set to the key '%s' in secret '%s'>" % (pick(["password", "api-key", "token"]), sec_name))
    envl.append((pick(PASSWORD_NAMES + GENERIC_CRED_NAMES), ref + "  Optional: false"))
    for _ in range(R.randint(1, 2)):
        envl.append(named(c, url=chance(0.3)))
    R.shuffle(envl)
    args = ["--listen=:8080"]
    if chance(0.35):
        args.append("--%s=%s" % (pick(["upstream-token", "relay-key", "license", "auth"]), gsec(c)))
    w = max(len(n) for n, _ in envl) + 2
    o = ["Name:             " + pod, "Namespace:        " + ns, "Priority:         0", "Service Account:  " + s,
         "Node:             ip-10-0-%d-%d.ec2.internal/10.0.%d.%d" % ((R.randint(0, 255),) * 2 + (R.randint(0, 255),) * 2),
         "Labels:           app=%s" % s, "                  pod-template-hash=%s" % h,
         "Status:           Running", "IP:               10.0.%d.%d" % (R.randint(0, 255), R.randint(2, 254)),
         "Controlled By:  ReplicaSet/%s-%s" % (s, h), "Containers:", "  %s:" % s,
         "    Container ID:  containerd://" + k_cid(c), "    Image:         " + img,
         "    Image ID:      %s@%s" % (img.rsplit(":", 1)[0], c.N("docker_digest")), "    Port:          8080/TCP",
         "    Args:"] + ["      " + a for a in args] + [
        "    State:          Running", "      Started:      %s" % http_date(), "    Ready:          True",
        "    Restart Count:  %d" % R.randint(0, 4), "    Environment:"] + \
        ["      %s%s" % ((n + ":").ljust(w), v) for n, v in envl] + [
        "    Mounts:", "      /var/run/secrets/kubernetes.io/serviceaccount from kube-api-access-%s (ro)" % rs(K8S, 5),
        "Events:", "  Type    Reason   Age   From     Message", "  ----    ------   ----  ----     -------",
        "  Normal  Pulled   %dm   kubelet  Container image \"%s\" already present on machine" % (R.randint(1, 59), img)]
    c.hint = {"command": "kubectl describe pod %s -n %s" % (pod, ns)}
    return "\n".join(o)


@T(KUBE, 7)
def t_k_configmap_deploy(c):
    name = "%s-config" % svc()
    ns = pick(ENVS)
    data = {}
    for _ in range(R.randint(2, 4)):
        n, v = env_neg(c)
        put(data, n, v)
    if chance(0.7):
        n, v = named(c, url=True)
        put(data, n, v)
    data = dict(sorted(data.items()))
    doc = {"apiVersion": "v1"}
    if chance(0.6):
        doc["binaryData"] = {pick(["logo.png", "truststore.jks", "geoip.mmdb", "feature-flags.bin"]): c.K(b64(rb(R.randint(30, 120))))}
    doc["data"] = data
    if chance(0.4):
        doc["data"]["app.yaml"] = "server:\n  port: 8080\nfeature_flags:\n  - %s\n" % pick(["beta_api", "async_export"])
    doc["kind"] = "ConfigMap"
    doc["metadata"] = k8s_meta(c, name, ns)
    c.hint = {"command": "kubectl get configmap %s -n %s -o yaml" % (name, ns)}
    return ydump(doc, li=False, qp=0.0)


@T(KUBE, 6)
def t_k_neg(c):
    k = R.randint(0, 2)
    if k == 0:
        c.hint = {"command": "kubectl get pods -n %s -o wide" % pick(ENVS)}
        o = ["NAME                                  READY   STATUS    RESTARTS   AGE   IP            NODE"]
        for _ in range(R.randint(3, 7)):
            s = svc()
            h, sfx = pod_parts()
            o.append("%-37s 1/1     Running   %d          %dd   10.0.%d.%d   ip-10-0-1-%d.ec2.internal" % (
                c.K("%s-%s-%s" % (s, h, sfx)), R.randint(0, 3), R.randint(1, 30), R.randint(0, 255), R.randint(2, 254), R.randint(2, 254)))
        return "\n".join(o)
    if k == 1:
        name = "%s-credentials" % svc()
        c.hint = {"command": "kubectl describe secret %s" % name}
        o = ["Name:         " + name, "Namespace:    " + pick(ENVS), "Labels:       app.kubernetes.io/managed-by=Helm",
             "Annotations:  meta.helm.sh/release-name: %s" % svc(), "", "Type:  Opaque", "", "Data", "===="]
        for key in R.sample(K8S_SECRET_KEYS + ["username", "host"], R.randint(2, 4)):
            o.append("%-14s %d bytes" % (key + ":", R.randint(8, 64)))
        return "\n".join(o)
    name = "%s-credentials" % svc()
    ents = [k8s_plain_entry(c) for _ in range(R.randint(2, 4))]
    ents = sorted(uniq(ents))
    doc = {"apiVersion": "v1", "data": {e[0]: e[1] for e in ents}, "kind": "Secret",
           "metadata": k8s_meta(c, name, pick(ENVS)), "type": "Opaque"}
    c.hint = {"command": "kubectl get secret %s -o yaml" % name}
    return ydump(doc, li=False, qp=0.0)


# ======================================================================= helm
HELM_PH = ["{{ .Values.auth.password }}", "ref+vault://secret/data/%s#password", "changeme", "${DB_PASSWORD}",
           "ref+awsssm:///prod/%s/api_key", "<set-via-sealed-secret>", "{{ requiredEnv \"API_TOKEN\" }}", "REPLACE_ME"]


def helm_ph(c):
    p = pick(HELM_PH)
    if "%s" in p:
        p = p % svc()
    return c.K(p)


def helm_values(c, n_leaks=None):
    v = {}
    pw1 = pwd(c)
    if chance(0.7):
        v["auth"] = {"database": svc(), "existingSecret": "", "password": pw1, "username": user()}
        if chance(0.5):
            v["auth"]["postgresPassword"] = pwd(c)
    else:
        v["auth"] = {"existingSecret": c.K("%s-db-credentials" % svc()), "password": helm_ph(c)}
        drop(c, pw1)
    v["image"] = {"repository": img_name(), "tag": c.N("short_sha"), "pullPolicy": "IfNotPresent"}
    if chance(0.5):
        v["image"]["digest"] = c.N("docker_digest")
    v["podAnnotations"] = {"checksum/config": c.N("sha256")}
    env = []
    for _ in range(n_leaks if n_leaks is not None else R.randint(1, 2)):
        n, val = named(c, url=chance(0.3))
        env.append({"name": n, "value": val})
    for _ in range(R.randint(1, 3)):
        n, val = env_neg(c)
        env.append({"name": n, "value": val})
    R.shuffle(env)
    v["env"] = env
    if chance(0.5):
        v["redis"] = {"auth": {"enabled": True, "password": pwd(c)}}
    if chance(0.4):
        key = pick(["apiKey", "licenseKey", "relaySeed", "upstreamAuth", "token", "edgeCreds"])
        v["integrations"] = {pick(["datadog", "sentry", "partner", "relay"]): {key: c.S(pk(0.7, 0.0)), "enabled": True}}
    if chance(0.4):
        v["ingress"] = {"enabled": True, "className": "nginx", "hosts": [{"host": "%s.%s" % (svc(), dom()),
                                                                            "paths": [{"path": "/", "pathType": "Prefix"}]}]}
    if chance(0.3):
        v["serviceAccount"] = {"annotations": {"eks.amazonaws.com/role-arn": c.K("arn:aws:iam::%s:role/%s-irsa" % (acct(), svc()))}}
    return v


@T(HELM, 16)
def t_helm_get_values(c):
    rel, ns = svc(), pick(ENVS)
    allf = chance(0.3)
    cmd = "helm get values %s -n %s%s" % (rel, ns, " --all" if allf else "")
    c.hint = {"command": cmd}
    vals = helm_values(c)
    if allf:
        vals["replicaCount"] = R.randint(1, 6)
        vals["resources"] = {"limits": {"cpu": "500m", "memory": "512Mi"}}
    head = "COMPUTED VALUES:" if allf else "USER-SUPPLIED VALUES:"
    return head + "\n" + ydump(dict(sorted(vals.items())), li=False, qp=0.15)


@T(HELM, 13)
def t_helm_values_file(c):
    path = pick(["values.yaml", "values-%s.yaml" % pick(ENVS), "charts/%s/values.yaml" % svc(), "deploy/helm/%s.values.yaml" % pick(ENVS)])
    c.hint = {"path": path}
    vals = helm_values(c)
    out = ydump(vals, li=True, qp=0.3)
    hdr = pick(["# Default values for %s.\n# This is a YAML-formatted file.\n" % svc(), "# Managed by platform team\n", ""])
    if chance(0.3):
        out += "\n# extraSecretEnv:\n#   API_TOKEN: %s" % helm_ph(c)
    return hdr + out


@T(HELM, 8)
def t_helm_template(c):
    rel = svc()
    ents = uniq([k8s_secret_entry(c, False) for _ in range(R.randint(1, 2))] + [k8s_plain_entry(c) for _ in range(R.randint(0, 2))])
    sec = {"apiVersion": "v1", "kind": "Secret",
           "metadata": {"name": "%s-secrets" % rel, "labels": {"app.kubernetes.io/instance": rel, "helm.sh/chart": "%s-%s" % (rel, version())}},
           "type": "Opaque", "data": {e[0]: e[1] for e in ents}}
    n, v = named(c)
    dep_env = [{"name": n, "value": v}, {"name": "DB_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "%s-secrets" % rel, "key": "password"}}}]
    dep = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": rel},
           "spec": {"template": {"metadata": {"annotations": {"checksum/secret": c.N("sha256")}},
                                 "spec": {"containers": [{"name": rel, "image": img_name() + "@" + c.N("docker_digest"), "env": dep_env}]}}}}
    c.hint = {"command": "helm template %s ./charts/%s -f values-%s.yaml" % (rel, rel, pick(ENVS))}
    return "---\n# Source: %s/templates/secret.yaml\n%s\n---\n# Source: %s/templates/deployment.yaml\n%s" % (
        rel, ydump(sec, li=True, qp=0.0), rel, ydump(dep, li=True, qp=0.0))


@T(HELM, 9)
def t_helm_install_set(c):
    rel = pick(["postgresql", "redis", "rabbitmq", "keycloak", "grafana", svc()])
    ns = pick(ENVS)
    sets = []
    sets.append("--set %s=%s" % (pick(["auth.postgresPassword", "auth.password", "adminPassword", "auth.rootPassword"]), shq(pwd(c))))
    if chance(0.6):
        sets.append("--set %s=%s" % (pick(["apiKey", "secrets.relay", "config.uplink", "license.key", "global.token"]), gsec(c)))
    if chance(0.3):
        sets.append("--set-string image.tag=%s" % c.N("short_sha"))
    cmd = "helm upgrade --install %s %s -n %s --create-namespace %s" % (rel, pick(["bitnami/" + rel, "oci://registry-1.docker.io/bitnamicharts/" + rel, "./chart"]), ns, " ".join(sets))
    c.hint = {"command": cmd}
    o = ["$ " + cmd] if chance(0.7) else []
    if not o:
        c.secrets.clear()
        c.kinds.clear()
        c.keep.clear()
    o += ["Release \"%s\" does not exist. Installing it now." % rel, "NAME: %s" % rel,
          "LAST DEPLOYED: %s" % dt().strftime("%a %b %d %H:%M:%S %Y"), "NAMESPACE: " + ns, "STATUS: deployed", "REVISION: 1",
          "TEST SUITE: None", "NOTES:", "CHART NAME: %s" % rel, "CHART VERSION: %s" % version(), "",
          "To get the password run:", "",
          "    export PASSWORD=%s" % c.K("$(kubectl get secret --namespace %s %s -o jsonpath=\"{.data.password}\" | base64 -d)" % (ns, rel))]
    return "\n".join(o)


@T(HELM, 7)
def t_helm_debug(c):
    rel, ns = svc(), pick(ENVS)
    cmd = "helm upgrade %s ./chart -n %s --dry-run --debug" % (rel, ns)
    c.hint = {"command": cmd}
    vals = helm_values(c, n_leaks=1)
    o = ["upgrade.go:%d: [debug] preparing upgrade for %s" % (R.randint(100, 200), rel),
         "upgrade.go:%d: [debug] performing update for %s" % (R.randint(100, 600), rel),
         "upgrade.go:%d: [debug] dry run for %s" % (R.randint(100, 600), rel), "NAME: " + rel,
         "LAST DEPLOYED: %s" % dt().strftime("%a %b %d %H:%M:%S %Y"), "NAMESPACE: " + ns, "STATUS: pending-upgrade",
         "REVISION: %d" % R.randint(2, 99), "USER-SUPPLIED VALUES:", ydump(vals, li=False, qp=0.1), "",
         "HOOKS:", "MANIFEST:"]
    return "\n".join(o)


@T(HELM, 7)
def t_helm_neg(c):
    k = R.randint(0, 2)
    if k == 0:
        c.hint = {"command": "helm list -A"}
        o = ["NAME            NAMESPACE   REVISION  UPDATED                                 STATUS    CHART                  APP VERSION"]
        for _ in range(R.randint(3, 6)):
            o.append("%-15s %-11s %-9d %s +0000 UTC  deployed  %s-%s   %s" % (svc(), pick(ENVS), R.randint(1, 80), dt(), svc(), version(), c.K(version())))
        return "\n".join(o)
    vals = {"auth": {"existingSecret": c.K("%s-db" % svc()), "password": helm_ph(c)},
            "image": {"repository": img_name(), "tag": c.N("short_sha"), "digest": c.N("docker_digest")},
            "podAnnotations": {"checksum/config": c.N("sha256")},
            "env": [{"name": n, "value": v} for n, v in [env_neg(c) for _ in range(R.randint(2, 4))]],
            "apiKey": helm_ph(c)}
    c.hint = {"command": "helm get values %s" % svc()} if k == 1 else {"path": "values.yaml"}
    out = ydump(vals, li=k != 1, qp=0.2)
    return ("USER-SUPPLIED VALUES:\n" + out) if k == 1 else out


# ======================================================================= terraform
def tf_pem(c, kind="tls_private_key_pem"):
    t, _, _ = private_key_any()
    body = t.split("\n", 1)[1].rsplit("\n", 1)[0]
    return t, body


def tf_attr_lines(pairs, ind, sign="+"):
    w = max(len(k) for k, _ in pairs)
    return ["%s%s %s = %s" % (" " * ind, sign, k.ljust(w), v) for k, v in pairs]


@T(TF, 16)
def t_tf_plan(c):
    o = []
    if chance(0.6):
        o += ["%s: Refreshing state... [id=%s]" % (pick(["aws_vpc.main", "aws_subnet.private[0]", "data.aws_caller_identity.current"]),
                                                   c.N("aws_res")) for _ in range(R.randint(1, 3))]
        o.append("")
    o += ["Terraform used the selected providers to generate the following execution plan. Resource actions are",
          "indicated with the following symbols:", "  + create", "  ~ update in-place", "",
          "Terraform will perform the following actions:", ""]
    nadd = nchg = 0
    blocks = R.sample(["db", "lambda", "ssm", "ecs", "userdata", "k8s", "iamkey"], R.randint(2, 3))
    for b in blocks:
        if b == "db":
            nadd += 1
            o += ['  # aws_db_instance.%s will be created' % svc(), '  + resource "aws_db_instance" "%s" {' % svc()]
            o += tf_attr_lines([("arn", "(known after apply)"), ("engine", '"postgres"'), ("identifier", '"%s-%s"' % (svc(), pick(ENVS))),
                                ("password", c.K("(sensitive value)")), ("username", '"%s"' % user())], 6)
            o.append("    }")
        elif b == "lambda":
            nchg += 1
            fn = "%s-handler" % svc()
            o += ['  # aws_lambda_function.%s will be updated in-place' % svc(), '  ~ resource "aws_lambda_function" "%s" {' % svc(),
                  '        id   = "%s"' % fn, "        # (18 unchanged attributes hidden)", "", "      ~ environment {",
                  "          ~ variables = {"]
            n, old = named(c, style=None)
            new = c.S(c.kinds[-1])
            o.append('              ~ "%s" = "%s" -> "%s"' % (n, old, new))
            n2, v2 = env_neg(c)
            o.append('                "%s" = "%s"' % (n2, v2))
            o += ["            }", "        }", "    }"]
        elif b == "ssm":
            nadd += 1
            o += ['  # aws_ssm_parameter.%s will be created' % svc(), '  + resource "aws_ssm_parameter" "%s" {' % svc()]
            o += tf_attr_lines([("arn", "(known after apply)"), ("name", '"/%s/%s/api_key"' % (pick(ENVS), svc())),
                                ("type", '"SecureString"'), ("value", "(sensitive value)"), ("key_id", '"%s"' % c.K(
                                    "arn:aws:kms:%s:%s:key/%s" % (pick(REGIONS), acct(), n_uuid())))], 6)
            o.append("    }")
        elif b == "ecs":
            nchg += 1
            o += ['  # aws_ecs_task_definition.app must be replaced', '-/+ resource "aws_ecs_task_definition" "app" {',
                  '      ~ arn                   = "%s" -> (known after apply)' % c.K(
                      "arn:aws:ecs:%s:%s:task-definition/%s:%d" % (pick(REGIONS), acct(), svc(), R.randint(2, 300))),
                  "      ~ container_definitions = jsonencode(", "          ~ [", "              ~ {",
                  "                  ~ environment = ["]
            n, v = named(c, url=True)
            o += ["                      + {", '                          + name  = "%s"' % n, '                          + value = "%s"' % v,
                  "                        },"]
            n2, v2 = env_neg(c)
            o += ["                        {", '                            name  = "%s"' % n2, '                            value = "%s"' % v2,
                  "                        },", "                    ]", '                  ~ image       = "%s:%s" -> "%s:%s"' % (
                      "app", c.N("short_sha"), "app", c.N("short_sha")),
                  "                    # (8 unchanged attributes hidden)", "                },", "            ]",
                  "        ) # forces replacement", "    }"]
        elif b == "userdata":
            nadd += 1
            pw = pwd(c)
            g = gsec(c)
            o += ['  # aws_instance.bastion will be created', '  + resource "aws_instance" "bastion" {',
                  '      + ami                    = "%s"' % c.N("aws_res"), '      + instance_type          = "t3.micro"',
                  "      + user_data              = <<-EOT", "            #!/bin/bash",
                  "            export DB_PASS='%s'" % pw, "            /opt/agent/install.sh --key %s" % g,
                  "        EOT", "    }"]
        elif b == "k8s":
            nadd += 1
            o += ['  # kubernetes_secret.app will be created', '  + resource "kubernetes_secret" "app" {',
                  "      + data = (sensitive value)", '      + id   = (known after apply)', '      + type = "Opaque"',
                  "      + metadata {", '          + name      = "%s-env"' % svc(), '          + namespace = "%s"' % pick(ENVS),
                  "        }", "    }"]
            c.K("(sensitive value)")
        else:
            nadd += 1
            o += ['  # aws_iam_access_key.ci will be created', '  + resource "aws_iam_access_key" "ci" {',
                  "      + id                             = (known after apply)",
                  "      + secret                         = (sensitive value)",
                  "      + ses_smtp_password_v4           = (sensitive value)", '      + user                           = "ci-%s"' % svc(),
                  "    }"]
            c.K("(sensitive value)")
    o += ["", "Plan: %d to add, %d to change, 0 to destroy." % (nadd, nchg)]
    cmd = "terraform plan" + pick(["", " -out=tfplan", " -var-file=%s.tfvars" % pick(ENVS)])
    if chance(0.25):
        p = pwd(c)
        cmd += " -var 'db_password=%s'" % p
        o.insert(0, "$ " + cmd)
    c.hint = {"command": cmd}
    return "\n".join(o)


@T(TF, 12)
def t_tf_output_json(c):
    outs = {}
    outs["db_endpoint"] = {"sensitive": False, "type": "string", "value": c.K("%s.c%s.%s.rds.amazonaws.com" % (svc(), rs(LALNUM, 12), pick(REGIONS)))}
    outs["db_password"] = {"sensitive": True, "type": "string", "value": pwd(c)}
    if chance(0.5):
        outs["ci_access_key_id"] = {"sensitive": False, "type": "string", "value": c.S("aws_access_key_id")}
        outs["ci_secret_access_key"] = {"sensitive": True, "type": "string", "value": c.S("aws_secret_access_key")}
    for _ in range(R.randint(1, 2)):
        nm = pick(["api_token", "relay_seed", "random_suffix_secret", "bootstrap", "signing_material", "edge_key", "uplink"])
        put(outs, nm, None)
        outs[nm] = {"sensitive": chance(0.7), "type": "string", "value": c.S(pk(0.7, 0.1))}
    if chance(0.35):
        t, body = tf_pem(c)
        c.enc_secret("tls_private_key_pem", jesc(body))
        outs["tls_private_key_pem"] = {"sensitive": True, "type": "string", "value": t + "\n"}
    outs["vpc_id"] = {"sensitive": False, "type": "string", "value": c.K("vpc-0" + rs(HEX, 16))}
    outs["role_arn"] = {"sensitive": False, "type": "string", "value": c.N("arn")}
    if chance(0.4):
        outs["subnet_ids"] = {"sensitive": False, "type": ["list", "string"], "value": [c.N("aws_res") for _ in range(2)]}
    c.hint = {"command": "terraform output -json"}
    return jd(dict(sorted(outs.items())))


@T(TF, 6)
def t_tf_output_text(c):
    k = R.randint(0, 1)
    if k == 0:
        nm = pick(["db_password", "admin_password", "api_token", "relay_seed"])
        v = pwd(c) if "password" in nm else gsec(c)
        cmd = "terraform output -raw " + nm
        c.hint = {"command": cmd}
        return v if chance(0.5) else "$ %s\n%s" % (cmd, v)
    c.hint = {"command": "terraform output"}
    lines = ['db_endpoint = "%s"' % c.K("%s-db.%s" % (svc(), dom())), "db_password = %s" % c.K("<sensitive>"),
             'vpc_id = "%s"' % c.K("vpc-0" + rs(HEX, 16)), 'cluster_name = "%s"' % pick(PROJECTS)]
    n = pick(["webhook_secret", "bootstrap_token", "relay_key", "service_token"])
    lines.append('%s = "%s"' % (n, c.S(pk(0.7, 0.0))))
    R.shuffle(lines)
    return "\n".join(sorted(lines))


@T(TF, 6)
def t_tf_state_show(c):
    k = R.randint(0, 1)
    if k == 0:
        c.hint = {"command": "terraform state show aws_iam_access_key.ci"}
        return "\n".join(['# aws_iam_access_key.ci:', 'resource "aws_iam_access_key" "ci" {',
                          '    create_date          = "%s"' % iso(), '    id                   = "%s"' % c.S("aws_access_key_id"),
                          '    secret               = (sensitive value)', '    ses_smtp_password_v4 = (sensitive value)',
                          '    status               = "Active"', '    user                 = "ci-%s"' % svc(), '}'])
    c.hint = {"command": "terraform state show random_password.db"}
    pw = G.pw_random()
    shown = chance(0.5)
    if shown:
        c.S("password_random", value=pw)
    return "\n".join(['# random_password.db:', 'resource "random_password" "db" {', '    bcrypt_hash      = (sensitive value)',
                      '    id               = "none"', '    length           = %d' % len(pw), '    lower            = true',
                      '    min_special      = 2', '    override_special = "!#%*+-=?^_~@&.,:"',
                      '    result           = "%s"' % pw if shown else '    result           = ' + c.K("(sensitive value)"), '}'])


@T(TF, 9)
def t_tf_state_pull(c):
    res = []
    akid = c.S("aws_access_key_id")
    res.append({"mode": "managed", "type": "aws_iam_access_key", "name": "ci", "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
                "instances": [{"schema_version": 0, "attributes": {"create_date": iso(), "encrypted_secret": None, "id": akid,
                                                                   "secret": c.S("aws_secret_access_key"),
                                                                   "ses_smtp_password_v4": c.S("aws_ses_smtp_password", value=rtok(B62 + "+/", 44)),
                                                                   "status": "Active", "user": "ci-" + svc()},
                               "sensitive_attributes": [[{"type": "get_attr", "value": "secret"}]]}]})
    if chance(0.7):
        pw = pwd(c)
        res.append({"mode": "managed", "type": "random_password", "name": "db", "provider": 'provider["registry.terraform.io/hashicorp/random"]',
                    "instances": [{"schema_version": 3, "attributes": {"id": "none", "length": 24, "result": pw, "special": True},
                                   "sensitive_attributes": []}]})
    if chance(0.5):
        res.append({"mode": "managed", "type": "aws_s3_bucket", "name": "logs", "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
                    "instances": [{"attributes": {"arn": c.N("arn"), "id": "%s-logs" % pick(PROJECTS),
                                                  "hosted_zone_id": c.K("Z" + rs(UALNUM, 13))}}]})
    st = {"version": 4, "terraform_version": "1.%d.%d" % (R.randint(5, 10), R.randint(0, 6)), "serial": R.randint(1, 900),
          "lineage": c.N("uuid"), "outputs": {}, "resources": res, "check_results": None}
    c.hint = {"command": pick(["terraform state pull", "cat terraform.tfstate"])}
    return jd(st)


@T(TF, 6)
def t_tf_apply(c):
    o = ["random_password.db: Creating...", "random_password.db: Creation complete after 0s [id=none]",
         "aws_secretsmanager_secret.db: Creating...",
         "aws_secretsmanager_secret.db: Creation complete after 1s [id=%s]" % c.N("arn"),
         "aws_instance.app: Creation complete after 32s [id=%s]" % c.N("aws_res"), "",
         "Apply complete! Resources: %d added, 0 changed, 0 destroyed." % R.randint(2, 9), "", "Outputs:", ""]
    outs = [('instance_id = "%s"' % c.N("aws_res")), "db_password = " + c.K("<sensitive>")]
    for _ in range(R.randint(1, 2)):
        nm = pick(["admin_token", "bootstrap_secret", "relay_seed", "grafana_admin_password", "uplink"])
        outs.append('%s = "%s"' % (nm, pwd(c) if "password" in nm else c.S(pk(0.7, 0.0))))
    o += sorted(outs)
    c.hint = {"command": "terraform apply -auto-approve"}
    return "\n".join(o)


@T(TF, 5)
def t_tf_neg(c):
    c.hint = {"command": "terraform plan"}
    o = ["aws_vpc.main: Refreshing state... [id=%s]" % c.K("vpc-0" + rs(HEX, 16)),
         "aws_iam_role.app: Refreshing state... [id=%s-role]" % svc(), "",
         "  # aws_db_instance.main will be updated in-place", '  ~ resource "aws_db_instance" "main" {',
         '        id       = "%s"' % c.K("db-" + rs(UALNUM, 26)), "      ~ password = %s" % c.K("(sensitive value)"),
         '      ~ tags     = {', '          ~ "commit" = "%s" -> "%s"' % (c.N("short_sha"), c.N("short_sha")), "        }",
         "        # (40 unchanged attributes hidden)", "    }", "",
         '  # aws_ssm_parameter.key will be updated in-place', '  ~ resource "aws_ssm_parameter" "key" {',
         '        arn   = "%s"' % c.N("arn"), '      ~ value = %s' % c.K("(sensitive value)"), "    }", "",
         "Plan: 0 to add, 2 to change, 0 to destroy.", "",
         "Changes to Outputs:", "  ~ db_password = %s" % c.K("(sensitive value)"), '  ~ image_digest = "%s" -> "%s"' % (c.N("docker_digest"), c.N("docker_digest"))]
    if chance(0.5):
        o.insert(0, 'Warning: Value for undeclared variable\n\nThe root module does not declare a variable named "api_key" but a value was found in file "%s.tfvars".' % pick(ENVS))
    return "\n".join(o)


# ======================================================================= git diff / log -p
GIT_FILES = [(".env", "env"), (".env.production", "env"), ("config/settings.yml", "yaml"), ("docker-compose.yml", "yaml"),
             ("deploy/values-prod.yaml", "yaml"), ("config/appsettings.json", "json"), ("config/default.json", "json"),
             ("src/main/resources/application.properties", "props"), ("infra/terraform.tfvars", "tfvars"),
             ("config.toml", "toml"), (".npmrc", "npmrc"), ("k8s/secret.yaml", "k8s")]


def gfmt(ft, name, val):
    if ft == "env":
        return "%s=%s" % (name, pick(['"%s"' % val, val]) if " " not in val else '"%s"' % val)
    if ft == "yaml":
        return "  %s: %s" % (snake(name), ys(val, 0.3))
    if ft == "json":
        return '    "%s": "%s",' % (camel(name), val)
    if ft == "props":
        return "%s=%s" % (name.lower().replace("_", "."), val)
    if ft in ("tfvars", "toml"):
        return '%s = "%s"' % (snake(name), val)
    if ft == "npmrc":
        return "%s=%s" % (name, val)
    return "  %s: %s" % (kebab(name), val)


def gsecret_pair(c, ft, url_ok=True):
    """Return (name, display, record_fn). For k8s files the value is base64."""
    if ft == "npmrc":
        if chance(0.6):
            return "//registry.npmjs.org/:_authToken", c.S("npm_token")
        return "//npm.pkg.github.com/:_authToken", c.S(pick(["github_pat", "generic_b62"]))
    if ft == "k8s":
        kind = pk(0.58, 0.15)
        disp, _, _ = raw(kind)
        return k8s_key_for(kind).upper().replace("-", "_"), c.enc_secret("k8s_secret_b64", b64s(disp))
    return named(c, url=url_ok and ft in ("env", "yaml", "props"), keepname=0.0)


def gneg_pair(c, ft):
    if ft == "npmrc":
        return pick([("registry", "https://registry.npmjs.org/"), ("@%s:registry" % pick(PROJECTS), "https://npm.pkg.github.com"),
                     ("always-auth", "true"), ("save-exact", "true")])
    if ft == "k8s":
        k, b, _, _ = k8s_plain_entry(c)
        return k.upper(), b
    return env_neg(c)


def hunk(c, ft, scenario):
    ctx_before = [gfmt(ft, *gneg_pair(c, ft)) for _ in range(R.randint(1, 3))]
    ctx_after = [gfmt(ft, *gneg_pair(c, ft)) for _ in range(R.randint(0, 2))]
    minus, plus = [], []
    if scenario == "add":
        for _ in range(R.randint(1, 2)):
            plus.append(gfmt(ft, *gsecret_pair(c, ft)))
        if chance(0.4):
            plus.append(gfmt(ft, *gneg_pair(c, ft)))
    elif scenario == "rotate":
        n, old = gsecret_pair(c, ft, url_ok=False)
        kind = c.kinds[-1]
        if ft == "k8s":
            disp, _, _ = raw(pick(GENERIC_KINDS + PASSWORD_KINDS))
            new = c.enc_secret("k8s_secret_b64", b64s(disp))
        elif ft == "npmrc":
            new = c.S(kind)
        else:
            new = c.S(kind)
        minus.append(gfmt(ft, n, old))
        plus.append(gfmt(ft, n, new))
    elif scenario == "scrub":
        n, old = gsecret_pair(c, ft, url_ok=False)
        ph = c.K(pick(["${%s}" % n.split("/")[-1].strip(":_").upper().replace(".", "_"), "<your-api-key>", "REPLACE_ME", "",
                       "changeme", "${{ secrets.%s }}" % pick(SECRET_REF_NAMES), "ENC[AES256_GCM,data:%s,type:str]" % "..."]) or "<redacted>")
        minus.append(gfmt(ft, n, old))
        plus.append(gfmt(ft, n, ph))
    else:  # neg: bump non-secret values
        n, v = gneg_pair(c, ft)
        minus.append(gfmt(ft, n, v))
        plus.append(gfmt(ft, n, c.N(pick(["short_sha", "docker_digest", "version", "git_sha"]))))
    a = R.randint(1, 60)
    old_n = len(ctx_before) + len(minus) + len(ctx_after)
    new_n = len(ctx_before) + len(plus) + len(ctx_after)
    head = "@@ -%d,%d +%d,%d @@%s" % (a, old_n, a, new_n, pick(["", "", " services:", " {", " [auth]"]))
    return [head] + [" " + l for l in ctx_before] + ["-" + l for l in minus] + ["+" + l for l in plus] + [" " + l for l in ctx_after]


def file_diff(c, scenario, f=None):
    path, ft = f or pick(GIT_FILES)
    o = ["diff --git a/%s b/%s" % (path, path)]
    if scenario == "add" and chance(0.25):
        o += ["new file mode 100644", "index 0000000..%s" % c.K(n_git_sha()[:7]), "--- /dev/null", "+++ b/" + path]
    else:
        o += ["index %s..%s 100644" % (c.K(rs(HEX, 7)), c.K(rs(HEX, 7))), "--- a/" + path, "+++ b/" + path]
    for _ in range(pick([1, 1, 2])):
        o += hunk(c, ft, scenario)
    return o


def commit_hdr(c, msg):
    who = pick(PEOPLE)
    d = dt()
    return ["commit " + c.N("git_sha") + pick(["", " (HEAD -> main, origin/main)", ""]),
            "Author: %s <%s>" % (who.capitalize(), email(who.replace("á", "a"))),
            "Date:   %s" % d.strftime("%a %b %d %H:%M:%S %Y +0000"), "", "    " + msg, ""]


MSGS = {"add": ["add sentry + db config", "wip: local config", "feat: wire up partner API", "chore: env for staging"],
        "rotate": ["chore: rotate staging credentials", "rotate keys after offboarding", "update tokens"],
        "scrub": ["fix: remove hardcoded token", "security: move secrets to env", "scrub credentials from config"],
        "neg": ["bump image digest", "chore(deps): update base image", "release %s" % version()]}


@T(GIT, 24)
def t_git_diff(c):
    sc = pick(["add", "add", "rotate", "scrub"])
    o = []
    for _ in range(pick([1, 1, 2])):
        o += file_diff(c, sc)
    staged = chance(0.3)
    c.hint = {"command": "git diff" + (" --cached" if staged else "")}
    return "\n".join(o)


@T(GIT, 17)
def t_git_log_p(c):
    o = []
    for i in range(R.randint(1, 3)):
        sc = pick(["add", "rotate", "scrub", "neg"]) if i else pick(["add", "rotate", "scrub"])
        o += commit_hdr(c, pick(MSGS[sc])) + file_diff(c, sc) + [""]
    c.hint = {"command": pick(["git log -p", "git log -p -- config/", "git log -p -3", "git log -p --all -S password"])}
    return "\n".join(o).rstrip()


@T(GIT, 9)
def t_git_show(c):
    sc = pick(["add", "rotate", "scrub"])
    sha = c.N("git_sha")
    o = ["commit " + sha, "Author: %s <%s>" % ("CI Bot", "ci@" + dom()), "Date:   %s" % dt().strftime("%a %b %d %H:%M:%S %Y +0000"),
         "", "    " + pick(MSGS[sc]), ""]
    if chance(0.4):
        o += ["    Reviewed-on: https://gitlab.%s/%s/%s/-/merge_requests/%d" % (dom(), pick(PROJECTS), svc(), R.randint(1, 900)),
              "    Change-Id: I%s" % c.N("git_sha"), ""]
    o += file_diff(c, sc)
    c.hint = {"command": "git show " + sha[:pick([7, 8, 12])]}
    return "\n".join(o)


@T(GIT, 9)
def t_git_neg(c):
    k = R.randint(0, 2)
    if k == 0:
        c.hint = {"command": "git log --oneline -n 10"}
        return "\n".join("%s %s" % (c.N("short_sha"), pick(sum(MSGS.values(), []) + ["fix flaky test", "docs: update README"]))
                         for _ in range(R.randint(4, 10)))
    if k == 1:
        c.hint = {"command": "git diff README.md"}
        ex1, ex2 = k_doc(c), k_doc(c)
        return "\n".join(["diff --git a/README.md b/README.md", "index %s..%s 100644" % (c.K(rs(HEX, 7)), c.K(rs(HEX, 7))),
                          "--- a/README.md", "+++ b/README.md", "@@ -40,6 +40,10 @@ ## Configuration",
                          " Set the following variables before running:", "+", "+```sh",
                          "+export API_KEY=%s" % ex1, "+export ALT_KEY=%s" % ex2, "+export DB_PASSWORD=%s" % c.K("<your-password>"), "+```",
                          " ", " See docs/deploy.md for details."])
    o = commit_hdr(c, pick(MSGS["neg"])) + file_diff(c, "neg")
    c.hint = {"command": "git log -p -1"}
    return "\n".join(o)


# ======================================================================= aws / gcloud / az
def asia():
    return "ASIA" + rs(B32, 16)


def sts_creds(c):
    return {"AccessKeyId": c.S("aws_access_key_id", value=asia()), "SecretAccessKey": c.S("aws_secret_access_key"),
            "SessionToken": c.S("aws_session_token"), "Expiration": iso().replace("Z", "+00:00")}


@T(CLOUD, 8)
def t_aws_sts(c):
    a = acct()
    role = "%s-%s" % (svc(), pick(["deploy", "admin", "readonly", "ci"]))
    sess = pick(["cli", "terraform", "botocore-session-%d" % epoch(), pick(PEOPLE).replace("á", "a")])
    k = R.randint(0, 2)
    if k == 2:
        cmd = "aws sts get-session-token --serial-number arn:aws:iam::%s:mfa/%s --token-code %06d" % (a, pick(PEOPLE).replace("á", "a"), R.randint(0, 999999))
        body = {"Credentials": sts_creds(c)}
    else:
        aroa = k_aroa(c)
        cmd = "aws sts assume-role --role-arn arn:aws:iam::%s:role/%s --role-session-name %s" % (a, role, sess)
        body = {"Credentials": sts_creds(c),
                "AssumedRoleUser": {"AssumedRoleId": "%s:%s" % (aroa, sess), "Arn": c.K("arn:aws:sts::%s:assumed-role/%s/%s" % (a, role, sess))}}
    c.hint = {"command": cmd + (" --output text" if k == 1 else "")}
    if k == 1:
        cr = body["Credentials"]
        au = body["AssumedRoleUser"]
        return "\n".join(["ASSUMEDROLEUSER\t%s\t%s" % (au["Arn"], au["AssumedRoleId"]),
                          "CREDENTIALS\t%s\t%s\t%s\t%s" % (cr["AccessKeyId"], cr["Expiration"], cr["SecretAccessKey"], cr["SessionToken"])])
    return json.dumps(body, indent=4)


@T(CLOUD, 5)
def t_aws_iam_key(c):
    u = "%s-%s" % (pick(["ci", "svc", "deploy"]), svc())
    c.hint = {"command": "aws iam create-access-key --user-name " + u}
    return json.dumps({"AccessKey": {"UserName": u, "AccessKeyId": c.S("aws_access_key_id"), "Status": "Active",
                                     "SecretAccessKey": c.S("aws_secret_access_key"), "CreateDate": iso().replace("Z", "+00:00")}}, indent=4)


@T(CLOUD, 4)
def t_aws_export(c):
    k = R.randint(0, 1)
    if k == 0:
        c.hint = {"command": "aws configure export-credentials --profile %s --format env" % pick(ENVS)}
        cr = sts_creds(c)
        return "\n".join(["export AWS_ACCESS_KEY_ID=" + cr["AccessKeyId"], "export AWS_SECRET_ACCESS_KEY=" + cr["SecretAccessKey"],
                          "export AWS_SESSION_TOKEN=" + cr["SessionToken"], "export AWS_CREDENTIAL_EXPIRATION=" + cr["Expiration"]])
    c.hint = {"command": "aws configure export-credentials --format process"}
    return json.dumps({"Version": 1, "AccessKeyId": c.S("aws_access_key_id"), "SecretAccessKey": c.S("aws_secret_access_key")}, indent=2)


@T(CLOUD, 6)
def t_aws_secrets(c):
    name = "%s/%s/%s" % (pick(ENVS), svc(), pick(["db", "api", "credentials", "config"]))
    rawout = chance(0.3)
    arn = "arn:aws:secretsmanager:%s:%s:secret:%s-%s" % (pick(REGIONS), acct(), name, rs(B62, 6))
    if chance(0.6):
        inner = {"username": user(), "password": pwd(c), "engine": "postgres", "host": c.K(host()), "port": 5432}
        if chance(0.4):
            inner[pick(["api_key", "relay_token", "seed"])] = gsec(c)
        ss = json.dumps(inner, separators=(",", ":"))
    else:
        ss = c.S(pk(0.6, 0.2))
    c.hint = {"command": "aws secretsmanager get-secret-value --secret-id " + name}
    if not rawout:
        body = {"ARN": c.K(arn), "Name": name, "VersionId": c.N("uuid"), "SecretString": ss, "VersionStages": ["AWSCURRENT"],
                "CreatedDate": "%d.%03d" % (epoch(), R.randint(0, 999))}
    else:
        c.hint = {"command": "aws secretsmanager get-secret-value --secret-id %s --query SecretString --output text" % name}
        return ss
    return json.dumps(body, indent=4)


@T(CLOUD, 5)
def t_aws_ssm_ecr(c):
    if chance(0.55):
        nm = "/%s/%s/%s" % (pick(ENVS), svc(), pick(["api_key", "db_password", "token", "seed", "license"]))
        v = pwd(c) if "password" in nm else c.S(pk(0.7, 0.0))
        c.hint = {"command": "aws ssm get-parameter --name %s --with-decryption" % nm}
        return json.dumps({"Parameter": {"Name": nm, "Type": "SecureString", "Value": v, "Version": R.randint(1, 20),
                                         "LastModifiedDate": "%d.%03d" % (epoch(), R.randint(0, 999)),
                                         "ARN": c.K("arn:aws:ssm:%s:%s:parameter%s" % (pick(REGIONS), acct(), nm)),
                                         "DataType": "text"}}, indent=4)
    tokj = json.dumps({"payload": b64(rb(R.randint(600, 900))), "datakey": b64(rb(180)), "version": "2", "type": "DATA_KEY",
                       "expiration": epoch()}, separators=(",", ":"))
    tok = c.S("ecr_token", value=b64s(tokj))
    reg = "%s.dkr.ecr.%s.amazonaws.com" % (acct(), pick(REGIONS))
    c.hint = {"command": "aws ecr get-login-password --region %s" % reg.split(".")[3]}
    return tok if chance(0.6) else "$ aws ecr get-login-password\n%s" % tok


def g_identity_token():
    now = epoch()
    return G.g_jwt("RS256", {"aud": "32555940559.apps.googleusercontent.com", "azp": n_google_client_id(), "email": email(),
                             "email_verified": True, "exp": now + 3600, "iat": now, "iss": "https://accounts.google.com",
                             "sub": str(R.randint(10 ** 20, 10 ** 21))})


@T(CLOUD, 6)
def t_gcloud_tokens(c):
    k = R.randint(0, 2)
    if k == 0:
        tok = c.S("google_oauth_access_token")
        cmd = pick(["gcloud auth print-access-token", "gcloud auth application-default print-access-token"])
        c.hint = {"command": cmd}
        return tok if chance(0.5) else "$ %s\n%s" % (cmd, tok)
    if k == 1:
        tok = c.S("jwt", value=g_identity_token())
        c.hint = {"command": "gcloud auth print-identity-token"}
        return tok
    c.hint = {"command": "gcloud config config-helper --format=json"}
    p = proj()
    return jd({"configuration": {"active_configuration": "default",
                                 "properties": {"compute": {"region": pick(GCP_REGIONS)}, "core": {"account": email(), "project": p}}},
               "credential": {"access_token": c.S("google_oauth_access_token"), "id_token": c.S("jwt", value=g_identity_token()),
                              "token_expiry": iso()},
               "sentinels": {"config_sentinel": "/home/%s/.config/gcloud/config_sentinel" % pick(PEOPLE).replace("á", "a")}})


@T(CLOUD, 5)
def t_gcloud_sakey(c):
    p = proj()
    sa = "%s@%s.iam.gserviceaccount.com" % (pick(["deployer", "terraform", "ci-runner", svc()]), p)
    kid = c.K(rs(HEX, 40))
    t2 = G.pem("PRIVATE KEY", G.der_pkcs8())
    body = t2.split("\n", 1)[1].rsplit("\n", 1)[0]
    c.enc_secret("gcp_service_account_key", jesc(body))
    d = {"type": "service_account", "project_id": p, "private_key_id": kid, "private_key": t2 + "\n", "client_email": sa,
         "client_id": c.K(str(R.randint(10 ** 20, 10 ** 21))), "auth_uri": "https://accounts.google.com/o/oauth2/auth",
         "token_uri": "https://oauth2.googleapis.com/token",
         "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
         "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/" + enc(sa), "universe_domain": "googleapis.com"}
    c.hint = {"command": "gcloud iam service-accounts keys create key.json --iam-account=%s && cat key.json" % sa}
    return "created key [%s] of type [json] as [key.json] for [%s]\n%s" % (kid, sa, jd(d))


@T(CLOUD, 4)
def t_gcloud_secret(c):
    if chance(0.5):
        nm = pick(["db-password", "api-key", "relay-seed", "%s-token" % svc()])
        v = pwd(c) if "password" in nm else c.S(pk(0.7, 0.0))
        c.hint = {"command": "gcloud secrets versions access latest --secret=%s" % nm}
        return v
    pw = pwd(c)
    inst = "%s-%s" % (pick(PROJECTS), pick(ENVS))
    cmd = "gcloud sql users set-password %s --instance=%s --password=%s" % (user(), inst, shq(pw))
    c.hint = {"command": cmd}
    return "$ %s\nUpdating Cloud SQL user...done." % cmd


@T(CLOUD, 6)
def t_az_sp(c):
    sub = n_uuid()
    tenant = c.N("uuid")
    app = c.N("uuid")
    nm = "%s-%s-sp" % (pick(PROJECTS), pick(ENVS))
    k = R.randint(0, 1)
    if k == 0:
        cmd = "az ad sp create-for-rbac --name %s --role Contributor --scopes /subscriptions/%s/resourceGroups/rg-%s" % (nm, c.K(sub), svc())
        pre = ["WARNING: Creating 'Contributor' role assignment under scope '/subscriptions/%s/resourceGroups/rg-%s'" % (sub, svc()),
               "WARNING: The output includes credentials that you must protect. Be sure that you do not include these credentials in your code or check the credentials into your source control. For more information, see https://aka.ms/azadsp-cli"]
        body = {"appId": app, "displayName": nm, "password": c.S("azure_client_secret"), "tenant": tenant}
    else:
        cmd = "az ad app credential reset --id %s --append" % app
        pre = ["WARNING: The output includes credentials that you must protect. Be sure that you do not include these credentials in your code or check the credentials into your source control. For more information, see https://aka.ms/azadsp-cli"]
        body = {"appId": app, "password": c.S("azure_client_secret"), "tenant": tenant}
    c.hint = {"command": cmd}
    return "\n".join(pre + [jd(body)])


@T(CLOUD, 5)
def t_az_token(c):
    tenant = n_uuid()
    now = epoch()
    jwt = G.g_jwt("RS256", {"aud": "https://management.azure.com/", "iss": "https://sts.windows.net/%s/" % tenant, "iat": now,
                            "nbf": now, "exp": now + 4000, "oid": n_uuid(), "tid": tenant, "upn": email(), "ver": "1.0"})
    c.S("azure_access_token", value=jwt)
    if chance(0.35):
        c.hint = {"command": "az account get-access-token --query accessToken -o tsv"}
        return jwt
    c.hint = {"command": "az account get-access-token"}
    return jd({"accessToken": jwt, "expiresOn": dt().strftime("%Y-%m-%d %H:%M:%S.000000"), "expires_on": now + 4000,
               "subscription": c.N("uuid"), "tenant": c.K(tenant), "tokenType": "Bearer"})


@T(CLOUD, 6)
def t_az_keys(c):
    k = R.randint(0, 3)
    acc = pick(PROJECTS) + pick(["store", "sa", "logs"]) + str(R.randint(1, 99))
    if k == 0:
        c.hint = {"command": "az storage account keys list -g rg-%s -n %s" % (svc(), acc)}
        return jd([{"creationTime": iso_ms(), "keyName": "key%d" % i, "permissions": "FULL", "value": c.S("azure_storage_key")}
                   for i in (1, 2)])
    if k == 1:
        c.hint = {"command": "az storage account show-connection-string -n %s" % acc}
        return jd({"connectionString": c.S("azure_storage_conn")})
    if k == 2:
        vault = "kv-%s-%s" % (pick(PROJECTS), pick(ENVS))
        nm = pick(["db-password", "api-key", "relay-seed", "signing-key"])
        c.hint = {"command": "az keyvault secret show --vault-name %s --name %s" % (vault, nm)}
        v = pwd(c) if "password" in nm else c.S(pk(0.7, 0.0))
        return jd({"attributes": {"created": iso().replace("Z", "+00:00"), "enabled": True, "recoveryLevel": "Recoverable+Purgeable"},
                   "contentType": None, "id": c.K("https://%s.vault.azure.net/secrets/%s/%s" % (vault, nm, rs(HEX, 32))),
                   "kid": None, "managed": None, "name": nm, "tags": {}, "value": v})
    reg = pick(PROJECTS) + "registry"
    c.hint = {"command": "az acr credential show -n " + reg}
    return jd({"passwords": [{"name": "password", "value": c.S("acr_password", value=rtok(B62 + "+/", 52))},
                             {"name": "password2", "value": c.S("acr_password", value=rtok(B62 + "+/", 52))}], "username": reg})


@T(CLOUD, 7)
def t_cloud_neg(c):
    k = R.randint(0, 4)
    if k == 0:
        a = acct()
        c.hint = {"command": "aws sts get-caller-identity"}
        return json.dumps({"UserId": k_aroa(c, pick(["AIDA", "AROA"])), "Account": c.K(a),
                           "Arn": c.K("arn:aws:iam::%s:user/%s" % (a, pick(PEOPLE).replace("á", "a")))}, indent=4)
    if k == 1:
        c.hint = {"command": "aws configure list"}
        return "\n".join(["      Name                    Value             Type    Location",
                          "      ----                    -----             ----    --------",
                          "   profile                <not set>             None    None",
                          "access_key     %s shared-credentials-file" % c.K("*" * 16 + rs(UALNUM, 4)),
                          "secret_key     %s shared-credentials-file" % c.K("*" * 16 + rs(B62, 4)),
                          "    region                %s      config-file    ~/.aws/config" % pick(REGIONS)])
    if k == 2:
        c.hint = {"command": "aws ec2 describe-instances --query 'Reservations[].Instances[].[InstanceId,ImageId,SubnetId]' --output text"}
        return "\n".join("%s\t%s\t%s" % (c.N("aws_res"), c.N("aws_res"), c.N("aws_res")) for _ in range(R.randint(2, 5)))
    if k == 3:
        c.hint = {"command": "az account show"}
        return jd({"environmentName": "AzureCloud", "id": c.N("uuid"), "isDefault": True, "name": "%s-%s" % (pick(PROJECTS), pick(ENVS)),
                   "state": "Enabled", "tenantId": c.N("uuid"), "user": {"name": email(), "type": "user"}})
    c.hint = {"command": "aws s3api head-object --bucket %s-assets --key app.js" % pick(PROJECTS)}
    return json.dumps({"AcceptRanges": "bytes", "LastModified": http_date(), "ContentLength": R.randint(100, 10 ** 6),
                       "ETag": jesc('"%s"' % c.K(rs(HEX, 32))), "VersionId": c.K(rtok(B62 + "._", 32)),
                       "ContentType": "application/javascript", "ServerSideEncryption": "AES256", "Metadata": {}}, indent=4)


# ======================================================================= main
ENCODED = {"basic_auth", "k8s_secret_b64", "docker_auth_b64", "b64_encoded_secret", "tls_key_b64", "kubeconfig_client_key"}
KEYMAT = {"tls_private_key_pem", "gcp_service_account_key"}
GENERICISH = {"session_cookie", "registry_token"}


def fam(k):
    if k in GENERIC or k in GENERICISH:
        return "generic"
    if k in PASSWORDS or k == "url_password":
        return "password"
    if k in ENCODED:
        return "encoded"
    if k in KEYMAT:
        return "keymat"
    return "vendor"


class Collide(Exception):
    pass


def finalize(c, text, idx):
    seen, secrets, kinds = set(), [], []
    for s, k in zip(c.secrets, c.kinds):
        if s in seen:
            continue
        seen.add(s)
        secrets.append(s)
        kinds.append(k)
    keep = []
    for k in c.keep:
        if k and k not in keep:
            keep.append(k)
    for v in secrets + keep:
        if v not in text:
            raise AssertionError("value not in text: ctx=%s val=%r\n---\n%s" % (c.context, v[:120], text[:3000]))
    for k in keep:
        for s in secrets:
            if k in s or s in k:
                raise Collide()
    rec = {"id": None, "kind": kinds[0] if kinds else "negative", "context": c.context, "text": text,
           "secrets": secrets, "keep": keep, "secret_kinds": kinds}
    if c.hint:
        rec["hint"] = c.hint
    return rec


def main():
    built, retries = [], 0
    for ctx, fn, n in TPL:
        for _ in range(n):
            for _attempt in range(50):
                c = C(ctx)
                try:
                    text = fn(c)
                    built.append(finalize(c, text, 0))
                    break
                except Collide:
                    retries += 1
            else:
                raise RuntimeError("could not build collision-free case for %s" % fn.__name__)
    R.shuffle(built)
    for i, r in enumerate(built):
        r["id"] = "devb-%04d" % (i + 1)
    # final global assertions
    for r in built:
        for v in r["secrets"] + r["keep"]:
            assert v in r["text"], (r["id"], v)
        for k in r["keep"]:
            for s in r["secrets"]:
                assert k not in s and s not in k, (r["id"], k, s)
    with io.TextIOWrapper(gzip.GzipFile(OUT, "wb", mtime=0), encoding="utf-8") as f:
        for r in built:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    n_sec = sum(len(r["secrets"]) for r in built)
    n_keep = sum(len(r["keep"]) for r in built)
    fams = collections.Counter(fam(k) for r in built for k in r["secret_kinds"])
    print("wrote %s  (collision retries: %d)" % (OUT, retries))
    print("cases=%d negative_cases=%d secrets=%d keep=%d kinds=%d" % (
        len(built), sum(1 for r in built if not r["secrets"]), n_sec, n_keep,
        len(set(k for r in built for k in r["secret_kinds"]))))
    print("families: " + ", ".join("%s=%d (%.0f%%)" % (f, fams[f], 100.0 * fams[f] / n_sec)
                                   for f in ["vendor", "generic", "password", "encoded", "keymat"]))
    print("%-10s %5s %4s %6s %5s %7s %7s %7s" % ("context", "cases", "neg", "secr", "keep", "generic", "passwd", "vendor"))
    by = collections.OrderedDict()
    for r in sorted(built, key=lambda r: r["context"]):
        d = by.setdefault(r["context"], collections.Counter())
        d["cases"] += 1
        d["neg"] += 0 if r["secrets"] else 1
        d["secr"] += len(r["secrets"])
        d["keep"] += len(r["keep"])
        for k in r["secret_kinds"]:
            d[fam(k)] += 1
    for ctx, d in by.items():
        print("%-10s %5d %4d %6d %5d %7d %7d %7d" % (ctx, d["cases"], d["neg"], d["secr"], d["keep"], d["generic"],
                                                     d["password"], d["vendor"]))
    if "--kinds" in sys.argv:
        print(collections.Counter(k for r in built for k in r["secret_kinds"]).most_common())


if __name__ == "__main__":
    main()
