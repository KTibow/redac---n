/**
 * Each of the random layer's vetoes (unnamed.ts VETOES) rules out the samples its own comment names: a veto's regex
 * and the comment that says what it keeps can't drift apart. Each sample is a text, the candidate token in it, and
 * the reason that must be among the token's vetoes.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { Doc } from "../src/context.ts";
import { candidates, features, vetoed, vetoes } from "../src/unnamed.ts";

// Lines of wrapped base64 (`base64 -w 64`, `fold -w 48`), and keys of their own lengths.
const [W64a, W64b, W44] = [
	"Vg1RWvyZpPEI5DHBG64pKamURbItXJ2SI9Cn0pLberAnYnsGTbVscQf9sIIWicaH",
	"EeExnVDOgfP83VuYrKUw3pOhY9FqGOgyNzecbx7hrbQwB4vi5psCjurUW69zBXat",
	"msNOhcEoYuH7eZVmetyoWTVJxQLlSnGtaQvDoD2oqole",
];
const [W48a, W48b, W48c] = [
	"ilNdXy8FLWjo9Fm3aIFVYNf1Ob0D8tZbplfHcYedgQqQDi4p",
	"rYfC4wWOwDjJrKF9ZlDjjUrvlyoxJBJVxCwoCATP3To4jJsv",
	"l2SXiIdbRRGXb05CXLwX7Bd01bfnjMWi39zsrR6mprODsBhd",
];
const [K40a, K40b, K56, K64, K68] = [
	"eotJOYulypay054dnn3KbTss1HpKMggOQD5zwLBE",
	"eOiMO6akx1Fbz2DhoHdipPwi4P7FZTRsty6xKPt7",
	"HME9YUjQ54QngwUwkkwJ7p1J9Y12Dg5I3KHZVdWo2aqxruVBwN5ru2vQ",
	"mSq4yvILSNX80CqzKlTipfzkxQQcUZpzr0c7nesCtNXrhUDYaa4JZLaVinD0UwKW",
	"YJBsFajqnT1ce7Ex8EwTrpeLAnaDoaecj7vXscd9xC4hbkiFZ9RgnaIyqNjU5vuUotTq",
];
const BLOB = `data:\n${W64a}\n${W64b}\n${W44}\n`;
const FOLDED = `$ base64 logo.bin | fold -w 48\n${W48a}\n${W48b}\n${W48c}\nCC15EtbXmINMRQqCxXdB\n`;

const SAMPLES: [reason: string, text: string, token: string][] = [
	["encrypted", "db_password: ENC[AES256_GCM,data:Qm9vVGhpc0lzQ2lwaGVydGV4dA9x,iv:", "Qm9vVGhpc0lzQ2lwaGVydGV4dA9x"],
	[
		"encrypted",
		"spring.datasource.password={cipher}9f8Kq2LmX7vR4tZpW1nB6yHc3JdE5sGa",
		"9f8Kq2LmX7vR4tZpW1nB6yHc3JdE5sGa",
	],
	[
		"encrypted",
		'app: "v1:Kx9mQ2vL7pZrTq8W:v1:Wn3Xc4Yb5Va6Ud7T:Te8Sf9Rg0Hh1Ij2Kk3Ll4Mm5Nn6Oo7Pp"',
		"Te8Sf9Rg0Hh1Ij2Kk3Ll4Mm5Nn6Oo7Pp",
	],
	[
		"analytics-cookie",
		"Cookie: __cf_bm=Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te8Sf9Rg; lang=en",
		"Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te8Sf9Rg",
	],
	["tracking-param", "https://www.amazon.com/dp/B0C1?pf_rd_r=Kx9mQ2vL7pZrTq8Wn3Xc&ref=x", "Kx9mQ2vL7pZrTq8Wn3Xc"],
	["aws-unique-id", '"RoleId": "AROAKX9MQ2VL7PZRTQ8WN"', "AROAKX9MQ2VL7PZRTQ8WN"],
	[
		"public-signature",
		"DKIM-Signature: v=1; a=rsa-sha256; d=example.fr;\n\ts=s1; bh=VfJAWBY9tjSinAgvlh++4kM+hzvZt0TrXJ3OryR3I0a=;\n\tb=MkS4BMShGaIqkBCF2fix6fPKtP8fFhWw34aG9/aaVCsRcp+TXb6X7ebLY9sq",
		"MkS4BMShGaIqkBCF2fix6fPKtP8fFhWw34aG9/aaVCsRcp+TXb6X7ebLY9sq",
	],
	[
		"public-id",
		'"atlassian-domain-verification=jhAVSJr3QEMfHOz0J4+9cqjgIvPzWKh616lx2pe7"',
		"jhAVSJr3QEMfHOz0J4+9cqjgIvPzWKh616lx2pe7",
	],
	[
		"public-signature",
		'{"thoughtSignature": "Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te8Sf9Rg0Hh1Ij2Kk3Ll4Mm5Nn6Oo7Pp8Qq"}',
		"Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te8Sf9Rg0Hh1Ij2Kk3Ll4Mm5Nn6Oo7Pp8Qq",
	],
	["id-name", '{"nextPageToken": "Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te8S"}', "Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te8S"],
	["id-name", '{"token_accessor": "Kx9mQ2vL7pZrTq8Wn3Xc4Yb5"}', "Kx9mQ2vL7pZrTq8Wn3Xc4Yb5"],
	["id-name", '{"userID": "Kx9mQ2vL7pZrTq8Wn3Xc4Yb5"}', "Kx9mQ2vL7pZrTq8Wn3Xc4Yb5"],
	[
		"encoded file",
		'<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk">',
		"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk",
	],
	// (A negative int64 field takes a varint's 10 bytes.)
	[
		"encoded message",
		'grpcurl -d \'{"page": "CP///////////wESC2hlbGxvIHdvcmxk"}\'',
		"CP///////////wESC2hlbGxvIHdvcmxk",
	],
	// (A float field is 4 bytes, fixed: field 1, then a string.)
	["encoded message", 'grpcurl -d \'{"page": "DQAAgD8SC2hlbGxvIHdvcmxk"}\'', "DQAAgD8SC2hlbGxvIHdvcmxk"],
	[
		"hashed-host",
		"|1|JfKTdBh7rNbXkVAQCRp4OQoPfmI=|USECr3SWf1JUPsms5AqfD5QfxkM= ssh-rsa AAAAB3NzaC1yc2E",
		"USECr3SWf1JUPsms5AqfD5QfxkM=",
	],
	[
		"hashed-host",
		"|1|+Xk9mQ2vL7pZrTq8Wn3Xc4Yb5Va=|USECr3SWf1JUPsms5AqfD5QfxkM= ssh-rsa",
		"Xk9mQ2vL7pZrTq8Wn3Xc4Yb5Va=",
	],
	["hex", "Thumbprint: 11F6AD8EC52A2984ABAAFD7C3B516503785C2072", "11F6AD8EC52A2984ABAAFD7C3B516503785C2072"],
	["slug", "see build-cache-x7k2-node for details", "build-cache-x7k2-node"],
	["identifier-shaped", "see build-cache-x7k2-node for details", "build-cache-x7k2-node"],
	["uuid", '"sessionId": "6f1c2b9e-3d4a-4e8f-9b7c-2a1d0e5f8c3b"', "6f1c2b9e-3d4a-4e8f-9b7c-2a1d0e5f8c3b"],
	["data-name", '{"embedding": "Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te8S"}', "Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te8S"],
	["repeating", "Key = ef012345ef012345ef012345ef012345", "ef012345ef012345ef012345ef012345"],
	[
		"ssh-public-key",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te8Sf9Rg0Hh1 me@host",
		"AAAAC3NzaC1lZDI1NTE5AAAAIKx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te8Sf9Rg0Hh1",
	],
	["callee", "EVP_PKEY_get1_DH(pkey)", "EVP_PKEY_get1_DH"],
	["callee", "the private key is x25519.X25519PrivateKey.from_private_bytes(raw)", "X25519PrivateKey"],
	["identifier-shaped", "H225_ArrayOf_CryptoH323Token", "H225_ArrayOf_CryptoH323Token"],
	[
		"hash-prefix",
		"P:openssl\nV:3.0.7-r0\nZ:Q1Uv35WBwtuePGrdxQuLDKbHVVTT4=\nF:etc/ssl/misc",
		"Q1Uv35WBwtuePGrdxQuLDKbHVVTT4=",
	],
	["hash-prefix", "+Z:Q1EfatjsUqKYSrqv18O1FlA3hcIHI=", "Q1EfatjsUqKYSrqv18O1FlA3hcIHI="],
	[
		"hash-prefix",
		"https://github.com/o/r/compare/a@4.20.0...a@4.20.1#diff-2b3c4f6a9e1d0c7b8a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3bR55",
		"diff-2b3c4f6a9e1d0c7b8a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3bR55",
	],
	[
		"public-id",
		'"node_id": "PRR_kwDOarJHIC7-6KbIAIl4ar3A", "state": "CHANGES_REQUESTED"',
		"PRR_kwDOarJHIC7-6KbIAIl4ar3A",
	],
	["public-id", '{"vpc_id": {"sensitive": false, "value": "vpc-0bddc3783c4aae5fc"}}', "vpc-0bddc3783c4aae5fc"],
	[
		"public-id",
		'{"image": "https://lh3.googleusercontent.com/tpBMFN5os8K-qXIHiAX5SZEmN5fCzIGrj9FdJtbZPUkC91ookSoY520NYn7fK5yq"}',
		"tpBMFN5os8K-qXIHiAX5SZEmN5fCzIGrj9FdJtbZPUkC91ookSoY520NYn7fK5yq",
	],
	["public-id", "gpg --recv-keys 7169605F62C751356D054A26A821E680E5FA6305", "7169605F62C751356D054A26A821E680E5FA6305"],
	["model-name", "ollama pull diffusiongemma-26B-A4B-it-GGUF", "diffusiongemma-26B-A4B-it-GGUF"],
	["number", "#define SEED 0x1f911b719147c712ull", "0x1f911b719147c712ull"],
	["local-part", "Message-ID: <CAOSkx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud@mail.gmail.com>", "CAOSkx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud"],
	[
		"local-part",
		"https://public-inbox.org/git/CAPig+kx9mQ2vL7pZrTq8Wn3Xc4Y=b5Va6UdTe8Sf9Rg@mail.gmail.com/t/",
		"CAPig+kx9mQ2vL7pZrTq8Wn3Xc4Y",
	],
	["local-part", '"to": "ExponentPushToken[Kx9mQ2vL7pZrTq8Wn3Xc4Y]"', "Kx9mQ2vL7pZrTq8Wn3Xc4Y"],
	[
		"sql-row",
		"INSERT INTO uploads (id, name) VALUES ('Kx9mQ2vL7pZrTq8Wn3Xc4Yb5', 'a.png');",
		"Kx9mQ2vL7pZrTq8Wn3Xc4Yb5",
	],
	[
		"sql-row",
		"INSERT INTO `uploads` (`id`, `name`) VALUES ('Kx9mQ2vL7pZrTq8Wn3Xc4Yb5', 'a.png');",
		"Kx9mQ2vL7pZrTq8Wn3Xc4Yb5",
	],
	["percent-fragment", "?next=%2Fdashboard%3Ftab%3DKx9mQ2vL7pZrTq8Wn3Xc4Yb5", "Kx9mQ2vL7pZrTq8Wn3Xc4Yb5"],
	[
		"resource-id",
		"/subscriptions/0b1f/resourceGroups/Kx9mQ2vL7pZrTq8Wn3Xc4Yb5/providers/Microsoft.Web",
		"Kx9mQ2vL7pZrTq8Wn3Xc4Yb5",
	],
	[
		"hostname",
		"https://kx9mq2vl7pzrtq8wn3xc4yb5.appsync-api.us-east-1.amazonaws.com/graphql",
		"kx9mq2vl7pzrtq8wn3xc4yb5",
	],
	[
		"public-browser-key",
		"posthog.init('Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te8Sf9Rg0Hh1Ij2', {api_host: x})",
		"Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te8Sf9Rg0Hh1Ij2",
	],
	["timestamp", "X-Amz-Date: 20240501T101500Z", "20240501T101500Z"],
	["words", "pip install qtquick3dphysics", "qtquick3dphysics"],
	["base64-text", "  greeting: dGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVy", "dGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVy"],
	// A wrapped blob's lines: at an encoder's width, its first and its shorter last; at another width, three in a row;
	// in escaped text, its lines broken by `\n`.
	["blob-line", BLOB, W64a],
	["blob-line", BLOB, W44],
	["blob-line", FOLDED, W48a],
	["blob-line", FOLDED, W48c],
	["blob-line", `resp = {'content': '${W64a}\\n${W64b}\\n${W44}\\n', 'encoding': 'base64'}`, W44],
	// A hash after its prefix: a pinned certificate's digest, a data URI's bytes, a go.sum hash whose base64 starts with
	// `//` (read past as a URL's `://`).
	[
		"hash-prefix",
		'<pin digest="SHA-256">aJMEfMoMJr7k+d9yETlywSrbhu2o0IdsvLdmMuHNkL4=</pin>',
		"aJMEfMoMJr7k+d9yETlywSrbhu2o0IdsvLdmMuHNkL4=",
	],
	[
		"hash-prefix",
		'<a href="data:application/octet-stream;base64,Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te8Sf9Rg0Hh1Ij2">',
		"Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te8Sf9Rg0Hh1Ij2",
	],
	[
		"hash-prefix",
		"golang.org/x/net v0.17.0 h1://Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te8Sf9Rg0Hh1I=",
		"Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te8Sf9Rg0Hh1I=",
	],
	// A security key's SSH public key, whose base64 names no algorithm the ssh-public-key veto reads.
	[
		"armored-public",
		"sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIKx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te8Sf9Rg0Hh1AAAABHNzaDo= me@host",
		"AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIKx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te8Sf9Rg0Hh1AAAABHNzaDo=",
	],
	// A path in a home directory's cache, though `$HOME` starts it.
	[
		"fs-path",
		"cp $HOME/.cache/huggingface/hub/Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te/config.json .",
		"Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te",
	],
	// IDs by what names them: a flag, prose ("Created job …"), a column's header above (a CSV's first line, a CLI's
	// table in capitals, Elasticsearch's lower-case one, a bar-separated one, a Markdown one).
	["id-name", "$ ./deploy.sh --run-id Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te", "Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te"],
	["id-name", "Created job Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te", "Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te"],
	[
		"id-name",
		"Exported users:\nid,name,plan\nxb6bxg56lral1qy9,Alyssa,pro\nq3J9vL7pZrTq8Wn3,Ben,free\n",
		"q3J9vL7pZrTq8Wn3",
	],
	[
		"id-name",
		"REPOSITORY   TAG       IMAGE ID                           SIZE\nweb          latest    Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te   120MB\n",
		"Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te",
	],
	[
		"name-identifier",
		"health status index    uuid                   pri rep\ngreen  open   logs-1   qG8y2nXkTzK3dL4mN5oP6Q   1   1\n",
		"qG8y2nXkTzK3dL4mN5oP6Q",
	],
	[
		"id-name",
		"|  Name      |  AppId                             |\n|  web       |  Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te  |\n",
		"Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te",
	],
	// (A Markdown table's cells needn't line up under their headers, and its rows above a token's can read as a header.)
	[
		"name-identifier",
		"| Service | ID |\n|---|---|\n| web | Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te |\n| api | Qm7pZrTq8Wn3Xc4Yb5Va6Ud7TeKx9mQ2 |\n",
		"Qm7pZrTq8Wn3Xc4Yb5Va6Ud7TeKx9mQ2",
	],
	[
		"name-hash",
		"| Test name | Commit |\n|---|---|\n| login | Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te |\n",
		"Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te",
	],
	// A JWK's public member wrapped onto the next line, as RFC examples print them.
	[
		"data-name",
		'{"kty": "RSA",\n "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc\n     BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v",\n "e": "AQAB"}',
		"BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v",
	],
	// A public key by the words before a bare `key`.
	["name-public", "Your public key: Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te", "Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te"],
	// Hex after a word prefix, under a name that mentions no credential; hex a digest's name follows.
	[
		"hex-suffix",
		"artifact: build-9f86d081884c7d659a2feaa0c55ad0159f86d081",
		"build-9f86d081884c7d659a2feaa0c55ad0159f86d081",
	],
	[
		"hex",
		"Here is the archive: 9f86d081884c7d659a2feaa0c55ad0159f86d081884c7d659a2feaa0c55ad015 (sha256)",
		"9f86d081884c7d659a2feaa0c55ad0159f86d081884c7d659a2feaa0c55ad015",
	],
	// A key shown cut short, its front before an ellipsis, a long vendor prefix's too.
	["placeholder", "ANTHROPIC_API_KEY=sk-ant-api03-Zx9K...", "sk-ant-api03-Zx9K"],
	["placeholder", "OPENAI_API_KEY=sk-proj-QmTxvRk9...", "sk-proj-QmTxvRk9"],
	// A cell of a command's table among counts and sizes: Elasticsearch's `_cat/indices`, `docker images`.
	[
		"table-row",
		"green open chunks-2026.10 z0JPk8Nk-z16-21STCuI2e 3 1 1820331 0 14.2gb 7.1gb",
		"z0JPk8Nk-z16-21STCuI2e",
	],
	["table-row", "yellow open logs Kx9mQ2vL7pZrTq8Wn3Xc4Y 1 1 52 0 1.1mb 1.1mb", "Kx9mQ2vL7pZrTq8Wn3Xc4Y"],
	// A static file's cache buster, in a page and in IIS's log.
	[
		"cache-buster",
		'<link href="/css/site.css?v=R1xcOGumKx9mQ2pLw7vRtZ8nB4cYd3HqT6uV1sWRUY7" />',
		"R1xcOGumKx9mQ2pLw7vRtZ8nB4cYd3HqT6uV1sWRUY7",
	],
	[
		"cache-buster",
		"2026-10-14 08:00:01 10.0.0.4 GET /css/site.css v=R1xcOGumKx9mQ2pLw7vRtZ8nB4cYd3HqT6uV1sWRUY7 443 - 10.0.0.9",
		"R1xcOGumKx9mQ2pLw7vRtZ8nB4cYd3HqT6uV1sWRUY7",
	],
	["cache-buster", '<script src="/js/app.min.js?ver=Kx9mQ2vL7pZrTq8Wn3Xc4Y"></script>', "Kx9mQ2vL7pZrTq8Wn3Xc4Y"],
	// The object a lookup is given.
	["lookup-id", '$s = ChargeBee\\Models\\Subscription::retrieve("b1AO9C0mWmtoh1Mlk");', "b1AO9C0mWmtoh1Mlk"],
	["lookup-id", 'const s = await stripe.subscriptions.retrieve("Kx9mQ2vL7pZrTq8Wn3Xc4Y");', "Kx9mQ2vL7pZrTq8Wn3Xc4Y"],
	["lookup-id", "user = User.objects.findById('Kx9mQ2vL7pZrTq8Wn3Xc4Y')", "Kx9mQ2vL7pZrTq8Wn3Xc4Y"],
	// IDs by their documented prefixes: WorkOS's and Clerk's organizations.
	["object-id", "organization: 'org_YWW51UBRXV18GF09IKVYQMG2PN',", "org_YWW51UBRXV18GF09IKVYQMG2PN"],
	// A name that says reference or organization says ID.
	["name-identifier", "pspReference=5V59S4TGC5KYYSDW&eventCode=AUTHORISATION", "5V59S4TGC5KYYSDW"],
	["name-hash", "SENTRY_RELEASE=63a66e12bb6436fe91488485a79d81f6f8966a55", "63a66e12bb6436fe91488485a79d81f6f8966a55"],
];

/** Tokens a veto must not rule out: what looks like its case, but isn't. */
const NOT: [reason: string, text: string, token: string][] = [
	// A password after a user and a colon, the URL's scheme left off, is no address's local part.
	["local-part", "export HTTPS_PROXY=svc:Kd8fQ2mZx9Lp4VnR7sTb3WyH@proxy.corp:8080", "Kd8fQ2mZx9Lp4VnR7sTb3WyH"],
	["local-part", "proxy = deploy:Kd8fQ2mZx9Lp4VnR7sTb3WyH@10.0.0.1:3128", "Kd8fQ2mZx9Lp4VnR7sTb3WyH"],
	// An RPC provider's key in its URL, after the API's version or in a key's parameter, near Solana's words.
	[
		"public-address",
		"RPC_URL=https://solana-devnet.g.alchemy.com/v2/QpDQ2eodexkZNDm3FHupsikXm4fjaPeY",
		"QpDQ2eodexkZNDm3FHupsikXm4fjaPeY",
	],
	[
		"public-address",
		"solana config set --url https://mainnet.helius-rpc.com/?api-key=QpDQ2eodexkZNDm3FHupsikXm4fjaPeY",
		"QpDQ2eodexkZNDm3FHupsikXm4fjaPeY",
	],
	// A hook's segment after a cloud resource starts a secret's path.
	[
		"resource-id",
		"curl -X POST https://ci.example.com/api/projects/42/webhooks/Kd8fQ2mZx9Lp4VnR7sTb3WyHq1Zx",
		"Kd8fQ2mZx9Lp4VnR7sTb3WyHq1Zx",
	],
	[
		"resource-id",
		"POST https://gitlab.example.com/api/v4/projects/7/trigger/Kd8fQ2mZx9Lp4VnR7sTb3WyHq1Zx",
		"Kd8fQ2mZx9Lp4VnR7sTb3WyHq1Zx",
	],
	// A request's target under a hook's segment, as an access log prints it, is a URL's path.
	[
		"fs-path",
		'10.0.0.5 - - [15/Oct/2026:10:00:00 +0000] "POST /hooks/Zk3vQ9xT2mLp7WnR4yUc8HbDq8Xk2LmN HTTP/1.1" 200 12',
		"Zk3vQ9xT2mLp7WnR4yUc8HbDq8Xk2LmN",
	],
	[
		"fs-path",
		'"POST /api/keys/Zk3vQ9xT2mLp7WnR4yUc8HbDq8Xk2LmN/rotate HTTP/1.1" 204',
		"Zk3vQ9xT2mLp7WnR4yUc8HbDq8Xk2LmN",
	],
	// Keys listed one per line under a handover are keys, though their widths match as a blob's lines do.
	[
		"blob-line",
		"Here are your new API keys:\nIhRIAJZE/PEO5pJ8eQjG6ZuJftA791osjvBiB7MCDfw=\nlXgCzYiAz6EwdnsyAatoWBPEVC2txVnt280dN9YDbMY=\nmxeXTdT/W94sA8J0TV/BoCf2PA8zVvnHoWu/+2fUSTY=",
		"mxeXTdT/W94sA8J0TV/BoCf2PA8zVvnHoWu/+2fUSTY=",
	],
	// A table's row with a credential's word on it, or too few counts; a cache buster's name on no static file; a lookup
	// of a secret.
	["table-row", "prod api_key Kx9mQ2vL7pZrTq8Wn3Xc4Y 3 1 52 0 1.1mb", "Kx9mQ2vL7pZrTq8Wn3Xc4Y"],
	["table-row", "web deploy Kx9mQ2vL7pZrTq8Wn3Xc4Y running alice prod", "Kx9mQ2vL7pZrTq8Wn3Xc4Y"],
	["cache-buster", "https://api.acme.io/v1/export?v=Kx9mQ2vL7pZrTq8Wn3Xc4Y", "Kx9mQ2vL7pZrTq8Wn3Xc4Y"],
	["lookup-id", 'secret = client.secrets.fetch("Kx9mQ2vL7pZrTq8Wn3Xc4Y")', "Kx9mQ2vL7pZrTq8Wn3Xc4Y"],
	["lookup-id", 'const c = new Client("Kx9mQ2vL7pZrTq8Wn3Xc4Y")', "Kx9mQ2vL7pZrTq8Wn3Xc4Y"],
	// A plural that is a hook's is no collection.
	["collection-id", "curl https://api.acme.io/v1/api-keys/Kx9mQ2vL7pZrTq8Wn3Xc4Y", "Kx9mQ2vL7pZrTq8Wn3Xc4Y"],
	// A key encoded twice decodes to a token, not text, though its base64 has a slash.
	[
		"base64-text",
		"  feed-access: RHhFUVNWZy8wTTJvL1M5cW9QR2Z4aEtkL1RKaTdheUJxdWx5ZUZkZ3F6TT0=",
		"RHhFUVNWZy8wTTJvL1M5cW9QR2Z4aEtkL1RKaTdheUJxdWx5ZUZkZ3F6TT0=",
	],
	// A URL's userinfo is a password or a token, not an email's local part.
	["local-part", "git clone https://oauth2:kT9xQ2mZpL4vRw8nBc3JeH7s@gitlab.com/x.git", "kT9xQ2mZpL4vRw8nBc3JeH7s"],
	["local-part", "git push https://kT9xQ2mZpL4vRw8nBc3JeH7s@github.com/o/r.git", "kT9xQ2mZpL4vRw8nBc3JeH7s"],
	["local-part", "git push https://kT9xQ2mZpL4vRw8nBc3JeH7s=x9@github.com/o/r.git", "kT9xQ2mZpL4vRw8nBc3JeH7s"],
	// Only a bare `key` names an object or a cache key; a `token` or a `secret` names a credential.
	["bare-key-hash", "token=acme_9f86d081884c7d659a2feaa0c55ad015", "acme_9f86d081884c7d659a2feaa0c55ad015"],
	[
		"bare-key-hash",
		"# cache\nsecret=9f86d081884c7d659a2feaa0c55ad0159f86d081884c7d659a2feaa0c55ad015",
		"9f86d081884c7d659a2feaa0c55ad0159f86d081884c7d659a2feaa0c55ad015",
	],
	["bare-key-hash", "Here is your key: acme_9f86d081884c7d659a2feaa0c55ad015", "acme_9f86d081884c7d659a2feaa0c55ad015"],
	// The unit repeated is short: a key written twice is a key.
	[
		"repeating",
		"Key = 9f86d081884c7d659a2feaa0c55ad0159f86d081884c7d659a2feaa0c55ad015",
		"9f86d081884c7d659a2feaa0c55ad0159f86d081884c7d659a2feaa0c55ad015",
	],
	// Prefixed hex in a vendor client's arguments is judged as plain hex there is: a key.
	[
		"hex-suffix",
		'algoliasearch("APPID12345", "acme_9f86d081884c7d659a2feaa0c55ad015")',
		"acme_9f86d081884c7d659a2feaa0c55ad015",
	],
	// Keys listed one per line have their own lengths: two of one length, a longer after a shorter, one at an
	// encoder's width beside one past it. Nor is a line that holds more than base64, beside a blob.
	["blob-line", `Keys:\n${K40a}\n${K40b}\n`, K40a],
	["blob-line", `Keys:\n${K40a}\n${K40b}\n`, K40b],
	["blob-line", `Keys:\n${K56}\n${W44}\n`, W44],
	["blob-line", `Keys:\n${K64}\n${K68}\n`, K64],
	["blob-line", `Keys:\n${K64}\n${K68}\n`, K68],
	["blob-line", `${W64a}\n$ ./notify.sh prod ${K40a}\n`, K40a],
	// A token after an SQL row is in no cell of it.
	[
		"sql-row",
		"sqlite> INSERT INTO uploads (id, name) VALUES ('k3j9x', 'a.png');\nsqlite> .quit\n$ ./notify.sh prod Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te\n",
		"Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te",
	],
	// An HTTP header, in HTTP/2's lower case too, is a key's place: a cuid's shape says nothing there.
	["cuid", "x-lumen: clx8kuby80001k9x2m4q8w5e7", "clx8kuby80001k9x2m4q8w5e7"],
	// A REST path without a leading slash is no file's path; a host's label before its TLD is no file name.
	[
		"fs-path",
		"gh api repos/acme/web/actions/secrets/Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te",
		"Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te",
	],
	["filename", "curl https://Kx9mQ2vL7pZrTq8Wn3Xc4Yb5.io/v1/ping", "Kx9mQ2vL7pZrTq8Wn3Xc4Yb5"],
	// A value with more after it on its line labels no PEM block below.
	[
		"block-label",
		"passphrase: Kx9mQ2-vL7pZr-Tq8Wn3  # for the key below\n-----BEGIN ENCRYPTED PRIVATE KEY-----\n",
		"Kx9mQ2-vL7pZr-Tq8Wn3",
	],
	// A table's header names no line after the table ends (a blank line, a line without bars).
	[
		"id-name",
		"| Service | ID |\n|---|---|\n| web | 1 |\n\n$ echo ok | ./notify.sh Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te\n",
		"Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te",
	],
	[
		"name-identifier",
		"IMAGE ID       SIZE\nab12cd34       120MB\n\nKx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te\n",
		"Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te",
	],
	[
		"id-name",
		"| ID | Service |\n|---|---|\n| 1 | web |\nKx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te\n",
		"Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te",
	],
	// A credential's ID by its phrase: Vault AppRole's secret ID.
	["id-name", "The secret id: Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te", "Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te"],
	// Only after `|1|` is a value of a SHA-1's size a hashed host.
	[
		"hashed-host",
		"curl -H 'X-Lumen: JfKTdBh7rNbXkVAQCRp4OQoPfmI=' https://api.lumen.dev",
		"JfKTdBh7rNbXkVAQCRp4OQoPfmI=",
	],
	// A credential's name outvotes what a token's shape or its place says.
	["identifier-shaped", 'api_key: "Kx9-mQ2-vL7-pZr-Tq8-Wn3"', "Kx9-mQ2-vL7-pZr-Tq8-Wn3"],
	["slug", 'password: "kx9q-tw3v-pz2m-rr8n-lb4c"', "kx9q-tw3v-pz2m-rr8n-lb4c"],
	["filename", 'session_token = "Kx9mQ2vL7pZrTq8Wn3Xc4Yb5.Va6Ud7.Te8Sf9Rg0Hh1Ij2Kk3"', "Kx9mQ2vL7pZrTq8Wn3Xc4Yb5"],
	["uuid", '"session_id": "Kx9mQ2vL7pZrTq8Wn3Xc4Yb5"', "Kx9mQ2vL7pZrTq8Wn3Xc4Yb5"],
	["cuid2", "secret_id=kx9mq2vl7pzrtq8wn3xc4yb5", "kx9mq2vl7pzrtq8wn3xc4yb5"],
	["base64-text", "password: dGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVy", "dGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVy"],
	// Bytes that only start like a message: a field past any schema's numbers, a key that never ends (five bytes with
	// the high bit), a field of binary bytes (a printable run in random bytes isn't text).
	["encoded message", 'grpcurl -d \'{"page": "wj4MaGVsbG8gd29ybGQh"}\'', "wj4MaGVsbG8gd29ybGQh"],
	["encoded message", 'grpcurl -d \'{"page": "//////8ACgxoZWxsbyB3b3JsZCE="}\'', "//////8ACgxoZWxsbyB3b3JsZCE="],
	["encoded message", 'grpcurl -d \'{"page": "Cg0A//79/Pv6+fhhYmNk"}\'', "Cg0A//79/Pv6+fhhYmNk"],
];

test("each veto rules out the samples its comment names", () => {
	const wrong: string[] = [];
	for (const [reason, text, token] of SAMPLES) {
		const doc = new Doc(text);
		const c = candidates(text).find((c) => c.token === token);
		const reasons = c ? vetoes(features(doc, c, false)) : [];
		if (!reasons.includes(reason))
			wrong.push(
				`${reason}: ${token} in ${JSON.stringify(text)} → ${
					c
						? reasons.join(", ") || "no veto"
						: `not a candidate (${candidates(text)
								.map((c) => c.token)
								.join(" ")})`
				}`,
			);
	}
	assert.deepEqual(wrong, []);
});

test("a veto leaves alone what only looks like its case", () => {
	const wrong: string[] = [];
	for (const [reason, text, token] of NOT) {
		const c = candidates(text).find((c) => c.token === token);
		if (c && vetoes(features(new Doc(text), c, false)).includes(reason)) wrong.push(`${reason}: ${token}`);
	}
	assert.deepEqual(wrong, []);
});

test("without the statistical vetoes, a token ruled out only by its look is left to the model", () => {
	const text = "see build-cache-x7k2-node for details";
	const f = features(new Doc(text), candidates(text)[0], false);
	assert.ok(vetoed(f));
	assert.equal(vetoed(f, { statistical: false }), undefined);
});
