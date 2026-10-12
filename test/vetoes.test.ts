/**
 * Each of the random layer's vetoes (unnamed.ts VETOES) rules out the samples its own comment names: a veto's regex
 * and the comment that says what it keeps can't drift apart. Each sample is a text, the candidate token in it, and
 * the reason that must be among the token's vetoes.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { Doc } from "../src/context.ts";
import { candidates, features, vetoes } from "../src/unnamed.ts";

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
	["data-name", '{"embedding": "Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te8S"}', "Kx9mQ2vL7pZrTq8Wn3Xc4Yb5Va6Ud7Te8S"],
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
];

/** Tokens a veto must not rule out: what looks like its case, but isn't. */
const NOT: [reason: string, text: string, token: string][] = [
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
	// Prefixed hex in a vendor client's arguments is judged as plain hex there is: a key.
	[
		"hex-suffix",
		'algoliasearch("APPID12345", "acme_9f86d081884c7d659a2feaa0c55ad015")',
		"acme_9f86d081884c7d659a2feaa0c55ad015",
	],
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
