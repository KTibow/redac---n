/**
 * The value gates against generated secrets: every shape that rules a value out (values.ts INERT_SHAPES, code, benign
 * values, placeholders) must reject random passwords and keys from every generator of the recall fuzz
 * (eval/fuzz-secrets.ts). A shape that a random value can satisfy by chance (a leading `:` or `@`, `%i` inside it,
 * `Fake` in the middle of it) fails here, named, before it leaks somewhere in the pipeline. And what the gates keep:
 * hashes, public keys, addresses, stand-ins.
 */
import assert from "node:assert/strict";
import { createHmac, generateKeyPairSync, sign } from "node:crypto";
import { test } from "node:test";
import { GENERATORS, seed } from "../eval/fuzz-secrets.ts";
import { isBech32Address } from "../src/checksums.ts";
import { Redactor } from "../src/index.ts";
import { isPlaceholder, isPublicJwt } from "../src/public.ts";
import { isDerCertificate, isDerPublicKey, isDerSignature, isPgpPublicKey, isRsaPublicKey } from "../src/publickeys.ts";
import { alphabetOf, shape } from "../src/random.ts";
import {
	inertShape,
	isBalanced,
	isBenignValue,
	isCode,
	isIdentifierShaped,
	isPasswordHash,
	isPath,
	isPodName,
	isRandomToken,
	isWordy,
	looksSecret,
} from "../src/values.ts";
import { hidden, kept, r } from "./helpers.ts";
import { randomBytes } from "./random.ts";

// (A person's phrase is shaped like an identifier, `Lambda-Lunar:join` like `acme-prod-2024`: only a password's name tells
// them apart, which the fuzz tries.)
test("no value gate accepts a generated secret", () => {
	seed(7);
	const hits = new Map<string, string[]>();
	for (const [gen, make] of Object.entries(GENERATORS)) {
		for (let i = 0; i < 10_000; i++) {
			const v = make();
			const gate =
				inertShape(v) ??
				(isCode(v, true)
					? "code"
					: isBenignValue(v)
						? "benign"
						: isPlaceholder(v)
							? "placeholder"
							: !looksSecret(v, true)
								? "not secret-looking"
								: !["phrase", "marked", "codelike"].includes(gen) && isIdentifierShaped(v)
									? "identifier-shaped"
									: undefined);
			if (gate) hits.set(`${gen}: ${gate}`, [...(hits.get(`${gen}: ${gate}`) ?? []), v]);
		}
	}
	assert.equal(
		hits.size,
		0,
		[...hits]
			.map(
				([k, vs]) =>
					`${k} (${vs.length}) ${vs
						.slice(0, 3)
						.map((v) => JSON.stringify(v))
						.join(" ")}`,
			)
			.join("\n"),
	);
});

test("every inert shape takes its own kind: references, masks, templates, public values", () => {
	const pkcs1 = generateKeyPairSync("rsa", { modulusLength: 1024 })
		.publicKey.export({ type: "pkcs1", format: "der" })
		.toString("base64");
	for (const v of [
		// Variables: shell's positional and named, Windows's, PHP's.
		"$1",
		"$DB_PASS2",
		"%SqlAdminPassword%",
		"%DB_PASSWORD%",
		"{$pwd}",
		"$this->passwd",
		"{$cfg['db']['pass']}",
		// References: names in brackets (short ones plain), a path of them, a secret's ARN, a cut interpolation, a
		// Nutanix Calm macro.
		"[PW]",
		"{db}",
		"<SecretsManager:prod/db/password>",
		"arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf",
		"${config.db",
		"@@{PostgresService.address}@@",
		// Masks and stand-ins.
		"***1234",
		"ab****yz",
		"$encrypted$",
		"xxxx1234",
		"sk-ant-xxxxx",
		"api-key-****",
		"sk-proj-abc...xyz",
		"ChangeMe123",
		// Templates.
		"db-%s-password",
		"%s_Password",
		"key%d.pem",
		// A secret listing's metadata.
		"2024-05-01T10:00:00Z",
		"Secret{name=db}",
		// Public identifiers and keys.
		"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
		"QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",
		"bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
		"npub1sg6plzptd64u62a878hep2kev88swjh3tw00gjsfl8f237lmu63q0uf63m",
		"S-1-5-21-3623811015-3361044348-30300820-1013",
		"1:123456789012:web:3f2a1b0c9d8e7f6a",
		"<CAJ1x2+abc=def@mail.gmail.com>",
		"0x3f2a1b0c",
		pkcs1,
		"MEUCIDeJz1xqWtFp7jUnMWW8R3aKb8IA+kgE07DhGQBjl6vsAiEAnpt+dlhD5BDjKSgcyQQT35sxJNe0RIXkTve2XTPcd0I=",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPUPzyFlRaik/Mg76607/G/bKQk2nGpBRREEdPMVg1DT deploy@ci",
		"test test test test test test test test test test test junk",
	])
		assert.ok(inertShape(v), v);
	// (Docker Compose's escape holds a name: `$${DB_PASS}`, not `$${Xk9mQ2vL}`.)
	assert.equal(inertShape("$${DB_PASS}"), "escaped variable");
	assert.equal(inertShape("$${Xk9mQ2vL}"), undefined);
});

test("a wordy value is words, numbers and short IDs in a word's case", () => {
	// (A long word with a digit reads oddly to the model, but its case doesn't flip as a generator's does.)
	for (const v of [
		"prod-nginxingress2-logs",
		"PROD_CLOUDWATCHLOGS2_EXPORT",
		"deploy-myServiceAccountNameForUploads",
		"GitHub-Actions-2024",
		"iPhone-build-2024",
		"münchen-prod-2024",
		"MÜNCHEN-STAGING",
	])
		assert.ok(isWordy(v), v);
	for (const v of ["prod-hqArruGhkoRtvpQplEac-2024", "acme-prod-XkPqWm9-2024"]) assert.ok(!isWordy(v), v);
});

test("a path is names a person gave, with no segment a generator made", () => {
	for (const v of [
		"certs/dev-key.pem",
		"/var/lib/myApp2/data",
		"/Library/macOS/keys",
		"./src/utils/getIdOf.ts",
		"./node_modules/XMLHttpRequest/lib",
		"/srv/{app}/logs",
	])
		assert.ok(isPath(v), v);
	for (const v of ["/srv/{4}/x", "/Summer2024", "/home/me/Tv$-ycX.K9+/key", "/s/Xk9mQ", "/NKR7uXt0UfYN9/"])
		assert.ok(!isPath(v), v);
});

test("public keys are recognised by structure, and private keys and random base64 aren't", () => {
	// SubjectPublicKeyInfo prefixes from `openssl pkey -pubout` (RSA, P-384, Ed25519, X25519); PKCS #8 and PKCS #1 private keys.
	for (const pub of [
		"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC",
		"MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEWjawrhMY",
		"MCowBQYDK2VwAyEASnZI8OdJjHCx2uFQ4kQXEjcT",
		"MCowBQYDK2VuAyEAq9X3J62JV0XiqutjddwDou3r",
	])
		assert.ok(isDerPublicKey(pub), pub);
	for (const priv of [
		"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj",
		"MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGb",
		"MC4CAQAwBQYDK2VwBCIEIGgLKVifQEFYw6VB6CRl",
		"MIICXQIBAAKBgQDF3QM26NYCoYbG/vNugxGLPbtd",
	])
		assert.ok(!isDerPublicKey(priv) && !isDerCertificate(priv), priv);
	// X.509 certificates' prefixes (ISRG Root X1's, an RSA certificate's with a 4-byte serial), not a public key's.
	for (const cert of [
		"MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw",
		"MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ",
	])
		assert.ok(isDerCertificate(cert) && !isDerPublicKey(cert), cert);
	assert.ok(!isDerCertificate("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC"));
	// OpenPGP: an old-format RSA 2048 key packet (`mQENB…`, as `gpg --export --armor` writes), a new-format Ed25519 one,
	// and a secret key packet (tag 5), a v4 RSA packet whose modulus doesn't start at its stated size and one whose length
	// isn't its fields'.
	const packet = (...bytes: number[]) => Buffer.from([...bytes, ...new Array(24).fill(0x5a)]).toString("base64");
	const time = [0x5f, 0x00, 0x00, 0x00];
	assert.ok(isPgpPublicKey(packet(0x99, 0x01, 0x0d, 0x04, ...time, 0x01, 0x08, 0x00, 0xc3)));
	assert.ok(
		isPgpPublicKey(
			packet(0xc6, 0x33, 0x04, ...time, 0x16, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01, 0x01, 0x07),
		),
	);
	assert.ok(!isPgpPublicKey(packet(0x95, 0x01, 0xd8, 0x04, ...time, 0x01, 0x08, 0x00, 0xc3)));
	assert.ok(!isPgpPublicKey(packet(0x99, 0x01, 0x0d, 0x04, ...time, 0x01, 0x08, 0x00, 0x43)));
	assert.ok(!isPgpPublicKey(packet(0x99, 0x01, 0x2d, 0x04, ...time, 0x01, 0x08, 0x00, 0xc3)));
	assert.ok(!isPgpPublicKey("mJMGzFqZ0RwWjxj6LkosHlPd0vlw9r677d56j1PT"));
	assert.ok(isPgpPublicKey("mQENBFXbjPUBCADjNjCUQwfxKL+RR2GA6pv/1K+zJZ8UWIF9S0lk7cVIEfJiprzzwiMw"));
	seed(11);
	for (const [gen, make] of Object.entries(GENERATORS)) {
		for (let i = 0; i < 30_000; i++) {
			const v = make();
			assert.ok(!isDerPublicKey(v) && !isDerCertificate(v) && !isPgpPublicKey(v), `${gen}: ${v}`);
		}
	}
});

test("a public key's or a signature's structure is read field by field: one field off and it isn't one", () => {
	const der = (b64: string, edit: (b: Buffer) => void) => {
		const b = Buffer.from(b64, "base64");
		edit(b);
		return b.toString("base64");
	};
	// A P-256 SubjectPublicKeyInfo; with its AlgorithmIdentifier a SET. An encrypted PKCS #8 private key opens with a
	// SEQUENCE and an OID too, PBES2's.
	const spki = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWjawrhMY";
	assert.ok(isDerPublicKey(spki));
	assert.ok(!isDerPublicKey(der(spki, (b) => (b[2] = 0x31))));
	const encrypted = generateKeyPairSync("ec", {
		namedCurve: "P-256",
		publicKeyEncoding: { type: "spki", format: "der" },
		privateKeyEncoding: { type: "pkcs8", format: "der", cipher: "aes-256-cbc", passphrase: "x" },
	}).privateKey.toString("base64");
	assert.ok(!isDerPublicKey(encrypted), encrypted);
	// A PKCS #1 RSAPublicKey; with its modulus a BIT STRING, or of a length no DER writes.
	const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
	const rsa = publicKey.export({ type: "pkcs1", format: "der" }).toString("base64");
	assert.ok(isRsaPublicKey(rsa));
	assert.ok(!isRsaPublicKey(der(rsa, (b) => (b[4] = 0x03))));
	assert.ok(!isRsaPublicKey(der(rsa, (b) => (b[5] = 0x85))));
	// An ECDSA signature, DER; with its SEQUENCE's length one more than its INTEGERs'.
	const signature = sign(
		"sha256",
		Buffer.from("x"),
		generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey,
	).toString("base64");
	assert.ok(isDerSignature(signature), signature);
	assert.ok(!isDerSignature(der(signature, (b) => b[1]++)));
	// OpenPGP: a public subkey packet (tag 14); a version 3 key packet.
	const time = [0x5f, 0x00, 0x00, 0x00];
	const packet = (...bytes: number[]) => Buffer.from([...bytes, ...new Array(24).fill(0x5a)]).toString("base64");
	assert.ok(isPgpPublicKey(packet(0xb9, 0x01, 0x0d, 0x04, ...time, 0x01, 0x08, 0x00, 0xc3)));
	assert.ok(!isPgpPublicKey(packet(0x99, 0x01, 0x0d, 0x03, ...time, 0x01, 0x08, 0x00, 0xc3)));
});

test("a password hash is recognised whole, not by how it starts", () => {
	for (const hash of [
		"$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW",
		"$6$rounds=5000$saltsalt$1tySNNgq6Honi21SstQhFBZIa4TOpuhR6v7fJtbxWwEy6BU3rZRVNtB.144R0..s/NUKKimOuL4AFnrIBJcFA0",
		"$y$j9T$S.4T3ozMcqze9SUeNROJ00$3CvWhykBSornxDsGuF1dAIS37HOTfoT0MvlYvjMZXH1",
		"$apr1$xEDJX9Qs$EZOndyCNeMgSMllTStRGR/",
		"pbkdf2_sha256$870000$Kx9mQ2vR7tL4pW8n$Hq3nT8wZ5rK2mV7bX4cJ9pL6sD1gQ8aF5eY0uI3oP2k=",
		"argon2$argon2id$v=19$m=102400,t=2,p=8$Kx9mQ2vR7tL4pW8n$Hq3nT8wZ5rK2mV7bX4cJ9pL6sD1g",
		"sha1$Kx9mQ2$2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
		"{SSHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=",
		"{CRYPT}$6$saltsalt$1tySNNgq6Honi21SstQhFBZIa4TOpuhR6v7fJtbxWwEy6BU3rZRVNtB.144R0..s/NUKKimOuL4AFnrIBJcFA0",
		"*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19",
		"md5d41d8cd98f00b204e9800998ecf8427e",
	])
		assert.ok(isPasswordHash(hash), hash);
	for (const password of [
		"md5$Xk9#mP2vQ!&z",
		"{SSHA}Xk9#mP2vQ!&z",
		"$1$Xk9#mP2vQ!&z",
		"$y$wJES6#Q&",
		"sha1$hunter2",
		"$1$Summer$2024",
		"$2b$Harbor$2291",
		"$6$$",
		"$5$a$b",
		"sha1$Harbor$2291Harbor2291Harbor",
	])
		assert.ok(!isPasswordHash(password), password);
});

test("a random token is told from words, numbers and dates by its characters", () => {
	const alphabets = [
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
		"0123456789abcdef",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
		"abcdefghijklmnopqrstuvwxyz",
	];
	for (const alphabet of alphabets) {
		let missed = 0;
		for (let i = 0; i < 2000; i++)
			if (!isRandomToken(Array.from(randomBytes(32), (b) => alphabet[b % alphabet.length]).join(""))) missed++;
		assert.ok(missed <= 2, `${alphabet}: ${missed} of 2000 read as not random`);
	}
	// (Hex whose letters are few, which the model reads as a number, is random too.)
	for (const v of [
		"2ccccbfc5a83859dfc3a267a3bdc5f1b",
		"9215e9b4b645255238729925759355c8",
		"HeCyNZaswaFJeXfywkHbZg",
		"qwhzkfmtvbnrxplo",
	])
		assert.ok(isRandomToken(v), v);
	for (const v of [
		"reset-password-confirm",
		"ProjectSettingsPage",
		"VerifyEmailPage2024.tsx",
		"sso-saml-setup-v2",
		"my-awesome-blog-post-2024",
		"2024-01-15T10-30-00",
		"1234567890123456",
		"deadbeefcafebabe",
	])
		assert.ok(!isRandomToken(v), v);
});

/** A bech32 string: `hrp`, `1`, and `data` (5-bit values) with their checksum. */
function bech32(hrp: string, data: number[]): string {
	const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
	const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
	const polymod = (values: number[]) => {
		let chk = 1;
		for (const v of values) {
			const top = chk >>> 25;
			chk = ((chk & 0x1ffffff) << 5) ^ v;
			for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= GEN[i];
		}
		return chk;
	};
	const expanded = [...hrp]
		.map((c) => c.charCodeAt(0) >> 5)
		.concat(
			[0],
			[...hrp].map((c) => c.charCodeAt(0) & 31),
		);
	const mod = polymod([...expanded, ...data, 0, 0, 0, 0, 0, 0]) ^ 1;
	const checksum = Array.from({ length: 6 }, (_, i) => (mod >>> (5 * (5 - i))) & 31);
	return `${hrp}1${[...data, ...checksum].map((v) => CHARSET[v]).join("")}`;
}

test("a pod's name is its workload's, a word in it, then two generated suffixes", () => {
	for (const pod of ["ledger-api-58d4f7c9b-rbjl3", "k8s-agent-7d9f8b6c4-x2k9p"]) assert.ok(isPodName(pod), pod);
	assert.ok(!isPodName("x9k2q-7d9f8b6c4-x2k9p"));
});

test("password hashes are kept whole by default and hidden whole with hashes: hide", () => {
	const strict = new Redactor({ fingerprintKey: "t", hashes: "hide" });
	for (const h of [
		"$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW",
		"$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHRzb21lc2FsdA$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
		"admin:$$apr1$$hQ8m3eOZ$$BipdBoppF6aFcg575ydC9h",
		'"pgbouncer" "SCRAM-SHA-256$4096:qLbMj3qclZjjuEL/zmcR+m==$6WxFxeMa1A7shll8oBYVkInYiCleL7JmJYsxMicZoFA=:zCrBeYZOjNvODYYYW+2L+QW8SQXuN9TcPtoBEIQhi1p="',
		"IDENTIFIED BY PASSWORD '*94BDCEBE19083CE2A1F959FD02F964C7AF4CFC29'",
	]) {
		kept(h, h);
		assert.ok(!strict.redact(h).text.includes(h.slice(-22, -2)), h);
	}
	assert.match(
		strict.redact("password_hash: $2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW").text,
		/^password_hash: \[REDACTED password hash #\w+\]$/,
	);
	assert.match(
		strict.redact("GRANT ALL ON *.* TO 'bob'@'%' IDENTIFIED BY '*3F1A9C2E7B5D4F6A8C0E2B4D6F8A0C2E4B6D8F0A';").text,
		/BY '\[REDACTED password hash #\w+\]';$/,
	);
});

test("a SCRAM hash is kept by default", () => {
	const t =
		" app_ro     | SCRAM-SHA-256$4096:RISB38K6PgWJthH+HeyHTm==$65IhIKafyYFvTDz4agc3ML3Xt8jgScvGEm9VRBethcx=:mGXsmSKxFxLZDGA1XPFCoi9FhIW6ko/a9zjU/ZbdFh4=";
	assert.equal(r().redact(t).text, t);
});

test("a password that starts like a crypt hash is a password", () => {
	hidden('DB_PASSWORD="$1$Summer$2024"', "Summer$2024");
});

test("a shadow entry and an argon2 hash are kept whole", () => {
	kept(
		"root:$6$saltsalt$1tySNNgq6Honi21SstQhFBZIa4TOpuhR6v7fJtbxWwEy6BU3rZRVNtB.144R0..s/NUKKimOuL4AFnrIBJcFA0:19000:0:99999:7:::",
		"1tySNNgq6Honi21",
	);
	kept(
		"password: '$argon2id$v=19$m=65536,t=3,p=4$/2bS0qjwpY4RD8lrQDsO+0$rnSRriSxuwsOo/fFtuVGeV1xYWly6vlVLpWzDglAr23'",
		"/2bS0qjwpY4RD8lrQDsO+0",
	);
});

test("a password that holds a placeholder word is still a password", () => {
	for (const v of [
		"Winter...2024",
		"Lunar…Tiger9",
		"Harbor123456789!",
		"Fake!Orbit2291",
		"invalidXk9mP2vQ7tL4",
		"Q7tL4wR8nZ_HERE91kd",
		"eternal.There9748",
	])
		hidden(`DB_PASSWORD='${v}'`, v);
});

test("a key cut short with ... or a placeholder word is a placeholder", () => {
	for (const v of ["sk-proj-abc...xyz", "YOUR_API_KEY_HERE", "sk_test_xxxxxxxxxxxx", "not-a-real-key"])
		kept(`OPENAI_API_KEY=${v}`, v);
});

test("hashes: hide holds in redactValue", () => {
	const hashing = new Redactor({ hashes: "hide" });
	const bcrypt = "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW";
	assert.ok(!JSON.stringify(hashing.redactValue({ content: `stored: ${bcrypt}` }).value).includes(bcrypt));
});

test("a PKCS#1 RSA public key is public at every modulus size, and zero filler is not a key", () => {
	for (const modulusLength of [1024, 2048, 4096]) {
		const { publicKey } = generateKeyPairSync("rsa", { modulusLength });
		const der = publicKey.export({ type: "pkcs1", format: "der" }).toString("base64");
		assert.ok(isRsaPublicKey(der), `${modulusLength} bits`);
	}
	assert.ok(!isRsaPublicKey("MIGJAoGBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
});

test("a bech32 string is an address unless its prefix says secret, in either case", () => {
	const data = Array.from({ length: 40 }, (_, i) => (i * 7 + 3) % 32);
	assert.ok(isBech32Address(bech32("skale", data)), "an HRP that merely starts with sk");
	assert.ok(isBech32Address(bech32("security", data)));
	for (const hrp of ["sk", "sec", "priv", "nsec"]) assert.ok(!isBech32Address(bech32(hrp, data)), hrp);
	assert.ok(isBech32Address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));
	assert.ok(isBech32Address("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"));
	assert.ok(!isBech32Address("Bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));
});

test("a stand-in word plus a tail is a weak password, not a placeholder", () => {
	for (const v of [
		"Changed2024",
		"Example7392",
		"Here2024",
		"ExampleXkqz",
		"Fake!Orbit2291",
		"invalidXk9mP2vQ7tL4",
		"Q7tL4wR8nZ_HERE91kd",
	])
		assert.ok(!isPlaceholder(v), v);
	for (const v of [
		"YOUR_KEY_HERE",
		"YOUR_API_KEY_HERE",
		"example-token",
		"<your-key>",
		"sk_test_xxxxxxxx",
		"changeMe",
		"exampleToken",
		"xxxx1234",
		"[REDACTED-SECRET]",
		"not-a-real-key",
	])
		assert.ok(isPlaceholder(v), v);
	hidden("DB_PASSWORD=Changed2024", "Changed2024");
	kept("DB_PASSWORD=YOUR_KEY_HERE", "YOUR_KEY_HERE");
});

test("masks, cut keys, templates with plain holes and test vectors are stand-ins; a key cut at its front isn't", () => {
	for (const v of [
		"xxxx8f2c", // a mask showing the last characters
		"sk-proj-abc...xyz", // a key printed cut short
		"sk-proj-QmTxvRk...a91F",
		"postgres://<user>:<password>@localhost:5432/app", // docs' holes that name what goes in them
		"postgres://${USER}:${PASS}@db:5432/app", // a template whose literal text is plain
		"000102030405060708090a0b0c0d0e0f", // test vectors counting by bytes: FIPS-197's key and plaintext, RFC 4231's key
		"00112233445566778899aabbccddeeff",
		"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
	])
		assert.ok(isPlaceholder(v), v);
	for (const v of [
		"...Kx9mQv2Lp7RtVw8NyKcHj0Df4Gs6Bz",
		"0110100110010110", // steps of one, but no run counts one way
		"7f3b9c2e1d4a5b6c",
	])
		assert.ok(!isPlaceholder(v), v);
});

test("an NTLM message's zero bytes don't make it a run of one character", () => {
	// (Its fields' zero bytes are 45% of the base64; the NT response after them is the credential.)
	const authenticate =
		"TlRMTVNTUAADAAAAAAAAAEAAAAAYABgAQAAAAAAAAABYAAAABgAGAFgAAAAAAAAAXgAAAAAAAABeAAAABYKIosOh8J5deyhG4Z8LatTHjiU3uQ8dao5MJWIAbwBiAA==";
	assert.ok(!isPlaceholder(authenticate));
	hidden(`Authorization: NTLM ${authenticate}`, authenticate);
});

test("a JWT signed with a weak common key is a real token, one signed with a documented key is public", () => {
	const sign = (key: string, claims: object) => {
		const part = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
		const unsigned = `${part({ alg: "HS256", typ: "JWT" })}.${part(claims)}`;
		return `${unsigned}.${createHmac("sha256", key).update(unsigned).digest("base64url")}`;
	};
	const claims = { uid: 4821, scope: "admin" };
	for (const key of ["secret", "test", "changeme", "key"]) assert.ok(!isPublicJwt(sign(key, claims)), key);
	for (const key of ["your-256-bit-secret", "shhhhh", "keyboard cat"]) assert.ok(isPublicJwt(sign(key, claims)), key);
	const token = sign("secret", claims);
	hidden(`export SESSION_TOKEN=${token}`, token.split(".")[2]);
});

test("a token's alphabet is the smallest that holds it, and its shape counts each class and its switches", () => {
	for (const [token, alphabet] of [
		["deadbeef1234", "hex"],
		["DEADBEEF1234", "HEX"],
		["DeadBeef1234", "b62"],
		["MFRGG234==", "b32"],
		["ABCXYZ89", "B36"],
		["ABCXYZabc234", "b62"],
		["qwertyuiop", "b36"],
		["ab+cd/EF", "b64"],
		["Kx9m_Qv2Lp", "b64url"],
		["ab+cd_EF", "other"],
		["Kx9!mQv2", "other"],
		["abc:def12", "other"],
		["abc~def", "other"],
	])
		assert.equal(alphabetOf(token), alphabet, token);
	const { lower, upper, digit, switches } = shape("aB3_:~");
	assert.deepEqual({ lower, upper, digit, switches }, { lower: 1, upper: 1, digit: 1, switches: 3 / 5 });
	assert.equal(shape("aaBB").switches, 1 / 3);
});

test("a stand-in is test words at any length, and a placeholder phrase run together to its `here`", () => {
	for (const [text, value] of [
		["password: super-secret-test-password-1234", "super-secret-test-password-1234"],
		["password: yourpasswordhere", "yourpasswordhere"],
		["DB_PASSWORD=passwordhere", "passwordhere"],
		["password: YourJwtSecretHere", "YourJwtSecretHere"],
		["DB_PASSWORD=password_!!!", "password_!!!"],
	])
		kept(text, value);
	// (A real password's digits are arbitrary, not a count.)
	hidden("DB_PASSWORD=secret1287", "secret1287");
});

test("names built from short parts are identifiers; a product key's groups and a generated run are not", () => {
	for (const v of [
		"RSA-OAEP-256",
		"SECP521R1-SHA512",
		"x86_64-amd64",
		"ALICE_brainpoolP224r1",
		"ubuntu2204-x86-64-node18",
		"py3-gcc-x64",
		"RHSA-2024:1234",
		"prod-db01-eu01",
	])
		assert.ok(isIdentifierShaped(v), v);
	for (const v of ["VK7X2-QM4P8-RT9W3-HJ6N2", "VKXQR-QM4P8-RT9W3", "qzxvbK9mWpL2-key"])
		assert.ok(!isIdentifierShaped(v), v);
	kept("key_curve: ECDH-brainpoolP384r1", "ECDH-brainpoolP384r1");
	hidden("api_key: qzxvbK9mWpL2-x7", "qzxvbK9mWpL2");
	assert.ok(isPodName("ledger-api-58d4f7c9b-rbjl3"));
	assert.ok(!isPodName("x7k2p9-q8w3e4-r5t6y"));
});

test("words in title case under a key's name are a name; a password rule's digit makes them a password", () => {
	kept("api_key: Nginx-Plus-Trial", "Nginx-Plus-Trial");
	hidden("DB_PASSWORD=Maple-Orbit-42", "Maple-Orbit-42");
});

test("brackets balance by kind, in order", () => {
	assert.ok(isBalanced("f(a[0], {b})"));
	assert.ok(!isBalanced("Ssaw(53n9DYc!(l7)"));
	assert.ok(!isBalanced("(a]"));
});

test("an empty token has no NaN in its shape, and = is no alphabet", () => {
	assert.equal(shape("").expectedSwitches, 0);
	assert.equal(alphabetOf("abcDEF12=="), alphabetOf("abcDEF12"));
});
