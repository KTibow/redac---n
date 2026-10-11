/**
 * Public keys recognised by their encoding's structure, from the first bytes of their base64: a DER
 * SubjectPublicKeyInfo (what `-----BEGIN PUBLIC KEY-----` holds) and an OpenPGP public key packet (an armored
 * `PUBLIC KEY BLOCK`'s body). Each check reads enough fields that agree with each other (a known algorithm's OID, a
 * key size and the bit it sets, a packet length that is its fields' sum) that random base64 passes with odds below one
 * in a hundred billion: a value that passes is kept. (Measured for PGP: about 1 random value in 10^8 has the header,
 * version, creation time and key size, and 1 in 14,000 of those the length.)
 */
import { base64Bytes, base64Prefix } from "./base64.ts";
import { type ArmoredBlock, armoredBlocks, beginLines } from "./pem.ts";

/** How much base64 text the checks read: 48 bytes cover every header they look at. */
const HEAD_CHARS = 64;

/** The first bytes base64 text encodes, or an empty array. */
function head(b64: string): Uint8Array {
	return base64Prefix(b64.slice(0, HEAD_CHARS)) ?? new Uint8Array();
}

const hex = (b: Uint8Array, from: number, length: number) =>
	Array.from(b.subarray(from, from + length), (x) => x.toString(16).padStart(2, "0")).join("");

/** Where a DER element's content starts, given where its tag is, and how long it is; or undefined for an invalid length. */
function derElement(b: Uint8Array, at: number): { content: number; length: number } | undefined {
	const first = b[at + 1];
	if (first === undefined) return undefined;
	if (first < 0x80) return { content: at + 2, length: first };
	const size = first & 0x7f;
	if (size < 1 || size > 3 || b.length < at + 2 + size) return undefined;
	let length = 0;
	for (let i = 0; i < size; i++) length = length * 256 + b[at + 2 + i];
	return { content: at + 2 + size, length };
}

/** Where a DER element's content starts, given where its tag is, or -1 for an invalid length. */
function derContent(b: Uint8Array, at: number): number {
	return derElement(b, at)?.content ?? -1;
}

/** Public key algorithms' OIDs: RSA, RSASSA-PSS, DSA, DH, EC, Ed25519, Ed448, X25519, X448. */
const KEY_ALGORITHMS = new Set([
	"2a864886f70d010101",
	"2a864886f70d01010a",
	"2a8648ce380401",
	"2a864886f70d010301",
	"2a8648ce3d0201",
	"2b6570",
	"2b6571",
	"2b656e",
	"2b656f",
]);

/**
 * A SubjectPublicKeyInfo: a SEQUENCE whose first element is the AlgorithmIdentifier, a SEQUENCE that starts with a
 * public key algorithm's OID. (A private key's PKCS #8 and PKCS #1 encodings start with an INTEGER version instead.)
 */
export function isDerPublicKey(b64: string): boolean {
	const b = head(b64);
	if (b[0] !== 0x30) return false;
	const inner = derContent(b, 0);
	if (inner < 0 || b[inner] !== 0x30) return false;
	const oid = derContent(b, inner);
	return oid >= 0 && b[oid] === 0x06 && KEY_ALGORITHMS.has(hex(b, oid + 2, b[oid + 1]));
}

/**
 * A private key's DER, whatever armor it's in: a SEQUENCE whose first element is a one-byte INTEGER version, 0 to 2
 * (PKCS #1's RSAPrivateKey and PKCS #8's PrivateKeyInfo start with 0, OneAsymmetricKey with 1, SEC 1's EC key with
 * 1). No public structure starts so: a SubjectPublicKeyInfo or a certificate opens with a SEQUENCE, an RSAPublicKey
 * with its modulus.
 */
export function isDerPrivateKey(b64: string): boolean {
	const b = head(b64);
	if (b[0] !== 0x30) return false;
	const inner = derContent(b, 0);
	return inner >= 0 && b[inner] === 0x02 && b[inner + 1] === 0x01 && b[inner + 2] <= 2;
}

/**
 * A PKCS #1 RSAPublicKey (`-----BEGIN RSA PUBLIC KEY-----`, `MIIBCgKCAQEA…`, `MIGJAoGBA…` for 1,024 bits): a SEQUENCE
 * of the modulus, 1,024 to 8,192 bits in steps of 512 with its top bit set, and an exponent of 1 to 4 bytes, the SEQUENCE's length the
 * two's.
 */
export function isRsaPublicKey(b64: string): boolean {
	const b = head(b64);
	const sequence = derElement(b, 0);
	const modulus = sequence && derElement(b, sequence.content);
	if (b[0] !== 0x30 || !sequence || !modulus || b[sequence.content] !== 0x02) return false;
	const exponent = sequence.length - (modulus.content - sequence.content) - modulus.length - 2; // (the exponent's tag and length)
	return (
		modulus.length >= 129 &&
		modulus.length <= 1025 &&
		modulus.length % 64 === 1 &&
		b[modulus.content] === 0 &&
		b[modulus.content + 1] >= 0x80 &&
		exponent >= 1 &&
		exponent <= 4
	);
}

/**
 * A DER ECDSA signature, whole: a SEQUENCE of two INTEGERs, r and s, of 1 to 66 bytes (P-256 to P-521; a leading zero
 * only before a top bit), the SEQUENCE's length theirs and the value's length the SEQUENCE's.
 */
export function isDerSignature(b64: string): boolean {
	if (b64.length > 200) return false;
	const b = base64Bytes(b64) ?? new Uint8Array();
	const content = derContent(b, 0);
	if (b[0] !== 0x30 || content < 0 || content + (b[1] < 0x80 ? b[1] : b[2]) !== b.length) return false;
	const integer = (at: number) =>
		b[at] === 0x02 && b[at + 1] >= 1 && b[at + 1] <= 66 && (b[at + 2] !== 0 || b[at + 3] >= 0x80);
	const s = content + 2 + b[content + 1];
	return integer(content) && integer(s) && s + 2 + b[s + 1] === b.length;
}

/** OpenPGP's elliptic curves by OID: NIST P-256, P-384, P-521, brainpool, secp256k1, Ed25519, Curve25519, Ed448, X448. */
const PGP_CURVES = new Set([
	"2a8648ce3d030107",
	"2b81040022",
	"2b81040023",
	"2b2403030208010107",
	"2b240303020801010b",
	"2b240303020801010d",
	"2b8104000a",
	"2b06010401da470f01",
	"2b060104019755010501",
	"2b6571",
	"2b656f",
]);

/** Seconds since 1970 of 1995-01-01: OpenPGP keys made before it don't turn up. */
const PGP_EPOCH = 788_918_400;

/**
 * An OpenPGP v4 public key or public subkey packet (tag 6 or 14), in the old or the new packet format: a creation
 * time since 1995 and not in the future, then an RSA modulus whose bit count agrees with its first byte, or an
 * elliptic curve's OID.
 */
export function isPgpPublicKey(b64: string): boolean {
	const b = head(b64);
	if (b.length < 16) return false;
	let tag: number;
	let body: number;
	let length: number;
	if ((b[0] & 0xc0) === 0x80) {
		// Old format: the tag in bits 5–2, the length's size in bits 1–0 (1, 2 or 4 octets).
		tag = (b[0] >> 2) & 0x0f;
		const size = [1, 2, 4][b[0] & 3];
		if (size === undefined) return false;
		body = 1 + size;
		length = 0;
		for (let i = 1; i < body; i++) length = length * 256 + b[i];
	} else if ((b[0] & 0xc0) === 0xc0) {
		// New format: the tag in bits 5–0, a length of 1, 2 or 5 octets.
		tag = b[0] & 0x3f;
		body = b[1] < 192 ? 2 : b[1] < 224 ? 3 : b[1] === 255 ? 6 : -1;
		if (body < 0) return false;
		length =
			body === 2
				? b[1]
				: body === 3
					? ((b[1] - 192) << 8) + b[2] + 192
					: ((b[2] << 24) | (b[3] << 16) | (b[4] << 8) | b[5]) >>> 0;
	} else return false;
	if ((tag !== 6 && tag !== 14) || b[body] !== 4) return false;
	const created = ((b[body + 1] << 24) | (b[body + 2] << 16) | (b[body + 3] << 8) | b[body + 4]) >>> 0;
	if (created < PGP_EPOCH || created > Date.now() / 1000 + 86_400) return false;
	const algorithm = b[body + 5];
	// (The packet's length is its fields': version, time and algorithm, 6 octets, then the key's.)
	if (algorithm === 1 || algorithm === 2 || algorithm === 3) {
		// RSA: the modulus is an MPI, its bit count (1,024 to 16,384) then its bytes, the first holding its top bit; then
		// the exponent's MPI, of 1 to 4 bytes (65537 takes 3).
		const bits = (b[body + 6] << 8) | b[body + 7];
		const top = b[body + 8];
		const exponent = length - 6 - 2 - Math.ceil(bits / 8) - 2;
		return (
			bits >= 1024 &&
			bits <= 16_384 &&
			top !== undefined &&
			31 - Math.clz32(top) === (bits - 1) % 8 &&
			exponent >= 1 &&
			exponent <= 4
		);
	}
	// ECDH, ECDSA, EdDSA: the curve's OID, after its length; the point's MPI; for ECDH its KDF parameters, 4 octets.
	if (algorithm !== 18 && algorithm !== 19 && algorithm !== 22) return false;
	const oid = b[body + 6];
	const at = body + 7 + oid;
	if (!PGP_CURVES.has(hex(b, body + 7, oid)) || at + 1 >= b.length) return false;
	const point = (b[at] << 8) | b[at + 1];
	return length === 6 + 1 + oid + 2 + Math.ceil(point / 8) + (algorithm === 18 ? 4 : 0);
}

/**
 * The labels of PEM armor that holds public material or ciphertext, neither of them a secret to redact: certificates
 * and their requests, CRLs, public keys, PGP public blocks and signatures, parameters; and `ENCRYPTED FILE`,
 * `PGP MESSAGE`, kept as encrypted values are.
 */
const PUBLIC_LABEL =
	/^(?:[A-Z0-9]+ )*(?:PUBLIC KEY|CERTIFICATE|X509 CRL|CERTIFICATE REQUEST|NEW CERTIFICATE REQUEST|PGP PUBLIC KEY BLOCK|PGP SIGNATURE|PGP MESSAGE|ENCRYPTED FILE|SSH2 PUBLIC KEY|DH PARAMETERS|EC PARAMETERS|PKCS7|CMS)$/;

/** The public armored blocks of a text (PUBLIC_LABEL's), in order. */
export const publicBlocks = (text: string): ArmoredBlock[] =>
	armoredBlocks(text).filter((b) => PUBLIC_LABEL.test(b.label));

/** Whether PEM text is public through and through: it has a BEGIN line, and every one is public armor (a bundle with a key isn't). */
export function isPublicPem(pem: string): boolean {
	const labels = [...beginLines(pem)].map((b) => b.label);
	return labels.length > 0 && labels.every((label) => PUBLIC_LABEL.test(label));
}
