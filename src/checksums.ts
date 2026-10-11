/**
 * Public identifiers whose last characters check the rest: crypto addresses (Base58Check, bech32) and base32 keys
 * with a CRC-16 (Stellar, NATS). A random string passes one by chance with odds of 2^-16 or less, so a value that
 * verifies is the public identifier it claims to be.
 */
import { sha256 } from "./hmac.ts";

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/** A Bitcoin-style address: Base58Check of 21 bytes with a P2PKH or P2SH version (mainnet or testnet) and a valid checksum. */
export function isBase58Address(t: string): boolean {
	if (t.length < 26 || t.length > 35 || !/^[123mnT][1-9A-HJ-NP-Za-km-z]+$/.test(t)) return false;
	let n = 0n;
	for (const c of t) n = n * 58n + BigInt(BASE58.indexOf(c));
	const bytes: number[] = [];
	while (n > 0n) {
		bytes.unshift(Number(n & 255n));
		n >>= 8n;
	}
	for (let i = 0; i < t.length && t[i] === "1"; i++) bytes.unshift(0);
	if (bytes.length !== 25 || ![0x00, 0x05, 0x6f, 0xc4, 0x41].includes(bytes[0])) return false; // (0x41: TRON)
	const check = sha256(sha256(Uint8Array.from(bytes.slice(0, 21))));
	return check[0] === bytes[21] && check[1] === bytes[22] && check[2] === bytes[23] && check[3] === bytes[24];
}

/**
 * The human-readable parts that name a secret, not an address: Nostr's `nsec` and `ncryptsec`, and the `sk`, `sec` and
 * `priv` that chains and tools give a private key (`sk1…`, `priv1…`), whose checksum would verify as well.
 */
const SECRET_HRP = /^(?:nsec|ncryptsec|sk|sec|priv)$/;

/** A bech32 or bech32m address (`bc1…`, `cosmos1…`, `npub1…`) whose checksum verifies; never a secret's prefix (`nsec1`). All lower case or all upper case (BIP-173); not mixed. */
export function isBech32Address(address: string): boolean {
	const t = address === address.toUpperCase() ? address.toLowerCase() : address;
	const m = /^([a-z]{2,16})1([02-9ac-hj-np-z]{30,90})$/.exec(t);
	if (!m || SECRET_HRP.test(m[1])) return false;
	const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
	const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
	const values = [...m[1]]
		.map((c) => c.charCodeAt(0) >> 5)
		.concat(
			[0],
			[...m[1]].map((c) => c.charCodeAt(0) & 31),
			[...m[2]].map((c) => CHARSET.indexOf(c)),
		);
	let chk = 1;
	for (const v of values) {
		const top = chk >>> 25;
		chk = ((chk & 0x1ffffff) << 5) ^ v;
		for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= GEN[i];
	}
	return chk === 1 || chk === 0x2bc830a3; // bech32, bech32m
}

/** A Stellar public key (`G…`, 56 base32 characters): version byte, 32 key bytes and a CRC-16 that checks out. */
export function isStellarPublicKey(t: string): boolean {
	return /^G[A-Z2-7]{55}$/.test(t) && crc16Ok(t);
}

/** A NATS public nkey: base32 of a prefix byte, 32 key bytes and a CRC-16 (XMODEM) that checks out. */
export function isNatsPublicKey(t: string): boolean {
	return /^[ACNOUX][A-Z2-7]{55}$/.test(t) && crc16Ok(t); // (`P` is a private key's prefix, and `S` a seed's)
}

/** Base32 of 33 bytes and their CRC-16 (XMODEM), as NATS nkeys and Stellar strkeys are. */
function crc16Ok(t: string): boolean {
	const bytes: number[] = [];
	let bits = 0;
	let acc = 0;
	for (const c of t) {
		acc = ((acc << 5) | "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(c)) & 0xfff; // (only the bits not yet emitted)
		bits += 5;
		if (bits >= 8) {
			bytes.push((acc >> (bits - 8)) & 255);
			bits -= 8;
		}
	}
	if (bytes.length !== 35) return false;
	let crc = 0;
	for (const b of bytes.slice(0, 33)) {
		crc ^= b << 8;
		for (let i = 0; i < 8; i++) crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
	}
	return crc === (bytes[33] | (bytes[34] << 8));
}
