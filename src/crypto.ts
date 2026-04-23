/**
 * Low-level crypto for phala-tee.
 *
 * All primitives come from @noble/* — pure-JS, audited, no native deps.
 * Everything here is intentionally small and transparent so a reviewer can
 * confirm we aren't faking a ✓.
 */

import { secp256k1 } from "@noble/curves/secp256k1";
import { p384 } from "@noble/curves/p384";
import { sha256 } from "@noble/hashes/sha256";
import { sha384 } from "@noble/hashes/sha512";
import { keccak_256 } from "@noble/hashes/sha3";
import { ed25519 } from "@noble/curves/ed25519";

// ---------- utilities ----------

const TE = new TextEncoder();

export function hexToBytes(h: string): Uint8Array {
	const s = h.startsWith("0x") || h.startsWith("0X") ? h.slice(2) : h;
	if (s.length % 2 !== 0) throw new Error("hex: odd length");
	const out = new Uint8Array(s.length / 2);
	for (let i = 0; i < out.length; i++) {
		const b = parseInt(s.substring(i * 2, i * 2 + 2), 16);
		if (Number.isNaN(b)) throw new Error("hex: invalid char");
		out[i] = b;
	}
	return out;
}

export function bytesToHex(b: Uint8Array): string {
	let s = "";
	for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, "0");
	return s;
}

export function constantTimeEq(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	let d = 0;
	for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
	return d === 0;
}

export function sha256Hex(data: Uint8Array | string): string {
	const bytes = typeof data === "string" ? TE.encode(data) : data;
	return bytesToHex(sha256(bytes));
}

// ---------- EIP-191 ECDSA recovery (secp256k1, keccak256) ----------

/**
 * Recover the Ethereum address that signed `text` with `signatureHex`
 * using the `personal_sign` / EIP-191 convention:
 *
 *   msg = "\x19Ethereum Signed Message:\n" + text.length + text
 *   hash = keccak256(msg)
 *   signature = r (32) || s (32) || v (1)
 *
 * Returns a 0x-prefixed checksum-less lowercase address.
 */
export function ecdsaRecoverEthAddress(text: string, signatureHex: string): string {
	const sig = hexToBytes(signatureHex);
	if (sig.length !== 65) {
		throw new Error(`ecdsaRecover: signature must be 65 bytes, got ${sig.length}`);
	}
	const r = sig.slice(0, 32);
	const s = sig.slice(32, 64);
	let v = sig[64];
	if (v >= 27) v -= 27;
	if (v !== 0 && v !== 1) {
		throw new Error(`ecdsaRecover: unexpected recovery v=${sig[64]}`);
	}

	const prefixed = "\x19Ethereum Signed Message:\n" + text.length + text;
	const msgHash = keccak_256(TE.encode(prefixed));

	// noble Signature from compact + recovery
	const signature = new secp256k1.Signature(bytesToBigInt(r), bytesToBigInt(s)).addRecoveryBit(v);
	const pubPoint = signature.recoverPublicKey(msgHash);
	const uncompressed = pubPoint.toRawBytes(false); // 65 bytes: 0x04 || X || Y
	if (uncompressed.length !== 65 || uncompressed[0] !== 0x04) {
		throw new Error("ecdsaRecover: bad uncompressed pubkey");
	}
	const addr = keccak_256(uncompressed.slice(1)).slice(-20);
	return "0x" + bytesToHex(addr);
}

function bytesToBigInt(b: Uint8Array): bigint {
	let v = 0n;
	for (const x of b) v = (v << 8n) | BigInt(x);
	return v;
}

// ---------- Ed25519 verify ----------

export function ed25519Verify(text: string, signatureHex: string, publicKeyHex: string): boolean {
	return ed25519.verify(hexToBytes(signatureHex), TE.encode(text), hexToBytes(publicKeyHex));
}

// ---------- JWT (ES384 / NVIDIA NRAS) ----------

export interface JwtVerifyResult {
	header: Record<string, unknown>;
	payload: Record<string, unknown>;
}

/** Thrown by jwtVerifyES384 when the JWT references a kid the JWKS lacks.
 * Callers (see verifyGpuFacet) should invalidate their JWKS cache and retry
 * once, so a routine NRAS key rotation doesn't produce a false ✗. */
export class JwtKidNotFoundError extends Error {
	readonly kid: string;
	constructor(kid: string) {
		super(`jwt: kid not found in jwks: ${kid}`);
		this.kid = kid;
		this.name = "JwtKidNotFoundError";
	}
}

/**
 * Verify a compact JWT signed with ES384 (ECDSA over P-384 + SHA-384) using
 * the provided JWKS. Returns the decoded header and payload on success.
 * Throws if signature is invalid, kid is not found, or alg is unsupported.
 *
 * NRAS issues ES384 JWTs; we accept only ES384 to prevent alg-confusion.
 */
export function jwtVerifyES384(jwt: string, jwks: JwksKey[]): JwtVerifyResult {
	const parts = jwt.split(".");
	if (parts.length !== 3) throw new Error("jwt: not 3 parts");
	const header = decodeJsonBase64Url(parts[0]);
	const payload = decodeJsonBase64Url(parts[1]);
	const sig = base64UrlToBytes(parts[2]);

	if (header.alg !== "ES384") {
		throw new Error(`jwt: unsupported alg ${String(header.alg)} (expected ES384)`);
	}
	const kid = header.kid;
	if (typeof kid !== "string") throw new Error("jwt: missing kid");
	const key = jwks.find((k) => k.kid === kid);
	if (!key) throw new JwtKidNotFoundError(kid);
	if (key.kty !== "EC" || key.crv !== "P-384") {
		throw new Error(`jwt: wrong key type for ES384: kty=${key.kty} crv=${key.crv}`);
	}

	const pub = jwkP384ToUncompressed(key);
	const signed = TE.encode(parts[0] + "." + parts[1]);
	const msgHash = sha384(signed);

	// JWS ES384 signature is r (48) || s (48), not DER.
	if (sig.length !== 96) throw new Error(`jwt: ES384 sig must be 96 bytes, got ${sig.length}`);
	const ok = p384.verify(sig, msgHash, pub, { format: "compact" });
	if (!ok) throw new Error("jwt: signature verification failed");

	return { header: header as Record<string, unknown>, payload: payload as Record<string, unknown> };
}

export interface JwksKey {
	kty: string;
	crv?: string;
	kid?: string;
	x?: string;
	y?: string;
	x5c?: string[];
	alg?: string;
	use?: string;
}

function jwkP384ToUncompressed(key: JwksKey): Uint8Array {
	if (!key.x || !key.y) throw new Error("jwt: JWK missing x/y");
	const x = base64UrlToBytes(key.x);
	const y = base64UrlToBytes(key.y);
	if (x.length !== 48 || y.length !== 48) {
		throw new Error(`jwt: P-384 x/y wrong length: ${x.length}/${y.length}`);
	}
	const out = new Uint8Array(97);
	out[0] = 0x04;
	out.set(x, 1);
	out.set(y, 49);
	return out;
}

function base64UrlToBytes(s: string): Uint8Array {
	const pad = s.length % 4 === 2 ? "==" : s.length % 4 === 3 ? "=" : "";
	const b64 = s.replaceAll("-", "+").replaceAll("_", "/") + pad;
	// Buffer is available in Node.
	return new Uint8Array(Buffer.from(b64, "base64"));
}

function decodeJsonBase64Url(s: string): Record<string, unknown> {
	const bytes = base64UrlToBytes(s);
	return JSON.parse(new TextDecoder().decode(bytes));
}
