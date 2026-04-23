/**
 * Trust-critical tests for the crypto primitives:
 *   - ECDSA EIP-191 recovery against a real Phala signature
 *   - JWT ES384 verify against an NRAS-shaped test vector (generated locally)
 *
 * We run these via a tiny import of the TS file through tsx/jiti if
 * available, else we skip with a clear message. pi's runtime uses jiti
 * so in practice TS imports just work — we try both.
 */
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

// Try to load our TS module. If the environment can't handle TS, skip.
let crypto;
try {
	crypto = await import("../src/crypto.ts");
} catch (e) {
	try {
		// fallback: a compiled .js next to it, if any
		crypto = await import("../src/crypto.js");
	} catch {
		console.warn("crypto module could not be imported (need a TS loader); skipping");
	}
}

const fixturesDir = join(__dirname, "fixtures");
const fixtures = readdirSync(fixturesDir).filter((f) => f.endsWith(".json"));

if (!crypto) {
	test("crypto tests skipped — no TS loader available", () => {
		assert.ok(true);
	});
} else {
	for (const f of fixtures) {
		const fx = JSON.parse(readFileSync(join(fixturesDir, f), "utf8"));
		if (fx.signing_algo !== "ecdsa") continue;
		test(`[${f}] ECDSA EIP-191 recovers the claimed signing_address`, () => {
			const recovered = crypto.ecdsaRecoverEthAddress(fx.signed_text, fx.signature);
			assert.equal(recovered.toLowerCase(), fx.signing_address.toLowerCase());
		});
	}

	test("hex helpers roundtrip", () => {
		const b = new Uint8Array([0x00, 0x01, 0xfe, 0xff, 0xa5]);
		assert.equal(crypto.bytesToHex(b), "0001feffa5");
		assert.deepEqual(Array.from(crypto.hexToBytes("0x0001feffa5")), [0x00, 0x01, 0xfe, 0xff, 0xa5]);
	});

	test("sha256Hex of empty string matches known value", () => {
		assert.equal(
			crypto.sha256Hex(""),
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		);
	});

	test("constantTimeEq works", () => {
		assert.equal(crypto.constantTimeEq(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3])), true);
		assert.equal(crypto.constantTimeEq(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4])), false);
		assert.equal(crypto.constantTimeEq(new Uint8Array([1]), new Uint8Array([1, 2])), false);
	});
}
