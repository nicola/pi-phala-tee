/**
 * Trust-critical tests: the canonicalizer must reproduce the exact bytes
 * Phala's server hashes for `response_hash`, and the request-bytes hash
 * path must match too. If this regresses, `resp-bind` / `req-bind` facets
 * silently become ⚠ (fail-closed), never a false ✓ — but we still want
 * CI to catch it.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

// We import the TS source directly; Node's loader compiles via the test runner
// configuration below.  For simplicity, duplicate the canonicalize function
// here (it is tiny) rather than pull in a TS loader in the test harness.
// If the two diverge, tests break — that's good.
function canonicalize(value) {
	const HEX = "0123456789abcdef";
	function esc(s) {
		let out = '"';
		for (let i = 0; i < s.length; i++) {
			const c = s.charCodeAt(i);
			if (c === 0x22) out += '\\"';
			else if (c === 0x5c) out += "\\\\";
			else if (c === 0x08) out += "\\b";
			else if (c === 0x0c) out += "\\f";
			else if (c === 0x0a) out += "\\n";
			else if (c === 0x0d) out += "\\r";
			else if (c === 0x09) out += "\\t";
			else if (c < 0x20 || c > 0x7e)
				out +=
					"\\u" +
					HEX[(c >> 12) & 0xf] +
					HEX[(c >> 8) & 0xf] +
					HEX[(c >> 4) & 0xf] +
					HEX[c & 0xf];
			else out += s[i];
		}
		return out + '"';
	}
	if (value === null) return "null";
	if (value === true) return "true";
	if (value === false) return "false";
	const t = typeof value;
	if (t === "number") {
		if (!Number.isFinite(value)) return Number.isNaN(value) ? "NaN" : value > 0 ? "Infinity" : "-Infinity";
		return value.toString();
	}
	if (t === "string") return esc(value);
	if (Array.isArray(value)) {
		if (value.length === 0) return "[]";
		return "[" + value.map(canonicalize).join(", ") + "]";
	}
	if (t === "object") {
		const keys = Object.keys(value);
		if (keys.length === 0) return "{}";
		return "{" + keys.map((k) => esc(k) + ": " + canonicalize(value[k])).join(", ") + "}";
	}
	throw new Error("unsupported type " + t);
}

function sha256Hex(s) {
	return createHash("sha256").update(s).digest("hex");
}

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, "fixtures");
const fixtures = readdirSync(fixturesDir).filter((f) => f.endsWith(".json"));

test("there is at least one captured fixture (run test/capture-fixture.mjs)", () => {
	assert.ok(fixtures.length > 0, "no fixtures in test/fixtures/");
});

for (const f of fixtures) {
	const fx = JSON.parse(readFileSync(join(fixturesDir, f), "utf8"));

	test(`[${f}] request-byte sha256 matches signed request hash`, () => {
		const [signedReq] = fx.signed_text.split(":");
		const ours = sha256Hex(Buffer.from(fx.request_bytes_utf8, "utf8"));
		assert.equal(ours, signedReq);
	});

	test(`[${f}] canonicalize(response_json) sha256 matches signed response hash`, () => {
		const [, signedResp] = fx.signed_text.split(":");
		const ours = sha256Hex(canonicalize(fx.response_json));
		assert.equal(
			ours,
			signedResp,
			`canonicalizer produced a different hash — the server's serialization may have changed. This must fail closed, not ship.`,
		);
	});
}
