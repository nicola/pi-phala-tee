/**
 * Canonical JSON serializer that reproduces Python's `json.dumps(obj)`
 * with default arguments. This is what Phala's server hashes for
 * `response_hash` in `/v1/signature/{chat_id}`.
 *
 * Specifically Python default:
 *   - separators: ', ' between items and ': ' between key and value
 *   - ensure_ascii=True: non-ASCII characters are escaped to \uXXXX
 *   - preserves insertion order of object keys
 *   - floats use Python's repr (we best-effort match)
 *   - no trailing newline
 *
 * We do NOT use `JSON.stringify` with a replacer because that still uses
 * JS default formatting between keys/items.
 *
 * SECURITY: This function is a trust-critical check (it decides whether
 * `resp-bind` can be ✓). Any discrepancy with the server's serializer must
 * cause the check to fail, not a false ✓.  Tests in test/canonical.test.mjs
 * use real fixtures captured from the API.
 */

const HEX = "0123456789abcdef";

function escapeString(s: string): string {
	let out = '"';
	for (let i = 0; i < s.length; i++) {
		const c = s.charCodeAt(i);
		if (c === 0x22) {
			out += '\\"'; // "
		} else if (c === 0x5c) {
			out += "\\\\"; // \
		} else if (c === 0x08) {
			out += "\\b";
		} else if (c === 0x0c) {
			out += "\\f";
		} else if (c === 0x0a) {
			out += "\\n";
		} else if (c === 0x0d) {
			out += "\\r";
		} else if (c === 0x09) {
			out += "\\t";
		} else if (c < 0x20 || c > 0x7e) {
			// Python ensure_ascii=True escapes all non-ASCII.
			// For code points > 0xFFFF, JS strings already hold surrogate pairs,
			// which Python also emits as two \uXXXX escapes — so iterating
			// code units (not code points) is correct.
			out += "\\u" + HEX[(c >> 12) & 0xf] + HEX[(c >> 8) & 0xf] + HEX[(c >> 4) & 0xf] + HEX[c & 0xf];
		} else {
			out += s[i];
		}
	}
	out += '"';
	return out;
}

function serializeNumber(n: number): string {
	if (!Number.isFinite(n)) {
		// Python emits NaN / Infinity by default (allow_nan=True) — mirror that.
		if (Number.isNaN(n)) return "NaN";
		return n > 0 ? "Infinity" : "-Infinity";
	}
	if (Number.isInteger(n)) return n.toString();
	// Python's repr of a float uses the shortest round-trip form, and so does
	// JavaScript's Number.prototype.toString(). They agree for most values we'll
	// see in OpenAI responses (which are typically integers), but differ on
	// edge cases (e.g. Python writes `1.0`, JS writes `1`). OpenAI responses
	// don't emit trailing-zero floats, so this is rarely exercised. If we see
	// a signature mismatch, `resp-bind` will fail closed (⚠/✗), never silent ✓.
	return n.toString();
}

export function canonicalize(value: unknown): string {
	if (value === null) return "null";
	if (value === true) return "true";
	if (value === false) return "false";
	const t = typeof value;
	if (t === "number") return serializeNumber(value as number);
	if (t === "string") return escapeString(value as string);
	if (Array.isArray(value)) {
		if (value.length === 0) return "[]";
		const parts: string[] = [];
		for (const v of value) parts.push(canonicalize(v));
		return "[" + parts.join(", ") + "]";
	}
	if (t === "object") {
		const obj = value as Record<string, unknown>;
		const keys = Object.keys(obj);
		if (keys.length === 0) return "{}";
		const parts: string[] = [];
		for (const k of keys) {
			parts.push(escapeString(k) + ": " + canonicalize(obj[k]));
		}
		return "{" + parts.join(", ") + "}";
	}
	throw new Error(`canonicalize: unsupported type ${t}`);
}
