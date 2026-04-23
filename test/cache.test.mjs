/**
 * Two-turn live test exercising:
 *   - signing-key cache (turn 2 should be much faster than turn 1)
 *   - TOFU upgrade: app facet moves from ⚠ (first use) to ✓ (intact) across turns
 *     within the SAME pinnedApps array passed to both calls.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

const API_KEY = process.env.PHALA_API_KEY;
const MODEL = process.env.PHALA_TEST_MODEL || "phala/qwen-2.5-7b-instruct";

if (!API_KEY) {
	test("cache: skipped (set PHALA_API_KEY)", () => assert.ok(true));
} else {
	const { installInterceptor, findRecord } = await import("../src/fetchIntercept.ts");
	const { verifyTurn } = await import("../src/verify.ts");

	async function oneTurn(pinnedApps) {
		const resp = await fetch("https://api.redpill.ai/v1/chat/completions", {
			method: "POST",
			headers: { "Content-Type": "application/json", Authorization: `Bearer ${API_KEY}` },
			body: JSON.stringify({
				model: MODEL,
				messages: [{ role: "user", content: "Reply: ack" }],
				stream: false,
				temperature: 0,
				max_tokens: 4,
			}),
		});
		const body = await resp.json();
		await new Promise((r) => setTimeout(r, 150));
		const record = findRecord(body.id);
		const t0 = Date.now();
		const verdict = await verifyTurn({
			apiKey: API_KEY,
			record,
			appIdentityMode: "tofu",
			pinnedApps,
			allowedApps: [],
			signingKeyCacheMs: 5 * 60 * 1000,
		});
		return { verdict, verifyMs: Date.now() - t0 };
	}

	test("cache hit on turn 2 + TOFU upgrades ⚠→✓", async () => {
		installInterceptor();
		const pins = [];

		const a = await oneTurn(pins);
		const b = await oneTurn(pins);

		const aBy = Object.fromEntries(a.verdict.facets.map((f) => [f.id, f]));
		const bBy = Object.fromEntries(b.verdict.facets.map((f) => [f.id, f]));

		console.log(`turn1 verify=${a.verifyMs}ms app=${aBy.app.status}`);
		console.log(`turn2 verify=${b.verifyMs}ms app=${bBy.app.status} (cached: ${bBy.tdx.detail.includes("cached")})`);

		// Turn 1: TOFU first use
		assert.equal(aBy.app.status, "warn");
		// Turn 2: TOFU intact → ✓
		assert.equal(bBy.app.status, "ok");
		// Turn 2: tdx/gpu facets came from cache
		assert.ok(bBy.tdx.detail.includes("cached"));
		assert.ok(bBy.gpu.detail.includes("cached"));
		// Turn 2 should be dramatically faster
		assert.ok(b.verifyMs < a.verifyMs / 2, `turn2 (${b.verifyMs}ms) not < turn1/2 (${a.verifyMs / 2}ms)`);
	});
}
