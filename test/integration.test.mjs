/**
 * End-to-end live integration test. Requires PHALA_API_KEY.
 * Skips automatically if the key is not set.
 *
 * Exercises the full verification pipeline against real Phala infrastructure:
 *   - fetch interceptor captures real bytes
 *   - signature fetch + ECDSA recovery
 *   - TDX delegated verify
 *   - reportdata binding
 *   - NVIDIA JWKS + JWT ES384 verify
 *   - event_log / vm_config app identity extraction
 */
import assert from "node:assert/strict";
import { test } from "node:test";

const API_KEY = process.env.PHALA_API_KEY;
const MODEL = process.env.PHALA_TEST_MODEL || "phala/qwen-2.5-7b-instruct";

if (!API_KEY) {
	test("integration: skipped (set PHALA_API_KEY to run)", () => {
		assert.ok(true);
	});
} else {
	const { installInterceptor, findRecord } = await import("../src/fetchIntercept.ts");
	const { verifyTurn } = await import("../src/verify.ts");

	test("full chain verifies on a real non-streaming turn", async () => {
		installInterceptor();
		const resp = await fetch("https://api.redpill.ai/v1/chat/completions", {
			method: "POST",
			headers: { "Content-Type": "application/json", Authorization: `Bearer ${API_KEY}` },
			body: JSON.stringify({
				model: MODEL,
				messages: [{ role: "user", content: "Reply with exactly the word: pong" }],
				stream: false,
				temperature: 0,
				max_tokens: 8,
			}),
		});
		assert.equal(resp.status, 200);
		const body = await resp.json();
		assert.ok(body.id, "response should have id");

		// Give the background consumer a moment to finish.
		await new Promise((r) => setTimeout(r, 200));

		const record = findRecord(body.id);
		assert.ok(record, "fetch interceptor should have recorded the turn");
		assert.equal(record.chatId, body.id);
		assert.equal(record.streamed, false);
		assert.ok(record.requestBytes.length > 0);
		assert.ok(record.responseBytes && record.responseBytes.length > 0);

		const verdict = await verifyTurn({
			apiKey: API_KEY,
			record,
			appIdentityMode: "tofu",
			pinnedApps: [],
			allowedApps: [],
			signingKeyCacheMs: 60_000,
		});

		console.log("facets:");
		for (const f of verdict.facets) {
			console.log(`  [${f.status}] ${f.id}: ${f.detail}`);
		}
		console.log("overall:", verdict.overall);
		console.log("appId:", verdict.appId);
		console.log("signingAddress:", verdict.signingAddress);

		// We do NOT assert overall==="ok" because tdx is delegated (⚠ by design
		// in v0) and app is TOFU-on-first-use (⚠). We assert the critical
		// cryptographic facets are OK.
		const byId = Object.fromEntries(verdict.facets.map((f) => [f.id, f]));
		assert.equal(byId.sig.status, "ok", `sig: ${byId.sig.detail}`);
		assert.equal(byId["req-bind"].status, "ok", `req-bind: ${byId["req-bind"].detail}`);
		assert.equal(byId["resp-bind"].status, "ok", `resp-bind: ${byId["resp-bind"].detail}`);
		assert.equal(byId.reportdata.status, "ok", `reportdata: ${byId.reportdata.detail}`);
		assert.equal(byId.gpu.status, "ok", `gpu: ${byId.gpu.detail}`);
		// tdx is ⚠ (delegated). App is ⚠ (TOFU pin on first use).
		assert.ok(byId.tdx.status !== "fail", `tdx: ${byId.tdx.detail}`);
		assert.ok(byId.app.status !== "fail", `app: ${byId.app.detail}`);
	});
}
