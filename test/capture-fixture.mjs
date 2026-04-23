#!/usr/bin/env node
/**
 * Capture a real Phala Confidential AI response + its signature, so our
 * canonicalizer can be tested against ground truth.
 *
 * Usage:  PHALA_API_KEY=sk-rp-... node test/capture-fixture.mjs
 * Writes: test/fixtures/<chat_id>.json
 */
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const API_KEY = process.env.PHALA_API_KEY;
if (!API_KEY) {
	console.error("PHALA_API_KEY not set");
	process.exit(1);
}
const BASE = "https://api.redpill.ai/v1";
const MODEL = process.argv[2] || "phala/qwen-2.5-7b-instruct";
const PROMPT = process.argv[3] || "Reply with exactly the word: pong";

const reqBody = {
	model: MODEL,
	messages: [{ role: "user", content: PROMPT }],
	stream: false,
	temperature: 0,
	max_tokens: 8,
};
const reqBytes = Buffer.from(JSON.stringify(reqBody), "utf8");

const chatResp = await fetch(`${BASE}/chat/completions`, {
	method: "POST",
	headers: { "Content-Type": "application/json", Authorization: `Bearer ${API_KEY}` },
	body: reqBytes,
});
const respBytes = Buffer.from(await chatResp.arrayBuffer());
const respJson = JSON.parse(respBytes.toString("utf8"));
const chatId = respJson.id;

const sigResp = await fetch(
	`${BASE}/signature/${encodeURIComponent(chatId)}?model=${encodeURIComponent(MODEL)}`,
	{ headers: { Authorization: `Bearer ${API_KEY}` } },
);
const sig = await sigResp.json();

const fixtureDir = join(dirname(fileURLToPath(import.meta.url)), "fixtures");
mkdirSync(fixtureDir, { recursive: true });
const out = {
	model: MODEL,
	chat_id: chatId,
	request_bytes_utf8: reqBytes.toString("utf8"),
	request_sha256: createHash("sha256").update(reqBytes).digest("hex"),
	response_json: respJson,
	signed_text: sig.text,
	signature: sig.signature,
	signing_address: sig.signing_address,
	signing_algo: sig.signing_algo,
};
const path = join(fixtureDir, `${chatId}.json`);
writeFileSync(path, JSON.stringify(out, null, 2));
console.log("wrote", path);
console.log("signed response hash:", sig.text.split(":")[1]);
