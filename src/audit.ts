/**
 * Append-only audit log of verification evidence.
 *
 * One JSON line per turn at ~/.pi/agent/tee-audit.jsonl.
 *
 * Purpose:
 *   - Post-hoc re-verification: all cryptographic evidence (quote, GPU
 *     report, signature, hashes, nonce) is recorded so an auditor can
 *     re-run the entire verification chain offline.
 *   - Forensics: if a user later suspects a particular turn was
 *     compromised, they can reproduce the verification from this log.
 *
 * DOES NOT contain:
 *   - API key (ever).
 *   - Prompt text / completion text / messages (to avoid creating a
 *     parallel store of potentially sensitive conversation content).
 *     Users who want to correlate with content should use pi's own session
 *     files, which they already control.
 */

import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { Verdict } from "./types.js";

export function appendAudit(path: string, verdict: Verdict): void {
	if (!path) return;
	try {
		mkdirSync(dirname(path), { recursive: true });
		const entry = {
			ts: new Date().toISOString(),
			chat_id: verdict.chatId,
			model: verdict.model,
			overall: verdict.overall,
			signing_address: verdict.signingAddress,
			app_id: verdict.appId,
			trust_center_url: verdict.trustCenterUrl,
			facets: verdict.facets,
			evidence: verdict.evidence, // no API key, no prompt/completion text
		};
		appendFileSync(path, JSON.stringify(entry) + "\n");
	} catch {
		// Audit logging must never break the agent. Silent fail is acceptable.
	}
}
