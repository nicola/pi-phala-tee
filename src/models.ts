/**
 * Curated list of models Phala runs in GPU TEE.
 *
 * Source: https://docs.phala.com/phala-cloud/confidential-ai/confidential-model/confidential-ai-api
 *
 * We deliberately do NOT pull the full `/v1/models` catalog from the gateway,
 * because it includes proxied non-TEE models (Anthropic, OpenAI GPT-5, o3,
 * etc.) that are served from ordinary infrastructure and are NOT covered by
 * the TDX+GPU attestation chain. Using the unfiltered list would invite users
 * to select an `anthropic/claude-*` from our "phala-tee" provider and see a
 * ✓ badge that doesn't reflect reality.
 *
 * If a model fails `/v1/attestation/report` at load time it is dropped from
 * the registered list. (Planned for v0.1; v0 ships the static list and
 * validates on first use.)
 *
 * Pricing is indicative (per Phala docs, USD per million tokens, in/out).
 * Context window values come from the docs. Max output tokens are
 * conservative — adjust if a model needs more.
 */

/** Matches pi-ai's ProviderModelConfig shape (see docs/custom-provider.md). */
export interface PhalaTeeModel {
	id: string;
	name: string;
	reasoning: boolean;
	input: ("text" | "image")[];
	cost: { input: number; output: number; cacheRead: number; cacheWrite: number };
	contextWindow: number;
	maxTokens: number;
}

export const PHALA_TEE_MODELS: PhalaTeeModel[] = [
	// --- Phala-operated TEE fleet ---
	{
		id: "phala/deepseek-chat-v3-0324",
		name: "DeepSeek V3 0324 (Phala TEE)",
		reasoning: false,
		input: ["text"],
		cost: { input: 0.28, output: 1.14, cacheRead: 0.28, cacheWrite: 0.28 },
		contextWindow: 163_000,
		maxTokens: 8_000,
	},
	{
		id: "phala/qwen2.5-vl-72b-instruct",
		name: "Qwen2.5 VL 72B (Phala TEE)",
		reasoning: false,
		input: ["text", "image"],
		cost: { input: 0.59, output: 0.59, cacheRead: 0.59, cacheWrite: 0.59 },
		contextWindow: 65_000,
		maxTokens: 8_000,
	},
	{
		id: "phala/gemma-3-27b-it",
		name: "Gemma 3 27B (Phala TEE)",
		reasoning: false,
		input: ["text"],
		cost: { input: 0.11, output: 0.4, cacheRead: 0.11, cacheWrite: 0.11 },
		contextWindow: 53_000,
		maxTokens: 8_000,
	},
	{
		id: "phala/gpt-oss-120b",
		name: "GPT-OSS 120B (Phala TEE)",
		reasoning: true,
		input: ["text"],
		cost: { input: 0.1, output: 0.49, cacheRead: 0.1, cacheWrite: 0.1 },
		contextWindow: 131_000,
		maxTokens: 16_000,
	},
	{
		id: "phala/gpt-oss-20b",
		name: "GPT-OSS 20B (Phala TEE)",
		reasoning: true,
		input: ["text"],
		cost: { input: 0.04, output: 0.15, cacheRead: 0.04, cacheWrite: 0.04 },
		contextWindow: 131_000,
		maxTokens: 8_000,
	},
	{
		id: "phala/qwen-2.5-7b-instruct",
		name: "Qwen2.5 7B (Phala TEE)",
		reasoning: false,
		input: ["text"],
		cost: { input: 0.04, output: 0.1, cacheRead: 0.04, cacheWrite: 0.04 },
		contextWindow: 32_000,
		maxTokens: 8_000,
	},
];
