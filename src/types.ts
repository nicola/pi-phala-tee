/**
 * Verification types for phala-tee.
 *
 * A `Verdict` describes the trustworthiness of one completed LLM turn.
 * Each `Facet` is an independent cryptographic check. A facet is ONLY ✓
 * when the check actually ran, against a trust root we accept locally
 * (or against a delegated verifier that we explicitly label).
 *
 * The overall status is derived from the worst facet:
 *   ✓  all facets ok
 *   ⚠  any facet warn (unchecked, delegated, unavailable, but no contradiction)
 *   ✗  any facet fail (cryptographic contradiction — do not trust)
 */

export type FacetStatus = "ok" | "warn" | "fail" | "skip";

export interface Facet {
	id: FacetId;
	label: string;
	status: FacetStatus;
	detail: string;
}

export type FacetId =
	| "transport"
	| "sig"
	| "req-bind"
	| "resp-bind"
	| "tdx"
	| "reportdata"
	| "gpu"
	| "app"
	| "fresh";

export type OverallStatus = "ok" | "warn" | "fail";

export interface Verdict {
	overall: OverallStatus;
	facets: Facet[];
	/** Identity of the TEE signing key for this turn. */
	signingAddress?: string;
	/** Phala app id extracted from event_log. */
	appId?: string;
	/** Phala Trust Center URL for this app (cross-verification). */
	trustCenterUrl?: string;
	/** OpenAI chat completion id. */
	chatId?: string;
	/** Model used. */
	model?: string;
	/** When verification completed. */
	verifiedAt: number;
	/** Evidence bundle (non-secret) — persisted for audit. */
	evidence?: Evidence;
	/** Error at top level, if verification itself crashed. */
	error?: string;
}

export interface Evidence {
	chatId: string;
	model: string;
	signingAddress: string;
	signingAlgo: "ecdsa" | "ed25519";
	text: string;
	signature: string;
	requestSha256?: string;
	responseSha256?: string;
	attestationNonce: string;
	intelQuoteHex: string;
	nvidiaPayload: string;
	info?: unknown;
	vmConfig?: unknown;
	eventLog?: unknown;
}

/** App-identity pin: the tuple we TOFU or allow-list against. */
export interface AppPin {
	appId: string;
	composeHash: string;
	osImageHash: string;
	keyProvider?: string;
	/** ISO timestamp when first pinned. */
	firstSeen: string;
	/** When last seen (updated on each successful verification). */
	lastSeen: string;
}

export interface ExtensionSettings {
	/** How to handle app identity: tofu (pin on first use), strict (must match allowlist), permissive (any). */
	appIdentityMode: "tofu" | "strict" | "permissive";
	/** Allow-list of AppPins for strict mode. */
	allowedApps: AppPin[];
	/** Pinned apps (TOFU mode state). */
	pinnedApps: AppPin[];
	/** Cache TTL for signing-key attestation, in ms. Must also be ≤ JWT exp and TDX collateral exp. */
	signingKeyCacheMs: number;
	/** If true, on any `fail` facet mark the turn in the audit log and surface an error (does not yet block). */
	strictMode: boolean;
	/** Audit log path. Empty string disables audit log. */
	auditLogPath: string;
}

export const DEFAULT_SETTINGS: ExtensionSettings = {
	appIdentityMode: "tofu",
	allowedApps: [],
	pinnedApps: [],
	signingKeyCacheMs: 5 * 60 * 1000,
	strictMode: false,
	auditLogPath: "", // filled in at init time with ~/.pi/tee-audit.jsonl
};
