/**
 * phala-tee — pi extension for Phala Confidential AI (GPU TEE via dstack).
 *
 * Registers a `phala-tee/*` provider backed by Phala's OpenAI-compatible
 * Confidential AI gateway, and cryptographically verifies every completed
 * turn against the Intel TDX + NVIDIA GPU CC + signing-key attestation
 * chain. Displays a per-turn badge with the verdict.
 *
 * See README.md in this directory for the full trust model.
 *
 * Security posture (v0):
 *   - sig / req-bind / resp-bind (non-streaming) / gpu: verified LOCALLY.
 *   - tdx: DELEGATED to cloud-api.phala.com (labelled ⚠, never ✓).
 *   - app: TOFU by default (pinned on first use, fail on change).
 *   - API key is read only from PHALA_API_KEY (or pi's auth.json if present).
 *     Never written to session state, audit log, or error messages.
 */

import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import { appendAudit } from "./src/audit.js";
import { findRecord, installInterceptor, lastRecord } from "./src/fetchIntercept.js";
import { PHALA_TEE_MODELS } from "./src/models.js";
import { loadSettings, saveSettings } from "./src/settings.js";
import { fullReport, widgetLines, widgetLinesIdle } from "./src/ui.js";
import type { Verdict } from "./src/types.js";
import { verifyTurn } from "./src/verify.js";

const PROVIDER_NAME = "phala-tee";
const BASE_URL = "https://api.redpill.ai/v1";
const API_KEY_ENV = "PHALA_API_KEY";
const AUTH_JSON = join(homedir(), ".pi", "agent", "auth.json");
const STATUS_ID = "phala-tee";

/**
 * Resolve the API key pi-ai will use for this provider.
 * Precedence: env var > auth.json[provider].key (api_key type).
 * Must match what pi-ai actually sends on the wire.
 */
function resolveApiKey(): string | undefined {
	const fromEnv = process.env[API_KEY_ENV];
	if (fromEnv) return fromEnv;
	try {
		const raw = readFileSync(AUTH_JSON, "utf8");
		const parsed = JSON.parse(raw) as Record<string, { type?: string; key?: string }>;
		const entry = parsed[PROVIDER_NAME];
		if (entry?.type === "api_key" && typeof entry.key === "string" && entry.key.length > 0) {
			return entry.key;
		}
	} catch {
		/* auth.json missing or unreadable — fine */
	}
	return undefined;
}

export default function (pi: ExtensionAPI) {
	// Install the fetch interceptor as early as possible so it covers
	// the very first provider call in this session.
	installInterceptor();

	// Load persistent settings (TOFU pins, allow-list, policy).
	const settings = loadSettings();

	// Resolve the API key up front so pi-ai sends the LITERAL key, not the
	// env-var name. pi-ai's `apiKey` field accepts either a literal key or an
	// env var name; if we pass the env var name and the env var isn't set,
	// pi-ai ends up sending the string "PHALA_API_KEY" as the bearer token,
	// which yields 401 "Invalid API key provided" from Phala. Resolving here
	// via resolveApiKey() means auth.json works out of the box.
	//
	// If no key is available, we still register the provider but mark it
	// inactive via the idle-widget path so /model selection is clearly broken.
	const resolvedKey = resolveApiKey();

	// Register the provider. We use the OpenAI-compatible API type so pi-ai
	// handles streaming, tool calling, images, and compat quirks natively.
	pi.registerProvider(PROVIDER_NAME, {
		baseUrl: BASE_URL,
		apiKey: resolvedKey ?? API_KEY_ENV,
		// `api: "openai-completions"` already sets Authorization: Bearer.
		// Setting `authHeader: true` on top of that clobbers it to empty.
		api: "openai-completions",
		models: PHALA_TEE_MODELS.map((m) => ({
			id: m.id,
			name: m.name,
			reasoning: m.reasoning,
			input: m.input,
			cost: m.cost,
			contextWindow: m.contextWindow,
			maxTokens: m.maxTokens,
		})),
	});

	// Track the most recent verdict so /tee can print it.
	let lastVerdict: Verdict | undefined;

	// Show / hide the widget based on whether phala-tee is the active
	// provider. No Phala model selected → no widget at all. This extension is
	// otherwise invisible unless the user opts into TEE-backed inference.
	const refreshWidget = (ctx: {
		hasUI: boolean;
		model?: { provider?: string };
		ui: {
			theme: { fg(t: string, s: string): string };
			setWidget: (id: string, lines: string[] | undefined) => void;
		};
	}) => {
		if (!ctx.hasUI) return;
		if (ctx.model?.provider !== PROVIDER_NAME) {
			// Other provider in use — clear our widget.
			ctx.ui.setWidget(STATUS_ID, undefined);
			return;
		}
		if (lastVerdict) {
			ctx.ui.setWidget(STATUS_ID, widgetLines(lastVerdict, ctx.ui.theme));
			return;
		}
		if (!resolveApiKey()) {
			ctx.ui.setWidget(
				STATUS_ID,
				widgetLinesIdle(ctx.ui.theme, `no API key — add "phala-tee" to ~/.pi/agent/auth.json`),
			);
			return;
		}
		ctx.ui.setWidget(STATUS_ID, widgetLinesIdle(ctx.ui.theme, "ready · awaiting first turn"));
	};

	pi.on("session_start", async (_event, ctx) => refreshWidget(ctx));
	pi.on("model_select", async (_event, ctx) => refreshWidget(ctx));

	pi.on("turn_end", async (event, ctx) => {
		const modelId = event.message.model;
		// We only verify turns that used a phala-tee model.
		// pi-ai sets `provider` on the AssistantMessage from the model config.
		const provider = (event.message as { provider?: string }).provider;
		if (provider !== PROVIDER_NAME) {
			// Active model isn't ours — make sure our widget isn't showing stale
			// content from a previous phala-tee turn.
			try {
				ctx.ui.setWidget(STATUS_ID, undefined);
			} catch {
				/* stale ctx */
			}
			return;
		}

		const apiKey = resolveApiKey();
		if (!apiKey) {
			ctx.ui.setWidget(STATUS_ID, widgetLinesIdle(ctx.ui.theme, "cannot verify — no API key"));
			return;
		}

		const record = findRecord();
		if (!record) {
			ctx.ui.setWidget(
				STATUS_ID,
				widgetLinesIdle(ctx.ui.theme, "no request record captured"),
			);
			return;
		}

		let verdict: Verdict;
		try {
			verdict = await verifyTurn({
				apiKey,
				record,
				appIdentityMode: settings.appIdentityMode,
				pinnedApps: settings.pinnedApps,
				allowedApps: settings.allowedApps,
				signingKeyCacheMs: settings.signingKeyCacheMs,
				signal: ctx.signal,
			});
		} catch (e) {
			const msg = e instanceof Error ? e.message : String(e);
			ctx.ui.setStatus(STATUS_ID, `✗ phala-tee: verification crashed: ${msg}`);
			return;
		}

		lastVerdict = verdict;

		// Persist evidence (no secrets) and possibly updated TOFU pins.
		appendAudit(settings.auditLogPath, verdict);
		try {
			saveSettings(settings);
		} catch {
			/* don't break the UI if settings write fails */
		}

		// In print mode (-p) the session may already be torn down by the time
		// this async handler completes. Any ctx.ui call would throw a
		// "stale context" error. Swallow those quietly — the audit log still
		// captured the verdict.
		try {
			ctx.ui.setWidget(STATUS_ID, widgetLines(verdict, ctx.ui.theme));
			if (verdict.overall === "fail") {
				ctx.ui.notify(
					`Phala TEE verification FAILED for ${modelId}: ${verdict.facets.find((f) => f.status === "fail")?.detail ?? verdict.error ?? "see /tee"}`,
					"error",
				);
			}
		} catch {
			/* stale ctx in print mode — verdict is in the audit log regardless */
		}
	});

	// /tee and ⌥T (alt+t) — expand into the full per-facet report.
	// ctrl+t is pi's "toggle thinking"; ctrl+shift+t clashes with pi-autoresearch.
	const showReport = (ctx: { ui: { theme: { fg(t: string, s: string): string }; notify: (m: string, k?: string) => void } }): void => {
		if (!lastVerdict) {
			ctx.ui.notify("No Phala TEE turn has been verified yet.", "info");
			return;
		}
		ctx.ui.notify(fullReport(lastVerdict, ctx.ui.theme), "info");
	};

	pi.registerCommand("tee", {
		description: "Show Phala TEE verification report for the last turn",
		handler: async (_args, ctx) => showReport(ctx),
	});

	pi.registerShortcut("alt+t", {
		description: "Show Phala TEE verification report (last turn)",
		handler: async (ctx) => showReport(ctx),
	});

	// /tee-trust — inspect and manage TOFU pins + allow-list.
	pi.registerCommand("tee-trust", {
		description: "Manage phala-tee app-identity trust policy (TOFU pins, allow-list)",
		handler: async (args, ctx) => {
			const sub = (args || "").trim().split(/\s+/)[0] || "show";
			if (sub === "show") {
				const lines: string[] = [];
				lines.push(`App-identity mode: ${settings.appIdentityMode}`);
				lines.push(`Strict mode:       ${settings.strictMode}`);
				lines.push(`Cache TTL:         ${Math.round(settings.signingKeyCacheMs / 1000)}s`);
				lines.push("");
				lines.push(`Pinned apps (${settings.pinnedApps.length}):`);
				for (const p of settings.pinnedApps) {
					lines.push(
						`  ${p.appId}  compose=${p.composeHash.slice(0, 16)}…  os=${p.osImageHash.slice(0, 16)}…  (first ${p.firstSeen})`,
					);
				}
				lines.push("");
				lines.push(`Allow-listed apps (strict mode; ${settings.allowedApps.length}):`);
				for (const p of settings.allowedApps) {
					lines.push(`  ${p.appId}  compose=${p.composeHash.slice(0, 16)}…`);
				}
				ctx.ui.notify(lines.join("\n"), "info");
			} else if (sub === "mode") {
				const newMode = args.split(/\s+/)[1];
				if (newMode !== "tofu" && newMode !== "strict" && newMode !== "permissive") {
					ctx.ui.notify("usage: /tee-trust mode <tofu|strict|permissive>", "error");
					return;
				}
				settings.appIdentityMode = newMode;
				saveSettings(settings);
				ctx.ui.notify(`phala-tee app-identity mode set to ${newMode}`, "info");
			} else if (sub === "reset-pins") {
				const ok = await ctx.ui.confirm(
					"Reset TOFU pins?",
					"All pinned app identities will be forgotten. They'll re-pin on next use.",
				);
				if (ok) {
					settings.pinnedApps = [];
					saveSettings(settings);
					ctx.ui.notify("phala-tee TOFU pins cleared.", "info");
				}
			} else if (sub === "promote-to-allow") {
				// Copy all current pins into the allow-list (for strict mode).
				settings.allowedApps = [...settings.pinnedApps.map((p) => ({ ...p }))];
				saveSettings(settings);
				ctx.ui.notify(
					`Promoted ${settings.allowedApps.length} pinned apps to allow-list.`,
					"info",
				);
			} else {
				ctx.ui.notify(
					"Subcommands: show | mode <tofu|strict|permissive> | reset-pins | promote-to-allow",
					"info",
				);
			}
		},
		getArgumentCompletions: (prefix) => {
			const opts = ["show", "mode", "reset-pins", "promote-to-allow"];
			const filtered = opts.filter((o) => o.startsWith(prefix));
			return filtered.length > 0 ? filtered.map((v) => ({ value: v, label: v })) : null;
		},
	});

	// Let power users see the raw last record for debugging.
	pi.registerCommand("tee-last", {
		description: "Inspect the last captured request/response record (phala-tee)",
		handler: async (_args, ctx) => {
			const r = lastRecord();
			if (!r) {
				ctx.ui.notify("No record yet.", "info");
				return;
			}
			const lines: string[] = [];
			lines.push(`chatId:  ${r.chatId ?? "(missing)"}`);
			lines.push(`model:   ${r.model ?? "(missing)"}`);
			lines.push(`stream:  ${r.streamed}`);
			lines.push(`status:  ${r.httpStatus}`);
			lines.push(`req:     ${r.requestBytes.length} bytes`);
			lines.push(`resp:    ${r.responseBytes?.length ?? 0} bytes`);
			lines.push(`latency: ${r.endedAt - r.startedAt} ms`);
			ctx.ui.notify(lines.join("\n"), "info");
		},
	});
}
