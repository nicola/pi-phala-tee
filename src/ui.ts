/**
 * UX surfaces for phala-tee.
 *
 * Idiomatic pi styling:
 *   - Single-line widget above the editor.
 *   - Uses theme color tokens (success / warning / error / accent / dim /
 *     muted) so it adapts to light + dark + user themes.
 *   - Never lies: ⚠ is shown for warn facets, ✗ for fail, ✓ for ok, · for skip.
 *
 * Layout:
 *
 *     🛡  TEE verified       ●●●●●●●●        ⌥T for details
 *     🛡  TEE partial        ●●●●⚠●⚠●        ⌥T for details
 *     🛡  TEE UNVERIFIED     ●●✗●●●●●        ⌥T for details
 *
 *   - Shield (accent) + "TEE" (accent) + headline (success/warning/error).
 *   - Per-facet indicator row: one glyph per facet in order
 *       sig · req · resp · tdx · rd · gpu · app · fresh
 *     colored by that facet's status (green/yellow/red).
 *   - Shortcut hint (dim).
 */

import type { Facet, FacetStatus, Verdict } from "./types.js";

export interface ThemeLike {
	fg(token: string, text: string): string;
}

// Order shown in the indicator row. "transport" is cosmetic so we omit it.
const INDICATOR_ORDER: Facet["id"][] = [
	"sig",
	"req-bind",
	"resp-bind",
	"tdx",
	"reportdata",
	"gpu",
	"app",
	"fresh",
];

// Map each facet status to a theme color token + glyph. Glyphs come first
// because colorblind users should still be able to read the state.
const STATUS_GLYPH: Record<FacetStatus, string> = {
	ok: "●",
	warn: "⚠",
	fail: "✗",
	skip: "·",
};
const STATUS_COLOR: Record<FacetStatus, string> = {
	ok: "success",
	warn: "warning",
	fail: "error",
	skip: "dim",
};

/**
 * Render the single-line widget for `ctx.ui.setWidget(id, lines)`.
 * `theme` is `ctx.ui.theme`.
 */
export function widgetLines(v: Verdict, theme: ThemeLike): string[] {
	const shield = theme.fg("accent", "🛡 ");
	const tag = theme.fg("accent", " TEE ");

	let headline: string;
	switch (v.overall) {
		case "ok":
			headline = theme.fg("success", "verified");
			break;
		case "warn":
			headline = theme.fg("warning", "partial");
			break;
		case "fail":
			headline = theme.fg("error", "UNVERIFIED");
			break;
	}

	// Indicator row: one glyph per facet, colored by status, space-separated.
	const byId = new Map(v.facets.map((f) => [f.id, f]));
	const glyphs: string[] = [];
	for (const id of INDICATOR_ORDER) {
		const f = byId.get(id);
		if (!f) {
			glyphs.push(theme.fg("dim", STATUS_GLYPH.skip));
			continue;
		}
		glyphs.push(theme.fg(STATUS_COLOR[f.status], STATUS_GLYPH[f.status]));
	}
	const indicator = glyphs.join(" ");

	const hint = theme.fg("dim", "⌥T for details");

	return [`${shield}${tag} ${headline}   ${indicator}   ${hint}`];
}

/** Placeholder line when there's no verdict yet (e.g. before first turn). */
export function widgetLinesIdle(theme: ThemeLike, message: string): string[] {
	const shield = theme.fg("accent", "🛡 ");
	const tag = theme.fg("accent", " TEE ");
	return [`${shield}${tag} ${theme.fg("dim", message)}`];
}

/**
 * Full per-facet report shown when the user presses ⇧T or runs /tee.
 * Uses theme colors but is a plain string with newlines so it works with
 * `ctx.ui.notify(..., "info")`.
 */
export function fullReport(v: Verdict, theme: ThemeLike): string {
	const out: string[] = [];
	const title = overallTitle(v.overall, theme);
	const rule = theme.fg("dim", "─".repeat(60));
	out.push(title);
	out.push(rule);

	out.push(
		`${theme.fg("muted", "Model")}        ${v.model ?? theme.fg("dim", "(unknown)")}`,
	);
	out.push(
		`${theme.fg("muted", "Chat ID")}      ${v.chatId ?? theme.fg("dim", "(unknown)")}`,
	);
	if (v.signingAddress) {
		out.push(
			`${theme.fg("muted", "Signer")}       ${theme.fg("accent", v.signingAddress)}`,
		);
	}
	if (v.appId) {
		out.push(`${theme.fg("muted", "App ID")}       ${v.appId}`);
	}
	if (v.trustCenterUrl) {
		out.push(
			`${theme.fg("muted", "Trust Center")} ${theme.fg("accent", v.trustCenterUrl)}`,
		);
	}
	out.push(
		`${theme.fg("muted", "Verified at")}  ${new Date(v.verifiedAt).toISOString()}`,
	);
	out.push("");
	out.push(theme.fg("muted", "Facets:"));
	for (const f of v.facets) {
		const g = theme.fg(STATUS_COLOR[f.status], STATUS_GLYPH[f.status]);
		const label = labelForId(f.id);
		out.push(`  ${g}  ${pad(label, 14)}  ${f.detail}`);
	}

	if (v.evidence) {
		out.push("");
		out.push(theme.fg("muted", "Evidence (full record in audit log):"));
		const dim = (s: string) => theme.fg("dim", s);
		out.push(`  ${dim("text           ")}${v.evidence.text}`);
		out.push(`  ${dim("signature      ")}${v.evidence.signature.slice(0, 40)}…`);
		out.push(`  ${dim("request sha256 ")}${v.evidence.requestSha256 ?? "(not computed)"}`);
		out.push(
			`  ${dim("resp sha256    ")}${v.evidence.responseSha256 ?? "(streamed / not computed)"}`,
		);
		out.push(`  ${dim("attest nonce   ")}${v.evidence.attestationNonce}`);
		out.push(`  ${dim("intel_quote    ")}${v.evidence.intelQuoteHex.length} hex chars`);
		out.push(`  ${dim("nvidia_payload ")}${v.evidence.nvidiaPayload.length} chars`);
	}
	if (v.error) {
		out.push("");
		out.push(theme.fg("error", `ERROR: ${v.error}`));
	}
	out.push("");
	out.push(theme.fg("muted", "Trust roots:"));
	out.push(theme.fg("dim", "  sig      secp256k1 / ed25519 verified locally"));
	out.push(theme.fg("dim", "  req/resp sha256 of wire bytes (local) vs server-signed hash"));
	out.push(theme.fg("dim", "  gpu      NRAS JWT verified against NVIDIA JWKS locally (ES384)"));
	out.push(
		theme.fg(
			"dim",
			"  tdx      verified locally by bundled dcap-qvl against Intel root",
		),
	);
	out.push(
		theme.fg(
			"dim",
			"           (or ⚠ delegated to cloud-api.phala.com if binary is missing)",
		),
	);
	out.push(theme.fg("dim", "  app      TOFU / strict / permissive — see /tee-trust"));
	return out.join("\n");
}

function overallTitle(overall: Verdict["overall"], theme: ThemeLike): string {
	switch (overall) {
		case "ok":
			return theme.fg("success", "🛡  Phala TEE verification — all checks passed");
		case "warn":
			return theme.fg(
				"warning",
				"🛡  Phala TEE verification — partial (honest ⚠ where trust is delegated or first-seen)",
			);
		case "fail":
			return theme.fg("error", "🛡  Phala TEE verification FAILED — do not trust this response");
	}
}

function labelForId(id: Facet["id"]): string {
	switch (id) {
		case "transport":
			return "transport";
		case "sig":
			return "sig";
		case "req-bind":
			return "req-bind";
		case "resp-bind":
			return "resp-bind";
		case "tdx":
			return "tdx";
		case "reportdata":
			return "reportdata";
		case "gpu":
			return "gpu";
		case "app":
			return "app";
		case "fresh":
			return "fresh";
	}
}

function pad(s: string, n: number): string {
	return s.length >= n ? s : s + " ".repeat(n - s.length);
}
