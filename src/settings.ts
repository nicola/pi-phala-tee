/**
 * Persistent settings for phala-tee.
 *
 * Lives at ~/.pi/agent/phala-tee.json (NOT in session state, so it survives
 * /new, /resume, and applies across projects).
 *
 * Contains:
 *   - appIdentityMode: tofu / strict / permissive
 *   - pinnedApps: TOFU pins accumulated over time
 *   - allowedApps: explicit allow-list for strict mode
 *   - signingKeyCacheMs: attestation cache TTL (min with JWT exp at runtime)
 *   - strictMode: fail-loud on any ✗ facet
 *
 * Explicitly NOT stored here: API keys.
 */

import { mkdirSync, readFileSync, renameSync, writeFileSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { DEFAULT_SETTINGS, type ExtensionSettings } from "./types.js";

const SETTINGS_PATH = join(homedir(), ".pi", "agent", "phala-tee.json");

export function loadSettings(): ExtensionSettings {
	if (!existsSync(SETTINGS_PATH)) {
		const s: ExtensionSettings = {
			...DEFAULT_SETTINGS,
			auditLogPath: join(homedir(), ".pi", "agent", "tee-audit.jsonl"),
		};
		return s;
	}
	try {
		const raw = readFileSync(SETTINGS_PATH, "utf8");
		const parsed = JSON.parse(raw) as Partial<ExtensionSettings>;
		return {
			...DEFAULT_SETTINGS,
			auditLogPath: join(homedir(), ".pi", "agent", "tee-audit.jsonl"),
			...parsed,
		};
	} catch {
		// If the settings file is corrupt, fail closed to defaults rather than
		// silently lose TOFU state. The user can inspect/fix the file manually.
		return { ...DEFAULT_SETTINGS, auditLogPath: join(homedir(), ".pi", "agent", "tee-audit.jsonl") };
	}
}

export function saveSettings(s: ExtensionSettings): void {
	mkdirSync(dirname(SETTINGS_PATH), { recursive: true });
	// Write atomically-ish: tmp file + rename.
	const tmp = SETTINGS_PATH + ".tmp";
	writeFileSync(tmp, JSON.stringify(s, null, 2));
	// rename is atomic on POSIX.
	renameSync(tmp, SETTINGS_PATH);
}
