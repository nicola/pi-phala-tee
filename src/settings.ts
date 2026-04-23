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

export const SETTINGS_PATH = join(homedir(), ".pi", "agent", "phala-tee.json");

/** Thrown when phala-tee.json exists but cannot be parsed. Callers must
 * surface this to the user — silently resetting to defaults would wipe
 * the TOFU pin store, allowing an attacker who can corrupt the file to
 * force a re-pin against a malicious identity on the next turn.
 * https://github.com/nicola/pi-phala-tee/issues/5 */
export class SettingsCorruptError extends Error {
	readonly path: string;
	readonly cause: unknown;
	constructor(path: string, cause: unknown) {
		super(
			`phala-tee settings file is corrupt: ${path}\n` +
				`Refusing to continue. Inspect and fix the JSON, or move it aside to ` +
				`reset TOFU state intentionally. Reason: ${cause instanceof Error ? cause.message : String(cause)}`,
		);
		this.path = path;
		this.cause = cause;
		this.name = "SettingsCorruptError";
	}
}

function defaults(): ExtensionSettings {
	return {
		...DEFAULT_SETTINGS,
		auditLogPath: join(homedir(), ".pi", "agent", "tee-audit.jsonl"),
	};
}

export function loadSettings(): ExtensionSettings {
	if (!existsSync(SETTINGS_PATH)) return defaults();
	let raw: string;
	try {
		raw = readFileSync(SETTINGS_PATH, "utf8");
	} catch (e) {
		// A read failure (permissions, disk error) is different from corruption;
		// we still must NOT silently drop the pin store, so surface it.
		throw new SettingsCorruptError(SETTINGS_PATH, e);
	}
	let parsed: Partial<ExtensionSettings>;
	try {
		parsed = JSON.parse(raw) as Partial<ExtensionSettings>;
	} catch (e) {
		throw new SettingsCorruptError(SETTINGS_PATH, e);
	}
	return { ...defaults(), ...parsed };
}

export function saveSettings(s: ExtensionSettings): void {
	mkdirSync(dirname(SETTINGS_PATH), { recursive: true });
	// Write atomically-ish: tmp file + rename.
	const tmp = SETTINGS_PATH + ".tmp";
	writeFileSync(tmp, JSON.stringify(s, null, 2));
	// rename is atomic on POSIX.
	renameSync(tmp, SETTINGS_PATH);
}
