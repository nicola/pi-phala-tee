/**
 * Local TDX quote verification via the `dcap-qvl` binary.
 *
 * This verifies the Intel TDX attestation quote **locally** against Intel's
 * root of trust. The PCCS (Provisioning Certificate Caching Service) is just
 * a cache of Intel-signed PCK certs + TCB info + CRLs — a malicious PCCS can
 * only cause verification to fail, not to falsely succeed, because dcap-qvl
 * validates all ECDSA signatures up to Intel's root CA which is baked into
 * the binary. So using Phala's PCCS (default) or Intel's PCS directly
 * (override via PCCS_URL env) is cryptographically equivalent for ✓.
 *
 * We spawn the bundled `dcap-qvl` binary as a subprocess. This keeps the
 * verifier as audited Rust code written by Phala (public, upstream) rather
 * than us re-implementing DCAP in JS. The binary is shipped per-platform in
 * `bin/<platform>-<arch>/dcap-qvl`.
 *
 * If no binary for the current platform is bundled, callers should fall
 * back to the delegated verifier (⚠) and emit a clear message telling
 * users how to build one with `cargo` from
 * https://github.com/Phala-Network/dcap-qvl.
 */

import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const PLATFORM_DIR_MAP: Record<string, string | undefined> = {
	"darwin-arm64": "darwin-arm64",
	"darwin-x64": "darwin-x64",
	"linux-x64": "linux-x64",
	"linux-arm64": "linux-arm64",
	"win32-x64": "win32-x64",
};

function binDir(): string {
	// extension root is two levels up from this file (src/tdxLocal.ts → ../../)
	const here = dirname(fileURLToPath(import.meta.url));
	return join(here, "..", "bin");
}

export function findDcapBinary(): string | undefined {
	const key = `${process.platform}-${process.arch}`;
	const sub = PLATFORM_DIR_MAP[key];
	if (!sub) return undefined;
	const name = process.platform === "win32" ? "dcap-qvl.exe" : "dcap-qvl";
	const p = join(binDir(), sub, name);
	return existsSync(p) ? p : undefined;
}

export interface LocalTdxResult {
	ok: boolean;
	/** Verdict from dcap-qvl: UpToDate / OutOfDate / ConfigurationNeeded / ... */
	status?: string;
	advisoryIds?: string[];
	/** Decoded TD report (full). */
	report?: TdReport;
	/** PCCS used (for the detail string). */
	pccs?: string;
	/** On failure. */
	error?: string;
}

export interface TdReport {
	tee_tcb_svn?: string;
	mr_seam?: string;
	mr_signer_seam?: string;
	td_attributes?: string;
	xfam?: string;
	mr_td?: string;
	mr_config_id?: string;
	mr_owner?: string;
	mr_owner_config?: string;
	rt_mr0?: string;
	rt_mr1?: string;
	rt_mr2?: string;
	rt_mr3?: string;
	report_data?: string;
}

/**
 * Run `dcap-qvl verify --hex <quote_file>` and return a structured result.
 *
 * Timeout: 10s. Collateral fetch is the slow part (~400ms on a warm run)
 * — a 10s budget accommodates cold starts / PCCS hiccups without hanging pi.
 */
export async function verifyTdxLocal(
	intelQuoteHex: string,
	opts?: { pccsUrl?: string; signal?: AbortSignal; timeoutMs?: number },
): Promise<LocalTdxResult> {
	const bin = findDcapBinary();
	if (!bin) {
		return {
			ok: false,
			error: `dcap-qvl binary not bundled for ${process.platform}-${process.arch}. Build with \`cargo build --release\` from https://github.com/Phala-Network/dcap-qvl and place at bin/${process.platform}-${process.arch}/dcap-qvl`,
		};
	}

	// dcap-qvl reads the quote from a FILE. Write to a per-invocation tmpdir
	// so concurrent calls don't collide. Tmpdir is removed at end regardless
	// of outcome. We use mkdtempSync (not mkstempSync) because Node lacks the
	// latter; the random suffix is unpredictable enough.
	const dir = mkdtempSync(join(tmpdir(), "phala-tee-"));
	const quotePath = join(dir, "quote.hex");
	try {
		writeFileSync(quotePath, intelQuoteHex);

		const env: NodeJS.ProcessEnv = { ...process.env };
		if (opts?.pccsUrl) env.PCCS_URL = opts.pccsUrl;

		const result = await new Promise<{ stdout: string; stderr: string; code: number | null }>(
			(resolve, reject) => {
				const child = spawn(bin, ["verify", "--hex", quotePath], {
					env,
					stdio: ["ignore", "pipe", "pipe"],
				});
				let stdout = "";
				let stderr = "";
				child.stdout.on("data", (d: Buffer) => {
					stdout += d.toString();
				});
				child.stderr.on("data", (d: Buffer) => {
					stderr += d.toString();
				});
				const t = setTimeout(() => {
					child.kill("SIGKILL");
					reject(new Error("dcap-qvl timed out"));
				}, opts?.timeoutMs ?? 10_000);
				opts?.signal?.addEventListener("abort", () => {
					child.kill("SIGKILL");
					reject(new Error("aborted"));
				});
				child.on("error", (e) => {
					clearTimeout(t);
					reject(e);
				});
				child.on("close", (code) => {
					clearTimeout(t);
					resolve({ stdout, stderr, code });
				});
			},
		);

		if (result.code !== 0) {
			return {
				ok: false,
				error: `dcap-qvl exited ${result.code}: ${(result.stderr || result.stdout).slice(0, 400)}`,
			};
		}

		// dcap-qvl prints a "Getting collateral from <url>..." line on stdout,
		// then a JSON object, then a "Quote verified" line. We locate the JSON
		// as the longest line that starts with '{'.
		let jsonLine = "";
		let pccs: string | undefined;
		for (const line of result.stdout.split("\n")) {
			const t = line.trim();
			if (t.startsWith("Getting collateral from")) {
				pccs = t.replace(/^Getting collateral from\s+/, "").replace(/\.\.\.$/, "");
			} else if (t.startsWith("{")) {
				jsonLine = t;
			}
		}
		if (!jsonLine) {
			return { ok: false, error: `no JSON from dcap-qvl: ${result.stdout.slice(0, 200)}` };
		}

		const parsed = JSON.parse(jsonLine) as {
			status?: string;
			advisory_ids?: string[];
			report?: { TD10?: TdReport; TD15?: TdReport };
		};
		// Quote body is under TD10 or TD15 depending on TDX generation.
		const report = parsed.report?.TD10 ?? parsed.report?.TD15;
		return {
			ok: true,
			status: parsed.status,
			advisoryIds: parsed.advisory_ids,
			report,
			pccs,
		};
	} finally {
		try {
			rmSync(dir, { recursive: true, force: true });
		} catch {
			/* ignore */
		}
	}
}
