/**
 * End-to-end verification for one completed Phala TEE LLM turn.
 *
 * Pipeline:
 *   1. Fetch /v1/signature/{chat_id} → `{text, signature, signing_address, signing_algo}`.
 *   2. Verify signature → address (ECDSA secp256k1 EIP-191 or Ed25519). Facet: `sig`.
 *   3. sha256(requestBytes) == text[:64]                                   Facet: `req-bind`.
 *   4. sha256(canonical(responseJson)) == text[65:]  (non-streaming only)  Facet: `resp-bind`.
 *   5. Generate fresh nonce; GET /v1/attestation/report?signing_address.
 *   6. POST quote.intel_quote to cloud-api.phala.com — DELEGATED in v0.    Facet: `tdx` (⚠).
 *   7. Parse quote.body.reportdata:
 *        - bytes [0..20) == signing_address  (right-padded to 32 bytes)
 *        - bytes [32..64) == our nonce                                     Facet: `reportdata`.
 *   8. POST nvidia_payload to nras.attestation.nvidia.com → JWT.
 *      Verify JWT signature locally against NRAS JWKS (ES384 / P-384).
 *      Check `x-nvidia-overall-att-result:true` and `eat_nonce==our_nonce`. Facet: `gpu`.
 *   9. Extract app_id, compose-hash, os-image-hash from event_log.
 *      Enforce TOFU / strict / permissive policy.                          Facet: `app`.
 *  10. Freshness: NRAS JWT `exp > now`, our nonce covered end-to-end.      Facet: `fresh`.
 *
 * Every facet can only become ✓ if the check was executed and passed.
 * Any network/JSON/parse error → ⚠ (or ✗ on cryptographic contradiction).
 * API key is read only via the `apiKey` argument; never logged.
 */

import { canonicalize } from "./canonical.js";
import {
	bytesToHex,
	constantTimeEq,
	ecdsaRecoverEthAddress,
	ed25519Verify,
	hexToBytes,
	JwtKidNotFoundError,
	jwtVerifyES384,
	type JwksKey,
	sha256Hex,
} from "./crypto.js";
import { rawFetch, type TurnRecord } from "./fetchIntercept.js";
import { findDcapBinary, verifyTdxLocal, type TdReport } from "./tdxLocal.js";
import type { AppPin, Evidence, Facet, FacetStatus, Verdict } from "./types.js";

const BASE = "https://api.redpill.ai/v1";
const PHALA_VERIFIER = "https://cloud-api.phala.com/api/v1/attestations/verify";
const NRAS_URL = "https://nras.attestation.nvidia.com/v3/attest/gpu";
const NRAS_JWKS = "https://nras.attestation.nvidia.com/.well-known/jwks.json";

// JWKS cache — NRAS certs rotate ~every 2 days. Cache for 1 hour.
let jwksCache: { fetchedAt: number; keys: JwksKey[] } | undefined;
const JWKS_TTL = 60 * 60 * 1000;

// Signing-key attestation cache. Keyed by signing_address.
//
// We cache the facets that are properties of the TEE itself (tdx, gpu,
// reportdata) plus the parsed app-identity *evidence* — but we RE-EVALUATE
// the app facet every turn, because the user's policy (pins/allow-list)
// can change between turns, and a first-use TOFU pin must upgrade from ⚠
// to ✓ on subsequent intact matches.
interface CachedAtt {
	expiresAt: number;
	tdxFacet: Facet;
	reportdataFacet: Facet;
	gpuFacet: Facet;
	appId: string | undefined;
	composeHash: string | undefined;
	osImageHash: string | undefined;
	keyProvider: string | undefined;
	/** Was TDX verified locally (so mr_config_id binding could be checked)? Needed
	 * to reproduce the delegated-TDX app-facet downgrade on cache-hit turns. */
	localTdxVerified: boolean;
	mrConfigBinding: "ok" | "mismatch" | "unchecked";
	evidence: Pick<Evidence, "attestationNonce" | "intelQuoteHex" | "nvidiaPayload" | "info" | "vmConfig" | "eventLog">;
}
const attCache = new Map<string, CachedAtt>();

export interface VerifyInput {
	apiKey: string;
	record: TurnRecord;
	/** App-identity policy and state (TOFU pin store). Mutated in place if pinning. */
	appIdentityMode: "tofu" | "strict" | "permissive";
	pinnedApps: AppPin[];
	allowedApps: AppPin[];
	signingKeyCacheMs: number;
	signal?: AbortSignal;
}

export async function verifyTurn(input: VerifyInput): Promise<Verdict> {
	const facets: Facet[] = [];
	const now = Date.now();
	const { record } = input;

	const chatId = record.chatId;
	const model = record.model;
	if (!chatId || !model) {
		return fail("missing chat_id or model — cannot verify", record.model);
	}

	facets.push({ id: "transport", label: "TLS", status: "ok", detail: "HTTPS to api.redpill.ai" });

	// --- 1. Fetch signature
	let sig: SignaturePayload;
	try {
		sig = await fetchJson<SignaturePayload>(
			`${BASE}/signature/${encodeURIComponent(chatId)}?model=${encodeURIComponent(model)}`,
			input.apiKey,
			input.signal,
		);
	} catch (e) {
		return fail(`signature fetch failed: ${errStr(e)}`, model, chatId);
	}
	const { text, signature, signing_address, signing_algo } = sig;
	const algo = (signing_algo || "ecdsa") as "ecdsa" | "ed25519";

	// --- 2. Verify signature → address
	facets.push(verifySignatureFacet(text, signature, signing_address, algo));

	// --- 3. Request-byte hash binding
	const [signedReqHash, signedRespHash] = text.split(":");
	const reqHashHex = sha256Hex(record.requestBytes);
	facets.push({
		id: "req-bind",
		label: "request content binding",
		status: reqHashHex === signedReqHash ? "ok" : "fail",
		detail:
			reqHashHex === signedReqHash
				? `sha256(request) matches signed hash`
				: `sha256 mismatch: ours=${reqHashHex.slice(0, 16)}… signed=${signedReqHash.slice(0, 16)}…`,
	});

	// --- 4. Response-byte hash binding (non-streaming only)
	facets.push(responseBindFacet(record, signedRespHash));

	// --- 5-9: attestation (cached per signing_address)
	const cached = attCache.get(signing_address.toLowerCase());
	if (cached && cached.expiresAt > now) {
		facets.push(markCached(cached.tdxFacet));
		facets.push(markCached(cached.reportdataFacet));
		facets.push(markCached(cached.gpuFacet));
		// Re-evaluate app identity fresh (see comment on CachedAtt).
		let cachedAppFacet = evaluateAppIdentity(
			cached.appId,
			cached.composeHash,
			cached.osImageHash,
			cached.keyProvider,
			input,
			cached.mrConfigBinding,
		);
		if (!cached.localTdxVerified && cachedAppFacet.status === "ok") {
			cachedAppFacet = {
				...cachedAppFacet,
				status: "warn",
				detail: `${cachedAppFacet.detail} · TDX delegated — compose-hash NOT cross-checked against mr_config_id`,
			};
		}
		facets.push(cachedAppFacet);
		facets.push({
			id: "fresh",
			label: "freshness",
			status: "ok",
			detail: `signing key attested ${Math.round((now - (cached.expiresAt - input.signingKeyCacheMs)) / 1000)}s ago (cache TTL ${Math.round(input.signingKeyCacheMs / 1000)}s)`,
		});
		return finalize(
			facets,
			model,
			chatId,
			signing_address,
			cached.appId,
			buildEvidence(chatId, model, signing_address, algo, text, signature, reqHashHex, currentRespHash(record), "", "", "", cached.evidence),
		);
	}

	// Fresh attestation fetch
	const nonce = randomNonceHex();
	let report: AttestationReport;
	try {
		report = await fetchJson<AttestationReport>(
			`${BASE}/attestation/report?model=${encodeURIComponent(model)}&nonce=${nonce}&signing_address=${encodeURIComponent(signing_address)}`,
			input.apiKey,
			input.signal,
		);
	} catch (e) {
		facets.push({ id: "tdx", label: "Intel TDX quote", status: "warn", detail: `attestation fetch failed: ${errStr(e)}` });
		facets.push({ id: "reportdata", label: "reportdata binding", status: "warn", detail: "skipped — attestation unavailable" });
		facets.push({ id: "gpu", label: "NVIDIA GPU CC", status: "warn", detail: "skipped — attestation unavailable" });
		facets.push({ id: "app", label: "app identity", status: "warn", detail: "skipped — attestation unavailable" });
		facets.push({ id: "fresh", label: "freshness", status: "warn", detail: "no fresh attestation" });
		return finalize(facets, model, chatId, signing_address, undefined);
	}

	// If multi-server, pick the entry matching our signing_address
	let att: AttestationReport = report;
	if (Array.isArray(report.all_attestations) && report.all_attestations.length > 0) {
		att =
			report.all_attestations.find(
				(a) => (a.signing_address || "").toLowerCase() === signing_address.toLowerCase(),
			) ?? report;
	}

	// --- 6. Intel TDX.
	// Prefer local dcap-qvl verification against Intel's root-of-trust.
	// Fall back to cloud-api.phala.com only if no binary is bundled for this
	// platform (honest ⚠ with a clear message).
	let tdxFacet: Facet;
	let tdxReportDataHex: string | undefined;
	let tdReport: TdReport | undefined;
	if (findDcapBinary()) {
		const local = await verifyTdxLocal(att.intel_quote, { signal: input.signal });
		if (!local.ok) {
			tdxFacet = {
				id: "tdx",
				label: "Intel TDX quote",
				status: "fail",
				detail: `local dcap-qvl: ${local.error}`,
			};
		} else if (local.status === "UpToDate") {
			tdxFacet = {
				id: "tdx",
				label: "Intel TDX quote",
				status: "ok",
				detail: `locally verified (dcap-qvl, Intel root); TCB UpToDate${local.pccs ? `; collateral from ${local.pccs}` : ""}`,
			};
			tdReport = local.report;
			tdxReportDataHex = local.report?.report_data;
		} else {
			// Crypto check passed but platform TCB is not current — honest ⚠.
			tdxFacet = {
				id: "tdx",
				label: "Intel TDX quote",
				status: "warn",
				detail: `locally verified, but TCB status=${local.status}${(local.advisoryIds || []).length ? ` (${local.advisoryIds!.join(",")})` : ""}`,
			};
			tdReport = local.report;
			tdxReportDataHex = local.report?.report_data;
		}
	} else {
		const del = await verifyTdxDelegated(att.intel_quote, input.signal);
		tdxFacet = del.ok
			? {
					id: "tdx",
					label: "Intel TDX quote",
					status: "warn",
					detail: `verified by cloud-api.phala.com (delegated — bundle dcap-qvl for ${process.platform}-${process.arch} to upgrade to ✓)`,
				}
			: {
					id: "tdx",
					label: "Intel TDX quote",
					status: "fail",
					detail: `verification failed: ${del.error}`,
				};
		tdxReportDataHex = del.reportDataHex;
	}
	facets.push(tdxFacet);

	// --- 7. reportdata binding
	const rdFacet = verifyReportDataFacet(tdxReportDataHex, signing_address, algo, nonce);
	facets.push(rdFacet);

	// --- 8. NVIDIA GPU CC
	const gpuFacet = await verifyGpuFacet(att.nvidia_payload, nonce, input.signal);
	facets.push(gpuFacet);

	// --- 9. App identity
	const parsedEventLog = parseMaybeJson(att.event_log) as EventLogEntry[] | undefined;
	const parsedInfo = parseMaybeJson(att.info) as { app_id?: string; instance_id?: string } | undefined;
	const parsedVmConfig = parseMaybeJson(att.vm_config) as { os_image_hash?: string } | undefined;
	const appId = parsedInfo?.app_id ?? findEvent(parsedEventLog, "app-id");
	const composeHash = findEvent(parsedEventLog, "compose-hash");
	const osImageHash = parsedVmConfig?.os_image_hash ?? findEvent(parsedEventLog, "os-image-hash");
	const keyProvider = findEvent(parsedEventLog, "key-provider");
	// Bonus: if local TDX verification succeeded, we can also check that the
	// TDX mr_config_id field cryptographically binds the compose-hash to the
	// quote itself — this is a stronger check than trusting the event_log
	// field alone. The dstack convention is mr_config_id = 0x01 || compose-hash
	// (the leading 0x01 is a domain-separation byte; the remaining 32 bytes
	// are the SHA-256 compose-hash, followed by 15 zero bytes of padding to
	// reach the 48-byte mr_config_id size).
	let mrConfigBinding: "ok" | "mismatch" | "unchecked" = "unchecked";
	if (tdReport?.mr_config_id && composeHash) {
		try {
			const mrc = hexToBytes(tdReport.mr_config_id);
			const wantComposeBytes = hexToBytes(composeHash);
			// Look for the compose-hash bytes anywhere in mr_config_id. The
			// dstack ABI places them at offset 1, but we match loosely to be
			// resilient to format tweaks; any exact substring match is still a
			// strong crypto binding (random collision is ~2^-256).
			let found = false;
			for (let i = 0; i + wantComposeBytes.length <= mrc.length; i++) {
				let eq = true;
				for (let j = 0; j < wantComposeBytes.length; j++) {
					if (mrc[i + j] !== wantComposeBytes[j]) {
						eq = false;
						break;
					}
				}
				if (eq) {
					found = true;
					break;
				}
			}
			mrConfigBinding = found ? "ok" : "mismatch";
		} catch {
			mrConfigBinding = "unchecked";
		}
	}

	let appFacet = evaluateAppIdentity(
		appId,
		composeHash,
		osImageHash,
		keyProvider,
		input,
		mrConfigBinding,
	);
	// HIGH: on delegated-TDX platforms we have no `tdReport`, so we could
	// NOT cross-check compose-hash against the TDX-signed mr_config_id. A
	// compromised cloud-api.phala.com could return `verified: true` while
	// the server crafts a matching event_log compose-hash. Refuse to show
	// ✓ in that case — downgrade to ⚠ with an explicit reason. See:
	// https://github.com/nicola/pi-phala-tee/issues/1
	if (!tdReport && appFacet.status === "ok") {
		appFacet = {
			...appFacet,
			status: "warn",
			detail: `${appFacet.detail} · TDX delegated — compose-hash NOT cross-checked against mr_config_id`,
		};
	}
	facets.push(appFacet);

	// --- 10. Freshness
	facets.push({
		id: "fresh",
		label: "freshness",
		status:
			rdFacet.status === "ok" && gpuFacet.status === "ok"
				? "ok"
				: rdFacet.status === "fail" || gpuFacet.status === "fail"
					? "fail"
					: "warn",
		detail: `attestation nonce ${nonce.slice(0, 16)}… bound in reportdata=${rdFacet.status} gpu=${gpuFacet.status}`,
	});

	// Cache for next turn if all critical facets passed
	if (
		tdxFacet.status !== "fail" &&
		rdFacet.status === "ok" &&
		(gpuFacet.status === "ok" || gpuFacet.status === "warn") &&
		appFacet.status !== "fail"
	) {
		const cacheEntry: CachedAtt = {
			expiresAt: now + input.signingKeyCacheMs,
			tdxFacet,
			reportdataFacet: rdFacet,
			gpuFacet,
			appId,
			composeHash,
			osImageHash,
			keyProvider,
			localTdxVerified: Boolean(tdReport),
			mrConfigBinding,
			evidence: {
				attestationNonce: nonce,
				intelQuoteHex: att.intel_quote,
				nvidiaPayload: att.nvidia_payload,
				info: parsedInfo,
				vmConfig: parsedVmConfig,
				eventLog: parsedEventLog,
			},
		};
		attCache.set(signing_address.toLowerCase(), cacheEntry);
	}

	const evidence = buildEvidence(
		chatId,
		model,
		signing_address,
		algo,
		text,
		signature,
		reqHashHex,
		currentRespHash(record),
		nonce,
		att.intel_quote,
		att.nvidia_payload,
		{ attestationNonce: nonce, intelQuoteHex: att.intel_quote, nvidiaPayload: att.nvidia_payload, info: parsedInfo, vmConfig: parsedVmConfig, eventLog: parsedEventLog },
	);
	return finalize(facets, model, chatId, signing_address, appId, evidence);
}

// -----------------------------------------------------------------------------
// Facet implementations
// -----------------------------------------------------------------------------

function verifySignatureFacet(
	text: string,
	signature: string,
	claimedAddress: string,
	algo: "ecdsa" | "ed25519",
): Facet {
	try {
		if (algo === "ecdsa") {
			const recovered = ecdsaRecoverEthAddress(text, signature);
			const ok = recovered.toLowerCase() === claimedAddress.toLowerCase();
			return {
				id: "sig",
				label: "signature",
				status: ok ? "ok" : "fail",
				detail: ok
					? `EIP-191 ECDSA → ${recovered}`
					: `recovered ${recovered} ≠ claimed ${claimedAddress}`,
			};
		} else {
			const ok = ed25519Verify(text, signature, claimedAddress);
			return {
				id: "sig",
				label: "signature",
				status: ok ? "ok" : "fail",
				detail: ok ? `Ed25519 → ${claimedAddress}` : "Ed25519 verification failed",
			};
		}
	} catch (e) {
		return { id: "sig", label: "signature", status: "fail", detail: `signature error: ${errStr(e)}` };
	}
}

function responseBindFacet(record: TurnRecord, signedRespHash: string): Facet {
	if (record.streamed) {
		return {
			id: "resp-bind",
			label: "response content binding",
			status: "warn",
			detail: "streamed response — server canonical form is not client-reproducible; use non-streaming for ✓",
		};
	}
	if (!record.responseBytes) {
		return {
			id: "resp-bind",
			label: "response content binding",
			status: "warn",
			detail: "response bytes not captured",
		};
	}
	try {
		const obj = JSON.parse(new TextDecoder().decode(record.responseBytes));
		const canonical = canonicalize(obj);
		const hash = sha256Hex(canonical);
		return {
			id: "resp-bind",
			label: "response content binding",
			status: hash === signedRespHash ? "ok" : "fail",
			detail:
				hash === signedRespHash
					? "sha256(canonical(response_json)) matches signed hash"
					: `sha256 mismatch: ours=${hash.slice(0, 16)}… signed=${signedRespHash.slice(0, 16)}…`,
		};
	} catch (e) {
		return {
			id: "resp-bind",
			label: "response content binding",
			status: "warn",
			detail: `cannot canonicalize: ${errStr(e)}`,
		};
	}
}

async function verifyTdxDelegated(
	intelQuoteHex: string,
	signal?: AbortSignal,
): Promise<{ ok: boolean; reportDataHex?: string; error?: string }> {
	try {
		const r = await rawFetch()(PHALA_VERIFIER, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ hex: intelQuoteHex }),
			signal,
		});
		if (!r.ok) return { ok: false, error: `HTTP ${r.status}` };
		const body = (await r.json()) as {
			quote?: { verified?: boolean; body?: { reportdata?: string; report_data?: string } };
		};
		if (!body.quote?.verified) return { ok: false, error: "quote.verified=false" };
		const rd = body.quote.body?.reportdata ?? body.quote.body?.report_data;
		return { ok: true, reportDataHex: rd };
	} catch (e) {
		return { ok: false, error: errStr(e) };
	}
}

function verifyReportDataFacet(
	reportDataHex: string | undefined,
	signingAddress: string,
	algo: "ecdsa" | "ed25519",
	nonce: string,
): Facet {
	if (!reportDataHex) {
		return { id: "reportdata", label: "reportdata binding", status: "warn", detail: "reportdata not returned by verifier" };
	}
	try {
		const rd = hexToBytes(reportDataHex);
		if (rd.length !== 64) {
			return { id: "reportdata", label: "reportdata binding", status: "fail", detail: `reportdata is ${rd.length} bytes, expected 64` };
		}
		const embeddedAddr = rd.slice(0, 32);
		const embeddedNonce = rd.slice(32, 64);

		// Phala's convention is right-padded (address occupies bytes [0..20),
		// remaining bytes in the 32-byte slot are zero). Docs incorrectly say
		// left-padded; we verified empirically.
		let addrOk = false;
		if (algo === "ecdsa") {
			const addr = hexToBytes(signingAddress);
			if (addr.length !== 20) {
				return { id: "reportdata", label: "reportdata binding", status: "fail", detail: `signing_address wrong length: ${addr.length}` };
			}
			const expected = new Uint8Array(32);
			expected.set(addr, 0); // right-pad with zeros
			addrOk = constantTimeEq(embeddedAddr, expected);
		} else {
			const pk = hexToBytes(signingAddress);
			if (pk.length !== 32) {
				return { id: "reportdata", label: "reportdata binding", status: "fail", detail: `ed25519 pubkey wrong length: ${pk.length}` };
			}
			addrOk = constantTimeEq(embeddedAddr, pk);
		}

		const nonceBytes = hexToBytes(nonce);
		const nonceOk = constantTimeEq(embeddedNonce, nonceBytes);

		if (addrOk && nonceOk) {
			return { id: "reportdata", label: "reportdata binding", status: "ok", detail: "signing_address and nonce bound in TDX quote" };
		}
		return {
			id: "reportdata",
			label: "reportdata binding",
			status: "fail",
			detail: `addr_bound=${addrOk} nonce_bound=${nonceOk}`,
		};
	} catch (e) {
		return { id: "reportdata", label: "reportdata binding", status: "fail", detail: `parse error: ${errStr(e)}` };
	}
}

async function verifyGpuFacet(
	nvidiaPayloadStr: string,
	expectedNonceHex: string,
	signal?: AbortSignal,
): Promise<Facet> {
	let payload: { nonce?: string };
	try {
		payload = JSON.parse(nvidiaPayloadStr) as { nonce?: string };
	} catch (e) {
		return { id: "gpu", label: "NVIDIA GPU CC", status: "fail", detail: `nvidia_payload parse: ${errStr(e)}` };
	}
	if (!payload.nonce || payload.nonce.toLowerCase() !== expectedNonceHex.toLowerCase()) {
		return { id: "gpu", label: "NVIDIA GPU CC", status: "fail", detail: "nvidia_payload nonce does not match our nonce" };
	}

	let jwks: JwksKey[];
	try {
		jwks = await getNrasJwks(signal);
	} catch (e) {
		return { id: "gpu", label: "NVIDIA GPU CC", status: "warn", detail: `NRAS JWKS fetch failed: ${errStr(e)}` };
	}

	let jwt: string | undefined;
	try {
		const r = await rawFetch()(NRAS_URL, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify(payload),
			signal,
		});
		if (!r.ok) return { id: "gpu", label: "NVIDIA GPU CC", status: "warn", detail: `NRAS HTTP ${r.status}` };
		const result = (await r.json()) as unknown;
		// NRAS returns a list of [key, jwt] pairs.
		if (Array.isArray(result) && result.length && Array.isArray(result[0]) && result[0].length >= 2) {
			jwt = result[0][1] as string;
		}
		if (!jwt) return { id: "gpu", label: "NVIDIA GPU CC", status: "warn", detail: "NRAS response missing JWT" };
	} catch (e) {
		return { id: "gpu", label: "NVIDIA GPU CC", status: "warn", detail: `NRAS fetch: ${errStr(e)}` };
	}

	// Verify the JWT. If the kid is missing from our JWKS cache, NRAS likely
	// rotated its signing key since we cached. Invalidate and retry once
	// before giving up. https://github.com/nicola/pi-phala-tee/issues/4
	let verdictBody: Record<string, unknown>;
	try {
		const ver = jwtVerifyES384(jwt, jwks);
		verdictBody = ver.payload;
	} catch (e) {
		if (e instanceof JwtKidNotFoundError) {
			try {
				invalidateJwksCache();
				const fresh = await getNrasJwks(signal, true);
				const ver = jwtVerifyES384(jwt, fresh);
				verdictBody = ver.payload;
			} catch (e2) {
				return {
					id: "gpu",
					label: "NVIDIA GPU CC",
					status: "fail",
					detail: `NRAS JWT verify (after JWKS refresh): ${errStr(e2)}`,
				};
			}
		} else {
			return { id: "gpu", label: "NVIDIA GPU CC", status: "fail", detail: `NRAS JWT verify: ${errStr(e)}` };
		}
	}

	const overall = verdictBody["x-nvidia-overall-att-result"];
	const eatNonce = verdictBody.eat_nonce;
	const exp = typeof verdictBody.exp === "number" ? verdictBody.exp : 0;
	const now = Math.floor(Date.now() / 1000);
	if (overall !== true) {
		return { id: "gpu", label: "NVIDIA GPU CC", status: "fail", detail: `x-nvidia-overall-att-result=${String(overall)}` };
	}
	if (typeof eatNonce !== "string" || eatNonce.toLowerCase() !== expectedNonceHex.toLowerCase()) {
		return { id: "gpu", label: "NVIDIA GPU CC", status: "fail", detail: "NRAS JWT eat_nonce mismatch" };
	}
	if (exp && exp < now) {
		return { id: "gpu", label: "NVIDIA GPU CC", status: "warn", detail: `NRAS JWT expired (exp=${exp})` };
	}
	return { id: "gpu", label: "NVIDIA GPU CC", status: "ok", detail: `NRAS JWT verified (ES384); overall=true; nonce bound; exp=${exp}` };
}

function evaluateAppIdentity(
	appId: string | undefined,
	composeHash: string | undefined,
	osImageHash: string | undefined,
	keyProvider: string | undefined,
	input: VerifyInput,
	mrConfigBinding: "ok" | "mismatch" | "unchecked",
): Facet {
	if (mrConfigBinding === "mismatch") {
		return {
			id: "app",
			label: "app identity",
			status: "fail",
			detail:
				"TDX mr_config_id does not contain the compose-hash claimed by event_log — app identity is lying",
		};
	}
	if (!appId || !composeHash) {
		return { id: "app", label: "app identity", status: "warn", detail: "app_id or compose-hash missing from attestation" };
	}
	const bindingSuffix =
		mrConfigBinding === "ok" ? " · compose-hash bound in TDX mr_config_id" : "";
	const current: AppPin = {
		appId,
		composeHash,
		osImageHash: osImageHash ?? "",
		keyProvider,
		firstSeen: new Date().toISOString(),
		lastSeen: new Date().toISOString(),
	};

	if (input.appIdentityMode === "permissive") {
		return {
			id: "app",
			label: "app identity",
			status: "warn",
			detail: `permissive mode: app ${appId} @ compose ${composeHash.slice(0, 12)}… accepted without pin${bindingSuffix}`,
		};
	}

	if (input.appIdentityMode === "strict") {
		const match = input.allowedApps.find(
			(p) =>
				p.appId === current.appId &&
				p.composeHash === current.composeHash &&
				(p.osImageHash === "" || p.osImageHash === current.osImageHash),
		);
		if (match) {
			return { id: "app", label: "app identity", status: "ok", detail: `allow-listed (${appId.slice(0, 12)}… / compose ${composeHash.slice(0, 12)}…)${bindingSuffix}` };
		}
		return {
			id: "app",
			label: "app identity",
			status: "fail",
			detail: `strict mode: app ${appId} / compose ${composeHash.slice(0, 12)}… not in allow-list`,
		};
	}

	// TOFU
	const pinned = input.pinnedApps.find((p) => p.appId === appId);
	if (!pinned) {
		// First encounter — pin it.
		input.pinnedApps.push(current);
		return {
			id: "app",
			label: "app identity",
			status: "warn",
			detail: `TOFU: pinned app ${appId.slice(0, 12)}… / compose ${composeHash.slice(0, 12)}… on first use — verify manually at trust.phala.com${bindingSuffix}`,
		};
	}
	const changed: string[] = [];
	if (pinned.composeHash !== composeHash) changed.push("compose-hash");
	if (pinned.osImageHash && osImageHash && pinned.osImageHash !== osImageHash) changed.push("os-image-hash");
	if (pinned.keyProvider && keyProvider && pinned.keyProvider !== keyProvider) changed.push("key-provider");
	if (changed.length > 0) {
		return {
			id: "app",
			label: "app identity",
			status: "fail",
			detail: `TOFU pin broken: ${changed.join(", ")} changed since first use. Inspect via trust.phala.com or re-pin intentionally.`,
		};
	}
	pinned.lastSeen = new Date().toISOString();
	return {
		id: "app",
		label: "app identity",
		status: "ok",
		detail: `TOFU pin intact (${appId.slice(0, 12)}… / compose ${composeHash.slice(0, 12)}…)${bindingSuffix}`,
	};
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

async function getNrasJwks(signal?: AbortSignal, forceRefresh = false): Promise<JwksKey[]> {
	const now = Date.now();
	if (!forceRefresh && jwksCache && now - jwksCache.fetchedAt < JWKS_TTL) return jwksCache.keys;
	const r = await rawFetch()(NRAS_JWKS, { signal });
	if (!r.ok) throw new Error(`JWKS HTTP ${r.status}`);
	const body = (await r.json()) as { keys?: JwksKey[] };
	if (!Array.isArray(body.keys)) throw new Error("JWKS: missing keys");
	jwksCache = { fetchedAt: now, keys: body.keys };
	return body.keys;
}

function invalidateJwksCache(): void {
	jwksCache = undefined;
}

async function fetchJson<T>(url: string, apiKey: string, signal?: AbortSignal): Promise<T> {
	const r = await rawFetch()(url, {
		headers: { Authorization: `Bearer ${apiKey}` },
		signal,
	});
	if (!r.ok) throw new Error(`HTTP ${r.status} ${r.statusText}`);
	return (await r.json()) as T;
}

function randomNonceHex(): string {
	const arr = new Uint8Array(32);
	crypto.getRandomValues(arr);
	return bytesToHex(arr);
}

function errStr(e: unknown): string {
	// Redact any accidental sk-rp-... in error messages, defensively.
	const s = e instanceof Error ? e.message : String(e);
	return s.replace(/sk-rp-[A-Za-z0-9]+/g, "sk-rp-[REDACTED]");
}

function markCached(f: Facet): Facet {
	return { ...f, detail: f.detail + " (cached)" };
}

function currentRespHash(record: TurnRecord): string {
	if (!record.responseBytes || record.streamed) return "";
	try {
		const obj = JSON.parse(new TextDecoder().decode(record.responseBytes));
		return sha256Hex(canonicalize(obj));
	} catch {
		return "";
	}
}

function buildEvidence(
	chatId: string,
	model: string,
	signingAddress: string,
	signingAlgo: "ecdsa" | "ed25519",
	text: string,
	signature: string,
	requestSha256: string,
	responseSha256: string,
	_nonce: string,
	_quoteHex: string,
	_nvPayload: string,
	sub: Pick<Evidence, "attestationNonce" | "intelQuoteHex" | "nvidiaPayload" | "info" | "vmConfig" | "eventLog">,
): Evidence {
	return {
		chatId,
		model,
		signingAddress,
		signingAlgo,
		text,
		signature,
		requestSha256,
		responseSha256,
		attestationNonce: sub.attestationNonce,
		intelQuoteHex: sub.intelQuoteHex,
		nvidiaPayload: sub.nvidiaPayload,
		info: sub.info,
		vmConfig: sub.vmConfig,
		eventLog: sub.eventLog,
	};
}

function finalize(
	facets: Facet[],
	model?: string,
	chatId?: string,
	signingAddress?: string,
	appId?: string,
	evidence?: Evidence,
): Verdict {
	const overall: FacetStatus = worst(facets);
	const overallMapped = overall === "skip" ? "warn" : (overall as "ok" | "warn" | "fail");
	return {
		overall: overallMapped,
		facets,
		model,
		chatId,
		signingAddress,
		appId,
		trustCenterUrl: appId ? `https://trust.phala.com/app/${appId}` : undefined,
		verifiedAt: Date.now(),
		evidence,
	};
}

function fail(msg: string, model?: string, chatId?: string): Verdict {
	return {
		overall: "fail",
		facets: [{ id: "sig", label: "verification", status: "fail", detail: msg }],
		model,
		chatId,
		verifiedAt: Date.now(),
		error: msg,
	};
}

function worst(facets: Facet[]): FacetStatus {
	if (facets.some((f) => f.status === "fail")) return "fail";
	if (facets.some((f) => f.status === "warn")) return "warn";
	if (facets.some((f) => f.status === "skip")) return "warn";
	return "ok";
}

function findEvent(events: EventLogEntry[] | undefined, name: string): string | undefined {
	if (!events) return undefined;
	const e = events.find((x) => x.event === name);
	return e && typeof e.event_payload === "string" ? e.event_payload : undefined;
}

function parseMaybeJson(v: unknown): unknown {
	if (typeof v === "string") {
		try {
			return JSON.parse(v);
		} catch {
			return v;
		}
	}
	return v;
}

// -----------------------------------------------------------------------------
// API types
// -----------------------------------------------------------------------------

interface SignaturePayload {
	text: string;
	signature: string;
	signing_address: string;
	signing_algo?: "ecdsa" | "ed25519";
}

interface AttestationReport {
	signing_address: string;
	signing_algo?: "ecdsa" | "ed25519";
	request_nonce?: string;
	intel_quote: string;
	nvidia_payload: string;
	info?: unknown;
	quote?: unknown;
	event_log?: unknown;
	vm_config?: unknown;
	all_attestations?: AttestationReport[];
}

interface EventLogEntry {
	event?: string;
	event_payload?: string;
	imr?: number;
	digest?: string;
}
