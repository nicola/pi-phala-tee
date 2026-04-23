# phala-tee

A [pi](https://github.com/badlogic/pi-mono) extension that registers
[Phala Confidential AI](https://docs.phala.com/phala-cloud/confidential-ai/overview)
(GPU TEE via dstack) as an LLM provider and **cryptographically verifies every
completed turn** against the Intel TDX + NVIDIA GPU CC + signing-key
attestation chain.

The point is not to save you typing an API key. The point is that you can see
— per turn — which links of the trust chain were actually verified, so the
answer to "did this response really come from a GPU TEE running code I
approve?" is crypto, not vibes.

---

## Quick start

```bash
export PHALA_API_KEY=sk-rp-…         # from https://cloud.phala.com
pi                                   # extension auto-loads from ~/.pi/agent/extensions/
/model                               # pick a phala-tee/* model
```

After each turn pi shows a badge like:

```
✓ TEE-verified · ✓sig ✓req ✓resp ⚠tdx ✓rd ✓gpu ⚠app ✓fresh · signer 0x3e6900b0…
```

Hover or run `/tee` for the full report. Run `/tee-trust show` to manage
app-identity pins.

---

## What each badge facet means

Every facet is an **independent cryptographic check**. A facet is **only ✓** if
the check actually ran against a trust root we verify **locally** (or against a
delegated verifier that we explicitly label ⚠). We will never show ✓ for a
check we skipped or delegated. Fail-closed is the rule.

| Facet | ✓ means | Trust root |
|---|---|---|
| `sig` | ECDSA-recover(EIP-191 over `text`) == claimed `signing_address`, or Ed25519 verify. | `@noble/curves` secp256k1 / ed25519, local. |
| `req-bind` | `sha256(exact_POST_body) == request_hash` from the signed `text`. | Local SHA-256. |
| `resp-bind` | `sha256(canonical(response_json)) == response_hash`. Canonicalizer reproduces Python's `json.dumps(obj)` byte-for-byte (tested with live fixtures). **Streamed turns get ⚠** because the server hashes an internal canonical form we can't reconstruct from the SSE stream. | Local SHA-256 + canonicalizer. |
| `tdx` | Intel TDX quote verified **locally** by bundled `dcap-qvl` (Phala-Network/dcap-qvl, Rust, audited upstream) against Intel's root CA. PCCS is just a signed-cert cache; a malicious PCCS can only cause verification to fail, not to falsely succeed. TCB status must be `UpToDate`; `OutOfDate` / `ConfigurationNeeded` / etc. downgrade to ⚠ with the advisory IDs shown. If no `dcap-qvl` binary is bundled for the current platform, falls back to the delegated verifier with an honest ⚠. | Intel root via DCAP (local). |
| `reportdata` | TDX `report_data[0..20)` == `signing_address` (right-padded to 32 bytes), `report_data[32..64)` == our fresh nonce. Proves the signing key is bound to the attested TEE and the attestation is fresh. | Local byte compare. |
| `gpu` | NVIDIA NRAS JWT signature verified **locally** against NVIDIA's JWKS (ES384 / P-384), plus `x-nvidia-overall-att-result:true` and `eat_nonce == our_nonce`. | NVIDIA root via JWKS. Local. |
| `app` | Compose-hash + `app_id` + `os-image-hash` extracted from the attestation `event_log` match either a TOFU-pinned tuple or an explicit allow-list entry, depending on mode. | User decision (TOFU or curated allow-list). |
| `fresh` | Our client-generated nonce flows into both the TDX `reportdata` and the NRAS JWT `eat_nonce`. Proves the attestation was generated for *this* verification round, not replayed. | Local nonce. |

### The overall status

- **✓ TEE-verified** — every facet ✓.
- **⚠ TEE-partial** — at least one facet is ⚠ (delegated, unreachable, or
  TOFU pin on first use). Nothing contradicts the other facets; respond
  according to your own risk tolerance.
- **✗ TEE-UNVERIFIED** — at least one cryptographic contradiction. Do not
  trust this response. A footer notification appears and (optionally) strict
  mode can block the message from being used as context.

---

## Threat model

Addressed:

- Plain MITM (TLS) — basic.
- A non-TEE server masquerading as Phala — broken by `sig` + `reportdata` + `gpu`.
- A compromised TEE image — broken by `app` (provided you have a meaningful
  allow-list, or at least a TOFU pin that you check against
  [`trust.phala.com/app/{app_id}`](https://trust.phala.com/) once).
- Response-content tampering in transit — broken by `resp-bind` on
  non-streaming responses; ⚠ on streamed responses.
- Attestation replay — broken by `fresh` (our per-turn 32-byte nonce bound
  into both TDX and GPU attestation).

**Out of scope** (hardware-trust assumptions we do not try to verify):

- Side-channel attacks on TDX or H100/H200 CC firmware.
- Supply-chain compromise of the Intel/NVIDIA root CAs themselves.
- Phala-the-company's own operational policies (this extension verifies the
  execution substrate is genuine TEE running a specific image — it does not
  make Phala not-an-organization).

---

## App-identity policy

Run `/tee-trust` to manage:

- **tofu** (default): pin the tuple `(app_id, compose-hash, os-image-hash,
  key-provider)` the first time we see a given `app_id`. Any subsequent
  change in those fields is a `fail` — the TEE image changed and we won't
  accept the TOFU pin silently.
- **strict**: only `app_id`s in `allowedApps` are ✓. Everything else is
  `fail`. Use `/tee-trust promote-to-allow` to move current pins into the
  allow-list after you've manually cross-verified them at
  `https://trust.phala.com/app/{app_id}`.
- **permissive**: never fails for app identity. Marked ⚠ always. For
  experimentation only.

Settings live in `~/.pi/agent/phala-tee.json` and survive sessions. They do
**not** live in pi's session state (so they apply across `/new`, `/resume`,
and all projects).

---

## Storage

| What | Where | Contains secrets? |
|---|---|---|
| API key | `PHALA_API_KEY` env var (process env only) | — |
| TOFU pins / policy | `~/.pi/agent/phala-tee.json` | no |
| Per-turn evidence (quote, GPU report, signature, hashes, nonce) | `~/.pi/agent/tee-audit.jsonl` | no API key, no prompt/completion text |
| pi session files | as usual (pi's `sessions/`) | the extension writes nothing there |

The audit log is append-only and self-contained: anyone can re-run the full
verification chain offline from a single line of it.

---

## Limitations / known ⚠s (v0.2)

1. **`tdx` is local on darwin-arm64; other platforms still delegate.** The
   repo ships a prebuilt `dcap-qvl` binary only for darwin-arm64. For other
   platforms, build with:
   ```bash
   git clone https://github.com/Phala-Network/dcap-qvl && cd dcap-qvl/cli
   cargo build --release
   mkdir -p ~/.pi/agent/extensions/phala-tee/bin/<platform>-<arch>
   cp target/release/dcap-qvl ~/.pi/agent/extensions/phala-tee/bin/<platform>-<arch>/
   ```
   Until then the extension falls back to the delegated verifier on those
   platforms (honest ⚠, not hidden).
2. **Streamed responses can't verify `resp-bind`.** Phala's server hashes
   a reassembled non-streaming JSON we can't reproduce from the SSE bytes.
   Non-streaming turns get full ✓. Tool-calling that needs streaming
   retains ✓ on every other facet.
3. **Model list is curated, not auto-discovered.** The gateway `/v1/models`
   endpoint returns 76 models, most of which (Anthropic, GPT-5, o3, etc.)
   are **not** in TEE — they're plain proxied. Auto-discovery would be
   dishonest because it would invite users to pick a non-TEE model from a
   "TEE provider". v0 ships the subset of ~6 Phala-operated TEE models
   documented by Phala. v0.1 will probe `/v1/attestation/report?model=X` at
   load time and include only models that produce a valid quote.
4. **NRAS JWT clock skew.** We accept JWT `exp > now` strictly (no grace
   window). Fine in practice because we verify immediately after each turn.
5. **Signing-key cache is in-memory.** We cache a verified attestation for
   the same `signing_address` for 5 minutes (or until the NRAS JWT expires,
   whichever is sooner), so subsequent turns verify in ~10 ms instead of
   several seconds. The cache is dropped on process exit.

---

## Verifying the verifier

Tests in `test/` are run with `tsx --test`:

```bash
# offline canonicalizer + crypto tests (no API calls)
npx tsx --test test/canonical.test.mjs test/crypto.test.mjs

# end-to-end live integration test (makes 1 chat call + attestation roundtrip)
PHALA_API_KEY=sk-rp-... npx tsx --test test/integration.test.mjs
```

The canonicalizer tests use real captured fixtures (run `test/capture-fixture.mjs`
with your API key to add more). If Phala ever changes their response
canonicalization the test breaks immediately — we fail closed, never a
silent false ✓.

---

## File layout

```
phala-tee/
├── index.ts               # pi extension factory: register provider, wire events, commands
├── package.json           # deps: @noble/curves, @noble/hashes
├── src/
│   ├── types.ts           # Verdict, Facet, Evidence, settings
│   ├── canonical.ts       # Python-json.dumps canonicalizer (tested)
│   ├── crypto.ts          # ECDSA EIP-191, Ed25519, JWT ES384, SHA-256 (tested)
│   ├── fetchIntercept.ts  # scoped api.redpill.ai fetch observer (records req/resp bytes + chat_id)
│   ├── verify.ts          # end-to-end verification orchestration
│   ├── models.ts          # curated TEE model list
│   ├── settings.ts        # persistent policy + TOFU pins
│   ├── audit.ts           # append-only evidence log
│   └── ui.ts              # badge / widget / /tee report composers
├── test/
│   ├── capture-fixture.mjs        # live fixture capture
│   ├── canonical.test.mjs         # fixture-based canonicalizer tests
│   ├── crypto.test.mjs            # ECDSA recovery + helpers
│   └── integration.test.mjs       # live end-to-end
└── README.md
```
