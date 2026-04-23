# phala-tee

> ⚠️ **Vibe-coded, highly experimental, do not use with confidential
> information.** This extension was built in a single session with an LLM
> pair-programmer. It has not been independently audited. The cryptographic
> primitives come from reputable libraries (`@noble/*`,
> `Phala-Network/dcap-qvl`) and the orchestration logic is tested against
> live fixtures, but the *composition* of those pieces into a trust verdict
> is novel code with unknown bugs. Treat the 🛡 badge as "probably right"
> rather than "certainly right", and don't send anything to a Phala TEE
> via this extension that you wouldn't also send to an ordinary cloud API.

A [pi](https://github.com/badlogic/pi-mono) extension that registers
[Phala Confidential AI](https://docs.phala.com/phala-cloud/confidential-ai/overview)
(GPU TEE via dstack) as an LLM provider and **cryptographically verifies
every completed turn** against the Intel TDX + NVIDIA GPU CC + signing-key
attestation chain.

The point is not to save you typing an API key. The point is that after every
response you can see — per turn — which links of the trust chain were actually
verified, so the answer to *"did this really come from a GPU TEE running code
I approve?"* is crypto, not vibes.

---

## Install

```bash
cd ~/.pi/agent/extensions
git clone https://github.com/nicola/pi-phala-tee.git phala-tee
cd phala-tee
npm install
```

Add your Phala API key to `~/.pi/agent/auth.json`:

```json
{
  "phala-tee": {
    "type": "api_key",
    "key": "sk-rp-..."
  }
}
```

Then start `pi`, `/model` → pick a `phala-tee/*` model, and chat.

A bundled `dcap-qvl` binary for **darwin-arm64** is included for fully-local
TDX verification. Users on other platforms still get the extension but fall
back to Phala's hosted verifier (shown as ⚠ with a clear message). See
[Other platforms](#other-platforms) below.

---

## UX

When a `phala-tee/*` model is active, a single-line widget appears above the
editor:

```
🛡  TEE verified     ● ● ● ● ● ● ● ●     ⌥T for details
🛡  TEE partial      ● ● ● ● ⚠ ● ⚠ ●     ⌥T for details
🛡  TEE UNVERIFIED   ● ● ✗ ● ● ● ● ●     ⌥T for details
```

- Per-facet indicators (sig · req · resp · tdx · rd · gpu · app · fresh),
  each coloured by that facet's status. Glyphs differ per state so it's
  readable without colour.
- **`⌥T`** (alt+T) or `/tee` → expand into the full per-facet report with
  trust-root notes.
- **`/tee-trust`** → manage app-identity pins and policy (see below).

The extension is fully invisible while a non-`phala-tee/*` model is active.

---

## What each facet means

Every facet is an **independent cryptographic check**. A facet is **only ✓**
if the check actually ran against a trust root we verify **locally** (or
against a delegated verifier that we explicitly label ⚠). We will never show
✓ for a check we skipped or delegated. Fail-closed is the rule.

| Facet | ✓ means | Trust root |
|---|---|---|
| `sig` | ECDSA-recover(EIP-191 over `text`) == claimed `signing_address`, or Ed25519 verify. | `@noble/curves` secp256k1 / ed25519, local. |
| `req-bind` | `sha256(exact_POST_body) == request_hash` from the signed `text`. | Local SHA-256. |
| `resp-bind` | `sha256(canonical(response_json)) == response_hash`. Canonicalizer reproduces Python's `json.dumps(obj)` byte-for-byte (tested with live fixtures). **Streamed turns get ⚠** because the server hashes an internal canonical form we can't reconstruct from the SSE stream. | Local SHA-256 + canonicalizer. |
| `tdx` | Intel TDX quote verified **locally** by bundled `dcap-qvl` (audited Rust from [Phala-Network/dcap-qvl](https://github.com/Phala-Network/dcap-qvl)) against Intel's root CA. PCCS is just a signed-cert cache; a malicious PCCS can only cause verification to fail, not to falsely succeed. TCB status must be `UpToDate`; `OutOfDate` / `ConfigurationNeeded` / etc. downgrade to ⚠ with the advisory IDs shown. | Intel root via DCAP (local). |
| `reportdata` | TDX `report_data[0..20)` == `signing_address` (right-padded to 32 bytes), `report_data[32..64)` == our fresh nonce. Proves the signing key is bound to the attested TEE and the attestation is fresh. | Local byte compare. |
| `gpu` | NVIDIA NRAS JWT signature verified **locally** against NVIDIA's JWKS (ES384 / P-384), plus `x-nvidia-overall-att-result:true` and `eat_nonce == our_nonce`. | NVIDIA root via JWKS. Local. |
| `app` | Compose-hash + `app_id` + `os-image-hash` extracted from the attestation `event_log` match either a TOFU-pinned tuple or an explicit allow-list entry, depending on mode. **Bonus:** compose-hash is also checked against the TDX `mr_config_id` field, which cryptographically binds the app identity into the quote itself — the report-shown as `compose-hash bound in TDX mr_config_id`. Mismatch between `event_log` and `mr_config_id` → immediate `✗` (identity lying). | User decision (TOFU or curated allow-list) + TDX measurement register. |
| `fresh` | Our client-generated 32-byte nonce flows into both the TDX `reportdata` and the NRAS JWT `eat_nonce`. Proves the attestation was generated for *this* verification round, not replayed. | Local nonce. |

### Overall status

- **✓ TEE-verified** — every facet ✓.
- **⚠ TEE-partial** — at least one facet ⚠ (network unreachable, TCB slightly
  stale, or TOFU pin on first use). Nothing contradicts the other facets;
  proceed according to your own risk tolerance.
- **✗ TEE-UNVERIFIED** — at least one cryptographic contradiction. Do not
  trust this response. A footer notification appears and (optionally) strict
  mode can block the message from being used as context.

---

## Threat model

Addressed:

- Plain MITM (TLS) — baseline.
- A non-TEE server masquerading as Phala — broken by `sig` + `reportdata` + `gpu`.
- A compromised TEE image — broken by `app` (TOFU pin, optional allow-list,
  plus cryptographic binding to TDX `mr_config_id`).
- Response-content tampering in transit — broken by `resp-bind` on
  non-streaming responses; ⚠ on streamed responses (honest).
- Attestation replay — broken by `fresh` (per-turn 32-byte nonce bound into
  both TDX `reportdata` and GPU attestation).
- Malicious PCCS — can only cause verification to *fail*, not to falsely
  succeed. The final ECDSA checks happen locally against Intel's root CA.

**Out of scope** (hardware-trust assumptions we don't try to verify):

- Side-channel attacks on TDX or H100/H200 CC firmware.
- Supply-chain compromise of the Intel/NVIDIA root CAs themselves.
- Phala-the-company's operational policies. This extension verifies the
  execution substrate is a genuine TEE running a specific image — it does
  not make Phala not-an-organization.

---

## App-identity policy

Run `/tee-trust` to inspect and manage:

- **tofu** (default): pin the tuple `(app_id, compose-hash, os-image-hash,
  key-provider)` the first time we see a given `app_id`. Any subsequent
  change = `✗`. First-use shows ⚠ (with the `mr_config_id` crypto-binding
  noted); second-use onwards shows ✓.
- **strict**: only `app_id`s in `allowedApps` are ✓; everything else is
  `✗`. Use `/tee-trust promote-to-allow` to move current pins into the
  allow-list after you've cross-verified them at
  `https://trust.phala.com/app/{app_id}`.
- **permissive**: never fails for app identity. Always ⚠. Experimentation
  only.

Settings live in `~/.pi/agent/phala-tee.json`. They don't live in pi's
session state, so they apply across `/new`, `/resume`, and all projects.

Commands:

```
/tee-trust show            # inspect policy + pins + allow-list
/tee-trust mode <tofu|strict|permissive>
/tee-trust reset-pins      # forget all TOFU pins
/tee-trust promote-to-allow # copy all current pins into allow-list
```

---

## Storage

| What | Where | Contains secrets? |
|---|---|---|
| API key | `~/.pi/agent/auth.json` (`phala-tee.key`) | yes — stays here, never copied elsewhere |
| TOFU pins / policy | `~/.pi/agent/phala-tee.json` | no |
| Per-turn evidence (quote, GPU report, signature, hashes, nonce) | `~/.pi/agent/tee-audit.jsonl` | no API key, no prompt/completion text |
| pi session files | pi's usual `sessions/` dir | the extension writes nothing there |

The audit log is append-only and self-contained: anyone can re-run the full
verification chain offline from a single line of it.

---

## Other platforms

Bundled binaries live in `bin/<platform>-<arch>/dcap-qvl`. v0.2 ships
**darwin-arm64** only. On any other platform the extension falls back to
Phala's hosted verifier (`tdx` facet shown as ⚠) with a clear message.

To build your own local binary (recommended):

```bash
git clone https://github.com/Phala-Network/dcap-qvl.git
cd dcap-qvl/cli
cargo build --release

cd ~/.pi/agent/extensions/phala-tee
mkdir -p bin/<platform>-<arch>
cp /path/to/dcap-qvl/cli/target/release/dcap-qvl bin/<platform>-<arch>/
```

Where `<platform>-<arch>` is one of `darwin-arm64`, `darwin-x64`,
`linux-x64`, `linux-arm64`, `win32-x64` (Windows uses `dcap-qvl.exe`).
Restart pi or `/reload` and the `tdx` facet should flip to ✓.

---

## Testing the verifier

Tests live in `test/`, run with `tsx --test`:

```bash
# offline canonicalizer + crypto tests (no API calls)
npx tsx --test test/canonical.test.mjs test/crypto.test.mjs

# end-to-end live integration test (makes 1 chat call + attestation roundtrip)
PHALA_API_KEY=sk-rp-... npx tsx --test test/integration.test.mjs

# 2-turn test that exercises the signing-key cache
PHALA_API_KEY=sk-rp-... npx tsx --test test/cache.test.mjs
```

The canonicalizer tests use real captured fixtures (regenerate with
`test/capture-fixture.mjs` against your API key to add more). If Phala ever
changes their response canonicalization the test breaks immediately — we
fail closed, never silent false ✓.

---

## Known ⚠s and follow-ups

1. **Streamed responses can't verify `resp-bind`.** Phala's server hashes a
   reassembled non-streaming JSON we can't reproduce from the SSE bytes.
   Non-streaming turns get full ✓. Tool-calling that needs streaming still
   retains ✓ on every other facet. Upstream feature request: expose the
   canonical signed bytes via header or endpoint.
2. **First-use TOFU pin shows ⚠.** On turn 2 the pin is ✓. Flipping to ✓ on
   first use requires a bundled signed allow-list of known-good Phala TEE
   app identities. Planned.
3. **Model list is curated, not auto-discovered.** The gateway's
   `/v1/models` endpoint returns ~76 proxied models including non-TEE
   providers (Anthropic, GPT-5, o3). Auto-including them would invite users
   to see a ✓ badge from a provider not actually in a TEE. A smarter v0.3
   will probe `/v1/attestation/report?model=X` at load and include only
   models that return valid quotes.
4. **Other-platform `tdx` is delegated.** See
   [Other platforms](#other-platforms). Always labelled ⚠, never hidden.

---

## License

MIT — see [LICENSE](./LICENSE).

## File layout

```
phala-tee/
├── index.ts               # pi extension factory: provider registration, events, commands
├── package.json           # deps: @noble/curves, @noble/hashes
├── bin/
│   └── darwin-arm64/
│       └── dcap-qvl       # bundled local TDX verifier (Phala-Network/dcap-qvl)
├── src/
│   ├── types.ts           # Verdict, Facet, Evidence, settings
│   ├── canonical.ts       # Python-json.dumps canonicalizer (fixture-tested)
│   ├── crypto.ts          # ECDSA EIP-191, Ed25519, JWT ES384, SHA-256
│   ├── fetchIntercept.ts  # scoped api.redpill.ai fetch observer (req/resp bytes + chat_id)
│   ├── verify.ts          # end-to-end verification orchestration
│   ├── tdxLocal.ts        # dcap-qvl subprocess wrapper
│   ├── models.ts          # curated TEE model list
│   ├── settings.ts        # persistent policy + TOFU pins
│   ├── audit.ts           # append-only evidence log
│   └── ui.ts              # badge / widget / /tee report composers
├── test/
│   ├── capture-fixture.mjs        # live fixture capture
│   ├── canonical.test.mjs         # fixture-based canonicalizer tests
│   ├── crypto.test.mjs            # ECDSA recovery + helpers
│   ├── integration.test.mjs       # live end-to-end
│   └── cache.test.mjs             # signing-key cache + TOFU upgrade
└── README.md
```
