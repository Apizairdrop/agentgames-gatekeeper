# apizairdrop Gatekeeper

Proof Gatekeeper agent for **zkVerify Agent Games Season 01** (21 Oct – 21 Nov 2026).

The agent receives signed transfer tasks at a public HTTPS endpoint, decides
**APPROVE** or **REJECT** with deterministic checks, and proves each decision
with the official Groth16 circuit (BN128, Circom 2.x). The platform re-verifies
the proof against its own registered verification key — a valid proof of a bad
decision still loses, and a wrong decision cannot even produce a witness.

## Tracks

- **Proof Gatekeeper** (this agent). 8 daily scored rounds, 13–21 Nov 2026.
  Score: +12 correct decision, −6 approving a trap, −3 rejecting a valid
  request, −2 timeout/offline, −2 proof fails to verify, plus a reliability
  bonus (verified proofs / tasks).

## How it works

1. Platform POSTs a signed JSON envelope to `/gatekeeper`:
   `agent-games.proof-gatekeeper.v1` with `input` (registered_vk, proof_vk,
   minimum, public_balance, expiry_block, current_block, recipient,
   condition_recipient, amount, max_transfer, proof_tx).
2. The server verifies the HMAC (`x-agent-games-signature`) over the RAW body
   before parsing. Mismatch → 401.
3. Deterministic decision (first failing trap wins):
   `VK_SUBSTITUTION` → `PROOF_REUSED` → `THRESHOLD_MISMATCH` →
   `EXPIRED_CONDITION` (strict: current_block == expiry_block is expired) →
   `RECIPIENT_MISMATCH` → `AMOUNT_OVERFLOW` → else `VALID_CONDITION` (APPROVE).
   Boundaries: balance == minimum is valid; amount == max is valid.
4. A Groth16 proof is generated locally with snarkjs and the official
   `gatekeeper` circuit. Circuit inputs: the 12 task fields + decision +
   a random private salt. `taskId` is mapped to a field element via
   keccak256(task_id) mod p (see `GATEKEEPER_TASK_ID_MODE`).
5. Response: `{ decision, reason_code, proof_tx, proof, public_signals }`,
   signed with `x-agent-games-signature` over the raw body.
6. Kurier (optional, best-effort): submits the proof to zkVerify mainnet for
   an on-chain finalization pointer. The local proof is the primary evidence;
   Kurier never blocks a response.

Preflight: the platform sends `agent-games.preflight.v1` before any task;
the server answers `{ ok: true, protocolVersion: "v1" }` (signed). Preflight
must pass before the platform marks the agent active.

## Run locally

```bash
npm install
npm test          # all 7 trap types + boundaries, proofs verified locally
cp .env.example .env   # fill in AGENT_GAMES_HMAC_SECRET from the dashboard
npm start         # listens on 0.0.0.0:$PORT (default 8080)
curl localhost:8080/health
```

## Deploy

The endpoint must be public HTTPS. Deploy from this repo (e.g. Railway,
Render, Fly.io) and set the env vars on the host. Then register the agent on
the dashboard with this repo URL and the endpoint URL, rotate the secret,
set `AGENT_GAMES_HMAC_SECRET`, restart, and run preflight.

## Environment

| Var | Required | Notes |
|---|---|---|
| `PORT` | no | default 8080 (hosts inject it) |
| `AGENT_GAMES_HMAC_SECRET` | yes (live) | dashboard → Rotate Secret |
| `AGENT_GAMES_HMAC_FORMAT` | no | `hex` (default) or `sha256=` |
| `GATEKEEPER_TASK_ID_MODE` | no | `keccak` (default), `numeric`, `hex` |
| `KURIER_API_KEY` | no | free at https://kurier.xyz |

## Files

- `server.js` — HTTP server, HMAC, preflight, `/gatekeeper`, `/health`
- `gatekeeper/decide.js` — deterministic decision logic (7 traps)
- `gatekeeper/prove.js` — circuit input assembly + proof generation
- `gatekeeper/test.js` — local test harness (all traps + boundaries)
- `shared/field.js` — BN128 field helpers (keccak256 mod p)
- `shared/hmac.js` — HMAC-SHA256 sign/verify
- `shared/snark.js` — snarkjs wrapper (prove / verify locally)
- `shared/kurier.js` — optional Kurier submission (best-effort)
- `circuits/` — official gatekeeper artifacts (wasm + zkey), vk_hash
  `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`

## Security

- No wallet, no private keys, no funds. This is a game endpoint only.
- Secrets come from env vars only; `.env` is gitignored; never log secrets.
- The decision is enforced in deterministic code — no language model makes
  the final call. The circuit is the referee.
