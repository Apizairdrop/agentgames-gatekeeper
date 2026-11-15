// apizairdrop Gatekeeper — HTTP server for the Proof Gatekeeper track.
//   POST /gatekeeper — Proof Gatekeeper tasks
//   GET  /health     — readiness (secret configured? self-test?)
//   GET  /           — info
//
// Every inbound request is HMAC-verified over the RAW body against
// x-agent-games-signature BEFORE parsing (when AGENT_GAMES_HMAC_SECRET is
// set). Every response is signed the same way. Preflight
// {"type":"agent-games.preflight.v1"} is answered {ok:true, protocolVersion:"v1"}.
//
// Fail closed: the gatekeeper rejects on any uncertainty. Nothing here ever
// approves, signs, or spends anything — this is a game endpoint only.
// No wallet, no keys.
const fs = require('fs');
const path = require('path');
const http = require('http');

// ---- tiny .env loader (no dependency) ----
(function loadEnv() {
  const envFile = path.join(__dirname, '.env');
  try {
    for (const line of fs.readFileSync(envFile, 'utf8').split('\n')) {
      const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/.exec(line);
      if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^['"]|['"]$/g, '');
    }
  } catch { /* no .env — env vars only */ }
})();

const { verifySignature, signatureFor } = require('./shared/hmac');
const { verifyLocally } = require('./shared/snark');
const { submitProof } = require('./shared/kurier');
const { decide } = require('./gatekeeper/decide');
const { proveTask } = require('./gatekeeper/prove');

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || '0.0.0.0';
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const HMAC_FORMAT = process.env.AGENT_GAMES_HMAC_FORMAT || 'hex'; // or 'sha256='
const KURIER_API_KEY = process.env.KURIER_API_KEY || '';
const TASK_ID_MODE = process.env.GATEKEEPER_TASK_ID_MODE || 'keccak';

let gatekeeperSelfTest = 'pending';

// ---- helpers ----
function sendJson(res, status, obj, sign) {
  const body = JSON.stringify(obj);
  const headers = { 'Content-Type': 'application/json' };
  if (sign && HMAC_SECRET) headers['x-agent-games-signature'] = signatureFor(HMAC_SECRET, body, HMAC_FORMAT);
  res.writeHead(status, headers);
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function verifyInbound(rawBody, req) {
  if (!HMAC_SECRET) {
    console.warn('[warn] AGENT_GAMES_HMAC_SECRET is not set — inbound HMAC is NOT verified. Set it before going live.');
    return true;
  }
  const sig = req.headers['x-agent-games-signature'];
  return verifySignature(HMAC_SECRET, rawBody, sig, HMAC_FORMAT);
}

function isPreflight(obj) {
  return obj && obj.type === 'agent-games.preflight.v1';
}

// ---- Gatekeeper handler ----
async function handleGatekeeper(obj) {
  const task = obj.input || obj;
  const required = ['registered_vk', 'proof_vk', 'minimum', 'public_balance', 'expiry_block', 'current_block', 'recipient', 'condition_recipient', 'amount', 'max_transfer'];
  for (const f of required) {
    if (task[f] === undefined || task[f] === null || task[f] === '') {
      return { status: 200, body: { decision: 'REJECT', reason_code: 'INVALID_TASK', proof_tx: String(task.proof_tx || '') } };
    }
  }
  const { decision, reason_code } = decide(task);
  const proofTx = String(task.proof_tx || '');
  if (reason_code === 'PROOF_REUSED') {
    // No proof to submit for a reused proof (platform excludes these from
    // the reliability bonus).
    return { status: 200, body: { decision, reason_code, proof_tx: proofTx } };
  }
  try {
    const { proof, publicSignals } = await proveTask(task, decision, TASK_ID_MODE);
    // Kurier (best-effort, background): on-chain finalization pointer.
    // Gatekeeper responses carry no proofReference field, so this is fire-and-forget.
    if (KURIER_API_KEY) {
      submitProof(KURIER_API_KEY, 'gatekeeper', proof, publicSignals, 15000).catch(() => {});
    }
    return { status: 200, body: { decision, reason_code, proof_tx: proofTx, proof, public_signals: publicSignals } };
  } catch (e) {
    console.error('[gatekeeper] proof generation failed (decision still returned):', e.message);
    return { status: 200, body: { decision, reason_code, proof_tx: proofTx } };
  }
}

// ---- startup self-test (prove the circuit works before serving) ----
async function selfTest() {
  try {
    const task = {
      task_id: 'gk_selftest_1', registered_vk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
      proof_vk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
      minimum: '1000', public_balance: '1460', expiry_block: '8430000', current_block: '8420000',
      recipient: '0x1111111111111111111111111111111111111111',
      condition_recipient: '0x1111111111111111111111111111111111111111',
      amount: '500', max_transfer: '1000', proof_tx: '0xselftest',
    };
    const { decision } = decide(task);
    const { proof, publicSignals } = await proveTask(task, decision, TASK_ID_MODE);
    const ok = await verifyLocally('gatekeeper', publicSignals, proof);
    gatekeeperSelfTest = ok && decision === 'APPROVE' ? 'PASS (APPROVE proof verifies locally)' : 'FAIL';
  } catch (e) {
    gatekeeperSelfTest = 'FAIL: ' + e.message;
  }
}

// ---- HTTP server ----
const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && req.url === '/health') {
      return sendJson(res, 200, {
        ok: true,
        gatekeeper: { hmacConfigured: !!HMAC_SECRET, taskIdMode: TASK_ID_MODE, selfTest: gatekeeperSelfTest },
        kurierConfigured: !!KURIER_API_KEY,
        uptimeSec: Math.floor(process.uptime()),
      });
    }
    if (req.method === 'GET' && req.url === '/') {
      return sendJson(res, 200, { service: 'apizairdrop-gatekeeper', track: 'proof-gatekeeper', endpoints: ['POST /gatekeeper', 'GET /health'] });
    }
    if (req.method !== 'POST' || req.url !== '/gatekeeper') {
      return sendJson(res, 404, { error: 'not found' });
    }
    const rawBody = await readBody(req);
    if (!verifyInbound(rawBody, req)) {
      console.warn('[warn] HMAC mismatch on', req.url);
      return sendJson(res, 401, { error: 'bad signature' });
    }
    let obj;
    try {
      obj = JSON.parse(rawBody.toString('utf8'));
    } catch {
      return sendJson(res, 400, { error: 'invalid JSON' });
    }
    if (isPreflight(obj)) {
      return sendJson(res, 200, { ok: true, protocolVersion: 'v1' }, true);
    }
    const result = await handleGatekeeper(obj);
    return sendJson(res, result.status, result.body, true);
  } catch (e) {
    console.error('[server] unhandled error:', e);
    return sendJson(res, 500, { error: 'internal error' });
  }
});

server.listen(PORT, HOST, async () => {
  console.log(`[server] listening on ${HOST}:${PORT}  (gatekeeper: /gatekeeper)`);
  console.log(`[server] HMAC secret: ${HMAC_SECRET ? 'configured' : 'NOT SET (inbound verification disabled)'}`);
  console.log(`[server] Kurier: ${KURIER_API_KEY ? 'configured' : 'not configured (local proofs only)'}`);
  await selfTest();
  console.log(`[server] self-test gatekeeper: ${gatekeeperSelfTest}`);
});
