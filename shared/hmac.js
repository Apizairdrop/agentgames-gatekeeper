// HMAC-SHA256 helpers for the Agent Games platform handshake.
// The platform signs every inbound envelope with the secret issued on the
// dashboard ("Rotate Secret") and sends it in the `x-agent-games-signature`
// header. We verify it over the RAW request body BEFORE parsing JSON, and
// sign every response the same way.
//
// Encoding: lowercase hex HMAC-SHA256 of the raw body by default. If the
// platform rejects the preflight, set AGENT_GAMES_HMAC_FORMAT=sha256= to
// send/verify the `sha256=<hex>` form instead.
const crypto = require('crypto');

function hmacHex(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
}

function signatureFor(secret, rawBody, format) {
  const hex = hmacHex(secret, rawBody);
  return format === 'sha256=' ? 'sha256=' + hex : hex;
}

function verifySignature(secret, rawBody, headerValue, format) {
  if (!secret || !headerValue) return false;
  const expected = signatureFor(secret, rawBody, format);
  const a = Buffer.from(expected);
  const b = Buffer.from(String(headerValue));
  if (a.length !== b.length) return false;
  try {
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

module.exports = { hmacHex, signatureFor, verifySignature };
