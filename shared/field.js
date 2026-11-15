// Field-element helpers for the BN128 (alt_bn128) prime field used by both
// Agent Games circuits. A field element is a BigInt in [0, p).
const { keccak_256 } = require('js-sha3');

const FIELD_PRIME = BigInt(
  '21888242871839275222246405745257275088548364400416034343698204186575808495617'
);

// Accepts a hex string (0x..), decimal string, number, or BigInt.
function toField(x) {
  let b;
  if (typeof x === 'bigint') b = x;
  else if (typeof x === 'number') b = BigInt(x);
  else if (typeof x === 'string' && x.startsWith('0x')) b = BigInt(x);
  else b = BigInt(x);
  const r = b % FIELD_PRIME;
  return r < 0n ? r + FIELD_PRIME : r;
}

// keccak256 over the concatenation of the given buffers, reduced mod p.
function keccak256ModP(buffers) {
  const hex = '0x' + keccak_256(Buffer.concat(buffers));
  return toField(BigInt(hex));
}

module.exports = { FIELD_PRIME, toField, keccak256ModP };
