// RingCT amounts: what an output is worth, once we know the output is ours.
//
// The chain does not carry amounts in the clear. Each output carries sixteen
// bytes of "ecdh info": eight bytes of amount, eight bytes of mask, each XORed
// with a one-time pad that only the owner of the output can compute. The pad is
//
//     shared = keccak256(derivation || varint(index))
//
// where `derivation` is the 8*a*R the scan has already computed for this
// transaction, and `index` is the output's position. The first eight bytes of
// `shared` decrypt the amount; the next eight decrypt the mask.
//
// Two details that are easy to get wrong and silent when wrong:
//   - the index is Monero's varint (LEB128, high bit means "another byte
//     follows"), not Bitcoin's CompactSize. They agree below 0x80 and disagree
//     forever after, which is exactly the range a real wallet reaches.
//   - the modern encoding is 8+8 bytes, not the 32+32 the original RingCT used.
//
// HONEST LIMIT, and it is not decorative: everything below is pinned to
// keccak-256's published vectors and to the LEB128 encoding, and to nothing
// else. There is no real Monero transaction in this repo to check the formula
// against end to end, so a round trip here proves the arithmetic is consistent
// with itself, not that it matches the chain. Until a real transaction is
// decoded and the amount matches one the owner knows, this file must not gate a
// payment: no screen, no receipt and no watcher may call a Monero amount
// confirmed on the strength of it.

import { keccak_256 } from '@noble/hashes/sha3.js';

// Monero's varint: seven bits per byte, the top bit says "more follows".
export function moneroVarint(value) {
  let n = Number(value);
  if (!Number.isSafeInteger(n) || n < 0) throw new Error('A varint is a whole number from zero.');
  const out = [];
  for (;;) {
    const byte = n & 0x7f;
    n = Math.floor(n / 128);
    if (n === 0) { out.push(byte); return Uint8Array.from(out); }
    out.push(byte | 0x80);
  }
}

function concat(left, right) {
  const out = new Uint8Array(left.length + right.length);
  out.set(left, 0);
  out.set(right, left.length);
  return out;
}

function xorInto(bytes, pad) {
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i += 1) out[i] = bytes[i] ^ pad[i];
  return out;
}

export function ecdhHash(derivation, index) {
  if (!(derivation instanceof Uint8Array) || derivation.length !== 32) {
    throw new Error('The derivation is 32 bytes, as the scan computed it.');
  }
  return keccak_256(concat(derivation, moneroVarint(index)));
}

// Eight bytes hold any value up to this, and the whole Monero supply sits just
// under it (18.4 million coins at twelve decimals). So this is the widest an
// amount can be, and it is used to refuse an amount that cannot be WRITTEN —
// there is deliberately no decode-time supply check, because a decoded u64 is by
// definition inside the range and such a check could never fail.
export const MAX_ATOMIC = 2n ** 64n - 1n;

function u64le(bytes) {
  let value = 0n;
  for (let i = 7; i >= 0; i -= 1) value = (value << 8n) | BigInt(bytes[i]);
  return value;
}

// Decrypt one output's ecdh info. `info` is the sixteen bytes the transaction
// carries; the amount comes back as a bigint of atomic units (12 decimals), and
// the mask as bytes — the mask is what makes two equal amounts indistinguishable
// on chain, and it is not a number to compare or add.
export function decodeAmount({ derivation, index, info } = {}) {
  if (!(info instanceof Uint8Array) || info.length !== 16) {
    throw new Error('An output carries sixteen bytes of ecdh info: eight of amount and eight of mask.');
  }
  const shared = ecdhHash(derivation, index);
  const value = u64le(xorInto(info.slice(0, 8), shared.slice(0, 8)));
  return { value, mask: xorInto(info.slice(8, 16), shared.slice(8, 16)) };
}

// The other direction, used by tests and by nothing else in this build: it is
// how a transaction is BUILT, and this wallet does not build Monero
// transactions yet. Kept beside the decoder so the two cannot drift, and named
// so a reader does not think it is a spend path.
export function encodeAmountForTest({ derivation, index, value, mask }) {
  if (typeof value !== 'bigint' || value < 0n || value > MAX_ATOMIC) {
    throw new Error('An amount is a bigint of atomic units.');
  }
  if (!(mask instanceof Uint8Array) || mask.length !== 8) throw new Error('The mask is eight bytes.');
  const shared = ecdhHash(derivation, index);
  const amount = new Uint8Array(8);
  let rest = value;
  for (let i = 0; i < 8; i += 1) { amount[i] = Number(rest & 0xffn); rest >>= 8n; }
  return concat(xorInto(amount, shared.slice(0, 8)), xorInto(mask, shared.slice(8, 16)));
}
