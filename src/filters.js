// Finding your own coins without asking anyone which coins are yours.
//
// BIP-157/158: every block has a small filter committing to the scripts it
// touched. A wallet downloads the filters and asks, locally, whether any of its
// own scripts appear. The peer serving them is never told the answer, and no
// block explorer is involved.
//
// The honest limit, stated where it cannot be lost: the peer learns WHICH
// BLOCKS matched your wallet over time, because you keep coming back for the
// next filter after a hit. The mitigation is several peers, chosen by you, over
// Tor, and rotating them — not a claim that this is free. A block explorer
// learns the same thing plus your address and your IP in one request.
//
// Scope: the basic filter type (0x00), P = 19, M = 784931. SipHash-2-4 is
// written here rather than taken from a dependency; it is checked against the
// published filters in the BIP-158 test vectors, which is a stronger check
// than a hand-copied hash value.

import { hex } from '@scure/base';
import { readVarint, reverseBytes, sha256d } from './tx.js';
import { verifyBlockBody } from './merkle.js';

export const BASIC_FILTER_TYPE = 0x00;
export const GOLOMB_P = 19;
export const GOLOMB_M = 784931;

const MASK64 = 0xffffffffffffffffn;

// ---- SipHash-2-4 -----------------------------------------------------------

function rotl64(value, bits) {
  const b = BigInt(bits);
  return ((value << b) | (value >> (64n - b))) & MASK64;
}

function readU64le(bytes, at) {
  let value = 0n;
  for (let i = 7; i >= 0; i -= 1) value = (value << 8n) | BigInt(bytes[at + i]);
  return value;
}

export function siphash24(key, data) {
  if (!(key instanceof Uint8Array) || key.length !== 16) throw new Error('SipHash needs a 16-byte key.');
  if (!(data instanceof Uint8Array)) throw new Error('SipHash needs bytes.');

  const k0 = readU64le(key, 0);
  const k1 = readU64le(key, 8);

  let v0 = 0x736f6d6570736575n ^ k0;
  let v1 = 0x646f72616e646f6dn ^ k1;
  let v2 = 0x6c7967656e657261n ^ k0;
  let v3 = 0x7465646279746573n ^ k1;

  const round = () => {
    v0 = (v0 + v1) & MASK64;
    v1 = rotl64(v1, 13);
    v1 ^= v0;
    v0 = rotl64(v0, 32);
    v2 = (v2 + v3) & MASK64;
    v3 = rotl64(v3, 16);
    v3 ^= v2;
    v0 = (v0 + v3) & MASK64;
    v3 = rotl64(v3, 21);
    v3 ^= v0;
    v2 = (v2 + v1) & MASK64;
    v1 = rotl64(v1, 17);
    v1 ^= v2;
    v2 = rotl64(v2, 32);
  };

  const whole = Math.floor(data.length / 8);
  for (let i = 0; i < whole; i += 1) {
    const m = readU64le(data, i * 8);
    v3 ^= m;
    round();
    round();
    v0 ^= m;
  }

  const tail = new Uint8Array(8);
  tail.set(data.slice(whole * 8), 0);
  tail[7] = data.length & 0xff;
  const m = readU64le(tail, 0);
  v3 ^= m;
  round();
  round();
  v0 ^= m;

  v2 ^= 0xffn;
  round();
  round();
  round();
  round();

  return (v0 ^ v1 ^ v2 ^ v3) & MASK64;
}

// ---- the range reduction and the coded set ---------------------------------

// The first 16 bytes of the block hash, as a uint256: the digest, not the
// reversed form a block explorer prints.
export function filterKey(blockHash) {
  const text = String(blockHash ?? '').trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(text)) throw new Error('A block hash is 64 hex characters.');
  return reverseBytes(hex.decode(text)).slice(0, 16);
}

function hashToRange(item, key, range) {
  const hashed = siphash24(key, item);
  return Number((hashed * range) >> 64n);
}

function sortedScripts(scripts) {
  const seen = new Set();
  const out = [];
  for (const script of scripts) {
    const text = hex.encode(script);
    if (seen.has(text)) continue;
    seen.add(text);
    out.push(script);
  }
  return out;
}

class BitWriter {
  constructor() {
    this.bits = [];
  }

  bit(value) {
    this.bits.push(value ? 1 : 0);
  }

  take(count, value) {
    for (let i = count - 1; i >= 0; i -= 1) this.bit((value >> i) & 1);
  }

  unary(count) {
    for (let i = 0; i < count; i += 1) this.bit(1);
    this.bit(0);
  }

  bytes() {
    const out = new Uint8Array(Math.ceil(this.bits.length / 8));
    for (let i = 0; i < this.bits.length; i += 1) {
      if (this.bits[i]) out[i >> 3] |= 0x80 >> (i & 7);
    }
    return out;
  }
}

class BitReader {
  constructor(bytes) {
    this.bytes = bytes;
    this.at = 0;
  }

  bit() {
    if ((this.at >> 3) >= this.bytes.length) throw new Error('The filter ended early.');
    const value = (this.bytes[this.at >> 3] >> (7 - (this.at & 7))) & 1;
    this.at += 1;
    return value;
  }

  unary() {
    let count = 0;
    while (this.bit() === 1) {
      count += 1;
      if (count > 1 << 24) throw new Error('The filter is not a filter.');
    }
    return count;
  }

  take(count) {
    let value = 0;
    for (let i = 0; i < count; i += 1) value = (value * 2) + this.bit();
    return value;
  }
}

function encodeVarint(n) {
  if (n < 0xfd) return Uint8Array.of(n);
  if (n <= 0xffff) return Uint8Array.of(0xfd, n & 0xff, (n >> 8) & 0xff);
  return Uint8Array.of(0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff);
}

// The basic filter's contents: every output script that is not OP_RETURN and
// not empty, plus every script spent by a non-coinbase input. Empty scripts
// are "nil" and BIP-158 says they are not included.
export function filterScripts({ outputScripts = [], prevScripts = [] } = {}) {
  const picked = [];
  for (const script of outputScripts) {
    if (!(script instanceof Uint8Array) || script.length === 0) continue;
    if (script[0] === 0x6a) continue;
    picked.push(script);
  }
  for (const script of prevScripts) {
    if (!(script instanceof Uint8Array) || script.length === 0) continue;
    picked.push(script);
  }
  return sortedScripts(picked);
}

export function buildBasicFilter({ outputScripts = [], prevScripts = [], blockHash } = {}) {
  const key = filterKey(blockHash);
  const items = filterScripts({ outputScripts, prevScripts });
  const range = BigInt(items.length * GOLOMB_M);

  const values = items.map((item) => hashToRange(item, key, range)).sort((a, b) => a - b);

  const writer = new BitWriter();
  let last = 0;
  for (const value of values) {
    const delta = value - last;
    writer.unary(Math.floor(delta / 2 ** GOLOMB_P));
    writer.take(GOLOMB_P, delta % 2 ** GOLOMB_P);
    last = value;
  }

  const body = writer.bytes();
  return new Uint8Array([...encodeVarint(items.length), ...body]);
}

// Does this block's filter name this script? Decoded locally; the peer never
// sees the question or the answer.
export function matchesFilter(filterBytes, blockHash, script) {
  if (!(filterBytes instanceof Uint8Array)) throw new Error('A filter is bytes.');
  if (!(script instanceof Uint8Array) || script.length === 0) return false;

  const key = filterKey(blockHash);
  const count = readVarint(filterBytes, 0);
  if (count.value === 0) return false;

  const target = hashToRange(script, key, BigInt(count.value * GOLOMB_M));
  const reader = new BitReader(filterBytes.slice(count.offset));

  let last = 0;
  for (let i = 0; i < count.value; i += 1) {
    const quotient = reader.unary();
    const value = (quotient * 2 ** GOLOMB_P) + reader.take(GOLOMB_P);
    last += value;
    // The set is sorted, so the moment we pass the target it cannot match.
    if (last === target) return true;
    if (last > target) return false;
  }
  return false;
}

// BIP-157 filter header: SHA256d(filter_hash || previous_header), with
// filter_hash = SHA256(filter bytes) — single hash, then double.
//
// Two details that cost two wrong answers before the vectors settled them:
// the canonical filter hash is a DOUBLE SHA-256 of the filter (BIP-157 is
// explicit), and both headers are exchanged in display order, so the previous
// header is reversed into digest order for the concatenation and the result is
// reversed back out.
export function filterHeader(filterBytes, previousHeader) {
  if (!(filterBytes instanceof Uint8Array)) throw new Error('A filter is bytes.');
  const prev = previousHeader instanceof Uint8Array ? previousHeader : hex.decode(String(previousHeader ?? ''));
  if (prev.length !== 32) throw new Error('The previous filter header is 32 bytes. Genesis uses 32 zeros.');
  return reverseBytes(sha256d(concatBytes([sha256d(filterBytes), reverseBytes(prev)])));
}

function concatBytes(parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

// Where the outputs of a block live, for building its filter from the block
// itself.
//
// The body is checked against its header before a single script is handed out
// (src/merkle.js). A filter rebuilt from a body that no header commits to would
// agree with itself and prove nothing, which is exactly the forge two colluding
// peers used: keep a real header, attach a body of your own, and the filter
// built from that body matches the filter you served.
export function blockOutputScripts(blockBytes) {
  const { blockHash, transactions } = verifyBlockBody(blockBytes);
  const scripts = [];
  for (const tx of transactions) {
    for (const output of tx.outputs) scripts.push(output.script);
  }
  return { blockHash, scripts };
}

// Does this filter really describe this block? The peer's filter is rebuilt
// from the block's own bytes — every output script, plus the scripts spent by
// non-coinbase inputs — and compared byte for byte. `prevScripts` is the chain
// context the caller has already scanned; a caller that does not know it cannot
// verify a filter, and must not pretend to.
export function filterMatchesBlock({ filter, block, prevScripts } = {}) {
  if (!(filter instanceof Uint8Array) || filter.length === 0) throw new Error('A filter is bytes.');
  if (!(block instanceof Uint8Array) || block.length === 0) throw new Error('A block is bytes.');
  // A rebuild without the scripts this block's inputs spend produces a filter
  // that cannot equal the real one for any block that spends anything, so the
  // honest answer is a refusal, not `false`. `false` reads as "this filter is
  // wrong"; the truth is "this wallet cannot tell". An empty list is a claim,
  // and it is only true when the block spends nothing from outside itself.
  if (!Array.isArray(prevScripts)) {
    throw new Error('Verifying a filter needs the scripts this block\'s inputs spend. Pass [] only when the block spends nothing outside itself.');
  }
  const { blockHash, scripts } = blockOutputScripts(block);
  const rebuilt = buildBasicFilter({ outputScripts: scripts, prevScripts, blockHash });
  if (rebuilt.length !== filter.length) return false;
  let diff = 0;
  for (let i = 0; i < rebuilt.length; i += 1) diff |= rebuilt[i] ^ filter[i];
  return diff === 0;
}
