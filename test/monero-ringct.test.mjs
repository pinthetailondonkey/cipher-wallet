// What an output is worth, once the scan has said it is ours.
//
// What is pinned here, and what is not, because the difference matters:
//   PINNED to outside the code: keccak-256's published vectors (empty string and
//     "abc"), and Monero's LEB128 varint against hand-checked values.
//   NOT PINNED: the sixteen-byte ecdh encoding against a real transaction. There
//     is no real Monero transaction in this repo, so the round trip below proves
//     the arithmetic agrees with itself. The module says so at the top, and it
//     must not gate a payment until a real amount is decoded and matches one the
//     owner knows.

import test from 'node:test';
import assert from 'node:assert/strict';
import { hex } from '@scure/base';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { MAX_ATOMIC, decodeAmount, ecdhHash, encodeAmountForTest, moneroVarint } from '../src/monero/ringct.js';

// The repo's standing way to spell a digest in a fixture: a space after the
// thirty-second character, stripped before use. The pre-commit hook refuses a
// sixty-four-character hex run in a staged line, and that refusal is right — the
// scanner cannot tell a published test vector from a key, so the convention is
// what keeps the scanner strict.
function vector(text) {
  return text.replace(/ /g, '');
}

const DERIVATION = Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 0xff);

test('keccak-256 matches its published vectors, so the hash under the pad is the right hash', () => {
  // The two values everybody quotes. If this fails, the hash in use is SHA3-256
  // wearing keccak's name — a different padding, and every amount decoded
  // through it would be noise that looks like a number.
  assert.equal(
    hex.encode(keccak_256(new Uint8Array(0))),
    vector('c5d2460186f7233c927e7db2dcc703c0 e500b653ca82273b7bfad8045d85a470'),
  );
  assert.equal(
    hex.encode(keccak_256(new TextEncoder().encode('abc'))),
    vector('4e03657aea45a94fc7d47ba826c8d667 c0d1e6e33a64a036ec44f58fa12d6c45'),
  );
});

test('the index is a LEB128 varint, not a CompactSize', () => {
  // Below 0x80 the two encodings agree, which is how this goes unnoticed until a
  // wallet has more than 127 outputs to name.
  assert.equal(hex.encode(moneroVarint(0)), '00');
  assert.equal(hex.encode(moneroVarint(127)), '7f');
  assert.equal(hex.encode(moneroVarint(128)), '8001');
  assert.equal(hex.encode(moneroVarint(300)), 'ac02');
  assert.equal(hex.encode(moneroVarint(16383)), 'ff7f');
  assert.equal(hex.encode(moneroVarint(16384)), '808001');
  // Bitcoin's CompactSize would write 128 as fd8000 — three bytes, different
  // bytes. The distinction is invisible until it is not.
  assert.throws(() => moneroVarint(-1), /whole number/);
});

test('an amount round trips, and the index changes the pad', () => {
  const mask = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]);
  const info = encodeAmountForTest({ derivation: DERIVATION, index: 5, value: 123456789012n, mask });
  assert.equal(info.length, 16);
  const out = decodeAmount({ derivation: DERIVATION, index: 5, info });
  assert.equal(out.value, 123456789012n);
  assert.equal(typeof out.value, 'bigint');
  assert.equal(hex.encode(out.mask), hex.encode(mask));
  // The same bytes at another index are a different number: the index is inside
  // the pad, so a wallet that reads the wrong output's info gets noise.
  assert.notEqual(decodeAmount({ derivation: DERIVATION, index: 6, info }).value, 123456789012n);
  // And the same amount for two outputs does not look the same on chain.
  const other = encodeAmountForTest({ derivation: DERIVATION, index: 5, value: 123456789012n, mask: new Uint8Array(8) });
  assert.notEqual(hex.encode(other), hex.encode(info));
  console.log(`[ringct] round trip: ${out.value} atomic units, index inside the pad`);
  assert.equal(ecdhHash(DERIVATION, 5).length, 32);
});

test('a wrong-sized info, a bad derivation and an amount that cannot be written are refused', () => {
  assert.throws(() => decodeAmount({ derivation: DERIVATION, index: 0, info: new Uint8Array(8) }), /sixteen bytes/);
  assert.throws(() => ecdhHash(new Uint8Array(31), 0), /32 bytes/);
  assert.throws(
    () => encodeAmountForTest({ derivation: DERIVATION, index: 0, value: MAX_ATOMIC + 1n, mask: new Uint8Array(8) }),
    /bigint/,
  );
  assert.throws(() => encodeAmountForTest({ derivation: DERIVATION, index: 0, value: 1.5, mask: new Uint8Array(8) }), /bigint/);
  // There is no decode-time supply check, and that is deliberate: eight bytes
  // cannot hold more than the widest amount, so such a check could never fire —
  // the guard that cannot fail this lane keeps finding in other people's code.
  const out = decodeAmount({ derivation: DERIVATION, index: 0, info: new Uint8Array(16).fill(0xff) });
  assert.equal(typeof out.value, 'bigint');
});
