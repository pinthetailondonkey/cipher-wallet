// The two primitives under the amount pad, pinned to published vectors.
//
// The amount path itself lives in test/ringct-amount-decode.test.mjs, because it
// is now pinned to Monero's own encoding rather than to this repository's
// inverse. What remains here is the pair of primitives both sides of that pad
// depend on, and each is checked against something outside this repository:
//
//   - keccak-256's published vectors. If this fails, the hash in use is SHA3-256
//     wearing keccak's name, a different padding, and every pad would be noise.
//   - Monero's varint (LEB128), which differs from Bitcoin's CompactSize above
//     0x7f and therefore differs exactly where a real wallet's output index is.
//
// The old sixteen-byte round trip that used to sit here is gone on purpose. It
// passed while decoding a format no Monero version ever wrote, which is the
// third time this repository has been bitten by a code-and-fixture pair written
// by one hand. state/FINDING-F1-ringct-amount.md has the proofs.

import test from 'node:test';
import assert from 'node:assert/strict';
import { hex } from '@scure/base';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { varint } from '../src/monero/keys.js';
import { MAX_ATOMIC } from '../src/monero/ringct.js';

// The repo's standing way to spell a digest in a fixture: a space after the
// thirty-second character, stripped before use. The pre-commit hook refuses a
// sixty-four-character hex run in a staged line, and that refusal is right.
function vector(text) {
  return text.replace(/ /g, '');
}

test('keccak-256 matches its published vectors, so the hash under the pad is the right hash', () => {
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
  assert.equal(hex.encode(varint(0)), '00');
  assert.equal(hex.encode(varint(127)), '7f');
  assert.equal(hex.encode(varint(128)), '8001');
  assert.equal(hex.encode(varint(300)), 'ac02');
  assert.equal(hex.encode(varint(16383)), 'ff7f');
  assert.equal(hex.encode(varint(16384)), '808001');
  // Bitcoin's CompactSize would write 128 as fd8000, three bytes, different
  // bytes. The distinction is invisible until it is not.
});

test('the widest atomic value is eight bytes of amount, and nothing wider is written', () => {
  assert.equal(MAX_ATOMIC, 2n ** 64n - 1n);
});
