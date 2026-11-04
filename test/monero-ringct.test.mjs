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
import { readFileSync } from 'node:fs';
import { Session } from 'node:inspector';
import { hex } from '@scure/base';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { decodePoint, encodePoint, varint } from '../src/monero/keys.js';
import { COMMITMENT_H_BYTES, MAX_ATOMIC, commitmentOf } from '../src/monero/ringct.js';

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

// C = amount*H + mask*G, but a zero amount or zero mask has a branch that
// returns the other addend directly (and a both-zero branch that returns the
// identity) rather than multiplying by zero. The three states are pinned to
// their three exact outputs first.
const H_POINT = decodePoint(COMMITMENT_H_BYTES);
const G_POINT = decodePoint(Uint8Array.from([
  0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
]));

test('commitmentOf returns each surviving addend for a zero amount or zero mask', () => {
  // amount 0 -> mask*G only.
  assert.equal(hex.encode(commitmentOf({ amount: 0n, mask: 3n })), hex.encode(encodePoint(G_POINT.multiplyUnsafe(3n))));
  // mask 0 -> amount*H only.
  assert.equal(hex.encode(commitmentOf({ amount: 3n, mask: 0n })), hex.encode(encodePoint(H_POINT.multiplyUnsafe(3n))));
  // both 0 -> the identity point, 0x01 then thirty-one zero bytes.
  assert.equal(hex.encode(commitmentOf({ amount: 0n, mask: 0n })), hex.encode(encodePoint(ed25519.Point.ZERO)));
  // and the general case is the sum, so the branches agree with the formula.
  assert.equal(
    hex.encode(commitmentOf({ amount: 5n, mask: 7n })),
    hex.encode(encodePoint(H_POINT.multiplyUnsafe(5n).add(G_POINT.multiplyUnsafe(7n)))),
  );
});

// Those outputs alone cannot watch the branches: 0*X is the identity and adding
// the identity is a no-op, so forcing either condition false changes no bytes
// (verified by mutation). The witness has to see which arm ran, and V8 precise
// coverage does. A fresh module instance per case (query string) makes the
// function's first execution of that case carry the untaken arms; a fresh
// instance matters because a warm function reports only its outer range.
const RINGCT_SRC = readFileSync(new URL('../src/monero/ringct.js', import.meta.url), 'utf8');
let coverageSeq = 0;

async function untakenArms(call) {
  const session = new Session();
  session.connect();
  const post = (method, params) => new Promise((resolve, reject) => {
    session.post(method, params, (error, result) => (error ? reject(error) : resolve(result)));
  });
  await post('Profiler.enable');
  await post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  coverageSeq += 1;
  const module = await import(`../src/monero/ringct.js?arms=${coverageSeq}`);
  call(module.commitmentOf);
  const { result } = await post('Profiler.takePreciseCoverage');
  await post('Profiler.stopPreciseCoverage');
  await post('Profiler.disable');
  session.disconnect();
  const entry = result.find((r) => r.url.includes('/src/monero/ringct.js'));
  const fn = entry.functions.find((f) => f.functionName === 'commitmentOf');
  return fn.ranges
    .filter((r) => r.count === 0)
    .map((r) => RINGCT_SRC.slice(r.startOffset, r.endOffset).replace(/\s+/g, ' '));
}

test('a zero amount, a zero mask, and both zero each take their own branch', async () => {
  const amount0 = await untakenArms((c) => c({ amount: 0n, mask: 3n }));
  assert.ok(
    amount0.includes(': decodePoint(COMMITMENT_H_BYTES).multiplyUnsafe(amount)'),
    'a zero amount must skip amount*H, not compute it and add the identity',
  );

  const mask0 = await untakenArms((c) => c({ amount: 3n, mask: 0n }));
  assert.ok(
    mask0.includes(': decodePoint(BASE_POINT).multiplyUnsafe(maskScalar)'),
    'a zero mask must skip mask*G, not compute it and add the identity',
  );

  const both0 = await untakenArms((c) => c({ amount: 0n, mask: 0n }));
  assert.ok(
    both0.includes(': (maskPoint === null ? amountPoint : amountPoint.add(maskPoint))'),
    'both zero must reach the identity arm, not the sum arm',
  );
  assert.ok(
    !both0.includes('? decodePoint(BASE_POINT).multiplyUnsafe(0n)'),
    'the identity arm is the one that runs when both amount and mask are zero',
  );
});
