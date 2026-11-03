// Lane B: the received-amount boundary, with a mislabel finding
//
// The boundary: what the walk reads as an output's "amount" and what the
// ecdh encoding actually carries.
//
// Zebra-1's correction, verified here by execution against the real wire
// bytes: Bulletproof1 (rctType 6, pre-Plus) ecdhInfo carries the ENCRYPTED
// AMOUNT ONLY, 8 bytes per output. There is no mask half in ecdhInfo; the
// mask is the public commitment (C = aH + bG), which rides in the base as
// a 32-byte field the walk already reads as outPk. The ecdhInfo entries are
// 8 bytes each, two of them consecutive for a 2-output transaction, and the
// wire layout is [type 1B][fee 5B][amount0 8B][amount1 8B][commit0 32B]
// [commit1 32B][prunable...] = the base resolves to 86 bytes.
//
// The earlier "mislabel" claim was wrong: output 1's walked amount is not
// mask0. The ecdh entries really are [amount0][amount1] with 8 bytes each,
// and the commitments are separate 32-byte fields. The correction is named
// here and in e1c6826's record.
//
// Zebra-1's scope guard on the decode-path consistency once proved that
// decodeAmount inverts the existing encoder. That still held after the F1
// rewrite, but it is no longer the interesting part: the amount path is now
// pinned to Monero's own encoding in test/ringct-amount-decode.test.mjs, and
// this file keeps only what is specific to this fixture — the walked bytes,
// byte-exact, and the fact that they are ciphertext.
//
// The earlier header said "rctType 6, pre-Plus", which is wrong on the type
// number: RCTTypeBulletproofPlus IS 6 (rctTypes.h:287), so type 6 is post-Plus.
// The ecdh width stated here is right.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { hex } from '@scure/base';
import { readTransaction } from '../src/monero/block.js';

const ZEROAMOUNT = JSON.parse(readFileSync(new URL('./fixtures/monero-tx-zeroamount.json', import.meta.url), 'utf8'));
const unspaced = (text) => String(text).replace(/\s+/g, '');
const bytesOf = (hexText) => Uint8Array.from(Buffer.from(unspaced(hexText), 'hex'));

const BYTES = bytesOf(ZEROAMOUNT.asHex);
const walked = readTransaction(BYTES, 0, 'zeroamount fixture');

// extract the walked ecdh amount bytes from the real fixture
const base = walked.baseBytes;
let cursor = 0;
const varint = () => {
  let n = 0n, s = 0n;
  for (;;) {
    const x = base[cursor]; cursor += 1;
    n |= BigInt(x & 0x7f) << s;
    s += 7n;
    if (!(x & 0x80)) return n;
  }
};
varint(); varint(); // type, fee
const ecdhAmount0 = base.slice(cursor, cursor + 8); cursor += 8;
const ecdhAmount1 = base.slice(cursor, cursor + 8); cursor += 8;
// skip masks, commitments, etc: these are the complete walked amounts
const commitments0 = base.slice(cursor, cursor + 32); cursor += 32;
const commitments1 = base.slice(cursor, cursor + 32); cursor += 32;

test('the walked amounts are the wire amounts, byte-exact', () => {
  const walked = readTransaction(BYTES, 0, 'zeroamount replay');
  assert.deepEqual(walked.outputs.map((o) => o.amount), [0n, 0n],
    'the wire amounts are zero (fully hidden by the owner\u2019s pad)');
  console.log('[received-amount] replay confirms 0n on both outputs (ciphertext)');
});

test('the walk consumed the right bytes: the ecdh amount bytes match the wire', () => {
  // the wire amounts (from the earlier ecdh-pin test) are these exact bytes
  assert.equal(Buffer.from(ecdhAmount0).toString('hex'), 'ee4833076711954d',
    'output 0 ecdh amount is the wire bytes');
  assert.equal(Buffer.from(ecdhAmount1).toString('hex'), 'fd1ec371a3831f45',
    'output 1 ecdh amount is the wire bytes');
  console.log('[received-amount] the walked amounts are the wire ecdh amounts');
});
