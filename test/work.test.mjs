// A header has to prove its work.
//
// Before this, the walk hashed headers and checked links and merkle roots, and
// never checked that a header was below the target it named — so a peer could
// invent a self-consistent 80-byte header, mine it for free, and serve a
// private chain. These tests pin the two halves of the fix: the compact-target
// decode, and the refusal of a header that does not meet its own target.

import test from 'node:test';
import assert from 'node:assert/strict';
import { hex } from '@scure/base';

import { headerHash, blockHash, walkBack } from '../src/chain.js';
import { meetsWork, targetFromBits, workRefusal, stampWork, EASY_BITS } from '../src/work.js';
import { reverseBytes, serializeTx, txid } from '../src/tx.js';

// The mainnet genesis header, byte for byte. Real, mined, and its nBits
// (0x1d00ffff) is the easiest real mainnet target. A header that is real must
// keep passing now that work is checked.
const GENESIS_HEADER = hex.decode(
  '01000000'
  + '00'.repeat(32)
  + '3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a'
  + '29ab5f49'
  + 'ffff001d'
  + '1dac2b7c',
);

function witness(name, ...values) {
  console.log(`[work] ${name}: ${values.join(' | ')}`);
}

test('the mainnet genesis header meets its own target', () => {
  assert.equal(GENESIS_HEADER.length, 80);
  assert.equal(
    headerHash(GENESIS_HEADER),
    '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f',
    'the pinned header is the genesis block, from its own bytes',
  );
  assert.equal(meetsWork(GENESIS_HEADER), true);
  assert.equal(workRefusal(GENESIS_HEADER), null);
  witness('genesis', headerHash(GENESIS_HEADER).slice(0, 16), 'meets work');
});

test('a header whose target is impossibly hard is refused by name', () => {
  // bits 0x03000000: exponent 3, mantissa 0 -> target 0, which no hash can meet.
  const header = Uint8Array.from(GENESIS_HEADER);
  header.set([0x00, 0x00, 0x00, 0x03], 72);
  assert.equal(meetsWork(header), false);
  assert.match(workRefusal(header), /zero proof-of-work target|does not meet/i);
  witness('impossible target', 'bits 0x03000000', 'refused');
});

test('the sign bit and a zero mantissa both decode to a refused target', () => {
  // The sign bit set on a non-zero mantissa is bitcoin's "negative" target.
  assert.throws(() => targetFromBits(0x01800001), /zero proof-of-work target/);
  // A zero mantissa is a zero target however large the exponent.
  assert.throws(() => targetFromBits(0x03000000), /zero proof-of-work target/);
  assert.throws(() => targetFromBits(0x00000000), /zero proof-of-work target/);
  // A negative test with a positive control: 0x1d00ffff is a real target.
  assert.doesNotThrow(() => targetFromBits(0x1d00ffff));
  witness('sign bit + zero', 'negative refused', 'zero refused');
});

test('targetFromBits decodes a known compact value to the right 256-bit bigint', () => {
  // 0x1d00ffff is the genesis difficulty: mantissa 0xffff, exponent 0x1d.
  assert.equal(targetFromBits(0x1d00ffff), 0xffffn << 208n);
  // And the regtest-grade target used to stamp synthetic headers.
  assert.equal(targetFromBits(EASY_BITS), 0x7fffffn << 232n);
  // Below exponent 3 the mantissa is shifted right, not left.
  assert.equal(targetFromBits(0x02008000), 128n);
  witness('decode', `0x1d00ffff -> ${targetFromBits(0x1d00ffff).toString(16).slice(0, 8)}…`);
});

test('stampWork writes a real target and grinds the nonce until it is met', () => {
  const header = stampWork(new Uint8Array(80).fill(0x2a));
  assert.equal(
    (header[72] | (header[73] << 8) | (header[74] << 16) | (header[75] << 24)) >>> 0,
    EASY_BITS,
    'the nBits field is the easy target, little-endian',
  );
  assert.equal(meetsWork(header), true);
  // Raising the target to something the same bytes cannot reach refuses them.
  const hard = Uint8Array.from(header);
  hard.set([0x00, 0x00, 0x00, 0x03], 72);
  assert.equal(meetsWork(hard), false);
  witness('stamp', hex.encode(header.slice(72, 76)), 'meets work');
});

// The boolean and the named refusal must never disagree: a header refused by
// one is refused by the other, so a caller using either sees the same verdict.
test('meetsWork and workRefusal agree at the boundary', () => {
  const header = stampWork(new Uint8Array(80).fill(3));
  assert.equal(meetsWork(header), workRefusal(header) === null);
});

// A block whose body is self-consistent but whose header names an unreachable
// target. The walk must refuse it at the header, by name, before the body is
// believed. Without the chain.js wiring this block would walk cleanly.
function blockWith(prevDigest, fill) {
  const tx = {
    version: 1,
    inputs: [{ txid: '00'.repeat(32), vout: 0xffffffff, scriptSig: Uint8Array.of(fill), sequence: 0xffffffff }],
    outputs: [{ value: 1000n, script: Uint8Array.of(0x51) }],
    lockTime: 0,
  };
  const header = new Uint8Array(80).fill(fill);
  header.set(prevDigest, 4);
  header.set(reverseBytes(hex.decode(txid(tx))), 36);
  stampWork(header);
  return { header, block: new Uint8Array([...header, 0x01, ...serializeTx(tx, { witness: false })]) };
}

test('the walk refuses a self-consistent block whose header meets no target', async () => {
  const { block } = blockWith(new Uint8Array(32), 7);
  // Reset nBits to an impossible target after the stamp. The bytes and merkle
  // root are untouched; only the work claim is not backed.
  const bad = Uint8Array.from(block);
  bad.set([0x00, 0x00, 0x00, 0x03], 72);
  const good = block;

  const served = new Map([[blockHash(good), good], [blockHash(bad), bad]]);
  const fetchBlock = async (_peer, asked) => {
    const bytes = served.get(asked);
    if (!bytes) throw new Error(`no such block ${asked}`);
    return { bytes };
  };

  // Positive control: the same block with its stamped target walks.
  const ok = await walkBack({ fetchBlock, peer: {}, tipHash: blockHash(good), tipHeight: 1 });
  assert.equal(ok.length, 1);

  await assert.rejects(
    walkBack({ fetchBlock, peer: {}, tipHash: blockHash(bad), tipHeight: 1 }),
    /does not meet its own work target|zero proof-of-work/,
  );
  witness('walk-level work', 'good walks', 'unbacked header refused by name');
});
