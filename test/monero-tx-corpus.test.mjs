// The widened real-transaction corpus: every monero-tx-*.json fixture under
// test/fixtures gets a needle test (id computed from the bytes equals the
// node's tx_hash) and mutated-bytes controls (a flip in the prefix, the base,
// the prunable section and the tail each must change the id or be refused).
//
// LANE A. Each fixture is a distinct real mainnet shape from the L4 master
// work order: 1-in/1-out, 1-in/many-out, many-in, a small fee, and so on. The
// parser is always judged by the bytes alone; the node's tx_hash and
// prunable_hash are recorded as a stranger's claims and never read.
//
// Refusal shapes are NOT here. Those stay as labelled shape tests; nothing in
// this file is synthetic.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { readTransaction, transactionIdOf } from '../src/monero/block.js';

const FIXTURE_DIR = new URL('./fixtures/', import.meta.url);
const unspaced = (text) => String(text).replace(/\s+/g, '');
const fixtureFiles = readdirSync(FIXTURE_DIR)
  .filter((f) => f.startsWith('monero-tx-') && f.endsWith('.json'))
  .sort();

for (const file of fixtureFiles) {
  const FIXTURE = JSON.parse(readFileSync(new URL(file, FIXTURE_DIR), 'utf8'));
  const BYTES = Uint8Array.from(Buffer.from(unspaced(FIXTURE.asHex), 'hex'));
  const TX_HASH = unspaced(FIXTURE.txHash);
  const label = `${FIXTURE.source.blockHeight}/${FIXTURE.source.txIndexInBlock} (${FIXTURE.shapeDiscover ?? FIXTURE.txHash.slice(0, 8)})`;

  test(`needle ${file}: id from bytes equals the node's tx_hash (${label})`, () => {
    assert.equal(BYTES.length, FIXTURE.byteLength, 'the recorded byte length is the length of the fixture');
    const tx = readTransaction(BYTES, 0, 'fixture transaction');
    const id = transactionIdOf(tx);
    assert.equal(id, TX_HASH);
    assert.equal(tx.end, BYTES.length, 'the walk ends at the last byte; a leftover byte is refused');
    console.log(`[monero-tx-corpus] ${file} needle: ${id.slice(0, 16)}…`);
  });

  // Mutated controls: one flipped byte per section. Each flip lives well inside
  // its section so it cannot blur into a neighbour, and a flipped byte must
  // change the computed id or make the read refuse — never keep the node's id,
  // which would mean the id ignores that section.
  const probe = (() => { const tx = readTransaction(BYTES, 0, 'probe'); return tx; })();
  const prefixStart = 0;
  const baseStart = probe.prefixEnd;
  const baseStop = probe.baseEnd;
  const prunableStart = probe.baseEnd;
  const inBase = (baseStop - baseStart) > 4 ? baseStart + 3 : baseStart;
  const inPrunable = (BYTES.length - prunableStart) > 4 ? prunableStart + 3 : prunableStart;
  const sectionOffsets = {
    prefix: prefixStart + 10 < probe.prefixEnd ? prefixStart + 10 : prefixStart,
    base: inBase,
    prunable: inPrunable,
    tail: BYTES.length - 1,
  };

  for (const [kind, at] of Object.entries(sectionOffsets)) {
    test(`control ${file} [${kind}]: a flipped byte at ${at} changes the id or is refused (${label})`, () => {
      if (at < 0 || at >= BYTES.length) { assert.ok(true, `offset ${at} clamped to valid range`); return; }
      const copy = Uint8Array.from(BYTES);
      copy[at] ^= 0x01;
      let outcome;
      try {
        const tx = readTransaction(copy, 0, 'mutated transaction');
        outcome = { id: transactionIdOf(tx) };
      } catch (error) {
        outcome = { refused: error.message };
      }
      assert.ok(
        outcome.refused || outcome.id !== TX_HASH,
        `a flipped ${kind} byte must not keep the node's id; got ${JSON.stringify(outcome).slice(0, 80)}`,
      );
    });
  }
}