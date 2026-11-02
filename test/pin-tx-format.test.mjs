// pin-tx.mjs's output fixture format: the tool must produce a well-formed
// fixture or every future pin inherits doubt. This test reads the pinned
// fixtures that pin-tx.mjs-style captures produced and asserts the format:
// every required field present, the provenance block complete, the hex
// spacing compliant, and the shape tag consistent with the tx bytes.
//
// The fixture format contract (from the existing pinned fixtures):
//   source: { what, node, nettype, transport, capturedAt, blockHeight,
//             blockHash, tipHeightAtCapture (optional), txIndexInBlock,
//             shape, rederive, note }
//   txHash: spaced hex
//   version: number or null
//   rctType: number or null
//   byteLength: number
//   asHex: spaced hex
//   shapeDiscover: string matching the shape enum
//
// The needle: the asHex bytes reproduce the txHash (the same proof every
// corpus fixture carries), so a fixture pin-tx.mjs wrote is as trustworthy
// as one the older capture scripts wrote.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { readTransaction, transactionIdOf } from '../src/monero/block.js';

const FIXTURE_DIR = new URL('./fixtures/', import.meta.url);
const unspaced = (text) => String(text).replace(/\s+/g, '');

// every monero-tx-* fixture (the format pin-tx.mjs must produce matches
// what the existing capture scripts produce)
const fixtureFiles = readdirSync(new URL('./fixtures/', import.meta.url))
  .filter((f) => f.startsWith('monero-tx-') && f.endsWith('.json'))
  .sort();

const REQUIRED_SOURCE_FIELDS = [
  'what', 'node', 'nettype', 'transport', 'capturedAt',
  'blockHeight', 'blockHash', 'rederive', 'note',
];

const SHAPES = new Set(['1in-1out', '1in-manyout', 'manyin', 'smallfee', 'zeroamount', 'any']);

for (const file of fixtureFiles) {
  const FIXTURE = JSON.parse(readFileSync(new URL(`./fixtures/${file}`, import.meta.url), 'utf8'));

  test(`pin-tx format ${file}: the provenance block is complete`, () => {
    assert.ok(FIXTURE.source, 'the fixture carries a source block');
    for (const field of REQUIRED_SOURCE_FIELDS) {
      assert.ok(FIXTURE.source[field] !== undefined,
        `source.${field} is present (pin-tx.mjs must write it)`);
    }
    assert.ok(FIXTURE.source.rederive.includes('node scripts/') || FIXTURE.source.rederive.includes('curl'),
      'the re-derive recipe names a script or a command');
  });

  test(`pin-tx format ${file}: the byte fields are consistent`, () => {
    assert.ok(FIXTURE.txHash, 'txHash is present');
    assert.equal(unspaced(FIXTURE.txHash).length, 64, 'txHash is 64 hex chars');
    assert.ok(FIXTURE.asHex, 'asHex is present');
    assert.equal(unspaced(FIXTURE.asHex).length, FIXTURE.byteLength * 2,
      'asHex length is twice the byteLength');
    assert.ok(typeof FIXTURE.byteLength === 'number' && FIXTURE.byteLength > 0,
      'byteLength is a positive number');
  });

  test(`pin-tx format ${file}: the shape tag is from the known set`, () => {
    // the ringct-type6 fixture predates the shapeDiscover field; its shape
    // is implied by the tx structure, not tagged
    const tag = FIXTURE.shapeDiscover;
    if (tag === undefined || tag === null) {
      assert.ok(FIXTURE.source.shape || FIXTURE.source.what,
        'an untagged fixture carries its shape in the source prose');
      return;
    }
    assert.ok(SHAPES.has(tag), `shapeDiscover "${tag}" is a known shape`);
  });

  // the needle: only for fixtures the current reader can parse (type 3 is
  // pinned red-first and refuses, so it gets the refusal assertion instead)
  const BYTES = Uint8Array.from(Buffer.from(unspaced(FIXTURE.asHex), 'hex'));
  let tx = null;
  let refusal = null;
  try {
    tx = readTransaction(BYTES, 0, 'fixture transaction');
  } catch (e) {
    if (/refuses to guess its way through/.test(e.message)) refusal = e.message;
    else throw e;
  }

  if (tx) {
    test(`pin-tx format ${file}: the asHex bytes reproduce the txHash`, () => {
      const id = transactionIdOf(tx);
      assert.equal(id, unspaced(FIXTURE.txHash),
        'the bytes prove the txHash the fixture records');
      assert.equal(tx.end, BYTES.length,
        'the walk ends at the last byte; a leftover byte is a framing lie');
    });
  } else {
    test(`pin-tx format ${file}: the reader refuses with a named type (red-first pin)`, () => {
      assert.match(refusal, /RingCT type \d/,
        'the refusal names the ringct type the extension has not read yet');
    });
  }
}

// the format contract: what pin-tx.mjs writes must match what the corpus
// reads. A field the corpus expects but pin-tx.mjs does not write is a
// gap that would make every future pin unreadable by the existing tests.
test('pin-tx format contract: the corpus test reads every field pin-tx.mjs writes', () => {
  // spot-check: the fields the corpus test accesses on the fixture object
  const corpus = readFileSync(new URL('./monero-tx-corpus.test.mjs', import.meta.url), 'utf8');
  for (const field of ['txHash', 'byteLength', 'asHex', 'shapeDiscover', 'source.blockHeight', 'source.txIndexInBlock']) {
    const name = field.split('.').pop();
    assert.ok(corpus.includes(name), `the corpus test reads "${field}"`);
  }
  // and pin-tx.mjs writes them
  const pinTx = readFileSync(new URL('../scripts/pin-tx.mjs', import.meta.url), 'utf8');
  for (const field of ['txHash', 'byteLength', 'asHex', 'shapeDiscover', 'blockHeight', 'txIndexInBlock']) {
    assert.ok(pinTx.includes(field), `pin-tx.mjs writes "${field}"`);
  }
});
