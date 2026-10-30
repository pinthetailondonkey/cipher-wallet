// What header-first walking COSTS, measured rather than described.
//
// The backwards walk reads every body, so a filter that omits our script costs
// nothing: the block is read anyway and the payment is found. Header-first
// fetches a body only when its filter matched — which is the whole point, and
// also the whole risk. Two peers that agree on a filter which omits our script
// are never contradicted by anything, because the block that would contradict
// them is never downloaded.
//
// This file is the number, not the argument: same block, same script, honest
// filter versus omitting filter, on both walks.

import test from 'node:test';
import assert from 'node:assert/strict';
import { hex } from '@scure/base';
import { blockHash } from '../src/chain.js';
import { buildBasicFilter } from '../src/filters.js';
import { scanBack, scanHeaderFirst } from '../src/blockScan.js';
import { reverseBytes, serializeTx, txid } from '../src/tx.js';

const OUR_SCRIPT = Uint8Array.from([0x00, 0x14, ...new Uint8Array(20).fill(7)]);
const OTHER_SCRIPT = Uint8Array.from([0x00, 0x14, ...new Uint8Array(20).fill(9)]);
const AMOUNT = 250000000n;

// One coinbase-shaped block, its body committed to by its own header.
function blockPaying(prevDigest, script, fill) {
  const tx = {
    version: 1,
    inputs: [{ txid: '00'.repeat(32), vout: 0xffffffff, scriptSig: Uint8Array.of(fill), sequence: 0xffffffff }],
    outputs: [{ value: AMOUNT, script }],
    lockTime: 0,
  };
  const header = new Uint8Array(80).fill(fill);
  header.set(prevDigest, 4);
  header.set(reverseBytes(hex.decode(txid(tx))), 36);
  return new Uint8Array([...header, 0x01, ...serializeTx(tx, { witness: false })]);
}

const BLOCK = blockPaying(new Uint8Array(32), OUR_SCRIPT, 7);
const HASH = blockHash(BLOCK);
const HONEST = buildBasicFilter({ blockHash: HASH, outputScripts: [OUR_SCRIPT, OTHER_SCRIPT] });
const OMITTING = buildBasicFilter({ blockHash: HASH, outputScripts: [OTHER_SCRIPT] });

function witness(name, ...values) {
  console.log(`[header-scan] ${name}: ${values.join(' | ')}`);
}

// Header-first, driven by functions: one header, one filter, one body. Nothing
// here is a socket, because what is being measured is arithmetic and a socket
// would only add timing.
function headerFirst(filter) {
  let bodies = 0;
  return scanHeaderFirst({
    fetchHeaders: async () => ({ headers: [BLOCK.slice(0, 80)] }),
    fetchFilter: async () => ({ filter, blockHash: HASH }),
    fetchBlock: async () => { bodies += 1; return { bytes: BLOCK }; },
    peer: {},
    anchorHash: '00'.repeat(32),
    anchorHeight: 0,
    tipHash: HASH,
    scripts: [OUR_SCRIPT],
  }).then((result) => ({ ...result, bodiesAsked: bodies }));
}

// The backwards walk, same one-block chain, same filter — read end to end.
function backwards(filter) {
  let bodies = 0;
  return scanBack({
    fetchFilter: async () => ({ filter, blockHash: HASH }),
    fetchBlock: async () => { bodies += 1; return { bytes: BLOCK }; },
    peer: {},
    tipHash: HASH,
    tipHeight: 1,
    scripts: [OUR_SCRIPT],
  }).then((result) => ({ ...result, bodiesAsked: bodies }));
}

test('HEADER-FIRST COST: an omitted filter hides a payment and nothing is downloaded to notice it', async () => {
  const honest = await headerFirst(HONEST);
  const lying = await headerFirst(OMITTING);
  assert.equal(honest.payments.length, 1, 'the honest filter brings the body and the payment is found');
  assert.equal(honest.bodiesFetched, 1);
  assert.equal(lying.payments.length, 0, 'the omitting filter is never contradicted, because its block is never fetched');
  assert.equal(lying.bodiesFetched, 0);
  assert.equal(lying.bodiesAsked, 0, 'no body was even asked for: the filter alone decided');
  witness('header-first', `honest payments ${honest.payments.length} bodies ${honest.bodiesFetched}`, `omitting payments ${lying.payments.length} bodies ${lying.bodiesFetched}`);
});

test('the same omission under the backwards walk costs nothing, because every body is read', async () => {
  const lying = await backwards(OMITTING);
  assert.equal(lying.payments.length, 1, 'the payment is found even though the filter omitted it');
  assert.equal(lying.bodiesAsked, 1);
  witness('backwards', `omitting payments ${lying.payments.length} bodies ${lying.bodiesAsked}`);
});

test('the difference is the number: one payment, and the only signal is missing bandwidth', async () => {
  const fast = await headerFirst(OMITTING);
  const slow = await backwards(OMITTING);
  // Stated as an assertion so it cannot drift into prose: the fast path loses
  // exactly what the slow path keeps, and reports nothing about having lost it.
  assert.equal(slow.payments.length - fast.payments.length, 1);
  assert.equal(fast.skipped.length, 1);
  witness('cost', `header-first loses ${slow.payments.length - fast.payments.length} payment(s)`, `bodies saved ${slow.bodiesAsked - fast.bodiesAsked}`);
});
