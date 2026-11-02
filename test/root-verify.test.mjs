// The root verifier's proof, judged against the pinned live-walk transcript:
// the same ids the walk proved from bytes, run through verifyTreeRoot, must
// reproduce the root the block's own bytes produce. Plus the refusals: bad
// hex anywhere is named, and a wrong claimed root returns a refusal string,
// not a boolean shrug. PREPARATION ONLY - this module is not wired into the
// scan layer; Lane C stays gated.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseBlock } from '../src/monero/block.js';
import { walkBlockTxs } from '../src/monero/blockWalk.js';
import { verifyTreeRoot } from '../src/monero/rootVerify.js';

const FIXTURE = JSON.parse(readFileSync(new URL('./fixtures/monero-live-walk-3797001.json', import.meta.url), 'utf8'));
const unspaced = (text) => String(text).replace(/\s+/g, '');
const bytesOf = (hexText) => Uint8Array.from(Buffer.from(unspaced(hexText), 'hex'));

const block = parseBlock(bytesOf(FIXTURE.block.blob));
const walk = walkBlockTxs(block, FIXTURE.txs.map((t) => bytesOf(t.asHex)));

test('root verifier: the proven ids reproduce the block root', () => {
  const r = verifyTreeRoot({
    minerTxId: block.minerTxId,
    transactionIds: walk.ids,
    claimedRoot: block.txTreeRoot,
  });
  assert.equal(r.matches, true);
  assert.equal(r.refusal, null);
  assert.equal(r.root, block.txTreeRoot);
  console.log('[root-verify] proven ids build the claimed root');
});

test('root verifier: a wrong claimed root gets a named refusal, not a shrug', () => {
  const wrongRoot = '00'.repeat(32);
  const r = verifyTreeRoot({
    minerTxId: block.minerTxId,
    transactionIds: walk.ids,
    claimedRoot: wrongRoot,
  });
  assert.equal(r.matches, false);
  assert.match(r.refusal, /bytes and list do not agree/);
  assert.match(r.refusal, /the proven ids build root/);
});

test('root verifier: bad hex is named with the offending slot', () => {
  assert.throws(
    () => verifyTreeRoot({ minerTxId: block.minerTxId, transactionIds: ['nothex'], claimedRoot: block.txTreeRoot }),
    /transaction id 0 is 64 hex characters/,
  );
  assert.throws(
    () => verifyTreeRoot({ minerTxId: 'zz', transactionIds: walk.ids, claimedRoot: block.txTreeRoot }),
    /the miner transaction id is 64 hex characters/,
  );
});

test('root verifier: spaced hex is accepted - the fixture spelling is the input spelling', () => {
  const r = verifyTreeRoot({
    minerTxId: block.minerTxId.replace(/(.{32})/, '$1 '),
    transactionIds: FIXTURE.txs.map((t) => t.provenId),
    claimedRoot: FIXTURE.walk.txTreeRoot,
  });
  assert.equal(r.matches, true);
});
