// A pooled scan must not refuse every block that spends old money.
//
// The defect this pins: rebuilding a block's filter needs the scripts its
// inputs spend. The walk holds the outputs of blocks it walked, but a real
// block also spends outputs from before the walk, and the old pooled path only
// had what the walk held — so `filterMatchesBlock` rebuilt a shorter filter,
// it could not equal the peer's real one, and the pooled scan refused. On a
// real chain that is nearly every block, which would make the safe pooled path
// unusable.
//
// The fix: when the client can `fetchTx`, the scripts of outside spends are
// fetched once (cached by txid) and the verification stays byte-exact. Without
// it, the honest refusal is unchanged.

import test from 'node:test';
import assert from 'node:assert/strict';
import { hex } from '@scure/base';

import { scanBack } from '../src/blockScan.js';
import { createPeerPool } from '../src/peers.js';
import { buildBasicFilter } from '../src/filters.js';
import { blockHash } from '../src/chain.js';
import { serializeTx, txid, reverseBytes } from '../src/tx.js';
import { stampWork } from '../src/work.js';

const OURS = Uint8Array.from([0x00, 0x14, ...new Uint8Array(20).fill(7)]);
const PREV = Uint8Array.from([0x00, 0x14, ...new Uint8Array(20).fill(3)]);
const OUTSIDE_TXID = 'aa'.repeat(32);

// A one-tx block that SPENDS an output from before the walk and pays us. The
// block is real: it hashes to its own name, meets its own work target, and its
// filter (built with the spent script) is exactly what a peer would serve.
function blockSpendingOutside() {
  const tx = {
    version: 2,
    inputs: [{ txid: OUTSIDE_TXID, vout: 0, scriptSig: Uint8Array.of(1), sequence: 0xffffffff }],
    outputs: [{ value: 5n, script: OURS }],
    lockTime: 0,
  };
  const header = new Uint8Array(80);
  header.set(reverseBytes(hex.decode(txid(tx))), 36);
  stampWork(header);
  const block = new Uint8Array([...header, 0x01, ...serializeTx(tx, { witness: false })]);
  const hash = blockHash(block);
  const filter = buildBasicFilter({ blockHash: hash, outputScripts: [OURS], prevScripts: [PREV] });
  return { block, hash, filter };
}

// The previous transaction, the one the block spends. Its output 0 is PREV.
const PREV_TX = serializeTx({
  version: 1,
  inputs: [{ txid: 'bb'.repeat(32), vout: 0xffffffff, scriptSig: Uint8Array.of(1), sequence: 0xffffffff }],
  outputs: [{ value: 9n, script: PREV }],
  lockTime: 0,
}, { witness: false });

function pool() {
  const peers = createPeerPool({ allowClearnet: true });
  peers.add('127.0.0.1:1');
  peers.add('127.0.0.1:2');
  return peers;
}

function clientFor({ block, filter, withFetchTx = true }) {
  const state = { txFetches: 0 };
  const client = {
    fetchFilter: async (_peer, asked) => ({ filter, blockHash: asked }),
    fetchBlock: async () => ({ bytes: block }),
  };
  if (withFetchTx) client.fetchTx = async () => { state.txFetches += 1; return { bytes: PREV_TX }; };
  return { client, state };
}

const WALK_PEER = { host: '127.0.0.1', port: 1 };

test('pooled scan accepts a block whose spend is outside the walk, via fetchTx', async () => {
  const { block, hash, filter } = blockSpendingOutside();
  const { client, state } = clientFor({ block, hash, filter });
  const out = await scanBack({
    peer: WALK_PEER,
    pool: pool(),
    client,
    fetchBlock: async () => ({ bytes: block }),
    tipHash: hash,
    tipHeight: 9,
    scripts: [OURS],
  });
  assert.equal(out.payments.length, 1, 'the payment is found, not refused away');
  assert.equal(state.txFetches, 1, 'the previous tx was fetched once');
  console.log('[pooled-prevouts] outside spend resolved, payment found');
});

test('a repeated outside spend fetches its tx only once', async () => {
  // Two inputs spending the same txid (different vouts) must not refetch.
  const prevTx = serializeTx({
    version: 1,
    inputs: [{ txid: 'bb'.repeat(32), vout: 0xffffffff, scriptSig: Uint8Array.of(1), sequence: 0xffffffff }],
    outputs: [{ value: 9n, script: PREV }, { value: 4n, script: PREV }],
    lockTime: 0,
  }, { witness: false });
  const tx = {
    version: 2,
    inputs: [
      { txid: OUTSIDE_TXID, vout: 0, scriptSig: Uint8Array.of(1), sequence: 0xffffffff },
      { txid: OUTSIDE_TXID, vout: 1, scriptSig: Uint8Array.of(1), sequence: 0xffffffff },
    ],
    outputs: [{ value: 5n, script: OURS }],
    lockTime: 0,
  };
  const header = new Uint8Array(80);
  header.set(reverseBytes(hex.decode(txid(tx))), 36);
  stampWork(header);
  const block = new Uint8Array([...header, 0x01, ...serializeTx(tx, { witness: false })]);
  const hash = blockHash(block);
  const filter = buildBasicFilter({ blockHash: hash, outputScripts: [OURS], prevScripts: [PREV, PREV] });
  let fetches = 0;
  const client = {
    fetchFilter: async (_peer, asked) => ({ filter, blockHash: asked }),
    fetchBlock: async () => ({ bytes: block }),
    fetchTx: async () => { fetches += 1; return { bytes: prevTx }; },
  };
  const out = await scanBack({ peer: WALK_PEER, pool: pool(), client, fetchBlock: async () => ({ bytes: block }), tipHash: hash, tipHeight: 9, scripts: [OURS] });
  assert.equal(out.payments.length, 1);
  assert.equal(fetches, 1, 'one txid, one fetch');
});

test('without client.fetchTx the pooled refusal is unchanged', async () => {
  const { block, hash, filter } = blockSpendingOutside();
  const { client } = clientFor({ block, hash, filter, withFetchTx: false });
  await assert.rejects(
    scanBack({ peer: WALK_PEER, pool: pool(), client, fetchBlock: async () => ({ bytes: block }), tipHash: hash, tipHeight: 9, scripts: [OURS] }),
    /does not produce/,
  );
});

test('the no-pool path is untouched and never calls fetchTx', async () => {
  const { block, hash, filter } = blockSpendingOutside();
  let fetches = 0;
  const out = await scanBack({
    fetchFilter: async (_peer, asked) => ({ filter, blockHash: asked }),
    fetchBlock: async () => ({ bytes: block }),
    peer: WALK_PEER,
    tipHash: hash,
    tipHeight: 9,
    scripts: [OURS],
  });
  assert.equal(out.payments.length, 1);
  assert.equal(fetches, 0);
});
