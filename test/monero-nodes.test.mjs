// Which Monero node a scan talks to, and what happens when one dies.
//
// The rule that these tests exist for is the one a merged answer would break:
// one scan, one node. A scan that carried on across a node's death would report
// one chain assembled from two operators, and nobody downstream could tell.

import test from 'node:test';
import assert from 'node:assert/strict';
import { OVERRIDE_ENV, PUBLIC_NODES, createNodePool } from '../src/monero/nodes.js';

// A v3 onion address shape: fifty-six base32 characters. The wallet reaches
// nodes over Tor, so this is the only kind of address the door accepts without
// someone saying clearnet is allowed.
const ONION = `${'abcdefghij'.repeat(5)}abcdef`.slice(0, 56) + '.onion';
const ONION_NODE = `${ONION}:18081`;

function witness(name, ...values) {
  console.log(`[nodes] ${name}: ${values.join(' | ')}`);
}

test('the shipped list is empty until the founder names addresses, and an empty pool refuses out loud', () => {
  assert.deepEqual(PUBLIC_NODES, []);
  assert.throws(() => createNodePool(), /No Monero node is configured/);
  // And the refusal is a read failure, not a statement about money.
  assert.throws(() => createNodePool(), (error) => !/payment/i.test(error.message));
  witness('empty pool', 'refused', 'no payment sentence');
});

test('a private override is the only node, even when a list is configured', () => {
  const pool = createNodePool({ nodes: [ONION_NODE, ONION_NODE], override: ONION_NODE, allowClearnet: true });
  assert.deepEqual(pool.nodes, [ONION_NODE]);
  assert.equal(pool.pick(), ONION_NODE);
});

test('selection is sticky for the session, not per query', () => {
  const pool = createNodePool({ nodes: [ONION_NODE, 'b.example:18081'], allowClearnet: true });
  assert.equal(pool.pick(), ONION_NODE);
  assert.equal(pool.pick(), ONION_NODE);
  assert.equal(pool.pick(), ONION_NODE);
  witness('sticky', pool.pick());
});

test('a node that dies mid-scan refuses the scan instead of stitching two answers', () => {
  const pool = createNodePool({ nodes: [ONION_NODE, 'b.example:18081'], allowClearnet: true });
  const node = pool.pick();
  pool.assertCurrent(node);
  // Mid-scan failure: the transport refuses. The pool must not quietly move to
  // the next node and let the same scan continue.
  pool.abandon(node);
  assert.throws(() => pool.assertCurrent(node), /one Monero node|stitch/);
  // The NEXT scan starts on the next node.
  assert.equal(pool.pick(), 'b.example:18081');
});

test('when every node has failed the wallet says so, and never says "no payment"', () => {
  const pool = createNodePool({ nodes: [ONION_NODE] });
  pool.abandon(pool.pick());
  assert.throws(
    () => pool.pick(),
    (error) => /failed read/.test(error.message) && !/no payment/i.test(error.message),
  );
  assert.equal(pool.exhausted, true);
  witness('exhausted', 'failed read', 'not a payment verdict');
});

// BOSS's ask: a user who HAS a node and a user who has NONE must be told
// different things. The first would otherwise go looking for a setting that is
// already right, and the second would keep retrying a list that is empty.
test('"nothing configured" and "everything failed" are two different sentences', () => {
  let none = '';
  try { createNodePool(); } catch (error) { none = error.message; }
  const pool = createNodePool({ nodes: [ONION_NODE] });
  pool.abandon(pool.pick());
  let failed = '';
  try { pool.pick(); } catch (error) { failed = error.message; }
  assert.ok(none && failed);
  assert.notEqual(none, failed);
  assert.match(none, /No Monero node is configured/);
  assert.match(failed, /No configured Monero node answered/);
  witness('two refusals', `none: ${none.slice(0, 28)}…`, `failed: ${failed.slice(0, 28)}…`);
});

test('an address that is not a host:port is refused rather than tried', () => {
  assert.throws(() => createNodePool({ nodes: ['http://node.example'] }), /not a node address/);
  assert.throws(() => createNodePool({ override: 'node.example' }), /not a node address/);
  assert.equal(OVERRIDE_ENV, 'CIPHER_XMR_NODE');
});

// AUDITOR's F-A, framed by ADJUDICATOR. The Bitcoin rail refuses a clearnet
// peer by default, and docs/L3-RECEIVE.md states the rule for the whole lane.
// This door shipped without it: a node at 1.2.3.4 would have been accepted and
// quietly learned where the wallet is. The rule now holds here too, with the
// allowance written where the address is — on the row, or by the person who
// typed the override — so a shipped list cannot hand out an allowance nobody
// chose.
test('a clearnet node is refused unless the allowance is written down', () => {
  for (const address of ['1.2.3.4:18081', 'node.example:18081', 'localhost:18081', '127.0.0.1:18081']) {
    assert.throws(() => createNodePool({ nodes: [address] }), /without Tor/, address);
  }
  // On the row: the allowance travels with the address it is about.
  const row = createNodePool({ nodes: [{ address: 'node.example:18081', allowClearnet: true }] });
  assert.deepEqual(row.nodes, ['node.example:18081']);
  // The override is the person's own address, so it is their allowance.
  assert.equal(createNodePool({ override: 'node.example:18081' }).pick(), 'node.example:18081');
  // And a blanket, for a build whose transport is known to be Tor.
  assert.equal(createNodePool({ nodes: ['node.example:18081'], allowClearnet: true }).pick(), 'node.example:18081');
  console.log('[nodes] clearnet refused by default; allowed only where it is written');
});

// ADJUDICATOR's F-B: the regex was \d{1,5}, which calls port 0 and 65536 to
// 99999 ports. Same class, same pass.
test('a port outside 1 to 65535 is not a port', () => {
  for (const address of ['node.onion:0', 'node.onion:65536', 'node.onion:99999', 'node.onion:-1']) {
    assert.throws(() => createNodePool({ override: address, allowClearnet: true }), /host:port, port 1 to 65535/, address);
  }
  assert.equal(createNodePool({ nodes: [`${ONION}:65535`] }).pick(), `${ONION}:65535`);
});
