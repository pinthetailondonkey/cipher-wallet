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

test('an address that is not a host:port is refused rather than tried', () => {
  assert.throws(() => createNodePool({ nodes: ['http://node.example'] }), /not a node address/);
  assert.throws(() => createNodePool({ override: 'node.example' }), /not a node address/);
  assert.equal(OVERRIDE_ENV, 'CIPHER_XMR_NODE');
});

// ADJUDICATOR's F-A. The Bitcoin rail refuses a clearnet peer by default, and
// docs/L3-RECEIVE.md states the rule for the whole lane. This door shipped
// without it: a node at 1.2.3.4 would have been accepted and quietly learned
// where the wallet is. Same refusal here, same words.
test('a clearnet node is refused unless clearnet was explicitly allowed', () => {
  for (const address of ['1.2.3.4:18081', 'node.example:18081', 'localhost:18081', '127.0.0.1:18081']) {
    assert.throws(() => createNodePool({ nodes: [address] }), /without Tor/, address);
    assert.throws(() => createNodePool({ override: address }), /without Tor/, address);
  }
  // Said out loud, it is allowed — the allowance is a decision, not a default.
  const pool = createNodePool({ nodes: ['node.example:18081'], allowClearnet: true });
  assert.equal(pool.pick(), 'node.example:18081');
  console.log('[nodes] clearnet refused by default, allowed when named');
});

// ADJUDICATOR's F-B: the regex was \d{1,5}, which calls port 0 and 65536 to
// 99999 ports. Same class, same pass.
test('a port outside 1 to 65535 is not a port', () => {
  for (const address of ['node.onion:0', 'node.onion:65536', 'node.onion:99999', 'node.onion:-1']) {
    assert.throws(() => createNodePool({ override: address, allowClearnet: true }), /host:port, port 1 to 65535/, address);
  }
  assert.equal(createNodePool({ nodes: [`${ONION}:65535`] }).pick(), `${ONION}:65535`);
});
