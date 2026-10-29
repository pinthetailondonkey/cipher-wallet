// Which Monero node a scan talks to, and what happens when one dies.
//
// The rule that these tests exist for is the one a merged answer would break:
// one scan, one node. A scan that carried on across a node's death would report
// one chain assembled from two operators, and nobody downstream could tell.

import test from 'node:test';
import assert from 'node:assert/strict';
import { OVERRIDE_ENV, PUBLIC_NODES, createNodePool } from '../src/monero/nodes.js';

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
  const pool = createNodePool({ nodes: ['a.example:18081', 'b.example:18081'], override: 'private.onion:18081' });
  assert.deepEqual(pool.nodes, ['private.onion:18081']);
  assert.equal(pool.pick(), 'private.onion:18081');
});

test('selection is sticky for the session, not per query', () => {
  const pool = createNodePool({ nodes: ['a.example:18081', 'b.example:18081'] });
  assert.equal(pool.pick(), 'a.example:18081');
  assert.equal(pool.pick(), 'a.example:18081');
  assert.equal(pool.pick(), 'a.example:18081');
  witness('sticky', pool.pick());
});

test('a node that dies mid-scan refuses the scan instead of stitching two answers', () => {
  const pool = createNodePool({ nodes: ['a.example:18081', 'b.example:18081'] });
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
  const pool = createNodePool({ nodes: ['a.example:18081'] });
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
