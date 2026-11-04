// THE RUNTIME DOOR for CIPHER_XMR_NODE.
//
// nodes.js has always exported the variable's NAME (OVERRIDE_ENV) and a pool
// that can honour an override, but before this file existed nothing read the
// variable at runtime: setting it changed nothing, and a wallet with nowhere to
// go failed deeper down with a socket error instead of saying so. These tests
// pin the two halves of the fix: the value is read when a scan asks (not when
// the module was imported), and "nothing configured" is a named refusal.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  OVERRIDE_ENV, PUBLIC_NODES, nodeOverride, nodeSourceFromEnv,
} from '../src/monero/nodes.js';

// A v3 onion address shape: fifty-six base32 characters. The wallet reaches
// nodes over Tor, so this is the only kind of address the door accepts without
// someone saying clearnet is allowed.
const ONION = `${'abcdefghij'.repeat(5)}abcdef`.slice(0, 56) + '.onion';
const ONION_NODE = `${ONION}:18081`;

function witness(name, ...values) {
  console.log(`[node-source] ${name}: ${values.join(' | ')}`);
}

test('the variable is named once, and the reader reads that name', () => {
  assert.equal(OVERRIDE_ENV, 'CIPHER_XMR_NODE');
  assert.equal(nodeOverride({ [OVERRIDE_ENV]: ONION_NODE }), ONION_NODE);
  witness('name', OVERRIDE_ENV);
});

test('unset, empty and whitespace-only all mean "no override", so the shipped list is used', () => {
  for (const env of [{}, { [OVERRIDE_ENV]: '' }, { [OVERRIDE_ENV]: '   ' }, null]) {
    assert.equal(nodeOverride(env), '', `env=${JSON.stringify(env)}`);
  }
  // With no override the shipped list answers; only a list with no rows refuses.
  assert.equal(nodeSourceFromEnv({ env: {} }).pick(), 'xmr-node.cakewallet.com:18081');
  assert.throws(() => nodeSourceFromEnv({ env: {}, nodes: [] }), /No Monero node is configured/);
  witness('unset', 'empty', 'whitespace', 'shipped list used; empty list refused');
});

test('the value is read at call time, so setting it changes the next scan', () => {
  const env = {};
  assert.equal(nodeOverride(env), '');
  env[OVERRIDE_ENV] = ONION_NODE;
  assert.equal(nodeOverride(env), ONION_NODE);
  assert.deepEqual(nodeSourceFromEnv({ env }).nodes, [ONION_NODE]);
  // and clearing it returns the wallet to the shipped list, not to nothing
  delete env[OVERRIDE_ENV];
  assert.deepEqual(nodeSourceFromEnv({ env }).nodes, ['xmr-node.cakewallet.com:18081']);
  witness('call time', 'set/unset changes without a re-import');
});

test('the override is the only node, even when the shipped list has rows', () => {
  const pool = nodeSourceFromEnv({
    env: { [OVERRIDE_ENV]: ONION_NODE },
    nodes: ['b.example:18081'],
    allowClearnet: true,
  });
  assert.deepEqual(pool.nodes, [ONION_NODE]);
  assert.equal(pool.pick(), ONION_NODE);
  witness('override', 'list ignored');
});

test('without an override the shipped list is what the scan uses', () => {
  const pool = nodeSourceFromEnv({
    env: {},
    nodes: [{ address: 'node.example:18081', allowClearnet: true }],
  });
  assert.deepEqual(pool.nodes, ['node.example:18081']);
  witness('list', 'used when no override');
});

test('the shipped list carries a live-verified row, so a no-environment wallet has a node', () => {
  assert.deepEqual(PUBLIC_NODES, [{ address: 'xmr-node.cakewallet.com:18081', allowClearnet: true }]);
  assert.equal(nodeSourceFromEnv({ env: {} }).pick(), 'xmr-node.cakewallet.com:18081');
  // and only a genuinely empty list refuses out loud, as a read failure
  assert.throws(
    () => nodeSourceFromEnv({ env: {}, nodes: [] }),
    (error) => /No Monero node is configured/.test(error.message) && !/payment/i.test(error.message),
  );
  witness('shipped row', 'used with no environment', 'empty list refuses');
});

test("the override is the person's own address, so it carries its clearnet allowance", () => {
  assert.equal(nodeSourceFromEnv({ env: { [OVERRIDE_ENV]: 'node.example:18081' } }).pick(),
    'node.example:18081');
  // while a shipped clearnet row still needs the allowance written on the row
  assert.throws(() => nodeSourceFromEnv({ env: {}, nodes: ['node.example:18081'] }), /without Tor/);
  witness('clearnet', 'override allowed', 'shipped row refused');
});

test('a malformed override is refused at the door, not at the first request', () => {
  assert.throws(() => nodeSourceFromEnv({ env: { [OVERRIDE_ENV]: 'http://node.example' } }),
    /not a node address/);
  assert.throws(() => nodeSourceFromEnv({ env: { [OVERRIDE_ENV]: 'node.example:99999' } }),
    /port 1 to 65535/);
  witness('malformed', 'refused before any scan starts');
});
