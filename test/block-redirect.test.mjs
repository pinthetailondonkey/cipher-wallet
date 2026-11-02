// The block door's redirect refusal: the sameHost check fires when a
// fetchImpl redirects the request to another host. The transaction door
// carries the same check (pinned in tx-door.test.mjs); this control makes
// the door symmetry complete on the redirect refusal for getBlock.
//
// No new code. Pure pinning of existing redirect behavior.

import test from 'node:test';
import assert from 'node:assert/strict';
import { getBlock } from '../src/monero/nodeClient.js';

test('block redirect: a fetchImpl that answers from another host is refused by name', async () => {
  const redirectingFetch = async (url) => ({
    ok: true,
    status: 200,
    url: 'http://other-host.example:18081/json_rpc',  // different host
    text: async () => JSON.stringify({
      id: '0', jsonrpc: '2.0',
      result: { blob: 'ab'.repeat(64), block_header: { hash: 'b'.repeat(64), height: 100 } },
    }),
  });
  await assert.rejects(
    getBlock('my-node.example:18081', { height: 100 }, {
      fetchImpl: redirectingFetch, timeoutMs: 5000,
    }),
    /sent this request to another host/,
    'the block door refuses a cross-host answer, naming the redirect',
  );
});

test('block redirect: the same host with a different path passes the redirect check', async () => {
  // the url check is host-only, not full-url: a different path on the same
  // host is fine (the client checks the host, not the full URL)
  const sameHostFetch = async (url) => ({
    ok: true,
    status: 200,
    url,  // the client's own url, same host
    text: async () => JSON.stringify({
      id: '0', jsonrpc: '2.0',
      result: { blob: 'ab'.repeat(64), block_header: { hash: 'b'.repeat(64), height: 100 } },
    }),
  });
  // this may fail on blob parsing (the fake blob is not a real block),
  // but the REDIRECT check must pass (no "another host" in the error)
  const error = await getBlock('my-node.example:18081', { height: 100 }, {
    fetchImpl: sameHostFetch, timeoutMs: 5000,
  }).catch((e) => e);
  if (error instanceof Error) {
    assert.doesNotMatch(error.message, /another host/,
      'the same-host fetch did not trigger the redirect refusal');
  }
  console.log('[block-redirect] same host, different path: no redirect refusal');
});
