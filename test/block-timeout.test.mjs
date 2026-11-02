// The block door's timeout discipline. The same deadline pattern the
// transaction door carries, pinned for getBlock: a silent node produces a
// named timely error, the error distinguishes transport failure from chain
// state, and a timeout does not poison the next call.
//
// No new code. Pure pinning of existing timeout behavior.

import test from 'node:test';
import assert from 'node:assert/strict';
import { getBlock } from '../src/monero/nodeClient.js';

test('block timeout: a silent node produces a named error within the deadline', async () => {
  const silentNode = (url, init) => new Promise((resolve, reject) => {
    init.signal.addEventListener('abort', () => {
      const e = new Error('The operation was aborted.');
      e.name = 'AbortError';
      reject(e);
    });
  });
  const start = Date.now();
  const error = await getBlock('silent.example:18081', { height: 100 }, {
    fetchImpl: silentNode,
    timeoutMs: 50,
  }).catch((e) => e);
  const elapsed = Date.now() - start;
  assert.ok(error instanceof Error, 'the hang produced an error, not a hang');
  assert.match(error.message, /did not answer within 50 ms/,
    'the error names the timeout window');
  assert.ok(elapsed < 5000, `the abort was timely (${elapsed}ms)`);
  console.log(`[block-timeout] silent node refused in ${elapsed}ms`);
});

test('block timeout: the error distinguishes transport failure from chain state', async () => {
  const silentNode = (url, init) => new Promise((resolve, reject) => {
    init.signal.addEventListener('abort', () => {
      const e = new Error('The operation was aborted.');
      e.name = 'AbortError';
      reject(e);
    });
  });
  const error = await getBlock('silent.example:18081', { height: 100 }, {
    fetchImpl: silentNode,
    timeoutMs: 50,
  }).catch((e) => e);
  assert.match(error.message, /A silent node is a failed read/,
    'the error says this is a failed read, not a finding about any payment');
  console.log('[block-timeout] transport refusal, not a chain claim');
});

test('block timeout: a timeout does not poison the next call', async () => {
  const calls = [];
  const flaky = (url, init) => {
    calls.push(url);
    if (calls.length === 1) {
      return new Promise((resolve, reject) => {
        init.signal.addEventListener('abort', () => {
          const e = new Error('The operation was aborted.');
          e.name = 'AbortError';
          reject(e);
        });
      });
    }
    return Promise.resolve({
      ok: true, status: 200, url,
      text: async () => JSON.stringify({
        id: '0', jsonrpc: '2.0',
        result: { blob: '10'.repeat(40), block_header: { hash: 'b'.repeat(64), height: 100 } },
      }),
    });
  };
  await getBlock('flaky.example:18081', { height: 100 }, {
    fetchImpl: flaky, timeoutMs: 50,
  }).catch(() => {});
  // the second call reaches the client's own blob validation (which may
  // refuse the fake blob, but the transport worked: no timeout)
  const error = await getBlock('flaky.example:18081', { height: 100 }, {
    fetchImpl: flaky, timeoutMs: 5000,
  }).catch((e) => e);
  // the second call's error (if any) is about the blob shape, not a timeout
  if (error instanceof Error) {
    assert.doesNotMatch(error.message, /did not answer within/,
      'the second call was not a timeout: the door recovered');
  }
  console.log('[block-timeout] a timeout does not poison the next call');
});
