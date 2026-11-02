// The transaction door's timeout discipline. The client carries a deadline
// on every call: a node that takes the connection and goes silent is a
// failed read, not a finding about any payment. These controls pin that
// discipline: a fetchImpl that never resolves must produce a clean error
// within the timeout window, the error must name the timeout, and a
// subsequent call on a fresh client must work (a timeout does not poison
// the door).
//
// No new code. Pure pinning of existing timeout behavior.

import test from 'node:test';
import assert from 'node:assert/strict';
import { getTransactions } from '../src/monero/nodeClient.js';

const HASH = 'a'.repeat(64);

test('timeout: a silent node produces a named error within the deadline', async () => {
  // a fetchImpl that respects the AbortSignal (as node's native fetch does)
  // but whose "server" never responds: the client's own timer must fire
  const silentNode = (url, init) => new Promise((resolve, reject) => {
    init.signal.addEventListener('abort', () => {
      const e = new Error('The operation was aborted.');
      e.name = 'AbortError';
      reject(e);
    });
  });
  const start = Date.now();
  const error = await getTransactions('silent.example:18081', [HASH], {
    fetchImpl: silentNode,
    timeoutMs: 50,
  }).catch((e) => e);
  const elapsed = Date.now() - start;
  assert.ok(error instanceof Error, 'the hang produced an error, not a hang');
  assert.match(error.message, /did not answer within 50 ms/,
    'the error names the timeout window');
  assert.ok(elapsed < 5000, `the abort was timely (${elapsed}ms, not a full default timeout)`);
  console.log(`[tx-timeout] silent node refused in ${elapsed}ms with the named error`);
});

test('timeout: the error is a failed read, not a finding about any payment', async () => {
  const silentNode = (url, init) => new Promise((resolve, reject) => {
    init.signal.addEventListener('abort', () => {
      const e = new Error('The operation was aborted.');
      e.name = 'AbortError';
      reject(e);
    });
  });
  const error = await getTransactions('silent.example:18081', [HASH], {
    fetchImpl: silentNode,
    timeoutMs: 50,
  }).catch((e) => e);
  assert.match(error.message, /A silent node is a failed read/,
    'the error distinguishes transport failure from chain state');
  console.log('[tx-timeout] the error is a transport refusal, not a chain claim');
});

test('timeout: a timeout does not poison the next call on the same door', async () => {
  // the client is stateless per call: after one timeout, a fresh call with
  // a working fetchImpl must succeed normally
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
      text: async () => JSON.stringify({ status: 'OK', txs: [{ as_hex: 'ab'.repeat(32) }], missed_tx: [] }),
    });
  };
  // first call times out
  await getTransactions('flaky.example:18081', [HASH], {
    fetchImpl: flaky, timeoutMs: 50,
  }).catch(() => {});
  // second call succeeds: the timeout did not leave state behind
  const r = await getTransactions('flaky.example:18081', [HASH], {
    fetchImpl: flaky, timeoutMs: 5000,
  });
  assert.equal(r.bytes.length, 1, 'the second call answered normally');
  assert.deepEqual(r.bytes[0], Uint8Array.from(Buffer.from('ab'.repeat(32), 'hex')),
    'the bytes are correct: the timeout left no residue');
  console.log('[tx-timeout] a timeout does not poison the next call');
});
