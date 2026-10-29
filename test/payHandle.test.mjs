import test from 'node:test';
import assert from 'node:assert/strict';
import { createHandle, isHandle, issuePocket, nextIndexFor } from '../src/payHandle.js';
import { rootFromMnemonic } from '../src/root.js';

const MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const SEED = rootFromMnemonic(MNEMONIC);

test('a handle is a 32-byte random pointer, not a key', () => {
  const a = createHandle();
  const b = createHandle();
  assert.match(a.id, /^[0-9a-f]{64}$/);
  assert.notEqual(a.id, b.id);
  assert.equal(isHandle(a), true);
});

test('two handles from the same seed are still unrelated', () => {
  const a = createHandle();
  const b = createHandle();
  assert.notEqual(a.id, b.id);
});

test('issuing a pocket moves the handle forward', () => {
  const handle = createHandle({ coin: 'btc' });
  assert.equal(nextIndexFor(handle, 'btc'), 0);
  const first = issuePocket(handle, SEED, { coin: 'btc' });
  assert.equal(first.pocket.index, 0);
  assert.equal(nextIndexFor(first.handle, 'btc'), 1);
  const second = issuePocket(first.handle, SEED, { coin: 'btc' });
  assert.equal(second.pocket.index, 1);
  assert.notEqual(first.pocket.address, second.pocket.address);
});

test('the same handle and seed re-derive the same pocket', () => {
  const handle = createHandle({ coin: 'btc' });
  const a = issuePocket(handle, SEED, { coin: 'btc' });
  const b = issuePocket(handle, SEED, { coin: 'btc' });
  assert.equal(a.pocket.address, b.pocket.address);
  assert.deepEqual(Array.from(a.pocket.privateKey), Array.from(b.pocket.privateKey));
});

test('each coin has its own index', () => {
  const handle = createHandle({ coin: 'btc' });
  const btc = issuePocket(handle, SEED, { coin: 'btc' });
  assert.equal(nextIndexFor(btc.handle, 'xmr'), 0);
});

test('damaged handles are refused, not repaired', () => {
  assert.equal(isHandle(null), false);
  assert.equal(isHandle({ v: 1, id: 'abc', next: {} }), false);
  assert.throws(() => nextIndexFor({ v: 1, id: 'a'.repeat(64), next: { btc: -1 } }, 'btc'), /damaged/);
});
