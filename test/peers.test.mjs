import test from 'node:test';
import assert from 'node:assert/strict';
import {
  agreedFilter,
  broadcast,
  checkPeer,
  createPeerPool,
  isOnionHost,
  peerKey,
} from '../src/peers.js';

const A = 'a'.repeat(56) + '.onion:8333';
const B = 'b'.repeat(56) + '.onion:8333';
const C = 'c'.repeat(56) + '.onion:8333';

test('an onion peer is accepted and known to be onion', () => {
  const peer = checkPeer(A);
  assert.equal(peer.kind, 'onion');
  assert.equal(peer.port, 8333);
});

test('a clearnet peer is refused unless clearnet was allowed', () => {
  assert.throws(() => checkPeer('peer.example.com:8333'), /would learn where you are/);
  assert.equal(checkPeer('peer.example.com:8333', { allowClearnet: true }).kind, 'clearnet');
});

test('a block explorer is refused as a peer', () => {
  assert.throws(() => checkPeer('mempool.space:8333', { allowClearnet: true }), /block explorer/);
});

test('a lookalike explorer host is refused too', () => {
  assert.throws(() => checkPeer('blockstream.info.evil.tld:8333', { allowClearnet: true }), /block explorer/);
});

test('a bad port or host is refused', () => {
  assert.throws(() => checkPeer('abcdef.onion:0'), /1 to 65535/);
  assert.throws(() => checkPeer('not a host:8333'), /not a hostname/);
});

test('onion detection does not accept a lookalike', () => {
  assert.equal(isOnionHost('a'.repeat(56) + '.onion'), true);
  assert.equal(isOnionHost('a'.repeat(56) + '.onion.example.com'), false);
});

test('the same peer is not added twice', () => {
  const pool = createPeerPool();
  pool.add(A);
  pool.add(A);
  assert.equal(pool.size(), 1);
});

test('picking rotates instead of always taking the first', () => {
  const pool = createPeerPool();
  pool.add(A); pool.add(B); pool.add(C);
  const one = pool.pick(1)[0];
  const two = pool.pick(1)[0];
  assert.notEqual(peerKey(one), peerKey(two));
});

test('one peer is not enough for an agreed filter', () => {
  const pool = createPeerPool();
  pool.add(A);
  assert.throws(() => pool.requireAgreement(2), /One peer is not a witness/);
});

test('two peers that agree are believed', async () => {
  const pool = createPeerPool();
  pool.add(A); pool.add(B);
  const filter = Uint8Array.of(1, 2, 3);
  const out = await agreedFilter(pool, async () => ({ filter }));
  assert.deepEqual([...out.filter], [1, 2, 3]);
  assert.equal(out.peers.length, 2);
});

test('two peers that disagree move nothing', async () => {
  const pool = createPeerPool();
  const peers = [pool.add(A), pool.add(B)];
  await assert.rejects(
    agreedFilter(pool, async (peer) => ({
      filter: peer.host.startsWith('a') ? Uint8Array.of(1, 2) : Uint8Array.of(9, 9),
    }), 'x'.repeat(64), { peers }),
    /did not agree/,
  );
});

test('a peer that fails is replaced by a third one that agrees', async () => {
  const pool = createPeerPool();
  const peers = [pool.add(A), pool.add(B), pool.add(C)];
  const out = await agreedFilter(pool, async (peer) => {
    if (peer.host.startsWith('a')) throw new Error('connection refused');
    return { filter: Uint8Array.of(7) };
  }, 'x'.repeat(64), { peers });
  assert.deepEqual([...out.filter], [7]);
  assert.equal(out.peers.length, 2);
});

test('with three peers configured, one dead peer does not stall the default path', async () => {
  const pool = createPeerPool();
  pool.add(A); pool.add(B); pool.add(C);
  let called = 0;
  const out = await agreedFilter(pool, async () => {
    called += 1;
    return { filter: Uint8Array.of(4) };
  });
  assert.equal(called, 3, 'one more than the quorum is asked when a spare exists');
  assert.equal(out.peers.length, 3);
});

test('a peer that answers with nothing is not counted', async () => {
  const pool = createPeerPool();
  const peers = [pool.add(A), pool.add(B)];
  await assert.rejects(
    agreedFilter(pool, async (peer) => (peer.host.startsWith('a') ? null : { filter: Uint8Array.of(1) }), 'x'.repeat(64), { peers }),
    /did not agree/,
  );
});

test('a broadcast counts when one peer takes it', async () => {
  const pool = createPeerPool();
  pool.add(A); pool.add(B);
  const out = await broadcast(pool, async (peer) => {
    if (peer.host.startsWith('a')) throw new Error('rejected');
  }, Uint8Array.of(1, 2, 3));
  assert.equal(out.acceptedBy.host.startsWith('b'), true);
  assert.equal(out.attempted.length, 2);
});

test('a broadcast nobody takes is an error naming who was tried', async () => {
  const pool = createPeerPool();
  pool.add(A); pool.add(B);
  await assert.rejects(
    broadcast(pool, async () => { throw new Error('rejected'); }, Uint8Array.of(1)),
    /No peer took the transaction/,
  );
});

test('an empty transaction is not broadcast', async () => {
  const pool = createPeerPool();
  pool.add(A);
  await assert.rejects(broadcast(pool, async () => {}, new Uint8Array(0)), /nothing to broadcast/);
});
