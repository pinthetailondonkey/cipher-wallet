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
  const blockHash = 'ef'.repeat(32);
  const out = await agreedFilter(pool, async (peer, asked) => ({ filter, blockHash: asked }), blockHash);
  assert.deepEqual([...out.filter], [1, 2, 3]);
  assert.equal(out.peers.length, 2);
});

test('two peers that disagree move nothing', async () => {
  const pool = createPeerPool();
  const peers = [pool.add(A), pool.add(B)];
  await assert.rejects(
    agreedFilter(pool, async (peer, asked) => ({
      filter: peer.host.startsWith('a') ? Uint8Array.of(1, 2) : Uint8Array.of(9, 9),
      blockHash: asked,
    }), '12'.repeat(32), { peers }),
    /did not agree/,
  );
});

test('a peer that fails is replaced by a third one that agrees', async () => {
  const pool = createPeerPool();
  const peers = [pool.add(A), pool.add(B), pool.add(C)];
  const out = await agreedFilter(pool, async (peer, asked) => {
    if (peer.host.startsWith('a')) throw new Error('connection refused');
    return { filter: Uint8Array.of(7), blockHash: asked };
  }, '12'.repeat(32), { peers });
  assert.deepEqual([...out.filter], [7]);
  assert.equal(out.peers.length, 2);
});

test('with three peers configured, one dead peer does not stall the default path', async () => {
  const pool = createPeerPool();
  pool.add(A); pool.add(B); pool.add(C);
  let called = 0;
  const out = await agreedFilter(pool, async (peer, asked) => {
    called += 1;
    return { filter: Uint8Array.of(4), blockHash: asked };
  }, 'ee'.repeat(32));
  assert.equal(called, 3, 'one more than the quorum is asked when a spare exists');
  assert.equal(out.peers.length, 3);
});

test('a peer that answers with nothing is not counted', async () => {
  const pool = createPeerPool();
  const peers = [pool.add(A), pool.add(B)];
  await assert.rejects(
    agreedFilter(pool, async (peer, asked) => (peer.host.startsWith('a') ? null : { filter: Uint8Array.of(1), blockHash: asked }), '12'.repeat(32), { peers }),
    /did not agree/,
  );
});

test('an answer about a different block is not an answer', async () => {
  // A peer may send a perfectly valid filter that belongs to another block.
  // Comparing filter bytes alone would let two such answers "agree" on data
  // that has nothing to do with the block we asked about — the wallet would
  // then match our script against the wrong block's filter and move nothing, or
  // worse, believe a block we never checked. The block hash echo is part of
  // what makes an answer an answer.
  const pool = createPeerPool();
  const peers = [pool.add(A), pool.add(B)];
  const asked = 'ab'.repeat(32);
  const out = [];
  await assert.rejects(
    agreedFilter(pool, async (peer) => {
      // One peer answers honestly and one answers about a different block; both
      // with the same filter bytes, so only the hash can tell them apart.
      const answer = { filter: Uint8Array.of(3, 1, 4), blockHash: peer.host.startsWith('a') ? asked : 'cd'.repeat(32) };
      out.push(`${peer.host} answered about ${answer.blockHash}`);
      return answer;
    }, asked, { peers }),
    /different block|did not name the block/,
  );
  assert.equal(out.length, 2, `both peers were asked; witnesses: ${out.join('; ')}`);
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

// AUDITOR's F27, reframed by ADJUDICATOR as claims-vs-code: a heightless
// verifiedFilter opens no socket and then reports that no PEER answered. That
// sentence is a claim about the network when the fault is the call site, and it
// sends a person to look at peers for their own missing argument. When every
// peer failed for the same reason, that reason is the answer.
test('when every peer fails for one reason, the reason is what is reported', async () => {
  const pool = createPeerPool();
  pool.add(A); pool.add(B);
  const cause = 'A filter is asked for by the height of the block it belongs to.';
  await assert.rejects(
    agreedFilter(pool, async () => { throw new Error(cause); }, 'ef'.repeat(32)),
    (error) => error.message === cause,
  );
  // Different reasons still get the round-up, because then no single one is the
  // answer and naming one would be picking a winner between peers.
  await assert.rejects(
    agreedFilter(pool, async (peer) => { throw new Error(peer.host.startsWith('a') ? 'timed out' : 'closed'); }, 'ef'.repeat(32)),
    /No peer answered with a filter/,
  );
  console.log('[peers] a shared cause is reported instead of blaming the peers');
});
