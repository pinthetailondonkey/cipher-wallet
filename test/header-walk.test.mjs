// Walking FORWARD through headers, from an anchor the wallet already believes.
//
// This is the shape header-first walking has to take, and the reason is not a
// preference: getheaders only answers forwards. Given a locator, a peer sends
// the headers AFTER it. So a walk that saves block downloads begins at a block
// this wallet already trusts and counts forward, checking every link.
//
// The anchor is the whole trust decision. It is REQUIRED, it has NO DEFAULT,
// and nothing in this repo pins one — the founder names a block by hand or this
// walk does not run. A required argument cannot drift into trusting a peer by
// accident; a default would be a checkpoint nobody chose.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { hex } from '@scure/base';
import { walkHeadersForward } from '../src/chain.js';

const VECTORS = JSON.parse(
  readFileSync(new URL('./fixtures/bip158-testnet-19.json', import.meta.url), 'utf8'),
).slice(1).map((row) => row.map((field) => (typeof field === 'string' ? field.replace(/ /g, '') : field)));

// Height 2 and height 3 are the only consecutive pair in the vectors, and the
// height-3 header names the height-2 block: one honest link to check.
const ANCHOR_2 = VECTORS[1];
const CHILD_3 = VECTORS[2];
const ANCHOR_HASH = ANCHOR_2[1];
const ANCHOR_HEIGHT = ANCHOR_2[0];
const CHILD_HASH = CHILD_3[1];
const CHILD_HEADER = hex.decode(CHILD_3[2]).slice(0, 80);

// A peer that answers with exactly the headers listed, whatever it is asked.
function peerServing(headers, { onAsk } = {}) {
  return async (_peer, { locator, stopHash } = {}) => {
    onAsk?.({ locator, stopHash });
    return { headers };
  };
}

function witness(name, ...values) {
  console.log(`[header-walk] ${name}: ${values.join(' | ')}`);
}

test('a forward walk counts heights from the anchor and checks the one link', async () => {
  const asks = [];
  const walked = await walkHeadersForward({
    fetchHeaders: peerServing([CHILD_HEADER], { onAsk: (ask) => asks.push(ask) }),
    peer: {},
    anchorHash: ANCHOR_HASH,
    anchorHeight: ANCHOR_HEIGHT,
    tipHash: CHILD_HASH,
  });
  assert.equal(walked.length, 1);
  assert.equal(walked[0].hash, CHILD_HASH);
  assert.equal(walked[0].height, ANCHOR_HEIGHT + 1, 'heights are counted from the anchor, never taken from the peer');
  // The question names the anchor as its locator: a walk that asked from
  // genesis would be asking a different question with the same answer shape.
  assert.deepEqual(asks[0].locator, [ANCHOR_HASH]);
  witness('forward', `anchor ${ANCHOR_HASH.slice(0, 16)}@${ANCHOR_HEIGHT}`, `reached ${CHILD_HASH.slice(0, 16)}@3`);
});

test('a walk with no anchor is refused, and there is no default to fall back on', async () => {
  const fetchHeaders = peerServing([CHILD_HEADER]);
  // Each refusal is named by its own words. When both said "anchor", removing
  // the hash check still matched the height check's sentence and the mutation
  // came back green — a test that could not tell the two apart.
  await assert.rejects(
    walkHeadersForward({ fetchHeaders, peer: {} }),
    /hash of a block this wallet already trusts/,
  );
  await assert.rejects(
    walkHeadersForward({ fetchHeaders, peer: {}, anchorHash: ANCHOR_HASH }),
    /height the anchor sits at/,
    'a hash without its height cannot be counted forward from',
  );
});

test('a peer that skips a block breaks the link and the walk stops', async () => {
  // Ask from genesis and serve the height-3 header: its parent is the height-2
  // block, so it does not connect to the anchor. A walk that trusted heights
  // instead of links would accept it.
  await assert.rejects(
    walkHeadersForward({
      fetchHeaders: peerServing([CHILD_HEADER]),
      peer: {},
      anchorHash: VECTORS[0][1],
      anchorHeight: 0,
    }),
    /does not connect/,
  );
});

test('a height counted past what four bytes hold is refused, not wrapped', async () => {
  await assert.rejects(
    walkHeadersForward({
      fetchHeaders: peerServing([CHILD_HEADER]),
      peer: {},
      anchorHash: ANCHOR_HASH,
      anchorHeight: 0xffffffff,
    }),
    /height/,
  );
});

test('a walk that stops short of the tip it was told to reach says so', async () => {
  // An empty answer is a clean end when no tip was named, and a refusal when
  // one was: otherwise a peer truncates the chain and the caller cannot tell.
  const walked = await walkHeadersForward({
    fetchHeaders: peerServing([]),
    peer: {},
    anchorHash: ANCHOR_HASH,
    anchorHeight: ANCHOR_HEIGHT,
  });
  assert.deepEqual(walked, []);
  await assert.rejects(
    walkHeadersForward({
      fetchHeaders: peerServing([]),
      peer: {},
      anchorHash: ANCHOR_HASH,
      anchorHeight: ANCHOR_HEIGHT,
      tipHash: CHILD_HASH,
    }),
    /stopped short|did not reach/,
  );
});
