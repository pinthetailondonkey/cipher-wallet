// The decoy door and the offset arithmetic behind it, judged three ways.
//
//   1. ARITHMETIC, on real rings. Every pinned transaction with a key input
//      carries a ring as RELATIVE offsets. The functions here must agree with
//      upstream's own two functions (cryptonote_format_utils.cpp at the pinned
//      commit), which are re-implemented inside this file so the module is not
//      its own oracle.
//   2. THE TRAP, measured. Reading those offsets as if they were absolute is
//      the classic wrong reader, and it agrees with the truth on the first
//      member. The test asserts it DISAGREES on every real ring past the first
//      member, so "the numbers look plausible" is not enough.
//   3. THE DOOR, against a pinned real answer and against the chain. The
//      fixture was captured live by scripts/pin-outs.mjs, which also fetched
//      the block at each answer's height, proved the named transaction is in
//      that block's own hash list, and found the key among that transaction's
//      outputs. Those conclusions are recorded here; the block and tx bytes
//      behind them are not pinned, and that is said rather than implied.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { readTransaction } from '../src/monero/block.js';
import { getOuts } from '../src/monero/nodeClient.js';
import { offsetsToAbsolute, absoluteToOffsets, ringFromOuts } from '../src/monero/outs.js';

const FIXTURE_DIR = new URL('./fixtures/', import.meta.url);
const read = (name) => JSON.parse(readFileSync(new URL(name, FIXTURE_DIR), 'utf8'));
const unspaced = (text) => String(text).replace(/\s+/g, '');
const bytesOf = (hexText) => Uint8Array.from(Buffer.from(unspaced(hexText), 'hex'));

// Upstream, written out again so this module is judged against the rule and
// not against itself: cryptonote_format_utils.cpp 1674 (cumulative sum) and
// 1682 (sort, then step back from the end).
const upstreamAbsolute = (offsets) => {
  const res = [...offsets];
  for (let i = 1; i < res.length; i += 1) res[i] += res[i - 1];
  return res;
};
const upstreamRelative = (offsets) => {
  const res = [...offsets];
  if (res.length === 0) return res;
  res.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  for (let i = res.length - 1; i !== 0; i -= 1) res[i] -= res[i - 1];
  return res;
};

const txFixtures = readdirSync(FIXTURE_DIR)
  .filter((f) => f.startsWith('monero-tx-') && f.endsWith('.json'))
  .sort();

const RINGS = [];
for (const file of txFixtures) {
  const FIXTURE = read(file);
  const tx = readTransaction(bytesOf(FIXTURE.asHex), 0, 'fixture transaction');
  for (const input of tx.inputs) {
    if (input.kind === 'key') RINGS.push({ file, offsets: input.keyOffsets, blockHeight: Number(FIXTURE.source.blockHeight) });
  }
}

test('the corpus actually carries real rings of more than one member', () => {
  assert.ok(RINGS.length >= 10, `expected the fixtures to carry rings, found ${RINGS.length}`);
  const widths = new Set(RINGS.map((r) => r.offsets.length));
  assert.ok([...widths].every((w) => w >= 2), 'every real ring here has decoys, so none of the controls below is vacuous');
  console.log(`[monero-outs] ${RINGS.length} real rings across ${new Set(RINGS.map((r) => r.file)).size} fixtures, widths ${[...widths].join(',')}`);
});

for (const { file, offsets } of RINGS) {
  test(`absolute offsets ${file}: agrees with upstream's cumulative sum`, () => {
    const ours = offsetsToAbsolute(offsets);
    assert.deepEqual(ours, upstreamAbsolute(offsets));
    // The first offset is ABSOLUTE: the cumulative sum must not touch it. This
    // is the whole reason upstream's loop starts at 1, and the assertion is
    // what would fail if someone "fixed" it into a real running total.
    assert.equal(ours[0], offsets[0]);
    for (let i = 1; i < ours.length; i += 1) {
      assert.ok(ours[i] > ours[i - 1], 'a real ring walks strictly upward: no zero step, no repeat');
    }
  });

  test(`relative offsets ${file}: round trips, and the wrong reader disagrees`, () => {
    const absolute = offsetsToAbsolute(offsets);
    assert.deepEqual(absoluteToOffsets(absolute), upstreamRelative(absolute));
    assert.deepEqual(absoluteToOffsets(absolute), offsets, 'absolute -> relative is the inverse on real bytes');

    // The trap, measured rather than asserted in prose: treating the offsets as
    // absolute is RIGHT for the first member and wrong for every one after it.
    const asIfAbsolute = [...offsets];
    assert.equal(asIfAbsolute[0], absolute[0], 'the first member cannot tell the two readings apart');
    for (let i = 1; i < offsets.length; i += 1) {
      assert.notEqual(asIfAbsolute[i], absolute[i], 'a reader that treats offsets as absolute is wrong from the second member on');
    }
  });
}

// ---------------------------------------------------------------- ring shape

const RING_SOURCE = read('monero-tx-rct-5.json');
const RING_TX = readTransaction(bytesOf(RING_SOURCE.asHex), 0, 'ring source');
const RING_OFFSETS = RING_TX.inputs.find((i) => i.kind === 'key').keyOffsets;
const RING_ABSOLUTE = offsetsToAbsolute(RING_OFFSETS);
const oursOf = (index) => RING_ABSOLUTE[index];
const ringOuts = () => RING_ABSOLUTE.map((index, i) => ({ amount: 0n, index, key: (i + 1).toString(16).padStart(64, '0') }));

test('ringFromOuts: a shuffled ring comes back sorted, with the offsets the chain wrote', () => {
  const shuffled = [...ringOuts()].reverse();
  const { ring, offsets, position } = ringFromOuts({ outs: shuffled, ours: oursOf(2) });
  assert.deepEqual(ring.map((r) => r.index), RING_ABSOLUTE, 'the ring is ordered by index, which is the order the offsets describe');
  assert.deepEqual(offsets, RING_OFFSETS, 'and the offsets are the ones a real transaction wrote for this ring');
  assert.equal(position, 2, 'our own member is found, not assumed at zero');
  assert.notEqual(position, 0, 'the position is not trivially zero, so a signer that assumed zero would be caught here');
});

test('ringFromOuts refuses a ring without our own output, naming what it holds', () => {
  const outs = ringOuts().filter((o) => o.index !== oursOf(3));
  assert.throws(() => ringFromOuts({ outs, ours: oursOf(3) }), /does not contain our own output/);
});

test('ringFromOuts refuses a repeated decoy index', () => {
  const outs = [...ringOuts(), { amount: 0n, index: oursOf(1), key: 'ab'.repeat(32) }];
  assert.throws(() => ringFromOuts({ outs }), /names output .* twice/);
});

test('ringFromOuts refuses a member with no usable key', () => {
  const outs = ringOuts().map((o, i) => (i === 1 ? { ...o, key: 'nothex' } : o));
  assert.throws(() => ringFromOuts({ outs }), /no 64-hex key/);
});

test('the offset writers refuse a value that is not a whole non-negative number', () => {
  assert.throws(() => offsetsToAbsolute([1n, -2n]), /negative/);
  assert.throws(() => offsetsToAbsolute([1, 'x']), /not a whole number/);
  assert.throws(() => absoluteToOffsets(undefined), /list/);
  assert.deepEqual(absoluteToOffsets([5n, 1n, 3n]), [1n, 2n, 2n], 'upstream sorts first, and so does this');
});

// ------------------------------------------------------------------- the door

const ANSWER = read('monero-get-outs-answer.json');
const realAnswer = () => ({
  status: 'OK',
  outs: ANSWER.response.outs.map((o) => ({
    key: o.key, mask: o.mask, height: o.height, unlocked: o.unlocked, txid: o.txid,
  })),
  untrusted: ANSWER.response.untrusted,
});
const okFetch = (body = realAnswer(), log = []) => async (url, init) => {
  log.push({ url, body: init?.body });
  return { ok: true, status: 200, url, text: async () => JSON.stringify(body) };
};

test('the door: a real answer parses in request order, with keys and masks intact', async () => {
  const log = [];
  const outputs = ANSWER.response.outs.map((o) => ({ amount: 0, index: o.index }));
  const r = await getOuts('node.example:18081', { outputs }, { fetchImpl: okFetch(realAnswer(), log) });

  assert.equal(r.outs.length, outputs.length);
  assert.deepEqual(r.outs.map((o) => Number(o.index)), outputs.map((o) => o.index), 'the order is the request order');
  assert.deepEqual(r.outs.map((o) => o.key), ANSWER.response.outs.map((o) => o.key));
  assert.deepEqual(r.outs.map((o) => o.mask), ANSWER.response.outs.map((o) => o.mask));
  assert.equal(r.outs[0].key.length, 64);
  assert.equal(log[0].url, 'http://node.example:18081/get_outs', 'the REST door');
  assert.equal(JSON.parse(log[0].body).get_txid, false, 'the txid is not asked for unless it is wanted');
  assert.equal(r.untrusted, false, 'the daemon\'s own untrusted flag is recorded, not read');
});

test('the door: a real answer joins the recorded chain verification', () => {
  // What pin-outs.mjs proved live, asserted here. The block and tx bytes are
  // NOT in this fixture: the replay checks the conclusions, and re-deriving
  // them means re-running the script.
  for (const v of ANSWER.verification) {
    assert.ok(ANSWER.response.outs.some((o) => o.index === v.index && o.txid === v.txid), 'every verified out is in the answer');
    assert.equal(v.txInBlock, true, `output ${v.index}: the named transaction is in the named block's own hash list`);
    assert.ok(v.keyFoundAtOutput >= 0, `output ${v.index}: the key is an output of that transaction`);
    assert.ok(v.blockHeight < 2300000, 'and the block is older than the spending transaction whose ring this is');
  }
  // The heights ascend with the indices, which is a property of the chain and
  // not of this code: it is what makes the index -> absolute conversion land
  // on real positions rather than on plausible-looking numbers.
  const heights = ANSWER.response.outs.map((o) => o.height);
  assert.deepEqual(heights, [...heights].sort((a, b) => a - b));
  console.log(`[monero-outs] ${ANSWER.verification.length} live-verified outs from ${ANSWER.source.node}`);
});

test('the door asks for the txid when asked, and carries it through', async () => {
  const log = [];
  const outputs = ANSWER.response.outs.map((o) => ({ amount: 0, index: o.index }));
  const r = await getOuts('node.example:18081', { outputs, getTxid: true }, { fetchImpl: okFetch(realAnswer(), log) });
  assert.equal(JSON.parse(log[0].body).get_txid, true);
  assert.equal(r.outs[0].txid, ANSWER.response.outs[0].txid);
});

test('the door refuses every way a stranger can cheat, by name', async () => {
  const outputs = ANSWER.response.outs.map((o) => ({ amount: 0, index: o.index }));
  const at = 'node.example:18081';

  await assert.rejects(getOuts(at, { outputs: [] }), /at least one/);
  await assert.rejects(getOuts(at, { outputs: [{ amount: 0, index: -1 }] }), /negative/);
  await assert.rejects(getOuts(at, { outputs: [{ amount: 0, index: 'x' }] }), /not a whole number/);

  const short = realAnswer();
  short.outs = short.outs.slice(0, 2);
  await assert.rejects(getOuts(at, { outputs }, { fetchImpl: okFetch(short) }), /count and the list do not agree/);

  const errored = { ...realAnswer(), status: 'Failed to get outs' };
  await assert.rejects(getOuts(at, { outputs }, { fetchImpl: okFetch(errored) }), /instead of OK/);

  const noList = { status: 'OK' };
  await assert.rejects(getOuts(at, { outputs }, { fetchImpl: okFetch(noList) }), /without an outs list/);

  const junkKey = realAnswer();
  junkKey.outs[1] = { ...junkKey.outs[1], key: 'zz'.repeat(32) };
  await assert.rejects(getOuts(at, { outputs }, { fetchImpl: okFetch(junkKey) }), /key that is not 64 hex/);

  const junkMask = realAnswer();
  junkMask.outs[1] = { ...junkMask.outs[1], mask: 'ab' };
  await assert.rejects(getOuts(at, { outputs }, { fetchImpl: okFetch(junkMask) }), /mask that is not 64 hex/);

  const redirected = async () => ({
    ok: true, status: 200, url: 'http://elsewhere.example:18081/get_outs', text: async () => JSON.stringify(realAnswer()),
  });
  await assert.rejects(getOuts(at, { outputs }, { fetchImpl: redirected }), /another host/);

  const dead = async () => { throw new Error('ECONNREFUSED'); };
  await assert.rejects(getOuts(at, { outputs }, { fetchImpl: dead }), /did not answer/);
});

test('the door checks the pinned node before the socket', async () => {
  const outputs = [{ amount: 0, index: 1 }];
  const other = async () => ({ ok: true, status: 200, url: 'http://other.example:18081/get_outs', text: async () => JSON.stringify(realAnswer()) });
  await assert.rejects(getOuts('other.example:18081', { outputs }, {
    pool: {
      pick: () => 'pinned.example:18081',
      assertCurrent: (node) => {
        if (node !== 'pinned.example:18081') throw new Error('A scan runs against one Monero node. Refusing to stitch results from two.');
      },
      abandon: () => {},
    },
    fetchImpl: other,
  }), /Refusing to stitch/);
});

test('the ring a real answer builds is the ring the writer can carry', () => {
  // The two lanes meet here: the offsets this module writes for a fetched ring
  // are the shape readTransaction reads back out of a real transaction.
  const outs = ANSWER.response.outs.map((o) => ({ amount: 0n, index: o.index, key: o.key }));
  const { ring, offsets, position } = ringFromOuts({ outs, ours: outs[1].index });
  assert.equal(position, 1);
  assert.deepEqual(offsetsToAbsolute(offsets), ring.map((r) => r.index), 'the offsets describe exactly this ring, in this order');
  assert.ok(offsets[0] > 0n, 'the first offset is absolute');
});
