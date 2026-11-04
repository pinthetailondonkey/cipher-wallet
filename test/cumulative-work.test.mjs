// A chain is priced by its total work, not by one header.
//
// Per-header proof-of-work (work.test.mjs) stops a peer serving a header that
// was never mined. It does not stop the cheaper lie: the peer chooses every
// header's own nBits, so it can name a trivially easy target on every invented
// block and mine a private chain for free. What it cannot fake is the SUM of
// the work those targets are worth. These tests pin the accounting
// (workForTarget/workOf/cumulativeWork), the walk exposing the total, and the
// `minWork` floor that refuses a chain too cheap to believe.

import test from 'node:test';
import assert from 'node:assert/strict';
import { hex } from '@scure/base';

import { blockHash, headerHash, walkBack, walkHeadersForward } from '../src/chain.js';
import { scanBack } from '../src/blockScan.js';
import { buildBasicFilter } from '../src/filters.js';
import { cumulativeWork, meetsWork, stampWork, targetFromBits, workForTarget, workOf } from '../src/work.js';
import { reverseBytes, serializeTx, sha256d, txid } from '../src/tx.js';

// The mainnet genesis header, byte for byte. Real and mined; its nBits
// (0x1d00ffff) is the easiest real mainnet target, so it is the floor of what
// "real work" looks like.
const GENESIS_HEADER = hex.decode(
  '01000000'
  + '00'.repeat(32)
  + '3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a'
  + '29ab5f49'
  + 'ffff001d'
  + '1dac2b7c',
);

function witness(name, ...values) {
  console.log(`[cumulative-work] ${name}: ${values.join(' | ')}`);
}

// The same shape the other walk tests use: an 80-byte header the caller can
// link, over a one-transaction body the header commits to by merkle root.
function buildBlock(prevDigest, fill, bits = null) {
  const tx = {
    version: 1,
    inputs: [{ txid: '00'.repeat(32), vout: 0xffffffff, scriptSig: Uint8Array.of(fill), sequence: 0xffffffff }],
    outputs: [{ value: 1000n, script: Uint8Array.of(0x51) }],
    lockTime: 0,
  };
  const raw = serializeTx(tx, { witness: false });
  const header = new Uint8Array(80).fill(fill);
  header.set(prevDigest, 4);
  header.set(reverseBytes(hex.decode(txid(tx))), 36);
  if (bits === null) {
    // stampWork only stamps EASY_BITS; it already grinds a real nonce.
    stampWork(header);
  } else {
    headerGrind(header, bits);
  }
  const block = new Uint8Array([...header, 0x01, ...raw]);
  return { block, header };
}

// Write `bits` into bytes 72..76 (little-endian) and grind the nonce until the
// header meets that target. A harder target than EASY_BITS is what makes an
// equal-length chain carry strictly more work, which stampWork cannot produce.
function headerGrind(header, bits) {
  header[72] = bits & 0xff;
  header[73] = (bits >>> 8) & 0xff;
  header[74] = (bits >>> 16) & 0xff;
  header[75] = (bits >>> 24) & 0xff;
  let nonce = 0;
  while (!meetsWork(header)) {
    nonce += 1;
    if (nonce > 0xffffffff) throw new Error('a test header could not be ground to its target');
    header[76] = nonce & 0xff;
    header[77] = (nonce >>> 8) & 0xff;
    header[78] = (nonce >>> 16) & 0xff;
    header[79] = (nonce >>> 24) & 0xff;
  }
  return header;
}

// A three-block chain, oldest first, each header naming the one before it.
function chainOfThree(fill, bits) {
  const grand = buildBlock(new Uint8Array(32), fill, bits);
  const mid = buildBlock(sha256d(grand.header), fill + 1, bits);
  const top = buildBlock(sha256d(mid.header), fill + 2, bits);
  const blocks = [grand.block, mid.block, top.block];
  const served = new Map(blocks.map((block) => [blockHash(block), block]));
  return { grand, mid, top, tip: blockHash(top.block), served };
}

test('workForTarget is 2^256/(target+1), hand-computed for a known compact target', () => {
  // 0x1d00ffff is the genesis difficulty. Its 256-bit target is 0xffff << 208.
  const target = 0xffffn << 208n;
  assert.equal(targetFromBits(0x1d00ffff), target);
  assert.equal(workForTarget(target), (1n << 256n) / (target + 1n));
  // A smaller target is strictly more work.
  assert.ok(workForTarget(target >> 1n) > workForTarget(target));
  witness('workForTarget', `bits 0x1d00ffff -> ${workForTarget(target)}`);
});

test('a real mainnet genesis header has a specific positive work', () => {
  const work = workOf(GENESIS_HEADER);
  assert.ok(work > 0n);
  assert.equal(work, workForTarget(targetFromBits(0x1d00ffff)), 'workOf reads the header\'s own nBits');
  witness('genesis work', work.toString().slice(0, 12) + '…');
});

test('cumulativeWork refuses a non-array or empty input by name', () => {
  assert.throws(() => cumulativeWork(null), /non-empty array/);
  assert.throws(() => cumulativeWork([]), /non-empty array/);
  assert.throws(() => cumulativeWork('not an array'), /non-empty array/);
  assert.equal(cumulativeWork([GENESIS_HEADER]), workOf(GENESIS_HEADER));
});

test('a three-block walk reports work equal to the manual cumulative sum', async () => {
  const { grand, mid, top, tip, served } = chainOfThree(7, null);
  const fetchBlock = async (_peer, asked) => {
    const bytes = served.get(asked);
    if (!bytes) throw new Error(`no such block ${asked}`);
    return { bytes };
  };
  const walked = await walkBack({ fetchBlock, peer: {}, tipHash: tip, tipHeight: 2 });
  assert.equal(walked.length, 3);
  const manual = cumulativeWork([grand.header, mid.header, top.header]);
  assert.equal(walked.work, manual);
  assert.equal(walked.work, walked.reduce((sum, b) => sum + workOf(b.bytes.slice(0, 80)), 0n));
  witness('walked work', `${walked.work}`, 'equals manual sum');
});

test('a minWork floor one above the chain refuses it; equal and below accept', async () => {
  const { grand, mid, top, tip, served } = chainOfThree(9, null);
  const fetchBlock = async (_peer, asked) => {
    const bytes = served.get(asked);
    if (!bytes) throw new Error(`no such block ${asked}`);
    return { bytes };
  };
  const total = cumulativeWork([grand.header, mid.header, top.header]);

  // RED-first: the floor names the cheap chain and blames the peer, because a
  // peer could have invented it for free.
  await assert.rejects(
    walkBack({ fetchBlock, peer: {}, tipHash: tip, tipHeight: 2, minWork: total + 1n }),
    new RegExp(`the chain carries ${total} work, below the floor ${total + 1n}; a peer could have invented it cheaply`),
  );
  // Exactly equal is not below: accepted, and credited with the full work.
  const equal = await walkBack({ fetchBlock, peer: {}, tipHash: tip, tipHeight: 2, minWork: total });
  assert.equal(equal.work, total);
  // Below accepts too.
  const below = await walkBack({ fetchBlock, peer: {}, tipHash: tip, tipHeight: 2, minWork: total - 1n });
  assert.equal(below.work, total);
  witness('minWork floor', `floor ${total + 1n} refuses`, 'equal accepts', 'below accepts');
});

test('minWork rejects a non-bigint or negative floor by name', async () => {
  const { tip, served } = chainOfThree(11, null);
  const fetchBlock = async (_peer, asked) => ({ bytes: served.get(asked) });
  await assert.rejects(
    walkBack({ fetchBlock, peer: {}, tipHash: tip, tipHeight: 2, minWork: 5 }),
    /minimum work floor is a non-negative bigint/,
  );
  await assert.rejects(
    walkBack({ fetchBlock, peer: {}, tipHash: tip, tipHeight: 2, minWork: -1n }),
    /minimum work floor is a non-negative bigint/,
  );
});

test('a chain whose headers carry a harder target carries strictly more work', async () => {
  // 0x1f00ffff is a genuinely harder real target than EASY_BITS (0x207fffff):
  // target 0xffff << 224 against 0x7fffff << 232, so its work is ~2^16 vs ~2.
  const easy = chainOfThree(13, null);
  const hard = chainOfThree(13, 0x1f00ffff);
  assert.equal(easy.served.size, 3);
  assert.ok(workOf(hard.mid.header) > workOf(easy.mid.header), 'the harder header is worth more');
  const manualEasy = cumulativeWork([easy.grand.header, easy.mid.header, easy.top.header]);
  const manualHard = cumulativeWork([hard.grand.header, hard.mid.header, hard.top.header]);
  assert.ok(manualHard > manualEasy, 'same length, strictly more work');
  witness('harder chain', `easy ${manualEasy}`, `hard ${manualHard}`);
});

test('the non-enumerable work does not leak into array equality or JSON', async () => {
  const { tip, served } = chainOfThree(17, null);
  const fetchBlock = async (_peer, asked) => ({ bytes: served.get(asked) });
  const walked = await walkBack({ fetchBlock, peer: {}, tipHash: tip, tipHeight: 2 });
  assert.equal(Object.prototype.propertyIsEnumerable.call(walked, 'work'), false);
  // A plain array of the same entries is deepStrictEqual: the hidden property
  // is invisible to it, which is why existing callers and tests are unchanged.
  assert.deepStrictEqual(walked, Array.from(walked));
  // JSON has no bigint in the entries, so replacer them: the array and a plain
  // copy must serialize identically, with no `work` key leaking in.
  const json = (arr) => JSON.stringify(arr, (_k, v) => (typeof v === 'bigint' ? v.toString() : v));
  assert.equal(json(walked), json(Array.from(walked)));
  assert.equal(typeof walked.work, 'bigint');
  witness('non-enumerable', 'deepStrictEqual plain', 'JSON equal');
});

// The forward walk and the scan carry the same price: both must accumulate and
// both must honour a floor, or a peer could sidestep the check by being asked
// the other way.
test('the forward walk reports work and refuses below a minWork floor', async () => {
  const { grand, mid, top } = chainOfThree(19, null);
  const anchorHash = blockHash(grand.block);
  const tip = blockHash(top.block);
  const fetchHeaders = async () => ({ headers: [mid.header, top.header] });
  const walked = await walkHeadersForward({ fetchHeaders, peer: {}, anchorHash, anchorHeight: 0, tipHash: tip });
  assert.equal(walked.length, 2);
  const manual = cumulativeWork([mid.header, top.header]);
  assert.equal(walked.work, manual);
  assert.equal(headerHash(mid.header), walked[0].hash);
  await assert.rejects(
    walkHeadersForward({ fetchHeaders, peer: {}, anchorHash, anchorHeight: 0, tipHash: tip, minWork: manual + 1n }),
    /below the floor/,
  );
  witness('forward work', `${walked.work}`, 'floor refuses');
});

test('scanBack forwards minWork and reports the walk\'s work', async () => {
  const { grand, mid, top, tip, served } = chainOfThree(21, null);
  const OUR = Uint8Array.of(0x51);
  const fetchBlock = async (_peer, asked) => {
    const bytes = served.get(asked);
    if (!bytes) throw new Error(`no such block ${asked}`);
    return { bytes };
  };
  const fetchFilter = async (_peer, hash) => ({ filter: buildBasicFilter({ blockHash: hash, outputScripts: [OUR] }) });
  const out = await scanBack({
    fetchFilter, fetchBlock, peer: {}, tipHash: tip, tipHeight: 2, scripts: [OUR],
  });
  assert.equal(out.scanned, 3);
  assert.equal(out.work, cumulativeWork([grand.header, mid.header, top.header]));
  assert.equal(out.payments.length, 3);
  await assert.rejects(
    scanBack({ fetchFilter, fetchBlock, peer: {}, tipHash: tip, tipHeight: 2, scripts: [OUR], minWork: out.work + 1n }),
    /below the floor/,
  );
  witness('scanBack work', `${out.work}`, 'floor refuses');
});
