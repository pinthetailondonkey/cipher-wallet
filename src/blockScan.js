// Looking for your own coins by walking back from a tip.
//
// Three things are worth saying before the code, because this file is what a
// reader trusts when the README is not open.
//
// scanBack does not save bandwidth. walkBack fetches, hashes and merkle-checks
// every block on the way back, so by the time scanBack sees a block its body is
// already in hand. The filter therefore decides what is REPORTED, not what is
// FETCHED.
//
// scanHeaderFirst, below, is the shape that saves the downloads: headers first,
// a filter per block, and a body only when the filter matched. It is built and
// measured, and it is NOT wired to a caller — it needs an anchor block that
// nothing in this repo is allowed to choose. The cost of the saving is stated
// there, and pinned by a test that prints both numbers.
//
// The filter is not an authority. What a block pays is read from the block,
// after the walk has checked that it is the block that was asked for and that
// its body hashes up to its own header (chain.js, merkle.js). A filter cannot
// make this wallet believe a payment that is not in a block.
//
// The filter is still a witness, in one narrow way. A basic filter names a
// script when the block PAYS it and when the block SPENDS it. So a filter that
// names one of our scripts, over a block that neither pays nor spends it, is a
// filter that lied — reported in `quiet`. Ruling out "spends" needs the spent
// output's script, which is only knowable when that output is in a block this
// walk has already read; inputs pointing outside the walked range are counted in
// `unresolved` and suppress the verdict, because this wallet cannot then tell a
// lie from an ordinary spend of older money.
//
// That suppression makes `quiet` nearly inert on a real chain, and the header
// has to say so rather than imply a working lie detector. Almost every real
// block spends an output older than the walk's stop, so almost every block
// carries an unresolved input and almost every lie is suppressed. Measured, two
// otherwise identical lies: a filter naming us over a payless coinbase-only
// block reports quiet 1; the same lie over a block holding one unrelated old
// coin reports quiet 0. Resolving those inputs needs the pocket store, which in
// production already knows our outputs — that is the fix, and it is not here.
//
// The limit, stated where it will be read: while every body is read, NO filter
// — omitting our script or lying about it — can hide a payment. An omission
// costs nothing visible; a lie costs one `quiet` entry and nothing else.
//
// With header-first, that stops being true: an omission means the body is never
// fetched, and a pair of peers agreeing on the omission can hide a payment
// outright. Measured, not argued: test/header-scan.test.mjs runs the same block
// and the same script through both walks and prints the difference.

import { matchesFilter } from './filters.js';
import { verifyBlockBody } from './merkle.js';
import { blockHash as hashOfBlock, walkBack, walkHeadersForward } from './chain.js';
import { parseTx } from './tx.js';
import { verifiedFilter, agreedTip } from './peers.js';
import { chooseTip } from './fork.js';

function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

// A coinbase input points at no transaction. It spends nothing, so it is not
// evidence of anything and must not be counted as money this wallet cannot see.
function isCoinbaseInput(input) {
  return input.txid === '00'.repeat(32) && input.vout === 0xffffffff;
}

// Walk back from `tipHash`, read our outputs out of every block, and use each
// block's filter to say what is worth REPORTING.
//
// Returns:
//   payments   — one entry per output paying one of our scripts, with a bigint
//                amount of satoshis.
//   spent      — inputs that spend one of our scripts, resolved against outputs
//                seen earlier in the same walk.
//   quiet      — blocks whose filter named us while the block neither paid nor
//                spent us, and every input in the walk resolved: a lying filter.
//   unresolved — input spends whose prevout is outside the walked range.
//   scanned    — how many blocks were walked.
//   work       — the chain's total proof-of-work (a bigint), so a caller sees
//                the price the walk charged, not just its length. `minWork`
//                (a bigint floor, optional) is forwarded to the walk, which
//                refuses a chain cheaper than it.
//
// A single peer is not a witness. When `pool` and `client` are given, every
// block's filter comes from peers.verifiedFilter: two independent peers must
// agree on it AND it is rebuilt from the block's own bytes before it is used
// here, so one lying peer cannot decide what is reported. Without a pool the
// scan behaves exactly as before — one fetchFilter, one peer — which keeps the
// older call sites and their tests unchanged; that path believes a lone peer by
// design, and the pool is how a caller stops doing so.
//
// The tip is the walk's other peer-supplied input. When a pool and client are
// given and the caller pinned no `tipHash` (passing one is still the deliberate
// override), the tip itself is agreed by two peers through peers.agreedTip
// before the walk starts, so a lone peer cannot name a tip on its own private
// chain and have the whole walk believe it. `client.fetchTip`, not `fetchTip`,
// so the pool path stays the only one that asks more than one peer.
//
// `client` has the peerClient.js shape: fetchFilter(peer, hash, opts) and
// fetchBlock(peer, hash). It is only consulted when a pool is given.
//
// FORK CHOICE is opt-in and off by default, because it changes which tip is
// walked when peers disagree. When `forkChoice` is true, a pool and client are
// given, the caller pinned no `tipHash`, and the client can `fetchTip`, the tip
// is chosen by forks.chooseTip instead of peers.agreedTip: two peers on
// opposite sides of a fork are not a refusal anymore, the HEAVIER chain wins,
// and only an exact-work tie between distinct tips is still refused. `forkDepth`
// bounds how far back each candidate tip is priced. With `forkChoice` false the
// behaviour is byte-identical to before, so existing callers and their tests
// are unchanged.
export async function scanBack({ fetchFilter, fetchBlock, peer, pool = null, client = null, tipHash, tipHeight, stopHash = null, maxSteps = 1000, scripts = [], minWork, forkChoice = false, forkDepth = 10 } = {}) {
  if (pool && (!client || typeof client.fetchFilter !== 'function' || typeof client.fetchBlock !== 'function')) {
    // Say so rather than quietly falling back to the lone `fetchFilter`: a
    // caller who asked for a quorum must not get one peer's word.
    throw new Error('A pooled scan needs a client with fetchFilter and fetchBlock, so the peers can be asked and the filter checked.');
  }
  if (!pool && typeof fetchFilter !== 'function') throw new Error('A scan needs a way to fetch a filter.');
  const wanted = (Array.isArray(scripts) ? scripts : []).filter((script) => script instanceof Uint8Array && script.length > 0);
  if (wanted.length === 0) throw new Error('A scan with no scripts would learn nothing, and would still tell a peer we asked.');

  const payments = [];
  const spent = [];
  const quiet = [];
  const outputsSeen = new Map();
  const prevScriptCache = new Map();
  let unresolved = 0;

  // A tip hash is the walk's starting claim, and one peer's word is not a
  // witness. When a pool and a client are present and the caller pinned no
  // tip, the pool decides the tip. `forkChoice` picks the heavier of the peers'
  // tips (chooseTip); otherwise two peers must name the SAME tip (agreedTip).
  // Passing a `tipHash` is still the deliberate override over both. Without a
  // pool, this is exactly the old behaviour: the caller's tip or walkBack's own
  // refusal.
  const pooledTip = pool && client && (tipHash === undefined || tipHash === null) && typeof client.fetchTip === 'function';
  let startTipHash = tipHash;
  let startTipHeight = tipHeight;
  if (pooledTip && forkChoice) {
    const chosen = await chooseTip(pool, client, { depth: forkDepth });
    startTipHash = chosen.hash;
    // The chosen tip's height is a claim the winning peer made; when the caller
    // pinned none, use it, or the walk would number the winner's blocks from a
    // height belonging to a different tip.
    if (startTipHeight === undefined || startTipHeight === null) startTipHeight = chosen.height;
  } else if (pooledTip) {
    startTipHash = (await agreedTip(pool, client.fetchTip)).hash;
  }

  const blocks = await walkBack({
    fetchBlock,
    peer,
    tipHash: startTipHash,
    tipHeight: startTipHeight,
    stopHash,
    maxSteps,
    // A chain is priced by its total work, not one header. Forwarded straight to
    // the walk, where the floor is enforced; `work` on the walk's array comes
    // back with it and is reported below.
    minWork,
  });

  // Oldest first, though the walk hands them back newest first. A block's spends
  // point at outputs in EARLIER blocks, so reading forwards is the only order in
  // which "this block spends our coin" can be answered from blocks already read.
  for (let i = blocks.length - 1; i >= 0; i -= 1) {
    const { hash, height, body, bytes: blockBytes } = blocks[i];
    // Pooled: the filter is the one two peers agreed on and the block confirms.
    // No pool: exactly the old single-peer question.
    //
    // Verification rebuilds the filter from the block, which needs the scripts
    // this block's inputs spend. Every spend into an earlier walked block was
    // indexed above (forwards is the only order that makes that knowable), so
    // it is handed over ready. A spend of older money outside the walk cannot
    // be rebuilt from what the walk holds — but the input names the previous
    // tx, and a basic filter describes what that tx PAID, so when the client
    // can `fetchTx` the scripts are fetched once (cached by txid) and the
    // verification stays exact instead of refusing every block that spends old
    // money. Without `client.fetchTx` the old behaviour holds: such a block is
    // a refusal, not a false `false`.
    const prevScripts = [];
    const outsideSpends = [];
    for (const tx of body.transactions) {
      for (const input of tx.inputs) {
        if (isCoinbaseInput(input)) continue;
        const output = outputsSeen.get(input.txid)?.[input.vout];
        if (output) prevScripts.push(output.script);
        else outsideSpends.push(input);
      }
    }
    if (pool && outsideSpends.length > 0 && typeof client?.fetchTx === 'function') {
      for (const spend of outsideSpends) {
        let outs = prevScriptCache.get(spend.txid);
        if (!outs) {
          const { bytes } = await client.fetchTx(peer, spend.txid);
          outs = parseTx(bytes).outputs.map((output) => output.script);
          prevScriptCache.set(spend.txid, outs);
        }
        const script = outs[spend.vout];
        if (script) prevScripts.push(script);
      }
    }
    const { filter } = pool
      ? await verifiedFilter(pool, client, hash, { startHeight: height, prevScripts, block: blockBytes })
      : await fetchFilter(peer, hash, { startHeight: height });
    const mentioned = wanted.filter((script) => matchesFilter(filter, hash, script));

    let paidHere = 0;
    let spentHere = 0;
    let unresolvedHere = 0;
    body.transactions.forEach((tx, index) => {
      const id = body.txids[index];
      // Inputs first: a spend reads an output from an earlier block, which in
      // this order has already been indexed.
      for (const input of tx.inputs) {
        if (isCoinbaseInput(input)) continue;
        const previous = outputsSeen.get(input.txid);
        const output = previous?.[input.vout];
        if (!output) { unresolvedHere += 1; continue; }
        if (wanted.some((script) => sameBytes(script, output.script))) {
          spentHere += 1;
          spent.push({ blockHash: hash, txid: id, prevTxid: input.txid, prevVout: input.vout, value: output.value });
        }
      }
      // Then the outputs, whatever the filter said. The filter decides what is
      // reported, never what is read.
      tx.outputs.forEach((output, vout) => {
        if (wanted.some((script) => sameBytes(script, output.script))) {
          paidHere += 1;
          payments.push({ blockHash: hash, txid: id, vout, value: output.value, script: output.script });
        }
      });
      outputsSeen.set(id, tx.outputs);
    });
    unresolved += unresolvedHere;

    // A verdict needs every spend in this block accounted for: an input from
    // before the walk could be the honest reason the filter named us.
    if (mentioned.length > 0 && paidHere === 0 && spentHere === 0 && unresolvedHere === 0) {
      quiet.push({ hash, mentioned });
    }
  }

  return { payments, spent, quiet, unresolved, scanned: blocks.length, work: blocks.work };
}

// Header-first: walk headers from an anchor, ask each block's filter, and fetch
// a body only when the filter matched.
//
// This is the BIP-157 shape, and it is the honest version of what scanBack's
// header said was missing. It is also a weaker promise, and the header states
// it rather than letting the saving speak for itself:
//
//   while every body is read (scanBack), no filter can hide a payment.
//   here, a filter that omits our script is never contradicted — the block
//   that would contradict it is never downloaded. The only trace is a body not
//   fetched, which no honest caller can distinguish from a quiet block.
//
// So this function reports `skipped` explicitly, and nothing may treat that
// list as evidence about a payment. What it does not do: it never reads spends,
// so it cannot say whether a block SPENT our coin — only whether one paid us.
// Resolving spends needs bodies that were not fetched, which is the same
// tradeoff seen from the other side.
//
// The anchor is required by walkHeadersForward and has no default here either.
export async function scanHeaderFirst({ fetchHeaders, fetchFilter, fetchBlock, peer, anchorHash, anchorHeight, tipHash = null, maxSteps = 2000, scripts = [] } = {}) {
  if (typeof fetchFilter !== 'function') throw new Error('A scan needs a way to fetch a filter.');
  if (typeof fetchBlock !== 'function') throw new Error('A scan needs a way to fetch a block.');
  const wanted = (Array.isArray(scripts) ? scripts : []).filter((script) => script instanceof Uint8Array && script.length > 0);
  if (wanted.length === 0) throw new Error('A scan with no scripts would learn nothing, and would still tell a peer we asked.');

  const headers = await walkHeadersForward({ fetchHeaders, peer, anchorHash, anchorHeight, tipHash, maxSteps });

  const payments = [];
  const skipped = [];
  let bodiesFetched = 0;

  for (const { hash, height } of headers) {
    const { filter } = await fetchFilter(peer, hash, { startHeight: height });
    if (!wanted.some((script) => matchesFilter(filter, hash, script))) {
      // Not evidence. A block that pays us and whose filter omits us lands here
      // and is indistinguishable from a block that pays nobody.
      skipped.push({ hash, height });
      continue;
    }
    const { bytes } = await fetchBlock(peer, hash);
    const actual = hashOfBlock(bytes);
    if (actual !== hash) {
      throw new Error(`That peer served block ${actual}, not ${hash}.`);
    }
    const body = verifyBlockBody(bytes);
    bodiesFetched += 1;
    body.transactions.forEach((tx, index) => {
      const id = body.txids[index];
      tx.outputs.forEach((output, vout) => {
        if (wanted.some((script) => sameBytes(script, output.script))) {
          payments.push({ blockHash: hash, txid: id, vout, value: output.value, script: output.script });
        }
      });
    });
  }

  return { payments, skipped, bodiesFetched, scanned: headers.length };
}
