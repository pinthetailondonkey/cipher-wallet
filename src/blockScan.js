// Looking for your own coins by walking back from a tip.
//
// Three things are worth saying before the code, because this file is what a
// reader trusts when the README is not open.
//
// It does not save bandwidth. walkBack fetches, hashes and merkle-checks every
// block on the way back, so by the time this module sees a block its body is
// already in hand. The filter therefore decides what is REPORTED, not what is
// FETCHED. Saving downloads needs header-first walking — getheaders and
// getcfheaders, a body fetched only when its filter matched — which is the
// BIP-157 shape and is not built here.
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
// The limit, stated where it will be read: a filter that OMITS our script means
// this wallet does not report a payment from that block. Today the body is in
// hand anyway, so the omission hides nothing that the block does not also hide
// by lying about a script; the moment header-first walking lands, an omission
// means the body is never fetched, and a pair of peers agreeing on the omission
// can hide a payment outright.

import { matchesFilter } from './filters.js';
import { walkBack } from './chain.js';

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
export async function scanBack({ fetchFilter, fetchBlock, peer, tipHash, stopHash = null, maxSteps = 1000, scripts = [] } = {}) {
  if (typeof fetchFilter !== 'function') throw new Error('A scan needs a way to fetch a filter.');
  const wanted = (Array.isArray(scripts) ? scripts : []).filter((script) => script instanceof Uint8Array && script.length > 0);
  if (wanted.length === 0) throw new Error('A scan with no scripts would learn nothing, and would still tell a peer we asked.');

  const payments = [];
  const spent = [];
  const quiet = [];
  const outputsSeen = new Map();
  let unresolved = 0;

  const blocks = await walkBack({ fetchBlock, peer, tipHash, stopHash, maxSteps });

  // Oldest first, though the walk hands them back newest first. A block's spends
  // point at outputs in EARLIER blocks, so reading forwards is the only order in
  // which "this block spends our coin" can be answered from blocks already read.
  for (let i = blocks.length - 1; i >= 0; i -= 1) {
    const { hash, body } = blocks[i];
    const { filter } = await fetchFilter(peer, hash);
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

  return { payments, spent, quiet, unresolved, scanned: blocks.length };
}
