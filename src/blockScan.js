// Looking for your own coins by walking back from a tip.
//
// The filter is a bandwidth saver, not an authority. It is small, and it says
// which blocks are worth downloading; what a block actually pays is read from
// the block, after the walk has checked that the block is the one that was
// asked for and that its body hashes up to its own header (chain.js,
// merkle.js). A filter that names a block which does not pay us therefore costs
// one download and nothing else, and is reported rather than forgotten.
//
// The limit, stated where it will be read: a filter that OMITS our script means
// the block is never fetched, so two peers that agree on the omission can hide
// a payment from this wallet. Nothing local can tell — the block that would
// prove it is the block that was never downloaded. The only top is to download
// blocks that no filter asked for, which is paying the whole chain's bandwidth
// to catch a lie that costs a stranger the same bandwidth to tell. That is a
// trade, and this build makes it in favour of the filter.

import { matchesFilter } from './filters.js';
import { walkBack } from './chain.js';

function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

// Walk back from `tipHash`, ask each block's filter whether it mentions any of
// `scripts`, and for the blocks that do, read what the block actually pays.
//
// Returns payments (one per output that pays one of our scripts, with a bigint
// amount), `quiet` (blocks whose filter named us but whose body did not pay —
// a fabricated filter that cost a download), and the blocks walked.
export async function scanBack({ fetchFilter, fetchBlock, peer, tipHash, stopHash = null, maxSteps = 1000, scripts = [] } = {}) {
  if (typeof fetchFilter !== 'function') throw new Error('A scan needs a way to fetch a filter.');
  const wanted = (Array.isArray(scripts) ? scripts : []).filter((script) => script instanceof Uint8Array && script.length > 0);
  if (wanted.length === 0) throw new Error('A scan with no scripts would learn nothing, and would still tell a peer we asked.');

  const payments = [];
  const quiet = [];
  const blocks = await walkBack({
    fetchBlock,
    peer,
    tipHash,
    stopHash,
    maxSteps,
    onBlock: async ({ hash, body }) => {
      const { filter } = await fetchFilter(peer, hash);
      const mentioned = wanted.filter((script) => matchesFilter(filter, hash, script));
      if (mentioned.length === 0) return;
      const paid = [];
      body.transactions.forEach((tx, index) => {
        tx.outputs.forEach((output, vout) => {
          if (wanted.some((script) => sameBytes(script, output.script))) {
            paid.push({ blockHash: hash, txid: body.txids[index], vout, value: output.value, script: output.script });
          }
        });
      });
      if (paid.length === 0) quiet.push({ hash, mentioned });
      payments.push(...paid);
    },
  });

  return { payments, quiet, scanned: blocks.length };
}
