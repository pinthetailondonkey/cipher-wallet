// The app as one runtime: the entry point that assembles the halves.
//
// Every module under src/ was written and tested as a unit, and until this file
// nothing imported both the Bitcoin side and the Monero side, so they had never
// met. `createWallet` is where they meet: one root seed, one pocket store, one
// pay handle, and a working surface that reaches BOTH rails from those.
//
// WHAT ACTUALLY RUNS THROUGH HERE, and what does not:
//
//   btc: issue() derives and persists a fresh pocket from the seed, and watch()
//        asks the watcher about a pocket and persists its answer. spend.*
//        derives the pocket key back from the SAME seed, builds, signs and
//        finalizes without leaving the device. scanBack() derives the wallet's
//        own output scripts from its issued pockets and walks a peer.
//   xmr: issueMonero() persists a Monero pocket with a real standard address;
//        monero.scan() proves one block from a node and looks for the wallet's
//        own outputs inside it. monero.pocket(s) is the join back to the seed.
//
// HONESTLY UNJOINED, said here rather than faked:
//   - No transport is constructed. peerClient needs a socket `connect`, so
//     scanBack() takes fetchFilter/fetchBlock/peer from the caller, and the
//     Monero scan takes an injected fetchImpl. This file chooses no Tor stack.
//   - A Monero finding is RETURNED, not written into the pocket store.
//     pocketStore.record() only accepts a signed watcher report; there is no
//     xmr watcher bridge yet, so a scan result does not move a state.
//   - A Bitcoin scan payment is likewise returned, not persisted: the watcher
//     is the only thing allowed to move a payment, and that separation is kept.
//   - There is no Monero spend. The xmr rail here is read-only, because no
//     Monero transaction builder exists in this build.
//
// The factory uses every module's PUBLIC signature only, so lanes editing
// receive.js / blockScan.js internals do not touch this file.

import { createPocketStore } from './pocketStore.js';
import { createReceive } from './receive.js';
import {
  buildSpend, signSpend, finalizeSpend, spendAsBase64, DUST_LIMIT, SPEND_STATES,
} from './spend.js';
import { checkPayment, childWatcherToken } from './watcher.js';
import { derivePocket, pocketFor } from './root.js';
import { p2wpkhScriptFor } from './tx.js';
import { scanBack as scanBackBitcoin } from './blockScan.js';
import { moneroPocket, DEFAULT_NETWORK as DEFAULT_XMR_NETWORK } from './monero/pocket.js';
import { scanBlockFromNode } from './monero/scanFromNode.js';
import { ownOutputsInBlock } from './monero/ownOutputs.js';
import { createHandle, nextIndexFor } from './payHandle.js';
import { nodeOverride } from './monero/nodes.js';

const DEFAULT_BTC_NETWORK = 'bc';

function isPocketStore(store) {
  return store && typeof store.issue === 'function' && typeof store.list === 'function';
}

// A wallet, from one root and one store.
//
// `store` is either a pocket store or the tiny key/value it is built on
// (memoryKv in tests, indexedDbKv in a browser). Passing the raw kv is the
// supported shape so a caller never has to know the store's internals.
export function createWallet({
  seed,
  store,
  watcherUrl = '',
  node = null,
  pool = null,
  moneroPool = null,
  peerPool = null,
  scripts = null,
  network = DEFAULT_BTC_NETWORK,
  moneroNetwork = DEFAULT_XMR_NETWORK,
  fetchImpl,
} = {}) {
  if (!(seed instanceof Uint8Array) || seed.length === 0) {
    throw new Error('A wallet is built from the root seed bytes.');
  }
  if (!store) throw new Error('A wallet needs a pocket store (or the kv it sits on).');
  const pockets = isPocketStore(store) ? store : createPocketStore(store);
  const btcNetwork = String(network || DEFAULT_BTC_NETWORK).toLowerCase();

  const receive = createReceive({ seed, store: pockets, watcherUrl });

  // --- bitcoin: issue, watch, spend -----------------------------------------

  // One pocket, translated out of the store and back to its key from the seed.
  // The stored address is checked against the re-derivation, so a store written
  // by another build cannot be spent from silently with the wrong key.
  async function derivePocketFor({ coin = 'btc', index, walletNetwork = btcNetwork } = {}) {
    const row = await pockets.get(coin, index);
    if (!row) throw new Error(`No ${coin} pocket #${index} was issued on this device.`);
    const key = pocketFor(seed, { coin, index, network: walletNetwork });
    if (row.address && key.address && row.address !== key.address) {
      throw new Error(`Pocket #${index} on this device does not re-derive to the stored ${coin} address.`);
    }
    return { ...key, coin, index };
  }

  // Issue a pocket for a customer. btc goes through the receive path; xmr needs
  // moneroPocket, because the receive path's xmr pocket carries no address (the
  // bitcoin-shaped pocketFor stops at the entropy).
  async function issue({ coin = 'btc', network: issueNetwork, ...options } = {}) {
    const key = String(coin || 'btc').toLowerCase();
    if (key === 'xmr') return issueMonero({ ...options, ...(issueNetwork ? { walletNetwork: issueNetwork } : {}) });
    return receive.issue({ coin: key, ...(issueNetwork ? { network: issueNetwork } : {}), ...options });
  }

  async function issueMonero({ walletNetwork = moneroNetwork, label = '' } = {}) {
    const build = (stored) => {
      const current = stored || createHandle({ coin: 'xmr', label });
      const index = nextIndexFor(current, 'xmr');
      const keys = moneroPocket(seed, index, { network: walletNetwork });
      const next = { ...current, next: { ...current.next, xmr: index + 1 } };
      return {
        keys,
        handle: next,
        pocket: { coin: 'xmr', index, address: keys.address, path: null, state: 'address_issued' },
      };
    };
    // issueNext (when the store has it) keeps read-handle -> derive -> write in
    // ONE queue turn, the same way receive.issue does, so two xmr issues in one
    // turn cannot reuse an index. The plain issue() is the fallback shape.
    if (typeof pockets.issueNext === 'function') {
      let keys;
      const { pocket, handle } = await pockets.issueNext((stored) => {
        const built = build(stored);
        keys = built.keys;
        return built;
      });
      return { pocket, handle, keys };
    }
    const current = (await receive.handle()) || createHandle({ coin: 'xmr', label });
    const built = build(current);
    const row = await pockets.issue(built.pocket, { handle: built.handle });
    return { pocket: row, handle: built.handle, keys: built.keys };
  }

  // Ask the watcher about one issued pocket. Thin over receive.scan so the
  // watcher half has a door here; the answer is persisted by receive.scan.
  function watch(options = {}) {
    return receive.scan(options);
  }

  // The spend half. build() needs the private key, which lives only in the
  // seed, so it loads the row and re-derives. sign()/finalize() are pure and
  // take what build() returned.
  const spend = {
    DUST_LIMIT,
    states: SPEND_STATES,
    derive: derivePocketFor,
    async build({ coin = 'btc', index, network: spendNetwork = btcNetwork, ...options } = {}) {
      const pocket = await derivePocketFor({ coin, index });
      return { ...buildSpend({ pocket, network: spendNetwork, ...options }), pocket };
    },
    sign({ psbt, pocket } = {}) {
      return signSpend({ psbt, pocket });
    },
    finalize({ psbt } = {}) {
      return finalizeSpend(psbt);
    },
    asBase64(psbt) {
      return spendAsBase64(psbt);
    },
  };

  // The scripts this wallet pays. Derived from its own issued bitcoin pockets,
  // unless the caller supplied some at build time. A P2WPKH script is the same
  // on every network (only the address prefix changes), so no network is taken.
  async function ownScripts() {
    const rows = (await pockets.list()).filter((row) => String(row.coin).toLowerCase() === 'btc' && row.address);
    return rows.map((row) => p2wpkhScriptFor(derivePocket(seed, 'btc', row.index).publicKey));
  }

  // Walk back from a tip over a peer, looking for our own coins. The peer
  // plumbing (fetchFilter/fetchBlock/peer) is the caller's, because no Tor stack
  // is chosen here. Scripts default to the wallet's own; an explicit list wins.
  //
  // A wallet-level `pool` is forwarded, so a caller that configured a pool gets
  // the agreeing-peers path in blockScan; passing pool: null explicitly keeps a
  // single trusted peer. A pooled scan also needs the caller's peer client.
  async function scanBack({ scripts: wanted = scripts, pool: scanPool = peerPool ?? pool, ...options } = {}) {
    const list = wanted ?? await ownScripts();
    return scanBackBitcoin({ ...options, pool: scanPool, scripts: list });
  }

  // --- monero: issue and read ----------------------------------------------

  function moneroPocketAt(index, { walletNetwork = moneroNetwork } = {}) {
    return moneroPocket(seed, index, { network: walletNetwork });
  }

  // Every xmr pocket on this device, keyed back from the seed. This is what a
  // scan hands to the prover: the scan only ever looks for the wallet's own.
  async function moneroPockets({ walletNetwork = moneroNetwork } = {}) {
    const rows = (await pockets.list()).filter((row) => String(row.coin).toLowerCase() === 'xmr');
    return rows.map((row) => moneroPocketAt(row.index, { walletNetwork }));
  }

  // Which one node this scan talks to. A monero node pool (or the shared
  // `pool`) picks and stays sticky; an explicit node wins; the CIPHER_XMR_NODE
  // door is the last resort. A peer pool can stand in for `pool`: its pick()
  // returns endpoints, which are turned back into host:port.
  function resolveNode() {
    const chosenPool = moneroPool ?? pool;
    if (chosenPool && typeof chosenPool.pick === 'function') {
      const picked = chosenPool.pick();
      if (typeof picked === 'string') return picked;
      const first = Array.isArray(picked) ? picked[0] : picked;
      if (typeof first === 'string') return first;
      if (first && first.host) return `${first.host}:${first.port}`;
    }
    if (node) return String(node).trim().toLowerCase();
    const fromEnv = nodeOverride();
    if (fromEnv) return fromEnv;
    throw new Error('This wallet has no Monero node: pass one, pass a pool, or set CIPHER_XMR_NODE.');
  }

  const monero = {
    network: moneroNetwork,
    pocket: moneroPocketAt,
    pockets: moneroPockets,
    // Prove one block from a node, then look for our own outputs in it. The
    // returned outputs carry their pocket index; nothing is persisted (see the
    // header: there is no xmr watcher bridge yet).
    async scan({ pockets: supplied, indices, hash, height, ...options } = {}) {
      const wantedPockets = supplied ?? (indices
        ? indices.map((index) => moneroPocketAt(index))
        : await moneroPockets());
      return scanBlockFromNode(resolveNode(), {
        hash, height, pockets: wantedPockets, pool: moneroPool, fetchImpl, ...options,
      });
    },
    // The proof layer on bytes the caller already holds.
    ownOutputs({ blockBytes, txBytesList, expectHash, trustViewTags, pockets: supplied } = {}) {
      if (!supplied) throw new Error('ownOutputs needs the pockets to look for; use monero.scan for the store-derived ones.');
      return ownOutputsInBlock({ blockBytes, txBytesList, expectHash, trustViewTags, pockets: supplied });
    },
  };

  return {
    seed,
    store: pockets,
    receive,
    issue,
    issueMonero,
    watch,
    spend,
    monero,
    scanBack,
    walletScripts: ownScripts,
    watcherUrl,
    node,
    pool,
    watcher: { checkPayment, childWatcherToken },
  };
}

export default createWallet;
