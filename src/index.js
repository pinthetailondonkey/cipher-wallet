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
//   - No Tor stack is chosen. peerClient needs a socket `connect`, so when the
//     caller passes one the wallet builds its own transport (wallet.peer) and
//     scanBack()/scanHeadersFirst() reach a peer without hand-passed fetchers;
//     without `connect`, scanBack() still takes fetchFilter/fetchBlock/peer from
//     the caller. The Monero scan takes an injected fetchImpl.
//   - A Monero finding is written to the pocket store only when the caller asks
//     (`monero.scan({ record: true })`, or `monero.recordFromScan`): the bridge
//     in src/monero/watch.js turns a found output into a watcher report, so the
//     same record() path and the same state walk move an xmr pocket. Without
//     `record` a finding is returned and forgotten.
//   - A Bitcoin scan payment is likewise returned, not persisted: the watcher
//     is the only thing allowed to move a payment, and that separation is kept.
//   - There is no Monero spend. The format can be WRITTEN now (`monero.tx`
//     re-encodes a transaction's prefix, base and type 6 prunable) and a ring
//     can be FETCHED and turned into offsets (`monero.ringFor`), but nothing
//     here computes a key image from a fetched output, builds a commitment,
//     signs a CLSAG, or broadcasts.
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
import { scanBack as scanBackBitcoin, scanHeaderFirst } from './blockScan.js';
import { createPeerClient } from './peerClient.js';
import { moneroPocket, DEFAULT_NETWORK as DEFAULT_XMR_NETWORK } from './monero/pocket.js';
import { reportsFromScan } from './monero/watch.js';
import { scanBlockFromNode } from './monero/scanFromNode.js';
import { ownOutputsInBlock } from './monero/ownOutputs.js';
import {
  writeTransactionPrefix, writeRctBase, writeType6Prunable, writeTransaction,
} from './monero/txWriter.js';
import { offsetsToAbsolute, absoluteToOffsets, ringFromOuts } from './monero/outs.js';
import { createHandle, nextIndexFor } from './payHandle.js';
import { nodeSourceFromEnv } from './monero/nodes.js';
import { getOuts } from './monero/nodeClient.js';

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
  connect = null,
  peerNetwork = 'mainnet',
  fetchImpl,
  env = globalThis.process?.env,
} = {}) {
  if (!(seed instanceof Uint8Array) || seed.length === 0) {
    throw new Error('A wallet is built from the root seed bytes.');
  }
  if (!store) throw new Error('A wallet needs a pocket store (or the kv it sits on).');
  const pockets = isPocketStore(store) ? store : createPocketStore(store);
  const btcNetwork = String(network || DEFAULT_BTC_NETWORK).toLowerCase();

  const receive = createReceive({ seed, store: pockets, watcherUrl });

  // The transport, when the caller supplies a socket. `connect(peer)` is the
  // exact shape peerClient.js expects, so the wallet can own the client and a
  // caller stops hand-wiring fetchFilter/fetchBlock/peer. With no `connect`
  // this stays null and every call below behaves exactly as before.
  const peerClient = typeof connect === 'function' ? createPeerClient({ connect, network: peerNetwork }) : null;

  // One peer record to walk with, when a pool is configured and the caller
  // passed none. `pick()` returns an array; the first is the single-peer walk's
  // peer. An empty pool degrades to undefined, not a throw, so the existing
  // caller-supplied path is never made worse by this file.
  function pickPeer(candidatePool) {
    if (!candidatePool || typeof candidatePool.pick !== 'function') return undefined;
    try {
      const picked = candidatePool.pick();
      return Array.isArray(picked) ? picked[0] : picked;
    } catch {
      return undefined;
    }
  }

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

  async function issueMonero({ walletNetwork = moneroNetwork, label = '', amount = null } = {}) {
    const build = (stored) => {
      const current = stored || createHandle({ coin: 'xmr', label });
      const index = nextIndexFor(current, 'xmr');
      const keys = moneroPocket(seed, index, { network: walletNetwork });
      const next = { ...current, next: { ...current.next, xmr: index + 1 } };
      return {
        keys,
        handle: next,
        pocket: { coin: 'xmr', index, address: keys.address, path: null, state: 'address_issued', demand: amount },
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

  // Walk back from a tip over a peer, looking for our own coins. Scripts default
  // to the wallet's own; an explicit list wins.
  //
  // The peer plumbing (fetchFilter/fetchBlock/peer) is the caller's unless the
  // wallet built a transport. When it did, anything the caller left out is
  // supplied from wallet.peer, and a pool with no peer picks one for the walk.
  // With no transport the arguments pass straight through, unchanged.
  //
  // A wallet-level `pool` is forwarded, so a caller that configured a pool gets
  // the agreeing-peers path in blockScan; passing pool: null explicitly keeps a
  // single trusted peer. A pooled scan also needs a peer client, which the
  // built transport supplies.
  async function scanBack({
    scripts: wanted = scripts,
    pool: scanPool = peerPool ?? pool,
    client,
    peer,
    fetchFilter,
    fetchBlock,
    ...options
  } = {}) {
    const list = wanted ?? await ownScripts();
    const wired = {};
    if (peerClient) {
      if (client !== undefined) wired.client = client; else wired.client = peerClient;
      if (fetchFilter !== undefined) wired.fetchFilter = fetchFilter; else wired.fetchFilter = peerClient.fetchFilter;
      if (fetchBlock !== undefined) wired.fetchBlock = fetchBlock; else wired.fetchBlock = peerClient.fetchBlock;
    } else {
      if (client !== undefined) wired.client = client;
      if (fetchFilter !== undefined) wired.fetchFilter = fetchFilter;
      if (fetchBlock !== undefined) wired.fetchBlock = fetchBlock;
    }
    const walkPeer = peer !== undefined ? peer : pickPeer(scanPool);
    if (walkPeer !== undefined) wired.peer = walkPeer;
    return scanBackBitcoin({ ...options, pool: scanPool, scripts: list, ...wired });
  }

  // Header-first: walk headers from an anchor, ask each block's filter, and
  // download a body only when the filter matched. The anchor is the caller's
  // (nothing here pins one); fetchHeaders/fetchFilter/fetchBlock come from the
  // built transport unless the caller supplies its own. Scripts default to the
  // wallet's own, the same as scanBack.
  async function scanHeadersFirst({
    scripts: wanted = scripts,
    pool: scanPool = peerPool ?? pool,
    peer,
    fetchHeaders,
    fetchFilter,
    fetchBlock,
    ...options
  } = {}) {
    const list = wanted ?? await ownScripts();
    const wired = {};
    if (peerClient) {
      wired.fetchHeaders = fetchHeaders !== undefined ? fetchHeaders : peerClient.fetchHeaders;
      wired.fetchFilter = fetchFilter !== undefined ? fetchFilter : peerClient.fetchFilter;
      wired.fetchBlock = fetchBlock !== undefined ? fetchBlock : peerClient.fetchBlock;
    } else {
      if (fetchHeaders !== undefined) wired.fetchHeaders = fetchHeaders;
      if (fetchFilter !== undefined) wired.fetchFilter = fetchFilter;
      if (fetchBlock !== undefined) wired.fetchBlock = fetchBlock;
    }
    const walkPeer = peer !== undefined ? peer : (peerClient ? pickPeer(scanPool) : undefined);
    if (walkPeer !== undefined) wired.peer = walkPeer;
    return scanHeaderFirst({ ...options, scripts: list, ...wired });
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
  // `pool`) picks and stays sticky; an explicit node wins; otherwise the node
  // door is `nodeSourceFromEnv`, which reads CIPHER_XMR_NODE and otherwise
  // falls to the shipped list. That pool is built once so the choice is sticky
  // across scans. A peer pool can stand in for `pool`: its pick() returns
  // endpoints, which are turned back into host:port.
  let walletNodePool = null;
  let walletNodePoolNode = null;
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
    if (!walletNodePool) walletNodePool = nodeSourceFromEnv({ env });
    walletNodePoolNode = walletNodePool.pick();
    return walletNodePoolNode;
  }

  // A failed read is not a finding. When the node came from the wallet's own
  // pool, the failure moves the session to the NEXT configured node, so the
  // following scan starts somewhere else rather than on a known-dead host. A
  // node the caller named (or an injected pool) is not this pool's to rotate.
  function nodeFailed(nodeAsked) {
    if (walletNodePool && walletNodePoolNode === nodeAsked) walletNodePool.abandon(nodeAsked);
  }

  const monero = {
    network: moneroNetwork,
    pocket: moneroPocketAt,
    pockets: moneroPockets,
    // Prove one block from a node, then look for our own outputs in it.
    //
    // `record` writes any finding into the pocket store through the same
    // watcher-report path the Bitcoin rail uses, so a found xmr payment moves a
    // pocket's state instead of being returned and forgotten. It is off by
    // default: a caller that only wants to look at a block asks for neither.
    // Remember a found output's `output` index is the pocket row it came from;
    // the five honest limits are in `monero/watch.js`.
    async scan({ pockets: supplied, indices, hash, height, tipHeight, record = false, ...options } = {}) {
      const wantedPockets = supplied ?? (indices
        ? indices.map((index) => moneroPocketAt(index))
        : await moneroPockets());
      const chosen = resolveNode();
      let out;
      try {
        out = await scanBlockFromNode(chosen, {
          hash, height, pockets: wantedPockets, pool: moneroPool, fetchImpl, ...options,
        });
      } catch (error) {
        nodeFailed(chosen);
        throw error;
      }
      if (!record) return out;
      const recorded = await monero.recordFromScan(out, { height, tipHeight });
      return { ...out, recorded };
    },

    // Write a scan's own findings into the pocket store. Returns one entry per
    // report: `{ pocket, output, ok }` or `{ ... , error }` when the store
    // refused (a pocket that already names another transaction, say). A refusal
    // is reported, not thrown, so one bad row cannot hide the rest of a scan.
    async recordFromScan(out, { height = null, tipHeight = null } = {}) {
      if (!out || !Array.isArray(out.outputs)) throw new Error('recordFromScan needs a scan result with outputs.');
      const results = [];
      for (const entry of reportsFromScan(out.outputs, { height, tipHeight })) {
        try {
          // A pocket issued with a price is checked against it; without one the
          // found value is the demand (see watch.js).
          const row = await pockets.get('xmr', entry.pocket);
          const demand = row?.demand ?? entry.report.amount;
          await pockets.record('xmr', entry.pocket, entry.report, { amount: demand });
          results.push({ pocket: entry.pocket, output: entry.output, txid: entry.report.txid, ok: true });
        } catch (error) {
          results.push({ pocket: entry.pocket, output: entry.output, txid: entry.report.txid, ok: false, error: error?.message || String(error) });
        }
      }
      return results;
    },
    // The proof layer on bytes the caller already holds.
    ownOutputs({ blockBytes, txBytesList, expectHash, trustViewTags, pockets: supplied } = {}) {
      if (!supplied) throw new Error('ownOutputs needs the pockets to look for; use monero.scan for the store-derived ones.');
      return ownOutputsInBlock({ blockBytes, txBytesList, expectHash, trustViewTags, pockets: supplied });
    },
    // The writing half of the format, reached from the wallet: a re-encode of
    // what a read parsed, and a from-scratch framing of the sections a spend
    // needs. Both are pure byte work: no keys, no node, no signing.
    tx: { writeTransactionPrefix, writeRctBase, writeType6Prunable, writeTransaction },

    // A ring for one of our outputs, and the arithmetic around it. This is the
    // step a spend needs before it can write anything: the input's offsets and
    // the members a signature signs against. The node is chosen the same way a
    // scan chooses one (sticky, rotated on failure), so a ring never stitches
    // two operators' answers together.
    //
    // `indices` are ABSOLUTE positions in the amount-0 output list, `ours` is
    // the one of those that is really ours. The answer is the ring ordered by
    // index, the offsets to write into the input, and our position in it.
    async ringFor({ indices, ours, amount = 0n, getTxid = false, node: suppliedNode, ...options } = {}) {
      if (!Array.isArray(indices) || indices.length === 0) {
        throw new Error('ringFor needs the absolute indices of the ring to fetch.');
      }
      const chosen = suppliedNode ? String(suppliedNode).trim().toLowerCase() : resolveNode();
      let answer;
      try {
        answer = await getOuts(chosen, { outputs: indices.map((index) => ({ amount, index })), getTxid }, {
          pool: moneroPool, fetchImpl, ...options,
        });
      } catch (error) {
        if (!suppliedNode) nodeFailed(chosen);
        throw error;
      }
      const built = ringFromOuts({ outs: answer.outs, ours });
      return { ...built, node: answer.address, untrusted: answer.untrusted };
    },
    ring: { offsetsToAbsolute, absoluteToOffsets, ringFromOuts },
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
    peer: peerClient,
    scanBack,
    scanHeadersFirst,
    walletScripts: ownScripts,
    watcherUrl,
    node,
    pool,
    watcher: { checkPayment, childWatcherToken },
  };
}

export default createWallet;
