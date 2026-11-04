// Who we talk to, and how many of them have to agree.
//
// A node the person runs is not required, and a block explorer is never
// allowed. What is left is a small set of ordinary peers reached over Tor,
// chosen by the wallet, rotated, and never trusted one at a time for anything
// that costs money.
//
// The rules here are the ones that keep that honest:
//   - never a public block explorer, and never a lookalike of one;
//   - a clearnet peer is refused unless someone deliberately allowed clearnet,
//     because the point of this wallet is that the peer does not learn an IP;
//   - filter data is accepted only when two independent peers agree, so one
//     lying peer cannot hide a payment or invent one;
//   - agreement is anchored on the first peer that answers, then checked
//     against one more. That is fail-closed — a liar cannot fabricate a filter
//     and an answer nobody seconds is refused — but it is not Sybil-proof: a
//     compromised peer asked first can force a refusal, and it cannot force a
//     false answer. Rotating the pool spreads that risk; it does not remove it;
//   - a broadcast counts when any peer takes it, and being taken is not being
//     mined. Nothing here says a transaction is paid.
//
// The transport is passed in, not imported. This module holds policy; the
// socket lives elsewhere, which is also what makes the policy testable against
// a fake that can lie.

import { blockOutputScripts, filterMatchesBlock } from './filters.js';
import { isPublicExplorer } from './watcher.js';

export const MIN_AGREEMENT = 2;

const ONION = /^[a-z2-7]{16,56}\.onion$/;
const HOSTNAME = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/;

function parsePeer(peer) {
  if (typeof peer === 'string') {
    const text = peer.trim().toLowerCase();
    const at = text.lastIndexOf(':');
    if (at === -1) throw new Error('A peer is written host:port.');
    return { host: text.slice(0, at), port: Number(text.slice(at + 1)) };
  }
  if (peer && typeof peer === 'object') {
    return { host: String(peer.host ?? '').trim().toLowerCase(), port: Number(peer.port) };
  }
  throw new Error('A peer is written host:port.');
}

function checkPort(port) {
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('A peer port is 1 to 65535.');
}

export function peerKey(peer) {
  return `${peer.host}:${peer.port}`;
}

export function isOnionHost(host) {
  return ONION.test(String(host ?? '').toLowerCase().replace(/\.$/, ''));
}

// Validate one peer against the rules, without adding it.
export function checkPeer(peer, { allowClearnet = false } = {}) {
  const { host, port } = parsePeer(peer);
  if (!host) throw new Error('A peer needs a host.');
  if (!HOSTNAME.test(host) && !isOnionHost(host)) throw new Error('That peer host is not a hostname.');
  checkPort(port);
  if (isPublicExplorer(`https://${host}/`)) {
    throw new Error('That is a block explorer. This wallet does not ask one anything.');
  }
  const onion = isOnionHost(host);
  if (!onion && !allowClearnet) {
    throw new Error('A peer reachable without Tor would learn where you are. Use an .onion peer, or say clearnet is allowed.');
  }
  return { host, port, kind: onion ? 'onion' : 'clearnet' };
}

export function createPeerPool({ allowClearnet = false } = {}) {
  const peers = [];
  let cursor = 0;

  function add(peer) {
    const checked = checkPeer(peer, { allowClearnet });
    const key = peerKey(checked);
    if (peers.some((existing) => peerKey(existing) === key)) return checked;
    peers.push(checked);
    return checked;
  }

  // Take `count` peers, walking the list so the same one is not always first.
  function pick(count = 1, { exclude = [] } = {}) {
    const skip = new Set(exclude.map((peer) => (typeof peer === 'string' ? peer : peerKey(peer))));
    const available = peers.filter((peer) => !skip.has(peerKey(peer)));
    if (available.length === 0) throw new Error('No peers are configured.');
    const want = Math.min(count, available.length);
    const chosen = [];
    for (let i = 0; i < want; i += 1) {
      chosen.push(available[(cursor + i) % available.length]);
    }
    cursor = (cursor + want) % available.length;
    return chosen;
  }

  return {
    add,
    list: () => peers.map((peer) => ({ ...peer })),
    size: () => peers.length,
    pick,
    requireAgreement(count = MIN_AGREEMENT) {
      if (peers.length < count) {
        throw new Error(`This needs ${count} independent peers and ${peers.length} are configured. One peer is not a witness.`);
      }
      return count;
    },
  };
}

// Ask two peers for the same filter. Agreement is the only answer that counts;
// disagreement means one of them is lying and this wallet does not know which,
// so nothing is believed and the caller is told which peers disagreed.
export async function agreedFilter(pool, fetchFilter, blockHash, { peers, startHeight } = {}) {
  // The hash the question was about, in one spelling. An answer has to name it
  // back: a valid filter from another block is not evidence about this block,
  // and comparing filter bytes alone would let two such answers agree on data
  // nobody asked for.
  const askedHash = String(blockHash ?? '').trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(askedHash)) {
    throw new Error('An agreed filter needs the 32-byte block hash it is asking about.');
  }
  pool.requireAgreement(MIN_AGREEMENT);
  // Ask one more than the quorum when one is available, so a single dead peer
  // does not stall the wallet when a spare is already configured.
  const asked = peers ?? pool.pick(Math.min(pool.size(), MIN_AGREEMENT + 1));
  if (asked.length < MIN_AGREEMENT) {
    throw new Error(`This needs ${MIN_AGREEMENT} independent peers and ${asked.length} were asked.`);
  }

  const answers = [];
  for (const peer of asked) {
    let answer;
    try {
      answer = await fetchFilter(peer, askedHash, { startHeight });
    } catch (error) {
      answers.push({ peer, error: error?.message || String(error) });
      continue;
    }
    if (!answer || !(answer.filter instanceof Uint8Array) || answer.filter.length === 0) {
      answers.push({ peer, error: 'no filter' });
      continue;
    }
    if (String(answer.blockHash ?? '').trim().toLowerCase() !== askedHash) {
      answers.push({ peer, error: 'answered about a different block' });
      continue;
    }
    answers.push({ peer, filter: answer.filter });
  }

  const good = answers.filter((answer) => answer.filter);
  const first = good[0];
  if (!first) {
    // Every peer failed. If they all failed for the SAME reason, that reason is
    // the answer: a missing argument on the calling side would otherwise be
    // reported as a claim about the network, and a person would go looking at
    // peers for a fault in their own call. Different reasons still get the
    // round-up, because then no single one of them is the answer.
    const reasons = new Set(answers.map((answer) => answer.error || 'no filter'));
    if (answers.length > 0 && reasons.size === 1) throw new Error([...reasons][0]);
    throw new Error('No peer answered with a filter.');
  }
  const agreed = good.filter((answer) => sameBytes(answer.filter, first.filter));
  if (agreed.length < MIN_AGREEMENT) {
    const who = answers.map((a) => `${a.peer.host}:${a.peer.port}${a.error ? ` (${a.error})` : ''}`).join(', ');
    throw new Error(`The peers did not agree on this block's filter, so nothing was believed. Asked: ${who}.`);
  }
  return { filter: first.filter, peers: agreed.map((answer) => answer.peer) };
}

// Ask peers where the chain ends.
//
// The tip hash is the most load-bearing peer-supplied value in a scan: walkBack
// starts from it and numbers every height down from `tipHeight`, and the filter
// question for every block below it is asked at a height the walk invented from
// that claim. A lone peer that names a tip on its own private chain therefore
// makes the whole walk believe that chain. Two peers have to name the same tip
// before the walk starts from it.
//
// Same shape and same fail-closed rule as agreedFilter: ask one more than the
// quorum when a spare is configured, anchor on the first valid answer, and
// require MIN_AGREEMENT to name the SAME hash back. A missing or malformed
// answer is a dead peer and is skipped, not a veto; a disagreeing valid answer
// is a veto.
export async function agreedTip(pool, fetchTip) {
  if (typeof fetchTip !== 'function') throw new Error('An agreed tip needs a way to fetch a tip.');
  pool.requireAgreement(MIN_AGREEMENT);
  const asked = pool.pick(Math.min(pool.size(), MIN_AGREEMENT + 1));
  if (asked.length < MIN_AGREEMENT) {
    throw new Error(`This needs ${MIN_AGREEMENT} independent peers and ${asked.length} were asked.`);
  }

  const answers = [];
  for (const peer of asked) {
    let answer;
    try {
      answer = await fetchTip(peer);
    } catch (error) {
      answers.push({ peer, error: error?.message || String(error) });
      continue;
    }
    // Accept a bare hash or an object carrying one. A tip that is not a hash is
    // no answer, the same way a filter that names another block is no answer.
    const hash = String(answer?.hash ?? answer?.tipHash ?? answer ?? '').trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(hash)) {
      answers.push({ peer, error: 'no tip' });
      continue;
    }
    answers.push({ peer, hash });
  }

  const good = answers.filter((answer) => answer.hash);
  const first = good[0];
  if (!first) {
    const reasons = new Set(answers.map((answer) => answer.error || 'no tip'));
    if (answers.length > 0 && reasons.size === 1) throw new Error([...reasons][0]);
    throw new Error('No peer answered with a tip.');
  }
  const agreed = good.filter((answer) => answer.hash === first.hash);
  if (agreed.length < MIN_AGREEMENT) {
    const who = answers.map((a) => `${a.peer.host}:${a.peer.port}${a.error ? ` (${a.error})` : ''}`).join(', ');
    throw new Error(`The peers did not agree on the tip, so nothing was believed. Asked: ${who}.`);
  }
  return { hash: first.hash, peers: agreed.map((answer) => answer.peer) };
}

// The filter a wallet may act on: agreed by two peers AND rebuilt from the
// block itself. Agreement alone is two peers saying the same thing, and two
// lying peers say the same thing too, so the block is the third witness. It
// only became one when the body started being checked: a header that hashes to
// the advertised hash says nothing about the transactions travelling under it,
// and a filter rebuilt from a forged body matches the forged filter. The body
// is checked against the header's merkle root in blockOutputScripts
// (src/merkle.js), which throws before this function can compare filters, so a
// body the header does not commit to is a refusal here rather than a believed
// payment. This comment previously claimed the forge was impossible while it
// was not; the false claim is recorded in README and pinned by a test.
export async function verifiedFilter(pool, client, blockHash, { prevScripts, peers, startHeight, block } = {}) {
  const agreed = await agreedFilter(pool, client.fetchFilter, blockHash, { peers, startHeight });
  const asked = String(blockHash ?? '').trim().toLowerCase();

  // The block the filter is checked against. A caller that already holds the
  // bytes (the scan's walk fetched and hash+merkle-verified them) passes them
  // and saves a second fetch; the same hash check below still runs, so a
  // supplied block that is not the one asked for is refused either way.
  let bytes = block ?? null;
  if (bytes !== null && !(bytes instanceof Uint8Array)) {
    throw new Error('A supplied block is bytes.');
  }

  // Otherwise ask a peer that agreed. If it will not serve the block, the
  // filter stays unverified and is refused rather than believed on agreement
  // alone.
  let lastError = null;
  if (!bytes) {
    for (const peer of agreed.peers) {
      try {
        ({ bytes } = await client.fetchBlock(peer, asked));
        break;
      } catch (error) {
        lastError = error;
      }
    }
  }
  if (!bytes) {
    throw new Error(`The filter was not verified against its block: ${lastError?.message || 'no peer served the block'}.`);
  }
  const { blockHash: actual } = blockOutputScripts(bytes);
  if (actual !== asked) {
    throw new Error(`That peer served block ${actual}, not ${asked}.`);
  }
  if (!filterMatchesBlock({ filter: agreed.filter, block: bytes, prevScripts })) {
    throw new Error('The peers agreed on a filter that its own block does not produce, so nothing was believed.');
  }
  return { filter: agreed.filter, peers: agreed.peers, block: bytes };
}

function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

// Hand the raw transaction to peers until one takes it. Being taken means a
// peer accepted the bytes; it does not mean the transaction is mined, and it
// does not mean the payment is made.
export async function broadcast(pool, sendTx, rawTx) {
  if (!(rawTx instanceof Uint8Array) || rawTx.length === 0) throw new Error('There is nothing to broadcast.');

  const attempted = [];
  for (const peer of pool.pick(pool.size())) {
    try {
      await sendTx(peer, rawTx);
      attempted.push({ peer, accepted: true });
      return { acceptedBy: peer, attempted };
    } catch (error) {
      attempted.push({ peer, accepted: false, error: error?.message || String(error) });
    }
  }
  const who = attempted.map((a) => `${a.peer.host}:${a.peer.port} (${a.error})`).join(', ');
  throw new Error(`No peer took the transaction. Tried: ${who}.`);
}
