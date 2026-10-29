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
export async function agreedFilter(pool, fetchFilter, blockHash, { peers } = {}) {
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
      answer = await fetchFilter(peer, blockHash);
    } catch (error) {
      answers.push({ peer, error: error?.message || String(error) });
      continue;
    }
    if (!answer || !(answer.filter instanceof Uint8Array) || answer.filter.length === 0) {
      answers.push({ peer, error: 'no filter' });
      continue;
    }
    answers.push({ peer, filter: answer.filter });
  }

  const good = answers.filter((answer) => answer.filter);
  const first = good[0];
  if (!first) throw new Error('No peer answered with a filter.');
  const agreed = good.filter((answer) => sameBytes(answer.filter, first.filter));
  if (agreed.length < MIN_AGREEMENT) {
    const who = answers.map((a) => `${a.peer.host}:${a.peer.port}${a.error ? ` (${a.error})` : ''}`).join(', ');
    throw new Error(`The peers did not agree on this block's filter, so nothing was believed. Asked: ${who}.`);
  }
  return { filter: first.filter, peers: agreed.map((answer) => answer.peer) };
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
