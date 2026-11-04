// Talking to one Monero node, as little as possible.
//
// A node is a stranger's server. It answers from its own copy of the chain and
// it can lie, stall, or serve a different network's blocks. This file's whole
// job is to make every one of those a refusal rather than a value that travels
// deeper into the wallet wearing the shape of a fact.
//
// What it returns is BYTES, never the node's parsed copy of them. The JSON a
// daemon sends beside the block is a convenience for humans; the wallet reads
// the blob and parses it itself (block.js). Two claims the daemon makes about
// its own answer are cross-checked and named as claims — the hash it says the
// block has, and the height it says the block sits at — because a lie there is
// cheap to make and cheap to catch when it disagrees with what was asked.
//
// One node per scan is nodes.js's rule and this file does not weaken it: a
// caller pins the node, and every request checks it is still the pinned one.
//
// CHECKED BEFORE THE SOCKET, NOT AFTER THE ANSWER. These doors used to ask the
// pool only once the bytes were already in hand, so a scan learned the node had
// been abandoned after it had already disclosed the request to it. The rule is
// worth nothing in that order: the point of refusing is to keep a stranger from
// receiving the query. Both doors now check first, and a pool that refuses
// means no request is made at all.
//
// A DEAD NODE ENDS THE SCAN, NOT THE PIN. A transport failure abandons the node
// in the pool, so the NEXT scan starts on the next node; the current call still
// refuses. Quietly retrying on another node inside one call would stitch two
// operators' answers into one result and make the refusals above meaningless.

import { hex } from '@scure/base';
import { createPinnedPool, nodeSourceFromEnv, OVERRIDE_ENV } from './nodes.js';

export const MAX_HEIGHT = 0xffffffff;

// WHICH POOL A CALL IS CHECKED AGAINST.
//
// An injected pool is the caller's, and it is used exactly as before: a scan
// layer that already chose a node keeps its own pin.
//
// With no pool, the door asks the wallet's own configuration. That is what
// makes CIPHER_XMR_NODE a door instead of a name: a caller that forgets to pass
// a pool no longer gets an unchecked call, it gets the environment's answer.
//
// When the environment names nothing, the caller has still named ONE node in
// the call itself, so the pin is that node. The shipped list is not consulted
// here: it is chosen a level up, by index.resolveNode, and passed down as the
// node, so a one-node pinned pool can only ever assert against the node the
// caller (or the wallet's own resolve step) wrote down.
//
// The named "nothing configured" refusal still belongs to createNodePool, and
// it is still what nodeSourceFromEnv() throws when a scan asks the wallet to
// choose. The alternative - refusing every no-pool call when the environment is
// empty - was measured and rejected: it turns 28 existing door tests red across
// block-redirect, block-timeout, tx-answer, tx-door and tx-timeout, which test
// the door's parsing against a named node and are not this lane's to rewrite.
// Those callers pass a node; that is a pin. A refactor that deletes this
// fallback has to carry those 28 tests with it.
// CONSTRUCTED ONCE, NOT PER CALL. A pool built and thrown away on every request
// would discard the sticky session and the abandon/rotation state, so "one node
// per scan" would only hold inside a single call - true on the page and false
// in the wallet. The resolver is lazy (reading the environment at import is
// exactly what c22e6a7 removed) and keyed on the CONFIGURATION, not only on
// which object carried it: the key is the override value, so editing an env
// object in place rebuilds, and the process environment gets one pool per value.
//
// RE-PICKED ON EVERY USE. pick() is idempotent while a session exists and takes
// the next node after an abandon. Without that, a transport failure emptied the
// cached session and every later call was refused with the stitching sentence -
// forever, with no request made, because nothing had been stitched: nothing had
// been asked. With it, the next call re-picks (the next node for a list) and,
// when the pool is genuinely exhausted, fails with pick()'s named
// "No configured Monero node answered. This is a failed read..." instead.
const POOLS_BY_ENV = new WeakMap();
const POOLS_BY_PROCESS = new Map();

function envKey(env) {
  return String(env?.[OVERRIDE_ENV] ?? '');
}

function buildConfiguredPool(env, key) {
  const configured = nodeSourceFromEnv({ env });
  // A fresh pool has no session. Taking it here is what makes the first assert
  // the pinned one, and it is where "every configured node has failed" is
  // refused - before the socket, not instead of it.
  configured.pick();
  return { key, pool: configured };
}

function configuredPool(env) {
  if (env && typeof env === 'object') {
    const key = envKey(env);
    const hit = POOLS_BY_ENV.get(env);
    if (hit && hit.key === key) {
      hit.pool.pick();      // idempotent; re-picks after an abandon
      return hit.pool;
    }
    const built = buildConfiguredPool(env, key);
    POOLS_BY_ENV.set(env, built);
    return built.pool;
  }
  const key = envKey(globalThis.process?.env);
  const hit = POOLS_BY_PROCESS.get(key);
  if (hit) {
    hit.pick();
    return hit;
  }
  const built = buildConfiguredPool(undefined, key).pool;
  POOLS_BY_PROCESS.set(key, built);
  return built;
}

function poolFor(pool, node, env) {
  if (pool) return pool;
  // The environment OVERRIDE is the wallet's own choice and is enforced: a
  // caller that passed a different node is refused rather than silently
  // talking to the wrong one. With no override, the caller has named one node
  // in the call itself and that is the pin — the shipped list is chosen one
  // level up (index.resolveNode), which passes the chosen node here, so the
  // door never invents a node of its own.
  const key = env === undefined ? envKey(globalThis.process?.env) : envKey(env);
  if (key) return configuredPool(env);
  return createPinnedPool(node);
}

const HEX64 = /^[0-9a-f]{64}$/;
const HEX = /^[0-9a-fA-F]*$/;

export function cleanNode(node) {
  const address = typeof node === 'string' ? node : String(node?.address ?? '');
  const text = address.trim().toLowerCase().replace(/\.$/, '');
  // Brackets stay allowed for an IPv6 literal; `]` must be escaped inside a
  // class, `[` must not.
  if (!/^[a-z0-9.[\]:-]+:\d{1,5}$/.test(text)) {
    throw new Error(`That is not a node address: ${address}. An address is host:port.`);
  }
  return text;
}

function sameHost(asked, url) {
  try {
    const host = new URL(url).host.toLowerCase();
    return host === asked;
  } catch {
    return false;
  }
}

// One JSON-RPC call. Every failure mode below is a refusal, and each says which
// one it is: a caller must not read "the node did not answer" as "no payment".
async function call(node, { method, params }, {
  fetchImpl = globalThis.fetch, timeoutMs = 10000, timeoutSignal, pool = null, env,
} = {}) {
  if (typeof fetchImpl !== 'function') throw new Error('A node call needs a way to fetch.');
  const address = cleanNode(node);

  // Before the socket: which node is this call actually allowed to talk to?
  // The pool is resolved here, so a caller that passed no pool is checked
  // against the wallet's configuration rather than skipped.
  const pinned = poolFor(pool, address, env);

  // Before the socket: is this still the pinned node? A refusal here costs
  // nothing and keeps the query from reaching a server the scan has left.
  pinned.assertCurrent(address);

  const url = `http://${address}/json_rpc`;

  // A node that takes the connection and then says nothing is a stall, and a
  // read that never ends is a payment that never moves. Unless the caller
  // brought its own signal, this call carries a deadline, and the deadline runs
  // until the body has been read rather than stopping when headers arrive.
  const controller = timeoutSignal ? null : new AbortController();
  let timedOut = false;
  const bounded = Number.isFinite(timeoutMs) && timeoutMs > 0;
  const timer = controller && bounded ? setTimeout(() => { timedOut = true; controller.abort(); }, timeoutMs) : null;
  const noAnswer = (error) => (timedOut
    ? new Error(`The Monero node ${address} did not answer within ${timeoutMs} ms. A silent node is a failed read, not a finding about any payment.`)
    : new Error(`The Monero node ${address} did not answer: ${error?.message || 'no answer'}. This is a failed read, not a finding about any payment.`));

  try {
    let response;
    try {
      response = await fetchImpl(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: '0', method, params: params ?? {} }),
        // A redirect is a different server answering. Refused by the platform.
        redirect: 'error',
        signal: timeoutSignal ?? controller.signal,
      });
    } catch (error) {
      // The node did not answer at all: it is dead for this wallet, but only
      // for the NEXT scan. Abandoning it here is not a failover - this call
      // still refuses, and nothing is retried on another node inside it. The
      // call is unconditional: a pool without abandon would lose rotation
      // silently, which is the same class of defect as checking after the
      // socket. Both pool builders here provide it.
      pinned.abandon(address);
      throw noAnswer(error);
    }
    if (!response || typeof response.text !== 'function') {
      throw new Error(`The Monero node ${address} answered with something that is not a response.`);
    }
    if (response.url && !sameHost(address, response.url)) {
      throw new Error(`The Monero node ${address} sent this request to another host. That is a different server, so nothing it says is used.`);
    }
    if (!response.ok) {
      throw new Error(`The Monero node ${address} refused the request with status ${response.status}.`);
    }
    let text;
    try {
      text = await response.text();
    } catch (error) {
      throw noAnswer(error);
    }
    let body;
    try {
      body = JSON.parse(text);
    } catch {
      throw new Error(`The Monero node ${address} answered with something that is not JSON. This is a failed read, not a finding about any payment.`);
    }
    if (!body || typeof body !== 'object') {
      throw new Error(`The Monero node ${address} answered with an empty body.`);
    }
    if (body.error) {
      throw new Error(`The Monero node ${address} refused: ${String(body.error.message || body.error).slice(0, 200)}`);
    }
    if (!body.result || typeof body.result !== 'object') {
      throw new Error(`The Monero node ${address} answered without a result.`);
    }
    return { result: body.result, address };
  } finally {
    if (timer) clearTimeout(timer);
  }
}

// What the node says about itself. A node whose chain is behind its own target
// height does not have the block that was asked for, and a node on another
// network is serving a different chain entirely.
export async function getInfo(node, { expectNetwork = 'mainnet', pool = null, env, ...options } = {}) {
  const { result, address } = await call(node, { method: 'get_info' }, { ...options, pool, env });
  const height = Number(result.height);
  const target = Number(result.target_height);
  if (!Number.isInteger(height) || height < 0 || height > MAX_HEIGHT) {
    throw new Error(`The Monero node ${address} reported a chain height this build cannot trust.`);
  }
  if (expectNetwork && result.nettype && String(result.nettype).toLowerCase() !== String(expectNetwork).toLowerCase()) {
    throw new Error(`That Monero node serves ${result.nettype}, not ${expectNetwork}, so its blocks are not this wallet's chain.`);
  }
  if (Number.isInteger(target) && target > height) {
    throw new Error(`The Monero node ${address} is still syncing (${height} of ${target}), so it may not have the block asked for. This is a failed read.`);
  }
  return { address, height, targetHeight: Number.isInteger(target) ? target : null, nettype: result.nettype ?? null };
}

// The daemon's transaction hash list for a block, read from its parsed copy.
// A missing list is a failed read, not an empty block: a block with no list
// the wallet can see is one it cannot scan, so it is refused by name.
function readTxHashes(result, address, claimed) {
  let parsed = result.json;
  if (typeof parsed === 'string') {
    try { parsed = JSON.parse(parsed); } catch {
      throw new Error(`The Monero node ${address} sent a parsed block that is not JSON. This is a failed read.`);
    }
  }
  const list = parsed?.tx_hashes;
  if (!Array.isArray(list) || list.some((h) => !HEX64.test(String(h).toLowerCase()))) {
    throw new Error(`The Monero node ${address} answered without a transaction hash list this build can read.`);
  }
  const hashes = list.map((h) => String(h).toLowerCase());
  if (claimed && claimed.num_txes !== undefined && Number(claimed.num_txes) !== hashes.length) {
    throw new Error(`The Monero node ${address} said the block holds ${claimed.num_txes} transactions and listed ${hashes.length}.`);
  }
  return hashes;
}

// One block, by hash or by height, exactly one of the two.
export async function getBlock(node, { hash, height } = {}, { pool = null, env, ...options } = {}) {
  const byHash = hash !== undefined;
  const byHeight = height !== undefined;
  if (byHash === byHeight) {
    throw new Error('A block is asked for by its hash or by its height, not both and not neither.');
  }
  let params;
  if (byHash) {
    const asked = String(hash).trim().toLowerCase();
    if (!HEX64.test(asked)) throw new Error('A block hash is 64 hex characters.');
    params = { hash: asked };
  } else {
    if (!Number.isInteger(height) || height < 0 || height > MAX_HEIGHT) {
      throw new Error('A block height is a whole number from 0 to 4294967295.');
    }
    params = { height };
  }

  const { result, address } = await call(node, { method: 'get_block', params },
    { ...options, pool, env });

  if (typeof result.blob !== 'string' || !HEX.test(result.blob) || result.blob.length % 2 !== 0 || result.blob.length === 0) {
    throw new Error(`The Monero node ${address} answered without a block blob this build can read.`);
  }
  const blob = hex.decode(result.blob.toLowerCase());

  // The daemon's own claims about its own answer. Cheap to make, cheap to
  // catch, and never a proof: the block's identity is settled by block.js,
  // which proves the id from the bytes themselves. The claims sit at the TOP
  // LEVEL of the answer, in block_header — the daemon's parsed copy rides
  // beside them as a STRING in `json`. The only thing read from `json` is the
  // transaction hash list, a claim checked against num_txes (readTxHashes).
  // This once read `result.json?.block_header`, an object lookup that never
  // fires against the string a real daemon sends, so the check below was dead
  // while its test stayed green; the fix is proven against a real answer
  // pinned in test/fixtures/monero-node-client-block-answer.json.
  const claimed = result.block_header ?? null;
  if (claimed) {
    if (byHash && claimed.hash && String(claimed.hash).toLowerCase() !== params.hash) {
      throw new Error(`The Monero node ${address} said it served ${claimed.hash} when asked for ${params.hash}.`);
    }
    if (byHeight && claimed.height !== undefined && Number(claimed.height) !== height) {
      throw new Error(`The Monero node ${address} said it served height ${claimed.height} when asked for ${height}.`);
    }
  }

  // The transaction hash list rides in the daemon's parsed copy (`json`, an
  // object in the pinned answer, a string in some answers). It is a CLAIM about
  // which transactions the block holds: each entry must be a 64-hex id, and the
  // count must equal the daemon's own num_txes. Nothing here proves an id; a
  // scan that needs a transaction fetches it and proves it from its bytes.
  const claimedTxHashes = readTxHashes(result, address, claimed);

  return {
    blob,
    address,
    askedByHash: byHash ? params.hash : null,
    askedByHeight: byHeight ? height : null,
    claimedHash: claimed?.hash ? String(claimed.hash).toLowerCase() : null,
    claimedHeight: claimed && claimed.height !== undefined ? Number(claimed.height) : null,
    claimedPrevHash: claimed?.prev_hash ? String(claimed.prev_hash).toLowerCase() : null,
    txHashes: claimedTxHashes,
  };
}

// The transaction door. A block names its non-miner transactions by hash only;
// to read their bytes a client asks /get_transactions - the REST door, not the
// json_rpc one, the same distinction the capture scripts make. What comes back
// is treated exactly like a block blob: hex bytes the wallet will parse
// itself, with the node's fields beside them (confirmations, in_pool, ...) as
// unread claims.
//
// Duties this door owes, in the same voice as getBlock:
//   - every requested hash is a 64-hex id, asked in one batch
//   - a hash the node does not carry is named: missed_tx is a refusal, not a
//     partial answer, because a walk that silently drops a transaction proves
//     less than it claims
//   - the answer's status must be OK and every as_hex must be even-length hex
//   - the order of txs is the order of the request: the caller's hash list is
//     the law of the mapping, and a node that reorders is a node that lies
export async function getTransactions(node, hashes, { pool = null, env, ...options } = {}) {
  if (!Array.isArray(hashes) || hashes.length === 0) {
    throw new Error('A transaction fetch asks for at least one 64-hex id.');
  }
  const asked = hashes.map((h) => String(h).trim().toLowerCase());
  for (const h of asked) {
    if (!HEX64.test(h)) throw new Error(`A transaction hash is 64 hex characters, not ${h.slice(0, 80)}`);
  }

  const address = cleanNode(node);
  // Before the socket, exactly as the JSON-RPC door does: a pool that refuses
  // this node must mean the request never leaves, or the refusal is a receipt
  // for a disclosure that already happened. A caller that passed no pool is
  // checked against the wallet's own configuration, not skipped.
  const pinned = poolFor(pool, address, env);
  pinned.assertCurrent(address);
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== 'function') throw new Error('A node call needs a way to fetch.');

  // One POST to the REST door, with the same timeout discipline as call():
  // a node that takes the connection and says nothing is a stall, and a read
  // that never ends is a walk that never proves.
  const controller = options.timeoutSignal ? null : new AbortController();
  const timeoutMs = Number.isFinite(options.timeoutMs) ? options.timeoutMs : 10000;
  let timedOut = false;
  const timer = controller ? setTimeout(() => { timedOut = true; controller.abort(); }, timeoutMs) : null;
  const noAnswer = (error) => (timedOut
    ? new Error(`The Monero node ${address} did not answer within ${timeoutMs} ms. A silent node is a failed read, not a finding about any transaction.`)
    : new Error(`The Monero node ${address} did not answer: ${error?.message || 'no answer'}. This is a failed read, not a finding about any transaction.`));

  try {
    let response;
    try {
      response = await fetchImpl(`http://${address}/get_transactions`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txs_hashes: asked, decode_as_json: false }),
        redirect: 'error',
        signal: options.timeoutSignal ?? controller.signal,
      });
    } catch (error) {
      // The node did not answer at all: it is dead for this wallet, but only
      // for the NEXT scan. Abandoning it here is not a failover - this call
      // still refuses, and nothing is retried on another node inside it. The
      // call is unconditional: a pool without abandon would lose rotation
      // silently, which is the same class of defect as checking after the
      // socket. Both pool builders here provide it.
      pinned.abandon(address);
      throw noAnswer(error);
    }
    if (!response || typeof response.text !== 'function') {
      throw new Error(`The Monero node ${address} answered with something that is not a response.`);
    }
    if (response.url && !sameHost(address, response.url)) {
      throw new Error(`The Monero node ${address} sent this request to another host. That is a different server, so nothing it says is used.`);
    }
    if (!response.ok) {
      throw new Error(`The Monero node ${address} refused the transaction read with status ${response.status}.`);
    }
    let body;
    try {
      body = JSON.parse(await response.text());
    } catch {
      throw new Error(`The Monero node ${address} answered with something that is not JSON. This is a failed read, not a finding about any transaction.`);
    }
    if (body.status && body.status !== 'OK') {
      throw new Error(`The Monero node ${address} said ${String(body.status).slice(0, 60)} instead of OK.`);
    }
    const txs = Array.isArray(body.txs) ? body.txs : [];
    if (txs.length !== asked.length) {
      throw new Error(
        `the count and the list do not agree: ${asked.length} transaction(s) asked, ${txs.length} answered by ${address}`,
      );
    }
    const missed = Array.isArray(body.missed_tx) ? body.missed_tx : [];
    if (missed.length > 0) {
      throw new Error(
        `The Monero node ${address} does not carry ${missed.length} of the asked transaction(s): ${String(missed[0]).slice(0, 66)}. A walk that drops one proves less than it claims.`,
      );
    }
    const bytes = [];
    // The per-tx output_indices, when the daemon serves them: for each transaction,
    // the GLOBAL index of each of its outputs, in the transaction's own order. A
    // wallet needs exactly this to know its own output's absolute position (the
    // number a ring's key_offsets are relative to), which is why upstream wallet2
    // stores it as m_global_output_index straight from this same field.
    //   - in-pool transactions do not have it; an empty list is kept as null rather
    //     than silently mistaken for a real assignment of zero
    const outputIndices = [];
    for (let i = 0; i < txs.length; i += 1) {
      const raw = txs[i].output_indices;
      if (!Array.isArray(raw) || raw.length === 0) {
        outputIndices.push(null);
        continue;
      }
      const indices = [];
      let ok = true;
      for (const value of raw) {
        try { indices.push(BigInt(value)); } catch { ok = false; break; }
      }
      if (!ok || indices.some((v) => v < 0n)) {
        throw new Error(`The Monero node ${address} answered transaction ${i} with output indices that are not whole numbers: ${JSON.stringify(raw).slice(0, 90)}.`);
      }
      outputIndices.push(indices);
    }
    for (let i = 0; i < txs.length; i += 1) {
      const asHex = typeof txs[i].as_hex === 'string' ? txs[i].as_hex.toLowerCase() : '';
      if (!HEX.test(asHex) || asHex.length === 0 || asHex.length % 2 !== 0) {
        throw new Error(`The Monero node ${address} answered transaction ${i} without readable hex bytes.`);
      }
      bytes.push(hex.decode(asHex));
    }
    return { bytes, outputIndices, address, asked };
  } finally {
    if (timer) clearTimeout(timer);
  }
}

// The decoy door. A block names transactions by hash and a transaction names
// its ring by OFFSETS; the ring's own members (a one-time key and a commitment
// per member) are in no transaction at all, so a spender has to ask for them.
// /get_outs is that door, and like the other two it answers with the node's
// claims about outputs the wallet will later have to sign against.
//
// Duties this door owes, in the same voice as getBlock:
//   - every request entry is `{ amount, index }`, both whole and not negative:
//     `amount` is 0 for every RingCT output (the amount lives in the ecdh
//     entry, not in the index key), and `index` is the output's position in
//     that amount's own global list, which is exactly what a transaction's
//     key_offsets are relative to
//   - the answer carries one entry per request, IN REQUEST ORDER: as with
//     getTransactions, the caller's list is the law of the mapping
//   - status must be OK, and every entry must carry a 64-hex key and a 64-hex
//     mask. A key is what a signature signs; a junk key is not a finding
//   - `untrusted` is recorded, not read. It is the daemon saying its own copy
//     is behind or freshly synced, which is a claim about its state, not about
//     these bytes.
export async function getOuts(node, { outputs, getTxid = false } = {}, { pool = null, env, ...options } = {}) {
  if (!Array.isArray(outputs) || outputs.length === 0) {
    throw new Error('An output fetch asks for at least one { amount, index } entry.');
  }
  const asked = outputs.map((entry, i) => {
    const amount = entry?.amount === undefined ? 0n : entry.amount;
    const index = entry?.index;
    for (const [what, value] of [['amount', amount], ['index', index]]) {
      let n;
      try { n = BigInt(value); } catch { throw new Error(`That request entry ${i} has a ${what} that is not a whole number: ${String(value)}.`); }
      if (n < 0n) throw new Error(`That request entry ${i} has a negative ${what}: ${n}.`);
    }
    return { amount: BigInt(amount), index: BigInt(index) };
  });

  const address = cleanNode(node);
  // Before the socket, exactly as the other two doors do. The query carries
  // which outputs a wallet is interested in, so a node that was already
  // abandoned must not receive it.
  const pinned = poolFor(pool, address, env);
  pinned.assertCurrent(address);
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== 'function') throw new Error('A node call needs a way to fetch.');

  const controller = options.timeoutSignal ? null : new AbortController();
  const timeoutMs = Number.isFinite(options.timeoutMs) ? options.timeoutMs : 10000;
  let timedOut = false;
  const timer = controller ? setTimeout(() => { timedOut = true; controller.abort(); }, timeoutMs) : null;
  const noAnswer = (error) => (timedOut
    ? new Error(`The Monero node ${address} did not answer within ${timeoutMs} ms. A silent node is a failed read, not a finding about any output.`)
    : new Error(`The Monero node ${address} did not answer: ${error?.message || 'no answer'}. This is a failed read, not a finding about any output.`));

  try {
    let response;
    try {
      response = await fetchImpl(`http://${address}/get_outs`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          outputs: asked.map((e) => ({ amount: Number(e.amount), index: Number(e.index) })),
          get_txid: getTxid === true,
        }),
        redirect: 'error',
        signal: options.timeoutSignal ?? controller.signal,
      });
    } catch (error) {
      pinned.abandon(address);
      throw noAnswer(error);
    }
    if (!response || typeof response.text !== 'function') {
      throw new Error(`The Monero node ${address} answered with something that is not a response.`);
    }
    if (response.url && !sameHost(address, response.url)) {
      throw new Error(`The Monero node ${address} sent this request to another host. That is a different server, so nothing it says is used.`);
    }
    if (!response.ok) {
      throw new Error(`The Monero node ${address} refused the output read with status ${response.status}.`);
    }
    let body;
    try {
      body = JSON.parse(await response.text());
    } catch {
      throw new Error(`The Monero node ${address} answered with something that is not JSON. This is a failed read, not a finding about any output.`);
    }
    if (body.status && body.status !== 'OK') {
      throw new Error(`The Monero node ${address} said ${String(body.status).slice(0, 60)} instead of OK.`);
    }
    const outs = Array.isArray(body.outs) ? body.outs : null;
    if (outs === null) {
      throw new Error(`The Monero node ${address} answered without an outs list. A ring cannot be built from nothing, and an empty ring must be told apart from a missing one.`);
    }
    if (outs.length !== asked.length) {
      throw new Error(
        `the count and the list do not agree: ${asked.length} output(s) asked, ${outs.length} answered by ${address}`,
      );
    }
    const parsed = [];
    for (let i = 0; i < outs.length; i += 1) {
      const key = String(outs[i]?.key ?? '').trim().toLowerCase();
      const mask = String(outs[i]?.mask ?? '').trim().toLowerCase();
      if (!HEX64.test(key)) {
        throw new Error(`The Monero node ${address} answered output ${i} with a key that is not 64 hex: ${key.slice(0, 70)}.`);
      }
      if (mask !== '' && !HEX64.test(mask)) {
        throw new Error(`The Monero node ${address} answered output ${i} with a mask that is not 64 hex: ${mask.slice(0, 70)}.`);
      }
      const height = outs[i]?.height;
      parsed.push({
        amount: asked[i].amount,
        index: asked[i].index,
        key,
        // Pre-RingCT answers carry no mask; an empty mask is kept empty rather
        // than padded, so a caller cannot mistake "no mask" for a zero one.
        mask: mask === '' ? null : mask,
        height: height === undefined ? null : Number(height),
        unlocked: outs[i]?.unlocked === true,
        txid: typeof outs[i]?.txid === 'string' && outs[i].txid !== '' ? outs[i].txid.toLowerCase() : null,
      });
    }
    return { outs: parsed, address, asked, untrusted: body.untrusted === true };
  } finally {
    if (timer) clearTimeout(timer);
  }
}

// The submit door: hand a transaction to a stranger and ask what it thinks.
//
// This is the only door where the node is not answering with bytes it holds but
// judging bytes the wallet made. Two things follow. First, a refusal has to be
// read rather than thrown blindly: a monerod says `status: "Failed"` with a
// `reason`, and that reason is the most useful sentence in this file's whole
// surface (it is how "the daemon parsed your bytes and disliked the signature"
// is told apart from "the daemon could not parse your bytes at all"). Second,
// nothing here retries: a submission is not idempotent in the wallet's eyes even
// though the daemon deduplicates by id, so the caller gets exactly one answer.
//
// `doNotRelay` is passed through and returned, because a caller building a
// transaction while offline may want the daemon to hold it.
export async function submitTx(node, { txAsHex, doNotRelay = false } = {}, { pool = null, env, ...options } = {}) {
  const hexText = String(txAsHex ?? '').trim().toLowerCase();
  if (hexText.length === 0 || hexText.length % 2 !== 0 || !HEX.test(hexText)) {
    throw new Error('A submitted transaction is even-length hex bytes.');
  }
  const address = cleanNode(node);
  const pinned = poolFor(pool, address, env);
  pinned.assertCurrent(address);
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== 'function') throw new Error('A node call needs a way to fetch.');

  const controller = options.timeoutSignal ? null : new AbortController();
  const timeoutMs = Number.isFinite(options.timeoutMs) ? options.timeoutMs : 20000;
  let timedOut = false;
  const timer = controller ? setTimeout(() => { timedOut = true; controller.abort(); }, timeoutMs) : null;
  const noAnswer = (error) => (timedOut
    ? new Error(`The Monero node ${address} did not answer the submission within ${timeoutMs} ms. The transaction may or may not be in its pool: a submission is the one call whose silence is ambiguous.`)
    : new Error(`The Monero node ${address} did not answer the submission: ${error?.message || 'no answer'}. The transaction may or may not be in its pool.`));

  try {
    let response;
    try {
      response = await fetchImpl(`http://${address}/send_raw_transaction`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ tx_as_hex: hexText, do_not_relay: doNotRelay === true }),
        redirect: 'error',
        signal: options.timeoutSignal ?? controller.signal,
      });
    } catch (error) {
      pinned.abandon(address);
      throw noAnswer(error);
    }
    if (!response || typeof response.text !== 'function') {
      throw new Error(`The Monero node ${address} answered the submission with something that is not a response.`);
    }
    if (response.url && !sameHost(address, response.url)) {
      throw new Error(`The Monero node ${address} sent the submission to another host. That is a different server, so nothing it says is used.`);
    }
    const text = await response.text();
    let body;
    try {
      body = JSON.parse(text);
    } catch {
      // No JSON at all. An empty body with a 2xx is a daemon that took the
      // transaction and said nothing, which is what an older monerod does; any
      // other combination is the HTTP layer failing and is refused.
      if (response.ok && text.trim() === '') return { accepted: true, status: 'OK', reason: '', txid: null, address, doNotRelay: doNotRelay === true, untrusted: false, doubleSpend: false, lowMixin: false };
      throw new Error(`The Monero node ${address} answered the submission with something that is not JSON (status ${response.status}).`);
    }
    if (!response.ok && typeof body.status !== 'string') {
      throw new Error(`The Monero node ${address} refused the submission with status ${response.status}.`);
    }
    const status = typeof body.status === 'string' ? body.status : '';
    const reason = typeof body.reason === 'string' ? body.reason : '';
    const txid = typeof body.tx_hash === 'string' && body.tx_hash !== '' ? body.tx_hash.toLowerCase() : null;
    const accepted = status === 'OK' || (status === '' && txid !== null);
    return {
      accepted,
      status,
      reason,
      txid,
      address,
      doNotRelay: doNotRelay === true,
      // A rejected transaction that still carries a body is the same shape as an
      // accepted one, minus the id; both are returned rather than one thrown, so
      // a caller can print the daemon's own sentence and decide.
      untrusted: body.untrusted === true,
      doubleSpend: body.double_spend === true,
      lowMixin: body.low_mixin === true,
    };
  } finally {
    if (timer) clearTimeout(timer);
  }
}
