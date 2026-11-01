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

import { hex } from '@scure/base';

export const MAX_HEIGHT = 0xffffffff;

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
async function call(node, { method, params }, { fetchImpl = globalThis.fetch, timeoutMs = 10000, timeoutSignal } = {}) {
  if (typeof fetchImpl !== 'function') throw new Error('A node call needs a way to fetch.');
  const address = cleanNode(node);
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
export async function getInfo(node, { expectNetwork = 'mainnet', ...options } = {}) {
  const { result, address } = await call(node, { method: 'get_info' }, options);
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
export async function getBlock(node, { hash, height } = {}, { pool = null, ...options } = {}) {
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

  const { result, address } = await call(node, { method: 'get_block', params }, options);
  if (pool) pool.assertCurrent(node);

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
