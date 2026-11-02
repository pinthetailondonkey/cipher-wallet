// The live chain walk: one real block, fetched from one real monerod over
// Tor, walked end to end through the proven pipeline. LANE B's close.
//
//   getBlock (json_rpc, blob kept, claims recorded) ->
//   parseBlock (id + hash list + tree root proven from bytes) ->
//   getTransactions (the block's own hash list, REST door) ->
//   walkBlockTxs (every tx id proven from its bytes; root re-proven)
//
// What lands in the fixture is the WHOLE transcript: the block bytes, every
// transaction's bytes as the node sent them, the computed ids, the computed
// root, the node's claims labelled as claims, and the full provenance block.
// A later test re-runs the walk on the pinned bytes and must reproduce every
// id and the root without asking any node anything.
//
// Doors honoured (same law as the other capture scripts):
//   CIPHER_XMR_NODE - the only node, by host:port. Nothing discovers a node.
//   CIPHER_TOR_SOCKS - optional host:port; set, every call rides it.
//   --height N (or --hash H) - which block. Nothing else is taken in.
//
//   CIPHER_XMR_NODE=xmr-node.cakewallet.com:18081 \
//   CIPHER_TOR_SOCKS=127.0.0.1:9050 \
//   node scripts/fetch-monero-live-walk.mjs --height 3796965 \
//     --out test/fixtures/monero-live-walk-3796965.json

import { spawn } from 'node:child_process';
import { writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { hex } from '@scure/base';
import { keccak_256 } from '@noble/hashes/sha3.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const arg = (name) => {
  const i = process.argv.indexOf(name);
  return i === -1 ? null : process.argv[i + 1];
};
const NODE = arg('--node') || process.env.CIPHER_XMR_NODE;
const TOR = arg('--tor') || process.env.CIPHER_TOR_SOCKS || '';
const HEIGHT = arg('--height');
const HASH = arg('--hash');
const OUT = arg('--out') || join(ROOT, 'test/fixtures/monero-live-walk.json');

if (!NODE) {
  console.error('No node. Set CIPHER_XMR_NODE (host:port). Nothing else picks a node.');
  process.exit(1);
}
if (!HEIGHT && !HASH) {
  console.error('Give --height N or --hash H. The walk pins one block.');
  process.exit(1);
}

// Tor's SOCKS is the one thing node's fetch cannot speak; curl is named here,
// in prose, the way the other capture scripts name it.
function curlFetch({ timeoutMs = 30000 } = {}) {
  return async (url, { headers = {}, body = '' } = {}) => {
    const args = ['-sS', '--max-time', String(Math.ceil(timeoutMs / 1000)), '-w', '\n%{http_code}'];
    if (TOR) args.push('--socks5-hostname', TOR);
    args.push('-X', 'POST', url);
    for (const [name, value] of Object.entries(headers)) args.push('-H', `${name}: ${value}`);
    if (body) args.push('--data-binary', body);
    return await new Promise((resolve, reject) => {
      const child = spawn('curl', args, { stdio: ['ignore', 'pipe', 'pipe'] });
      let out = '';
      let err = '';
      child.stdout.on('data', (c) => { out += c; });
      child.stderr.on('data', (c) => { err += c; });
      child.on('error', reject);
      child.on('close', (code) => {
        if (code !== 0) return reject(new Error(`curl exited ${code}: ${err.trim() || 'no message'}`));
        const status = Number(out.slice(out.lastIndexOf('\n') + 1));
        const text = out.slice(0, out.lastIndexOf('\n'));
        if (!Number.isInteger(status)) return reject(new Error('curl printed no HTTP status.'));
        resolve({ ok: status >= 200 && status < 300, status, url, text: async () => text });
      });
    });
  };
}
const fetchImpl = curlFetch();

async function jsonRpc(method, params) {
  const r = await fetchImpl(`http://${NODE}/json_rpc`, {
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: '0', method, params }),
  });
  if (!r.ok) throw new Error(`${method} -> HTTP ${r.status}. A failed capture, not a finding.`);
  const parsed = JSON.parse(await r.text());
  if (parsed.error) throw new Error(`${method} refused: ${String(parsed.error.message).slice(0, 200)}`);
  return parsed.result;
}

async function restGetTransactions(hashes) {
  const r = await fetchImpl(`http://${NODE}/get_transactions`, {
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ txs_hashes: hashes, decode_as_json: false }),
  });
  if (!r.ok) throw new Error(`get_transactions -> HTTP ${r.status}.`);
  const parsed = JSON.parse(await r.text());
  if (parsed.status && parsed.status !== 'OK') throw new Error(`get_transactions said ${parsed.status}.`);
  if (Array.isArray(parsed.missed_tx) && parsed.missed_tx.length > 0) {
    throw new Error(`the node does not carry ${parsed.missed_tx.length} of the asked transactions.`);
  }
  if (!Array.isArray(parsed.txs) || parsed.txs.length !== hashes.length) {
    throw new Error(`the count and the list do not agree: ${hashes.length} asked, ${Array.isArray(parsed.txs) ? parsed.txs.length : 0} answered.`);
  }
  return parsed.txs.map((t) => t.as_hex);
}

// The pipeline, imported from the same modules the wallet runs. Nothing here
// re-implements a check the modules already own.
const { getBlock } = await import(join(ROOT, 'src/monero/nodeClient.js'));
const { parseBlock } = await import(join(ROOT, 'src/monero/block.js'));
const { walkBlockTxs } = await import(join(ROOT, 'src/monero/blockWalk.js'));

const asked = HEIGHT ? { height: Number(HEIGHT) } : { hash: String(HASH).toLowerCase() };
const started = new Date().toISOString();
console.log(`[live-walk] asking ${NODE} for block ${HEIGHT ? `at height ${HEIGHT}` : `by hash`} ...`);
const answered = await getBlock(NODE, asked, { fetchImpl, timeoutMs: 30000 });
const blobHex = hex.encode(answered.blob);

const block = parseBlock(answered.blob);
console.log(`[live-walk] parsed: id ${block.id.slice(0, 16)}… ${block.txHashes.length} hash-list entr(ies)`);
if (answered.claimedHash && answered.claimedHash !== block.id) {
  throw new Error(`the node claimed ${answered.claimedHash} but the bytes prove ${block.id}: a node lie, caught.`);
}

const txHex = await restGetTransactions(block.txHashes);
console.log(`[live-walk] fetched ${txHex.length} transaction answer(s)`);

const txBytesList = txHex.map((h) => hex.decode(h.toLowerCase()));
const walk = walkBlockTxs(block, txBytesList);
console.log(`[live-walk] 33/33-style proof: ${walk.ids.length} id(s) from bytes match the list; root matches`);
console.log(`[live-walk] tree root ${walk.txTreeRoot.slice(0, 16)}…`);

const spaced = (hexText) => String(hexText).replace(/(.{32})/g, '$1 ').trim();
const fixture = {
  source: {
    what: 'One live chain walk: a real block fetched from a monerod over Tor, walked end to end through the proven pipeline (getBlock -> parseBlock -> getTransactions -> walkBlockTxs).',
    node: NODE,
    nettype: 'mainnet',
    transport: TOR ? `curl --socks5-hostname via ${TOR} (Tor; the node saw a Tor exit, not this machine)` : 'curl, direct',
    capturedAt: started,
    finishedAt: new Date().toISOString(),
    askedBy: HEIGHT ? { height: Number(HEIGHT) } : { hash: String(HASH).toLowerCase() },
    rederive: `CIPHER_XMR_NODE=${NODE} ${TOR ? `CIPHER_TOR_SOCKS=${TOR} ` : ''}node scripts/fetch-monero-live-walk.mjs --height ${HEIGHT ?? `<height of ${HASH}>`} --out <this file>`,
    note: 'The node is a stranger and its claims are recorded as claims. Every id below is computed from bytes by the repo parser; claimedHash is what the node said and was cross-checked once, by the capture, against the proven id.',
  },
  block: {
    heightAnswered: answered.claimedHeight,
    provenId: spaced(block.id),
    claimedHash: answered.claimedHash ? spaced(answered.claimedHash) : null,
    txCount: block.txHashes.length,
    txTreeRoot: spaced(block.txTreeRoot),
    blob: spaced(blobHex),
  },
  txs: txHex.map((h, i) => ({
    indexInBlock: i + 1,
    provenId: spaced(walk.ids[i]),
    byteLength: txBytesList[i].length,
    asHex: spaced(h.toLowerCase()),
  })),
  walk: {
    idsAllProven: true,
    txTreeRoot: spaced(walk.txTreeRoot),
    rootMatchesBlock: walk.txTreeRoot === block.txTreeRoot,
  },
};

await writeFile(OUT, `${JSON.stringify(fixture, null, 1)}\n`);
console.log(`[live-walk] wrote ${OUT}`);
console.log(`[live-walk] tx count ${fixture.txs.length}, root ${walk.txTreeRoot.slice(0, 24)}…`);
