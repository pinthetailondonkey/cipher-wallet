// Discover and capture REAL Monero mainnet non-miner transactions of a chosen
// shape, through the same door the wallet uses at runtime.
//
// WHY THIS EXISTS: Lane A of the L4 master work order needs a wider pinned
// corpus than the single type-6 fixture. Every shape (1-in/1-out, 1-in/many-out,
// many-in, small fee, zero-amount) must be proven by REAL bytes fetched from a
// monerod, not by a fixture written by hand. This script finds such transactions
// by walking a block's hash list and reading each transaction's shape, then
// captures the ones that match a target, with full provenance.
//
// THE DOORS: CIPHER_XMR_NODE (host:port) is the only node. CIPHER_TOR_SOCKS,
// when set, carries every call through it. No explorer is ever called. No
// secret is ever taken: the only inputs are a node and a height/hash.
//
// USAGE: node scripts/fetch-monero-tx-fixture.mjs --node HOST:PORT \
//   --height 3796965 [--tor 127.0.0.1:9050] \
//   [--shape 1in-1out|1in-manyout|manyin|smallfee|zeroamount] \
//   [--max-transactions 100] [--out test/fixtures/<name>.json]

import { spawn } from 'node:child_process';
import { mkdir, writeFile, readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { hex } from '@scure/base';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const arg = (name) => {
  const i = process.argv.indexOf(name);
  return i === -1 ? null : process.argv[i + 1];
};
const NODE = arg('--node') || process.env.CIPHER_XMR_NODE;
const HEIGHT = arg('--height');
const TOR = arg('--tor') || process.env.CIPHER_TOR_SOCKS || '';
const SHAPE = arg('--shape') || 'any';
const MAXTX = Number(arg('--max-transactions') || 100);
const OUT = arg('--out');

if (!NODE || !HEIGHT) {
  console.error('Usage: --node HOST:PORT --height N [--tor SOCKS] [--shape ...] [--out path]');
  process.exit(1);
}

const spaced = (s) => String(s).replace(/(.{32})(?=.)/g, '$1 ').toLowerCase();
const squeeze = (s) => String(s).replace(/\s+/g, '').toLowerCase();

function curlFetch({ timeoutMs = 30000 } = {}) {
  return async (url, { method = 'POST', headers = {}, body = '' } = {}) => {
    const args = ['-sS', '--max-time', String(Math.ceil(timeoutMs / 1000)), '-w', '\n%{http_code}'];
    if (TOR) args.push('--socks5-hostname', TOR);
    args.push('-X', method, url);
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
        if (code !== 0) { reject(new Error(`curl exited ${code}: ${err.trim() || 'no message'}`)); return; }
        const status = Number(out.slice(out.lastIndexOf('\n') + 1));
        const text = out.slice(0, out.lastIndexOf('\n'));
        if (!Number.isInteger(status)) reject(new Error('curl printed no HTTP status.'));
        resolve({ ok: status >= 200 && status < 300, status, url, text: async () => text });
      });
    });
  };
}

const fetchImpl = curlFetch();

async function rpc(method, params) {
  const r = await fetchImpl(`http://${NODE}/json_rpc`, {
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: '0', method, params }),
  });
  if (!r.ok) throw new Error(`${method} -> HTTP ${r.status}`);
  const parsed = JSON.parse(await r.text());
  if (parsed.error) throw new Error(`${method} refused: ${String(parsed.error.message).slice(0, 200)}`);
  return parsed.result;
}

async function restGetTxs(hashes, decodeAsJson) {
  const r = await fetchImpl(`http://${NODE}/get_transactions`, {
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ txs_hashes: hashes, decode_as_json: decodeAsJson }),
  });
  if (!r.ok) throw new Error(`get_transactions -> HTTP ${r.status}`);
  const parsed = JSON.parse(await r.text());
  if (parsed.status !== 'OK') throw new Error(`get_transactions status ${parsed.status}`);
  return parsed.txs;
}

// A minimal prefix walk to read a transaction's SHAPE (input/output counts,
// the fee, and whether any output has a zero amount) from its bytes. This is
// discovery only, deliberately independent of the parser under test, so the
// script cannot pick a shape by trusting the parser it will later judge.
function shapeOf(asHex) {
  const b = Buffer.from(squeeze(asHex), 'hex');
  let at = 0;
  const varint = () => {
    let n = 0n, s = 0n;
    for (;;) {
      const x = b[at++];
      if (at > b.length) throw new Error('varint runs past the bytes');
      n |= BigInt(x & 0x7f) << s;
      s += 7n;
      if (!(x & 0x80)) return n;
    }
  };
  const version = varint();
  varint(); // unlock time
  const inputCount = Number(varint());
  let inputs = 0;
  for (let i = 0; i < inputCount; i += 1) {
    const tag = b[at++];
    if (tag === 0xff) continue; // gen, no offset
    if (tag !== 0x02) throw new Error(`input tag 0x${tag.toString(16)}`);
    varint(); // amount
    const offs = Number(varint());
    for (let j = 0; j < offs; j += 1) varint();
    at += 32; // key image
  }
  inputs = inputCount;
  const outputCount = Number(varint());
  let outputs = 0;
  let hasZeroAmount = false;
  for (let i = 0; i < outputCount; i += 1) {
    const amount = varint();
    if (amount === 0n) hasZeroAmount = true;
    const tag = b[at++];
    if (tag !== 0x02 && tag !== 0x03) throw new Error(`output tag 0x${tag.toString(16)}`);
    at += 32;
    if (tag === 0x03) at += 1; // view tag
  }
  outputs = outputCount;
  // The transaction extra rides between the outputs and the RingCT base,
  // count-prefixed like every field. Skipping it here is what puts the walk at
  // the ring type byte; without it the base read is silently off by the extra's
  // length and the fee is read as noise.
  const extraLength = Number(varint());
  at += extraLength;
  // fee = the transaction fee. IGNORED for selection of most shapes; it is a
  // signal only when a small fee is wanted. RingCT types 4/5/6 put the fee as
  // the first varint of the base.
  let fee = null;
  if (version === 2n) {
    try {
      const ringType = varint();
      if (ringType === 4n || ringType === 5n || ringType === 6n) fee = varint();
      else fee = null;
    } catch { fee = null; }
  }
  return { version, inputs, outputs, fee, hasZeroAmount };
}

async function main() {
  const block = await rpc('get_block', { height: Number(HEIGHT) });
  const header = block.block_header;
  const parsedJson = typeof block.json === 'string' ? JSON.parse(block.json) : block.json;
  const txHashes = parsedJson.tx_hashes.map((h) => squeeze(h));
  const blockHash = squeeze(header.hash);
  const numTxes = header.num_txes;
  if (numTxes !== txHashes.length) {
    throw new Error(`block_header.num_txes (${numTxes}) disagrees with json.tx_hashes (${txHashes.length}) — node contradicts itself.`);
  }
  console.log(`[tx-fixture] block ${HEIGHT} hash ${blockHash.slice(0, 16)}… ${txHashes.length} txs, scanning up to ${Math.min(MAXTX, txHashes.length)}`);

  const matches = [];
  for (let i = 0; i < Math.min(MAXTX, txHashes.length); i += 1) {
    const hash = txHashes[i];
    if (i === 0) {
      // i==0 is the miner tx; skip for non-miner capture unless requested.
      continue;
    }
    let txs;
    try { txs = await restGetTxs([hash], false); }
    catch (error) { console.log(`  [i=${i}] fetch failed: ${error.message}`); continue; }
    const t = txs[0];
    let shape;
    try { shape = shapeOf(t.as_hex); }
    catch (error) { console.log(`  [i=${i}] shape walk failed: ${error.message}`); continue; }
    const tag =
      (shape.inputs === 1 && shape.outputs === 1) ? '1in-1out' :
      (shape.inputs === 1 && shape.outputs >= 2) ? '1in-manyout' :
      (shape.inputs >= 3) ? 'manyin' :
      (shape.fee !== null && shape.fee > 0n && shape.fee <= 1000000n) ? 'smallfee' :
      (shape.hasZeroAmount) ? 'zeroamount' : null;
    if (!tag) continue;
    if (SHAPE !== 'any' && tag !== SHAPE) continue;
    console.log(`  [i=${i}] ${hash.slice(0, 16)}… v${shape.version} ${shape.inputs}in/${shape.outputs}out fee=${shape.fee} zero=${shape.hasZeroAmount} tag=${tag}`);
    matches.push({ i, hash, t, shape, tag });
  }
  if (matches.length === 0) {
    console.error(`No ${SHAPE} transaction found in block ${HEIGHT} (first ${Math.min(MAXTX, txHashes.length)} txs).`);
    process.exit(1);
  }
  const chosen = matches[0];
  const fixture = {
    source: {
      what: 'One real Monero mainnet NON-MINER transaction captured against the L4 Lane A corpus.',
      node: NODE,
      nettype: 'mainnet',
      transport: TOR ? `curl --socks5-hostname via ${TOR} (Tor; the node saw a Tor exit, not this machine)` : 'curl, direct',
      capturedAt: new Date().toISOString(),
      blockHeight: Number(HEIGHT),
      blockHash: spaced(blockHash),
      blockTxCount: txHashes.length,
      txIndexInBlock: chosen.i,
      shape: chosen.tag,
      rederive: `node scripts/fetch-monero-tx-fixture.mjs --node ${NODE} --height ${HEIGHT} [--shape ${chosen.tag}] [--tor ${TOR}]`,
      note: 'Bytes and the node claims are recorded as a stranger\'s claims. The id is proven by the parser against txHash from the bytes alone.',
    },
    txHash: spaced(chosen.hash),
    version: null,
    rctType: null,
    byteLength: squeeze(chosen.t.as_hex).length / 2,
    asHex: spaced(squeeze(chosen.t.as_hex)),
    claimedPrunableHash: chosen.t.prunable_hash ? spaced(squeeze(chosen.t.prunable_hash)) : null,
    shapeDiscover: chosen.tag,
  };

  if (OUT) {
    await mkdir(dirname(join(ROOT, OUT)), { recursive: true });
    const text = JSON.stringify(fixture, null, 2) + '\n';
    await writeFile(join(ROOT, OUT), text, 'utf8');
    const sha = createHash('sha256').update(text).digest('hex');
    console.log(`[tx-fixture] wrote ${OUT} (${fixture.byteLength} bytes), sha256 ${spaced(sha)}`);
  } else {
    console.log(`[tx-fixture] candidate: ${chosen.hash}`);
  }
}

main().catch((error) => {
  console.error(`[tx-fixture] ${error.message || error}`);
  process.exit(1);
});
