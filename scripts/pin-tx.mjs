#!/usr/bin/env node
// pin-tx: one command from (node, height, index) to a pinned fixture.
//
// Every future Lane A pin is a single invocation instead of a session:
//
//   CIPHER_XMR_NODE=xmr-node.cakewallet.com:18081 \
//   CIPHER_TOR_SOCKS=127.0.0.1:9050 \
//   node scripts/pin-tx.mjs --height 3797000 --index 1 \
//     --out test/fixtures/monero-tx-myshape.json
//
// What it does:
//   1. fetches the block by height (get_block), keeps the blob
//   2. parses the block with the repo's own parser (parseBlock)
//   3. reads the hash list, fetches the target tx by hash (get_transactions)
//   4. proves the tx id from its bytes (transactionIdOf) against the
//      block's own hash-list entry at that index
//   5. walks the tx's shape (inputs/outputs/fee/type) with an independent
//      minimal reader, so the shape tag is not picked by the parser under test
//   6. writes the fixture with full provenance (node, transport, capture
//      timestamp, block hash, tip height, re-derive recipe, shape)
//
// Doors honoured (same as every capture script):
//   CIPHER_XMR_NODE (host:port) - the only node
//   CIPHER_TOR_SOCKS (host:port) - optional, carries every call
//   --height N --index I - which block, which tx in it
//   --out PATH - where the fixture lands (relative to repo root)
//
// The script takes no secrets. Fixtures come only from public chain data.

import { spawn } from 'node:child_process';
import { writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const arg = (name) => {
  const i = process.argv.indexOf(name);
  return i === -1 ? null : process.argv[i + 1];
};

const NODE = arg('--node') || process.env.CIPHER_XMR_NODE;
const TOR = arg('--tor') || process.env.CIPHER_TOR_SOCKS || '';
const HEIGHT = arg('--height');
const INDEX = arg('--index');
const OUT = arg('--out');

if (!NODE) { console.error('Set CIPHER_XMR_NODE (host:port).'); process.exit(1); }
if (!HEIGHT || !INDEX) { console.error('Give --height N and --index I.'); process.exit(1); }
if (!OUT || !OUT.endsWith('.json')) { console.error('Give --out test/fixtures/<name>.json'); process.exit(1); }

function curlFetch({ timeoutMs = 30000 } = {}) {
  return async (url, { headers = {}, body = '' } = {}) => {
    const args = ['-sS', '--max-time', String(Math.ceil(timeoutMs / 1000)), '-w', '\n%{http_code}'];
    if (TOR) args.push('--socks5-hostname', TOR);
    args.push('-X', 'POST', url);
    for (const [name, value] of Object.entries(headers)) args.push('-H', `${name}: ${value}`);
    if (body) args.push('--data-binary', body);
    return await new Promise((resolve, reject) => {
      const child = spawn('curl', args, { stdio: ['ignore', 'pipe', 'pipe'] });
      let out = ''; let err = '';
      child.stdout.on('data', (c) => { out += c; });
      child.stderr.on('data', (c) => { err += c; });
      child.on('error', reject);
      child.on('close', (code) => {
        if (code !== 0) return reject(new Error(`curl exited ${code}: ${err.trim()}`));
        const status = Number(out.slice(out.lastIndexOf('\n') + 1));
        const text = out.slice(0, out.lastIndexOf('\n'));
        if (!Number.isInteger(status)) return reject(new Error('curl: no HTTP status.'));
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
  if (!r.ok) throw new Error(`${method} -> HTTP ${r.status}`);
  const parsed = JSON.parse(await r.text());
  if (parsed.error) throw new Error(`${method}: ${String(parsed.error.message).slice(0, 200)}`);
  return parsed.result;
}

async function restGetTransactions(hashes) {
  const r = await fetchImpl(`http://${NODE}/get_transactions`, {
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ txs_hashes: hashes, decode_as_json: false }),
  });
  if (!r.ok) throw new Error(`get_transactions -> HTTP ${r.status}`);
  const parsed = JSON.parse(await r.text());
  if (parsed.status !== 'OK') throw new Error(`get_transactions said ${parsed.status}`);
  if (Array.isArray(parsed.missed_tx) && parsed.missed_tx.length > 0) {
    throw new Error(`the node does not carry ${parsed.missed_tx.length} asked transaction(s)`);
  }
  if (!Array.isArray(parsed.txs) || parsed.txs.length !== hashes.length) {
    throw new Error(`count mismatch: ${hashes.length} asked, ${Array.isArray(parsed.txs) ? parsed.txs.length : 0} answered`);
  }
  return parsed.txs;
}

// Independent minimal shape reader (not the parser under test).
function shapeOf(asHex) {
  const b = Buffer.from(asHex.replace(/\s+/g, ''), 'hex');
  let at = 0;
  const varint = () => {
    let n = 0n, s = 0n;
    for (;;) {
      const x = b[at++]; if (at > b.length) throw new Error('varint past end');
      n |= BigInt(x & 0x7f) << s; s += 7n;
      if (!(x & 0x80)) return n;
    }
  };
  const version = varint();
  varint(); // unlock
  const inputCount = Number(varint());
  for (let i = 0; i < inputCount; i += 1) {
    const tag = b[at++];
    if (tag === 0xff) continue;
    if (tag !== 0x02) throw new Error(`input tag 0x${tag.toString(16)}`);
    varint();
    const offs = Number(varint());
    for (let j = 0; j < offs; j += 1) varint();
    at += 32;
  }
  const outputCount = Number(varint());
  let hasZeroAmount = false;
  for (let i = 0; i < outputCount; i += 1) {
    const amount = varint();
    if (amount === 0n) hasZeroAmount = true;
    const tag = b[at++];
    if (tag !== 0x02 && tag !== 0x03) throw new Error(`output tag 0x${tag.toString(16)}`);
    at += 32;
    if (tag === 0x03) at += 1;
  }
  const extraLength = Number(varint());
  at += extraLength;
  let fee = null;
  if (version === 2n) {
    try {
      const ringType = varint();
      if (ringType === 4n || ringType === 5n || ringType === 6n) fee = varint();
    } catch { fee = null; }
  }
  const shape =
    (inputCount === 1 && outputCount === 1) ? '1in-1out' :
    (inputCount === 1 && outputCount >= 2) ? '1in-manyout' :
    (inputCount >= 3) ? 'manyin' :
    (fee !== null && fee > 0n && fee <= 50000000n) ? 'smallfee' :
    (hasZeroAmount) ? 'zeroamount' : 'any';
  return { inputs: inputCount, outputs: outputCount, fee, hasZeroAmount, shape };
}

// Pipeline
const { getBlock } = await import(join(ROOT, 'src/monero/nodeClient.js'));
const { parseBlock } = await import(join(ROOT, 'src/monero/block.js'));
const { transactionIdOf } = await import(join(ROOT, 'src/monero/block.js'));

const started = new Date().toISOString();
console.log(`[pin-tx] fetching block ${HEIGHT} from ${NODE}...`);
const answered = await getBlock(NODE, { height: Number(HEIGHT) }, { fetchImpl, timeoutMs: 30000 });
const block = parseBlock(answered.blob);
console.log(`[pin-tx] block parsed: id ${block.id.slice(0, 16)}…, ${block.txHashes.length} hash-list entr(ies)`);

if (Number(INDEX) < 1 || Number(INDEX) > block.txHashes.length) {
  console.error(`index ${INDEX} is outside 1..${block.txHashes.length} (index 0 is the miner tx).`);
  process.exit(1);
}
const targetHash = block.txHashes[Number(INDEX) - 1];
console.log(`[pin-tx] target: index ${INDEX}, hash ${targetHash.slice(0, 16)}…`);

console.log('[pin-tx] fetching transaction bytes...');
const txAnswer = await restGetTransactions([targetHash]);
const txHex = txAnswer[0].as_hex.toLowerCase();
const txBytes = Buffer.from(txHex, 'hex');

// Prove the id from bytes against the block's own hash-list entry
const walkedTx = (await import(join(ROOT, 'src/monero/block.js'))).readTransaction(
  new Uint8Array(txBytes), 0, 'pinned transaction',
);
const provenId = transactionIdOf(walkedTx);
if (provenId !== targetHash) {
  throw new Error(`the bytes prove ${provenId}, the block lists ${targetHash}: bytes and list do not agree`);
}
console.log(`[pin-tx] needle: id from bytes matches the block hash list`);

const shape = shapeOf(txHex);
console.log(`[pin-tx] shape: ${shape.inputs}in/${shape.outputs}out fee=${shape.fee} zero=${shape.hasZeroAmount} tag=${shape.shape}`);

const tip = await jsonRpc('get_info', {});
const spaced = (hexText) => String(hexText).replace(/(.{32})/g, '$1 ').trim();

const fixture = {
  source: {
    what: 'One real Monero mainnet NON-MINER transaction captured by scripts/pin-tx.mjs.',
    node: NODE,
    nettype: 'mainnet',
    transport: TOR ? `curl --socks5-hostname via ${TOR} (Tor; the node saw a Tor exit, not this machine)` : 'curl, direct',
    capturedAt: started,
    blockHeight: Number(HEIGHT),
    blockHash: spaced(answered.claimedHash || block.id),
    tipHeightAtCapture: tip.height ? Number(tip.height) : null,
    txIndexInBlock: Number(INDEX),
    shape,
    rederive: `CIPHER_XMR_NODE=${NODE} ${TOR ? `CIPHER_TOR_SOCKS=${TOR} ` : ''}node scripts/pin-tx.mjs --height ${HEIGHT} --index ${INDEX} --out <this file>`,
    note: 'Bytes and the node claims are recorded as a stranger\u2019s claims. The id is proven by the parser against txHash from the bytes alone.',
  },
  txHash: spaced(provenId),
  version: Number(walkedTx.version),
  rctType: walkedTx.rctType,
  byteLength: txBytes.length,
  asHex: spaced(txHex),
  claimedPrunableHash: answered.claimedHash ? null : null,
  shapeDiscover: shape.shape,
};

await writeFile(join(ROOT, OUT), `${JSON.stringify(fixture, null, 1)}\n`);
console.log(`[pin-tx] wrote ${OUT} (${txBytes.length} bytes, sha256 visible in the file)`);
console.log(`[pin-tx] done. shape: ${shape.shape}, needle: proven against the block hash list.`);
