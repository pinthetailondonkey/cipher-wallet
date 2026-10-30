// Capture one real Monero block for the pinned fixture, through the same door
// the wallet itself uses at runtime.
//
// WHY THIS EXISTS: the block reader's first body model was written by the same
// hand as its fixtures, so a green suite proved nothing (block.js, F1/F2). The
// only cure is a (bytes, id) pair from Monero's own output — a monerod's
// get_block answer — pinned into test/fixtures the way every other vector in
// this repository is pinned: named source, re-derivation recipe, checksums.
//
// THE DOORS THIS SCRIPT HONOURS:
//   - CIPHER_XMR_NODE is the only node. No list is consulted, no node is
//     discovered, and every call this script makes goes to that one node.
//   - CIPHER_TOR_SOCKS, when set (host:port), carries every call through that
//     SOCKS proxy so the node never learns this machine's address. Unset, the
//     call goes direct — the same allowance typing an override always is.
//   - No block explorer is called, ever. A monerod speaks the protocol the
//     wallet speaks; an explorer is a different thing and is not one.
//
// WHAT IT CAPTURES, AND WHY EACH CLAIM IS RECORDED: one block by height (with a
// small transaction count so the fixture stays readable) and its parent. The
// parent is fetched for one check only: the child's header must name the
// parent's id — Monero's own chain rule — so a fabricated pair has to be a
// valid chain segment, not just a blob that agrees with itself. The byte-level
// proof (our parser's id for the pinned bytes) belongs to the test, not here.
//
// HOW TO RE-DERIVE (this is also how the fixture was first captured):
//   CIPHER_XMR_NODE=xmr-node.cakewallet.com:18081 \
//   CIPHER_TOR_SOCKS=127.0.0.1:9050 \
//   node scripts/fetch-monero-block-fixture.mjs --height <height> [--out test/fixtures/<name>.json]
// Without --height it walks back from the node's tip until it finds a block
// with 1..6 transactions, so the fixture pins a count section that is exercised
// but not enormous. --out names a different fixture file (relative to the
// repository root) for a second pair; the default stays the first fixture.

import { spawn } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { getBlock, getInfo } from '../src/monero/nodeClient.js';
import { parseBlockHeader } from '../src/monero/block.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const outArg = process.argv.includes('--out') ? process.argv[process.argv.indexOf('--out') + 1] : null;
if (outArg !== null && (!outArg.endsWith('.json') || outArg.includes('..'))) {
  console.error('--out is a .json path relative to the repository root.');
  process.exit(1);
}
const OUT = outArg !== null ? join(ROOT, outArg) : join(ROOT, 'test/fixtures/monero-block-mainnet.json');

const NODE = process.env.CIPHER_XMR_NODE;
if (!NODE) {
  console.error('No node. Set CIPHER_XMR_NODE (host:port) — the same override door the wallet uses. Nothing else picks a node.');
  process.exit(1);
}
const TOR = process.env.CIPHER_TOR_SOCKS || '';

// One JSON-RPC POST, carried by curl. Tor's SOCKS is the one thing node's
// built-in fetch cannot speak, and this script adds no dependency for it: curl
// is named here, in prose, in the file whose whole job is honesty about where
// bytes came from. The last stdout line is the HTTP status, so the caller sees
// refusals the same way node's fetch would report them.
function curlFetch({ timeoutMs = 25000 } = {}) {
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
      child.stdout.on('data', (chunk) => { out += chunk; });
      child.stderr.on('data', (chunk) => { err += chunk; });
      child.on('error', reject);
      child.on('close', (code) => {
        if (code !== 0) {
          reject(new Error(`curl exited ${code}: ${err.trim() || 'no message'}`));
          return;
        }
        const status = Number(out.slice(out.lastIndexOf('\n') + 1));
        const text = out.slice(0, out.lastIndexOf('\n'));
        if (!Number.isInteger(status)) {
          reject(new Error(`curl printed no HTTP status. This is a failed capture, not a finding.`));
          return;
        }
        // nodeClient treats its fetchImpl like the platform's fetch: it awaits
        // response.text() as a method and checks response.url for redirects.
        resolve({ ok: status >= 200 && status < 300, status, url, text: async () => text });
      });
    });
  };
}

const fetchImpl = curlFetch();

// The raw call this script makes for the fields the wallet's own door does not
// return (the daemon's version, the transaction-hash list, the parsed block
// header). monerod answers get_block with `json` as a STRING that must be
// parsed; this is the same answer nodeClient.getBlock checks, read once more
// for the capture.
async function rawCall(method, params) {
  const response = await fetchImpl(`http://${NODE}/json_rpc`, {
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: '0', method, params }),
  });
  if (!response.ok) throw new Error(`The node refused ${method} with status ${response.status}. This is a failed capture.`);
  const parsed = JSON.parse(await response.text());
  if (parsed.error) throw new Error(`The node refused ${method}: ${String(parsed.error.message).slice(0, 200)}`);
  return parsed.result;
}

// The pre-commit hook refuses a bare 64-hex-character run on any line, because
// that is what a leaked key looks like. The fixtures' settled policy (founder
// ruling 2026-10-29) is a space every 32 hex characters, recorded in
// test/fixtures/README.md. The test strips whitespace before use.
const spaced = (hexText) => String(hexText).replace(/(.{32})/g, '$1 ').trim();

async function captureAtHeight(height) {
  const raw = await rawCall('get_block', { height });
  const blobHex = String(raw.blob || '').toLowerCase();
  if (!/^[0-9a-f]*$/.test(blobHex) || blobHex.length === 0 || blobHex.length % 2 !== 0) {
    throw new Error(`The node answered height ${height} without a block blob this script can read.`);
  }
  let parsedJson;
  try {
    parsedJson = typeof raw.json === 'string' ? JSON.parse(raw.json) : raw.json;
  } catch {
    throw new Error(`The node's parsed-block answer at height ${height} is not JSON. This is a failed capture.`);
  }
  // monerod's shape: `result.block_header` carries the claims (hash, height,
  // prev_hash, versions), while the parsed `result.json` block repeats the
  // wire fields (prev_id, miner_tx, tx_hashes). Two fields in one answer name
  // the same parent; they are cross-checked so a capture cannot pin a
  // self-inconsistent claim.
  const header = raw?.block_header ?? parsedJson?.block_header ?? null;
  if (!header || !header.hash) {
    throw new Error(`The node's answer at height ${height} carries no block header claim to record.`);
  }
  const wirePrevId = String(parsedJson?.prev_id ?? header.prev_hash ?? '').toLowerCase();
  if (wirePrevId !== String(header.prev_hash ?? '').toLowerCase()) {
    throw new Error(`The node's answer at height ${height} names two different parents (${wirePrevId} in the wire block, ${header.prev_hash} in its header). This is a failed capture.`);
  }
  const txHashes = parsedJson?.tx_hashes ?? [];
  if (!Array.isArray(txHashes) || txHashes.some((h) => !/^[0-9a-fA-F]{64}$/.test(String(h)))) {
    throw new Error(`The node's transaction-hash list at height ${height} is not a list of 64-hex ids.`);
  }
  return { height, blobHex, header, txHashes };
}

async function main() {
  const argHeight = process.argv.includes('--height')
    ? Number(process.argv[process.argv.indexOf('--height') + 1])
    : null;
  if (argHeight !== null && (!Number.isInteger(argHeight) || argHeight < 0)) {
    console.error('--height is a whole number from zero.');
    process.exit(1);
  }

  // The wallet's own door enforces what it always enforces: one node, named
  // network, not still syncing. The raw capture reads the same node right
  // after, and the two must agree, byte for byte, below.
  const info = await getInfo(NODE, { fetchImpl });
  const rawInfo = await rawCall('get_info', {});
  console.log(`[fixture] node ${info.address} nettype ${rawInfo.nettype} version ${rawInfo.version} tip ${rawInfo.height} (target ${info.targetHeight})`);
  if (String(rawInfo.nettype).toLowerCase() !== 'mainnet') {
    console.error('This capture is for the mainnet fixture. A stagenet pair would pin the format but not this wallet\'s chain.');
    process.exit(1);
  }

  let chosen = null;
  const startHeight = argHeight ?? rawInfo.height - 2;
  for (let height = startHeight; height >= Math.max(0, startHeight - 200) && !chosen; height -= 1) {
    const candidate = await captureAtHeight(height);
    const txCount = candidate.txHashes.length;
    console.log(`[fixture] height ${height}: ${txCount} transaction${txCount === 1 ? '' : 's'} beside the miner transaction`);
    if (argHeight !== null) { chosen = candidate; break; } // an explicit height is pinned as asked, whatever its size
    if (txCount >= 1 && txCount <= 6) chosen = candidate;
  }
  if (!chosen) {
    console.error(`No block with 1..6 transactions within 200 heights below ${startHeight}. Pass --height to pin a specific block.`);
    process.exit(1);
  }

  // The parent: only for the chain-linkage claim the fixture records.
  const parent = await captureAtHeight(chosen.height - 1);

  // The wallet's own door, read once more so the pinned bytes are the bytes
  // the product's reader accepts, not just what a capture script liked.
  const viaDoor = await getBlock(NODE, { height: chosen.height }, { fetchImpl });
  if (Buffer.from(viaDoor.blob).toString('hex') !== chosen.blobHex) {
    throw new Error(`The node served a different blob to the wallet's own reader than to this capture. This is a failed capture, not a fixture.`);
  }
  const viaDoorParent = await getBlock(NODE, { height: parent.height }, { fetchImpl });

  // The header of the pinned blob names the parent's id: Monero's own chain
  // rule, checked with the header reader that already shipped.
  const header = parseBlockHeader(Uint8Array.from(Buffer.from(chosen.blobHex, 'hex')));
  if (header.prevId !== parent.header.hash.toLowerCase()) {
    throw new Error(`The blob's header names ${header.prevId} as its parent, but the node says height ${parent.height} is ${parent.header.hash.toLowerCase()}. This is a failed capture, not a fixture.`);
  }

  const fixture = {
    source: {
      what: 'One real Monero mainnet block, as a monerod served it over json_rpc get_block.',
      node: info.address,
      // Some nodes answer get_info with no version string at all. An empty
      // field would read like a capture gap, so the script records the node's
      // own silence in words — the fallback is written here, not by a hand
      // touching the fixture after capture.
      daemonVersion: String(rawInfo.version || 'the node answered get_info with no version string'),
      nettype: rawInfo.nettype,
      tipHeightAtCapture: rawInfo.height,
      capturedAt: new Date().toISOString(),
      transport: TOR ? `curl --socks5-hostname via ${TOR} (Tor; the node saw a Tor exit, not this machine)` : 'curl, direct',
      rederive: 'CIPHER_XMR_NODE=<node:port> CIPHER_TOR_SOCKS=127.0.0.1:9050 node scripts/fetch-monero-block-fixture.mjs --height <height>',
      note: 'The node is a stranger\'s server and its claims are recorded as claims. What the fixture pins is the bytes; the id and the chain link are proven by this repository\'s own parser in test/monero-block.test.mjs, against the id recorded here.',
    },
    block: {
      height: chosen.height,
      majorVersion: chosen.header.major_version,
      minorVersion: chosen.header.minor_version,
      claimedId: spaced(chosen.header.hash.toLowerCase()),
      claimedPrevId: spaced(chosen.header.prev_hash.toLowerCase()),
      claimedMinerTxId: chosen.header.miner_tx_hash ? spaced(String(chosen.header.miner_tx_hash).toLowerCase()) : '',
      claimedTxHashes: chosen.txHashes.map((h) => spaced(String(h).toLowerCase())),
      blob: spaced(chosen.blobHex),
    },
    parent: {
      height: parent.height,
      claimedId: spaced(parent.header.hash.toLowerCase()),
      note: 'The child blob\'s header must name this id — checked at capture and re-proven by the test.',
      doorReplay: {
        childBlobHexLength: chosen.blobHex.length / 2,
        childServedTwice: Buffer.from(viaDoor.blob).toString('hex') === chosen.blobHex,
        parentServedTwice: Buffer.from(viaDoorParent.blob).toString('hex') === parent.blobHex ? undefined : false,
      },
    },
  };

  await mkdir(dirname(OUT), { recursive: true });
  const text = JSON.stringify(fixture, null, 2) + '\n';
  await writeFile(OUT, text, 'utf8');
  const sha256 = createHash('sha256').update(text).digest('hex');
  console.log(`[fixture] wrote ${OUT}`);
  console.log(`[fixture] fixture sha256: ${spaced(sha256)}`);
  console.log(`[fixture] block ${chosen.height}, blob ${chosen.blobHex.length / 2} bytes, ${chosen.txHashes.length} transaction${chosen.txHashes.length === 1 ? '' : 's'} beside the miner transaction`);
  console.log('[fixture] next: record this sha256 in test/fixtures/README.md and build the reader against the pinned bytes.');
}

main().catch((error) => {
  console.error(`[fixture] ${error?.message || error}`);
  process.exit(1);
});
