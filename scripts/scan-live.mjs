// The live scan: one real block, scanned for a pocket's own outputs, over the
// same proven pipeline the tests use.
//
//   getBlock -> ownOutputsInBlock (parseBlock -> walkBlockTxs -> scan -> decode)
//
// It prints what it found and changes nothing on disk. The pinned fixtures are
// how the tests stay offline; this script is how a human checks that the live
// path still runs against a real node.
//
// Doors honoured (same law as the capture scripts):
//   CIPHER_XMR_NODE  - the only node, by host:port. Nothing discovers a node.
//   CIPHER_TOR_SOCKS - optional host:port; set, every call rides it.
//   --height N (or --hash H) - which block.
//   --seed "words"   - optional BIP39 phrase; default is the published
//                      'abandon … about' seed, whose pockets pay strangers.
//
//   CIPHER_XMR_NODE=xmr-node.cakewallet.com:18081 \
//   node scripts/scan-live.mjs --height 3796965

import { spawn } from 'node:child_process';
import { scanBlockFromNode } from '../src/monero/scanFromNode.js';
import { rootFromMnemonic } from '../src/root.js';
import { moneroPocket } from '../src/monero/pocket.js';

const arg = (name) => {
  const i = process.argv.indexOf(name);
  return i === -1 ? null : process.argv[i + 1];
};
const NODE = arg('--node') || process.env.CIPHER_XMR_NODE;
const TOR = arg('--tor') || process.env.CIPHER_TOR_SOCKS || '';
const HEIGHT = arg('--height');
const HASH = arg('--hash');
const POCKETS = Number(arg('--pockets') || 4);
const PHRASE = arg('--seed')
  || 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

if (!NODE) {
  console.error('No node. Set CIPHER_XMR_NODE (host:port). Nothing else picks a node.');
  process.exit(1);
}
if (!HEIGHT && !HASH) {
  console.error('Give --height N or --hash H. The scan pins one block.');
  process.exit(1);
}

// Tor's SOCKS is the one thing node's fetch cannot speak; curl is named here,
// in prose, the way the other scripts name it.
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

const seed = rootFromMnemonic(PHRASE);
const pockets = Array.from({ length: POCKETS }, (_, index) => moneroPocket(seed, index));

const started = Date.now();
const out = await scanBlockFromNode(NODE, {
  height: HEIGHT ? Number(HEIGHT) : undefined,
  hash: HASH ?? undefined,
  pockets,
  fetchImpl: curlFetch(),
});

console.log(`block     ${out.blockId}`);
console.log(`scanned   ${out.transactionsScanned} transaction(s)`);
console.log(`pockets   ${pockets.length}, first address ${pockets[0].address}`);
console.log(`owned     ${out.outputs.length}`);
for (const row of out.outputs) {
  const value = row.value === undefined ? `refused: ${row.refused}` : `${row.value} atomic`;
  console.log(`  pocket ${row.pocket} output ${row.output} tx ${row.txid.slice(0, 16)}… ${value}`);
}
console.log(`took      ${Date.now() - started} ms`);
if (out.outputs.length === 0) {
  console.log('An empty result is an honest answer here: the default seed pays strangers.');
}
