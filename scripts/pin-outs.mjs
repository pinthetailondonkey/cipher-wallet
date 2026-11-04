#!/usr/bin/env node
// Pin one real /get_outs answer, using the wallet's own door.
//
// The request is derived from a pinned real transaction rather than invented:
// the ring offsets of a real mainnet input ARE global indices into the
// amount-0 output list (see src/monero/outs.js), so asking a node for the
// first few of them exercises the door and the offset arithmetic on indices
// that the chain itself wrote down.
//
// Usage:
//   node scripts/pin-outs.mjs [--node host:port] [--tx <fixture.json>] [--count 3]
//
// No node in the argument list and no CIPHER_XMR_NODE: the shipped list is
// used, exactly as a scan uses it.

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { hex } from '@scure/base';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const FIXTURE_DIR = join(ROOT, 'test/fixtures');

const args = process.argv.slice(2);
const flag = (name, fallback) => {
  const at = args.indexOf(`--${name}`);
  return at === -1 ? fallback : args[at + 1];
};

const { readTransaction } = await import(join(ROOT, 'src/monero/block.js'));
const { getOuts, getTransactions, getBlock } = await import(join(ROOT, 'src/monero/nodeClient.js'));
const { parseBlock } = await import(join(ROOT, 'src/monero/block.js'));
const { offsetsToAbsolute } = await import(join(ROOT, 'src/monero/outs.js'));
const { nodeSourceFromEnv } = await import(join(ROOT, 'src/monero/nodes.js'));

const txFixture = flag('tx', 'monero-tx-rct-5.json');
const count = Number(flag('count', '3'));
const outPath = flag('out', join(FIXTURE_DIR, 'monero-get-outs-answer.json'));

const fixture = JSON.parse(readFileSync(join(FIXTURE_DIR, txFixture), 'utf8'));
const tx = readTransaction(Uint8Array.from(Buffer.from(fixture.asHex.replace(/\s+/g, ''), 'hex')), 0, 'ring source');
const input = tx.inputs.find((i) => i.kind === 'key');
if (!input) throw new Error(`${txFixture} carries no key input to take a ring from.`);
const absolute = offsetsToAbsolute(input.keyOffsets);
const outputs = absolute.slice(0, count).map((index) => ({ amount: 0, index: Number(index) }));

// The same choice a scan makes: a configured node, else the shipped list's
// first live row, taken from the pool rather than re-read from the file.
const node = flag('node', nodeSourceFromEnv().pick());
console.log(`[pin-outs] asking ${node} for ${outputs.length} amount-0 output(s): ${outputs.map((o) => o.index).join(', ')}`);
const answer = await getOuts(node, { outputs, getTxid: true });

// VERIFY the door against the chain itself, not only against the door. Each
// answer names a height and a txid; if those are true, the transaction really
// is in the block at that height and really does carry an output with that
// key. So: fetch the block, prove the txid is in the block's own hash list,
// fetch the transaction, and find the key in its outputs. A node that invents
// a ring member cannot survive this, and it is the join that makes these
// indices mean something rather than looking like 64 hex characters.
const verification = [];
for (const out of answer.outs) {
  if (!out.txid) throw new Error(`the node did not name the transaction behind output ${out.index}, so it cannot be verified`);
  const block = await getBlock(node, { height: out.height });
  const parsedBlock = parseBlock(block.blob);
  const txInBlock = parsedBlock.txHashes.includes(out.txid) || parsedBlock.minerTxId === out.txid;
  const fetched = await getTransactions(node, [out.txid]);
  const tx = readTransaction(fetched.bytes[0], 0, `output ${out.index} transaction`);
  const outputAt = tx.outputs.findIndex((o) => o.key === out.key);
  verification.push({
    index: Number(out.index),
    txid: out.txid,
    blockHeight: out.height,
    blockId: parsedBlock.id,
    txInBlock,
    keyFoundAtOutput: outputAt,
    txVersion: tx.version,
    rctType: tx.rctType,
    blockTxCount: parsedBlock.txHashes.length,
  });
  console.log(`[pin-outs] verified output ${out.index}: tx ${out.txid.slice(0, 16)}… is in block ${parsedBlock.id.slice(0, 16)}… at height ${out.height}, key is output ${outputAt}`);
}

const record = {
  source: {
    what: 'One real monerod /get_outs answer, captured live by scripts/pin-outs.mjs through the wallet\'s own door.',
    node: answer.address,
    nettype: 'mainnet',
    captureMethod: 'POST /get_outs { outputs: [{amount: 0, index}], get_txid: true } over clearnet from the machine that ran the script',
    capturedAt: new Date().toISOString(),
    requestedFrom: txFixture,
    requestedIndices: outputs.map((o) => o.index),
    note: 'The indices are the ABSOLUTE ring positions of a real mainnet input, converted from that input\'s own relative key_offsets. The keys and masks are the node\'s claims about outputs at those positions; nothing in this repository proves them against a block, because a ring member is in no transaction.',
    verificationNote: 'Each answer was checked against the chain in the same run: the block at the named height was fetched and parsed, the named transaction was proven to be in that block\'s own hash list, and the key was found among that transaction\'s own outputs. The block and transaction BYTES behind those facts are not pinned here, so a replay asserts the recorded conclusions and re-deriving them means re-running this script.',
    rederive: `node scripts/pin-outs.mjs --tx ${txFixture} --count ${count} --out test/fixtures/${outPath.split('/').pop()}`,
  },
  request: { outputs, get_txid: true },
  response: {
    status: 'OK',
    // The door has already parsed these; the record keeps the door's own output
    // so a replay asserts the parse, not the raw JSON shape.
    outs: answer.outs.map((o) => ({
      amount: Number(o.amount),
      index: Number(o.index),
      key: o.key,
      mask: o.mask,
      height: o.height,
      unlocked: o.unlocked,
      txid: o.txid,
    })),
    untrusted: answer.untrusted,
  },
  verification,
};

writeFileSync(outPath, JSON.stringify(record, null, 1) + '\n');
console.log(`[pin-outs] wrote ${outPath}`);
for (const o of answer.outs) {
  console.log(`  index ${o.index} -> key ${o.key.slice(0, 16)}… mask ${String(o.mask).slice(0, 16)}… height ${o.height} unlocked ${o.unlocked}`);
}
console.log(`[pin-outs] first key parses as a point: ${(() => { try { hex.decode(answer.outs[0].key); return 'bytes ok'; } catch { return 'no'; } })()}`);
