#!/usr/bin/env node
// Build one unsigned Monero spend and hand it to a real node.
//
// The point is not to have a valid transaction (the proofs are zero, so it is
// not) but to make a stranger's daemon read the bytes this build wrote and say
// WHERE it stopped. "Could not parse" and "parsed, but the signature is wrong"
// are different verdicts about different halves of this build, and only a real
// daemon can give either.
//
// The ring is fetched live with the wallet's own door, from a real input's own
// absolute positions, so the request is a real ring and not invented indices.
//
// Usage:
//   node scripts/build-and-submit.mjs [--node host:port] [--tx <fixture.json>] [--ring 6] [--no-relay]

import { readFileSync } from 'node:fs';
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
const { rootFromMnemonic } = await import(join(ROOT, 'src/root.js'));
const { moneroPocket } = await import(join(ROOT, 'src/monero/pocket.js'));
const { offsetsToAbsolute, ringFromOuts } = await import(join(ROOT, 'src/monero/outs.js'));
const { getOuts, submitTx } = await import(join(ROOT, 'src/monero/nodeClient.js'));
const { nodeSourceFromEnv } = await import(join(ROOT, 'src/monero/nodes.js'));
const keys = await import(join(ROOT, 'src/monero/keys.js'));
const { buildOutput, buildSpend } = await import(join(ROOT, 'src/monero/build.js'));

const txFixture = flag('tx', 'monero-tx-rct-5.json');
const ringSize = Number(flag('ring', '6'));
const noRelay = args.includes('--no-relay');
const pinFile = args.includes('--no-pin') ? null : flag('pin', join(ROOT, 'test/fixtures/monero-built-spend.json'));
const node = flag('node', nodeSourceFromEnv().pick());
const XMR = 1_000_000_000_000n;

// A wallet out of the demo mnemonic: two pockets, sender and recipient.
const seed = rootFromMnemonic('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
const sender = moneroPocket(seed, 0);
const recipient = moneroPocket(seed, 1);

// An output the sender owns, built here so its one-time secret is known. On a
// funded wallet this is what a scan would have found instead.
const priorSecret = keys.hashToScalar(Uint8Array.from([5, 5, 5]));
const priorDerivation = keys.keyDerivation(keys.secretToPublic(priorSecret), sender.viewSecret);
const owned = buildOutput({ derivation: priorDerivation, index: 0, spendPublic: sender.spend, value: 10n * XMR });
const ownedSecret = keys.deriveSecretKey(priorDerivation, 0, sender.spendSecret);

// A REAL ring: the absolute positions of a real mainnet input's own offsets.
const fixture = JSON.parse(readFileSync(join(FIXTURE_DIR, txFixture), 'utf8'));
const sourceTx = readTransaction(Uint8Array.from(Buffer.from(fixture.asHex.replace(/\s+/g, ''), 'hex')), 0, 'ring source');
const absolute = offsetsToAbsolute(sourceTx.inputs.find((i) => i.kind === 'key').keyOffsets);
const indices = absolute.slice(0, ringSize).map(Number);

console.log(`[build-submit] asking ${node} for ${indices.length} real ring member(s): ${indices.join(', ')}`);
const answer = await getOuts(node, { outputs: indices.map((index) => ({ amount: 0, index })) });
const ring = ringFromOuts({ outs: answer.outs, ours: answer.outs[0].index });
console.log(`[build-submit] ring built: ${ring.ring.length} members, offsets ${ring.offsets.slice(0, 3).join(',')}…`);

const fee = 30_000_000n;
const txSecret = keys.hashToScalar(Uint8Array.from([6, 6, 6]));
const built = buildSpend({
  input: {
    keyOffsets: ring.offsets,
    outputKey: owned.key,
    outputSecret: ownedSecret,
    value: 10n * XMR,
    mask: owned.mask,
  },
  recipients: [
    { spendPublic: recipient.spend, viewPublic: recipient.view, value: 4n * XMR },
    { spendPublic: sender.spend, viewPublic: sender.view, value: 10n * XMR - 4n * XMR - fee },
  ],
  fee,
  txSecret,
});

console.log(`[build-submit] built ${built.bytes.length} bytes, id ${built.id}`);
console.log(`[build-submit] budgets: prefix ${built.prefix.length}, base ${built.base.length}, prunable ${built.prunable.length}`);
console.log(`[build-submit] key image ${hex.encode(built.keyImage)}, pseudo-out ${hex.encode(built.pseudoOut).slice(0, 16)}…`);

// The recipient really can read the payment back out of these bytes.
const { scanTransaction, transactionPublicKey, bridgeWalkedTransaction } = await import(join(ROOT, 'src/monero/scan.js'));
const walkTx = readTransaction(built.bytes, 0, 'built');
const found = scanTransaction({
  pocket: recipient,
  transactionPublicKey: transactionPublicKey(walkTx.extra),
  outputs: bridgeWalkedTransaction(walkTx).outputs,
});
console.log(`[build-submit] the recipient's own scan finds output(s) ${found.join(', ') || '(none)'} in the bytes it just built`);

const verdict = await submitTx(node, { txAsHex: hex.encode(built.bytes), doNotRelay: noRelay });
console.log(`[build-submit] ${node} answered: accepted=${verdict.accepted} status=${JSON.stringify(verdict.status)} reason=${JSON.stringify(verdict.reason)} txid=${verdict.txid}`);
console.log(`[build-submit] local id ${built.id} vs node txid ${verdict.txid ?? '(none)'}${verdict.txid && verdict.txid !== built.id ? '  MISMATCH' : ''}`);

// A second submission with ONE BYTE REMOVED. The contrast is the evidence: the
// daemon's "could not read these bytes" and "read them, disliked the crypto" are
// different sentences, and only a real daemon can say which one our bytes get.
const truncated = built.bytes.slice(0, built.bytes.length - 1);
const cutVerdict = await submitTx(node, { txAsHex: hex.encode(truncated), doNotRelay: noRelay });
console.log(`[build-submit] same bytes, last byte removed: status=${JSON.stringify(cutVerdict.status)} reason=${JSON.stringify(cutVerdict.reason)}`);

if (pinFile) {
  const { writeFileSync } = await import('node:fs');
  writeFileSync(pinFile, JSON.stringify({
    source: {
      what: 'One UNSIGNED Monero spend built by this repository, and the two things a real daemon said about it. The verdicts are the evidence: the intact bytes are read and expanded and then fail verification (nothing is signed), while the same bytes with one byte removed fail the parse/expand stage by name.',
      node,
      nettype: 'mainnet',
      capturedAt: new Date().toISOString(),
      ringFrom: txFixture,
      ringIndicesFetched: indices,
      daemonSites: 'on_send_raw_tx (core_rpc_server.cpp) reports "Sanity check failed" for a blob tx_sanity_check cannot parse or expand, and a broader reason list for one it can; the empty reason is handle_incoming_tx failing verification with no specific flag set.',
      rederive: `node scripts/build-and-submit.mjs --node ${node}`,
      note: 'The transaction is NOT in the chain and never will be: its input is an output this build constructed, not a funded one. The bytes are reproduced offline by the test from the build inputs below.',
    },
    build: {
      mnemonic: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
      senderIndex: 0,
      recipientIndex: 1,
      priorSecret: hex.encode(priorSecret),
      txSecret: hex.encode(txSecret),
      fee: fee.toString(),
      amounts: ['4000000000000', (10n * XMR - 4n * XMR - fee).toString()],
      ringOffsets: ring.offsets.map((o) => o.toString()),
      ringIndices: ring.ring.map((r) => Number(r.index)),
      ownedValue: (10n * XMR).toString(),
      ownedIndex: 0,
    },
    bytes: hex.encode(built.bytes),
    byteLength: built.bytes.length,
    id: built.id,
    verdicts: {
      intact: { accepted: verdict.accepted, status: verdict.status, reason: verdict.reason, txid: verdict.txid },
      lastByteRemoved: { accepted: cutVerdict.accepted, status: cutVerdict.status, reason: cutVerdict.reason, txid: cutVerdict.txid },
    },
  }, null, 1) + '\n');
  console.log(`[build-submit] pinned ${pinFile}`);
}
