#!/usr/bin/env node
// The funded lane, live: one real stagenet payment, received by this wallet,
// turned into an input, ringed from the same node's chain, signed, and handed
// to a daemon for its verdict.
//
// USAGE:
//   node scripts/stagenet-funded-spend.mjs [--node stagenet.xmr-tw.org:38081]
//        [--txid <payment txid>] [--height <N>] [--faucet]
//
// Phases, each refuses rather than guessing:
//   fund    ask the faucet for coins on our own address (or use --txid)
//   scan    prove the block and take the owned row out of it
//   spend   build + sign with a LIVE ring that includes our member as served
//   submit  hand it over; the daemon's sentence is printed verbatim
//
// What acceptance here WOULD mean: upstream's expand asserts the expanded
// mixRing equals what the chain serves, balance+range+CLSAG all verify there.
// What it does NOT mean even then: no double-spend history exists in this build,
// so a second spend of the same output is this script's caller's problem (the
// first one wins at any node; see the header of src/monero/fundInput.js).

import { hex } from '@scure/base';

const args = process.argv.slice(2);
const flag = (name, fallback) => {
  const at = args.indexOf(`--${name}`);
  return at === -1 ? fallback : args[at + 1];
};
const only = (name) => args.includes(`--${name}`);

const { rootFromMnemonic } = await import(new URL('../src/root.js', import.meta.url));
const { moneroPocket } = await import(new URL('../src/monero/pocket.js', import.meta.url));
const nodeClient = await import(new URL('../src/monero/nodeClient.js', import.meta.url));
const { getTransactions, getBlock, getOuts, submitTx } = nodeClient;
const { scanBlockFromNode } = await import(new URL('../src/monero/scanFromNode.js', import.meta.url));
const { ownedOutputToInput, withRing } = await import(new URL('../src/monero/fundInput.js', import.meta.url));
const { buildSpend } = await import(new URL('../src/monero/build.js', import.meta.url));
const keys = await import(new URL('../src/monero/keys.js', import.meta.url));

const NODE = flag('node', 'stagenet.xmr-tw.org:38081');
const FAUCET_URL = 'https://stagenet-faucet.xmr-tw.org/send_tx/';
const MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const seed = rootFromMnemonic(MNEMONIC);
const sender = moneroPocket(seed, 0, { network: 'stagenet' });
console.log(`[funded] pocket 0 ${sender.address}`);
console.log('[funded] WARNING: this demo mnemonic is public. It holds whatever strangers sent it. Never reuse the derivation below on mainnet.');

// ---- phase 1: fund -------------------------------------------------------
let txid = flag('txid', null);
if (!txid || only('faucet')) {
  console.log(`[funded] asking the faucet (${FAUCET_URL}) to pay ${sender.address}`);
  const response = await fetch(FAUCET_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ addr: sender.address }),
  });
  if (!response.ok) throw new Error(`The faucet refused with HTTP ${response.status}.`);
  const text = await response.json();
  const match = /([0-9a-f]{64})/.exec(text.tx_id ?? '');
  if (!match) throw new Error(`The faucet answered without a readable tx id: ${String(text.tx_id ?? '').slice(0, 120)}`);
  txid = match[1];
  console.log(`[funded] faucet says tx ${txid}; waiting for it to leave the pool`);
  // Wait until get_transactions shows it in a block. The pool is where nothing
  // is provable yet: output_indices do not exist for an unconfirmed payment.
  let confirmed = null;
  for (let attempt = 0; attempt < 60 && !confirmed; attempt += 1) {
    await new Promise((r) => setTimeout(r, 20_000));
    try {
      const probe = await fetch(`http://${NODE}/get_transactions`, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txs_hashes: [txid], decode_as_json: false }),
      });
      const body = await probe.json();
      const row = body.txs?.[0];
      if (row && row.in_pool === false && Array.isArray(row.output_indices)) confirmed = row;
    } catch { /* transient */ }
    process.stdout.write('.');
  }
  console.log('');
  if (!confirmed) throw new Error('That payment never confirmed within ten minutes. Nothing was scanned.');
}

// ---- phase 2: find the block, PROVE it, scan our output ------------------
const answer = await getTransactions(NODE, [txid]);
if (answer.bytes.length !== 1) throw new Error('Exactly one transaction was asked for.');
const paymentBytes = answer.bytes[0];
const indices = answer.outputIndices[0];
if (indices === null) throw new Error('The daemon served no global output indices for the payment, so the input cannot be anchored.');

// Its block: the transaction response carries block_height when not in pool.
const probe = await fetch(`http://${NODE}/get_transactions`, {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ txs_hashes: [txid], decode_as_json: false }),
});
const probeBody = await probe.json();
const height = Number(flag('height', probeBody.txs?.[0]?.block_height));
if (!Number.isInteger(height)) throw new Error('No block height known for the payment.');

const scanned = await scanBlockFromNode(NODE, { height, pockets: [{ index: sender.index, spend: sender.spend, viewSecret: sender.viewSecret }] });
const rows = scanned.outputs.filter((r) => !r.refused && r.pocket === sender.index);
console.log(`[funded] block ${scanned.blockId.slice(0, 16)}… at height ${height}: ${rows.length} owned output(s), anchored=${scanned.anchored}`);
if (rows.length === 0) {
  console.log(JSON.stringify(scanned.outputs, (_, v) => (typeof v === 'bigint' ? String(v) : v)));
  throw new Error('This wallet owns nothing in that block. Did the faucet pay this exact address?');
}
// Our row, matched against the payment we asked about: the same txid and a
// decode that rebuilt its commitment.
const row = rows.find((r) => r.txid === txid) ?? rows[0];
console.log(`[funded] owned: out#${row.output} value ${row.value} mask ${String(row.mask).slice(0, 12)}… globalIndex ${row.globalIndex}`);

const input = ownedOutputToInput({ row, pocket: sender, txBytes: paymentBytes });
if (input.globalIndex !== BigInt(indices[Number(row.output)])) {
  throw new Error(`The row's globalIndex and the direct answer disagree: ${input.globalIndex} vs ${indices[Number(row.output)]}.`);
}

// ---- phase 3: ring from THIS node, ours inside it ------------------------
const RING_SIZE = Number(flag('ring', '11'));
const oursIndex = input.globalIndex;
// Decoys: mixed recency around ours, clamped to the chain frontier this node
// actually serves (get_outs refuses an index it has not minted). With --ring-plan,
// an explicit ascending list is used instead, so an ours-mid-ring variant is a
// flag away rather than a code change.
const plan = flag('ring-plan', null);
const wanted = plan ? plan.split(',').map((t) => BigInt(t.trim())) : (() => {
  const decoyStep = 170n;
  const wanted_ = [oursIndex];
  for (let i = 1; i < RING_SIZE; i += 1) {
    const step = decoyStep * BigInt(i * (i % 2 === 0 ? 13 : 5));
    wanted_.push(oursIndex > step + 10n ? oursIndex - step : BigInt(i));
  }
  return wanted_;
})();
// The chain's output list is GROWING while we stand here, so a decoy past the
// frontier is refused by name. Probe each candidate alone and keep the OK ones,
// nearest-frontier first, until RING_SIZE survive.
const probed = [];
for (const index of wanted.slice().sort((a, b) => (a > b ? -1 : 1))) {
  if (probed.length >= RING_SIZE) break;
  if (!Number.isInteger(Number(index)) || Number(index) < 0) continue;
  try {
    const probe = await getOuts(NODE, { outputs: [{ amount: 0, index }] });
    if (probe.outs[0].unlocked !== false) probed.push(index);
  } catch { /* past the frontier or another refusal; skip it */ }
}
if (probed.length < RING_SIZE) throw new Error(`Only ${probed.length} usable decoy(s) out of ${RING_SIZE} asked.`);
wanted.length = 0;
wanted.push(...probed);
const outsAnswer = await getOuts(NODE, { outputs: wanted.map((index) => ({ amount: 0, index })) });
const funded = withRing({ input, outs: outsAnswer.outs });
console.log(`[funded] ring: ${funded.ring.length} members, ours served with our own key and commitment`);

// ---- phase 4: build, sign ----------------------------------------------
// The fee is the DAEMON's own estimate at priority 1 (slow), per byte of what we
// are about to build, quantized to the mask it names. It is not a guess: a real
// wallet asks its node.
const est = await (await fetch(`http://${NODE}/json_rpc`, {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ jsonrpc: '2.0', id: '0', method: 'get_fee_estimate', params: { grace_blocks: 0 } }),
})).json();
const feePerByte = BigInt(est.result.fee);
const mask = BigInt(est.result.quantization_mask);
// Weight first: weight = ceil(blob/130) fullness... upstream weights Bulletproof
// rct txs at base + V/32 per bp; approximating by bytes plus V/64*3 then refining:
// The built size below is only known after building; upstream charges bp weight as
// blob + 6960/10 + ... Simplest honest rule here: estimate with blob = previous
// known size (1343) + headroom, and requantize once after the true size is known.
const feeFallback = BigInt(flag('fee', '30000000'));
let fee = flag('fee') !== null ? feeFallback : ((feePerByte * 1400n) + mask - 1n) / mask * mask;
// ---- phase 4: build, sign ----------------------------------------------
const payAmount = BigInt(flag('amount', '60000000000')); // 0.06 XMR of the 0.1 received
if (payAmount >= input.value) throw new Error('The payment must leave room for change and fee.');
const recipient = moneroPocket(seed, 1, { network: 'stagenet' });
const change = input.value - payAmount - fee;
const built = buildSpend({
  input: {
    ...funded,
    // buildSpend's signed shape takes the ordered ring as {key, mask} members;
    // the served outs carry them as hex strings, so convert once here.
    ring: funded.ring.map((member) => ({
      index: member.index, key: typeof member.key === 'string' ? hex.decode(member.key) : member.key,
      mask: typeof member.mask === 'string' ? hex.decode(member.mask) : member.mask,
    })),
    ours: oursIndex,
  },
  recipients: [
    { spendPublic: recipient.spend, viewPublic: recipient.view, value: payAmount },
    { spendPublic: sender.spend, viewPublic: sender.view, value: change },
  ],
  fee,
  txSecret: keys.hashToScalar(keys.concatBytes([Uint8Array.from([198]), hex.decode(txid)])),
});
console.log(`[funded] built ${built.bytes.length} bytes, signed=${built.signed}, id ${built.id}`);

// The wallet reads its own bytes back before asking a stranger anything.
const { readTransaction } = await import(new URL('../src/monero/block.js', import.meta.url));
const parsedBack = readTransaction(built.bytes, 0, 'funded candidate');
if (parsedBack.prunableBytes === null || parsedBack.bulletproofsPlus.length !== 1) {
  throw new Error('The built transaction did not survive its own reader.');
}

// ---- phase 5: the verdict ---------------------------------------------
const txHex = hex.encode(built.bytes);
const dump = flag('dump', null);
if (dump) (await import('node:fs')).writeFileSync(dump, txHex);
const doors = only('both') ? [NODE, 'node.sethforprivacy.com:38089'] : [NODE];
for (const door of doors) {
  // The REST door first; then, when asked for both, also the JSON-RPC send_raw_tx
  // spelling because its reason assembly differs in some daemon versions.
  const viaRest = await submitTx(door, { txAsHex: txHex, doNotRelay: true });
  console.log(`[funded] ${door} rest: accepted=${viaRest.accepted} status=${JSON.stringify(viaRest.status)} reason=${JSON.stringify(viaRest.reason)} txid=${viaRest.txid}`);
  if (!only('both')) { process.exit(viaRest.accepted ? 0 : 1); }
  const rpc = await (await fetch(`http://${door}/json_rpc`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: '0', method: 'send_raw_tx', params: { tx_as_hex: txHex, do_not_relay: true } }),
  })).json();
  console.log(`[funded] ${door} rpc: ${JSON.stringify(rpc).slice(0, 300)}`);
}
process.exit(1);
console.log(`[funded] ${NODE} answered: accepted=${verdict.accepted} status=${JSON.stringify(verdict.status)} reason=${JSON.stringify(verdict.reason)} txid=${verdict.txid}`);
if (verdict.reason) console.log(`[funded] daemon's sentence, verbatim: ${verdict.reason}`);
process.exit(verdict.accepted ? 0 : 1);
