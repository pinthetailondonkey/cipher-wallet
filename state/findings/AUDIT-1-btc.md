# AUDIT-1 — bitcoin/legacy side (lane A1, independent)

Scope: src/units.js, root.js, vault.js, deviceEnvelope.js, pocketStore.js, payHandle.js,
address.js, tx.js, psbt.js, spend.js, receive.js, paymentState.js, watcher.js. Read as
hypotheses from README ("The shape", "The vault is two layers", "The receive path", "The spend
path", "What a spend does not prove"), then broken by execution. Probes: state/findings/probe-A1{,b,c,d}.mjs.

Baseline (btc files only): `node --test test/{units,spend,tx,psbt,vault,deviceEnvelope,receive,
pocketStore,paymentState,watcher,address,root,payHandle}.test.mjs` -> 148 pass / 0 fail.

FALSE leads the list.

## FALSE — AREA 5 (receive): two concurrent issue() calls reuse one pocket/address; the second payment is then refused

Command: `node state/findings/probe-A1d.mjs` (real 5ms-latency kv, not same-tick)

    issue A -> index 0 bc1q3sfyvjz3pta4
    issue B -> index 0 bc1q3sfyvjz3pta4
    same address handed to two customers: true
    pockets persisted: [ 0 ]
    first payment recorded: tx-ONE seen
    second payment -> REFUSED: This pocket already names a different transaction.

Cause: receive.issue reads the handle with `await handle()` OUTSIDE the store's serialized queue,
then calls store.issue with `now=undefined`... no — the handle read is the un-serialized step. Two
issues in the same turn both read the same stored handle, both derive the same next index/address;
store.issue then sees an existing row with the same address and only moves the handle, returning the
existing row. Expected race output (probe-A1b, store already has a pocket): both calls -> index 1,
same address, one row. So "a fresh pocket per payment" fails under concurrency: two orders share an
address, and because pocketStore enforces one-pocket-one-txid, the second order's payment cannot be
recorded at all.

Crash half of the claim is fine: `probe-A1.mjs` AREA5 simulates a kv.set that throws mid-write; the
retry re-uses index 0 (no gap, no skipped index). VERIFIED for crash, FALSE for concurrency.

## PARTIAL — AREA 5 (receive): xmr is not reachable end to end

`createReceive.issue({coin:'xmr'})` -> pocket with `address === null`; `scan` throws
`This pocket has no address to ask about.` (probe-A1, and pinned by test/receive.test.mjs). root.pocketFor
only builds an address for btc. So the receive path is btc-only; xmr keys exist elsewhere but nothing in
this module makes an xmr pocket payable. The code pins the refusal as intended, it is not a silent bug.

## PARTIAL — AREA 1 (units): rounding is sound; the floor has sharp edges

Commands: probe-A1, probe-A1b, probe-A1c.

Verified by execution: no float crosses (normalizeAmount throws on a number; amountUnits returns null);
round-half-up never drops a sat (`0.000000015`->2, `0.000000014`->1); scale is exactly 8/12; btc/xmr
roundtrip fuzz 0 mismatches; sum stays BigInt; unknown rail refused. No 1-piconero off-by-one found.

Sharp edges, all by refusal, none money-losing:
- `amountUnits` accepts only non-negative decimal strings: `'-1'` and `unitsToAmount(-1n,'btc')` are
  asymmetric (the latter works, the former returns null).
- exponent form is refused with no message: `amountUnits('1e-8','btc') === null`. Reachable from a
  watcher that emits `{"amount":1e-8}`: parseExactAmounts quotes only `\d+(\.\d+)?`, so the number
  survives and applyWatcherReport reports the payment "short of the order" (probe-A1b C).
- `unitsToAmount` accepts a non-safe integer number and silently loses precision (only a BigInt should
  cross); no caller currently passes one.

## PARTIAL — AREA 2 (vault/envelope): copied blob is dead, codes are distinct, but the seal iterations option is unusable

Command: probe-A1 AREA2, probe-A1c.

Verified: same-device copied blob opens; the same blob against a different device secret throws
`DeviceKeyMissing/wrong-key` (a DeviceKeyError), never `wrong-pin`; `wrong-pin`, `pin-too-short`,
`damaged-vault` are three distinct codes, so a wrong PIN and a device error cannot be conflated in a
wipe counter. AAD binds pk+kind; a wrong pk/kind fails as missing.

Defect: `sealVault(secret,pin,{iterations})` with any value `< KDF_ITERATIONS` produces a vault that
`isDamagedVault` rejects, so `openVault` reports `damaged-vault` and it can never open (probe-A1c:
iter 599999/100000/1 -> REFUSED damaged-vault). The `iterations` option is therefore only usable at
the exact default. Latent today because every caller uses the default.

## VERIFIED — AREA 3 (spend): change, dust, fee, one pocket, verified==signed

Command: probe-A1 AREA3.

- change never quietly to the payee: same address (and same address shouted uppercase) refused.
- accounting exact: for every boundary tried, sum(tx.outputs) + returned `fee` === utxo.value.
- dust: change of 293 goes to the miner (fee grows, one output); 294 is kept as an output.
- one pocket: a utxo below amount+fee is refused.
- the value written to the payee output equals the validated `amount`; no check-then-mutate found.
- note (not a defect, policy): a payee output below the 294 dust limit is still created.

## PARTIAL — AREA 4 (paymentState/watcher): no backwards step, but a value is skipped and spend states are unwired

Watchdog VERIFIED: a report must carry source==='watcher' and a txid; a short or missing amount is
refused; the state only moves forward; pocketStore clamps confirmations with Math.max and refuses a
second txid (`This pocket already names a different transaction`); a repeated report is a no-op and
survives reload (probe-A1b D). watcher.js itself is sound: HMAC over `<ts>:<body>` with the per-address
child token, 120s freshness, address/currency echo, tampered body refused (probe-A1 AREA4).

Gaps:
- `address_issued` + a report with >=3 confirmations jumps straight to the `confirmed` value, never
  writing `seen` (probe-A1). Both edges are walked in one call, seenAt is set, so the effect is right,
  but the stored state skips a name on the "nothing skips" line.
- `created` is a declared state no producer ever writes (receive always issues `address_issued`); a
  report that arrives at `created` with confirmations is REFUSED by "has to be seen before".
- spend.js `SPEND_STATES = built/signed/broadcast/seen/confirmed` has no consumer outside spend.js;
  the built->confirmed chain is not joined to paymentState at all, so "built" never appears in a
  payment row.
- watcher amount read through a bare exponent number is misread as short (see AREA 1).

## PARTIAL — AREA 4 (watcher trust): the watcher's own tx is taken on faith by design

pocketStore.record trusts report.txid/confirmations/amount once the watcher signature passes; the
wallet never checks the chain itself. This matches "A watcher is the only thing that moves a payment".

## OVERALL

One FALSE (concurrent issue reuses a pocket/address, and the second payment is then unrecordable),
everything else VERIFIED or PARTIAL; no units/rounding money bug, no spend change/dust defect.
