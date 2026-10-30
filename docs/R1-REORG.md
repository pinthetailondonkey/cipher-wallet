# R1: a confirmed payment the chain no longer holds

A decision page, not a design. Nothing below is built. The founder rules on
which option, if any, is built.

The code this page is about is **not in this repository**. It is the shipped
messenger's payment path, measured at `4c2b6165e86bd603e24f38009b894dcd84f1358f`
in `/home/aegis/cipher`. This wallet is a separate product and has no orders.
The paper lives here because the wallet lane holds it; the code it describes
does not.

## 1. The exposure, in two sentences

Once a payment is marked confirmed the app stops looking at it forever, so if
the block that held it is later dropped by the chain nobody ever finds out;
this needs a chain rewrite deeper than three Bitcoin blocks or ten Monero
blocks, which is rare but has happened, and the app has never counted how
often. The loss lands on the vendor — they ship goods against money that went
back to the buyer, both sides keep a signed receipt saying the payment
happened, and no part of the app can take either back.

### What is measured, and where

Anchors are file:line in the shipped app at the commit above. Every one of
these was read, not assumed.

- One writer. `applyWatcherReport` (`src/lib/paymentState.js:239`) is the only
  code that moves a payment to confirmed.
- After confirmed, a later answer saying "pending" or naming no transaction
  changes nothing (`src/lib/paymentWatch.js:382`). An answer with **fewer**
  confirmations throws `did not move` (`src/lib/paymentState.js:274`) and is
  swallowed to "nothing happened" (`src/lib/paymentWatch.js:430`).
- The state is also worked out from history by taking the highest claim ever
  made (`src/lib/orderActions.js:84`), and a lower claim is refused (`:91`).
  So even a rebuilt view cannot go down.
- The state table has forward edges only (`src/lib/paymentState.js:27`). The
  threshold (Bitcoin 3, Monero 10, overridable) is checked once, on the scan
  that writes confirmed, and never again.
- **No count is stored anywhere.** Not in the order, not in the receipt, not
  in the spent-transaction record. The only `confirmations` key on disk is the
  per-coin threshold the person chose (`src/Wallet.jsx:101`). So a payment
  buried five blocks deep and a payment that has vanished look identical.
- **Nothing asks after confirmed.** The chain check has one caller
  (`src/features/chat/useCommerce.js:522`, the "Check the chain" handler); no
  timer in the app touches the watcher; and the button itself is withheld
  once the payment is confirmed, on both sides (`src/lib/orderActions.js:393`,
  `:412`, `:405`). The one exception — an order a later message walked back
  from a sealed state (`:371`-`:384`) — still offers the button, but running it
  on a confirmed payment lands in the same dead end and the screen says "your
  watcher has not seen this payment yet", which is the wrong sentence for a
  vanished transaction.
- **Last poll after confirmed: zero, ever.** That number is why the ordering
  in this page matters: a way to lower the state is dead code if nothing ever
  fetches the answer that would lower it.

At the moment of confirming, the vendor signs a receipt naming the
transaction, stores it, marks the transaction spent so it cannot pay a second
order, and sends it to the buyer (`src/features/chat/useCommerce.js:618`,
`:629`, `:632`). The buyer's card then shows confirmed from that receipt alone
(`src/lib/orderActions.js:138`), with no chain check on the buyer's device.

## 2. The options

Recommendation marked. Cost is stated in what it takes to build, what it risks
to the deal, and what it does not do.

### (a) Do nothing, and document the risk for vendors

**Cost.** Zero code. A page in the vendor help text saying that a confirmed
payment can, in rare cases, be reorged away, and that the app cannot tell.

**Buys.** Nothing changes in the money path. No new failure can be introduced.

**Cannot fix.** Everything. The receipt still asserts a payment the chain may
not hold, the vendor still ships on it, and the warning reaches only vendors
who read it. It also moves the risk onto the least informed party, after the
fact, in prose.

### (b) Keep watching confirmed payments for a window, and only FLAG a vanished transaction — never un-confirm — RECOMMENDED

**Cost.** A new sweep: for a bounded window after confirmation, the device
keeps asking its own watcher about that one order, on a fixed schedule, and
records the answer. It touches no state machine, writes no new signed object,
and cannot un-confirm anything. The proposal is a 24-hour window with four
asks (15 minutes, 1 hour, 6 hours, 24 hours); **the window and the count are
the founder's numbers, not measured ones** — this page does not assert that
24 hours is the right depth, and the code's own thresholds (3 and 10) are the
only figures here taken from the app.

**What it costs in privacy.** Each ask tells the watcher that this device
still cares about that address. The watcher already knows the address, so this
is a small addition, not a new disclosure — but it is not free, and it is
worth one sentence on screen if the founder wants the wallet's usual honesty
about what a watcher learns.

**Buys.** The app finally fetches the answer that says a transaction is gone,
and says so while the vendor can still act — before shipping, or inside the
shipping window. It is strictly better than (a) and a fraction of (c).

**Cannot fix.** The receipt and the spent-transaction record still claim the
payment. The state still says confirmed. A vendor who has already shipped
still shipped; the flag only gives them grounds for a dispute. And the flag is
inert unless it reaches a person, which is the next section.

### (c) The full door: store the count, allow the state to step down, revoke the receipt and the spent-transaction record

**Cost.** The largest, and the most dangerous. It edits the one function that
a separate security fix (F7 — payment facts cannot be walked back by a peer's
claim) is built on. Making the state lowerable means deciding who may lower
it: only this device's own watcher report may lower a state this device wrote,
and the buyer's confirmed came from the vendor's receipt, not from the buyer's
watcher — so the buyer needs a signed **revocation** from the vendor, or its
own watcher, to lose the state. That is a new signed object, a new evidence
rule, and a new ordering rule in the derivation, which currently only ever
takes the maximum.

**Buys.** The app can say what is true: this payment is no longer on the chain.
A vendor has a state that matches the chain, and a buyer's card stops asserting
a payment that did not happen.

**Cannot fix.** Goods already shipped. It also makes a new mistake possible
that does not exist today — un-confirming a payment that is perfectly fine —
so every rule it adds is a chance to be wrong in the other direction. And it
cannot make the chain stable: it can only report.

## 3. For each option, what it cannot fix — and how a flag reaches a human

(a) fixes nothing, by construction. (c) cannot recover goods or make the chain
stable, and it adds a new way to be wrong. (b) cannot change any state.

A flag nobody looks at is not a defence, so (b) is only worth building if the
flag is pushed at a person. Concretely, and in order of how hard they are to
ignore:

1. **A mark on the order card that survives a reload and a history re-fetch.**
   The app already has this shape for a different refusal: `writeDeviceMark`
   (`src/features/chat/useCommerce.js:29`, used for the unreadable-record case
   at `:580`) writes a mark to storage, so the card keeps saying it after the
   toast is gone. The vanished-payment flag must be the same kind of object —
   stored, not held in a screen's memory, or the next message refresh erases
   it.
2. **A count on the orders list**, so the vendor sees it without opening the
   order. A flag only on the card is a flag behind a tap.
3. **A buzz.** A receipt names one transaction and buzzes; a typing indicator
   does not. A vanished payment is a money fact and should reach the device
   the way an order update does — the same push path, not a silent write.

What (b) should say, in words, matters as much as that it says anything: "The
chain no longer shows this payment" is a fact; "your payment failed" is a
conclusion the app cannot draw. The second sentence would be a lie in the case
where the transaction is re-mined on the winning chain a minute later, which
is the common case.

## 4. The migration cost of (c)

Two objects already sit on devices, and both are the ones a revocation would
have to reach. Neither may be deleted: the founder's rule is that commerce
data is sacred and the only wipe is the panic wipe.

- **Receipts** (`scopedSet('receipt_<order>')`, written at
  `useCommerce.js:629`). A receipt is signed and its hash is what a vouch
  names. A revocation cannot edit it — editing a signed object invalidates it
  and breaks every vouch that names its hash. So a revocation must be a
  **second signed object** that names the receipt's hash, stored beside it.
  Receipts already on devices need no rewrite: they carry no revocation, and
  absence means "not revoked". New code must read the pair.
- **Spent-transaction entries** (`scopedSet('consumed_txids')`, written at
  `:632`). Their job is to stop one transfer paying two orders. A revoked
  entry must keep that job: if the same transaction is re-mined on the winning
  chain, it is still the same transaction and still pays the same order, so the
  entry stays. If it never returns, the entry is a tombstone, not a payment —
  and it must not block the buyer's replacement payment, which is a different
  transaction and therefore a different entry. Entries written before (c) have
  no count and no revocation field; they are read as "confirmed, count
  unknown", never rewritten.
- **The derivation is the hard part.** `paymentEvidence` takes the maximum
  rank over all history and every sent update. A revocation must be able to
  outrank a receipt, which means the rule stops being a maximum and becomes an
  ordered fact: a revocation dated after the receipt wins. That rule must hold
  across a reload and a history re-fetch, or a re-fetch of the relay's copy
  will resurrect the confirmed state — the exact "state that lives only in
  memory" failure this project already treats as a bug class. Migration
  therefore includes proving that an old device with old receipts and a new
  device agree after both have re-fetched.
- **Two devices, one order.** A vendor's device and a buyer's device both hold
  a state. If the vendor's watcher says the payment is gone, the vendor's
  device can lower its own state; the buyer's cannot, and must not be told to
  by anything but a signed revocation. A design that lowers both from one
  watcher answer is a design where a vendor's watcher can un-pay a buyer.

## 5. Acceptance criteria, if (c) is ever built

Tests that must exist, red first, before anyone calls it done.

1. A stored confirmation count is written, survives a reload, survives a
   history re-fetch, and is the value the next scan compares against.
2. A lower count after confirmed moves the payment down — and every step the
   walk makes is named: confirmed to seen on a lower count; seen or confirmed
   to a vanished state when the watcher stops naming the transaction. It never
   falls below seen, because the address was issued and the money may yet
   arrive.
3. A count that falls and then rises again re-confirms, without skipping a
   step and without a stale count winning.
4. A vanished transaction reported after confirmed is visible on the order
   card, survives a reload and a history re-fetch, and the passing/failing
   test names the sentence on screen.
5. A receipt is revoked by a second signed object naming its hash; the buyer's
   card stops saying confirmed; a vouch that names the old receipt hash still
   verifies, and the order no longer counts as paid.
6. A spent-transaction entry is never silently deleted. The same transaction
   re-mined re-confirms the same order. A replacement payment on a new
   transaction is not blocked by the tombstone.
7. A forged revocation, a receipt from a third key, and a struck receipt are
   all refused — the F7 gate still holds, and no peer can lower this device's
   payment state by claim.
8. A device that has not itself fetched the contrary report never lowers: an
   un-confirm is never triggered by an incoming message alone.
9. Raising the threshold after a payment is confirmed does not retroactively
   lower it; the new threshold applies to the next report.
10. The full suite is green, and deleting the lowering edge reddens a named
    test title — a mutation that changes nothing is not evidence that the
    edge is guarded.

## 6. Numbers this page does not assert

- How often a reorg deeper than 3 or 10 blocks happens. The app has never
  counted, and this page does not invent a figure.
- What window is long enough for option (b). 24 hours and four asks is a
  proposal for the founder to accept or replace, not a measurement.
- Whether any vendor has already shipped against a vanished payment. Nothing
  in the app records that, and no device can be asked.

## 7. What this page decides

Nothing. It exists so the founder can rule between (a), (b) and (c) knowing
what each costs and what each leaves broken. The recommendation is (b), with
(c) designed and gated but not built until a real vanished payment is seen in
the field — because (b) is the only option that fetches the truth without
risking a payment that is perfectly fine, and it does not touch
`paymentState.js`, `paymentWatch.js`, `orderActions.js` or `useCommerce.js`.
