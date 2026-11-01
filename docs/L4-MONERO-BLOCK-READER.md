# L4 — the Monero block reader: built wrong, withdrawn, rebuilt on real bytes

This page records what this repository built for reading Monero blocks, what a
review found in it, what the withdrawal was for, and what the code does now.

**One sentence:** the first reader refused to prove a block's identity and then
turned out not to read Monero's block layout at all; the reader this repository
ships now names a block the exact id its own node says it has — proven against
five pinned real blocks — and refuses everything it cannot prove.

## What was built, and what review found

Commit `80ba48d` added a strict parser, a node client, 22 tests, and a green
gate of 382. Review (ADJUDICATOR) executed two defects in it:

- **F1 — the body model was wrong.** Monero's block blob is
  `header || miner_tx || varint(tx_hash_count) || 32-byte hash × count`.
  The parser read a full transaction after the count, and its own test writer
  built that same fictional layout, so every test passed against bytes no node
  emits. Measured both ways after the review: the real shape throws, the
  fictional shape is accepted.
- **F2 — the version 2 transaction id rule was never Monero's.** A v2 id is
  `cn_fast_hash(prefix_hash || base_rct_hash || prunable_hash)`. The parser
  hashed the prefix alone and included the RingCT type byte inside it. Every
  real miner transaction is version 2, so every id it would have emitted was
  wrong — and the test checked only that the id was 64 hex characters.

The reason 382 tests were green is the part worth keeping: **the parser and its
fixtures were written by the same hand.** A fixture built by the code under test
proves only that the code agrees with itself. This repository had already
written that rule into the module header as a reason not to pin the block id
rule against our own writer — and then built the body model inside the same
loop.

The withdrawal that followed refused every body rather than guess, and named
what would reopen the door: one real `(bytes, hash)` pair from Monero's own
output, pinned with provenance. That is what happened next.

## What the code does now

- `parseBlockHeader(bytes)` — unchanged in substance. Two version varints, a
  timestamp, the previous id, a four-byte nonce. Tested field by field, with a
  cut header refused as a header.
- `parseBlock(bytes)` — reads the real layout: the miner transaction in full,
  the other transactions as the 32-byte hashes the blob carries, the walk
  ending exactly at the last byte. It proves the id: the version 2 transaction
  id rule as Monero writes it, the transaction tree, and the block id with the
  fold that is easy to miss — Monero hashes the hashing blob through the
  string serializer, so a varint of the blob's byte length rides ahead of the
  bytes. A caller who knows the id passes `expectHash` and a disagreement
  refuses. Five pinned real blocks judge it, and mutated copies of the same
  bytes refuse.
- **Version 1, exactly this far and no further:** the miner's own transaction
  is read — a v1 coinbase serializes as its prefix alone, so its id is
  keccak(prefix), proven on block 100 and block 202612 — while a v1 transaction
  that is not the miner's is refused by name, because its signatures section
  has no pinned proof. **This build identifies a v1-era block but cannot read a
  v1-era transaction that is not the miner's: a scan across pre-RingCT heights
  proves each block's id and still cannot read what rides inside it, so an
  empty result there means "not read", never "nothing there".**
- **Block 202612**, the one exception on the chain, is handled in Monero's own
  order: the computed id first, then the recorded id only when the walked
  height says 202612 AND the raw blob's hash equals Monero's constant. The
  height is a claim read out of the bytes; the blob hash is the binding, and a
  test flips one byte of the real block to prove it.
- `src/monero/nodeClient.js` — the claim check now reads the top-level
  `block_header`, where a real daemon puts its claims; it once read
  `result.json?.block_header`, which never fires against the string a real
  daemon sends, and its test passed `json` as an object — the same
  fixture-writer's trap, in the door. A pinned real answer now serves the
  suite: a lying hash or height throws. It also returns the block's own
  transaction hash list (`txHashes`) from the daemon's parsed copy, checked
  against `num_txes`; the previous reader dropped it, so a scan built on
  `getBlock` was blind. The rest held in review: a deadline
  that runs through the body read, another host refused, non-2xx refused, not
  JSON refused, wrong network refused, still syncing refused, one pinned node
  per scan. One known minor stands: `sameHost` drops a default `:80` from
  `response.url` while `cleanNode` keeps it, so a `:80` node is refused —
  fail-closed, and worth knowing rather than fixing in a hurry.
- `readTransaction(...)` — the same reader that serves the block's miner
  slot is now also callable for a NON-miner transaction. A version 2 RingCT
  type 6 (Bulletproof+/CLSAG) transaction is read and its id proven from its
  bytes alone; the node's `tx_hash` and `prunable_hash` are never trusted.
  This is reads-only: the base is skimmed (fee, one eight-byte amount per
  output, one commitment per output) and never amount-decoded, and no scan or
  spend path uses it. The block's miner slot is unchanged: a miner transaction
  of any non-Null RingCT type is still refused by name.

## The non-miner transaction read, red-first

The type-6 needle test —
`THE NEEDLE: the real RingCT type 6 transaction reads, and its id is the
node's tx_hash` — was written first and failed against the then-current
reader with the refusal it names:
`That fixture transaction carries RingCT type 6. Every miner transaction
Monero has mined since RingCT is type Null ... deliberately refused read`. The
refusal was the red state; the same failing assertion, against the pre-fix
reader, is in this repository's own `test/monero-tx-read.test.mjs` history. The
green commit then made it pass and added four mutated-bytes controls that flip
one byte in the real bytes — prefix, base, prunable, and prunable tail — each
forcing an id change or a refusal, so the id is proven to depend on every
section and on nothing the node claimed.

## The tests, and the one that matters

- `THE NEEDLE: every pinned pair — this reader names each block the id its node
  says it has` — five blocks: transaction tree shapes 7, 5, 1, 514 and 1, two
  transaction-id eras, and the exception block. This is the one test a
  self-written fixture could never satisfy; every rule in the reader feeds the
  ids it checks.
- Six controls mutate the REAL bytes — a wrong claim, a flipped nonce, a
  flipped byte inside the miner transaction, a flipped walked hash, a trailing
  byte, and one flipped byte of block 202612 proving the exception is bound to
  the exact bytes, never to the claimed height.
- Refusal shapes, built synthetically and labelled as shape tests: the
  fictional layout from the first version, a truncated blob, a v1 transaction
  with key inputs, a non-Null RingCT type, a first transaction that is not the
  coinbase, a malformed claim.
- Tree unit pins for the small branches, from tree-hash.c's own rules.

The node client's real-shape tests were written red-first: three failed against
the dead check before the fix, by name.

## What this page does not claim

- It does not claim the reader reads transactions broadly. It reads the block's
  miner transaction and, on its own, one pinned non-miner RingCT type 6
  transaction whose id is proven from its bytes. It does not read other
  transaction types or amounts, and a scan that must identify a non-miner
  transaction before decoding it is still later work.
- It does not claim the node client is a chain reader. It fetches bytes and
  cross-checks the daemon's cheap claims; the identity is proven from the
  bytes.
- It does not claim anything here is part of the shipped messenger: this
  repository is a separate product with its own history, and its tip does not
  appear in the launch cut.

## Correction kept in the open

An earlier version of this page said refusals 4 and 5 had "no test of their
own" three lines under a table that named their tests — drift inside the commit
that created the page, on a page claiming it quoted the code so it could not
drift. The table and the internals it described are gone with the withdrawn
reader; the lesson is not, and it is why this page states what the tests assert
rather than what the code is supposed to do. A second drift was caught before
it shipped: this page still described the reader as refusing every body after
the rebuild landed, and was rewritten the same day.
