# L4 — the Monero block reader: built, reviewed, withdrawn, refused

This page records what this repository built for reading Monero blocks, what a
review found in it, and what the code does now. It is short because the honest
answer is short.

**One sentence:** the reader refused to prove a block's identity and then turned
out not to read Monero's block layout at all; it now parses a header and refuses
every body, out loud, and a test asserts the refusal by name.

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

## What the code does now

- `parseBlockHeader(bytes)` — unchanged in substance. Two version varints, a
  timestamp, the previous id, a four-byte nonce. Tested field by field, with a
  cut header refused as a header.
- `parseBlock(bytes)` — refuses **every** input, with a sentence that names the
  byte model, the transaction id rule, and what would have to exist first: one
  real `(bytes, hash)` pair. There is no flag that opens it; an opt-in would be
  the same trap with a better-sounding name.
- `src/monero/nodeClient.js` — unchanged. Its guards held in review: a deadline
  that runs through the body read, another host refused, non-2xx refused, not
  JSON refused, wrong network refused, still syncing refused, one pinned node
  per scan. One known minor: `sameHost` drops a default `:80` from
  `response.url` while `cleanNode` keeps it, so a `:80` node is refused —
  fail-closed, and worth knowing rather than fixing in a hurry.

## The tests, and the one that matters

- `F1: a blob in the shape a real node returns is refused, and the refusal
  names the byte model` — the real layout must not be mistaken for a cut-short
  varint.
- `F1: the fictional layout this repository used to build is refused too, so a
  fixture cannot reopen the door` — the old test writer's layout is refused as
  well, which is what stops the trap from re-forming.
- `F2: no transaction id is emitted for a version 2 transaction, because that
  rule was never Monero's` — the shape every real miner transaction has must
  produce no id at all.
- `THE GAP: a block has no proven identity, and a caller asking for
  verification is refused like everything else`.

Red-first was proved by running these against the old module at `80ba48d`
before the fix: **4 red, 2 green** (the two header tests are the controls).
The mutation that removes the refusal reddens the same four by name, counted
4 of 6.

## What would reopen this

One real `(bytes, hash)` pair from Monero's own output, pinned in
`test/fixtures` with provenance the way the other vectors are pinned, and a body
model built to it: miner transaction inline, then the hashes of the others, with
those transactions fetched separately. The transaction id rule then needs the
real base and prunable sections, not a guess. Until then a wrong identity is
worse than none, and this build emits none.

## What this page does not claim

- It does not claim the reader is complete. It claims the door refuses.
- It does not claim the node client is a chain reader. It fetches bytes.
- It does not claim anything here is part of the shipped messenger: this
  repository is a separate product with its own history, and its tip does not
  appear in the launch cut.

## Correction kept in the open

An earlier version of this page said refusals 4 and 5 had "no test of their
own" three lines under a table that named their tests — drift inside the commit
that created the page, on a page claiming it quoted the code so it could not
drift. The table and the internals it described are gone with the withdrawn
reader; the lesson is not, and it is why this page states what the tests assert
rather than what the code is supposed to do.
