# AUDIT c5ed375 (Lane D node driver), base 842f133

Auditor: Lane A. HEAD moved to d47803f mid-audit (another lane); findings are about
c5ed375's src/monero/scanFromNode.js, test/scan-from-node.test.mjs, scripts/scan-live.mjs.
Every claim recomputed, not read.

Target files (committed test run in place as `test/zz-audit-committed.test.mjs`):
```
$ git show c5ed375:test/scan-from-node.test.mjs > test/zz-audit-committed.test.mjs
$ node --test test/zz-audit-committed.test.mjs   # 7/7 pass (committed suite green)
```
Live reproduction of the commit's live claim:
```
$ CIPHER_XMR_NODE=xmr-node.cakewallet.com:18081 node scripts/scan-live.mjs --height 3796965
block     1777215e7b0758dced972b7191c2f2d2 6e22fd6212d38893d5fac05dffec1a99
scanned   34 transaction(s)
owned     0
took      4844 ms
```

---

## A. Hash-request identity

Attack: asked hash `00*32`, node claims `00*32` (so the fetch claim-check PASSES) and
serves block 3796965's bytes. If only the cheap claim check existed, this would pass.

```
[A2 asked 00.. claim 00..] REFUSED: That block proves the id 1777215e..., not 000...0.
  The bytes and the id do not agree, so neither travels further.
```
The refusal comes from `parseBlock(..., {expectHash})` inside `ownOutputsInBlock`, i.e.
the byte-level proof, and it runs before `walkBlockTxs`/`scanOne`, so no pocket sees
bytes. A node cannot get past BOTH: claim-check fires when `claimed.hash !== asked`, byte
proof fires when `id(bytes) !== asked`; setting `claimed.hash = asked` only moves the
refusal to the byte proof. Omitting `block_header` entirely still leaves the byte proof
(probe A2 is exactly that shape with the claim aligned). The committed test 2 does
exercise the byte proof, not the claim check (its stub aligns the claim with the ask).

VERDICT: VERIFIED.

## B. Height-request path

Attack 1: serve a DIFFERENT block (3795290) as bytes while requesting height 3796965 and
claiming height 3796965.
```
[B height request, other block, faithful height claim] RESOLVED
  blockId=fc39a116b90b56da scanned=1 claimedHeight=3796965
```
So the driver accepts a block that is not at the requested height. Confirmed why: a
Monero block HEADER has no height field (`block.js parseBlockHeader`), so height is not
recoverable from one block's bytes at all. The only link to N is the node's own
`block_header.height` claim, checked in `getBlock`. `fetched.claimedHeight` is never
compared by the driver; it is only echoed as `nodeClaimedHeight` (grep: scanFromNode.js
line 70, nowhere else). And with `block_header` absent the height check is skipped too:
```
[no block_header at all (height request)] RESOLVED scanned=34 id=1777215e7b07
```
Attack 2, tautology: the height branch does `const proven = parseBlock(blob)` then
`ownOutputsInBlock({..., expectHash: proven.id})`, which calls `parseBlock(blob,
{expectHash: proven.id})` on the SAME bytes. `parseBlock` is deterministic, so the
second proof can never fail; it re-derives an id from bytes and checks it equals an id
derived from those same bytes. No external anchor, only internal self-consistency.

VERDICT: PARTIAL. Behaviour is defensible for one block, but header/commit overclaim it.

## C. Fetch shape

`getBlock`'s list is the daemon's claim; the binding is `walkBlockTxs`, which compares
count and each fetched id, index by index, against `parseBlock`'s own hash list (from
bytes). The only "hole" is that `getTransactions` never checks returned txid == requested,
so a node may return correct bytes for a mislabeled requested hash. Two probes:
```
[C claim swapped, bytes match claim]  ... (bytes fabricated to match the swap) ->
[probe4 swapped claim + swapped bytes] REFUSED:
  bytes and list do not agree: hash-list index 0 claims ed77f05e..., the bytes prove 4ab65415...
[C2 claim has junk hash (zz...)] REFUSED: ... without a transaction hash list this build can read.
```
A claim whose LENGTH disagrees with the body, and a claim that is empty for a 33-tx body:
```
[empty claimed tx list for 33-tx block] REFUSED:
  the count and the list do not agree: the block lists 33 transactions, 0 were fetched
```
`num_txes` cross-check is live and correct against the real daemon: it is read from
`block_header.num_txes` where monerod actually puts it, and compared to the json list:
```
[live get_block] block_header keys include num_txes=33; json is a string; json has tx_hashes len 33, no num_txes
[json tx_hashes 33, header num_txes 34] REFUSED: ... said the block holds 34 transactions and listed 33.
```
Non-64-hex and short/long-consistency both caught. No block is scanned whose list escaped
the body comparison.

VERDICT: VERIFIED (the disagreement is caught, at the walk, by count and by bytes).

## D. Stub vs real daemon

Pinned real answer `test/fixtures/monero-node-client-block-answer.json` and a fresh live
`get_block`/`get_transactions` on xmr-node.cakewallet.com. Real shape:
- `json` is a STRING containing `tx_hashes` and NO `num_txes`;
- `num_txes` lives in `result.block_header`;
- `get_transactions` answers at TOP level `{status, txs, missed_tx?}`, `txs[i]` carries
  `as_hex` and `tx_hash`, and `missed_tx` is OMITTED when empty; an absent hash is moved
  into `missed_tx` and dropped from `txs`.

Committed stub diverges on two axes:
```
[real] num_txes in block_header, json has none.
[stub] num_txes in json, block_header = {height, hash} only.
=> committed-stub shape, json.num_txes=999 over an empty list: ACCEPTED, count check BYPASSED
   real-shape num_txes=999 in block_header: REFUSED "...holds 999 transactions and listed 0"
```
So the stub never exercises `readTxHashes`'s num_txes cross-check (block_header has no
num_txes), and it also fabricates a tx entry with `as_hex: undefined` for an absent hash
and always sends `missed_tx: []`, where a real node moves it to `missed_tx`. Its
`txs[i].hash` also differs from real `tx_hash` (client ignores it, so harmless). json-as-
string and top-level REST shape DO match reality. (The lane has since committed d47803f
that filters to `missed_tx`; the committed c5ed375 stub does not.)

VERDICT: PARTIAL. Test runs, but its fetch-accounting shape is not the daemon's.

## E. Honesty

Honest parts: header explicitly disclaims a range walk and spendability; commit's live
claim reproduced (34 txs, ~4.8s, empty); "no pool by default" matches code.

Overclaims:
1. Header: "the two checks together mean a node cannot serve a different block than
   either one" and "the proof is re-run against the proven id". On a height request the
   re-proof is a tautology (B) and there is no height anchor, so the block MAY be a
   different block; the sentence implies more binding than exists.
2. Commit: "getTransactions for the block's own hash list". It is the DAEMON's claimed
   list driving the fetch; the block's own list only appears later inside the walk.
3. Header's "the id is proven from the bytes first" is true, but reads as if it settles
   the requested height; nothing about the height is proven from bytes (header has none).

VERDICT: PARTIAL.

---

OVERALL: order and byte-level block proof are real and the disagreement is caught; but
the height path's re-proof is a tautology with no single-block height anchor, and the
stub's num_txes/missed_tx shape is not the daemon's.
