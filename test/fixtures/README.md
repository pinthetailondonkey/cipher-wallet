# Test fixtures

## bip158-testnet-19.json

The BIP-158 test vectors for basic block filters on testnet, from

    https://raw.githubusercontent.com/bitcoin/bips/master/bip-0158/testnet-19.json

Original file sha256 (a space after character 32 for the same reason, below;
remove it before checking):

    d9049756f744e561b882a8eff507582f b7cd74ed9cf5542bdac58257449ee2a2

**One transformation, applied and visible:** every bare 64-character hex string
(a block hash, a previous filter header, a filter header) has a single space
after its 32nd character. Everything else is byte-identical to the download,
and `test/filters.test.mjs` strips the space before use.

Why: `.githooks/pre-commit` refuses any added line containing a 32-byte hex
string, because that is what a leaked key looks like. A block hash looks the
same to a regular expression. The scanner stays on; the fixture carries a space
instead. To re-derive it, download the file above, check the sha256, and insert
a space after character 32 of each 64-character hex string.

## monero-crypto.txt

A bounded subset of Monero's generated crypto vectors, from

    https://raw.githubusercontent.com/monero-project/monero/3fd0f88c20f559839cafb20911cb13cb45eba7bd/tests/crypto/tests.txt

Pinned to that commit, not to master. The full source file sha256 (space after
character 32 for the reason above):

    98cf75c9c4bb48dc10d6e93b4b54767c fa32e66955c5ac4b8349eb627a603c18

This fixture's own sha256:

    e2b348e11b8c6b710c2f8a48682a371a 45cf0d5755fe923546a73909cfee8ffb

**Two transformations, both visible.** Lines are grouped by command in this
order, and each section keeps every positive vector up to this count:

    secret_key_to_public_key  32
    hash_to_scalar            32
    biased_hash_to_ec         64
    generate_key_derivation   32
    generate_key_image        32
    derive_public_key         32
    derive_view_tag           16
    derive_secret_key         all 256

Every refusal vector in a section is kept as well — Monero ends a section with
lines whose expected result is `false`, and there are 16 each in
`secret_key_to_public_key`, `generate_key_derivation` and `derive_public_key`,
48 in all. They come after the positive vectors, so the counts above are of the
positive lines and the file is 544 lines.

The first cut of this file said "the first N lines of each section" and that
silently dropped all 48, because they are at the ends. The negative controls are
the half that proves a value is refused rather than accidentally accepted, so a
cut that loses them is a cut that should fail loudly: the test asserts 16 per
section and 256 `derive_secret_key` lines, not just a total.

`derive_secret_key` is kept whole because it was missing entirely and is the
only in-repo pin for `deriveSecretKey`; the pairing test next to it is
structural and would pass with a shared wrong hash. The full source file is
8.4 MB and most of it is ring signatures this wallet does not implement yet, so
the rest stays cut.

Every 64-character hex field has one space after character 32, as above.
`test/monero-keys.test.mjs` rejoins the fields by the fixed arity of each
command and strips nothing else.

`generate_keys` lines were left out deliberately: Monero generates those with a
seeded PRNG, so they are reproducible inside Monero's test binary and not
derivable from the recorded values. `hash_to_point` was left out as well: it
tests a different function (unbiased, blake2b-based) that this wallet does not
use. The key-image path uses `biased_hash_to_ec`, which is here.

## monero-base58.txt

Monero's own base58 and address vectors, from

    https://raw.githubusercontent.com/monero-project/monero/3fd0f88c20f559839cafb20911cb13cb45eba7bd/tests/unit_tests/base58.cpp

Pinned to the same commit as the crypto vectors. Source file sha256:

    75c446818fc1c4be2906722de3b86cc1 52f2e80e4b33dcf660d1c9055be268b7

This fixture's own sha256:

    644f401b82ccbe995eabb4f9d32031f8 da8949544631fe4df8eec8f5e77cc67b

**Two transformations, both visible.** Each `TEST_...` line in that C++ file is
one row here, whitespace-separated, hex in lower case, in this shape:

    encode_block <data> <string>
    encode       <data> <string>
    decode_pos   <string> <data>
    decode_neg   <string>
    addr         <tag> <data> <address>
    addr_neg     <address>
    keys_addr    <spend and view keys> <address>

202 rows: 29 block encodings, 17 string encodings, 33 decodes, 85 refusals
(56 string-level plus 29 block-level), 21 address round-trips, 16 address
refusals, and one real account key pair with the address Monero makes from it.
That last row is the only one that pins an address to keys rather than to
itself. Hex payloads of 64 characters or more get a space every 32
characters — the same space-after-character-32 rule as above, repeated — and an
empty payload is written `-`. Without it a 128-character payload would contain
bare 64-character runs, which is exactly what the scanner refuses.

One vector in the source is not here: `decode_fails_due_invalid_char_00`, which
embeds a NUL byte in the address. A text fixture cannot carry it, so it is
stated as missing rather than quietly omitted. Nothing else is cut.

The tag column keeps the source's own spelling, so `0x1122334455667788` appears
as that rather than as decimal.

**This is settled policy, not a workaround.** The founder ruled on 2026-10-29:
the hook is never edited and no fixtures exception is ever added, so the space
after character 32 is the standing way to keep a published test vector in the
repository without weakening the scanner. Any future fixture containing a bare
32-byte hex value follows the same pattern and records its source checksum
here.

## monero-block-*.json (five real blocks)

Five real Monero mainnet blocks, bytes and ids taken from a monerod's own
`get_block` answers by `scripts/fetch-monero-block-fixture.mjs` — the same node
door the wallet uses at runtime (`CIPHER_XMR_NODE`, the only override; no node
list, no explorer, ever). All were captured from `xmr-node.cakewallet.com:18081`
through Tor (`curl --socks5-hostname` via `127.0.0.1:9050`), so the node never
saw this machine, on 2026-10-30. The node answered `get_info` with no version
string at all, at every ask; that silence is recorded in each file rather than
papered over with a version the node did not give.

The blocks were chosen for what they prove together, not for being remarkable:

    monero-block-mainnet.json    height 3795294, 6 transactions, tree of 7, v2
    monero-block-mainnet-b.json  height 3795284, 4 transactions, tree of 5, v2
    monero-block-mainnet-c.json  height 3795290, 0 transactions, tree of 1, v2
    monero-block-202612.json     height 202612, 513 transactions, v1 — the chain's one exception
    monero-block-v1-early.json   height 100, 0 transactions, v1 — plain, unentangled

Counted per rule: the v2 rules have three witnesses — tree shapes 7, 5 and 1
cover the branches Monero's tree hash produces, and three blob lengths give the
block id's length fold three shots at being wrong. The v1 coinbase rule has
two: block 100 is a plain pre-RingCT coinbase, and 202612 is the same rule
inside the one block whose id Monero overrides — pinned so the exception's
constants are proven by the bytes they bind, and so the one abnormality on the
chain never testifies about itself alone.

Each file carries: the block blob, the daemon's claimed id, previous id, miner
transaction id and transaction-hash list, the parent's claimed id (the child's
header must name it — Monero's own chain rule, checked at capture and re-proven
by the test), the daemon's nettype and tip at capture, and the transport used.
Fixture sha256s, a space after character 32 as always:

    monero-block-mainnet.json    e79e6c9980d3607d2f5eba7cc535d2f8 9dd718e2a210499f7f77a4533199ce80
    monero-block-mainnet-b.json  370d1593ed040d9e4f2939ae5c1ac4f2 0910ba180e975c904154029f8250934f
    monero-block-mainnet-c.json  38ce6f663c86b77bd6009b49a45be8d7 7d467e24ad26730c6fd3c4363b3614ca
    monero-block-202612.json     2edaa51cd8cdcfc089291d547bf2cb2c 68ee99ded59c7e131fadc29b2fd934a9
    monero-block-v1-early.json   fc82a345957b613a46988cc50449ea30 0c16c6ad0e6cb1a646a106e7d7fe0d7a

**One transformation, applied and visible:** every hex field — the blob
included — is written with a space every 32 hex characters, per the settled
policy above. Nothing else is transformed; the bytes are the daemon's own, and
`test/monero-block.test.mjs` strips whitespace before use.

To re-derive, point the capture script at any mainnet node (through Tor or not,
your call) and pin the same heights:

    CIPHER_XMR_NODE=<host:port> CIPHER_TOR_SOCKS=127.0.0.1:9050 \
      node scripts/fetch-monero-block-fixture.mjs --height 3795294
    ... --height 3795284 --out test/fixtures/monero-block-mainnet-b.json
    ... --height 3795290 --out test/fixtures/monero-block-mainnet-c.json
    ... --height 202612 --out test/fixtures/monero-block-202612.json
    ... --height 100   --out test/fixtures/monero-block-v1-early.json

A mined block never changes, so re-capture at these heights reproduces the same
blob, ids and hash list byte for byte; only the capture metadata (tip, time)
moves. The daemon's claims are recorded as a stranger's claims: what these
fixtures pin is the bytes, and the proof that the ids belong to those bytes is
this repository's own parser in `test/monero-block.test.mjs`, which computes
each id from the blob and refuses any disagreement.

## monero-node-client-block-answer.json

One real monerod `get_block` answer for height 3795294, pinned for its SHAPE:
the daemon sends its own parsed copy of the block as a STRING in `json`, and
its claims (hash, height, prev_hash, miner_tx_hash) at the TOP LEVEL in
`block_header`. The node client's claim check once read
`result.json?.block_header` — an object lookup that never fires against the
string a real daemon sends — so the check was dead while its test stayed
green, because that test passed `json` as an object. Same node and transport
as the block fixtures, same day; `test/monero-node-client.test.mjs` serves
this answer to the client and proves a lying claim throws.

Fixture sha256, spaced as always:

    736dfdda312af557eb728ff2cbda7909 48940a173ac61e1d88444135c2bf429e

**Transformations, visible:** every hex field of 64 characters or more carries
a space every 32 characters, and `json` is stored PARSED and re-stringified by
the test when serving — a real daemon sends it as a string and the client must
meet it as one. The `json` contents are spaced too. The client reads exactly one
thing from them: `tx_hashes`, the block's transaction list, which it checks
against `num_txes` and carries home as `txHashes`. Those hashes are the
block's own list, the same list `monero-block-mainnet.json` pins; the test
checks the two agree. The blob and ids equal
`monero-block-mainnet.json` exactly, which is the re-derivation check for this
file — a raw answer carries `depth`, which moves with the tip, so the raw
bytes are not expected to hash the same twice.

## monero-tx-ringct-type6.json

One real Monero mainnet NON-MINER transaction: version 2, RingCT type 6
(Bulletproof+ with CLSAG), 2220 bytes, id

    ed77f05e2a61c2a636e3923e7bb50a4f 8fc16a3fe7f3c4a408f3c9849fa4abbc

It sits at index 0 of block 3796965, whose hash is

    1777215e7b0758dced972b7191c2f2d2 6e22fd6212d38893d5fac05dffec1a99

The block has 33 transactions. Captured 2026-11-01 from
`xmr-node.cakewallet.com:18081` through Tor (`curl --socks5-hostname` via
`127.0.0.1:9050`): `get_block` for the block and its `tx_hashes`, then REST
`/get_transactions` for this id. The node's own claims (`tx_hash`,
`prunable_hash`) are recorded as claims and never trusted by the parser.

The file's own sha256, spaced as always:

    1c6c2da45d930cc3dc0a3442a27ab0f8 bbe08bfb80a4f9b3e10734ff649bf47c

**Transformations, visible:** `asHex`, `txHash`, `blockHash` and
`claimedPrunableHash` carry a space every 32 hex characters, per the settled
policy above. The test strips whitespace before use. Nothing else is changed.

What this fixture pins is the BYTES. The id is proven by this repository's
parser from those bytes alone, in `test/monero-tx-read.test.mjs`.

Re-derive: fetch block 3796965 and the transaction as above, and check the
sha256 of the bytes against `source.blockHash` and `txHash`.

## monero-tx-1in-manyout.json

One real Monero mainnet NON-MINER transaction: version 2, RingCT type 6
(Bulletproof+ with CLSAG), 1535 bytes, 1 input and 2 outputs, id

    4ab654156cd0f2b0cb576c14e2653c5a c328ba8f6fc1841ef10897d34bbe2021

It sits at index 1 of block 3796965 (33 transactions), captured 2026-11-01
from `xmr-node.cakewallet.com:18081` through Tor via
`scripts/fetch-monero-tx-fixture.mjs --shape 1in-manyout`. Same provenance
block as `monero-tx-ringct-type6.json`: `get_block` for the block and its
`tx_hashes`, then REST `/get_transactions` for this id.

This is the Lane A corpus shape "1 input / many outputs". The node's claims
(`tx_hash`, `prunable_hash`) are recorded as claims and never trusted.

The file's own sha256, spaced as always:

    9ceaf363aeeb7290e55d62368f21d662 cb124528e531a87de95bb6a6f5705538

**Transformations, visible:** every hex field carries a space every 32 hex
characters; the test strips whitespace before use. The id is proven from the
bytes alone by `test/monero-tx-corpus.test.mjs`, which runs the needle and the
four mutated-bytes controls (prefix, base, prunable, tail) on every
`monero-tx-*.json` fixture.

## monero-tx-manyin.json

One real Monero mainnet NON-MINER transaction: version 2, RingCT type 6
(Bulletproof+ with CLSAG), 19407 bytes, 27 inputs and 2 outputs, id

    97cbc8f9d80ceffcb985ba12205e8896 67c2a0c95adb0b36f619e9b78c17d20a

It sits at index 2 of block 3796992 (4 transactions), captured 2026-11-01
from `xmr-node.cakewallet.com:18081` through Tor via
`scripts/fetch-monero-tx-fixture.mjs --shape manyin`. Same provenance block
as the other Lane A fixtures.

This is the Lane A corpus shape "many inputs (3+)". The node's claims are
recorded and never trusted; the id is proven from the bytes alone.

The file's own sha256, spaced as always:

    004d5e96c2b983c51dde8d2c4fe3352f 22706ba7e6b2630b10de1c3f48d07f0c

Id and controls are proven by `test/monero-tx-corpus.test.mjs`, which runs
the needle and the four mutated-bytes controls on every `monero-tx-*.json`
fixture.

## monero-tx-type3-1in.json

One real Monero mainnet NON-MINER transaction: version 2, RingCT type 3
(RCTTypeBulletproof: a Bulletproof1 range proof with an MLSAG), 1911 bytes, 1
input and 2 outputs, id

    37c26ae22cd23ebb5d1333aed66e6cf1 073a65c52e0f6c40928651deba084e51

It sits at index 1 of block 1750000, whose hash is

    a9262002d78adc4829a5d5ea0be47e31 d0b47f819f394a4f0f108d516a4831f1

Captured 2026-11-02 from `xmr-node.cakewallet.com:18081` through Tor (`curl
--socks5-hostname` via `127.0.0.1:9050`) with `scripts/pin-tx.mjs`. The node's
claims are recorded and never trusted; the id is proven from the bytes alone.

This file once said `type5` in its name while the type is 3; it is renamed for
its type, and `monero-tx-type3-2in.json` is the multi-input witness beside it.
The full base-and-prunable layout is written out in the fixture's own
`source.layout`, resolved by reading the pinned `rctTypes.h`.

The file's own sha256, spaced as always:

    ee90a17a50fdb8878bfd6a721d15e9a4 54b764c2decb774e03d9db2d00b33db1

Id and controls are proven by `test/monero-tx-corpus.test.mjs`.

## monero-tx-type3-2in.json

One real Monero mainnet NON-MINER transaction: version 2, RingCT type 3
(RCTTypeBulletproof), 2707 bytes, 2 inputs and 2 outputs, id

    d2e04503b2db017f729388dbea4f8a74 17e7eabc624978074b08a6cdeaebfd7c

It sits at index 5 of the same block 1750000, captured the same way. It is the
witness for the MLSAG dimensions: type 3 is the simple layout, one MLSAG per
input, so `ss` is (mixin+1) rows by two columns with one `cc` each. A walk that
used one row per input plus an aggregate and a single `cc` (the Full layout)
agrees with this only when there is one input, and against this fixture walks
384 bytes short and computes the wrong id. The 1-input pin could not see it.

The file's own sha256, spaced as always:

    1160e8d765ac34bb73015ea39b49ba4a 7c0d82a87b61d8bc3902db5484121a8d

Id and controls are proven by `test/monero-tx-corpus.test.mjs`.

## monero-tx-rct-{1,2,4,5}.json

The four RingCT types this reader did not cover, pinned so it could learn them.
Each is ONE real mainnet non-miner transaction, captured over Tor by
`scripts/pin-tx.mjs`, at the height and hash-list index recorded in its own
`source` block.

Provenance is complete per fixture: node, nettype, transport (Tor socks5-hostname,
so the node saw an exit), capture timestamp, block height and hash, transaction
index plus BOTH index conventions (`txIndexInBlock` is 1-based with the miner at
0; `txHashListIndex` is 0-based and is what a re-deriver indexing `tx_hashes`
must use), the endpoint pair, a `rederive` recipe, and the layout the type
carries. `sha256` is over the file as committed, with a space after character 32
for the pre-commit hook, so remove the space before checking.

| type | name | height | hash-list index | bytes | sha256 |
|---|---|---|---|---|---|
| 1 | RCTTypeFull | 1600000 | 0 | 13192 | `006e9a25cc2d639578e73666a599b606 8ae8b08543f4d121622ee7b85d2713b4` |
| 2 | RCTTypeSimple | 1500000 | 0 | 13524 | `05c3697969ffa39556cf1fd2882d61c6 9cc2b38bfe7b28fcfc226b0018ab647c` |
| 4 | RCTTypeBulletproof2 | 1800000 | 0 | 2629 | `3a205e1e5c068ccf0c8632061c3e578e 82cfa99b82795689cfb5919ac4b07bb2` |
| 5 | RCTTypeCLSAG | 2300000 | 0 | 1451 | `e374e63ffc765ecf03760048770dfc4a c09d24c60ea150565ec8902bfbf36cf4` |

Shape notes, because each is a trap rather than a detail:

- **Type 1 (Full)** writes **one** MLSAG for the whole transaction. The matrix is
  `mixin + 1` rows by `inputs + 1` columns, so "one MLSAG per input" is correct
  for type 2 and wrong here.
- **Type 2 (Simple)** is the only type that writes `pseudoOuts` in the **base**,
  before `ecdhInfo`. Every Bulletproof-family type writes them in the prunable
  instead; Full writes none at all.
- **Types 1 and 2** use **Borromean** range proofs, one per output, each 193
  keys. Types 3, 4, 5 and 6 use Bulletproof proofs, whose count is a raw 4-byte
  FIELD for type 3 and a varint for 4, 5 and 6.
- **Types 4 and 5** are the compressed-ecdh types: eight bytes of truncated
  amount per output and **no mask**, which is derived rather than carried. Types
  1, 2 and 3 carry a 32-byte mask and a 32-byte amount.

**Input counts, and one honest hole.** Types 2 and 4 here have two inputs each, so
the per-input and per-output terms are both exercised on those. The type 1 and
type 5 samples have ONE input each. For type 5 that costs nothing, its CLSAG
block is exactly `ringSize + 2` keys and was proved on an earlier fixture. For
type 1 it does cost something: the Full matrix is `inputs + 1` columns, and with
one input that term is only ever tested as 2. A two-input type 1 would settle it
and has not been found - sweeps of 1180000-1340000 and 1390000-1700000 at a
500-block stride returned none.

Then the source explains why, and it shrinks the hole: cryptonote_tx_utils.cpp:549
is `use_simple_rct = sources.size() > 1 || range_proof_type != RangeProofBorromean`,
so the non-simple (Full) version is chosen only for exactly ONE source under
Borromean, and Simple is taken as soon as there is more than one. Full is in
practice a single-input shape. Measured rather than assumed: two disjoint sweeps
(1550000-1600000 and 1240000-1290000, stride 300/200) covered 185 type-1
transactions and found **zero** multi-input.

So the `inputs + 1` term is real in the serializer but is always 2 on chain, and
this fixture is representative of every Full transaction there is. What remains
unwitnessed is only the `> 2` case, which would need a hand-built transaction,
not a chain search. Do not read this fixture as pinning anything beyond that.

The type numbering is the `rctTypes.h` enum at the pinned commit, where 3 is
Bulletproof and 6 is BulletproofPlus, so 4 and 5 are Bulletproof2 and CLSAG and
not "more Bulletproof".

## monero-get-outs-answer.json — one live /get_outs answer, verified against the chain

The ring door's only witness. A ring member is in no transaction (a transaction
names its ring by POSITION, not by key), so unlike every other fixture here
these keys cannot be proven by re-parsing bytes the wallet holds. What the
capture does instead is prove them against the chain in the same run:
`scripts/pin-outs.mjs` asked for the absolute positions of a real input's ring,
then for EACH answer fetched the block at the height the node named, parsed it,
proved the named transaction is in that block's own hash list, fetched that
transaction, and found the key among its outputs.

The request is not invented: the indices are the absolute positions of
`monero-tx-rct-5.json`'s own input, so the offsets the wallet computes for a real
ring are what a node was actually asked about. Heights came back older than that
transaction's block, which is what a ring of decoys must be.

What is NOT pinned: the block and transaction bytes behind the recorded
verification, so the test asserts the recorded conclusions rather than
re-deriving them. Re-deriving means re-running the script, which needs a node.
Provenance, node and re-derive recipe are in the fixture's `source`.
