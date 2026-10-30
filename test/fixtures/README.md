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

## monero-block-mainnet.json, -b.json, -c.json

Three real Monero mainnet blocks, bytes and ids taken from a monerod's own
`get_block` answers by `scripts/fetch-monero-block-fixture.mjs` — the same node
door the wallet uses at runtime (`CIPHER_XMR_NODE`, the only override; no node
list, no explorer, ever). All three were captured from
`xmr-node.cakewallet.com:18081` through Tor
(`curl --socks5-hostname` via `127.0.0.1:9050`), so the node never saw this
machine, on 2026-10-30. The node answered `get_info` with no version string at
all, at every ask; that silence is recorded in each file rather than papered
over with a version the node did not give.

The blocks were chosen for what they prove together, not for being remarkable:

    monero-block-mainnet.json    height 3795294, 6 transactions, tree of 7
    monero-block-mainnet-b.json  height 3795284, 4 transactions, tree of 5
    monero-block-mainnet-c.json  height 3795290, 0 transactions, tree of 1

Tree shapes 7, 5 and 1 are the branches Monero's tree hash has on this chain —
the odd-count verbatim fold at 7 and 5, the single-hash tree at 1 — and the
three blob lengths (1734, 357, 141 bytes) give the block id's length fold three
witnesses instead of one. One pair can be a coincidence; three cannot.

Each file carries: the block blob, the daemon's claimed id, previous id, miner
transaction id and transaction-hash list, the parent's claimed id (the child's
header must name it — Monero's own chain rule, checked at capture and re-proven
by the test), the daemon's nettype and tip at capture, and the transport used.
Fixture sha256s, a space after character 32 as always:

    monero-block-mainnet.json    e79e6c9980d3607d2f5eba7cc535d2f8 9dd718e2a210499f7f77a4533199ce80
    monero-block-mainnet-b.json  370d1593ed040d9e4f2939ae5c1ac4f2 0910ba180e975c904154029f8250934f
    monero-block-mainnet-c.json  38ce6f663c86b77bd6009b49a45be8d7 7d467e24ad26730c6fd3c4363b3614ca

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

A mined block never changes, so re-capture at these heights reproduces the same
blob, ids and hash list byte for byte; only the capture metadata (tip, time)
moves. The daemon's claims are recorded as a stranger's claims: what these
fixtures pin is the bytes, and the proof that the ids belong to those bytes is
this repository's own parser in `test/monero-block.test.mjs`, which computes
each id from the blob and refuses any disagreement.
