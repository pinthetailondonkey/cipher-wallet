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

    6d706ee09d12cbad30c00d681d349068 3173497aa037d0007957af01259f8a2f

**Two transformations, both visible.** Lines are grouped by command in this
order and cut to these counts:

    secret_key_to_public_key  32
    hash_to_scalar            32
    biased_hash_to_ec         64
    generate_key_derivation   32
    generate_key_image        32
    derive_public_key         32
    derive_view_tag           16

and every 64-character hex field has one space after character 32, as above.
`test/monero-keys.test.mjs` rejoins the fields by the fixed arity of each
command and strips nothing else.

`generate_keys` lines were left out deliberately: Monero generates those with a
seeded PRNG, so they are reproducible inside Monero's test binary and not
derivable from the recorded values. `hash_to_point` was left out as well: it
tests a different function (unbiased, blake2b-based) that this wallet does not
use. The key-image path uses `biased_hash_to_ec`, which is here.

**This is settled policy, not a workaround.** The founder ruled on 2026-10-29:
the hook is never edited and no fixtures exception is ever added, so the space
after character 32 is the standing way to keep a published test vector in the
repository without weakening the scanner. Any future fixture containing a bare
32-byte hex value follows the same pattern and records its source checksum
here.
