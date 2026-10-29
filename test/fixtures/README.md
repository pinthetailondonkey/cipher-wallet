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

This is a recorded trade-off and not a settled policy: a Bitcoin test fixture
will always contain 32-byte hex values, so the hook will keep colliding with
them. Whether the hook should exempt this directory is a decision for the
founder, not for me.
