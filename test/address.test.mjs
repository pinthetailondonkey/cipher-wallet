import test from 'node:test';
import assert from 'node:assert/strict';
import { hex } from '@scure/base';
import { decodeAddress } from '../src/address.js';

// Vectors from BIP-173 and BIP-350, the "valid" table.
const VALID = [
  ['BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4', 'bc', '0014751e76e8199196d454941c45d1b3a323f1433bd6', 'p2wpkh'],
  ['tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7', 'tb', '00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262', 'p2wsh'],
  ['bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y', 'bc', '5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6', 'witness'],
  ['BC1SW50QGDZ25J', 'bc', '6002751e', 'witness'],
  ['bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs', 'bc', '5210751e76e8199196d454941c45d1b3a323', 'witness'],
  ['bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0', 'bc', '512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', 'witness'],
];

for (const [address, network, script, kind] of VALID) {
  test(`BIP vector decodes: ${address}`, () => {
    const out = decodeAddress(address, network);
    assert.equal(hex.encode(out.script), script);
    assert.equal(out.kind, kind);
    assert.equal(out.network, network);
  });
}

// The "invalid" table. Each must throw, and none may return a script.
const INVALID = [
  ['bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd', 'bc'], // bech32 instead of bech32m
  ['bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh', 'bc'],                      // bech32m instead of bech32
  ['bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4', 'bc'], // bad character in checksum
  ['BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R', 'bc'], // invalid witness version
  ['bc1pw5dgrnzv', 'bc'],                                                     // program length 1
  ['bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav', 'bc'], // 41 bytes
  ['BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P', 'bc'],                             // v0 length
  ['bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf', 'bc'], // bad padding
  ['tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j', 'tb'], // non-zero padding
  ['bc1gmk9yu', 'bc'],                                                        // empty data
];

for (const [address, network] of INVALID) {
  test(`BIP invalid vector is refused: ${address.slice(0, 22)}...`, () => {
    assert.throws(() => decodeAddress(address, network));
  });
}

test('mixed case is refused before the checksum is even looked at', () => {
  assert.throws(() => decodeAddress('tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq', 'tb'), /mixes upper and lower case/);
});

test('an address for another network is refused', () => {
  assert.throws(() => decodeAddress('tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7', 'bc'), /different network/);
});

test('the genesis coinbase address decodes to its known key hash', () => {
  const out = decodeAddress('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', 'bc');
  assert.equal(out.kind, 'p2pkh');
  assert.equal(hex.encode(out.program), '62e907b15cbf27d5425399ebf6f0fb50ebb88f18');
  assert.equal(hex.encode(out.script), '76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac');
});

test('a base58 P2SH address pays the script hash', () => {
  const out = decodeAddress('3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy', 'bc');
  assert.equal(out.kind, 'p2sh');
  assert.equal(hex.encode(out.script), 'a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb87');
});

test('a base58 address for another network is refused', () => {
  // version 0x6f is testnet P2PKH, not mainnet
  assert.throws(() => decodeAddress('mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn', 'bc'), /different network/);
});

test('an empty address is refused', () => {
  assert.throws(() => decodeAddress('', 'bc'), /An address is required/);
});
