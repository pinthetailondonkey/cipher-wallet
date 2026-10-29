import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  ADDRESS_PREFIXES, decodeAddress, encodeAddress,
} from '../src/monero/address.js';
import { decodeAddr, encodeAddr } from '../src/monero/base58.js';
import { isValidPublicKey, secretToPublic } from '../src/monero/keys.js';

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const unhex = (text) => Uint8Array.from(Buffer.from(text, 'hex'));

// Monero's own account key pair and the address it makes from it, from
// tests/unit_tests/base58.cpp at the pinned commit. This is the pin: everything
// else here is self-consistency, and self-consistency cannot tell a right
// encoder from a wrong one that agrees with itself.
function pinnedKeys() {
  const path = fileURLToPath(new URL('./fixtures/monero-base58.txt', import.meta.url));
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    const tokens = line.trim().split(/\s+/).filter(Boolean);
    if (tokens[0] !== 'keys_addr') continue;
    const blob = unhex(tokens.slice(1, -1).join(''));
    return {
      spend: blob.subarray(0, 32),
      view: blob.subarray(32, 64),
      address: tokens.at(-1),
    };
  }
  throw new Error('the pinned account address is missing from the fixture');
}

const PINNED = pinnedKeys();

// A second, unrelated pair, so a test cannot pass by both being the same key.
const OTHER_SPEND = secretToPublic(unhex('0b'.repeat(32)));
const OTHER_VIEW = secretToPublic(unhex('0c'.repeat(32)));

test('the pinned keys produce exactly the address Monero produces', () => {
  assert.equal(encodeAddress({ spend: PINNED.spend, view: PINNED.view }), PINNED.address);
});

test('the pinned address decodes to the keys it was made from', () => {
  const decoded = decodeAddress(PINNED.address, { network: 'mainnet' });
  assert.equal(decoded.network, 'mainnet');
  assert.equal(decoded.kind, 'standard');
  assert.equal(hex(decoded.spend), hex(PINNED.spend));
  assert.equal(hex(decoded.view), hex(PINNED.view));
  assert.equal(decoded.paymentId, undefined);
});

test('the prefix table is the one in cryptonote_config.h', () => {
  assert.deepEqual({ ...ADDRESS_PREFIXES.mainnet }, { standard: 18, integrated: 19, subaddress: 42 });
  assert.deepEqual({ ...ADDRESS_PREFIXES.testnet }, { standard: 53, integrated: 54, subaddress: 63 });
  assert.deepEqual({ ...ADDRESS_PREFIXES.stagenet }, { standard: 24, integrated: 25, subaddress: 36 });
});

test('every network and kind round-trips, and the prefix says which it is', () => {
  for (const network of Object.keys(ADDRESS_PREFIXES)) {
    for (const kind of ['standard', 'subaddress']) {
      const address = encodeAddress({ spend: OTHER_SPEND, view: OTHER_VIEW, network, kind });
      const { tag } = decodeAddr(address);
      assert.equal(tag, BigInt(ADDRESS_PREFIXES[network][kind]), `${network} ${kind} prefix`);
      const back = decodeAddress(address);
      assert.equal(back.network, network);
      assert.equal(back.kind, kind);
      assert.equal(hex(back.spend), hex(OTHER_SPEND));
    }
  }
});

test('an integrated address carries its payment id and nothing else does', () => {
  const paymentId = unhex('00112233445566aa');
  const address = encodeAddress({
    spend: OTHER_SPEND, view: OTHER_VIEW, kind: 'integrated', paymentId,
  });
  const back = decodeAddress(address);
  assert.equal(back.kind, 'integrated');
  assert.equal(hex(back.paymentId), hex(paymentId));

  assert.throws(
    () => encodeAddress({ spend: OTHER_SPEND, view: OTHER_VIEW, kind: 'integrated' }),
    /eight-byte payment id/,
  );
  assert.throws(
    () => encodeAddress({ spend: OTHER_SPEND, view: OTHER_VIEW, kind: 'integrated', paymentId: unhex('0011') }),
    /eight-byte payment id/,
  );
  // Asking for a plain address with a payment id is a contradiction, not a tag.
  assert.throws(
    () => encodeAddress({ spend: OTHER_SPEND, view: OTHER_VIEW, paymentId }),
    /does not carry a payment id/,
  );
  assert.throws(
    () => encodeAddress({ spend: OTHER_SPEND, view: OTHER_VIEW, kind: 'subaddress', paymentId }),
    /does not carry a payment id/,
  );
});

test('an address cannot be built from a key that is not a key', () => {
  const zero = new Uint8Array(32);
  assert.equal(isValidPublicKey(zero), false, 'a point of order four is not a key');
  assert.equal(isValidPublicKey(unhex('01' + '00'.repeat(31))), false, 'the identity is not a key');
  assert.equal(isValidPublicKey(OTHER_SPEND), true);
  assert.throws(() => encodeAddress({ spend: zero, view: OTHER_VIEW }), /not a valid public key/);
  assert.throws(() => encodeAddress({ spend: OTHER_SPEND, view: zero }), /not a valid public key/);
});

// The four refusals Monero's own address tests name, reproduced from our side.
test('an address Monero refuses is refused here too', () => {
  const keys = new Uint8Array(64);
  keys.set(PINNED.spend, 0);
  keys.set(PINNED.view, 32);

  // A character outside the alphabet.
  const badFormat = `0${PINNED.address.slice(1)}`;
  assert.throws(() => decodeAddress(badFormat), Error);

  // A prefix that is not one of the nine this wallet knows.
  assert.throws(() => decodeAddress(encodeAddr(0, keys)), /prefix this wallet knows/);

  // One byte short of two keys.
  assert.throws(() => decodeAddress(encodeAddr(18, keys.subarray(1))), /key material/);

  // A spend key of zeros: a valid curve point of order four, not a key.
  const zeroSpend = new Uint8Array(keys);
  zeroSpend.fill(0, 0, 32);
  assert.throws(() => decodeAddress(encodeAddr(18, zeroSpend)), /spend key .* not a valid public key/);

  // A view key that is not on the curve at all.
  const badView = new Uint8Array(keys);
  badView[63] = 0x01;
  assert.throws(() => decodeAddress(encodeAddr(18, badView)), /view key .* not a valid public key/);
});

test('an address from another network is refused rather than relabelled', () => {
  assert.throws(() => decodeAddress(PINNED.address, { network: 'testnet' }), /mainnet address, not a testnet/);
});
