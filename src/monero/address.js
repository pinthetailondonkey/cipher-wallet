// A Monero address: a prefix saying what it is, two public keys, and a checksum.
//
// The prefix is a varint, not a fixed byte, and the three networks use different
// numbers for the same three kinds of address. The numbers here are copied from
// cryptonote_config.h at the pinned commit rather than remembered:
//
//                      standard   integrated   subaddress
//   mainnet               18          19           42
//   testnet               53          54           63
//   stagenet              24          25           36
//
// The payload is the spend public key then the view public key, with an
// eight-byte payment id appended for an integrated address. Both keys must pass
// Monero's own check — a curve point, not the identity, and in the prime-order
// subgroup — because Monero refuses an address that names anything less, and a
// wallet that produced one would be handing out an address nobody can pay.

import { isValidPublicKey } from './keys.js';
import { decodeAddr, encodeAddr } from './base58.js';

export const ADDRESS_PREFIXES = Object.freeze({
  mainnet: Object.freeze({ standard: 18, integrated: 19, subaddress: 42 }),
  testnet: Object.freeze({ standard: 53, integrated: 54, subaddress: 63 }),
  stagenet: Object.freeze({ standard: 24, integrated: 25, subaddress: 36 }),
});

export const ADDRESS_KINDS = Object.freeze(['standard', 'integrated', 'subaddress']);
export const PAYMENT_ID_LENGTH = 8;
const KEY_LENGTH = 32;

function checkKey(bytes, name) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== KEY_LENGTH) {
    throw new Error(`${name} is 32 bytes.`);
  }
  if (!isValidPublicKey(bytes)) {
    throw new Error(`${name} is not a valid public key. An address cannot be built from it.`);
  }
  return bytes;
}

function kindOfTag(tag) {
  for (const [network, prefixes] of Object.entries(ADDRESS_PREFIXES)) {
    for (const kind of ADDRESS_KINDS) {
      // The reader yields a BigInt: a prefix is a varint, not a byte.
      if (BigInt(prefixes[kind]) === tag) return { network, kind };
    }
  }
  return null;
}

export function encodeAddress({
  spend, view, network = 'mainnet', kind = 'standard', paymentId,
} = {}) {
  const prefixes = ADDRESS_PREFIXES[network];
  if (!prefixes) throw new Error(`That is not a network this wallet knows: ${network}`);
  if (!ADDRESS_KINDS.includes(kind)) throw new Error(`That is not a kind of address: ${kind}`);

  checkKey(spend, 'The spend key');
  checkKey(view, 'The view key');

  const parts = [spend, view];
  if (kind === 'integrated') {
    if (!(paymentId instanceof Uint8Array) || paymentId.length !== PAYMENT_ID_LENGTH) {
      throw new Error('An integrated address carries an eight-byte payment id.');
    }
    parts.push(paymentId);
  } else if (paymentId !== undefined) {
    // A payment id is part of an integrated address, not a tag stuck onto one.
    // Silently dropping it would hand out an address that does not match what
    // the caller asked for.
    throw new Error(`A ${kind} address does not carry a payment id. Use an integrated address.`);
  }

  const payload = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let at = 0;
  for (const part of parts) {
    payload.set(part, at);
    at += part.length;
  }
  return encodeAddr(prefixes[kind], payload);
}

export function decodeAddress(text, { network } = {}) {
  if (typeof text !== 'string' || text.trim() === '') throw new Error('An address is text.');
  const { tag, data } = decodeAddr(text.trim());
  const found = kindOfTag(tag);
  if (!found) throw new Error('That is not an address prefix this wallet knows.');
  if (network && network !== found.network) {
    throw new Error(`That is a ${found.network} address, not a ${network} one.`);
  }

  const expected = found.kind === 'integrated' ? 2 * KEY_LENGTH + PAYMENT_ID_LENGTH : 2 * KEY_LENGTH;
  if (data.length !== expected) {
    throw new Error(`A ${found.kind} address carries ${expected} bytes of key material, not ${data.length}.`);
  }

  const spend = data.subarray(0, KEY_LENGTH);
  const view = data.subarray(KEY_LENGTH, 2 * KEY_LENGTH);
  if (!isValidPublicKey(spend)) throw new Error('The spend key in that address is not a valid public key.');
  if (!isValidPublicKey(view)) throw new Error('The view key in that address is not a valid public key.');

  const address = { network: found.network, kind: found.kind, spend, view };
  if (found.kind === 'integrated') address.paymentId = data.subarray(2 * KEY_LENGTH);
  return address;
}
