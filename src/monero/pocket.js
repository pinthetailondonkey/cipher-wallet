// A Monero pocket: one address, one spend key, one view key. It can receive any
// number of payments to that address; "one payment" is not a rule here.
//
// L3 — see docs/L3-RECEIVE.md. Each pocket is its own whole wallet, not a
// subaddress of a shared account. A subaddress shares the account's view key,
// so one key would see every pocket; that is the link L3 exists to remove and
// the reason this module does not call Monero's subaddress derivation at all.
//
// The derivation is frozen. These lines are a money rule, not a style choice: a
// changed derivation restores a different wallet, shows a zero balance, and
// looks exactly like a pocket that was never paid. The test beside this module
// pins the first three addresses so any change to the derivation fails loudly.
//
// What this proves and what it does not: Monero's primitives underneath are
// pinned to Monero's own generated vectors, so the keys and the address are
// built by Monero's rules. The BIP39-to-Monero entropy path is ours — Monero's
// own 25-word seed uses a different scheme — so these addresses are correct by
// this wallet's documented derivation and not by Monero's wallet conventions.

import { xmrPocketEntropy } from '../root.js';
import { scReduce32, secretToPublic, viewSecretFromSpend } from './keys.js';
import { encodeAddress } from './address.js';

export const DEFAULT_NETWORK = 'mainnet';

export function moneroPocket(seed, index, { network = DEFAULT_NETWORK } = {}) {
  const entropy = xmrPocketEntropy(seed, index);
  // Monero's account generation: the seed is reduced to a scalar, and the view
  // secret is the keccak of that scalar, reduced. The view key never stands
  // alone, which is why one secret at rest is enough.
  const spendSecret = scReduce32(entropy);
  const viewSecret = viewSecretFromSpend(spendSecret);

  const spend = secretToPublic(spendSecret);
  const view = secretToPublic(viewSecret);

  // Standard, never subaddress: a pocket is a whole wallet and the prefix says
  // so. The keys are checked again inside encodeAddress — a pocket that cannot
  // be paid must fail here rather than be handed to a customer.
  const address = encodeAddress({ spend, view, network, kind: 'standard' });

  return {
    index,
    network,
    spendSecret,
    viewSecret,
    spend,
    view,
    address,
  };
}
