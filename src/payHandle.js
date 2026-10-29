// The pay handle: the one stable thing a customer is given.
//
// It is a POINTER, never a chain key. Its id is 32 random bytes, not derived
// from the root, so publishing it reveals nothing about the wallet and it
// cannot be used to walk to a pocket. The handle says "ask this device for the
// next pocket"; the device derives it from the root, on this device only.
//
// `issuePocket` is pure: it returns the derived pocket plus the NEXT handle.
// Persisting the new handle is the caller's job, in the same commit as the
// pocket, so a crash cannot hand the same index out twice.

import { pocketFor } from './root.js';

export const HANDLE_VERSION = 1;

function hex(bytes) {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

export function createHandle({ coin = 'btc', label = '' } = {}) {
  const id = hex(crypto.getRandomValues(new Uint8Array(32)));
  return {
    v: HANDLE_VERSION,
    id,
    label: String(label || ''),
    next: { [String(coin).toLowerCase()]: 0 },
  };
}

export function isHandle(handle) {
  return !!handle && typeof handle === 'object'
    && handle.v === HANDLE_VERSION
    && /^[0-9a-f]{64}$/.test(String(handle.id || ''))
    && handle.next && typeof handle.next === 'object';
}

export function nextIndexFor(handle, coin) {
  if (!isHandle(handle)) throw new Error('That is not a pay handle.');
  const key = String(coin || '').toLowerCase();
  const index = handle.next[key] ?? 0;
  if (!Number.isInteger(index) || index < 0) throw new Error('The pay handle is damaged.');
  return index;
}

// The pocket for the next index, and the handle that says a new one was used.
export function issuePocket(handle, seed, { coin, network = 'bc' } = {}) {
  const key = String(coin || '').toLowerCase();
  const index = nextIndexFor(handle, key);
  const pocket = pocketFor(seed, { coin: key, index, network });
  const next = {
    ...handle,
    next: { ...handle.next, [key]: index + 1 },
  };
  return { pocket: { ...pocket, coin: key, index }, handle: next };
}
