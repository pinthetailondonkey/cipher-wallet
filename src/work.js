// Proof of work: a header has to hash below the target it names.
//
// The walk hashes every header and checks that every link joins, and it checks
// that every body hashes up to the merkle root the header commits to. None of
// that is proof of work: a peer can invent an 80-byte header that links and a
// body that matches it, mine it for free (zero leading zeros), and serve a
// self-consistent private chain. The missing check is the one that costs the
// peer something — the header's own hash against the compact target in its own
// nBits field.
//
// nBits is a compact encoding of a 256-bit target: one byte of exponent, a
// 23-bit mantissa, and a sign bit that bitcoin treats as "negative target" and
// this wallet refuses. The decode below is the classic compact form; the only
// care worth taking is the two ways it collapses to a zero target (a zero
// mantissa, and the sign bit), because a zero target is a target no hash can
// meet and believing one would refuse real blocks.
//
// The comparison is exact and done on bytes: the double-sha256 of the header is
// read as a little-endian 256-bit integer and required to be at most the target.
// `hash <= target`, not `hash < target`, because the one hash that equals the
// target is as valid as one below it.

import { sha256d } from './tx.js';

const HEADER_SIZE = 80;
const BITS_OFFSET = 72;
const SIGN_BIT = 0x00800000;
const MANTISSA_MASK = 0x007fffff;
const MAX_256 = (1n << 256n) - 1n;

// The compact target a header names, as a 256-bit bigint. `bits` is the uint32
// read little-endian from header bytes 72..76.
//
// Refuses a zero target (and the sign-bit "negative" form, which decodes to
// zero here) by name: a target of zero would refuse every block, and a header
// that names it is not a header this wallet can judge.
export function targetFromBits(bits) {
  if (!Number.isInteger(bits) || bits < 0 || bits > 0xffffffff) {
    throw new Error('A compact target is a 32-bit unsigned integer.');
  }
  const exponent = (bits >>> 24) & 0xff;
  const mantissa = bits & MANTISSA_MASK;
  const negative = (bits & SIGN_BIT) !== 0 && mantissa !== 0;

  // exponent <= 3 shifts the mantissa right; above it, left. The result is
  // masked to 256 bits, which is what a 256-bit target can hold and what a
  // nonsense exponent (bitcoin's own arithmetic truncates the same way) means.
  let target = exponent <= 3
    ? BigInt(mantissa) >> BigInt(8 * (3 - exponent))
    : BigInt(mantissa) << BigInt(8 * (exponent - 3));
  target &= MAX_256;

  if (negative || target === 0n) {
    throw new Error('That header names a zero proof-of-work target, which no hash can meet.');
  }
  return target;
}

function headerBits(header) {
  if (!(header instanceof Uint8Array) || header.length < HEADER_SIZE) {
    throw new Error('A block header is at least 80 bytes.');
  }
  return (
    header[BITS_OFFSET]
    | (header[BITS_OFFSET + 1] << 8)
    | (header[BITS_OFFSET + 2] << 16)
    | (header[BITS_OFFSET + 3] << 24)
  ) >>> 0;
}

function hashAsBigInt(header) {
  const digest = sha256d(header.slice(0, HEADER_SIZE));
  let value = 0n;
  for (let i = digest.length - 1; i >= 0; i -= 1) value = (value << 8n) | BigInt(digest[i]);
  return value;
}

// The named refusal for a header that does not prove its work, or null when it
// does. Named separately so a caller can report it without a boolean losing the
// reason.
export function workRefusal(header) {
  let target;
  try {
    target = targetFromBits(headerBits(header));
  } catch (error) {
    return error.message;
  }
  if (hashAsBigInt(header) > target) {
    return 'That header does not meet its own work target, so a peer could have invented it for free.';
  }
  return null;
}

export function meetsWork(header) {
  return workRefusal(header) === null;
}

export function assertMeetsWork(header) {
  const refusal = workRefusal(header);
  if (refusal) throw new Error(refusal);
  return header;
}

// How much work a target is worth, as the expected number of hashes a miner
// has to try: `2^256 / (target + 1)`. This is the standard expected-work form
// used by Bitcoin and Ethereum (their `2^256/(target+1)`); a smaller target is
// worth more work, and summing it over a chain prices the chain rather than one
// header. A bigint, exact, never rounded.
export function workForTarget(target) {
  if (typeof target !== 'bigint' || target < 0n) {
    throw new Error('A proof-of-work target is a non-negative bigint.');
  }
  return (1n << 256n) / (target + 1n);
}

// The work one header is worth: the work of the target its own nBits names.
export function workOf(header) {
  return workForTarget(targetFromBits(headerBits(header)));
}

// The work a whole chain is worth: the sum of every header's work. Order does
// not matter, but the headers do, so an empty chain is refused by name rather
// than quietly summing to zero. One header proves only that one header was
// mined; a chain is priced by its total, which is what a peer cannot fake
// cheaply by naming an easy target on every invented block.
export function cumulativeWork(headers) {
  if (!Array.isArray(headers) || headers.length === 0) {
    throw new Error('Cumulative work is summed over a non-empty array of headers.');
  }
  let total = 0n;
  for (const header of headers) total += workOf(header);
  return total;
}

// The regtest-grade compact target used to stamp synthetic headers, which are
// never mined. 0x207fffff is a real target (~2^255), so a stamped header keeps
// its nBits meaningful rather than setting a magic flag.
export const EASY_BITS = 0x207fffff;

// Write EASY_BITS into a header's nBits field (bytes 72..76, little-endian),
// then grind the nonce (bytes 76..80) until the header actually meets that
// target. The target alone leaves a synthetic header passing only about half
// the time, which would make a test that stamps a fixed header flaky; grinding
// a real (if easy) target keeps the stamp honest and the result deterministic.
// Mutates and returns the header so it can be chained where the header is made.
export function stampWork(header) {
  if (!(header instanceof Uint8Array) || header.length < HEADER_SIZE) {
    throw new Error('A block header is at least 80 bytes.');
  }
  header[BITS_OFFSET] = EASY_BITS & 0xff;
  header[BITS_OFFSET + 1] = (EASY_BITS >>> 8) & 0xff;
  header[BITS_OFFSET + 2] = (EASY_BITS >>> 16) & 0xff;
  header[BITS_OFFSET + 3] = (EASY_BITS >>> 24) & 0xff;
  let nonce = 0;
  while (workRefusal(header) !== null) {
    nonce += 1;
    if (nonce > 0xffffffff) throw new Error('A header could not be made to meet its own easy target.');
    const at = BITS_OFFSET + 4;
    header[at] = nonce & 0xff;
    header[at + 1] = (nonce >>> 8) & 0xff;
    header[at + 2] = (nonce >>> 16) & 0xff;
    header[at + 3] = (nonce >>> 24) & 0xff;
  }
  return header;
}
