// Monero's base58 — not Bitcoin's.
//
// The two look similar and are not interchangeable:
//   - eight-byte blocks are read BIG-endian, and each block's length decides how
//     many characters it takes (1->2, 2->3, 3->5, 4->6, 5->7, 6->9, 7->10, 8->11);
//   - the alphabet is the same 58 characters Bitcoin uses;
//   - an address is a varint prefix, then the payload, then four bytes of
//     keccak-256 over both.
// The big-endian read inside an otherwise little-endian system is the part that
// passes most vectors and fails the rest, which is why every vector here comes
// from Monero's own tests/unit_tests/base58.cpp rather than from memory.
//
// Decoding refuses rather than guesses: an invalid character, a block length
// that is not one of the eight valid ones, and a value that does not fit the
// block are each a throw.

import { keccak_256 } from '@noble/hashes/sha3.js';
import { readVarint, varint } from './keys.js';

export const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const ALPHABET_SIZE = 58n;

// Characters per encoded block, indexed by the number of bytes in that block.
// Index 0 is unused and exists so the table can be read by size.
export const ENCODED_BLOCK_SIZES = Object.freeze([0, 2, 3, 5, 6, 7, 9, 10, 11]);

const FULL_BLOCK = 8;
const FULL_ENCODED_BLOCK = 11;
const CHECKSUM_SIZE = 4;

const DECODED_BLOCK_SIZES = new Map(
  ENCODED_BLOCK_SIZES.map((encoded, bytes) => [encoded, bytes]),
);

function concat(arrays) {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const a of arrays) {
    out.set(a, at);
    at += a.length;
  }
  return out;
}

function encodeBlock(block) {
  const size = block.length;
  if (size < 1 || size > FULL_BLOCK) throw new Error('A base58 block is 1 to 8 bytes.');
  let value = 0n;
  for (const byte of block) value = (value << 8n) | BigInt(byte);
  const width = ENCODED_BLOCK_SIZES[size];
  const out = Array.from({ length: width }, () => ALPHABET[0]);
  for (let i = width - 1; value > 0n; i -= 1) {
    out[i] = ALPHABET[Number(value % ALPHABET_SIZE)];
    value /= ALPHABET_SIZE;
  }
  return out.join('');
}

function decodeBlock(text) {
  const decodedSize = DECODED_BLOCK_SIZES.get(text.length);
  if (decodedSize === undefined) {
    // Not one of 2, 3, 5, 6, 7, 9, 10 or 11: no byte length produces it.
    throw new Error(`A base58 block is not ${text.length} characters long.`);
  }
  let value = 0n;
  for (const character of text) {
    const digit = ALPHABET.indexOf(character);
    if (digit === -1) throw new Error(`That is not a Monero base58 character: ${character}`);
    value = value * ALPHABET_SIZE + BigInt(digit);
  }
  // A block can only hold so much: 58^length grows faster than 256^bytes, so
  // some character strings denote more than their block can carry. Monero
  // catches this as uint64 overflow inside the loop; with BigInt the value is
  // simply too large, and the same eight-byte block is bounded the same way.
  if ((1n << BigInt(8 * decodedSize)) <= value) {
    throw new Error('That base58 block is larger than the bytes it stands for.');
  }
  const out = new Uint8Array(decodedSize);
  let rest = value;
  for (let i = decodedSize - 1; i >= 0; i -= 1) {
    out[i] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  return out;
}

export function encode(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new Error('Base58 encodes bytes.');
  if (bytes.length === 0) return '';
  const fullBlocks = Math.floor(bytes.length / FULL_BLOCK);
  const lastSize = bytes.length % FULL_BLOCK;
  const pieces = [];
  for (let i = 0; i < fullBlocks; i += 1) {
    pieces.push(encodeBlock(bytes.subarray(i * FULL_BLOCK, (i + 1) * FULL_BLOCK)));
  }
  if (lastSize > 0) pieces.push(encodeBlock(bytes.subarray(fullBlocks * FULL_BLOCK)));
  return pieces.join('');
}

export function decode(text) {
  if (typeof text !== 'string') throw new Error('Base58 decodes text.');
  if (text === '') return new Uint8Array(0);
  const fullBlocks = Math.floor(text.length / FULL_ENCODED_BLOCK);
  const lastSize = text.length % FULL_ENCODED_BLOCK;
  if (!DECODED_BLOCK_SIZES.has(lastSize)) {
    throw new Error(`A base58 string cannot end with a ${lastSize}-character block.`);
  }
  const pieces = [];
  for (let i = 0; i < fullBlocks; i += 1) {
    pieces.push(decodeBlock(text.slice(i * FULL_ENCODED_BLOCK, (i + 1) * FULL_ENCODED_BLOCK)));
  }
  if (lastSize > 0) pieces.push(decodeBlock(text.slice(fullBlocks * FULL_ENCODED_BLOCK)));
  return concat(pieces);
}

// prefix (varint) || payload || first four bytes of keccak over both.
export function encodeAddr(tag, payload) {
  if (!(payload instanceof Uint8Array)) throw new Error('A payload is bytes.');
  const body = concat([varint(tag), payload]);
  return encode(concat([body, keccak_256(body).subarray(0, CHECKSUM_SIZE)]));
}

export function decodeAddr(text) {
  const raw = decode(text);
  if (raw.length <= CHECKSUM_SIZE) throw new Error('That is too short to be an address.');
  const body = raw.subarray(0, raw.length - CHECKSUM_SIZE);
  const checksum = raw.subarray(raw.length - CHECKSUM_SIZE);
  const expected = keccak_256(body).subarray(0, CHECKSUM_SIZE);
  let diff = 0;
  for (let i = 0; i < CHECKSUM_SIZE; i += 1) diff |= checksum[i] ^ expected[i];
  if (diff !== 0) throw new Error('That address has a checksum that does not match its contents.');
  const { value, length } = readVarint(body);
  return { tag: value, data: body.subarray(length) };
}
