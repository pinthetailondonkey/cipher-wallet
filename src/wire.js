// Bitcoin's peer wire, the small part this wallet needs.
//
// peers.js takes the transport as an injected function so the policy can be
// tested; this module is the bytes that transport carries. A frame is: a
// four-byte magic, a twelve-byte NUL-padded command, a little-endian payload
// length, a four-byte checksum (the first four bytes of sha256d of the
// payload), then the payload.
//
// Every field is checked rather than trusted. A peer on the other end is a
// stranger: a bad magic, a checksum that does not match, a length that
// disagrees with the bytes that arrived, or a command that is not a word are
// refusals, not something to skip past. Parsing "leniently" is how a peer gets
// to decide what this wallet believes.

import { hex } from '@scure/base';
import { readVarint, sha256d } from './tx.js';

export const MAGIC = Object.freeze({
  mainnet: 'f9beb4d9',
  testnet: '0b110907',
  signet: '0a03cf40',
  regtest: 'fabfb5da',
});

export const BASIC_FILTER_TYPE = 0x00;
const HEADER_SIZE = 24;
const COMMAND_SIZE = 12;
const MAX_PAYLOAD = 8 * 1024 * 1024;
const MAGIC_BYTES = 'f9beb4d9';

function magicFor(network) {
  const magic = MAGIC[String(network ?? 'mainnet').toLowerCase()];
  if (!magic) throw new Error('That is not a Bitcoin network.');
  return hex.decode(magic);
}

function commandBytes(command) {
  const text = String(command ?? '');
  if (!/^[a-z0-9]+$/.test(text) || text.length > COMMAND_SIZE) {
    throw new Error('A command is one to twelve lowercase characters.');
  }
  const bytes = new Uint8Array(COMMAND_SIZE);
  for (let i = 0; i < text.length; i += 1) bytes[i] = text.charCodeAt(i);
  return bytes;
}

function commandOf(bytes) {
  let end = bytes.length;
  while (end > 0 && bytes[end - 1] === 0) end -= 1;
  let text = '';
  for (let i = 0; i < end; i += 1) {
    const byte = bytes[i];
    if (byte < 0x21 || byte > 0x7e) throw new Error('That frame names its command in bytes that are not characters.');
    text += String.fromCharCode(byte);
  }
  return text;
}

function checksumOf(payload) {
  return sha256d(payload).slice(0, 4);
}

export function frame(command, payload = new Uint8Array(), network = 'mainnet') {
  if (!(payload instanceof Uint8Array)) throw new Error('A payload is bytes.');
  if (payload.length > MAX_PAYLOAD) throw new Error('That message is larger than this wallet reads.');
  const out = new Uint8Array(HEADER_SIZE + payload.length);
  out.set(magicFor(network), 0);
  out.set(commandBytes(command), 4);
  const length = payload.length;
  out[16] = length & 0xff;
  out[17] = (length >> 8) & 0xff;
  out[18] = (length >> 16) & 0xff;
  out[19] = (length >> 24) & 0xff;
  out.set(checksumOf(payload), 20);
  out.set(payload, HEADER_SIZE);
  return out;
}

// One whole frame from `bytes` at `offset`. The caller decides what to do with
// an unknown command; the framing itself is all-or-nothing.
export function decodeFrame(bytes, { network = 'mainnet', offset = 0 } = {}) {
  if (!(bytes instanceof Uint8Array)) throw new Error('A frame arrives as bytes.');
  if (bytes.length - offset < HEADER_SIZE) throw new Error('That frame is shorter than its header.');
  const magic = magicFor(network);
  for (let i = 0; i < 4; i += 1) {
    if (bytes[offset + i] !== magic[i]) throw new Error('That frame does not start with this network’s magic.');
  }
  const command = commandOf(bytes.slice(offset + 4, offset + 16));
  if (!command) throw new Error('That frame names no command.');
  const length = bytes[offset + 16] | (bytes[offset + 17] << 8)
    | (bytes[offset + 18] << 16) | (bytes[offset + 19] << 24);
  if (length < 0 || length > MAX_PAYLOAD) throw new Error('That frame claims a length this wallet will not read.');
  if (bytes.length - offset - HEADER_SIZE < length) throw new Error('That frame ends before its payload does.');
  const payload = bytes.slice(offset + HEADER_SIZE, offset + HEADER_SIZE + length);
  const checksum = bytes.slice(offset + 20, offset + 24);
  const expected = checksumOf(payload);
  let diff = 0;
  for (let i = 0; i < 4; i += 1) diff |= checksum[i] ^ expected[i];
  if (diff !== 0) throw new Error('That frame’s checksum does not match its payload.');
  return { command, payload, size: HEADER_SIZE + length };
}

// getcfilters: filter type, start height (little-endian), stop block hash.
export function encodeGetCfilters({ startHeight, stopHash, filterType = BASIC_FILTER_TYPE } = {}) {
  if (!Number.isInteger(startHeight) || startHeight < 0) throw new Error('A start height is a whole number from zero.');
  const hash = hex.decode(String(stopHash ?? ''));
  if (hash.length !== 32) throw new Error('A stop hash is 32 bytes.');
  const out = new Uint8Array(1 + 4 + 32);
  out[0] = filterType;
  out[1] = startHeight & 0xff;
  out[2] = (startHeight >> 8) & 0xff;
  out[3] = (startHeight >> 16) & 0xff;
  out[4] = (startHeight >> 24) & 0xff;
  out.set(hash, 5);
  return out;
}

export function decodeGetCfilters(payload) {
  if (!(payload instanceof Uint8Array) || payload.length !== 37) {
    throw new Error('A getcfilters message is 37 bytes.');
  }
  const startHeight = payload[1] | (payload[2] << 8) | (payload[3] << 16) | (payload[4] << 24);
  return { filterType: payload[0], startHeight, stopHash: hex.encode(payload.slice(5, 37)) };
}

// cfilter: filter type, the block hash it answers for, then the filter as a
// length-prefixed byte string. The hash is returned so the caller can refuse an
// answer about a block it did not ask for.
export function encodeCfilter({ blockHash, filter, filterType = BASIC_FILTER_TYPE } = {}) {
  if (!(filter instanceof Uint8Array) || filter.length === 0) throw new Error('A filter is bytes.');
  const hash = hex.decode(String(blockHash ?? ''));
  if (hash.length !== 32) throw new Error('A block hash is 32 bytes.');
  const size = encodeCompactSize(filter.length);
  const out = new Uint8Array(1 + 32 + size.length + filter.length);
  out[0] = filterType;
  out.set(hash, 1);
  out.set(size, 33);
  out.set(filter, 33 + size.length);
  return out;
}

export function decodeCfilter(payload) {
  if (!(payload instanceof Uint8Array) || payload.length < 34) {
    throw new Error('A cfilter message is at least 34 bytes.');
  }
  const size = readVarint(payload, 33);
  const at = size.offset;
  if (payload.length - at !== Number(size.value)) {
    throw new Error('That cfilter’s length does not match the bytes it carries.');
  }
  return {
    filterType: payload[0],
    blockHash: hex.encode(payload.slice(1, 33)),
    filter: payload.slice(at),
  };
}

// CompactSize: the same seven-bits-per-byte varint the rest of the protocol
// uses, written here so a message can be built without reaching into tx.js.
export function encodeCompactSize(value) {
  if (!Number.isInteger(value) || value < 0) throw new Error('A length is a whole number from zero.');
  if (value < 0xfd) return Uint8Array.of(value);
  if (value <= 0xffff) return Uint8Array.of(0xfd, value & 0xff, (value >> 8) & 0xff);
  if (value <= 0xffffffff) {
    return Uint8Array.of(0xfe, value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, (value >>> 24) & 0xff);
  }
  throw new Error('That length does not fit in a CompactSize this build writes.');
}

export { MAGIC_BYTES };
