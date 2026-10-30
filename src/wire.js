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
import { readVarint, reverseBytes, sha256d } from './tx.js';

export const MAGIC = Object.freeze({
  mainnet: 'f9beb4d9',
  testnet: '0b110907',
  signet: '0a03cf40',
  regtest: 'fabfb5da',
});

export const BASIC_FILTER_TYPE = 0x00;
export const FRAME_HEADER_SIZE = 24;
const HEADER_SIZE = FRAME_HEADER_SIZE;
const COMMAND_SIZE = 12;
export const MAX_PAYLOAD = 8 * 1024 * 1024;
const MAGIC_BYTES = 'f9beb4d9';

function magicFor(network) {
  const magic = MAGIC[String(network ?? 'mainnet').toLowerCase()];
  if (!magic) throw new Error('That is not a Bitcoin network.');
  return hex.decode(magic);
}

// Hashes on the wire are in internal (little-endian) order; the display order a
// person and a peer write them in is the reverse. Every 32-byte hash that
// crosses this boundary is converted here, once, so a message built from a
// display hash is correct on the wire.
function wireHash(text) {
  const display = hex.decode(String(text ?? ''));
  if (display.length !== 32) throw new Error('A hash is 32 bytes.');
  return reverseBytes(display);
}

function displayHash(bytes) {
  return hex.encode(reverseBytes(bytes));
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
  // Four bytes hold 0..4294967295, and a height above that does not fit: it
  // would be written as its low four bytes, so 2^32 becomes 0 — the genesis
  // range, which is the question this wallet stopped asking on purpose. The
  // bound sits here rather than at a caller because the value is produced HERE.
  if (!Number.isInteger(startHeight) || startHeight < 0 || startHeight > 0xffffffff) {
    throw new Error('A start height is a whole number from 0 to 4294967295.');
  }
  const hash = wireHash(stopHash);
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
  // Unsigned. A height has no sign, and the signed shifts read 0xffffffff as
  // -1 — a value our own encoder could produce before it was bounded, and one a
  // peer can still send.
  const startHeight = (payload[1] | (payload[2] << 8) | (payload[3] << 16) | (payload[4] << 24)) >>> 0;
  return { filterType: payload[0], startHeight, stopHash: displayHash(payload.slice(5, 37)) };
}

// cfilter: filter type, the block hash it answers for, then the filter as a
// length-prefixed byte string. The hash is returned so the caller can refuse an
// answer about a block it did not ask for.
export function encodeCfilter({ blockHash, filter, filterType = BASIC_FILTER_TYPE } = {}) {
  if (!(filter instanceof Uint8Array) || filter.length === 0) throw new Error('A filter is bytes.');
  const hash = wireHash(blockHash);
  const size = encodeCompactSize(filter.length);
  const out = new Uint8Array(1 + 32 + size.length + filter.length);
  out[0] = filterType;
  out.set(hash, 1);
  out.set(size, 33);
  out.set(filter, 33 + size.length);
  return out;
}

// A count is canonical or it is not a count. CompactSize has exactly one
// encoding for each value: 0xfd introduces a value of at least 0xfd, 0xfe one of
// at least 0x10000, 0xff one of at least 0x100000000. Bitcoin Core refuses the
// padded forms, so a wallet that accepts them is reading a message no peer
// would have sent, and one sender can spell the same message several ways.
function readCanonicalVarint(bytes, offset) {
  const decoded = readVarint(bytes, offset);
  const first = bytes[offset];
  const least = first === 0xfd ? 0xfd : first === 0xfe ? 0x10000 : first === 0xff ? 0x100000000 : 0;
  if (decoded.value < least) {
    throw new Error('That message writes its count in a padded form, which is not a CompactSize.');
  }
  return decoded;
}

export function decodeCfilter(payload) {
  if (!(payload instanceof Uint8Array) || payload.length < 34) {
    throw new Error('A cfilter message is at least 34 bytes.');
  }
  const size = readCanonicalVarint(payload, 33);
  const at = size.offset;
  if (payload.length - at !== Number(size.value)) {
    throw new Error('That cfilter’s length does not match the bytes it carries.');
  }
  return {
    filterType: payload[0],
    blockHash: displayHash(payload.slice(1, 33)),
    filter: payload.slice(at),
  };
}

// getheaders: a protocol version, a locator of block hashes, and a stop hash.
//
// The locator is the FORWARD question. A peer answers with the headers that
// come AFTER the first locator entry it recognises, oldest first — so this is
// how a header-first walk starts: from a block the wallet already believes,
// never from the tip it was handed. There is no backwards form of this message,
// which is why header-first is a forward sync and not a cheaper walkBack.
//
// A locator with no entries is the genesis question in another coat: a node
// will happily send its whole header chain. A locator longer than a node reads
// is refused rather than sent, so this wallet cannot ask a question real
// Bitcoin Core would truncate.
export const MAX_LOCATOR = 101;

export function encodeGetHeaders({ version = PROTOCOL_VERSION, locator = [], stopHash } = {}) {
  const list = Array.isArray(locator) ? locator : [];
  if (list.length === 0) {
    throw new Error('A headers question needs at least one block hash to start from.');
  }
  if (list.length > MAX_LOCATOR) {
    throw new Error(`A locator carries at most ${MAX_LOCATOR} block hashes.`);
  }
  const hashes = list.map((hash) => wireHash(String(hash).trim().toLowerCase()));
  const stop = wireHash(String(stopHash ?? '00'.repeat(32)).trim().toLowerCase());
  const count = encodeCompactSize(hashes.length);
  const out = new Uint8Array(4 + count.length + 32 * hashes.length + 32);
  const view = new DataView(out.buffer);
  view.setUint32(0, version, true);
  out.set(count, 4);
  let at = 4 + count.length;
  for (const hash of hashes) { out.set(hash, at); at += 32; }
  out.set(stop, at);
  return out;
}

// headers: a count, then that many 80-byte headers, oldest first. The message
// is all-or-nothing — a tail that does not fill a whole header is a refusal,
// because a partly-read chain segment would be walked as if it were whole.
export const SERIALIZED_HEADER_SIZE = 80;

export function encodeHeaders(headers = []) {
  const list = Array.isArray(headers) ? headers : [];
  // Strict on purpose: a headers answer this wallet WRITES is only used by
  // drills, and a wrong-length header there should be a refusal, not padding.
  const count = encodeCompactSize(list.length);
  const out = new Uint8Array(count.length + list.length * SERIALIZED_HEADER_SIZE);
  out.set(count, 0);
  let at = count.length;
  for (const header of list) {
    if (!(header instanceof Uint8Array) || header.length !== SERIALIZED_HEADER_SIZE) {
      throw new Error('A block header is 80 bytes.');
    }
    out.set(header, at);
    at += SERIALIZED_HEADER_SIZE;
  }
  return out;
}

export function decodeHeaders(payload) {
  if (!(payload instanceof Uint8Array) || payload.length === 0) {
    throw new Error('A headers message starts with a count.');
  }
  const count = readCanonicalVarint(payload, 0);
  const at = count.offset;
  const want = count.offset + Number(count.value) * SERIALIZED_HEADER_SIZE;
  if (payload.length !== want) {
    throw new Error('That headers answer is cut short: its count and its bytes disagree.');
  }
  const headers = [];
  for (let i = 0; i < Number(count.value); i += 1) {
    headers.push(payload.slice(at + i * SERIALIZED_HEADER_SIZE, at + (i + 1) * SERIALIZED_HEADER_SIZE));
  }
  return { headers };
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


// ---- handshake and block fetching -----------------------------------------

export const PROTOCOL_VERSION = 70016;
export const MSG_WITNESS_BLOCK = 0x40000002;

// The two service bits this wallet needs a peer to claim, and both now have a
// reader: NODE_NETWORK ("serves the full chain") is checked before a block is
// asked for, NODE_COMPACT_FILTERS (BIP-157) before a filter is. A peer that
// claims neither is not refusing us later — it answers with nothing, or with
// something else entirely, and the silence reads as a wallet fault.
export const NODE_NETWORK = 1n;
export const NODE_COMPACT_FILTERS = 64n;

function u64le(value) {
  const out = new Uint8Array(8);
  let n = BigInt(value);
  for (let i = 0; i < 8; i += 1) { out[i] = Number(n & 0xffn); n >>= 8n; }
  return out;
}

function readU64le(bytes, at) {
  let value = 0n;
  for (let i = 7; i >= 0; i -= 1) value = (value << 8n) | BigInt(bytes[at + i]);
  return value;
}

function ipv6Of(text) {
  // IPv4 peers are sent as ::ffff:a.b.c.d on the wire. Anything that is not an
  // address this build can spell is the zero address, which asks nothing of the
  // peer and reveals nothing.
  const out = new Uint8Array(16);
  const parts = String(text ?? '').trim().split('.').map(Number);
  if (parts.length === 4 && parts.every((p) => Number.isInteger(p) && p >= 0 && p <= 255)) {
    out[10] = 0xff; out[11] = 0xff;
    out.set(parts, 12);
  }
  return out;
}

function netAddr({ services = 0n, ip = '', port = 0 } = {}) {
  const out = new Uint8Array(26);
  out.set(u64le(services), 0);
  out.set(ipv6Of(ip), 8);
  out[24] = (port >> 8) & 0xff;
  out[25] = port & 0xff;
  return out;
}

export function encodeVersion({
  version = PROTOCOL_VERSION,
  services = 0n,
  timestamp = Math.floor(Date.now() / 1000),
  addrRecv = {},
  addrFrom = {},
  nonce = 0n,
  userAgent = '/cipher-wallet:0.1/',
  startHeight = 0,
  relay = false,
} = {}) {
  const agent = new TextEncoder().encode(String(userAgent));
  if (agent.length > 255) throw new Error('A user agent is at most 255 bytes.');
  // The same four bytes a filter asks about, bounded the same way: a raw
  // setUint32 wraps 2^32 to 0 and -1 to 0xffffffff without a word.
  if (!Number.isInteger(startHeight) || startHeight < 0 || startHeight > 0xffffffff) {
    throw new Error('A start height is a whole number from 0 to 4294967295.');
  }
  const out = new Uint8Array(4 + 8 + 8 + 26 + 26 + 8 + 1 + agent.length + 4 + 1);
  const view = new DataView(out.buffer);
  view.setUint32(0, version, true);
  out.set(u64le(services), 4);
  out.set(u64le(BigInt(timestamp)), 12);
  out.set(netAddr(addrRecv), 20);
  out.set(netAddr(addrFrom), 46);
  out.set(u64le(nonce), 72);
  out[80] = agent.length;
  out.set(agent, 81);
  view.setUint32(81 + agent.length, startHeight, true);
  out[85 + agent.length] = relay ? 1 : 0;
  return out;
}

export function decodeVersion(payload) {
  if (!(payload instanceof Uint8Array) || payload.length < 4 + 8 + 8 + 26 + 26 + 8 + 1 + 4) {
    throw new Error('That version message is cut short.');
  }
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const version = view.getUint32(0, true);
  const services = readU64le(payload, 4);
  const timestamp = Number(readU64le(payload, 12));
  const nonce = readU64le(payload, 72);
  const agentLength = payload[80];
  if (81 + agentLength + 4 > payload.length) throw new Error('That version message is cut short.');
  const userAgent = new TextDecoder().decode(payload.slice(81, 81 + agentLength));
  const startHeight = view.getUint32(81 + agentLength, true);
  const relay = payload.length > 85 + agentLength ? payload[85 + agentLength] === 1 : undefined;
  return { version, services, timestamp, nonce, userAgent, startHeight, relay };
}

// getdata: a count, then (type, hash) pairs. One block at a time is all this
// wallet asks for.
export function encodeGetData({ type = MSG_WITNESS_BLOCK, hash } = {}) {
  const blockHash = wireHash(hash);
  const out = new Uint8Array(1 + 4 + 32);
  out[0] = 1;
  out[1] = type & 0xff;
  out[2] = (type >> 8) & 0xff;
  out[3] = (type >> 16) & 0xff;
  out[4] = (type >>> 24) & 0xff;
  out.set(blockHash, 5);
  return out;
}

export function decodeGetData(payload) {
  const count = readCanonicalVarint(payload, 0);
  if (count.value !== 1) throw new Error('This wallet asks for one block at a time.');
  if (payload.length - count.offset !== 36) throw new Error('A getdata message is one type and one hash.');
  const type = payload[count.offset] | (payload[count.offset + 1] << 8)
    | (payload[count.offset + 2] << 16) | (payload[count.offset + 3] << 24);
  return { type, hash: displayHash(payload.slice(count.offset + 4)) };
}

export { MAGIC_BYTES };
