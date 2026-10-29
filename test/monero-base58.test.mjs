import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  ALPHABET, decode, decodeAddr, encode, encodeAddr,
} from '../src/monero/base58.js';

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const unhex = (text) => (text === '-' ? new Uint8Array(0) : Uint8Array.from(Buffer.from(text, 'hex')));

// Monero's own tests/unit_tests/base58.cpp, at the pinned commit. The file
// records its provenance and its one transformation in test/fixtures/README.md;
// long hex fields carry spaces, so each row is rebuilt by where its text field
// sits rather than by a fixed field count.
function readRows() {
  const path = fileURLToPath(new URL('./fixtures/monero-base58.txt', import.meta.url));
  const rows = [];
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    const tokens = line.trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    const [command, ...rest] = tokens;
    const row = { command };
    if (command === 'encode_block' || command === 'encode') {
      // ... hex ... then the encoded string
      row.address = rest.at(-1);
      row.data = unhex(rest.slice(0, -1).join(''));
    } else if (command === 'decode_pos') {
      // the string, then ... hex ...; the empty string is written as "-"
      row.address = rest[0] === '-' ? '' : rest[0];
      row.data = unhex(rest.slice(1).join(''));
    } else if (command === 'decode_neg' || command === 'addr_neg') {
      row.address = rest[0];
    } else if (command === 'addr') {
      // tag, then ... hex ..., then the address
      row.tag = BigInt(rest[0]);
      row.address = rest.at(-1);
      row.data = unhex(rest.slice(1, -1).join(''));
    } else if (command === 'keys_addr') {
      // One real account key pair and its address; test/monero-address.test.mjs
      // is what uses it.
      continue;
    } else {
      throw new Error(`unknown row in the base58 fixture: ${command}`);
    }
    rows.push(row);
  }
  return rows;
}

const ROWS = readRows();
const rowsOf = (command) => ROWS.filter((row) => row.command === command);

test('the alphabet is Monero’s 58 characters, without 0, O, I or l', () => {
  assert.equal(ALPHABET.length, 58);
  for (const forbidden of ['0', 'O', 'I', 'l']) assert.equal(ALPHABET.includes(forbidden), false);
});

test('blocks encode exactly as Monero encodes them', () => {
  const rows = rowsOf('encode_block');
  assert.equal(rows.length, 29, `the block vectors were cut or added to: ${rows.length}`);
  for (const { data, address } of rows) {
    assert.equal(encode(data), address, `block ${hex(data)}`);
  }
});

test('whole strings encode exactly as Monero encodes them', () => {
  const rows = rowsOf('encode');
  assert.equal(rows.length, 17, `the string vectors were cut or added to: ${rows.length}`);
  for (const { data, address } of rows) {
    assert.equal(encode(data), address, `data ${hex(data)}`);
  }
});

test('decoding matches Monero, including the empty string', () => {
  const rows = rowsOf('decode_pos');
  assert.equal(rows.length, 33, `the decode vectors were cut or added to: ${rows.length}`);
  for (const { data, address } of rows) {
    assert.equal(hex(decode(address)), hex(data), `string ${address || '(empty)'}`);
  }
});

test('decoding refuses everything Monero refuses', () => {
  const rows = rowsOf('decode_neg');
  // Invalid lengths, overflow, and characters outside the alphabet. Asserting
  // the count matters: a cut that drops them would otherwise pass on nothing.
  // 56 whole-string refusals plus 29 block-level ones in Monero's file.
  assert.equal(rows.length, 85, `the refusal vectors were cut or added to: ${rows.length}`);
  for (const { address } of rows) {
    assert.throws(() => decode(address), Error, `accepted ${address}`);
  }
});

test('an address prefix and payload round-trip through the checksum', () => {
  const rows = rowsOf('addr');
  assert.equal(rows.length, 21, `the address vectors were cut or added to: ${rows.length}`);
  for (const { tag, data, address } of rows) {
    const decoded = decodeAddr(address);
    assert.equal(decoded.tag, tag, `tag of ${address}`);
    assert.equal(hex(decoded.data), hex(data), `payload of ${address}`);
    assert.equal(encodeAddr(tag, data), address, `re-encode of ${address}`);
  }
});

test('an address Monero refuses is refused here too', () => {
  const rows = rowsOf('addr_neg');
  assert.equal(rows.length, 16, `the address refusal vectors were cut or added to: ${rows.length}`);
  for (const { address } of rows) {
    assert.throws(() => decodeAddr(address), Error, `accepted ${address}`);
  }
});
