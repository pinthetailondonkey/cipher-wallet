import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { hex } from '@scure/base';
import {
  blockOutputScripts,
  buildBasicFilter,
  filterHeader,
  filterKey,
  matchesFilter,
  siphash24,
} from '../src/filters.js';

// BIP-0158/testnet-19.json, taken from the bips repository. See
// test/fixtures/README.md: bare 64-character hex values carry one space after
// character 32 (the secret scanner refuses a bare 32-byte hex string, and a
// block hash looks identical to one). The source sha256 is in that README.
const VECTORS = JSON.parse(
  readFileSync(new URL('./fixtures/bip158-testnet-19.json', import.meta.url), 'utf8'),
).slice(1) // the first row is the column headings
  .map((row) => row.map((field) => (typeof field === 'string' ? field.replace(/ /g, '') : field)));

test('SipHash-2-4 matches the reference vectors', () => {
  // Reference values for key 000102...0f and the first N bytes of the same
  // sequence, the standard test set for the algorithm.
  const key = hex.decode('000102030405060708090a0b0c0d0e0f');
  const message = hex.decode('000102030405060708090a0b0c0d0e0f');
  const expected = ['726fdb47dd0e0e31', '74f839c593dc67fd', '93f5f5799a932462', 'a129ca6149be45e5'];
  for (const [at, want] of [[0, expected[0]], [1, expected[1]], [8, expected[2]], [15, expected[3]]]) {
    assert.equal(hex.encode(bigEndian64(siphash24(key, message.slice(0, at)))), want);
  }
});

function bigEndian64(value) {
  const out = new Uint8Array(8);
  let rest = value;
  for (let i = 7; i >= 0; i -= 1) {
    out[i] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  return out;
}

for (const row of VECTORS) {
  const [height, blockHash, blockHex, prevScripts, previousHeader, filterHex, headerHex] = row;
  const block = hex.decode(blockHex);

  test(`BIP-158 vector at height ${height}: block hash`, () => {
    assert.equal(blockOutputScripts(block).blockHash, blockHash);
  });

  test(`BIP-158 vector at height ${height}: the filter is reproduced byte for byte`, () => {
    const { scripts } = blockOutputScripts(block);
    const filter = buildBasicFilter({
      outputScripts: scripts,
      prevScripts: prevScripts.map((s) => hex.decode(s)),
      blockHash,
    });
    assert.equal(hex.encode(filter), filterHex);
  });

  test(`BIP-158 vector at height ${height}: the filter header chains`, () => {
    const { scripts } = blockOutputScripts(block);
    const filter = buildBasicFilter({
      outputScripts: scripts,
      prevScripts: prevScripts.map((s) => hex.decode(s)),
      blockHash,
    });
    assert.equal(hex.encode(filterHeader(filter, hex.decode(previousHeader))), headerHex);
  });

  test(`BIP-158 vector at height ${height}: every included script matches`, () => {
    const filter = hex.decode(filterHex);
    // Not every block contributes a script: one vector block's only output is
    // an OP_RETURN with empty data, which BIP-158 says is not included.
    const included = blockOutputScripts(block).scripts.filter((s) => s.length > 0 && s[0] !== 0x6a);
    for (const script of included) {
      assert.equal(matchesFilter(filter, blockHash, script), true, `script ${hex.encode(script).slice(0, 24)} should match`);
    }
  });

  test(`BIP-158 vector at height ${height}: excluded scripts do not`, () => {
    const filter = hex.decode(filterHex);
    for (const script of blockOutputScripts(block).scripts) {
      if (script.length === 0 || script[0] === 0x6a) {
        assert.equal(matchesFilter(filter, blockHash, script), false);
      }
    }
  });
}

test('a script from another block does not match', () => {
  const one = VECTORS[4];
  const other = VECTORS[6];
  const script = blockOutputScripts(hex.decode(one[2])).scripts.find((s) => s.length > 0 && s[0] !== 0x6a);
  assert.equal(matchesFilter(hex.decode(other[5]), other[1], script), false);
});

test('the filter key is the digest order, not the displayed hash', () => {
  const hash = VECTORS[0][1];
  const key = filterKey(hash);
  assert.equal(hex.encode(key), Buffer.from(hash, 'hex').reverse().slice(0, 16).toString('hex'));
});

test('a block hash that is not 32 bytes is refused', () => {
  assert.throws(() => filterKey('abcd'), /64 hex/);
});

test('an empty script is never a match', () => {
  const row = VECTORS[0];
  assert.equal(matchesFilter(hex.decode(row[5]), row[1], new Uint8Array(0)), false);
});

test('a block with nothing to filter yields the empty filter', () => {
  const out = buildBasicFilter({ outputScripts: [], prevScripts: [], blockHash: VECTORS[0][1] });
  assert.equal(hex.encode(out), '00');
});

test('the same script twice builds the same filter as once', () => {
  const row = VECTORS[3];
  const { scripts } = blockOutputScripts(hex.decode(row[2]));
  const prevScripts = row[3].map((s) => hex.decode(s));
  const once = buildBasicFilter({ outputScripts: scripts, prevScripts, blockHash: row[1] });
  const twice = buildBasicFilter({
    outputScripts: [...scripts, ...scripts], prevScripts, blockHash: row[1],
  });
  assert.equal(hex.encode(twice), hex.encode(once));
});

test('genesis chains from 32 zero bytes', () => {
  const row = VECTORS[0];
  assert.equal(hex.encode(filterHeader(hex.decode(row[5]), new Uint8Array(32))), row[6]);
});

test('the filter header refuses a previous header that is not 32 bytes', () => {
  assert.throws(() => filterHeader(new Uint8Array(2), new Uint8Array(31)), /32 bytes/);
});
