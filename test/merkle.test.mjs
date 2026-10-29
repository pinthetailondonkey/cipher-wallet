// A block's body against its header.
//
// The bug this closes was executed, not feared: a peer kept a real 80-byte
// header, attached a body of its own choosing that paid a script it wanted paid,
// and both checks the wallet had — "the header hashes to the advertised hash"
// and "the filter matches the body" — passed. A filter rebuilt from a forged
// body agrees with a filter built from that same forged body. The header's
// merkle field is the only thing that ties the two together, and nothing read
// it.
//
// The positive controls here are the published BIP-158 blocks: every one of
// them must verify, and its transaction ids must agree with the independently
// tested `txid()` in src/tx.js. A check that is simply too strict would refuse
// a real block and fail these; a check that does nothing would accept the forged
// body below.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { hex } from '@scure/base';
import { parseTx, readVarint, reverseBytes, serializeTx, sha256d, txid } from '../src/tx.js';
import { headerMerkleRoot, merkleRootOf, txidOf, verifyBlockBody } from '../src/merkle.js';

const VECTORS = JSON.parse(
  readFileSync(new URL('./fixtures/bip158-testnet-19.json', import.meta.url), 'utf8'),
).slice(1).map((row) => row.map((field) => (typeof field === 'string' ? field.replace(/ /g, '') : field)));

function witness(name, ...values) {
  console.log(`[merkle] ${name}: ${values.join(' | ')}`);
}

function txidsIn(bytes) {
  const count = readVarint(bytes, 80);
  const out = [];
  let at = count.offset;
  for (let i = 0; i < count.value; i += 1) {
    const tx = parseTx(bytes, { offset: at, exact: false });
    out.push({ tx, at, id: txidOf(bytes, at, tx) });
    at += tx.size;
  }
  return out;
}

test('every published block verifies against its own header, and its txids agree with txid()', () => {
  // Ten vectors, ten blocks. The count is exact so a fixture that quietly
  // stopped loading would show here rather than as a smaller green.
  assert.equal(VECTORS.length, 10);
  const seen = [];
  for (const [height, blockHash, blockHex] of VECTORS) {
    const bytes = hex.decode(blockHex);
    const out = verifyBlockBody(bytes);
    assert.equal(out.blockHash, blockHash, `height ${height}`);
    assert.equal(out.merkleRoot, headerMerkleRoot(bytes.slice(0, 80)), `height ${height}`);
    // The two ways of naming a transaction must agree: bytes-with-witness-cut
    // (this module) and re-serialized-without-witness (tx.js, tested against
    // BIP-143). They disagree if the marker/flag is left in, which is how this
    // was written first.
    let witnesses = 0;
    for (const { tx, id } of txidsIn(bytes)) {
      assert.equal(id, txid(tx), `height ${height}`);
      if (tx.witness) witnesses += 1;
    }
    seen.push(`${height}:${out.txids.length}tx${witnesses ? `/${witnesses}w` : ''}`);
  }
  witness('verified blocks', seen.join(' '));
});

test('the merkle root of one transaction is that transaction, and of two is their pair', () => {
  const [, , blockHex] = VECTORS[0];
  const bytes = hex.decode(blockHex);
  const [{ id }] = txidsIn(bytes);
  assert.equal(merkleRootOf([id]), id);

  const [a, b] = ['11'.repeat(32), '22'.repeat(32)];
  // Spelled plainly, the pair hash is sha256d of the two ids in internal order.
  const pair = new Uint8Array(64);
  pair.set(reverseBytes(hex.decode(a)), 0);
  pair.set(reverseBytes(hex.decode(b)), 32);
  assert.equal(merkleRootOf([a, b]), hex.encode(reverseBytes(sha256d(pair))));
  // An odd node is paired with itself, three ids being (0,1) then (2,2).
  const pair01 = sha256d(pair);
  const pair22 = sha256d(new Uint8Array([...reverseBytes(hex.decode(b)), ...reverseBytes(hex.decode(b))]));
  const top = new Uint8Array([...pair01, ...pair22]);
  assert.equal(merkleRootOf([a, b, b]), hex.encode(reverseBytes(sha256d(top))));
  witness('merkle fold', `single ${merkleRootOf([id]).slice(0, 16)}`, 'pair and odd tail checked');
});

// A body that pays `script`, which no header commits to.
function forgedBlock({ headerFrom, script }) {
  const header = hex.decode(headerFrom).slice(0, 80);
  const tx = {
    version: 2,
    inputs: [{ txid: '00'.repeat(32), vout: 0xffffffff, scriptSig: Uint8Array.of(0x51), sequence: 0xffffffff }],
    outputs: [{ value: 5000000000n, script }],
    lockTime: 0,
  };
  return new Uint8Array([...header, 0x01, ...serializeTx(tx, { witness: false })]);
}

test('a real header with a body it does not commit to is refused', () => {
  const [, blockHash, blockHex] = VECTORS[0];
  const ourScript = Uint8Array.from([0x00, 0x14, ...new Uint8Array(20).fill(7)]);
  const forged = forgedBlock({ headerFrom: blockHex, script: ourScript });

  // The header is untouched, so it still hashes to the advertised hash: that
  // check cannot see this.
  assert.equal(hex.encode(reverseBytes(sha256d(forged.slice(0, 80)))), blockHash);
  // And the body really does pay our script, so a filter built from it would
  // match a filter built from it.
  const tx = parseTx(forged, { offset: 81, exact: true });
  assert.equal(hex.encode(tx.outputs[0].script), hex.encode(ourScript));

  assert.throws(() => verifyBlockBody(forged), /merkle root/);
  witness('forged body under a real header', `header ${blockHash.slice(0, 16)}`, 'refused');
});

test('the same transaction twice in one body is refused, and so are trailing bytes', () => {
  const [, , blockHex] = VECTORS[0];
  const real = hex.decode(blockHex);
  const oneTx = real.slice(80);
  const doubled = new Uint8Array([...real.slice(0, 80), 0x02, ...oneTx.slice(1), ...oneTx.slice(1)]);
  assert.throws(() => verifyBlockBody(doubled), /twice/);

  const trailing = new Uint8Array([...real, 0x00]);
  assert.throws(() => verifyBlockBody(trailing), /bytes after its last transaction/);

  assert.throws(() => verifyBlockBody(new Uint8Array([...real.slice(0, 80), 0x00])), /at least one transaction/);
  witness('malformed bodies', 'duplicate refused', 'trailing byte refused', 'empty refused');
});
