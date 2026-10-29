import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { ed25519 } from '@noble/curves/ed25519.js';
import {
  FIELD,
  FIELD_CONSTANTS,
  GROUP_ORDER,
  decodePoint,
  derivePublicKey,
  deriveSecretKey,
  hashToPoint,
  hashToScalar,
  isCanonicalScalar,
  keyDerivation,
  keyImage,
  scReduce32,
  secretToPublic,
  varint,
  viewSecretFromSpend,
  viewTag,
} from '../src/monero/keys.js';

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const unhex = (text) => Uint8Array.from(Buffer.from(text, 'hex'));

// The fixture is Monero's own tests/crypto/tests.txt, cut to a bounded subset.
// Every 64-character hex field has one space after character 32 so it is not a
// bare 32-byte hex run (see test/fixtures/README.md). The field layout per
// command is fixed, so joining is done by arity rather than by guessing. A
// command may have two layouts: the ordinary vector, and the refusal vector
// Monero ends a section with, which has no expected output and one fewer field.
const SHAPE = {
  secret_key_to_public_key: [[2, 1, 2], [2, 1]],
  // The data being hashed may itself be 32 bytes, so its width is not fixed.
  hash_to_scalar: [['*', 2]],
  biased_hash_to_ec: [[2, 2]],
  generate_key_derivation: [[2, 2, 1, 2], [2, 2, 1]],
  generate_key_image: [[2, 2, 2]],
  derive_public_key: [[2, 1, 2, 1, 2], [2, 1, 2, 1]],
  derive_view_tag: [[2, 1, 1]],
  derive_secret_key: [[2, 1, 2, 2]],
};

function readVectors() {
  const path = fileURLToPath(new URL('./fixtures/monero-crypto.txt', import.meta.url));
  const rows = [];
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    const tokens = line.trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    const [command, ...rest] = tokens;
    const alternatives = SHAPE[command];
    assert.ok(alternatives, `unknown vector command in the fixture: ${command}`);
    const fixedOf = (alt) => alt.filter((w) => w !== '*').reduce((a, b) => a + b, 0);
    const shape = alternatives.find((alt) => (alt.includes('*')
      ? rest.length > fixedOf(alt)
      : rest.length === fixedOf(alt)));
    assert.ok(shape, `unexpected field count for ${command}: ${rest.length}`);
    const fixed = fixedOf(shape);
    const fields = [];
    let at = 0;
    for (const width of shape) {
      const take = width === '*' ? rest.length - fixed : width;
      fields.push(rest.slice(at, at + take).join(''));
      at += take;
    }
    rows.push({ command, fields });
  }
  return rows;
}

const VECTORS = readVectors();

// A refusal vector carries `false` where an expected output would be. Monero
// puts them at the end of a section, which is exactly where a "keep the first N
// lines" cut loses them — it did, the first time this fixture was cut.
const rowsOf = (command) => VECTORS.filter((v) => v.command === command);
const positivesOf = (command) => rowsOf(command).filter((v) => v.fields.at(-1) !== 'false');
const refusalsOf = (command) => rowsOf(command).filter((v) => v.fields.at(-1) === 'false');

test('the fixture carries every section it is supposed to', () => {
  const kinds = new Set(VECTORS.map((v) => v.command));
  for (const command of Object.keys(SHAPE)) assert.ok(kinds.has(command), `missing ${command}`);
  assert.ok(VECTORS.length >= 500, 'the fixture was cut too short to be worth keeping');
});

test('l * G is the identity, so the group order constant is right', () => {
  assert.equal(ed25519.Point.BASE.multiplyUnsafe(GROUP_ORDER - 1n).add(ed25519.Point.BASE).is0(), true);
  assert.equal(ed25519.Point.BASE.multiplyUnsafe(1n).is0(), false);
});

test('the field constants are the numbers their own comments describe', () => {
  const c = FIELD_CONSTANTS;
  const A = 486662n;
  const t = (A * (A + 2n)) % FIELD;
  const twice = (2n * t) % FIELD;
  assert.equal(c.ma, (FIELD - A) % FIELD, '-A');
  assert.equal(c.ma2, (FIELD - ((A * A) % FIELD)) % FIELD, '-A^2');
  assert.equal((c.sqrtM1 * c.sqrtM1) % FIELD, FIELD - 1n, 'sqrt(-1) squared is -1');
  assert.equal((c.fffb1 * c.fffb1) % FIELD, (FIELD - twice) % FIELD, 'sqrt(-2A(A+2))');
  assert.equal((c.fffb2 * c.fffb2) % FIELD, twice, 'sqrt(2A(A+2))');
  // These two are A(A+2), not 2A(A+2) — the factor of two is only in the first pair.
  assert.equal((c.fffb3 * c.fffb3) % FIELD, (FIELD - ((c.sqrtM1 * t) % FIELD)) % FIELD, 'sqrt(-sqrt(-1)A(A+2))');
  assert.equal((c.fffb4 * c.fffb4) % FIELD, (c.sqrtM1 * t) % FIELD, 'sqrt(sqrt(-1)A(A+2))');
});

test('secret_key_to_public_key matches Monero for every vector', () => {
  const rows = positivesOf('secret_key_to_public_key');
  assert.equal(rows.length, 32, `the positive vectors were cut or added to: ${rows.length}`);
  for (const { fields } of rows) {
    const [secret, , expected] = fields;
    assert.equal(hex(secretToPublic(unhex(secret))), expected);
  }
});

test('hash_to_scalar matches Monero for every vector', () => {
  const rows = VECTORS.filter((v) => v.command === 'hash_to_scalar');
  assert.equal(rows.length, 32, `the positive vectors were cut or added to: ${rows.length}`);
  for (const { fields } of rows) {
    const [data, expected] = fields;
    assert.equal(hex(hashToScalar(unhex(data))), expected);
  }
});

test('hash to point matches Monero for every vector', () => {
  const rows = VECTORS.filter((v) => v.command === 'biased_hash_to_ec');
  assert.equal(rows.length, 64, `the positive vectors were cut or added to: ${rows.length}`);
  for (const { fields } of rows) {
    const [publicKey, expected] = fields;
    assert.equal(hex(hashToPoint(unhex(publicKey))), expected);
  }
});

test('key derivation matches Monero for every vector', () => {
  const rows = positivesOf('generate_key_derivation');
  assert.equal(rows.length, 32, `the positive vectors were cut or added to: ${rows.length}`);
  for (const { fields } of rows) {
    const [publicKey, secret, ok, expected] = fields;
    assert.equal(ok, 'true');
    assert.equal(hex(keyDerivation(unhex(publicKey), unhex(secret))), expected);
  }
});

test('key images match Monero for every vector', () => {
  const rows = VECTORS.filter((v) => v.command === 'generate_key_image');
  assert.equal(rows.length, 32, `the positive vectors were cut or added to: ${rows.length}`);
  for (const { fields } of rows) {
    const [publicKey, secret, expected] = fields;
    assert.equal(hex(keyImage(unhex(publicKey), unhex(secret))), expected);
  }
});

test('derived one-time keys match Monero for every vector', () => {
  const rows = positivesOf('derive_public_key');
  assert.equal(rows.length, 32, `the positive vectors were cut or added to: ${rows.length}`);
  for (const { fields } of rows) {
    const [derivation, index, base, ok, expected] = fields;
    assert.equal(ok, 'true');
    assert.equal(hex(derivePublicKey(unhex(derivation), Number(index), unhex(base))), expected);
  }
});

test('view tags match Monero for every vector', () => {
  const rows = VECTORS.filter((v) => v.command === 'derive_view_tag');
  assert.equal(rows.length, 16, `the positive vectors were cut or added to: ${rows.length}`);
  for (const { fields } of rows) {
    const [derivation, index, expected] = fields;
    assert.equal(viewTag(unhex(derivation), Number(index)), parseInt(expected, 16));
  }
});

test('derived one-time secrets match Monero for every vector', () => {
  const rows = rowsOf('derive_secret_key');
  // Monero emits 256 of these and they are the only in-repo pin for
  // deriveSecretKey. A shorter file means the fixture was cut again.
  assert.equal(rows.length, 256, 'the derive_secret_key vectors went missing');
  for (const { fields } of rows) {
    const [derivation, index, secret, expected] = fields;
    assert.equal(hex(deriveSecretKey(unhex(derivation), Number(index), unhex(secret))), expected);
  }
});

test('every vector Monero refuses, this wallet refuses too', () => {
  const cases = {
    secret_key_to_public_key: (f) => secretToPublic(unhex(f[0])),
    generate_key_derivation: (f) => keyDerivation(unhex(f[0]), unhex(f[1])),
    derive_public_key: (f) => derivePublicKey(unhex(f[0]), Number(f[1]), unhex(f[2])),
  };
  for (const [command, run] of Object.entries(cases)) {
    const rows = refusalsOf(command);
    // 16 per section in Monero's file. Asserting the count is the point: a cut
    // that drops them again would otherwise pass on an empty list.
    assert.equal(rows.length, 16, `${command} lost its refusal vectors`);
    for (const { fields } of rows) {
      assert.throws(() => run(fields), Error, `${command} accepted a vector Monero refuses`);
    }
  }
});

// This one is structural: it holds for any shared hash, so it would still pass
// if both functions used the same wrong one. It is kept as a shape check. The
// real pin for deriveSecretKey is Monero's 256 vectors above.
test('a derived one-time secret and its public key are a pair', () => {
  const derivation = Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 0xff);
  const secret = scReduce32(Uint8Array.from({ length: 32 }, (_, i) => (i * 11 + 5) & 0xff));
  const publicKey = secretToPublic(secret);
  const oneTimeSecret = deriveSecretKey(derivation, 3, secret);
  const oneTimePublic = derivePublicKey(derivation, 3, publicKey);
  assert.equal(hex(secretToPublic(oneTimeSecret)), hex(oneTimePublic));
});

test('the view secret is the keccak of the spend secret, reduced', () => {
  const spend = unhex('f7'.repeat(32));
  const view = viewSecretFromSpend(spend);
  assert.equal(view.length, 32);
  assert.ok(isCanonicalScalar(view));
  // deterministic, and not simply the spend secret echoed back
  assert.equal(hex(view), hex(viewSecretFromSpend(spend)));
  assert.notEqual(hex(view), hex(spend));
});

test('a scalar that is not reduced is refused rather than silently used', () => {
  const tooBig = Uint8Array.from(Buffer.from((GROUP_ORDER + 1n).toString(16).padStart(64, '0'), 'hex').reverse());
  assert.equal(isCanonicalScalar(tooBig), false);
  assert.throws(() => secretToPublic(tooBig), /not reduced mod l/);
});

test('a zero secret is refused at every door, not only where a public key is built', () => {
  const zero = new Uint8Array(32);
  const publicKey = secretToPublic(scReduce32(Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 0xff)));
  const derivation = unhex('11'.repeat(32));
  assert.throws(() => secretToPublic(zero), /zero is not a key/);
  // Without the guard these return the identity point, encoded as 0x01 then
  // zeros: a zero key image, which no other Monero node would accept.
  assert.throws(() => keyImage(publicKey, zero), /zero is not a key/);
  assert.throws(() => keyDerivation(publicKey, zero), /zero is not a key/);
  assert.throws(() => deriveSecretKey(derivation, 0, zero), /zero is not a key/);
});

test('a secret of the wrong length is refused', () => {
  assert.throws(() => secretToPublic(new Uint8Array(31)), /32 bytes/);
});

test('a point that is not on the curve is refused', () => {
  // 0xff… is not a canonical y-coordinate, so it is not a point. Hashing bytes
  // for a key image is a different operation and does not decode the input.
  const bad = Uint8Array.from({ length: 32 }, () => 0xff);
  assert.throws(() => decodePoint(bad), /not a point on the curve/);
  assert.equal(decodePoint(hashToPoint(bad)).toBytes().length, 32, 'the hash of those same bytes is a point');
});

test('the varint is Monero’s, not protobuf’s', () => {
  assert.equal(hex(varint(0)), '00');
  assert.equal(hex(varint(1)), '01');
  assert.equal(hex(varint(127)), '7f');
  assert.equal(hex(varint(128)), '8001');
  assert.equal(hex(varint(217407)), 'bfa20d');
});
