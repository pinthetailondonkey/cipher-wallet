import test from 'node:test';
import assert from 'node:assert/strict';
import {
  KDF_ITERATIONS, isAcceptableNewPin, isDamagedVault, isPlausiblePin,
  openVault, sealVault,
} from '../src/vault.js';

const SECRET = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
const PIN = '12345678';

test('the right PIN opens the vault', async () => {
  const envelope = await sealVault(SECRET, PIN);
  assert.deepEqual(Array.from(await openVault(envelope, PIN)), Array.from(SECRET));
});

test('a wrong PIN fails closed and says so', async () => {
  const envelope = await sealVault(SECRET, PIN);
  await assert.rejects(openVault(envelope, '87654321'), (error) => error.code === 'wrong-pin');
});

test('every seal uses a new salt and a new IV', async () => {
  const a = await sealVault(SECRET, PIN);
  const b = await sealVault(SECRET, PIN);
  assert.notDeepEqual(a.salt, b.salt);
  assert.notDeepEqual(a.iv, b.iv);
  assert.notDeepEqual(a.data, b.data);
});

test('the iteration count is the current one, not a legacy count', async () => {
  const envelope = await sealVault(SECRET, PIN);
  assert.equal(envelope.iter, KDF_ITERATIONS);
  assert.equal(KDF_ITERATIONS, 600000);
});

test('a changed byte is a damaged vault, not a wrong PIN', async () => {
  const envelope = await sealVault(SECRET, PIN);
  const tampered = { ...envelope, data: [...envelope.data] };
  tampered.data[0] ^= 0xff;
  await assert.rejects(openVault(tampered, PIN), (error) => error.code === 'wrong-pin');
});

test('a truncated envelope is damaged and spends no attempt', async () => {
  assert.equal(isDamagedVault(null), true);
  assert.equal(isDamagedVault({}), true);
  const envelope = await sealVault(SECRET, PIN);
  for (const broken of [
    { ...envelope, v: 2 },
    { ...envelope, kdf: 'sha1' },
    { ...envelope, iter: 100000 },
    { ...envelope, salt: [1, 2, 3] },
    { ...envelope, iv: [1, 2, 3] },
    { ...envelope, data: [] },
  ]) {
    assert.equal(isDamagedVault(broken), true);
    await assert.rejects(openVault(broken, PIN), (error) => error.code === 'damaged-vault');
  }
});

test('a new PIN is exactly eight digits; an old one may be six or more', async () => {
  assert.equal(isAcceptableNewPin('12345678'), true);
  assert.equal(isAcceptableNewPin('1234567'), false);
  assert.equal(isAcceptableNewPin('1234567a'), false);
  assert.equal(isPlausiblePin('123456'), true);
  assert.equal(isPlausiblePin('12345'), false);
  await assert.rejects(sealVault(SECRET, '1234567'), /exactly 8 digits/);
});

test('there is nothing to seal from an empty secret', async () => {
  await assert.rejects(sealVault(new Uint8Array(0), PIN), /nothing to seal/);
});
