import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DeviceKeyMissing, DeviceKeyUnavailable, isDeviceVault,
  makeSecretProvider, wrapDeviceVault, unwrapDeviceVault,
} from '../src/deviceEnvelope.js';

const INNER = { v: 1, kdf: 'pbkdf2-sha256-aes-gcm', iter: 600000, salt: [1], iv: [2], data: [3] };

function providerWith(secret) {
  return makeSecretProvider({
    kind: 'prf',
    available: async () => true,
    enroll: async () => ({ k: 'prf', id: 'device-1' }),
    getSecret: async () => secret,
    destroy: async () => {},
  });
}

const PROVIDER = providerWith(new Uint8Array(32).fill(7));
const OTHER = providerWith(new Uint8Array(32).fill(9));
const DK = { k: 'prf', id: 'device-1' };

test('the device layer opens back to the same inner vault', async () => {
  const wrapped = await wrapDeviceVault(PROVIDER, 'pkA', DK, INNER);
  assert.equal(isDeviceVault(wrapped), true);
  assert.deepEqual(await unwrapDeviceVault(wrapped, 'pkA', PROVIDER), INNER);
});

test('a different device key does not open it, and is not a wrong PIN', async () => {
  const wrapped = await wrapDeviceVault(PROVIDER, 'pkA', DK, INNER);
  await assert.rejects(
    unwrapDeviceVault(wrapped, 'pkA', OTHER),
    (error) => error instanceof DeviceKeyMissing && error.code === 'wrong-key',
  );
});

test('the envelope is bound to the account it was wrapped for', async () => {
  const wrapped = await wrapDeviceVault(PROVIDER, 'pkA', DK, INNER);
  await assert.rejects(unwrapDeviceVault(wrapped, 'pkB', PROVIDER), (error) => error.code === 'wrong-key');
});

test('a changed byte fails closed', async () => {
  const wrapped = await wrapDeviceVault(PROVIDER, 'pkA', DK, INNER);
  const tampered = { ...wrapped, data: [...wrapped.data] };
  tampered.data[0] ^= 0xff;
  await assert.rejects(unwrapDeviceVault(tampered, 'pkA', PROVIDER), (error) => error.code === 'wrong-key');
});

test('a provider of the wrong kind is refused, not guessed', async () => {
  const wrapped = await wrapDeviceVault(PROVIDER, 'pkA', DK, INNER);
  const other = makeSecretProvider({ ...PROVIDER, kind: 'safe' });
  await assert.rejects(unwrapDeviceVault(wrapped, 'pkA', other), (error) => error.code === 'kind-mismatch');
});

test('a vault cannot be wrapped twice', async () => {
  const wrapped = await wrapDeviceVault(PROVIDER, 'pkA', DK, INNER);
  await assert.rejects(wrapDeviceVault(PROVIDER, 'pkA', DK, wrapped), (error) => error instanceof DeviceKeyUnavailable);
});

test('no provider and no account each say so plainly', async () => {
  const wrapped = await wrapDeviceVault(PROVIDER, 'pkA', DK, INNER);
  await assert.rejects(unwrapDeviceVault(wrapped, 'pkA', null), (error) => error.code === 'no-provider');
  await assert.rejects(unwrapDeviceVault(wrapped, '', PROVIDER), (error) => error.code === 'no-account');
  await assert.rejects(unwrapDeviceVault({ v: 3 }, 'pkA', PROVIDER), (error) => error.code === 'malformed');
});
