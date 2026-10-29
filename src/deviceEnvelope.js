// The device envelope: an outer AES-GCM layer around the PIN vault.
//
//   vault = {
//     v: 3,
//     dk: { k: 'prf' | 'safe' | 'keystore', ...public handle of the device key },
//     iv: [12 bytes], data: [ciphertext],
//   }
//   data = AES-GCM(device key, JSON(inner vault), aad = deviceVaultAad(pk, k))
//
// The inner vault is the PIN vault exactly as src/vault.js writes it. Opening
// takes both: the device first, then the PIN. A copy of the stored files has
// the PIN layer but not the device key, so a copied ciphertext is dead.
//
// Ported from cipher/src/lib/vaultEnvelope.js @ ec6e98b. Nothing here writes a
// vault to storage; it only builds and opens blobs.

export const DEVICE_VAULT_VERSION = 3;
export const DEVICE_KINDS = ['prf', 'safe', 'keystore'];

const HKDF_INFO = 'cipher-vault-3';

// Typed so the PIN counter can tell them from a wrong PIN: none of these is
// ever counted toward a wipe.
export class DeviceKeyError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = 'DeviceKeyError';
    this.code = code;
  }
}

export class DeviceKeyCancelled extends DeviceKeyError {
  constructor(message) {
    super('cancelled', message || 'The device prompt was cancelled.');
    this.name = 'DeviceKeyCancelled';
  }
}

export class DeviceKeyMissing extends DeviceKeyError {
  constructor(code = 'missing', message) {
    super(code, message || 'This device does not hold the key for this account.');
    this.name = 'DeviceKeyMissing';
  }
}

export class DeviceKeyUnavailable extends DeviceKeyError {
  constructor(code = 'unavailable', message) {
    super(code, message || 'This device cannot lock an account to itself.');
    this.name = 'DeviceKeyUnavailable';
  }
}

export const isDeviceKeyError = (error) => error instanceof DeviceKeyError;

export const isDeviceVault = (vault) => !!vault && typeof vault === 'object' && vault.v === DEVICE_VAULT_VERSION;

export function deviceVaultAad(pk, kind) {
  return `cipher-vault-3|${pk}|${kind}`;
}

const enc = new TextEncoder();
const dec = new TextDecoder();

async function aesKeyFromSecret(secret, usage) {
  const material = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: enc.encode(HKDF_INFO) },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    [usage],
  );
}

// A provider whose device secret is 32 bytes the page can hold for a moment
// (a passkey PRF output, a Keystore-stored secret). The AES layer is the same
// for all of them.
//
// Interface: kind, available(), enroll(pk) -> dk, seal/open, destroy(pk, dk).
export function makeSecretProvider({ kind, available, enroll, getSecret, destroy, ...rest }) {
  return {
    ...rest,
    kind,
    available,
    enroll,
    destroy,
    async seal(pk, dk, bytes, aad) {
      const secret = await getSecret(pk, dk);
      const key = await aesKeyFromSecret(secret, 'encrypt');
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, bytes);
      return { iv: Array.from(iv), data: Array.from(new Uint8Array(data)) };
    },
    async open(pk, dk, blob, aad) {
      const secret = await getSecret(pk, dk);
      const key = await aesKeyFromSecret(secret, 'decrypt');
      const plain = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(blob.iv), additionalData: aad },
        key,
        new Uint8Array(blob.data),
      );
      return new Uint8Array(plain);
    },
  };
}

export async function wrapDeviceVault(provider, pk, dk, innerVault) {
  if (!provider || !dk || dk.k !== provider.kind) throw new DeviceKeyUnavailable('kind-mismatch');
  if (isDeviceVault(innerVault)) throw new DeviceKeyUnavailable('already-wrapped');
  const aad = enc.encode(deviceVaultAad(pk, dk.k));
  const { iv, data } = await provider.seal(pk, dk, enc.encode(JSON.stringify(innerVault)), aad);
  return { v: DEVICE_VAULT_VERSION, dk, iv, data };
}

// Returns the inner PIN vault. Everything that goes wrong here is a
// DeviceKeyError: the person is never told they typed a wrong PIN for it.
export async function unwrapDeviceVault(vault, pk, provider) {
  if (!provider) throw new DeviceKeyMissing('no-provider');
  if (!pk) throw new DeviceKeyMissing('no-account');
  const dk = vault?.dk;
  if (!dk || typeof dk.k !== 'string' || !Array.isArray(vault.iv) || !Array.isArray(vault.data)) {
    throw new DeviceKeyMissing('malformed');
  }
  if (dk.k !== provider.kind) throw new DeviceKeyMissing('kind-mismatch');
  let plain;
  try {
    plain = await provider.open(pk, dk, { iv: vault.iv, data: vault.data }, enc.encode(deviceVaultAad(pk, dk.k)));
  } catch (error) {
    if (error instanceof DeviceKeyError) throw error;
    throw new DeviceKeyMissing('wrong-key');
  }
  let inner;
  try {
    inner = JSON.parse(dec.decode(plain));
  } catch {
    throw new DeviceKeyMissing('malformed');
  }
  if (!inner || typeof inner !== 'object' || isDeviceVault(inner)) throw new DeviceKeyMissing('malformed');
  return inner;
}

// One place that says which provider this build uses. Set by platform code at
// start; tests set a fake.
let currentProvider = null;
export const setDeviceProvider = (provider) => { currentProvider = provider || null; };
export const getDeviceProvider = () => currentProvider;
