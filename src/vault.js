// The vault: the one place the root is written down.
//
// Ported from the vault half of cipher/src/useIdentity.js @ ec6e98b:
// PBKDF2-SHA256 (600,000 iterations, the current count) over the PIN with a
// per-vault random salt, then AES-GCM-256 with a fresh IV. No phone number,
// no account, no server: the PIN is the only credential.
//
// PHASE 0 SCOPE, stated so nothing is assumed: this is the INNER vault only.
// Cipher wraps this PIN vault inside a device-key envelope (v3) so a copied
// ciphertext is dead without the device key. That envelope is Phase 1 and is
// NOT here. Until it lands, the caller must not treat a vault written by this
// module as device-bound. The protection it does give is real and tested:
// a wrong PIN fails closed, a changed byte fails closed, and each seal is a
// new salt and a new IV.

export const MIN_PIN_LENGTH = 8;           // a new PIN: exactly eight digits
export const MIN_EXISTING_PIN_LENGTH = 6;  // opening an older vault
export const KDF_ITERATIONS = 600000;
export const ENVELOPE_VERSION = 1;
export const KDF_NAME = 'pbkdf2-sha256-aes-gcm';

export function isAcceptableNewPin(pin) {
  return typeof pin === 'string' && /^[0-9]{8}$/.test(pin);
}

export function isPlausiblePin(pin) {
  return typeof pin === 'string' && pin.length >= MIN_EXISTING_PIN_LENGTH;
}

// An envelope this build can still try to open. Anything else is damaged and
// says so on its own — it is not a wrong PIN and must not spend an attempt.
export function isDamagedVault(envelope) {
  if (!envelope || typeof envelope !== 'object') return true;
  if (envelope.v !== ENVELOPE_VERSION) return true;
  if (envelope.kdf !== KDF_NAME) return true;
  if (!Number.isInteger(envelope.iter) || envelope.iter < KDF_ITERATIONS) return true;
  if (!Array.isArray(envelope.salt) || envelope.salt.length !== 16) return true;
  if (!Array.isArray(envelope.iv) || envelope.iv.length !== 12) return true;
  if (!Array.isArray(envelope.data) || envelope.data.length === 0) return true;
  return false;
}

async function deriveKey(pin, salt, iterations) {
  const material = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(String(pin)),
    { name: 'PBKDF2' },
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

// Seal secret bytes under a PIN. A new salt and a new IV every time, so two
// seals of the same secret share no bytes.
export async function sealVault(secretBytes, pin, { iterations = KDF_ITERATIONS } = {}) {
  if (!(secretBytes instanceof Uint8Array) || secretBytes.length === 0) {
    throw new Error('There is nothing to seal.');
  }
  if (!isAcceptableNewPin(pin)) throw new Error(`PIN must be exactly ${MIN_PIN_LENGTH} digits.`);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(pin, salt, iterations);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    secretBytes,
  );
  return {
    v: ENVELOPE_VERSION,
    kdf: KDF_NAME,
    iter: iterations,
    salt: Array.from(salt),
    iv: Array.from(iv),
    data: Array.from(new Uint8Array(ciphertext)),
  };
}

// Open a vault. A wrong PIN and a changed byte both fail closed; the caller
// decides which sentence to show, and only a failed PIN may spend an attempt.
export async function openVault(envelope, pin) {
  if (!isPlausiblePin(pin)) throw Object.assign(new Error('Enter your PIN.'), { code: 'pin-too-short' });
  if (isDamagedVault(envelope)) {
    throw Object.assign(new Error('This device holds a damaged copy. Use the recovery phrase.'), { code: 'damaged-vault' });
  }
  const key = await deriveKey(pin, new Uint8Array(envelope.salt), envelope.iter);
  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(envelope.iv) },
      key,
      new Uint8Array(envelope.data),
    );
  } catch {
    throw Object.assign(new Error('The PIN did not open this vault.'), { code: 'wrong-pin' });
  }
  return new Uint8Array(plaintext);
}
