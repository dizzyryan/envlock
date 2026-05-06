'use strict';

const sodium = require('libsodium-wrappers');

/**
 * Asymmetric encryption using X25519 sealed boxes (libsodium).
 *
 * Sealed boxes provide anonymous public-key encryption:
 * - Sender does NOT need to identify themselves
 * - Only the recipient's public key is needed to encrypt
 * - Only the recipient can decrypt with their private key
 *
 * Under the hood: X25519 key agreement + XSalsa20-Poly1305 authenticated encryption.
 *
 * We use Ed25519 keys as the canonical keypair and derive X25519 keys from them.
 * This is a well-established pattern (used by Signal, age, etc.) that gives each
 * user a single keypair for both signing (Ed25519) and encryption (X25519).
 */

/**
 * Ensure libsodium is initialized before any crypto operations.
 * libsodium-wrappers requires an async init step.
 */
async function ensureReady() {
  await sodium.ready;
}

/**
 * Convert an Ed25519 public key to X25519 (Curve25519) for encryption.
 *
 * Security: This is a one-way mathematical conversion using the birational map
 * between Ed25519 and Curve25519. It does NOT weaken either key.
 *
 * @param {Uint8Array} ed25519Pk - 32-byte Ed25519 public key
 * @returns {Uint8Array} 32-byte X25519 public key
 */
function ed25519PkToX25519(ed25519Pk) {
  return sodium.crypto_sign_ed25519_pk_to_curve25519(ed25519Pk);
}

/**
 * Convert an Ed25519 secret key to X25519 (Curve25519) for decryption.
 *
 * @param {Uint8Array} ed25519Sk - 64-byte Ed25519 secret key
 * @returns {Uint8Array} 32-byte X25519 secret key
 */
function ed25519SkToX25519(ed25519Sk) {
  return sodium.crypto_sign_ed25519_sk_to_curve25519(ed25519Sk);
}

/**
 * Encrypt a data key for a specific recipient using their Ed25519 public key.
 *
 * Flow:
 * 1. Convert recipient's Ed25519 public key → X25519 public key
 * 2. Seal the data key using crypto_box_seal (anonymous encryption)
 *
 * The sealed box includes an ephemeral X25519 keypair internally, providing
 * forward secrecy for this particular encryption operation.
 *
 * @param {Buffer} dataKey - 32-byte symmetric data key to encrypt
 * @param {Uint8Array} recipientEd25519Pk - Recipient's Ed25519 public key
 * @returns {string} Base64-encoded sealed box
 */
function encryptDataKeyForRecipient(dataKey, recipientEd25519Pk) {
  const x25519Pk = ed25519PkToX25519(recipientEd25519Pk);
  const sealed = sodium.crypto_box_seal(new Uint8Array(dataKey), x25519Pk);
  return Buffer.from(sealed).toString('base64');
}

/**
 * Decrypt a data key using the recipient's Ed25519 secret key.
 *
 * Flow:
 * 1. Convert Ed25519 keypair → X25519 keypair
 * 2. Open the sealed box using crypto_box_seal_open
 *
 * If the sealed box was tampered or the wrong key is used, this throws.
 *
 * @param {string} encryptedKeyBase64 - Base64-encoded sealed box
 * @param {Uint8Array} recipientEd25519Pk - Recipient's Ed25519 public key
 * @param {Uint8Array} recipientEd25519Sk - Recipient's Ed25519 secret key
 * @returns {Buffer} 32-byte decrypted data key
 */
function decryptDataKey(encryptedKeyBase64, recipientEd25519Pk, recipientEd25519Sk) {
  const sealed = Buffer.from(encryptedKeyBase64, 'base64');
  const x25519Pk = ed25519PkToX25519(recipientEd25519Pk);
  const x25519Sk = ed25519SkToX25519(recipientEd25519Sk);

  const dataKey = sodium.crypto_box_seal_open(
    new Uint8Array(sealed),
    x25519Pk,
    x25519Sk
  );

  if (!dataKey) {
    throw new Error('Failed to decrypt data key — wrong key or tampered ciphertext');
  }

  return Buffer.from(dataKey);
}

module.exports = {
  ensureReady,
  encryptDataKeyForRecipient,
  decryptDataKey,
  ed25519PkToX25519,
  ed25519SkToX25519,
};
