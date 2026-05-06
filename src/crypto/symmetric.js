'use strict';

const crypto = require('node:crypto');

// --- AES-256-GCM Configuration ---
// GCM provides authenticated encryption: confidentiality + integrity in one pass.
const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32; // 256 bits
const IV_LENGTH = 12; // 96 bits — NIST recommended for GCM
const TAG_LENGTH = 16; // 128-bit authentication tag

/**
 * Generate a cryptographically secure random data key.
 * This is the symmetric key used to encrypt the .env file contents.
 *
 * @returns {Buffer} 32-byte random key
 */
function generateDataKey() {
  return crypto.randomBytes(KEY_LENGTH);
}

/**
 * Encrypt plaintext using AES-256-GCM.
 *
 * Security properties:
 * - Fresh random 12-byte IV ensures semantic security (identical plaintexts → different ciphertexts)
 * - GCM authentication tag detects any ciphertext tampering
 * - No key derivation needed here — key is already a full-entropy 32-byte random
 *
 * @param {Buffer} plaintext - Data to encrypt
 * @param {Buffer} key - 32-byte symmetric key
 * @returns {{ iv: string, tag: string, ciphertext: string }} Base64-encoded components
 */
function encrypt(plaintext, key) {
  if (!Buffer.isBuffer(plaintext)) {
    throw new Error('Plaintext must be a Buffer');
  }
  if (!Buffer.isBuffer(key) || key.length !== KEY_LENGTH) {
    throw new Error(`Key must be a ${KEY_LENGTH}-byte Buffer`);
  }

  const iv = crypto.randomBytes(IV_LENGTH);

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, {
    authTagLength: TAG_LENGTH,
  });

  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ciphertext: encrypted.toString('base64'),
  };
}

/**
 * Decrypt AES-256-GCM ciphertext.
 *
 * Security: Authentication tag is verified before returning ANY plaintext.
 * If ciphertext or IV was tampered, final() throws and no data is returned.
 *
 * @param {{ iv: string, tag: string, ciphertext: string }} envelope - Encrypted components
 * @param {Buffer} key - 32-byte symmetric key
 * @returns {Buffer} Decrypted plaintext
 */
function decrypt(envelope, key) {
  if (!Buffer.isBuffer(key) || key.length !== KEY_LENGTH) {
    throw new Error(`Key must be a ${KEY_LENGTH}-byte Buffer`);
  }

  const iv = Buffer.from(envelope.iv, 'base64');
  const tag = Buffer.from(envelope.tag, 'base64');
  const ciphertext = Buffer.from(envelope.ciphertext, 'base64');

  if (iv.length !== IV_LENGTH) {
    throw new Error('Invalid IV length');
  }
  if (tag.length !== TAG_LENGTH) {
    throw new Error('Invalid authentication tag length');
  }

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, {
    authTagLength: TAG_LENGTH,
  });

  // Set auth tag BEFORE update/final — GCM verifies on final()
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

  return decrypted;
}

module.exports = {
  generateDataKey,
  encrypt,
  decrypt,
  KEY_LENGTH,
  IV_LENGTH,
  TAG_LENGTH,
  ALGORITHM,
};
