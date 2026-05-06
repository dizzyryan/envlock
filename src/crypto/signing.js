'use strict';

const sodium = require('libsodium-wrappers');

/**
 * Ed25519 digital signatures for tamper protection.
 *
 * Security model:
 * - The .env.enc file is signed by a trusted signer after encryption.
 * - Before decryption, signatures are verified against a LOCAL trust store.
 * - An attacker who modifies .env.enc and re-signs with their own key will be
 *   rejected because their key is NOT in the verifier's trust store.
 * - Trust is anchored OUTSIDE the file (in ~/.envlock/trust.json), preventing
 *   the attacker from simply adding their public key to the file.
 */

/**
 * Generate a new Ed25519 keypair.
 *
 * The secret key is 64 bytes (seed + public key concatenated, libsodium convention).
 * The public key is 32 bytes.
 *
 * @returns {{ publicKey: Uint8Array, secretKey: Uint8Array }}
 */
function generateSigningKeypair() {
  return sodium.crypto_sign_keypair();
}

/**
 * Compute the canonical signing payload from an envelope.
 *
 * CRITICAL: We sign everything EXCEPT the signatures field itself.
 * This prevents circular dependencies and allows signature to cover all
 * meaningful data (ciphertext, recipients, metadata).
 *
 * We use deterministic JSON serialization (sorted keys at ALL levels) to ensure
 * the same logical content always produces the same byte sequence for signing.
 *
 * @param {object} envelope - The .env.enc envelope object
 * @returns {Uint8Array} Canonical byte representation to sign
 */
function computeSigningPayload(envelope) {
  // Create a copy without signatures for canonical representation
  const forSigning = {
    version: envelope.version,
    cipher: envelope.cipher,
    env: envelope.env,
    recipients: envelope.recipients,
  };

  // Deterministic serialization: recursively sort all object keys
  const canonical = JSON.stringify(forSigning, canonicalReplacer);
  return new Uint8Array(Buffer.from(canonical, 'utf8'));
}

/**
 * JSON replacer that sorts object keys recursively for canonical serialization.
 * Arrays maintain their order (order-dependent), objects get sorted keys.
 */
function canonicalReplacer(key, value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const sorted = {};
    for (const k of Object.keys(value).sort()) {
      sorted[k] = value[k];
    }
    return sorted;
  }
  return value;
}

/**
 * Sign an envelope with a signer's Ed25519 secret key.
 *
 * Produces a detached signature (64 bytes) over the canonical payload.
 * Detached signatures allow verification without needing to unwrap the message.
 *
 * @param {object} envelope - The envelope to sign (without signatures)
 * @param {Uint8Array} secretKey - 64-byte Ed25519 secret key
 * @returns {string} Base64-encoded detached signature
 */
function signEnvelope(envelope, secretKey) {
  const payload = computeSigningPayload(envelope);
  const signature = sodium.crypto_sign_detached(payload, secretKey);
  return Buffer.from(signature).toString('base64');
}

/**
 * Verify a detached Ed25519 signature over an envelope.
 *
 * @param {object} envelope - The envelope that was signed
 * @param {string} signatureBase64 - Base64-encoded signature to verify
 * @param {Uint8Array} publicKey - 32-byte Ed25519 public key of alleged signer
 * @returns {boolean} True if signature is valid
 */
function verifySignature(envelope, signatureBase64, publicKey) {
  try {
    const payload = computeSigningPayload(envelope);
    const signature = Buffer.from(signatureBase64, 'base64');

    if (signature.length !== sodium.crypto_sign_BYTES) {
      return false;
    }

    return sodium.crypto_sign_verify_detached(
      new Uint8Array(signature),
      payload,
      publicKey
    );
  } catch {
    // Any error during verification means the signature is invalid
    return false;
  }
}

/**
 * Verify that at least one signature on the envelope comes from a trusted signer.
 *
 * SECURITY-CRITICAL FUNCTION:
 * - This MUST be called BEFORE any decryption attempt.
 * - It enforces the trust model: only locally-trusted keys can authorize decryption.
 * - An attacker can re-sign with their own key, but it won't be in the trust store.
 *
 * @param {object} envelope - Complete envelope including signatures
 * @param {Map<string, Uint8Array>} trustedSigners - Map of id → Ed25519 public key
 * @returns {{ valid: boolean, signerId: string|null, error: string|null }}
 */
function verifyEnvelopeTrust(envelope, trustedSigners) {
  if (!envelope.signatures || !Array.isArray(envelope.signatures) || envelope.signatures.length === 0) {
    return { valid: false, signerId: null, error: 'No signatures present in envelope' };
  }

  // Check each signature against trusted signers
  for (const sig of envelope.signatures) {
    const trustedKey = trustedSigners.get(sig.id);

    if (!trustedKey) {
      // This signer is not trusted — skip (attacker's signature)
      continue;
    }

    // Verify the signature with the trusted key
    const isValid = verifySignature(envelope, sig.sig, trustedKey);

    if (isValid) {
      return { valid: true, signerId: sig.id, error: null };
    }
    // If signature doesn't verify, the file was modified after signing — continue checking others
  }

  return {
    valid: false,
    signerId: null,
    error: 'No valid signature from a trusted signer. File may have been tampered with.',
  };
}

module.exports = {
  generateSigningKeypair,
  computeSigningPayload,
  signEnvelope,
  verifySignature,
  verifyEnvelopeTrust,
};
