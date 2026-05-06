'use strict';

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

/**
 * Trust store management for envlock.
 *
 * SECURITY-CRITICAL: The trust store lives at ~/.envlock/trust.json
 * and contains Ed25519 public keys of authorized signers.
 *
 * This is the security anchor of the entire system:
 * - Trust is defined LOCALLY, not inside the encrypted file
 * - An attacker who modifies .env.enc cannot add themselves as trusted
 * - Only keys explicitly added by the user are accepted
 *
 * The trust store MUST be protected by filesystem permissions (0600).
 */

const ENVLOCK_HOME = process.env.ENVLOCK_HOME
  ? path.resolve(process.env.ENVLOCK_HOME)
  : path.join(os.homedir(), '.envlock');

const ENVLOCK_DIR = ENVLOCK_HOME;
const TRUST_FILE = path.join(ENVLOCK_DIR, 'trust.json');
const KEYS_DIR = path.join(ENVLOCK_DIR, 'keys');

/**
 * Ensure the ~/.envlock directory structure exists with correct permissions.
 */
function ensureEnvlockDir() {
  if (!fs.existsSync(ENVLOCK_DIR)) {
    fs.mkdirSync(ENVLOCK_DIR, { mode: 0o700, recursive: true });
  }
  if (!fs.existsSync(KEYS_DIR)) {
    fs.mkdirSync(KEYS_DIR, { mode: 0o700, recursive: true });
  }
}

/**
 * Load the trust store from disk.
 *
 * @returns {{ trusted_signers: Array<{ id: string, public_key: string }> }}
 */
function loadTrustStore() {
  if (!fs.existsSync(TRUST_FILE)) {
    return { trusted_signers: [] };
  }

  try {
    const raw = fs.readFileSync(TRUST_FILE, 'utf8');
    const data = JSON.parse(raw);

    if (!data.trusted_signers || !Array.isArray(data.trusted_signers)) {
      return { trusted_signers: [] };
    }

    return data;
  } catch (err) {
    throw new Error(`Failed to read trust store at ${TRUST_FILE}: ${err.message}`);
  }
}

/**
 * Save the trust store to disk with restrictive permissions.
 *
 * @param {{ trusted_signers: Array<{ id: string, public_key: string }> }} store
 */
function saveTrustStore(store) {
  ensureEnvlockDir();
  fs.writeFileSync(TRUST_FILE, JSON.stringify(store, null, 2), { mode: 0o600 });
}

/**
 * Get trusted signers as a Map of id → Uint8Array (Ed25519 public key).
 *
 * @returns {Map<string, Uint8Array>} Map of signer ID to public key bytes
 */
function getTrustedSignersMap() {
  const store = loadTrustStore();
  const map = new Map();

  for (const signer of store.trusted_signers) {
    const keyBytes = Buffer.from(signer.public_key, 'base64');
    map.set(signer.id, new Uint8Array(keyBytes));
  }

  return map;
}

/**
 * Add a trusted signer to the local trust store.
 *
 * @param {string} id - Signer identifier (e.g., username or email)
 * @param {string} publicKeyBase64 - Ed25519 public key in base64
 */
function addTrustedSigner(id, publicKeyBase64) {
  const store = loadTrustStore();

  // Validate key length (Ed25519 public key = 32 bytes)
  const keyBytes = Buffer.from(publicKeyBase64, 'base64');
  if (keyBytes.length !== 32) {
    throw new Error(`Invalid Ed25519 public key length: expected 32 bytes, got ${keyBytes.length}`);
  }

  // Check for duplicate
  const existing = store.trusted_signers.find((s) => s.id === id);
  if (existing) {
    existing.public_key = publicKeyBase64;
  } else {
    store.trusted_signers.push({ id, public_key: publicKeyBase64 });
  }

  saveTrustStore(store);
}

/**
 * Remove a trusted signer from the local trust store.
 *
 * @param {string} id - Signer identifier to remove
 * @returns {boolean} True if the signer was found and removed
 */
function removeTrustedSigner(id) {
  const store = loadTrustStore();
  const before = store.trusted_signers.length;
  store.trusted_signers = store.trusted_signers.filter((s) => s.id !== id);

  if (store.trusted_signers.length === before) {
    return false;
  }

  saveTrustStore(store);
  return true;
}

/**
 * Save a keypair to the local keys directory.
 *
 * @param {string} id - Key identifier
 * @param {Uint8Array} publicKey - 32-byte Ed25519 public key
 * @param {Uint8Array} secretKey - 64-byte Ed25519 secret key
 */
function saveKeypair(id, publicKey, secretKey) {
  ensureEnvlockDir();

  const keyFile = path.join(KEYS_DIR, `${id}.json`);
  const data = {
    id,
    public_key: Buffer.from(publicKey).toString('base64'),
    secret_key: Buffer.from(secretKey).toString('base64'),
  };

  // Secret key file must be owner-only readable
  fs.writeFileSync(keyFile, JSON.stringify(data, null, 2), { mode: 0o600 });
}

/**
 * Load a keypair from the local keys directory.
 *
 * @param {string} id - Key identifier
 * @returns {{ id: string, publicKey: Uint8Array, secretKey: Uint8Array } | null}
 */
function loadKeypair(id) {
  const keyFile = path.join(KEYS_DIR, `${id}.json`);

  if (!fs.existsSync(keyFile)) {
    return null;
  }

  try {
    const raw = fs.readFileSync(keyFile, 'utf8');
    const data = JSON.parse(raw);

    return {
      id: data.id,
      publicKey: new Uint8Array(Buffer.from(data.public_key, 'base64')),
      secretKey: new Uint8Array(Buffer.from(data.secret_key, 'base64')),
    };
  } catch (err) {
    throw new Error(`Failed to load keypair '${id}': ${err.message}`);
  }
}

/**
 * List all locally stored key IDs.
 *
 * @returns {string[]} Array of key IDs
 */
function listLocalKeys() {
  if (!fs.existsSync(KEYS_DIR)) {
    return [];
  }

  return fs
    .readdirSync(KEYS_DIR)
    .filter((f) => f.endsWith('.json'))
    .map((f) => f.replace('.json', ''));
}

module.exports = {
  ENVLOCK_DIR,
  TRUST_FILE,
  KEYS_DIR,
  ensureEnvlockDir,
  loadTrustStore,
  saveTrustStore,
  getTrustedSignersMap,
  addTrustedSigner,
  removeTrustedSigner,
  saveKeypair,
  loadKeypair,
  listLocalKeys,
};
