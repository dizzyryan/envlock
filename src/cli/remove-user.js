'use strict';

const path = require('node:path');
const fs = require('node:fs');
const { symmetric, asymmetric, signing } = require('../crypto');
const {
  loadKeypair,
  loadEnvelope,
  saveEnvelope,
  zeroBuffer,
  listLocalKeys,
  fileExists,
} = require('../utils');

/**
 * Remove a recipient from .env.enc with FULL KEY ROTATION.
 *
 * SECURITY-CRITICAL: Simply removing the recipient entry is NOT sufficient.
 * The removed user previously had access to the encrypted data key. If the
 * data key is not rotated, they could use a cached copy to decrypt the ciphertext.
 *
 * Therefore, remove-user MUST:
 * 1. Decrypt the current .env content
 * 2. Generate a NEW random data key
 * 3. Re-encrypt .env with the new data key
 * 4. Re-encrypt the new data key for all REMAINING recipients
 * 5. Re-sign the envelope
 *
 * This ensures the removed user's previously-cached data key is useless.
 *
 * @param {string[]} args - CLI arguments after "remove-user"
 */
async function handleRemoveUser(args) {
  const removeId = args[0];

  if (!removeId) {
    console.error('Error: No user ID specified.');
    console.error('Usage: envlock remove-user <id> [--env <file.enc>] [--key <signer-id>]');
    process.exit(1);
  }

  // Parse options
  let envFilePath = '.env.enc';
  let signerId = null;

  for (let i = 1; i < args.length; i++) {
    if ((args[i] === '--env' || args[i] === '-e') && args[i + 1]) {
      envFilePath = args[++i];
    } else if ((args[i] === '--key' || args[i] === '-k') && args[i + 1]) {
      signerId = args[++i];
    }
  }

  // Find signer key
  if (!signerId) {
    const localKeys = listLocalKeys();
    if (localKeys.length === 0) {
      console.error('Error: No local keys found.');
      process.exit(1);
    }
    signerId = localKeys[0];
  }

  if (signerId === removeId) {
    console.error('Error: Cannot remove yourself as a recipient.');
    process.exit(1);
  }

  const signerKeypair = loadKeypair(signerId);
  if (!signerKeypair) {
    console.error(`Error: Signing key '${signerId}' not found.`);
    process.exit(1);
  }

  // Load envelope
  const envelope = loadEnvelope(envFilePath);

  // Verify the target user exists
  if (!envelope.recipients.some((r) => r.id === removeId)) {
    console.error(`Error: '${removeId}' is not a current recipient.`);
    process.exit(1);
  }

  // Find our own recipient entry
  const myEntry = envelope.recipients.find((r) => r.id === signerId);
  if (!myEntry) {
    console.error(`Error: '${signerId}' is not a current recipient — cannot decrypt.`);
    process.exit(1);
  }

  // Decrypt existing data key
  let oldDataKey = null;
  try {
    oldDataKey = asymmetric.decryptDataKey(
      myEntry.encrypted_key,
      signerKeypair.publicKey,
      signerKeypair.secretKey
    );
  } catch {
    console.error('Error: Failed to decrypt data key.');
    process.exit(1);
  }

  // Decrypt current .env content
  let plaintext = null;
  try {
    plaintext = symmetric.decrypt(envelope.env, oldDataKey);
  } catch {
    console.error('Error: Failed to decrypt environment data.');
    process.exit(1);
  }

  // Zero old data key — it's now compromised from the removed user's perspective
  zeroBuffer(oldDataKey);
  oldDataKey = null;

  // --- KEY ROTATION: Generate completely new data key ---
  const newDataKey = symmetric.generateDataKey();

  // Re-encrypt .env with new data key (new random IV)
  const newEnvEncrypted = symmetric.encrypt(plaintext, newDataKey);

  // Zero plaintext
  zeroBuffer(plaintext);
  plaintext = null;

  // Remove the target user and re-encrypt data key for remaining recipients
  const remainingRecipients = envelope.recipients.filter((r) => r.id !== removeId);

  // We need the public keys of remaining recipients — they're in the .envlock.json
  // or we can only re-encrypt for ourselves (the signer)
  const newRecipientEntries = [];

  for (const recipient of remainingRecipients) {
    // For ourselves, we have the key directly
    if (recipient.id === signerId) {
      const encryptedKey = asymmetric.encryptDataKeyForRecipient(newDataKey, signerKeypair.publicKey);
      newRecipientEntries.push({
        id: recipient.id,
        algo: 'x25519-xsalsa20-poly1305',
        encrypted_key: encryptedKey,
      });
    } else {
      // For other recipients, load their public key from .envlock.json
      let recipientPk;
      try {
        recipientPk = loadRecipientPublicKey(recipient.id);
      } catch (err) {
        console.error(`Error loading public key for '${recipient.id}': ${err.message}`);
        process.exit(1);
      }
      if (recipientPk) {
        const encryptedKey = asymmetric.encryptDataKeyForRecipient(newDataKey, recipientPk);
        newRecipientEntries.push({
          id: recipient.id,
          algo: 'x25519-xsalsa20-poly1305',
          encrypted_key: encryptedKey,
        });
      } else {
        console.warn(`  Warning: Could not find public key for '${recipient.id}' — they will be removed too.`);
        console.warn(`  To re-add them, run: envlock add-user ${recipient.id} <their_public_key>`);
      }
    }
  }

  // Zero new data key
  zeroBuffer(newDataKey);

  // Build new envelope
  const newEnvelope = {
    version: 1,
    cipher: 'aes-256-gcm',
    env: newEnvEncrypted,
    recipients: newRecipientEntries,
    signatures: [],
  };

  // Sign with signer's key
  const signature = signing.signEnvelope(newEnvelope, signerKeypair.secretKey);
  newEnvelope.signatures.push({
    id: signerId,
    sig: signature,
  });

  // Save
  saveEnvelope(envFilePath, newEnvelope);

  console.log(`✓ Removed '${removeId}' and rotated data key`);
  console.log(`  Remaining recipients: ${newRecipientEntries.map((r) => r.id).join(', ')}`);
  console.log(`  Re-signed by '${signerId}'`);
  console.log(`  File: ${path.resolve(envFilePath)}`);

  // Update .envlock.json
  removeFromRecipientsFile(removeId);
}

/**
 * Load a recipient's Ed25519 public key from .envlock.json.
 *
 * @param {string} id - Recipient ID
 * @returns {Uint8Array|null} Public key bytes or null if not found
 */
function loadRecipientPublicKey(id) {
  const recipientsPath = path.resolve('.envlock.json');

  if (!fileExists(recipientsPath)) {
    return null;
  }

  try {
    const raw = fs.readFileSync(recipientsPath, 'utf8');
    const data = JSON.parse(raw);

    if (data.recipients && Array.isArray(data.recipients)) {
      const entry = data.recipients.find((r) => r.id === id);
      if (entry && entry.public_key) {
        if (typeof entry.public_key !== 'string') {
          throw new Error(
            `Recipient '${id}' is missing a base64 public_key in ${recipientsPath}`
          );
        }

        let keyBytes;
        try {
          keyBytes = Buffer.from(entry.public_key, 'base64');
        } catch (err) {
          throw new Error(
            `Recipient '${id}' has an invalid base64 public key in ${recipientsPath}: ${err.message}`
          );
        }

        if (keyBytes.length !== 32) {
          throw new Error(
            `Recipient '${id}' has invalid Ed25519 public key length (expected 32 bytes) in ${recipientsPath}`
          );
        }

        return new Uint8Array(keyBytes);
      }
    }
  } catch (err) {
    throw err;
  }

  return null;
}

/**
 * Remove a user from .envlock.json if it exists.
 */
function removeFromRecipientsFile(id) {
  const recipientsPath = path.resolve('.envlock.json');

  if (!fileExists(recipientsPath)) {
    return;
  }

  try {
    const raw = fs.readFileSync(recipientsPath, 'utf8');
    const data = JSON.parse(raw);

    if (data.recipients && Array.isArray(data.recipients)) {
      data.recipients = data.recipients.filter((r) => r.id !== id);
      fs.writeFileSync(recipientsPath, JSON.stringify(data, null, 2));
      console.log(`  Updated .envlock.json`);
    }
  } catch {
    // Non-fatal
  }
}

module.exports = { handleRemoveUser };
