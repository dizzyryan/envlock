'use strict';

const fs = require('node:fs');
const path = require('node:path');
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
 * Add a new recipient to an existing .env.enc file.
 *
 * Security flow:
 * 1. Load envelope
 * 2. Decrypt data key using local private key
 * 3. Re-encrypt data key for the new recipient
 * 4. Add recipient entry to envelope
 * 5. Re-sign the modified envelope
 *
 * NOTE: This does NOT rotate the data key. If the goal is to ensure the added
 * user could not have decrypted the file before this operation, a full re-encrypt
 * would be needed. However, since they didn't have access to the sealed box
 * before being added, forward secrecy is maintained by the sealed box itself.
 *
 * @param {string[]} args - CLI arguments after "add-user"
 */
async function handleAddUser(args) {
  const newUserId = args[0];
  const newUserPublicKey = args[1];

  if (!newUserId || !newUserPublicKey) {
    console.error('Error: Missing arguments.');
    console.error('Usage: envlock add-user <id> <public_key_base64> [--env <file.enc>] [--key <signer-id>]');
    process.exit(1);
  }

  // Validate public key
  const newPkBytes = Buffer.from(newUserPublicKey, 'base64');
  if (newPkBytes.length !== 32) {
    console.error(`Error: Invalid public key length (expected 32 bytes, got ${newPkBytes.length})`);
    process.exit(1);
  }
  const newPk = new Uint8Array(newPkBytes);

  // Parse options
  let envFilePath = '.env.enc';
  let signerId = null;

  for (let i = 2; i < args.length; i++) {
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
      console.error('Error: No local keys found. Run "envlock keygen <id>" first.');
      process.exit(1);
    }
    signerId = localKeys[0];
  }

  const signerKeypair = loadKeypair(signerId);
  if (!signerKeypair) {
    console.error(`Error: Signing key '${signerId}' not found.`);
    process.exit(1);
  }

  // Load envelope
  const envelope = loadEnvelope(envFilePath);

  // Check if user already exists
  if (envelope.recipients.some((r) => r.id === newUserId)) {
    console.error(`Error: '${newUserId}' is already a recipient.`);
    process.exit(1);
  }

  // Find our own recipient entry to decrypt the data key
  const myEntry = envelope.recipients.find((r) => r.id === signerId);
  if (!myEntry) {
    console.error(`Error: '${signerId}' is not a current recipient — cannot decrypt data key.`);
    process.exit(1);
  }

  // Decrypt existing data key
  let dataKey = null;
  try {
    dataKey = asymmetric.decryptDataKey(
      myEntry.encrypted_key,
      signerKeypair.publicKey,
      signerKeypair.secretKey
    );
  } catch {
    console.error('Error: Failed to decrypt data key.');
    process.exit(1);
  }

  // Encrypt data key for new recipient
  const encryptedKeyForNew = asymmetric.encryptDataKeyForRecipient(dataKey, newPk);

  // Zero data key
  zeroBuffer(dataKey);
  dataKey = null;

  // Add new recipient
  envelope.recipients.push({
    id: newUserId,
    algo: 'x25519-xsalsa20-poly1305',
    encrypted_key: encryptedKeyForNew,
  });

  // Re-sign (clear old signatures, sign with current signer)
  envelope.signatures = [];
  const signature = signing.signEnvelope(envelope, signerKeypair.secretKey);
  envelope.signatures.push({
    id: signerId,
    sig: signature,
  });

  // Save
  saveEnvelope(envFilePath, envelope);

  console.log(`✓ Added '${newUserId}' as recipient`);
  console.log(`  Re-signed by '${signerId}'`);
  console.log(`  File: ${path.resolve(envFilePath)}`);

  // Also update .envlock.json if it exists
  updateRecipientsFile(newUserId, newUserPublicKey);
}

/**
 * Update the .envlock.json recipients file if it exists.
 */
function updateRecipientsFile(id, publicKeyBase64) {
  const recipientsPath = path.resolve('.envlock.json');

  if (!fileExists(recipientsPath)) {
    return; // No recipients file to update
  }

  try {
    const raw = fs.readFileSync(recipientsPath, 'utf8');
    const data = JSON.parse(raw);

    if (!data.recipients) {
      data.recipients = [];
    }

    if (!data.recipients.some((r) => r.id === id)) {
      data.recipients.push({ id, public_key: publicKeyBase64 });
      fs.writeFileSync(recipientsPath, JSON.stringify(data, null, 2));
      console.log(`  Updated .envlock.json`);
    }
  } catch {
    // Non-fatal
  }
}

module.exports = { handleAddUser };
