'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { symmetric, asymmetric, signing } = require('../crypto');
const { loadKeypair, fileExists, zeroBuffer, saveEnvelope } = require('../utils');

/**
 * Encrypt a .env file and produce a .env.enc envelope.
 *
 * Security flow:
 * 1. Read .env into a Buffer (never a string, to avoid V8 interning)
 * 2. Generate a random 32-byte data key
 * 3. Encrypt .env with AES-256-GCM using the data key
 * 4. For each recipient: encrypt the data key using their X25519 public key (sealed box)
 * 5. Sign the entire envelope with the signer's Ed25519 private key
 * 6. Write the signed envelope to disk
 * 7. Zero sensitive buffers
 *
 * @param {string[]} args - CLI arguments after "encrypt"
 */
async function handleEncrypt(args) {
  const filePath = args[0];

  if (!filePath) {
    console.error('Error: No input file specified.');
    console.error('Usage: envlock encrypt <file> [--key <signer-id>] [--out <output>] [--recipients <file>]');
    process.exit(1);
  }

  const resolvedInput = path.resolve(filePath);

  if (!fileExists(resolvedInput)) {
    console.error(`Error: File not found: ${resolvedInput}`);
    process.exit(1);
  }

  // Parse CLI options
  let signerId = null;
  let outputPath = null;
  let recipientsFile = null;

  for (let i = 1; i < args.length; i++) {
    if ((args[i] === '--key' || args[i] === '-k') && args[i + 1]) {
      signerId = args[++i];
    } else if ((args[i] === '--out' || args[i] === '-o') && args[i + 1]) {
      outputPath = args[++i];
    } else if ((args[i] === '--recipients' || args[i] === '-r') && args[i + 1]) {
      recipientsFile = args[++i];
    }
  }

  // Default signer: first available local key
  if (!signerId) {
    const { listLocalKeys } = require('../utils');
    const keys = listLocalKeys();
    if (keys.length === 0) {
      console.error('Error: No signing key found. Run "envlock keygen <id>" first.');
      process.exit(1);
    }
    signerId = keys[0];
  }

  // Load signer's keypair
  const signerKeypair = loadKeypair(signerId);
  if (!signerKeypair) {
    console.error(`Error: Signing key '${signerId}' not found.`);
    console.error('Run "envlock keygen <id>" to generate a key.');
    process.exit(1);
  }

  // Load recipients list
  let recipients;
  try {
    recipients = loadRecipients(recipientsFile, signerKeypair);
  } catch (err) {
    console.error(`Error loading recipients: ${err.message}`);
    process.exit(1);
  }

  if (recipients.length === 0) {
    console.error('Error: No recipients configured. Use --recipients or add a .envlock.json file.');
    process.exit(1);
  }

  // Read .env file as Buffer (security: avoid string interning)
  let plaintext = null;
  try {
    plaintext = fs.readFileSync(resolvedInput);
  } catch (err) {
    console.error(`Error reading file: ${err.message}`);
    process.exit(1);
  }

  // Generate random data key (32 bytes of full entropy)
  const dataKey = symmetric.generateDataKey();

  // Encrypt .env content with AES-256-GCM
  const envEncrypted = symmetric.encrypt(plaintext, dataKey);

  // Zero plaintext immediately
  zeroBuffer(plaintext);
  plaintext = null;

  // Encrypt data key for each recipient using sealed box (X25519)
  const recipientEntries = [];
  for (const recipient of recipients) {
    const encryptedKey = asymmetric.encryptDataKeyForRecipient(
      dataKey,
      recipient.publicKey
    );
    recipientEntries.push({
      id: recipient.id,
      algo: 'x25519-xsalsa20-poly1305',
      encrypted_key: encryptedKey,
    });
  }

  // Zero the data key after all recipients are encrypted
  zeroBuffer(dataKey);

  // Build the envelope (without signatures — signing comes last)
  const envelope = {
    version: 1,
    cipher: 'aes-256-gcm',
    env: envEncrypted,
    recipients: recipientEntries,
    signatures: [],
  };

  // Sign the envelope with the signer's Ed25519 private key
  const signature = signing.signEnvelope(envelope, signerKeypair.secretKey);
  envelope.signatures.push({
    id: signerId,
    sig: signature,
  });

  // Write to disk
  const resolvedOutput = outputPath
    ? path.resolve(outputPath)
    : path.resolve(resolvedInput + '.enc');

  saveEnvelope(resolvedOutput, envelope);

  console.log(`✓ Encrypted and signed by '${signerId}'`);
  console.log(`  Recipients: ${recipients.map((r) => r.id).join(', ')}`);
  console.log(`  Output: ${resolvedOutput}`);
  console.log('');
  console.log('  This file is safe to commit to Git.');
}

/**
 * Load recipients from a .envlock.json file or fallback to the signer themselves.
 *
 * Recipients file format:
 * {
 *   "recipients": [
 *     { "id": "alice", "public_key": "<base64 Ed25519 public key>" },
 *     { "id": "bob", "public_key": "<base64 Ed25519 public key>" }
 *   ]
 * }
 *
 * @param {string|null} recipientsFile - Explicit path to recipients file
 * @param {{ id: string, publicKey: Uint8Array }} signerKeypair - Fallback recipient
 * @returns {Array<{ id: string, publicKey: Uint8Array }>}
 */
function loadRecipients(recipientsFile, signerKeypair) {
  // Try explicit file, then .envlock.json in cwd
  const candidates = recipientsFile
    ? [path.resolve(recipientsFile)]
    : [path.resolve('.envlock.json')];

  for (const candidate of candidates) {
    if (fileExists(candidate)) {
      try {
        const raw = fs.readFileSync(candidate, 'utf8');
        const data = JSON.parse(raw);

        if (data.recipients && Array.isArray(data.recipients)) {
          const recipients = [];
          for (const recipient of data.recipients) {
            if (!recipient.id || typeof recipient.id !== 'string') {
              throw new Error(`Recipient entry missing valid id in ${candidate}`);
            }

            if (typeof recipient.public_key !== 'string') {
              throw new Error(`Recipient '${recipient.id}' is missing a base64 public_key in ${candidate}`);
            }

            let keyBytes;
            try {
              keyBytes = Buffer.from(recipient.public_key, 'base64');
            } catch (err) {
              throw new Error(
                `Recipient '${recipient.id}' has an invalid base64 public key in ${candidate}: ${err.message}`
              );
            }

            if (keyBytes.length !== 32) {
              throw new Error(
                `Recipient '${recipient.id}' has invalid Ed25519 public key length (expected 32 bytes) in ${candidate}`
              );
            }

            recipients.push({
              id: recipient.id,
              publicKey: new Uint8Array(keyBytes),
            });
          }

          return recipients;
        }
      } catch (err) {
        console.error(`Error: Failed to parse ${candidate}: ${err.message}`);
        throw err;
      }
    }
  }

  // Fallback: encrypt only for the signer themselves
  return [{ id: signerKeypair.id, publicKey: signerKeypair.publicKey }];
}

module.exports = { handleEncrypt };
