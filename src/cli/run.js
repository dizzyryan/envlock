'use strict';

const path = require('node:path');
const { spawn } = require('node:child_process');
const { symmetric, asymmetric, signing } = require('../crypto');
const {
  parseEnvBuffer,
  loadKeypair,
  getTrustedSignersMap,
  loadEnvelope,
  zeroBuffer,
  listLocalKeys,
} = require('../utils');

/**
 * Run a command with decrypted environment variables injected.
 *
 * SECURITY-CRITICAL FLOW (order matters):
 * 1. Load .env.enc from disk
 * 2. Load local trust store (trusted Ed25519 public keys)
 * 3. VERIFY SIGNATURES FIRST — reject if no trusted signature validates
 * 4. Only THEN attempt decryption
 * 5. Decrypt data key using local private key (sealed box open)
 * 6. Decrypt .env content using data key (AES-256-GCM)
 * 7. Parse env vars from decrypted buffer
 * 8. Zero all sensitive buffers
 * 9. Spawn child process with injected env vars
 *
 * @param {string[]} args - CLI arguments after "run"
 * @param {string[]} fullArgs - Full argv for finding -- separator
 */
async function handleRun(args, fullArgs) {
  // Find the -- separator in original args
  const separatorIndex = fullArgs.indexOf('--');
  if (separatorIndex === -1 || separatorIndex === fullArgs.length - 1) {
    console.error('Error: No command specified after --');
    console.error('Usage: envlock run [--env <file.enc>] [--key <id>] -- <command>');
    process.exit(1);
  }

  const userCommand = fullArgs.slice(separatorIndex + 1);
  const preArgs = fullArgs.slice(fullArgs.indexOf('run') + 1, separatorIndex);

  // Parse options before --
  let envFilePath = '.env.enc';
  let keyId = null;

  for (let i = 0; i < preArgs.length; i++) {
    if ((preArgs[i] === '--env' || preArgs[i] === '-e') && preArgs[i + 1]) {
      envFilePath = preArgs[++i];
    } else if ((preArgs[i] === '--key' || preArgs[i] === '-k') && preArgs[i + 1]) {
      keyId = preArgs[++i];
    }
  }

  // --- Step 1: Load encrypted envelope ---
  const envelope = loadEnvelope(envFilePath);

  // Validate envelope structure
  if (envelope.version !== 1) {
    console.error(`Error: Unsupported envelope version: ${envelope.version}`);
    process.exit(1);
  }

  // --- Step 2: Load trust store ---
  const trustedSigners = getTrustedSignersMap();

  if (trustedSigners.size === 0) {
    console.error('Error: No trusted signers configured.');
    console.error('Run "envlock trust <id> <public_key>" to add trusted signers.');
    process.exit(1);
  }

  // --- Step 3: VERIFY SIGNATURES BEFORE DECRYPTION ---
  // This is the core security guarantee: we NEVER decrypt unless a trusted
  // signer has vouched for this file's integrity.
  const verification = signing.verifyEnvelopeTrust(envelope, trustedSigners);

  if (!verification.valid) {
    console.error('✗ SIGNATURE VERIFICATION FAILED');
    console.error(`  ${verification.error}`);
    console.error('');
    console.error('  This file may have been tampered with.');
    console.error('  Do NOT trust its contents.');
    process.exit(1);
  }

  // --- Step 4: Find our recipient entry ---
  if (!keyId) {
    // Auto-detect: find first local key that has a recipient entry
    const localKeys = listLocalKeys();
    for (const id of localKeys) {
      if (envelope.recipients.some((r) => r.id === id)) {
        keyId = id;
        break;
      }
    }
  }

  if (!keyId) {
    console.error('Error: No local key matches any recipient in the envelope.');
    console.error('Available recipients: ' + envelope.recipients.map((r) => r.id).join(', '));
    process.exit(1);
  }

  const keypair = loadKeypair(keyId);
  if (!keypair) {
    console.error(`Error: Private key '${keyId}' not found locally.`);
    process.exit(1);
  }

  const recipientEntry = envelope.recipients.find((r) => r.id === keyId);
  if (!recipientEntry) {
    console.error(`Error: '${keyId}' is not a recipient of this file.`);
    process.exit(1);
  }

  // --- Step 5: Decrypt data key (sealed box) ---
  let dataKey = null;
  try {
    dataKey = asymmetric.decryptDataKey(
      recipientEntry.encrypted_key,
      keypair.publicKey,
      keypair.secretKey
    );
  } catch (err) {
    console.error('Error: Failed to decrypt data key. Key mismatch or corrupted envelope.');
    process.exit(1);
  }

  // --- Step 6: Decrypt .env content (AES-256-GCM) ---
  let decryptedBuffer = null;
  try {
    decryptedBuffer = symmetric.decrypt(envelope.env, dataKey);
  } catch (err) {
    console.error('Error: Failed to decrypt environment data. Corrupted ciphertext.');
    process.exit(1);
  }

  // Zero data key immediately after use
  zeroBuffer(dataKey);
  dataKey = null;

  // --- Step 7: Parse environment variables ---
  const envVars = parseEnvBuffer(decryptedBuffer);

  // Zero decrypted buffer immediately after parsing
  zeroBuffer(decryptedBuffer);
  decryptedBuffer = null;

  // --- Step 8: Spawn child process ---
  const childEnv = {
    ...process.env,
    ...envVars, // Decrypted vars take precedence
  };

  const cmd = userCommand[0];
  const cmdArgs = userCommand.slice(1);

  // Using spawn with shell:true to support shell syntax (pipes, etc.)
  // Secrets are passed via env option (not visible in ps/top, unlike CLI args)
  const child = spawn(cmd, cmdArgs, {
    env: childEnv,
    stdio: 'inherit',
    shell: true,
  });

  child.on('error', (err) => {
    console.error(`Error executing command: ${err.message}`);
    process.exit(1);
  });

  child.on('close', (code) => {
    process.exit(code ?? 1);
  });

  // Forward signals to child for graceful shutdown
  for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
    process.on(signal, () => child.kill(signal));
  }
}

module.exports = { handleRun };
