'use strict';

const { addTrustedSigner, removeTrustedSigner, loadTrustStore, TRUST_FILE } = require('../utils');

/**
 * Manage the local trust store.
 *
 * Commands:
 *   envlock trust <id> <public_key>  — Add a signer to trusted list
 *   envlock untrust <id>             — Remove a signer from trusted list
 *   envlock trust-list               — Show all trusted signers
 *
 * SECURITY NOTE: This modifies ~/.envlock/trust.json which is the security
 * anchor for the entire system. Only add keys that you have verified
 * out-of-band (in person, over a secure channel, etc.).
 */

/**
 * Add a trusted signer.
 */
async function handleTrust(args) {
  const id = args[0];
  const publicKey = args[1];

  if (!id || !publicKey) {
    console.error('Error: Missing arguments.');
    console.error('Usage: envlock trust <id> <public_key_base64>');
    console.error('');
    console.error('SECURITY: Only add keys verified out-of-band (e.g., in person).');
    process.exit(1);
  }

  // Validate key format
  const keyBytes = Buffer.from(publicKey, 'base64');
  if (keyBytes.length !== 32) {
    console.error(`Error: Invalid key length (expected 32 bytes, got ${keyBytes.length})`);
    process.exit(1);
  }

  addTrustedSigner(id, publicKey);

  console.log(`✓ Added '${id}' to trusted signers`);
  console.log(`  Key: ${publicKey}`);
  console.log(`  Store: ${TRUST_FILE}`);
}

/**
 * Remove a trusted signer.
 */
async function handleUntrust(args) {
  const id = args[0];

  if (!id) {
    console.error('Error: No signer ID specified.');
    console.error('Usage: envlock untrust <id>');
    process.exit(1);
  }

  const removed = removeTrustedSigner(id);

  if (removed) {
    console.log(`✓ Removed '${id}' from trusted signers`);
  } else {
    console.error(`Error: '${id}' is not in the trust store.`);
    process.exit(1);
  }
}

/**
 * List all trusted signers.
 */
async function handleTrustList() {
  const store = loadTrustStore();

  if (store.trusted_signers.length === 0) {
    console.log('No trusted signers configured.');
    console.log('Run "envlock trust <id> <public_key>" to add one.');
    return;
  }

  console.log(`Trusted signers (${store.trusted_signers.length}):`);
  console.log(`  Store: ${TRUST_FILE}`);
  console.log('');

  for (const signer of store.trusted_signers) {
    console.log(`  ${signer.id}`);
    console.log(`    ${signer.public_key}`);
  }
}

module.exports = { handleTrust, handleUntrust, handleTrustList };
