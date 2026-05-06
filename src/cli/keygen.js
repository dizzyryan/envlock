'use strict';

const { signing } = require('../crypto');
const { saveKeypair, addTrustedSigner, loadKeypair } = require('../utils');

/**
 * Generate a new Ed25519 keypair for a user.
 *
 * This keypair is used for:
 * - Signing .env.enc files (Ed25519 detached signatures)
 * - Decrypting data keys (via Ed25519 → X25519 conversion)
 *
 * The keypair is stored at ~/.envlock/keys/<id>.json with 0600 permissions.
 * The public key is also added to the local trust store automatically.
 *
 * @param {string[]} args - CLI arguments after "keygen"
 */
async function handleKeygen(args) {
  const id = args[0];

  if (!id) {
    console.error('Error: No key ID specified.');
    console.error('Usage: envlock keygen <id>');
    console.error('Example: envlock keygen alice');
    process.exit(1);
  }

  // Check if key already exists
  const existing = loadKeypair(id);
  if (existing) {
    console.error(`Error: Key '${id}' already exists.`);
    console.error('Delete ~/.envlock/keys/' + id + '.json to regenerate.');
    process.exit(1);
  }

  // Generate Ed25519 keypair
  const keypair = signing.generateSigningKeypair();

  // Save to local key store
  saveKeypair(id, keypair.publicKey, keypair.privateKey);

  // Auto-trust own key (you always trust yourself)
  const publicKeyBase64 = Buffer.from(keypair.publicKey).toString('base64');
  addTrustedSigner(id, publicKeyBase64);

  console.log(`✓ Generated Ed25519 keypair for '${id}'`);
  console.log(`  Key stored: ~/.envlock/keys/${id}.json`);
  console.log(`  Auto-trusted: added to ~/.envlock/trust.json`);
  console.log('');
  console.log(`  Public key (share with team):`);
  console.log(`  ${publicKeyBase64}`);
  console.log('');
  console.log('  Teammates should run:');
  console.log(`  envlock trust ${id} ${publicKeyBase64}`);
}

module.exports = { handleKeygen };
