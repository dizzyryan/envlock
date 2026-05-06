#!/usr/bin/env node
'use strict';

const sodium = require('libsodium-wrappers');
const { version } = require('../package.json');

const args = process.argv.slice(2);
const command = args[0];

function printUsage() {
  const usage = `
envlock — Secure multi-user .env encryption with tamper-proof signing

Usage:
  envlock keygen <id>                            Generate Ed25519 keypair
  envlock encrypt <file> [options]               Encrypt a .env file
  envlock run [options] -- <command>             Run command with decrypted env
  envlock add-user <id> <public_key> [options]   Add recipient to .env.enc
  envlock remove-user <id> [options]             Remove recipient (rotates key)
  envlock trust <id> <public_key>                Trust a signer's key
  envlock untrust <id>                           Remove trusted signer
  envlock trust-list                             List trusted signers
  envlock version                               Show current envlock version
  envlock help                                   Show this help

Options:
  --env, -e <path>      Path to .env.enc file (default: .env.enc)
  --key, -k <id>        Signing/decryption key ID
  --out, -o <path>      Output path for encrypt
  --recipients, -r <f>  Recipients file (default: .envlock.json)

Security Model:
  • Secrets encrypted with AES-256-GCM (random data key)
  • Data key encrypted per-user via X25519 sealed boxes
  • Files signed with Ed25519 — verified against LOCAL trust store
  • Signature verification BEFORE decryption (tamper = reject)
  • Trust anchored at ~/.envlock/trust.json (never from .env.enc)

Examples:
  envlock keygen alice
  envlock encrypt .env
  envlock run -- npm run dev
  envlock add-user bob <bob_public_key>
  envlock remove-user eve
`;
  console.log(usage.trim());
}

/**
 * Main entry point. Ensures libsodium is ready before dispatching commands.
 */
async function main() {
  // libsodium requires async initialization
  await sodium.ready;

  switch (command) {
    case 'keygen': {
      const { handleKeygen } = require('./cli/keygen');
      await handleKeygen(args.slice(1));
      break;
    }

    case 'encrypt': {
      const { handleEncrypt } = require('./cli/encrypt');
      await handleEncrypt(args.slice(1));
      break;
    }

    case 'run': {
      const { handleRun } = require('./cli/run');
      await handleRun(args.slice(1), args);
      break;
    }

    case 'add-user': {
      const { handleAddUser } = require('./cli/add-user');
      await handleAddUser(args.slice(1));
      break;
    }

    case 'remove-user': {
      const { handleRemoveUser } = require('./cli/remove-user');
      await handleRemoveUser(args.slice(1));
      break;
    }

    case 'trust': {
      const { handleTrust } = require('./cli/trust');
      await handleTrust(args.slice(1));
      break;
    }

    case 'untrust': {
      const { handleUntrust } = require('./cli/trust');
      await handleUntrust(args.slice(1));
      break;
    }

    case 'trust-list': {
      const { handleTrustList } = require('./cli/trust');
      await handleTrustList();
      break;
    }

    case 'version':
    case '--version':
    case '-v':
      console.log(`envlock ${version}`);
      break;

    case 'help':
    case '--help':
    case '-h':
      printUsage();
      break;

    default:
      if (command) {
        console.error(`Unknown command: ${command}`);
      }
      printUsage();
      process.exit(command ? 1 : 0);
  }
}

main().catch((err) => {
  console.error(`Fatal error: ${err.message}`);
  process.exit(1);
});
