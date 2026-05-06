'use strict';

const fs = require('node:fs');
const path = require('node:path');

/**
 * Zero out a Buffer's contents (best-effort memory sanitization).
 *
 * Limitation: V8's garbage collector may have already copied the data.
 * We still do this to reduce the window of exposure in memory dumps.
 *
 * @param {Buffer|Uint8Array} buffer - Buffer to zero
 */
function zeroBuffer(buffer) {
  if (Buffer.isBuffer(buffer) || buffer instanceof Uint8Array) {
    buffer.fill(0);
  }
}

/**
 * Check if a file exists and is readable.
 *
 * @param {string} filePath - Path to check
 * @returns {boolean}
 */
function fileExists(filePath) {
  try {
    fs.accessSync(filePath, fs.constants.R_OK);
    return true;
  } catch {
    return false;
  }
}

/**
 * Load and parse a .env.enc file from disk.
 *
 * @param {string} filePath - Path to the encrypted envelope file
 * @returns {object} Parsed JSON envelope
 */
function loadEnvelope(filePath) {
  const resolved = path.resolve(filePath);

  if (!fileExists(resolved)) {
    throw new Error(`Encrypted file not found: ${resolved}`);
  }

  try {
    const raw = fs.readFileSync(resolved, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    throw new Error(`Failed to parse encrypted file: ${err.message}`);
  }
}

/**
 * Save an envelope to disk with restricted permissions.
 *
 * @param {string} filePath - Output path
 * @param {object} envelope - Envelope object to serialize
 */
function saveEnvelope(filePath, envelope) {
  const resolved = path.resolve(filePath);
  fs.writeFileSync(resolved, JSON.stringify(envelope, null, 2), { mode: 0o600 });
}

module.exports = {
  zeroBuffer,
  fileExists,
  loadEnvelope,
  saveEnvelope,
};
