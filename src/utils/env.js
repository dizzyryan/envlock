'use strict';

/**
 * Parse a .env file content (as Buffer) into a key-value object.
 *
 * Supports:
 * - KEY=VALUE
 * - KEY="quoted value" (double quotes stripped)
 * - KEY='quoted value' (single quotes stripped)
 * - Comments (lines starting with #)
 * - Empty lines (ignored)
 * - Values containing = characters
 *
 * @param {Buffer} buffer - Raw .env file content
 * @returns {object} Parsed environment variables as { KEY: "value" }
 */
function parseEnvBuffer(buffer) {
  if (!Buffer.isBuffer(buffer)) {
    throw new Error('Input must be a Buffer');
  }

  const content = buffer.toString('utf8');
  const env = {};
  const lines = content.split(/\r?\n/);

  for (const line of lines) {
    const trimmed = line.trim();

    // Skip empty lines and comments
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }

    // Match KEY=VALUE pattern (only first = is separator)
    const separatorIndex = trimmed.indexOf('=');
    if (separatorIndex === -1) {
      continue;
    }

    const key = trimmed.slice(0, separatorIndex).trim();
    let value = trimmed.slice(separatorIndex + 1).trim();

    // Strip surrounding quotes if present
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    if (key) {
      env[key] = value;
    }
  }

  return env;
}

module.exports = { parseEnvBuffer };
