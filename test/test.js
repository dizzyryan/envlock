'use strict';

const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');
const { version: packageVersion } = require('../package.json');
const sodium = require('libsodium-wrappers');

async function runTests() {
  await sodium.ready;

  const { symmetric, asymmetric, signing } = require('../src/crypto');
  const { parseEnvBuffer } = require('../src/utils/env');
  const { zeroBuffer } = require('../src/utils/helpers');

  // ============================================================
  // SYMMETRIC ENCRYPTION TESTS (AES-256-GCM)
  // ============================================================

  console.log('--- Symmetric (AES-256-GCM) ---');

  // Test: round-trip encrypt/decrypt
  {
    const key = symmetric.generateDataKey();
    const plaintext = Buffer.from('DB_HOST=localhost\nDB_PASS=s3cr3t\n');
    const encrypted = symmetric.encrypt(plaintext, key);

    assert.ok(encrypted.iv, 'must have iv');
    assert.ok(encrypted.tag, 'must have tag');
    assert.ok(encrypted.ciphertext, 'must have ciphertext');

    const decrypted = symmetric.decrypt(encrypted, key);
    assert.deepStrictEqual(decrypted, plaintext);
    console.log('  ✓ Round-trip encrypt/decrypt');
  }

  // Test: wrong key fails
  {
    const key1 = symmetric.generateDataKey();
    const key2 = symmetric.generateDataKey();
    const plaintext = Buffer.from('SECRET=value');
    const encrypted = symmetric.encrypt(plaintext, key1);

    assert.throws(() => symmetric.decrypt(encrypted, key2));
    console.log('  ✓ Wrong key rejected');
  }

  // Test: tampered ciphertext fails
  {
    const key = symmetric.generateDataKey();
    const encrypted = symmetric.encrypt(Buffer.from('data'), key);

    const ct = Buffer.from(encrypted.ciphertext, 'base64');
    ct[0] ^= 0xff;
    encrypted.ciphertext = ct.toString('base64');

    assert.throws(() => symmetric.decrypt(encrypted, key));
    console.log('  ✓ Tampered ciphertext rejected');
  }

  // Test: unique IV per encryption
  {
    const key = symmetric.generateDataKey();
    const plaintext = Buffer.from('same data');
    const e1 = symmetric.encrypt(plaintext, key);
    const e2 = symmetric.encrypt(plaintext, key);

    assert.notStrictEqual(e1.iv, e2.iv, 'IVs must be unique');
    assert.notStrictEqual(e1.ciphertext, e2.ciphertext, 'Ciphertexts must differ');
    console.log('  ✓ Unique IV per encryption');
  }

  // ============================================================
  // ASYMMETRIC ENCRYPTION TESTS (X25519 sealed box)
  // ============================================================

  console.log('\n--- Asymmetric (X25519 sealed box) ---');

  // Test: encrypt/decrypt data key for recipient
  {
    const keypair = sodium.crypto_sign_keypair();
    const dataKey = symmetric.generateDataKey();

    const sealed = asymmetric.encryptDataKeyForRecipient(dataKey, keypair.publicKey);
    assert.ok(typeof sealed === 'string', 'sealed must be base64 string');

    const recovered = asymmetric.decryptDataKey(sealed, keypair.publicKey, keypair.privateKey);
    assert.deepStrictEqual(recovered, dataKey);
    console.log('  ✓ Sealed box encrypt/decrypt');
  }

  // Test: wrong key cannot decrypt
  {
    const keypair1 = sodium.crypto_sign_keypair();
    const keypair2 = sodium.crypto_sign_keypair();
    const dataKey = symmetric.generateDataKey();

    const sealed = asymmetric.encryptDataKeyForRecipient(dataKey, keypair1.publicKey);

    assert.throws(() => {
      asymmetric.decryptDataKey(sealed, keypair2.publicKey, keypair2.privateKey);
    });
    console.log('  ✓ Wrong recipient key rejected');
  }

  // Test: sealed box is non-deterministic (different each time)
  {
    const keypair = sodium.crypto_sign_keypair();
    const dataKey = symmetric.generateDataKey();

    const sealed1 = asymmetric.encryptDataKeyForRecipient(dataKey, keypair.publicKey);
    const sealed2 = asymmetric.encryptDataKeyForRecipient(dataKey, keypair.publicKey);

    assert.notStrictEqual(sealed1, sealed2, 'Sealed boxes must be non-deterministic');
    console.log('  ✓ Non-deterministic sealed boxes');
  }

  // ============================================================
  // SIGNING TESTS (Ed25519)
  // ============================================================

  console.log('\n--- Signing (Ed25519) ---');

  // Test: sign and verify
  {
    const keypair = signing.generateSigningKeypair();
    const envelope = {
      version: 1,
      cipher: 'aes-256-gcm',
      env: { iv: 'abc', tag: 'def', ciphertext: 'ghi' },
      recipients: [{ id: 'alice', algo: 'x25519-xsalsa20-poly1305', encrypted_key: 'xyz' }],
      signatures: [],
    };

    const sig = signing.signEnvelope(envelope, keypair.privateKey);
    const valid = signing.verifySignature(envelope, sig, keypair.publicKey);
    assert.strictEqual(valid, true);
    console.log('  ✓ Sign and verify');
  }

  // Test: wrong key fails verification
  {
    const keypair1 = signing.generateSigningKeypair();
    const keypair2 = signing.generateSigningKeypair();

    const envelope = {
      version: 1,
      cipher: 'aes-256-gcm',
      env: { iv: 'a', tag: 'b', ciphertext: 'c' },
      recipients: [],
      signatures: [],
    };

    const sig = signing.signEnvelope(envelope, keypair1.privateKey);
    const valid = signing.verifySignature(envelope, sig, keypair2.publicKey);
    assert.strictEqual(valid, false);
    console.log('  ✓ Wrong signer key rejected');
  }

  // Test: tampered envelope fails verification
  {
    const keypair = signing.generateSigningKeypair();
    const envelope = {
      version: 1,
      cipher: 'aes-256-gcm',
      env: { iv: 'a', tag: 'b', ciphertext: 'original' },
      recipients: [],
      signatures: [],
    };

    const sig = signing.signEnvelope(envelope, keypair.privateKey);

    // Tamper with the envelope after signing
    const tampered = { ...envelope, env: { iv: 'a', tag: 'b', ciphertext: 'MODIFIED' } };
    const valid = signing.verifySignature(tampered, sig, keypair.publicKey);
    assert.strictEqual(valid, false);
    console.log('  ✓ Tampered envelope signature rejected');
  }

  // Test: verifyEnvelopeTrust with trusted and untrusted keys
  {
    const trustedKeypair = signing.generateSigningKeypair();
    const attackerKeypair = signing.generateSigningKeypair();

    const envelope = {
      version: 1,
      cipher: 'aes-256-gcm',
      env: { iv: 'x', tag: 'y', ciphertext: 'z' },
      recipients: [],
      signatures: [],
    };

    // Attacker signs the file
    const attackerSig = signing.signEnvelope(envelope, attackerKeypair.privateKey);
    envelope.signatures.push({ id: 'attacker', sig: attackerSig });

    // Trust store only contains the legitimate key
    const trustedSigners = new Map();
    trustedSigners.set('admin', trustedKeypair.publicKey);

    // Verification must FAIL — attacker's key is not trusted
    const result = signing.verifyEnvelopeTrust(envelope, trustedSigners);
    assert.strictEqual(result.valid, false);
    console.log('  ✓ Untrusted signer rejected (attacker scenario)');
  }

  // Test: verifyEnvelopeTrust with valid trusted signature
  {
    const trustedKeypair = signing.generateSigningKeypair();

    const envelope = {
      version: 1,
      cipher: 'aes-256-gcm',
      env: { iv: 'x', tag: 'y', ciphertext: 'z' },
      recipients: [],
      signatures: [],
    };

    const sig = signing.signEnvelope(envelope, trustedKeypair.privateKey);
    envelope.signatures.push({ id: 'admin', sig });

    const trustedSigners = new Map();
    trustedSigners.set('admin', trustedKeypair.publicKey);

    const result = signing.verifyEnvelopeTrust(envelope, trustedSigners);
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.signerId, 'admin');
    console.log('  ✓ Trusted signer accepted');
  }

  // ============================================================
  // FULL INTEGRATION TEST
  // ============================================================

  console.log('\n--- Integration (full encrypt → verify → decrypt flow) ---');

  {
    // Simulate two users: alice (admin/signer) and bob (recipient)
    const aliceKeypair = sodium.crypto_sign_keypair();
    const bobKeypair = sodium.crypto_sign_keypair();

    // Original .env content
    const envContent = Buffer.from('DATABASE_URL=postgres://localhost/myapp\nAPI_KEY=sk-secret-123\n');

    // Step 1: Generate random data key
    const dataKey = symmetric.generateDataKey();

    // Step 2: Encrypt .env with AES-256-GCM
    const envEncrypted = symmetric.encrypt(envContent, dataKey);

    // Step 3: Encrypt data key for both recipients (sealed box)
    const aliceEncKey = asymmetric.encryptDataKeyForRecipient(dataKey, aliceKeypair.publicKey);
    const bobEncKey = asymmetric.encryptDataKeyForRecipient(dataKey, bobKeypair.publicKey);

    // Step 4: Build envelope
    const envelope = {
      version: 1,
      cipher: 'aes-256-gcm',
      env: envEncrypted,
      recipients: [
        { id: 'alice', algo: 'x25519-xsalsa20-poly1305', encrypted_key: aliceEncKey },
        { id: 'bob', algo: 'x25519-xsalsa20-poly1305', encrypted_key: bobEncKey },
      ],
      signatures: [],
    };

    // Step 5: Alice signs the envelope
    const sig = signing.signEnvelope(envelope, aliceKeypair.privateKey);
    envelope.signatures.push({ id: 'alice', sig });

    // Step 6: Verify signature (as Bob would when running)
    const trustedSigners = new Map();
    trustedSigners.set('alice', aliceKeypair.publicKey);

    const verification = signing.verifyEnvelopeTrust(envelope, trustedSigners);
    assert.strictEqual(verification.valid, true);

    // Step 7: Bob decrypts data key
    const bobEntry = envelope.recipients.find((r) => r.id === 'bob');
    const recoveredKey = asymmetric.decryptDataKey(
      bobEntry.encrypted_key,
      bobKeypair.publicKey,
      bobKeypair.privateKey
    );

    // Step 8: Decrypt .env content
    const decrypted = symmetric.decrypt(envelope.env, recoveredKey);
    assert.deepStrictEqual(decrypted, envContent);

    // Step 9: Parse env vars
    const envVars = parseEnvBuffer(decrypted);
    assert.strictEqual(envVars.DATABASE_URL, 'postgres://localhost/myapp');
    assert.strictEqual(envVars.API_KEY, 'sk-secret-123');

    console.log('  ✓ Full flow: encrypt → sign → verify → decrypt → parse');
  }

  // ============================================================
  // ATTACKER SCENARIO TEST
  // ============================================================

  console.log('\n--- Attacker scenario ---');

  {
    const legitimateKeypair = sodium.crypto_sign_keypair();
    const attackerKeypair = sodium.crypto_sign_keypair();

    // Legitimate envelope created and signed by legitimate user
    const envContent = Buffer.from('SECRET=real-secret');
    const dataKey = symmetric.generateDataKey();
    const envEncrypted = symmetric.encrypt(envContent, dataKey);

    // Attacker creates their OWN envelope with different content
    const evilContent = Buffer.from('SECRET=phished-value');
    const evilDataKey = symmetric.generateDataKey();
    const evilEncrypted = symmetric.encrypt(evilContent, evilDataKey);
    const attackerEncKey = asymmetric.encryptDataKeyForRecipient(evilDataKey, attackerKeypair.publicKey);

    const evilEnvelope = {
      version: 1,
      cipher: 'aes-256-gcm',
      env: evilEncrypted,
      recipients: [
        { id: 'attacker', algo: 'x25519-xsalsa20-poly1305', encrypted_key: attackerEncKey },
      ],
      signatures: [],
    };

    // Attacker signs with their own key
    const evilSig = signing.signEnvelope(evilEnvelope, attackerKeypair.privateKey);
    evilEnvelope.signatures.push({ id: 'attacker', sig: evilSig });

    // Victim's trust store only trusts the legitimate key
    const trustedSigners = new Map();
    trustedSigners.set('admin', legitimateKeypair.publicKey);

    // Verification MUST fail — attacker's key is not trusted
    const result = signing.verifyEnvelopeTrust(evilEnvelope, trustedSigners);
    assert.strictEqual(result.valid, false);
    console.log('  ✓ Attacker-signed envelope rejected by trust verification');
  }

  // ============================================================
  // UTILITY TESTS
  // ============================================================

  console.log('\n--- Utilities ---');

  // Test: parseEnvBuffer
  {
    const input = Buffer.from([
      '# Comment',
      '',
      'HOST=localhost',
      'PORT=3000',
      'PASS="multi word"',
      "KEY='single'",
      'EQUALS=a=b=c',
      'EMPTY=',
    ].join('\n'));

    const parsed = parseEnvBuffer(input);
    assert.strictEqual(parsed.HOST, 'localhost');
    assert.strictEqual(parsed.PORT, '3000');
    assert.strictEqual(parsed.PASS, 'multi word');
    assert.strictEqual(parsed.KEY, 'single');
    assert.strictEqual(parsed.EQUALS, 'a=b=c');
    assert.strictEqual(parsed.EMPTY, '');
    console.log('  ✓ parseEnvBuffer');
  }

  // Test: zeroBuffer
  {
    const buf = Buffer.from('sensitive');
    zeroBuffer(buf);
    assert.ok(buf.every((b) => b === 0));
    console.log('  ✓ zeroBuffer');
}

  // ============================================================
  // CLI INTEGRATION TESTS
  // ============================================================

  console.log('\n--- CLI integration ---');

  const repoRoot = path.resolve(__dirname, '..');
  const cliPath = path.join(repoRoot, 'src', 'cli.js');
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'envlock-test-'));
  const envlockHome = fs.mkdtempSync(path.join(os.tmpdir(), 'envlock-home-'));

  const runCli = (args, options = {}) => {
    const result = spawnSync('node', [cliPath, ...args], {
      cwd: options.cwd || repoRoot,
      env: { ...process.env, ENVLOCK_HOME: envlockHome, ...(options.env || {}) },
      encoding: 'utf8',
    });

    if (options.expectExitCode !== undefined) {
      assert.strictEqual(
        result.status,
        options.expectExitCode,
        `Expected exit ${options.expectExitCode} for envlock ${args.join(' ')}, got ${result.status}\nSTDOUT: ${result.stdout}\nSTDERR: ${result.stderr}`
      );
    }

    return result;
  };

  // 1. keygen alice
  const keygenResult = runCli(['keygen', 'alice-test'], { expectExitCode: 0 });
  assert.match(keygenResult.stdout, /Generated Ed25519 keypair/);

  // 2. trust bob (using alice's public key just to populate store)
  const aliceKeyPath = path.join(envlockHome, 'keys', 'alice-test.json');
  const aliceKey = JSON.parse(fs.readFileSync(aliceKeyPath, 'utf8'));
  runCli(['trust', 'alice-test', aliceKey.public_key], { expectExitCode: 0 });

  // 3. Set up .envlock.json with alice as recipient
  const recipientsPath = path.join(tempDir, '.envlock.json');
  fs.writeFileSync(
    recipientsPath,
    JSON.stringify({ recipients: [{ id: 'alice-test', public_key: aliceKey.public_key }] }, null, 2)
  );

  // 4. Create plaintext .env
  const envPath = path.join(tempDir, '.env');
  fs.writeFileSync(envPath, 'FOO=bar\nSECRET=top-secret\n');

  // 5. Encrypt (output to temp)
  const encryptResult = runCli(
    ['encrypt', envPath, '--recipients', recipientsPath, '--key', 'alice-test', '--out', path.join(tempDir, '.env.enc')],
    { expectExitCode: 0 }
  );
  assert.match(encryptResult.stdout, /Encrypted and signed/);

  // 6. Run command with decrypted env (print FOO)
  const runResult = runCli(
    ['run', '--env', path.join(tempDir, '.env.enc'), '--key', 'alice-test', '--', 'node -e "console.log(process.env.FOO)"'],
    {
      expectExitCode: 0,
    }
  );
  assert.match(runResult.stdout, /bar/);

  // 7. Add user bob-test
  const keygenBob = runCli(['keygen', 'bob-test'], { expectExitCode: 0 });
  assert.match(keygenBob.stdout, /Generated Ed25519 keypair/);

  const bobKey = JSON.parse(fs.readFileSync(path.join(envlockHome, 'keys', 'bob-test.json'), 'utf8'));
  runCli(['add-user', 'bob-test', bobKey.public_key, '--env', path.join(tempDir, '.env.enc'), '--key', 'alice-test'], {
    expectExitCode: 0,
    cwd: tempDir,
  });

  // 8. Ensure bob can run
  const runBob = runCli(
    ['run', '--env', path.join(tempDir, '.env.enc'), '--key', 'bob-test', '--', 'node -e "console.log(process.env.SECRET)"'],
    { expectExitCode: 0 }
  );
  assert.match(runBob.stdout, /top-secret/);

  // 9. Version command mirrors package.json
  {
    const versionResult = runCli(['version'], { expectExitCode: 0 });
    assert.strictEqual(versionResult.stdout.trim(), `envlock ${packageVersion}`);

    const flagResult = runCli(['--version'], { expectExitCode: 0 });
    assert.strictEqual(flagResult.stdout.trim(), `envlock ${packageVersion}`);
  }

  // 10. Remove bob and ensure he loses access
  runCli(['remove-user', 'bob-test', '--env', path.join(tempDir, '.env.enc'), '--key', 'alice-test'], {
    expectExitCode: 0,
    cwd: tempDir,
  });

  const runBobAfterRemoval = runCli(
    ['run', '--env', path.join(tempDir, '.env.enc'), '--key', 'bob-test', '--', 'node -e "console.log(\"should fail\")"'],
    { expectExitCode: 1 }
  );
  assert.match(runBobAfterRemoval.stderr, /not a recipient/);

  // 11. Tamper with signature and expect failure before decryption
  const envelopePath = path.join(tempDir, '.env.enc');
  const envelope = JSON.parse(fs.readFileSync(envelopePath, 'utf8'));
  envelope.signatures = [{ id: 'attacker', sig: envelope.signatures[0].sig }];
  fs.writeFileSync(envelopePath, JSON.stringify(envelope, null, 2));

  const tamperedRun = runCli(
    ['run', '--env', envelopePath, '--key', 'alice-test', '--', 'node -e "console.log(\"should fail\")"'],
    { expectExitCode: 1 }
  );
  assert.match(tamperedRun.stderr, /SIGNATURE VERIFICATION FAILED/);

  // Cleanup temporary artifacts (best effort)
  fs.rmSync(tempDir, { recursive: true, force: true });
  fs.rmSync(envlockHome, { recursive: true, force: true });

  console.log('\n═══════════════════════════════════');
  console.log('All tests passed ✓');
}

runTests().catch((err) => {
  console.error('Test failure:', err);
  process.exit(1);
});
