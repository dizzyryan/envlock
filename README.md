# envlock

Secure multi-user `.env` encryption with **tamper-proof Ed25519 signing** and **runtime-only decryption**. Designed for teams that commit encrypted secrets to Git.

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│  .env (plaintext)                                               │
│     ↓                                                           │
│  AES-256-GCM encrypt (random 32-byte data key, random 12B IV)   │
│     ↓                                                           │
│  Data key sealed per-recipient (X25519 sealed box)              │
│     ↓                                                           │
│  Envelope signed (Ed25519 detached signature)                   │
│     ↓                                                           │
│  .env.enc (safe to commit)                                      │
└─────────────────────────────────────────────────────────────────┘

At runtime:
  1. Verify signature against LOCAL trust store (reject if untrusted)
  2. Unseal data key with recipient's private key
  3. Decrypt .env in memory (never written to disk)
  4. Inject env vars into child process
```

## Installation

```bash
npm install
npm link  # Makes 'envlock' available globally
```

Requires **Node.js >= 18**.

---

## Quick Start

### 1. Generate your keypair

```bash
envlock keygen <your_id>
# Output: public key (share this with your team)
```

This creates `~/.envlock/keys/<your_id>.json` (private, never share) and auto-trusts your own key.

### 2. Set up recipients file

Create `.envlock.json` in your project root (commit this to Git):

```json
{
  "recipients": [
    { "id": "alice", "public_key": "<alice_public_key_base64>" },
    { "id": "bob", "public_key": "<bob_public_key_base64>" }
  ]
}
```

### 3. Trust your teammates' signing keys

```bash
envlock trust <their_id> <their_public_key_base64>
```

**Important:** Verify keys out-of-band (in person, over a secure channel).

### 4. Encrypt your `.env`

```bash
envlock encrypt .env
# Creates .env.enc — safe to commit

> `envlock encrypt` writes `.env.enc` with `0600` permissions so only your user
> can read it by default. If your workflow requires broader access (e.g., shared
> build user), adjust permissions deliberately (`chmod 0644 .env.enc`).
```

### 5. Run commands with decrypted secrets

```bash
envlock run -- npm run dev
envlock run -- node server.js
envlock run --env staging.env.enc -- npm start
```

---

## CLI Reference

| Command | Description |
|---------|-------------|
| `envlock keygen <id>` | Generate Ed25519 keypair |
| `envlock encrypt <file> [opts]` | Encrypt `.env` → `.env.enc` |
| `envlock run [opts] -- <cmd>` | Decrypt and run command |
| `envlock add-user <id> <pubkey>` | Add recipient (no key rotation) |
| `envlock remove-user <id>` | Remove recipient + rotate data key |
| `envlock trust <id> <pubkey>` | Add signer to local trust store |
| `envlock untrust <id>` | Remove signer from trust store |
| `envlock trust-list` | List trusted signers |
| `envlock version` | Print the current envlock version |

### Options

- `--env, -e <path>` — Path to `.env.enc` (default: `.env.enc`)
- `--key, -k <id>` — Signing/decryption key ID
- `--out, -o <path>` — Output path for encrypt
- `--recipients, -r <file>` — Recipients file (default: `.envlock.json`)

---

## File Format

```json
{
  "version": 1,
  "cipher": "aes-256-gcm",
  "env": {
    "iv": "<base64, 12 bytes>",
    "tag": "<base64, 16 bytes>",
    "ciphertext": "<base64>"
  },
  "recipients": [
    {
      "id": "alice",
      "algo": "x25519-xsalsa20-poly1305",
      "encrypted_key": "<base64, sealed box>"
    }
  ],
  "signatures": [
    {
      "id": "alice",
      "sig": "<base64, 64-byte Ed25519 signature>"
    }
  ]
}
```

---

## Trust Model

### Where trust lives

```
~/.envlock/
├── trust.json           # Trusted Ed25519 signer public keys
└── keys/
    └── <id>.json        # Your private keypair (mode 0600)
```

### Verification rules (enforced on every `run`)

1. Load `.env.enc`
2. For each signature: is signer ID in `~/.envlock/trust.json`?
3. If yes: verify Ed25519 signature over canonical payload
4. If **no valid trusted signature** → **REJECT** (exit 1, no decryption)

### Why this stops attackers

An attacker who gains write access to the repo can:
- Modify `.env.enc`
- Add themselves as a recipient
- Re-sign with their own key

**But:** their key is NOT in any team member's local trust store → signature verification fails → decryption is blocked.

---

## Recommended `.gitignore`

```gitignore
# Never commit plaintext secrets
.env
.env.local
.env.*.local

# Safe to commit (encrypted artefacts stay tracked)
# (leave .env.enc and .envlock.json UN-ignored)
```

---

## Security Guarantees vs Limitations

### Protects Against

| Threat | Mitigation |
|--------|-----------|
| Plaintext secrets in git | `.env.enc` is AES-256-GCM encrypted |
| Unauthorized modification | Ed25519 signature verified against local trust store |
| Attacker adding themselves as recipient | Signature from untrusted key is rejected |
| IV/nonce reuse | Fresh random 12-byte IV per encryption |
| Data key compromise after user removal | `remove-user` performs full key rotation |
| Sealed box replay | Each sealed box uses an ephemeral X25519 keypair internally |
| Ciphertext tampering | GCM authentication tag (128-bit) verified before returning plaintext |
| Secrets written to disk at runtime | Decryption is memory-only; child gets env via `spawn({env})` |

### Does NOT Protect Against

| Threat | Why |
|--------|-----|
| **Stolen private key** | If an attacker obtains `~/.envlock/keys/<id>.json`, they can decrypt any `.env.enc` where that ID is a recipient. Protect your private key with filesystem permissions and disk encryption. |
| **Runtime memory compromise** | Once secrets are decrypted and injected as env vars, they exist in the child process memory. `ptrace`, `/proc/pid/environ`, or a debugger can read them. This is inherent to all env-var-based secret injection. |
| **Malicious dependencies** | A compromised npm package running in your process can read `process.env`. envlock cannot sandbox your application's own code. |
| **Compromised build/CI machine** | If the machine running `envlock run` is rooted, the attacker can intercept everything. |
| **Application logging secrets** | If your app logs `process.env`, secrets appear in logs. envlock cannot prevent this. |
| **Social engineering** | If a team member is tricked into trusting an attacker's key (`envlock trust attacker <key>`), the security model breaks. |
| **V8 garbage collection** | JavaScript strings are immutable and GC'd nondeterministically. Secrets parsed into the env object cannot be reliably erased from memory. Best-effort buffer zeroing is applied where possible. |

### Why Encryption Does NOT Protect Runtime Secrets

Encryption protects **data at rest**. The moment a program needs secrets, they must exist in plaintext in memory:

1. **OS kernel delivers env vars in the clear** — `execve()` copies them into the new process's stack. Any process with sufficient privileges (root, same UID with ptrace) can inspect them.

2. **No hardware enclave** — without SGX/TrustZone, there is no way to use a secret in computation while keeping it encrypted. The CPU operates on plaintext.

3. **envlock's threat model** — protect secrets at rest (git, backups, disk theft) and enforce authorization (only trusted signers can produce valid encrypted files). It does **not** replace runtime secrets managers (HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager) for production systems requiring per-request credential rotation or hardware-backed key storage.

---

## Key Management Best Practices

1. **Never commit private keys** — `~/.envlock/keys/` must never be in a repo
2. **Verify public keys out-of-band** — before running `envlock trust`, confirm the key via a secure side-channel (in person, video call, signed message)
3. **Rotate on compromise** — if a private key is exposed, `remove-user` that ID (rotates data key) and have them `keygen` a new keypair
4. **Use disk encryption** — `~/.envlock/` should live on an encrypted volume
5. **Minimal trust** — only trust keys of active team members; `untrust` departed members

---

## Versioning & Releases

- `package.json` holds the canonical semantic version (`npm version <patch|minor|major>` will update both files and create a git tag).
- `envlock version` exposes the version to users via the CLI.
- To publish a new release on GitHub: commit the version bump, run `git tag v<major>.<minor>.<patch>`, and push with `git push origin --tags`.

## Development

```bash
# Run tests (16 tests covering all crypto layers + attacker scenario)
npm test

# Make CLI executable
chmod +x src/cli.js
```

## Project Structure

```
src/
├── cli.js               # Entry point + command dispatch
├── cli/
│   ├── keygen.js        # Key generation
│   ├── encrypt.js       # Encrypt .env → .env.enc
│   ├── run.js           # Verify + decrypt + spawn
│   ├── add-user.js      # Add recipient
│   ├── remove-user.js   # Remove recipient + rotate
│   └── trust.js         # Trust store management
├── crypto/
│   ├── symmetric.js     # AES-256-GCM
│   ├── asymmetric.js    # X25519 sealed boxes
│   ├── signing.js       # Ed25519 signatures
│   └── index.js
└── utils/
    ├── env.js           # .env file parsing
    ├── trust.js         # Trust store I/O
    ├── helpers.js       # Buffer zeroing, file helpers
    └── index.js
```

## License

MIT
