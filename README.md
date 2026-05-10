# `@notifycode/hash-it`

> Enterprise-grade token and password security library — Mastercard-style public/private key token verification, native JavaScript.

[![Tests](https://img.shields.io/badge/tests-155%20passing-brightgreen)](#testing)
[![Coverage](https://img.shields.io/badge/coverage-96%25-brightgreen)](#testing)
[![Node](https://img.shields.io/badge/node-%3E%3D18-blue)](#installation)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue)](#)
[![Zero deps](https://img.shields.io/badge/dependencies-zero-brightgreen)](#)

---

## What makes hash-it unique

**Mastercard-style asymmetric token verification — natively in JavaScript.** No external crypto dependencies.

Most libraries use shared-secret (HMAC) token signing. hash-it uses public/private key cryptography:

```
┌─────────────────┐          ┌──────────────────────┐
│  Token Issuer   │          │  Token Verifier(s)   │
│  (private key)  │  token   │  (public key only —  │
│  signs tokens   │ ───────► │   can verify but     │
│                 │          │   CANNOT forge)       │
└─────────────────┘          └──────────────────────┘
```

The private key never leaves the issuer. Any service with only the public key can verify tokens. No single point of compromise.

---

## Features

| Feature | Details |
|---|---|
| 🔐 **Password Hashing** | Argon2id (OWASP recommended) with PBKDF2 fallback |
| 🔑 **Asymmetric Tokens** | ECDSA P-256/P-384/P-521 + RSA-4096 + RSA-PSS |
| 🔄 **Key Rotation** | Multi-key PublicKeySet — rotate without breaking existing tokens |
| 🔒 **Encryption** | AES-256-GCM (AEAD), AES-256-CBC, ChaCha20-Poly1305 |
| 🎫 **Session Management** | Access + refresh token pairs |
| 🪙 **API Tokens** | Opaque tokens with embedded verifiable claims |
| ⚡ **Zero Dependencies** | Node.js `crypto` only — nothing to audit |
| 🐰 **Bun + Node.js** | Full dual CJS/ESM support |
| 🛡️ **Timing-Safe** | Constant-time comparisons throughout |

---

## Installation

```bash
# npm
npm install @notifycode/hash-it

# Bun
bun add @notifycode/hash-it

# pnpm
pnpm add @notifycode/hash-it
```

**Requires Node.js ≥ 18 or Bun (any version).**

---

## Quick Start

```typescript
import { hashit } from '@notifycode/hash-it';

// 1. Hash a password (Argon2id, OWASP defaults)
const { hash } = await hashit.password.hash('user-password');
const { valid } = await hashit.password.verify('user-password', hash);

// 2. Generate a key pair
const keyPair = hashit.keys.generate(); // ECDSA P-256

// 3. Sign and verify a token (Mastercard-style)
const token = hashit.token.sign(
  { sub: 'user_123', role: 'admin' },
  { privateKey: keyPair.privateKey, expiresIn: '15m' }
);

const { valid: tokenValid, payload } = hashit.token.verify(token, {
  publicKey: keyPair.publicKey, // Only the PUBLIC key needed!
});

// 4. Session management
const session = hashit.session.create(keyPair, {
  sub: 'user_123',
  claims: { role: 'admin' },
});

// 5. API tokens (like GitHub's ghp_ or Stripe's sk_)
const apiToken = hashit.apiToken.generate(keyPair, {
  prefix: 'myapp_',
  expiresIn: '90d',
  claims: { scopes: ['read', 'write'] },
});
```

---

## API Reference

All functionality is accessible via the `hashit` object:

```typescript
import { hashit } from '@notifycode/hash-it';
```

---

### `hashit.password`

#### `.hash(password, options?)`

Hash a password using Argon2id with OWASP-recommended parameters.

```typescript
const result = await hashit.password.hash('my-password');
// result.hash      — the stored hash string
// result.algorithm — 'argon2id'
// result.salt      — base64url-encoded salt
// result.timingMs  — milliseconds taken
```

**Options** (`Argon2Options`):
| Option | Default | Description |
|---|---|---|
| `memoryCost` | `65536` | Memory cost in KiB (64MB) |
| `timeCost` | `3` | Iteration count |
| `parallelism` | `4` | Thread count |
| `hashLength` | `32` | Output length in bytes |
| `saltLength` | `16` | Salt length in bytes (min 12) |

#### `.verify(password, hash)`

Verify a password. Always constant-time.

```typescript
const { valid, needsRehash, timingMs } = await hashit.password.verify('my-password', storedHash);

// Upgrade hash if parameters have been increased
if (valid && needsRehash) {
  const { hash: newHash } = await hashit.password.hash('my-password');
  await db.updateUserHash(userId, newHash);
}
```

#### `.needsRehash(hash, options?)`

Check if a hash was created with weaker parameters than current defaults.

```typescript
if (hashit.password.needsRehash(storedHash)) {
  // Re-hash on next successful login
}
```

---

### `hashit.keys`

#### `.generate(options?)`

Generate an asymmetric key pair for token signing.

```typescript
// ECDSA P-256 (default — best performance/security balance)
const keyPair = hashit.keys.generate();

// ECDSA P-384 (higher security, slightly slower)
const keyPair = hashit.keys.generate({ algorithm: 'ES384' });

// RSA-4096 (legacy compatibility)
const keyPair = hashit.keys.generate({ algorithm: 'RS256' });

// With a named key ID (for rotation)
const keyPair = hashit.keys.generate({ algorithm: 'ES256', kid: 'key-2024-01' });
```

**Supported algorithms:** `ES256`, `ES384`, `ES512`, `RS256`, `RS512`, `PS256`

#### `.exportPublic(keyPair)`

Export the public key for distribution to verifier services.

```typescript
const publicEntry = hashit.keys.exportPublic(keyPair);
// { kid, algorithm, publicKey, createdAt }
// Distribute this — it contains NO private key
```

#### `.buildKeySet(entries[])`

Build a `PublicKeySet` for multi-key rotation support.

```typescript
const keySet = hashit.keys.buildKeySet([
  hashit.keys.exportPublic(newKey),
  hashit.keys.exportPublic(previousKey), // kept during rotation window
]);
```

---

### `hashit.token`

#### `.sign(payload, options)`

Sign a payload and produce a compact JWT-compatible token.

```typescript
const token = hashit.token.sign(
  { sub: 'user_123', role: 'admin', org: 'acme' },
  {
    privateKey: keyPair.privateKey,
    kid: keyPair.kid,           // key ID in header (required for rotation)
    algorithm: 'ES256',         // default
    expiresIn: '15m',           // '30s', '15m', '1h', '7d', '2w' or seconds
    issuer: 'auth-service',
    audience: 'api-service',
  }
);
```

#### `.verify(token, options)`

Verify signature + all claims. Returns structured result (never throws).

```typescript
const result = hashit.token.verify(token, {
  publicKey: keyPair.publicKey,   // string or PublicKeySet
  issuer: 'auth-service',         // optional — verified if provided
  audience: 'api-service',        // optional — verified if provided
  algorithms: ['ES256', 'ES384'], // optional — restrict allowed algorithms
  clockSkew: 30,                  // seconds of tolerance (default: 30)
});

if (result.valid) {
  console.log(result.payload?.sub);       // 'user_123'
  console.log(result.payload?.role);      // 'admin'
  console.log(result.kid);               // key ID used
  console.log(result.algorithm);         // 'ES256'
} else {
  console.log(result.error);             // human-readable error
}
```

#### `.decode(token)` ⚠️

Decode without verifying. **Never use for authentication.**

```typescript
const payload = hashit.token.decode(token); // UNSAFE — no signature check
```

---

### `hashit.session`

#### `.create(keyPair, options)`

Create an access + refresh token pair.

```typescript
const session = hashit.session.create(keyPair, {
  sub: 'user_123',
  issuer: 'auth-service',
  accessExpiresIn: '15m',   // default
  refreshExpiresIn: '7d',   // default
  claims: { role: 'admin', org: 'acme' },
});

// session.accessToken    — short-lived, send to client
// session.refreshToken   — long-lived, store securely
// session.accessExpiresAt  — Unix timestamp
// session.refreshExpiresAt — Unix timestamp
// session.tokenType      — 'Bearer'
```

#### `.verify(token, publicKey, options?)`

Verify a session access token.

```typescript
const { valid, payload } = hashit.session.verify(
  session.accessToken,
  keyPair.publicKey  // or PublicKeySet for rotation
);
```

#### `.rotate(refreshToken, keyPair, options)`

Exchange a refresh token for a fresh session pair.

```typescript
const newSession = hashit.session.rotate(session.refreshToken, keyPair, {
  sub: 'user_123',
  issuer: 'auth-service',
});
```

---

### `hashit.apiToken`

#### `.generate(keyPair, options?)`

Generate an opaque API token with embedded cryptographic claims.

```typescript
const apiToken = hashit.apiToken.generate(keyPair, {
  prefix: 'myapp_',         // default: 'hsh_'
  sub: 'org_123',
  expiresIn: '90d',         // or null for non-expiring
  claims: { scopes: ['read', 'write'], tier: 'pro' },
});

// apiToken.token   — 'myapp_eyJhbGciOiJFUzI1NiJ9...'
// apiToken.prefix  — 'myapp_'
// apiToken.masked  — 'myapp_****3a1b'  (safe for logs)
// apiToken.expiresAt — Unix timestamp or null
```

#### `.verify(token, publicKey)`

Verify and decode an API token.

```typescript
const { valid, payload } = hashit.apiToken.verify(apiToken.token, keyPair.publicKey);
```

#### `.mask(token)`

Mask a token for safe display in logs/UI.

```typescript
hashit.apiToken.mask('hsh_eyJhbGci...longtoken');
// → 'hsh_****en'
```

---

### `hashit.encrypt`

#### `.seal(plaintext, key, options?)`

Encrypt using AES-256-GCM (authenticated encryption — detects tampering).

```typescript
const sealed = hashit.encrypt.seal('sensitive-data', 'my-encryption-key');
// { ciphertext, iv, tag, algorithm: 'aes-256-gcm' }
```

**Options:**
| Option | Default | Options |
|---|---|---|
| `algorithm` | `aes-256-gcm` | `aes-256-gcm`, `aes-256-cbc`, `chacha20-poly1305` |

#### `.open(encrypted, key)`

Decrypt. Throws `HashItError` if key is wrong or data is tampered.

```typescript
const plaintext = hashit.encrypt.open(sealed, 'my-encryption-key');
```

---

### `hashit.utils`

```typescript
// Cryptographically secure random bytes (base64url)
const secret = hashit.utils.randomBytes(32);

// Constant-time comparison (prevents timing attacks)
const match = hashit.utils.safeEqual(providedToken, storedToken);

// Parse duration strings
hashit.utils.parseDuration('15m'); // → 900
hashit.utils.parseDuration('7d');  // → 604800

// Generate a token fingerprint (for device binding)
const fp = hashit.utils.fingerprint('user-agent:chrome,ip:1.2.3.4');
```

---

## Key Rotation

Key rotation without breaking existing tokens:

```typescript
// 1. Generate a new key pair
const newKey = hashit.keys.generate({ kid: 'key-2025-01' });

// 2. Build a key set with both old and new keys
const keySet = hashit.keys.buildKeySet([
  hashit.keys.exportPublic(newKey),
  hashit.keys.exportPublic(oldKey), // keeps validating old tokens
]);

// 3. Sign new tokens with the new key
const token = hashit.token.sign(payload, {
  privateKey: newKey.privateKey,
  kid: newKey.kid,
});

// 4. Verify tokens against the key set (works for both old and new)
const result = hashit.token.verify(token, { publicKey: keySet });

// 5. After the refresh window passes, remove the old key from the set
```

---

## Tree-Shakeable Named Exports

For bundle size optimization, all functions are also available as named exports:

```typescript
import {
  hashPassword, verifyPassword,
  signToken, verifyToken,
  generateKeyPair, buildKeySet,
  seal, open,
  createSession, rotateSession,
} from '@notifycode/hash-it';
```

---

## Error Handling

All errors extend `HashItError` with a structured `code`:

```typescript
import { HashItError, HashItErrorCode } from '@notifycode/hash-it';

try {
  const result = hashit.token.verify(token, { publicKey });
  if (!result.valid) {
    console.log(result.error); // human-readable
  }
} catch (err) {
  if (err instanceof HashItError) {
    switch (err.code) {
      case HashItErrorCode.INVALID_KEY:   // ...
      case HashItErrorCode.DECRYPT_FAILED: // ...
    }
  }
}
```

**Error codes:** `INVALID_KEY`, `INVALID_TOKEN`, `TOKEN_EXPIRED`, `TOKEN_NOT_YET_VALID`, `SIGNATURE_INVALID`, `ALGORITHM_MISMATCH`, `KEY_NOT_FOUND`, `AUDIENCE_MISMATCH`, `ISSUER_MISMATCH`, `ENCRYPT_FAILED`, `DECRYPT_FAILED`, `HASH_FAILED`, `INVALID_PARAMS`

---

## Testing

```bash
npm test              # run all 155 tests
npm run test:watch    # watch mode
```

Coverage: **96%+** statements, branches, functions, lines.

---

## Security

See [SECURITY.md](SECURITY.md) for the responsible disclosure process and threat model.

---

## License

MIT © Neza
