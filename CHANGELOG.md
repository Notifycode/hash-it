# Changelog

All notable changes to `@notifycode/hash-it` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2025-05-10

### Added

- **`hashit.password`** — Argon2id password hashing with OWASP-recommended parameters
  - PBKDF2-SHA512 fallback for constrained environments
  - Automatic upgrade detection via `needsRehash()`
  - DoS protection: passwords >1024 chars pre-hashed with SHA-512
  - Constant-time verification via `timingSafeEqual`

- **`hashit.token`** — Mastercard-style asymmetric token signing and verification
  - ECDSA P-256/P-384/P-521 support (`ES256`, `ES384`, `ES512`)
  - RSA-4096 support (`RS256`, `RS512`, `PS256`)
  - JWT-compatible compact token format
  - Full claims validation: `exp`, `nbf`, `iss`, `aud`, `jti`
  - Clock skew tolerance (configurable, default 30s)

- **`hashit.keys`** — Asymmetric key pair management
  - Key pair generation for all supported algorithms
  - `PublicKeySet` for multi-key rotation support
  - Key lookup by `kid` for efficient rotation

- **`hashit.session`** — Session token pair management
  - Access + refresh token pair creation
  - Refresh token rotation
  - Type-safe session verification

- **`hashit.apiToken`** — Opaque API token generation
  - Embedded cryptographic claims (like GitHub's `ghp_`, Stripe's `sk_`)
  - Configurable prefix
  - Token masking for safe log output

- **`hashit.encrypt`** — Symmetric authenticated encryption
  - AES-256-GCM (default — AEAD, tamper-evident)
  - AES-256-CBC with Encrypt-then-MAC
  - ChaCha20-Poly1305 (where supported)
  - PBKDF2-derived keys from passwords

- **`hashit.utils`** — Security utilities
  - `randomBytes()` — CSPRNG random bytes
  - `safeEqual()` — constant-time string comparison
  - `parseDuration()` — human-readable duration parsing
  - `fingerprint()` — HMAC-based token fingerprinting

- **Dual CJS/ESM build** — full Node.js and Bun support
- **Zero runtime dependencies** — Node.js `crypto` module only
- **155 tests** — 96%+ coverage
- **Full TypeScript types** — strict mode, all public APIs documented