# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 1.x | ✅ Actively supported |

Security patches are released immediately upon verification.

---

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Report security issues via email: **security@notifycode.org**

Include in your report:
1. Description of the vulnerability
2. Steps to reproduce
3. Affected versions
4. Potential impact assessment
5. Any suggested mitigations (optional)

We aim to acknowledge reports within **48 hours** and provide a fix within **7 days** for critical issues.

---

## Threat Model

### What hash-it protects against

| Threat | Mitigation |
|---|---|
| Password brute force | Argon2id with high memory/time cost |
| Timing attacks | Constant-time comparison (`timingSafeEqual`) throughout |
| Token forgery | Asymmetric cryptography — private key never transmitted |
| Token tampering | ECDSA/RSA signature over full header+payload |
| Key compromise | Key rotation via `PublicKeySet` — revoke without downtime |
| Replay attacks | JTI (JWT ID) unique per token; exp/nbf claims enforced |
| Algorithm confusion | Explicit algorithm allowlisting in `verifyToken` |
| CBC padding oracle | AES-GCM (AEAD) default; CBC uses Encrypt-then-MAC |
| Key derivation weakness | PBKDF2-SHA512 with 100,000 iterations for symmetric keys |
| Long password DoS | Passwords >1024 chars pre-hashed with SHA-512 |

### What hash-it does NOT protect against

- **Compromised private key storage** — protect your private keys using HSMs or secrets managers
- **Side-channel attacks at the hardware level** — Node.js runs in userspace
- **Application-level vulnerabilities** — SQL injection, XSS, SSRF etc.
- **Insecure token transmission** — always use TLS 1.3+
- **Token theft** — use short access token lifetimes (15m default) and refresh rotation

---

## Key Rotation Policy

1. Generate a new key pair at minimum every **12 months**
2. Keep the old public key in the `PublicKeySet` for the lifetime of the longest-lived token using it
3. After rotation, the old private key should be destroyed
4. Use `kid` (key ID) in all tokens to enable efficient key lookup

---

## Token Expiration Rules

| Token Type | Recommended Lifetime |
|---|---|
| Access token | 15 minutes |
| Refresh token | 7 days |
| API token | 90 days (rotate via CI) |
| Session cookie | Match refresh token lifetime |

Implement refresh token rotation: invalidate the old refresh token when issuing a new one.

---

## Dependency Security

hash-it uses **zero external runtime dependencies** — only Node.js built-in `crypto` module. This eliminates the entire supply chain attack surface for crypto operations.

### Audit schedule

Run `npm audit` weekly. Any **high** or **critical** vulnerabilities block releases.

```bash
npm audit
npm audit --audit-level=high
```

---

## Cryptographic Primitives

All algorithms used are NIST-approved or widely vetted:

| Purpose | Algorithm | Standard |
|---|---|---|
| Password hashing | Argon2id | OWASP 2023 |
| Key derivation (symmetric) | PBKDF2-SHA512 | NIST SP 800-132 |
| Token signing (primary) | ECDSA P-256 | NIST FIPS 186-4 |
| Token signing (RSA) | RSA-4096 / RSA-PSS | NIST SP 800-131A |
| Symmetric encryption | AES-256-GCM | NIST SP 800-38D |
| Alternate cipher | ChaCha20-Poly1305 | RFC 8439 |
| HMAC (CBC integrity) | HMAC-SHA256 | FIPS 198-1 |
| Random generation | `crypto.randomBytes` | CSPRNG |

---

## Security Best Practices for Consumers

1. **Store private keys securely** — use environment variables, AWS Secrets Manager, HashiCorp Vault, etc.
2. **Never log tokens** — if you must log for debugging, use `hashit.apiToken.mask()`
3. **Validate all claims** — always pass `issuer` and `audience` to `verify()`
4. **Restrict algorithms** — pass `algorithms: ['ES256']` to prevent algorithm substitution
5. **Rotate keys annually** — use `PublicKeySet` to rotate without downtime
6. **Short access token lifetimes** — 15 minutes is the default for a reason
7. **Implement refresh token rotation** — invalidate old refresh tokens on use
8. **Use HTTPS everywhere** — tokens provide authentication, not transport security

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the complete security patch history.
