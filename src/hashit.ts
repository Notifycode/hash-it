/**
 * @notifycode/hash-it
 *
 * Enterprise-grade token and password security library.
 * Mastercard-style public/private key token verification — native JavaScript.
 *
 * @example
 * import { hashit } from '@notifycode/hash-it';
 *
 * // Password hashing
 * const { hash } = await hashit.password.hash('my-password');
 * const { valid } = await hashit.password.verify('my-password', hash);
 *
 * // Key generation
 * const keyPair = hashit.keys.generate();
 *
 * // Token signing & verification (Mastercard-style)
 * const token = hashit.token.sign({ sub: 'user123' }, {
 *   privateKey: keyPair.privateKey,
 *   expiresIn: '15m',
 * });
 *
 * const { valid, payload } = hashit.token.verify(token, {
 *   publicKey: keyPair.publicKey,
 * });
 *
 * // Session management
 * const session = hashit.session.create(keyPair, { sub: 'user123' });
 *
 * // API tokens
 * const apiToken = hashit.apiToken.generate(keyPair, { prefix: 'myapp_' });
 */

import type { Argon2Options, HashItInterface } from './types/index.js';

import { hashPassword, verifyPassword, needsRehash } from './core/password.js';
import { signToken, verifyToken, decodeToken } from './core/token.js';
import {
  generateKeyPair,
  exportPublicKey,
  buildKeySet,
} from './core/keys.js';
import { seal, open } from './core/encrypt.js';
import { createSession, verifySession, rotateSession } from './core/session.js';
import { generateApiToken, verifyApiToken, maskToken } from './core/apiToken.js';
import {
  randomBytes,
  safeEqual,
  parseDuration,
  fingerprint,
} from './utils/helpers.js';

// ── hashit object ─────────────────────────────────────────────────────────────

/**
 * The main hashit interface.
 * All library functionality is accessible through this object.
 */
export const hashit: HashItInterface = {
  // ── Password ────────────────────────────────────────────────────────────────

  password: {
    /**
     * Hash a password using Argon2id (OWASP recommended).
     *
     * @example
     * const { hash } = await hashit.password.hash('my-password');
     */
    hash: async (password: string, options?: Argon2Options) => hashPassword(password, options),

    /**
     * Verify a password against a stored hash.
     * Uses constant-time comparison to prevent timing attacks.
     *
     * @example
     * const { valid, needsRehash } = await hashit.password.verify('my-password', storedHash);
     */
   verify: async (password: string, storedHash: string) => verifyPassword(password, storedHash),

    /**
     * Check if a stored hash needs re-hashing (e.g. parameters upgraded).
     *
     * @example
     * if (hashit.password.needsRehash(storedHash)) {
     *   const { hash } = await hashit.password.hash(plaintext);
     *   await db.updateHash(userId, hash);
     * }
     */
    needsRehash,
  },

  // ── Token ───────────────────────────────────────────────────────────────────

  token: {
    /**
     * Sign a payload with a private key.
     * Produces a compact JWT-compatible token.
     *
     * @example
     * const token = hashit.token.sign({ sub: 'user123', role: 'admin' }, {
     *   privateKey: keyPair.privateKey,
     *   kid: keyPair.kid,
     *   expiresIn: '15m',
     *   issuer: 'my-service',
     * });
     */
    sign: signToken,

    /**
     * Verify and decode a signed token.
     * Validates signature, expiry, issuer, and audience.
     *
     * Supports key rotation: pass a PublicKeySet to verify against
     * multiple keys simultaneously.
     *
     * @example
     * const { valid, payload } = hashit.token.verify(token, {
     *   publicKey: keyPair.publicKey,
     *   issuer: 'my-service',
     * });
     *
     * // With key rotation:
     * const { valid, payload } = hashit.token.verify(token, {
     *   publicKey: keySet, // PublicKeySet with multiple keys
     * });
     */
    verify: verifyToken,

    /**
     * Decode a token WITHOUT verifying its signature.
     * ⚠️ UNSAFE — never use for authentication decisions.
     * Use only for debugging or extracting non-sensitive metadata.
     */
    decode: decodeToken,
  },

  // ── Keys ────────────────────────────────────────────────────────────────────

  keys: {
    /**
     * Generate an asymmetric key pair for token signing.
     * Default: ECDSA P-256 (ES256) — best performance/security balance.
     *
     * @example
     * const keyPair = hashit.keys.generate();
     * const rsaKeyPair = hashit.keys.generate({ algorithm: 'RS256' });
     * const namedKey = hashit.keys.generate({ algorithm: 'ES384', kid: 'key-2024' });
     */
    generate: generateKeyPair,

    /**
     * Export the public key from a key pair as a distributable entry.
     *
     * @example
     * const publicEntry = hashit.keys.exportPublic(keyPair);
     * // Distribute this to services that need to verify tokens
     */
    exportPublic: exportPublicKey,

    /**
     * Build a PublicKeySet for key rotation support.
     * Include the current key AND previous keys to avoid rejecting
     * tokens issued before rotation.
     *
     * @example
     * const keySet = hashit.keys.buildKeySet([
     *   hashit.keys.exportPublic(currentKey),
     *   hashit.keys.exportPublic(previousKey),
     * ]);
     */
    buildKeySet,
  },

  // ── Encrypt ─────────────────────────────────────────────────────────────────

  encrypt: {
    /**
     * Encrypt a string using AES-256-GCM (authenticated encryption).
     * Returns a structured result safe to store or transmit.
     *
     * @example
     * const sealed = hashit.encrypt.seal('sensitive data', 'my-secret-key');
     */
    seal,

    /**
     * Decrypt a previously sealed value.
     * Throws if the key is wrong or data has been tampered with.
     *
     * @example
     * const plaintext = hashit.encrypt.open(sealed, 'my-secret-key');
     */
    open,
  },

  // ── Session ─────────────────────────────────────────────────────────────────

  session: {
    /**
     * Create a session token pair (access + refresh).
     * Access tokens: 15m (default). Refresh tokens: 7d (default).
     *
     * @example
     * const { accessToken, refreshToken } = hashit.session.create(keyPair, {
     *   sub: 'user_123',
     *   issuer: 'my-app',
     *   claims: { role: 'admin' },
     * });
     */
    create: createSession,

    /**
     * Verify a session access token.
     *
     * @example
     * const { valid, payload } = hashit.session.verify(accessToken, keyPair.publicKey);
     */
    verify: verifySession,

    /**
     * Rotate a session using a refresh token.
     * Validates the refresh token and issues a fresh access + refresh pair.
     *
     * @example
     * const newSession = hashit.session.rotate(refreshToken, keyPair, {
     *   sub: 'user_123',
     * });
     */
    rotate: rotateSession,
  },

  // ── API Token ────────────────────────────────────────────────────────────────

  apiToken: {
    /**
     * Generate an opaque API token with embedded cryptographic claims.
     * Similar to GitHub's ghp_ or Stripe's sk_ tokens — but verifiable.
     *
     * @example
     * const { token, masked } = hashit.apiToken.generate(keyPair, {
     *   prefix: 'myapp_',
     *   sub: 'org_123',
     *   expiresIn: '90d',
     *   claims: { scopes: ['read', 'write'] },
     * });
     */
    generate: generateApiToken,

    /**
     * Verify an API token.
     *
     * @example
     * const { valid, payload } = hashit.apiToken.verify('myapp_eyJ...', keyPair.publicKey);
     */
    verify: verifyApiToken,

    /**
     * Mask an API token for safe display in logs/UI.
     *
     * @example
     * hashit.apiToken.mask('hsh_eyJhbGciOiJFUzI1NiJ9.abc123def');
     * // → 'hsh_****ef'
     */
    mask: maskToken,
  },

  // ── Utils ────────────────────────────────────────────────────────────────────

  utils: {
    /**
     * Generate cryptographically secure random bytes as base64url string.
     *
     * @example
     * const secret = hashit.utils.randomBytes(32); // 32 bytes = 256 bits
     */
    randomBytes,

    /**
     * Generate a token fingerprint for binding tokens to devices/sessions.
     *
     * @example
     * const fp = hashit.utils.fingerprint('user-agent:chrome,ip:192.168.1.1');
     */
    fingerprint,

    /**
     * Constant-time string comparison — prevents timing attacks.
     * Use when comparing secrets, tokens, or hashes.
     *
     * @example
     * if (hashit.utils.safeEqual(providedToken, storedToken)) { ... }
     */
    safeEqual,

    /**
     * Parse a duration string to seconds.
     *
     * @example
     * hashit.utils.parseDuration('15m'); // → 900
     * hashit.utils.parseDuration('7d');  // → 604800
     */
    parseDuration,
  },
};
