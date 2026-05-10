/**
 * @notifycode/hash-it
 *
 * Enterprise-grade token and password security library.
 * Mastercard-style public/private key token verification — native JavaScript.
 *
 * @version 1.0.0
 * @author Neza
 * @license MIT
 */

// ── Primary API ───────────────────────────────────────────────────────────────

export { hashit } from './hashit.js';

// ── Named Exports (for tree-shaking) ─────────────────────────────────────────

// Password
export {
  hashPassword,
  verifyPassword,
  needsRehash,
  hashPasswordPbkdf2,
} from './core/password.js';

// Token
export { signToken, verifyToken, decodeToken } from './core/token.js';

// Keys
export { generateKeyPair, exportPublicKey, buildKeySet, findKeyInSet } from './core/keys.js';

// Encryption
export { seal, open } from './core/encrypt.js';

// Session
export { createSession, verifySession, rotateSession } from './core/session.js';

// API Tokens
export { generateApiToken, verifyApiToken, maskToken } from './core/apiToken.js';

// Utilities
export { randomBytes, safeEqual, parseDuration, fingerprint, generateJti } from './utils/helpers.js';

// Errors
export {
  HashItError,
  InvalidKeyError,
  InvalidTokenError,
  TokenExpiredError,
  TokenNotYetValidError,
  SignatureInvalidError,
  AlgorithmMismatchError,
  KeyNotFoundError,
  AudienceMismatchError,
  IssuerMismatchError,
} from './utils/errors.js';

// Types
export type {
  // Core
  PasswordAlgorithm,
  SignatureAlgorithm,
  EncryptionAlgorithm,
  TokenType,

  // Password
  Argon2Options,
  Pbkdf2Options,
  HashResult,
  VerifyResult,

  // Keys
  KeyPair,
  KeyGenOptions,
  PublicKeySet,
  PublicKeyEntry,

  // Token
  TokenClaims,
  SignTokenOptions,
  VerifyTokenOptions,
  TokenVerifyResult,

  // Encryption
  EncryptOptions,
  EncryptResult,

  // Session
  SessionOptions,
  SessionTokenPair,

  // API Token
  ApiToken,
  ApiTokenOptions,

  // Fingerprint
  TokenFingerprint,

  // Interface
  HashItInterface,
} from './types/index.js';

export { HashItErrorCode } from './types/index.js';
