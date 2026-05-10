// ─────────────────────────────────────────────────────────────────────────────
// @notifycode/hash-it — Type Definitions
// Enterprise-grade token and password security library
// ─────────────────────────────────────────────────────────────────────────────

// ── Core ─────────────────────────────────────────────────────────────────────

/**
 * Supported hashing algorithms for password hashing.
 * Argon2id is required by OWASP for new systems.
 */
export type PasswordAlgorithm = 'argon2id' | 'pbkdf2' | 'bcrypt';

/**
 * Supported signature algorithms for token signing.
 * ECDSA P-256 is preferred for performance; RSA-4096 for legacy compatibility.
 */
export type SignatureAlgorithm = 'ES256' | 'ES384' | 'ES512' | 'RS256' | 'RS512' | 'PS256';

/**
 * Supported symmetric encryption algorithms.
 */
export type EncryptionAlgorithm = 'aes-256-gcm' | 'aes-256-cbc' | 'chacha20-poly1305';

/**
 * Token types supported by the library.
 */
export type TokenType = 'access' | 'refresh' | 'session' | 'api' | 'custom';

// ── Password Hashing ──────────────────────────────────────────────────────────

/**
 * Options for Argon2id password hashing.
 */
export interface Argon2Options {
  /** Memory cost in KiB (default: 65536 = 64MB — OWASP recommended) */
  memoryCost?: number;
  /** Time cost / iterations (default: 3) */
  timeCost?: number;
  /** Parallelism / threads (default: 4) */
  parallelism?: number;
  /** Output hash length in bytes (default: 32) */
  hashLength?: number;
  /** Salt length in bytes (default: 16 — minimum required) */
  saltLength?: number;
}

/**
 * Options for PBKDF2 password hashing.
 */
export interface Pbkdf2Options {
  /** Number of iterations (default: 600000 — OWASP 2023 recommendation) */
  iterations?: number;
  /** Key length in bytes (default: 32) */
  keyLength?: number;
  /** HMAC digest algorithm (default: sha512) */
  digest?: 'sha256' | 'sha384' | 'sha512';
  /** Salt length in bytes (default: 16) */
  saltLength?: number;
}

/**
 * Result of a password hash operation.
 */
export interface HashResult {
  /** The encoded hash string (algorithm-specific format) */
  hash: string;
  /** Algorithm used */
  algorithm: PasswordAlgorithm;
  /** Base64-encoded salt used */
  salt: string;
  /** Milliseconds taken to hash */
  timingMs: number;
}

/**
 * Result of a password verification operation.
 */
export interface VerifyResult {
  /** Whether the password matches */
  valid: boolean;
  /** Whether the hash needs re-hashing (e.g. parameters upgraded) */
  needsRehash: boolean;
  /** Milliseconds taken to verify */
  timingMs: number;
}

// ── Key Management ────────────────────────────────────────────────────────────

/**
 * An asymmetric key pair.
 */
export interface KeyPair {
  /** PEM-encoded private key */
  privateKey: string;
  /** PEM-encoded public key */
  publicKey: string;
  /** Signature algorithm this key pair is for */
  algorithm: SignatureAlgorithm;
  /** Key ID — used for rotation/identification */
  kid: string;
  /** ISO timestamp of key creation */
  createdAt: string;
}

/**
 * Options for key pair generation.
 */
export interface KeyGenOptions {
  /** Signature algorithm (default: ES256) */
  algorithm?: SignatureAlgorithm;
  /** Custom key ID (default: auto-generated) */
  kid?: string;
}

/**
 * A key set containing multiple public keys for verification (JWKS-style).
 */
export interface PublicKeySet {
  keys: PublicKeyEntry[];
}

export interface PublicKeyEntry {
  kid: string;
  algorithm: SignatureAlgorithm;
  publicKey: string;
  createdAt: string;
}

// ── Token Creation & Verification ─────────────────────────────────────────────

/**
 * Standard token claims (JWT-compatible).
 */
export interface TokenClaims {
  /** Subject — typically a user ID */
  sub?: string;
  /** Issuer */
  iss?: string;
  /** Audience */
  aud?: string | string[];
  /** JWT ID — unique per token */
  jti?: string;
  /** Issued at (Unix timestamp) */
  iat?: number;
  /** Not before (Unix timestamp) */
  nbf?: number;
  /** Expiry (Unix timestamp) */
  exp?: number;
  /** Token type */
  type?: TokenType;
  /** Additional custom claims */
  [key: string]: unknown;
}

/**
 * Options for creating a signed token.
 */
export interface SignTokenOptions {
  /** The private key PEM string to sign with */
  privateKey: string;
  /** Key ID for header */
  kid?: string;
  /** Signature algorithm (default: ES256) */
  algorithm?: SignatureAlgorithm;
  /** Expiry as seconds from now, or ISO duration string e.g. '1h', '7d', '30m' */
  expiresIn?: number | string;
  /** Issuer claim */
  issuer?: string;
  /** Audience claim */
  audience?: string | string[];
  /** Additional custom claims */
  claims?: Record<string, unknown>;
}

/**
 * Options for verifying a signed token.
 */
export interface VerifyTokenOptions {
  /** Public key PEM or a PublicKeySet for multi-key rotation support */
  publicKey: string | PublicKeySet;
  /** Expected issuer — verification fails if mismatch */
  issuer?: string;
  /** Expected audience — verification fails if mismatch */
  audience?: string | string[];
  /** Allowed algorithms (default: all supported) */
  algorithms?: SignatureAlgorithm[];
  /** Clock skew tolerance in seconds (default: 30) */
  clockSkew?: number;
}

/**
 * Result of a token verification operation.
 */
export interface TokenVerifyResult {
  /** Whether the token signature and claims are valid */
  valid: boolean;
  /** Decoded token payload (only if valid) */
  payload?: TokenClaims;
  /** Error message if invalid */
  error?: string;
  /** Key ID used */
  kid?: string;
  /** Algorithm used */
  algorithm?: SignatureAlgorithm;
}

// ── Symmetric Encryption ──────────────────────────────────────────────────────

/**
 * Options for symmetric token encryption.
 */
export interface EncryptOptions {
  /** Encryption algorithm (default: aes-256-gcm) */
  algorithm?: EncryptionAlgorithm;
  /** Additional authenticated data for AEAD modes */
  aad?: string;
}

/**
 * Result of an encryption operation.
 */
export interface EncryptResult {
  /** The encrypted ciphertext (base64) */
  ciphertext: string;
  /** Initialization vector (base64) */
  iv: string;
  /** Authentication tag for AEAD modes (base64) */
  tag?: string;
  /** Algorithm used */
  algorithm: EncryptionAlgorithm;
}

// ── Session Management ────────────────────────────────────────────────────────

/**
 * A complete session token pair (access + refresh).
 */
export interface SessionTokenPair {
  /** Short-lived access token */
  accessToken: string;
  /** Long-lived refresh token */
  refreshToken: string;
  /** Access token expiry (Unix timestamp) */
  accessExpiresAt: number;
  /** Refresh token expiry (Unix timestamp) */
  refreshExpiresAt: number;
  /** Token type (always 'Bearer') */
  tokenType: 'Bearer';
}

/**
 * Options for creating a session token pair.
 */
export interface SessionOptions {
  /** Subject (user ID) */
  sub: string;
  /** Issuer */
  issuer?: string;
  /** Access token lifetime (default: '15m') */
  accessExpiresIn?: string | number;
  /** Refresh token lifetime (default: '7d') */
  refreshExpiresIn?: string | number;
  /** Additional claims */
  claims?: Record<string, unknown>;
}

// ── API Token ─────────────────────────────────────────────────────────────────

/**
 * An opaque API token with embedded claims.
 */
export interface ApiToken {
  /** The full opaque token string */
  token: string;
  /** Token prefix for identification (e.g. 'hsh_') */
  prefix: string;
  /** Masked token for display (e.g. 'hsh_****abc1') */
  masked: string;
  /** When this token expires */
  expiresAt: number | null;
}

/**
 * Options for generating an API token.
 */
export interface ApiTokenOptions {
  /** Prefix for the token (default: 'hsh_') */
  prefix?: string;
  /** Custom claims to embed */
  claims?: Record<string, unknown>;
  /** Expiry e.g. '90d', 3600 (seconds), or null for never */
  expiresIn?: string | number | null;
  /** Subject (user/org ID) */
  sub?: string;
}

// ── Fingerprinting ────────────────────────────────────────────────────────────

/**
 * A token fingerprint for binding tokens to devices/sessions.
 */
export interface TokenFingerprint {
  /** The fingerprint hash */
  fingerprint: string;
  /** Algorithm used */
  algorithm: 'sha256' | 'sha512';
  /** Timestamp of creation */
  createdAt: number;
}

// ── Errors ────────────────────────────────────────────────────────────────────

/**
 * Error codes for structured error handling.
 */
export enum HashItErrorCode {
  INVALID_KEY = 'INVALID_KEY',
  INVALID_TOKEN = 'INVALID_TOKEN',
  TOKEN_EXPIRED = 'TOKEN_EXPIRED',
  TOKEN_NOT_YET_VALID = 'TOKEN_NOT_YET_VALID',
  SIGNATURE_INVALID = 'SIGNATURE_INVALID',
  ALGORITHM_MISMATCH = 'ALGORITHM_MISMATCH',
  KEY_NOT_FOUND = 'KEY_NOT_FOUND',
  AUDIENCE_MISMATCH = 'AUDIENCE_MISMATCH',
  ISSUER_MISMATCH = 'ISSUER_MISMATCH',
  ENCRYPT_FAILED = 'ENCRYPT_FAILED',
  DECRYPT_FAILED = 'DECRYPT_FAILED',
  HASH_FAILED = 'HASH_FAILED',
  VERIFY_FAILED = 'VERIFY_FAILED',
  INVALID_PARAMS = 'INVALID_PARAMS',
}

// ── hashit Interface ──────────────────────────────────────────────────────────

/**
 * The main hashit interface — clean, ergonomic API for all operations.
 */
export interface HashItInterface {
  /** Password operations */
  password: {
    /** Hash a password using Argon2id */
    hash(password: string, options?: Argon2Options): Promise<HashResult>;
    /** Verify a password against a hash */
    verify(password: string, hash: string): Promise<VerifyResult>;
    /** Check if a hash needs rehashing (e.g. parameters changed) */
    needsRehash(hash: string, options?: Argon2Options): boolean;
  };
  /** Token signing & verification (Mastercard-style asymmetric) */
  token: {
    /** Sign a payload with a private key */
    sign(payload: TokenClaims, options: SignTokenOptions): string;
    /** Verify and decode a signed token */
    verify(token: string, options: VerifyTokenOptions): TokenVerifyResult;
    /** Decode without verifying (unsafe — never use for auth) */
    decode(token: string): TokenClaims | null;
  };
  /** Key pair management */
  keys: {
    /** Generate a new asymmetric key pair */
    generate(options?: KeyGenOptions): KeyPair;
    /** Export public key as a PublicKeySet entry */
    exportPublic(keyPair: KeyPair): PublicKeyEntry;
    /** Build a multi-key PublicKeySet for rotation */
    buildKeySet(keys: PublicKeyEntry[]): PublicKeySet;
  };
  /** Symmetric encryption */
  encrypt: {
    /** Encrypt a string */
    seal(plaintext: string, key: string, options?: EncryptOptions): EncryptResult;
    /** Decrypt a string */
    open(encrypted: EncryptResult, key: string): string;
  };
  /** Session management */
  session: {
    /** Create a session token pair (access + refresh) */
    create(keyPair: KeyPair, options: SessionOptions): SessionTokenPair;
    /** Verify an access token */
    verify(token: string, publicKey: string | PublicKeySet): TokenVerifyResult;
    /** Rotate a session using a refresh token */
    rotate(refreshToken: string, keyPair: KeyPair, options: SessionOptions): SessionTokenPair;
  };
  /** API token management */
  apiToken: {
    /** Generate an opaque API token */
    generate(keyPair: KeyPair, options?: ApiTokenOptions): ApiToken;
    /** Verify an API token */
    verify(token: string, publicKey: string | PublicKeySet): TokenVerifyResult;
    /** Mask a token for display */
    mask(token: string): string;
  };
  /** Utilities */
  utils: {
    /** Generate cryptographically secure random bytes (base64) */
    randomBytes(length?: number): string;
    /** Generate a fingerprint for token binding */
    fingerprint(data: string, algorithm?: 'sha256' | 'sha512'): TokenFingerprint;
    /** Constant-time string comparison (prevents timing attacks) */
    safeEqual(a: string, b: string): boolean;
    /** Parse duration string to seconds ('1h' → 3600) */
    parseDuration(duration: string): number;
  };
}
