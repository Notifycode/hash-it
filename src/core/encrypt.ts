/**
 * Symmetric Encryption Module
 *
 * Implements AES-256-GCM (default), AES-256-CBC, and ChaCha20-Poly1305
 * using Node.js native crypto — zero external dependencies.
 *
 * AES-256-GCM is the recommended default:
 * - Authenticated encryption (AEAD) — detects tampering
 * - 128-bit authentication tag
 * - NIST-approved
 * - Hardware acceleration on modern CPUs
 */

import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  pbkdf2Sync,
  createHmac,
} from 'crypto';
import type { EncryptOptions, EncryptResult, EncryptionAlgorithm } from '../types/index.js';
import { HashItErrorCode } from '../types/index.js';
import { HashItError } from '../utils/errors.js';

// ── Constants ─────────────────────────────────────────────────────────────────

const IV_SIZES: Record<EncryptionAlgorithm, number> = {
  'aes-256-gcm': 12,        // 96-bit IV for GCM (NIST recommended)
  'aes-256-cbc': 16,        // 128-bit IV for CBC
  'chacha20-poly1305': 12,  // 96-bit nonce for ChaCha20
};

const KEY_SIZE = 32; // 256-bit for AES-256
const PBKDF2_ITERATIONS = 100_000;
const SALT_MARKER = 'hashit-enc-v1';

// ── Key Derivation ────────────────────────────────────────────────────────────

/**
 * Derive a 256-bit key from a password using PBKDF2-SHA512.
 * Uses a fixed application-specific salt component plus the iv for uniqueness.
 */
function deriveKey(password: string, salt: Buffer): Buffer {
  if (password.length < 8) {
    throw new HashItError(
      'Encryption key must be at least 8 characters',
      HashItErrorCode.INVALID_KEY
    );
  }

  return pbkdf2Sync(
    password,
    Buffer.concat([Buffer.from(SALT_MARKER, 'utf8'), salt]),
    PBKDF2_ITERATIONS,
    KEY_SIZE,
    'sha512'
  );
}

// ── Seal (Encrypt) ────────────────────────────────────────────────────────────

/**
 * Encrypt plaintext using AES-256-GCM (default) or specified algorithm.
 *
 * Returns structured result with ciphertext, IV, and authentication tag.
 * The returned object is safe to store or transmit.
 *
 * @example
 * const sealed = seal('sensitive-data', 'my-secret-key');
 * // { ciphertext: '...', iv: '...', tag: '...', algorithm: 'aes-256-gcm' }
 */
export function seal(
  plaintext: string,
  key: string,
  options?: EncryptOptions
): EncryptResult {
  const algorithm: EncryptionAlgorithm = options?.algorithm ?? 'aes-256-gcm';

  const ivSize = IV_SIZES[algorithm];
  if (ivSize === undefined) {
    throw new HashItError(`Unsupported encryption algorithm: ${algorithm}`, HashItErrorCode.ENCRYPT_FAILED);
  }

  const iv = randomBytes(ivSize);
  const derivedKey = deriveKey(key, iv);

  try {
    if (algorithm === 'aes-256-gcm') {
      return sealGcm(plaintext, derivedKey, iv, options?.aad);
    }

    if (algorithm === 'chacha20-poly1305') {
      return sealChaCha(plaintext, derivedKey, iv, options?.aad);
    }

    // AES-256-CBC (no AEAD — add HMAC for integrity)
    return sealCbc(plaintext, derivedKey, iv, key);
  } catch (err) {
    if (err instanceof HashItError) throw err;
    throw new HashItError(
      `Encryption failed: ${err instanceof Error ? err.message : 'unknown'}`,
      HashItErrorCode.ENCRYPT_FAILED
    );
  }
}

function sealGcm(plaintext: string, key: Buffer, iv: Buffer, aad?: string): EncryptResult {
  const cipher = createCipheriv('aes-256-gcm', key, iv) as ReturnType<typeof createCipheriv> & {
    getAuthTag(): Buffer;
    setAAD(aad: Buffer): void;
  };

  if (aad) {
    (cipher as any).setAAD(Buffer.from(aad, 'utf8'));
  }

  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);

  const tag = (cipher as any).getAuthTag() as Buffer;

  return {
    ciphertext: encrypted.toString('base64url'),
    iv: iv.toString('base64url'),
    tag: tag.toString('base64url'),
    algorithm: 'aes-256-gcm',
  };
}

function sealChaCha(plaintext: string, key: Buffer, iv: Buffer, aad?: string): EncryptResult {
  const cipher = createCipheriv('chacha20-poly1305', key, iv, {
    authTagLength: 16,
  }) as any;

  if (aad) {
    cipher.setAAD(Buffer.from(aad, 'utf8'));
  }

  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag() as Buffer;

  return {
    ciphertext: encrypted.toString('base64url'),
    iv: iv.toString('base64url'),
    tag: tag.toString('base64url'),
    algorithm: 'chacha20-poly1305',
  };
}

function sealCbc(plaintext: string, key: Buffer, iv: Buffer, originalKey: string): EncryptResult {
  const cipher = createCipheriv('aes-256-cbc', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);

  // HMAC-SHA256 for integrity (Encrypt-then-MAC)
  const mac = createHmac('sha256', originalKey)
    .update(Buffer.concat([iv, encrypted]))
    .digest('base64url');

  return {
    ciphertext: `${encrypted.toString('base64url')}.${mac}`,
    iv: iv.toString('base64url'),
    algorithm: 'aes-256-cbc',
  };
}

// ── Open (Decrypt) ────────────────────────────────────────────────────────────

/**
 * Decrypt a previously sealed value.
 *
 * @example
 * const plaintext = open(sealed, 'my-secret-key');
 * // 'sensitive-data'
 */
export function open(encrypted: EncryptResult, key: string): string {
  const { ciphertext, iv: ivB64, tag: tagB64, algorithm } = encrypted;

  const iv = Buffer.from(ivB64, 'base64url');
  const derivedKey = deriveKey(key, iv);

  try {
    if (algorithm === 'aes-256-gcm') {
      return openGcm(ciphertext, derivedKey, iv, tagB64);
    }

    if (algorithm === 'chacha20-poly1305') {
      return openChaCha(ciphertext, derivedKey, iv, tagB64);
    }

    return openCbc(ciphertext, derivedKey, iv, key);
  } catch (err) {
    if (err instanceof HashItError) throw err;
    throw new HashItError(
      'Decryption failed — invalid key or tampered ciphertext',
      HashItErrorCode.DECRYPT_FAILED
    );
  }
}

function openGcm(ciphertext: string, key: Buffer, iv: Buffer, tagB64?: string): string {
  if (!tagB64) {
    throw new HashItError('GCM authentication tag is required', HashItErrorCode.DECRYPT_FAILED);
  }

  const decipher = createDecipheriv('aes-256-gcm', key, iv) as any;
  decipher.setAuthTag(Buffer.from(tagB64, 'base64url'));

  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(ciphertext, 'base64url')),
    decipher.final(),
  ]);

  return decrypted.toString('utf8');
}

function openChaCha(ciphertext: string, key: Buffer, iv: Buffer, tagB64?: string): string {
  if (!tagB64) {
    throw new HashItError('ChaCha20-Poly1305 auth tag is required', HashItErrorCode.DECRYPT_FAILED);
  }

  const decipher = createDecipheriv('chacha20-poly1305', key, iv, {
    authTagLength: 16,
  }) as any;

  decipher.setAuthTag(Buffer.from(tagB64, 'base64url'));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(ciphertext, 'base64url')),
    decipher.final(),
  ]);

  return decrypted.toString('utf8');
}

function openCbc(ciphertext: string, key: Buffer, iv: Buffer, originalKey: string): string {
  const [ciphertextB64, macB64] = ciphertext.split('.');
  if (!ciphertextB64 || !macB64) {
    throw new HashItError('Invalid CBC ciphertext format', HashItErrorCode.DECRYPT_FAILED);
  }

  const ciphertextBuf = Buffer.from(ciphertextB64, 'base64url');

  // Verify HMAC before decrypting (Encrypt-then-MAC)
  const expectedMac = createHmac('sha256', originalKey)
    .update(Buffer.concat([iv, ciphertextBuf]))
    .digest('base64url');

  if (expectedMac !== macB64) {
    throw new HashItError('CBC integrity check failed — data may be tampered', HashItErrorCode.DECRYPT_FAILED);
  }

  const decipher = createDecipheriv('aes-256-cbc', key, iv);
  const decrypted = Buffer.concat([decipher.update(ciphertextBuf), decipher.final()]);

  return decrypted.toString('utf8');
}
