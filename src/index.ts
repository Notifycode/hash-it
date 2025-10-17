import { createCipheriv, createDecipheriv, randomBytes, pbkdf2Sync } from 'crypto';
import type { TokenCryptoParams } from './types';

const ALGORITHM = 'aes-256-cbc';
const IV_LENGTH = 16;
const SALT = 'token-crypto-lib';
const KEY_LENGTH = 32; // AES-256 = 32 bytes

function deriveKey(key: string): Buffer {
  if (key.length < 6) {
    throw new Error('Key must be at least 6 characters long');
  }

  return pbkdf2Sync(key, SALT, 100_000, KEY_LENGTH, 'sha256');
}

/**
 * Encrypts a token using a flexible-length key (min 6 chars)
 */
export function hashToken({ token, key }: TokenCryptoParams): string {
  const derivedKey = deriveKey(key);
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, derivedKey, iv);

  const encrypted = Buffer.concat([cipher.update(token, 'utf8'), cipher.final()]);

  return `${iv.toString('base64')}:${encrypted.toString('base64')}`;
}

/**
 * Decrypts a token using the same flexible-length key
 */
export function decodeHashedToken({ token, key }: TokenCryptoParams): string {
  const [ivBase64, encryptedBase64] = token.split(':');
  if (!ivBase64 || !encryptedBase64) {
    throw new Error('Invalid token format. Expected IV:EncryptedToken');
  }

  const iv = Buffer.from(ivBase64, 'base64');
  const encrypted = Buffer.from(encryptedBase64, 'base64');
  const derivedKey = deriveKey(key);

  const decipher = createDecipheriv(ALGORITHM, derivedKey, iv);
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);

  return decrypted.toString('utf8');
}
