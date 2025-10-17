import CryptoJS from 'crypto-js';
import type { TokenCryptoParams } from './types';

const SALT = 'token-crypto-lib';
const KEY_SIZE = 256 / 32; // AES-256 = 32 bytes
const ITERATIONS = 100_000;

/**
 * Derives a key using PBKDF2 (sync and cossmpatible)
 */
function deriveKey(key: string): CryptoJS.lib.WordArray {
  if (key.length < 6) {
    throw new Error('Key must be at least 6 characters long');
  }

  return CryptoJS.PBKDF2(key, SALT, {
    keySize: KEY_SIZE,
    iterations: ITERATIONS,
    hasher: CryptoJS.algo.SHA256,
  });
}

/**
 * Encrypts a token using AES with a derived key
 */
export function hashToken({ token, key }: TokenCryptoParams): string {
  const derivedKey = deriveKey(key);
  const iv = CryptoJS.lib.WordArray.random(16); // 128-bit IV

  const encrypted = CryptoJS.AES.encrypt(token, derivedKey, {
    iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
  });

  return `${CryptoJS.enc.Base64.stringify(iv)}:${encrypted.ciphertext.toString(CryptoJS.enc.Base64)}`;
}

/**
 * Decrypts an encrypted token using the same derived key
 */
export function decodeHashedToken({ token, key }: TokenCryptoParams): string {
  const [ivBase64, encryptedBase64] = token.split(':');

  if (!ivBase64 || !encryptedBase64) {
    throw new Error('Invalid token format. Expected IV:EncryptedToken');
  }

  const iv = CryptoJS.enc.Base64.parse(ivBase64);
  const ciphertext = CryptoJS.enc.Base64.parse(encryptedBase64);
  const derivedKey = deriveKey(key);

  const decrypted = CryptoJS.AES.decrypt(
    {
      ciphertext,
    } as any,
    derivedKey,
    {
      iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    }
  );

  return decrypted.toString(CryptoJS.enc.Utf8);
}
