import {
  randomBytes as nodeRandomBytes,
  timingSafeEqual,
  createHmac,
} from 'crypto';
import type { TokenFingerprint } from '../types/index.js';
import { InvalidKeyError } from './errors.js';

/**
 * Generate cryptographically secure random bytes encoded as base64url.
 */
export function randomBytes(length = 32): string {
  if (length < 8) {
    throw new InvalidKeyError('Random bytes length must be at least 8');
  }
  return nodeRandomBytes(length).toString('base64url');
}

/**
 * Constant-time string comparison to prevent timing attacks.
 * Returns true only if both strings are identical.
 */
export function safeEqual(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');

  // Pad to same length to avoid length leak while still using timingSafeEqual
  if (bufA.length !== bufB.length) {
    // Still do the comparison to prevent short-circuit timing difference
    const maxLen = Math.max(bufA.length, bufB.length);
    const paddedA = Buffer.alloc(maxLen);
    const paddedB = Buffer.alloc(maxLen);
    bufA.copy(paddedA);
    bufB.copy(paddedB);
    timingSafeEqual(paddedA, paddedB); // run to maintain timing
    return false;
  }

  return timingSafeEqual(bufA, bufB);
}

/**
 * Duration string parser.
 * Supports: s (seconds), m (minutes), h (hours), d (days), w (weeks)
 * Examples: '15m' → 900, '7d' → 604800, '1h' → 3600
 */
export function parseDuration(duration: string | number): number {
  if (typeof duration === 'number') return duration;

  const match = duration.match(/^(\d+(?:\.\d+)?)(s|m|h|d|w)$/);
  if (!match) {
    throw new InvalidKeyError(
      `Invalid duration format: "${duration}". Use: 30s, 15m, 1h, 7d, 2w`
    );
  }

  const value = parseFloat(match[1] as string);
  const unit = match[2];

  const multipliers: Record<string, number> = {
    s: 1,
    m: 60,
    h: 3600,
    d: 86400,
    w: 604800,
  };

  return Math.floor(value * (multipliers[unit as string] ?? 1));
}

/**
 * Generate a cryptographic fingerprint for token binding.
 * Used to bind tokens to specific devices/sessions (Mastercard-style).
 */
export function fingerprint(
  data: string,
  algorithm: 'sha256' | 'sha512' = 'sha256'
): TokenFingerprint {
  const secret = nodeRandomBytes(32);
  const hmac = createHmac(algorithm, secret);
  hmac.update(data);

  return {
    fingerprint: hmac.digest('base64url'),
    algorithm,
    createdAt: Math.floor(Date.now() / 1000),
  };
}

/**
 * Get current Unix timestamp in seconds.
 */
export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/**
 * Base64url encode (URL-safe, no padding).
 */
export function base64urlEncode(input: Buffer | string): string {
  const buf = typeof input === 'string' ? Buffer.from(input, 'utf8') : input;
  return buf.toString('base64url');
}

/**
 * Base64url decode.
 */
export function base64urlDecode(input: string): Buffer {
  return Buffer.from(input, 'base64url');
}

/**
 * Generate a unique token ID (JTI).
 */
export function generateJti(): string {
  return randomBytes(24);
}

/**
 * Validate a PEM key string.
 */
export function isPemKey(key: string): boolean {
  return (
    typeof key === 'string' &&
    (key.includes('-----BEGIN') || key.includes('-----END'))
  );
}
