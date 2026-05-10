/**
 * Key Management Module
 *
 * Implements RSA-4096 and ECDSA P-256/P-384/P-521 key pair generation
 * using Node.js native crypto — zero external dependencies.
 *
 * Architecture mirrors Mastercard's token service:
 * - Each issuer holds a private key (signing authority)
 * - Public keys are distributed for verification
 * - Keys have IDs (kid) for rotation without breaking existing tokens
 */

import { generateKeyPairSync } from 'crypto';
import type {
  KeyPair,
  KeyGenOptions,
  PublicKeyEntry,
  PublicKeySet,
  SignatureAlgorithm,
} from '../types/index.js';
import { randomBytes } from '../utils/helpers.js';
import { InvalidKeyError } from '../utils/errors.js';

// ── Algorithm Mappings ────────────────────────────────────────────────────────

type CurveMap = Record<string, string>;
type HashMap = Record<string, string>;

const EC_CURVES: CurveMap = {
  ES256: 'prime256v1', // NIST P-256
  ES384: 'secp384r1', // NIST P-384
  ES512: 'secp521r1', // NIST P-521
};

const RSA_HASH: HashMap = {
  RS256: 'SHA-256',
  RS512: 'SHA-512',
  PS256: 'SHA-256',
};

// ── Key Generation ────────────────────────────────────────────────────────────

/**
 * Generate an asymmetric key pair for token signing.
 *
 * Defaults to ECDSA P-256 (ES256) — best balance of security and performance.
 * For maximum compatibility with legacy systems, use RS256 (RSA-4096).
 *
 * @example
 * // Generate an ECDSA P-256 key pair (recommended)
 * const keyPair = generateKeyPair();
 *
 * // Generate an RSA-4096 key pair (legacy compatibility)
 * const keyPair = generateKeyPair({ algorithm: 'RS256' });
 *
 * // Generate with a custom key ID
 * const keyPair = generateKeyPair({ algorithm: 'ES256', kid: 'my-key-2024' });
 */
export function generateKeyPair(options?: KeyGenOptions): KeyPair {
  const algorithm: SignatureAlgorithm = options?.algorithm ?? 'ES256';
  const kid = options?.kid ?? randomBytes(16);
  const createdAt = new Date().toISOString();

  if (algorithm in EC_CURVES) {
    return generateEcKeyPair(algorithm, kid, createdAt);
  }

  if (algorithm in RSA_HASH) {
    return generateRsaKeyPair(algorithm, kid, createdAt);
  }

  throw new InvalidKeyError(`Unsupported algorithm: ${algorithm}`, {
    supported: [...Object.keys(EC_CURVES), ...Object.keys(RSA_HASH)],
  });
}

function generateEcKeyPair(
  algorithm: SignatureAlgorithm,
  kid: string,
  createdAt: string
): KeyPair {
  const curve = EC_CURVES[algorithm];
  if (!curve) throw new InvalidKeyError(`Unknown EC algorithm: ${algorithm}`);

  const { privateKey, publicKey } = generateKeyPairSync('ec', {
    namedCurve: curve,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });

  return { privateKey, publicKey, algorithm, kid, createdAt };
}

function generateRsaKeyPair(
  algorithm: SignatureAlgorithm,
  kid: string,
  createdAt: string
): KeyPair {
  // RSA-4096 as per project requirements
  const modulusLength = 4096;

  const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength,
    publicExponent: 0x10001, // 65537 — standard
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });

  return { privateKey, publicKey, algorithm, kid, createdAt };
}

// ── Key Set (Rotation Support) ────────────────────────────────────────────────

/**
 * Export a key pair's public key as a PublicKeySet entry.
 * Distribute this to verification services.
 */
export function exportPublicKey(keyPair: KeyPair): PublicKeyEntry {
  return {
    kid: keyPair.kid,
    algorithm: keyPair.algorithm,
    publicKey: keyPair.publicKey,
    createdAt: keyPair.createdAt,
  };
}

/**
 * Build a PublicKeySet from multiple public key entries.
 * This is used for key rotation — verifiers hold multiple keys and
 * select the correct one by kid from the token header.
 *
 * @example
 * const keySet = buildKeySet([
 *   exportPublicKey(currentKeyPair),
 *   exportPublicKey(previousKeyPair), // kept for tokens issued before rotation
 * ]);
 */
export function buildKeySet(keys: PublicKeyEntry[]): PublicKeySet {
  if (!keys.length) {
    throw new InvalidKeyError('Key set must contain at least one key');
  }
  return { keys };
}

/**
 * Find a public key in a key set by kid.
 * Used during token verification when multiple keys are in rotation.
 */
export function findKeyInSet(keySet: PublicKeySet, kid: string): PublicKeyEntry | null {
  return keySet.keys.find((k) => k.kid === kid) ?? null;
}
