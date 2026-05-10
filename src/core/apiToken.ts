/**
 * API Token Module
 *
 * Generates and verifies opaque API tokens — similar to GitHub's ghp_ tokens
 * or Stripe's sk_ tokens — but with embedded cryptographic signatures.
 *
 * Format: <prefix>_<signed-payload-base64url>
 * Example: hsh_eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature
 *
 * The token looks opaque to end-users but contains a verifiable JWT inside.
 */

import type {
  KeyPair,
  ApiToken,
  ApiTokenOptions,
  TokenVerifyResult,
  PublicKeySet,
} from '../types/index.js';
import { signToken, verifyToken } from './token.js';
import { parseDuration, nowSeconds } from '../utils/helpers.js';

const DEFAULT_PREFIX = 'hsh_';

/**
 * Generate an opaque API token with embedded cryptographic claims.
 *
 * @example
 * const apiToken = generateApiToken(keyPair, {
 *   prefix: 'myapp_',
 *   sub: 'org_123',
 *   expiresIn: '90d',
 *   claims: { scopes: ['read', 'write'] },
 * });
 *
 * console.log(apiToken.token);  // myapp_eyJhbGci...
 * console.log(apiToken.masked); // myapp_****abc1
 */
export function generateApiToken(keyPair: KeyPair, options?: ApiTokenOptions): ApiToken {
  const {
    prefix = DEFAULT_PREFIX,
    claims = {},
    expiresIn = null,
    sub,
  } = options ?? {};

  const now = nowSeconds();
  const expiresAt = expiresIn != null ? now + parseDuration(expiresIn) : null;

  const payload = {
    ...claims,
    ...(sub ? { sub } : {}),
    type: 'api' as const,
  };

  const jwt = signToken(payload, {
    privateKey: keyPair.privateKey,
    kid: keyPair.kid,
    algorithm: keyPair.algorithm,
    ...(expiresIn != null ? { expiresIn } : {}),
  });

  const token = `${prefix}${jwt}`;

  return {
    token,
    prefix,
    masked: maskToken(token, prefix),
    expiresAt,
  };
}

/**
 * Verify an API token.
 *
 * @example
 * const result = verifyApiToken('hsh_eyJ...', keyPair.publicKey);
 * if (result.valid) {
 *   console.log(result.payload?.scopes);
 * }
 */
export function verifyApiToken(
  token: string,
  publicKey: string | PublicKeySet
): TokenVerifyResult {
  // Strip the prefix to get the underlying JWT
  const jwtPart = stripPrefix(token);
  return verifyToken(jwtPart, { publicKey });
}

/**
 * Mask an API token for safe display.
 * Preserves the prefix and shows last 4 characters.
 *
 * @example
 * maskToken('hsh_eyJhbGciOiJFUzI1NiJ9.abc123');
 * // → 'hsh_****3123'
 */
export function maskToken(token: string, prefix?: string): string {
  const pfx = prefix ?? detectPrefix(token);
  const body = token.slice(pfx.length);
  const lastFour = body.slice(-4);
  return `${pfx}****${lastFour}`;
}

function detectPrefix(token: string): string {
  const underscoreIdx = token.indexOf('_');
  if (underscoreIdx > 0 && underscoreIdx <= 8) {
    return token.slice(0, underscoreIdx + 1);
  }
  return '';
}

function stripPrefix(token: string): string {
  const underscoreIdx = token.indexOf('_');
  if (underscoreIdx > 0 && underscoreIdx <= 8) {
    return token.slice(underscoreIdx + 1);
  }
  return token;
}
