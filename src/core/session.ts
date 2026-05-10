/**
 * Session Management Module
 *
 * Implements access + refresh token patterns using asymmetric signatures.
 * Mirrors enterprise session architectures (Auth0, Okta, etc.) but
 * natively in JavaScript with no external dependencies.
 */

import type {
  KeyPair,
  SessionOptions,
  SessionTokenPair,
  VerifyTokenOptions,
  TokenVerifyResult,
  PublicKeySet,
} from '../types/index.js';
import { signToken, verifyToken } from './token.js';
import { parseDuration, nowSeconds } from '../utils/helpers.js';
import { HashItError } from '../utils/errors.js';
import { HashItErrorCode } from '../types/index.js';

const DEFAULT_ACCESS_EXPIRES_IN = '15m';
const DEFAULT_REFRESH_EXPIRES_IN = '7d';

/**
 * Create a session token pair (access + refresh) signed with the given key pair.
 *
 * Access tokens: short-lived (default 15m), contain user claims
 * Refresh tokens: long-lived (default 7d), minimal claims for rotation
 *
 * @example
 * const session = createSession(keyPair, {
 *   sub: 'user_123',
 *   issuer: 'my-app',
 *   claims: { role: 'admin', org: 'acme' },
 * });
 *
 * // session.accessToken  — send to client, use for API calls
 * // session.refreshToken — store securely, use to rotate
 */
export function createSession(
  keyPair: KeyPair,
  options: SessionOptions
): SessionTokenPair {
  const {
    sub,
    issuer,
    accessExpiresIn = DEFAULT_ACCESS_EXPIRES_IN,
    refreshExpiresIn = DEFAULT_REFRESH_EXPIRES_IN,
    claims = {},
  } = options;

  if (!sub) {
    throw new HashItError('Session subject (sub) is required', HashItErrorCode.INVALID_PARAMS);
  }

  const now = nowSeconds();
  const accessExpiry = now + parseDuration(accessExpiresIn);
  const refreshExpiry = now + parseDuration(refreshExpiresIn);

  const accessToken = signToken(
    { ...claims, sub, type: 'access' },
    {
      privateKey: keyPair.privateKey,
      kid: keyPair.kid,
      algorithm: keyPair.algorithm,
      expiresIn: accessExpiresIn,
      ...(issuer !== undefined ? { issuer } : {}),
    }
  );

  const refreshToken = signToken(
    { sub, type: 'refresh' },
    {
      privateKey: keyPair.privateKey,
      kid: keyPair.kid,
      algorithm: keyPair.algorithm,
      expiresIn: refreshExpiresIn,
      ...(issuer !== undefined ? { issuer } : {}),
    }
  );

  return {
    accessToken,
    refreshToken,
    accessExpiresAt: accessExpiry,
    refreshExpiresAt: refreshExpiry,
    tokenType: 'Bearer',
  };
}

/**
 * Verify a session access token.
 *
 * @example
 * const result = verifySession(accessToken, keyPair.publicKey);
 * if (result.valid) {
 *   const userId = result.payload?.sub;
 * }
 */
export function verifySession(
  token: string,
  publicKey: string | PublicKeySet,
  options?: Partial<VerifyTokenOptions>
): TokenVerifyResult {
  return verifyToken(token, {
    publicKey,
    ...options,
  });
}

/**
 * Rotate a session using a refresh token.
 * Verifies the refresh token, then issues a fresh access + refresh pair.
 *
 * @example
 * const newSession = rotateSession(oldRefreshToken, keyPair, {
 *   sub: 'user_123',
 *   issuer: 'my-app',
 * });
 */
export function rotateSession(
  refreshToken: string,
  keyPair: KeyPair,
  options: SessionOptions
): SessionTokenPair {
  const result = verifyToken(refreshToken, {
    publicKey: keyPair.publicKey,
    ...(options.issuer !== undefined ? { issuer: options.issuer } : {}),
  });

  if (!result.valid) {
    throw new HashItError(
      `Refresh token is invalid: ${result.error ?? 'unknown'}`,
      HashItErrorCode.INVALID_TOKEN
    );
  }

  if (result.payload?.type !== 'refresh') {
    throw new HashItError(
      'Provided token is not a refresh token',
      HashItErrorCode.INVALID_TOKEN
    );
  }

  // Use the sub from the refresh token if not provided
  const sub = options.sub ?? (result.payload.sub as string);

  return createSession(keyPair, { ...options, sub });
}
