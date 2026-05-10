/**
 * Token Module — Mastercard-Style Asymmetric Token Architecture
 *
 * This module implements the core of hash-it's value proposition:
 * public/private key token verification, natively in JavaScript.
 *
 * Architecture (mirrors Mastercard Token Service):
 * ┌─────────────────┐          ┌──────────────────────┐
 * │  Token Issuer   │          │  Token Verifier(s)   │
 * │  (has private   │  token   │  (has public key     │
 * │   key only)     │ ───────► │   only — can verify  │
 * │                 │          │   but NOT forge)      │
 * └─────────────────┘          └──────────────────────┘
 *
 * The private key NEVER leaves the issuer.
 * Any service with the public key can verify the token.
 * No shared secret = no single point of compromise.
 *
 * Token format: <base64url-header>.<base64url-payload>.<base64url-signature>
 * (JWT-compatible for interoperability)
 */

import { createSign, createVerify } from 'crypto';
import type {
  TokenClaims,
  SignTokenOptions,
  VerifyTokenOptions,
  TokenVerifyResult,
  SignatureAlgorithm,
  PublicKeySet,
} from '../types/index.js';
import { HashItErrorCode } from '../types/index.js';
import { HashItError, InvalidTokenError, SignatureInvalidError } from '../utils/errors.js';
import { base64urlEncode, base64urlDecode, nowSeconds, generateJti, parseDuration } from '../utils/helpers.js';
import { findKeyInSet } from './keys.js';

// ── Algorithm → Node.js crypto mappings ───────────────────────────────────────

type AlgoConfig = { nodeAlgo: string; type: 'ec' | 'rsa' | 'rsa-pss' };

const ALGORITHM_MAP: Record<SignatureAlgorithm, AlgoConfig> = {
  ES256: { nodeAlgo: 'SHA256', type: 'ec' },
  ES384: { nodeAlgo: 'SHA384', type: 'ec' },
  ES512: { nodeAlgo: 'SHA512', type: 'ec' },
  RS256: { nodeAlgo: 'SHA256', type: 'rsa' },
  RS512: { nodeAlgo: 'SHA512', type: 'rsa' },
  PS256: { nodeAlgo: 'SHA256', type: 'rsa-pss' },
};

// ── Token Header ──────────────────────────────────────────────────────────────

interface TokenHeader {
  alg: SignatureAlgorithm;
  typ: 'JWT';
  kid?: string;
}

// ── Sign ──────────────────────────────────────────────────────────────────────

/**
 * Sign a payload using a private key.
 *
 * Produces a compact token: header.payload.signature
 * Compatible with JWT parsers (RS256/ES256).
 *
 * @example
 * const token = signToken({ sub: 'user123', role: 'admin' }, {
 *   privateKey: keyPair.privateKey,
 *   kid: keyPair.kid,
 *   algorithm: 'ES256',
 *   expiresIn: '15m',
 *   issuer: 'my-service',
 * });
 */
export function signToken(
  payload: TokenClaims,
  options: SignTokenOptions
): string {
  const {
    privateKey,
    kid,
    algorithm = 'ES256',
    expiresIn,
    issuer,
    audience,
    claims = {},
  } = options;

  if (!privateKey) {
    throw new HashItError('Private key is required', HashItErrorCode.INVALID_KEY);
  }

  const algoConfig = ALGORITHM_MAP[algorithm];
  if (!algoConfig) {
    throw new HashItError(`Unsupported algorithm: ${algorithm}`, HashItErrorCode.ALGORITHM_MISMATCH);
  }

  const now = nowSeconds();

  const fullPayload: TokenClaims = {
    ...claims,
    ...payload,
    iat: now,
    jti: payload.jti ?? generateJti(),
  };

  if (issuer) fullPayload.iss = issuer;
  if (audience) fullPayload.aud = audience;
  if (expiresIn !== undefined) {
    fullPayload.exp = now + parseDuration(expiresIn);
  }

  const header: TokenHeader = { alg: algorithm, typ: 'JWT' };
  if (kid) header.kid = kid;

  const headerB64 = base64urlEncode(JSON.stringify(header));
  const payloadB64 = base64urlEncode(JSON.stringify(fullPayload));
  const signingInput = `${headerB64}.${payloadB64}`;

  try {
    const sign = createSign(algoConfig.nodeAlgo);
    sign.update(signingInput);

    const signatureBuffer = algoConfig.type === 'rsa-pss'
      ? sign.sign({
          key: privateKey,
          padding: 6, // RSA_PKCS1_PSS_PADDING
          saltLength: -2, // RSA_PSS_SALTLEN_DIGEST
        })
      : sign.sign(privateKey);

    const signatureB64 = base64urlEncode(signatureBuffer);
    return `${signingInput}.${signatureB64}`;
  } catch (err) {
    throw new HashItError(
      `Failed to sign token: ${err instanceof Error ? err.message : 'unknown error'}`,
      HashItErrorCode.INVALID_KEY,
      { algorithm }
    );
  }
}

// ── Verify ────────────────────────────────────────────────────────────────────

/**
 * Verify a signed token and return its decoded payload.
 *
 * Validates:
 * - Signature (cryptographic)
 * - Expiry (exp claim)
 * - Not-before (nbf claim)
 * - Issuer (iss claim) — if expected issuer provided
 * - Audience (aud claim) — if expected audience provided
 * - Algorithm — only allows explicitly permitted algorithms
 *
 * @example
 * const result = verifyToken(token, {
 *   publicKey: keyPair.publicKey,
 *   issuer: 'my-service',
 *   audience: 'my-client',
 * });
 * if (result.valid) {
 *   console.log(result.payload?.sub); // 'user123'
 * }
 */
export function verifyToken(
  token: string,
  options: VerifyTokenOptions
): TokenVerifyResult {
  const {
    publicKey,
    issuer,
    audience,
    algorithms,
    clockSkew = 30,
  } = options;

  // ── 1. Parse ────────────────────────────────────────────────────────────────
  const parts = token.split('.');
  if (parts.length !== 3) {
    return {
      valid: false,
      error: 'Invalid token format: expected 3 parts (header.payload.signature)',
    };
  }

  const [headerB64, payloadB64, signatureB64] = parts as [string, string, string];

  let header: TokenHeader;
  let payload: TokenClaims;

  try {
    header = JSON.parse(base64urlDecode(headerB64).toString('utf8')) as TokenHeader;
    payload = JSON.parse(base64urlDecode(payloadB64).toString('utf8')) as TokenClaims;
  } catch {
    return { valid: false, error: 'Token contains malformed JSON' };
  }

  // ── 2. Algorithm check ──────────────────────────────────────────────────────
  const algorithm = header.alg as SignatureAlgorithm;

  if (!algorithm || !(algorithm in ALGORITHM_MAP)) {
    return { valid: false, error: `Unsupported algorithm: ${algorithm}` };
  }

  if (algorithms && !algorithms.includes(algorithm)) {
    return {
      valid: false,
      error: `Algorithm ${algorithm} is not in allowed list: ${algorithms.join(', ')}`,
    };
  }

  // ── 3. Resolve public key (supports key rotation) ────────────────────────────
  let resolvedPublicKey: string;

  if (typeof publicKey === 'string') {
    resolvedPublicKey = publicKey;
  } else {
    // PublicKeySet — find by kid
    const kid = header.kid;
    if (!kid) {
      // No kid in header — try each key
      const result = tryVerifyWithKeySet(
        `${headerB64}.${payloadB64}`,
        signatureB64,
        publicKey,
        algorithm,
        header.kid
      );
      if (!result) {
        return { valid: false, error: 'Signature verification failed with all available keys' };
      }
      resolvedPublicKey = result;
    } else {
      const keyEntry = findKeyInSet(publicKey as PublicKeySet, kid);
      if (!keyEntry) {
        return { valid: false, error: `Key not found: ${kid}` };
      }
      resolvedPublicKey = keyEntry.publicKey;
    }
  }

  // ── 4. Verify signature ──────────────────────────────────────────────────────
  const algoConfig = ALGORITHM_MAP[algorithm];
  if (!algoConfig) {
    return { valid: false, error: `Unknown algorithm config: ${algorithm}` };
  }

  const signingInput = `${headerB64}.${payloadB64}`;
  const signatureBuffer = base64urlDecode(signatureB64);

  let signatureValid = false;
  try {
    const verify = createVerify(algoConfig.nodeAlgo);
    verify.update(signingInput);

    if (algoConfig.type === 'rsa-pss') {
      signatureValid = verify.verify(
        {
          key: resolvedPublicKey,
          padding: 6, // RSA_PKCS1_PSS_PADDING
          saltLength: -2,
        },
        signatureBuffer
      );
    } else {
      signatureValid = verify.verify(resolvedPublicKey, signatureBuffer);
    }
  } catch {
    return { valid: false, error: 'Signature verification failed' };
  }

  if (!signatureValid) {
    return { valid: false, error: 'Signature is invalid' };
  }

  // ── 5. Claims validation ─────────────────────────────────────────────────────
  const now = nowSeconds();

  if (payload.exp !== undefined && now > (payload.exp as number) + clockSkew) {
    return {
      valid: false,
      error: `Token expired at ${new Date((payload.exp as number) * 1000).toISOString()}`,
    };
  }

  if (payload.nbf !== undefined && now < (payload.nbf as number) - clockSkew) {
    return {
      valid: false,
      error: `Token not valid until ${new Date((payload.nbf as number) * 1000).toISOString()}`,
    };
  }

  if (issuer && payload.iss !== issuer) {
    return {
      valid: false,
      error: `Issuer mismatch: expected "${issuer}", got "${payload.iss ?? 'none'}"`,
    };
  }

  if (audience !== undefined) {
    const tokenAud = payload.aud;
    const expectedAuds = Array.isArray(audience) ? audience : [audience];
    const tokenAuds = Array.isArray(tokenAud) ? tokenAud : [tokenAud];
    const hasMatch = expectedAuds.some((ea) => tokenAuds.includes(ea));
    if (!hasMatch) {
      return {
        valid: false,
        error: `Audience mismatch: expected one of [${expectedAuds.join(', ')}]`,
      };
    }
  }

  return {
    valid: true,
    payload,
    ...(header.kid !== undefined ? { kid: header.kid } : {}),
    algorithm,
  };
}

/**
 * Decode a token without verifying its signature.
 * ⚠️ UNSAFE — never use this for authentication. Only for debugging.
 */
export function decodeToken(token: string): TokenClaims | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  try {
    return JSON.parse(base64urlDecode(parts[1] as string).toString('utf8')) as TokenClaims;
  } catch {
    return null;
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function tryVerifyWithKeySet(
  signingInput: string,
  signatureB64: string,
  keySet: PublicKeySet,
  algorithm: SignatureAlgorithm,
  _kid?: string
): string | null {
  const algoConfig = ALGORITHM_MAP[algorithm];
  if (!algoConfig) return null;

  const signatureBuffer = base64urlDecode(signatureB64);

  for (const keyEntry of keySet.keys) {
    try {
      const verify = createVerify(algoConfig.nodeAlgo);
      verify.update(signingInput);
      const valid = verify.verify(keyEntry.publicKey, signatureBuffer);
      if (valid) return keyEntry.publicKey;
    } catch {
      // Try next key
    }
  }

  return null;
}
