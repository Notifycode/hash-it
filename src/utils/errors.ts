import { HashItErrorCode } from '../types/index.js';

/**
 * Base error class for all hash-it errors.
 * Provides structured error codes for programmatic handling.
 */
export class HashItError extends Error {
  public readonly code: HashItErrorCode;
  public readonly context: Record<string, unknown> | undefined;

  constructor(
    message: string,
    code: HashItErrorCode,
    context?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'HashItError';
    this.code = code;
    this.context = context ?? undefined;

    // Maintain proper prototype chain in transpiled environments
    Object.setPrototypeOf(this, HashItError.prototype);
  }

  toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      context: this.context,
    };
  }
}

export class InvalidKeyError extends HashItError {
  constructor(message = 'Invalid or missing key', context?: Record<string, unknown>) {
    super(message, HashItErrorCode.INVALID_KEY, context);
    this.name = 'InvalidKeyError';
    Object.setPrototypeOf(this, InvalidKeyError.prototype);
  }
}

export class InvalidTokenError extends HashItError {
  constructor(message = 'Invalid token format', context?: Record<string, unknown>) {
    super(message, HashItErrorCode.INVALID_TOKEN, context);
    this.name = 'InvalidTokenError';
    Object.setPrototypeOf(this, InvalidTokenError.prototype);
  }
}

export class TokenExpiredError extends HashItError {
  constructor(expiredAt: number) {
    super('Token has expired', HashItErrorCode.TOKEN_EXPIRED, { expiredAt });
    this.name = 'TokenExpiredError';
    Object.setPrototypeOf(this, TokenExpiredError.prototype);
  }
}

export class TokenNotYetValidError extends HashItError {
  constructor(validFrom: number) {
    super('Token is not yet valid', HashItErrorCode.TOKEN_NOT_YET_VALID, { validFrom });
    this.name = 'TokenNotYetValidError';
    Object.setPrototypeOf(this, TokenNotYetValidError.prototype);
  }
}

export class SignatureInvalidError extends HashItError {
  constructor(context?: Record<string, unknown>) {
    super('Token signature is invalid', HashItErrorCode.SIGNATURE_INVALID, context);
    this.name = 'SignatureInvalidError';
    Object.setPrototypeOf(this, SignatureInvalidError.prototype);
  }
}

export class AlgorithmMismatchError extends HashItError {
  constructor(expected: string, received: string) {
    super(
      `Algorithm mismatch: expected ${expected}, got ${received}`,
      HashItErrorCode.ALGORITHM_MISMATCH,
      { expected, received }
    );
    this.name = 'AlgorithmMismatchError';
    Object.setPrototypeOf(this, AlgorithmMismatchError.prototype);
  }
}

export class KeyNotFoundError extends HashItError {
  constructor(kid: string) {
    super(`Key not found in key set: ${kid}`, HashItErrorCode.KEY_NOT_FOUND, { kid });
    this.name = 'KeyNotFoundError';
    Object.setPrototypeOf(this, KeyNotFoundError.prototype);
  }
}

export class AudienceMismatchError extends HashItError {
  constructor(expected: string | string[], received?: string | string[]) {
    super('Token audience does not match', HashItErrorCode.AUDIENCE_MISMATCH, {
      expected,
      received,
    });
    this.name = 'AudienceMismatchError';
    Object.setPrototypeOf(this, AudienceMismatchError.prototype);
  }
}

export class IssuerMismatchError extends HashItError {
  constructor(expected: string, received?: string) {
    super('Token issuer does not match', HashItErrorCode.ISSUER_MISMATCH, {
      expected,
      received,
    });
    this.name = 'IssuerMismatchError';
    Object.setPrototypeOf(this, IssuerMismatchError.prototype);
  }
}
