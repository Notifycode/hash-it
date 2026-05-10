import { signToken, verifyToken, decodeToken } from '../src/core/token.js';
import { generateKeyPair, exportPublicKey, buildKeySet } from '../src/core/keys.js';
import { hashit } from '../src/hashit.js';

describe('Token Signing & Verification — Mastercard-style', () => {
  let keyPair: ReturnType<typeof generateKeyPair>;

  beforeAll(() => {
    keyPair = generateKeyPair({ kid: 'test-key-001' });
  });

  // ── signToken ──────────────────────────────────────────────────────────────

  describe('signToken', () => {
    it('should produce a 3-part JWT-compatible token', () => {
      const token = signToken({ sub: 'user123' }, { privateKey: keyPair.privateKey });
      const parts = token.split('.');
      expect(parts).toHaveLength(3);
    });

    it('should embed kid in token header when provided', () => {
      const token = signToken(
        { sub: 'user123' },
        { privateKey: keyPair.privateKey, kid: keyPair.kid }
      );
      const header = JSON.parse(Buffer.from(token.split('.')[0]!, 'base64url').toString());
      expect(header.kid).toBe(keyPair.kid);
    });

    it('should set iat (issued at) automatically', () => {
      const before = Math.floor(Date.now() / 1000);
      const token = signToken({ sub: 'user123' }, { privateKey: keyPair.privateKey });
      const payload = JSON.parse(Buffer.from(token.split('.')[1]!, 'base64url').toString());
      expect(payload.iat).toBeGreaterThanOrEqual(before);
    });

    it('should set exp when expiresIn is provided (string)', () => {
      const token = signToken(
        { sub: 'user123' },
        { privateKey: keyPair.privateKey, expiresIn: '1h' }
      );
      const payload = JSON.parse(Buffer.from(token.split('.')[1]!, 'base64url').toString());
      expect(payload.exp).toBeGreaterThan(payload.iat);
    });

    it('should set exp when expiresIn is provided (number)', () => {
      const token = signToken(
        { sub: 'user123' },
        { privateKey: keyPair.privateKey, expiresIn: 3600 }
      );
      const payload = JSON.parse(Buffer.from(token.split('.')[1]!, 'base64url').toString());
      expect(payload.exp - payload.iat).toBe(3600);
    });

    it('should embed issuer and audience claims', () => {
      const token = signToken(
        { sub: 'user123' },
        {
          privateKey: keyPair.privateKey,
          issuer: 'my-service',
          audience: 'my-client',
        }
      );
      const payload = JSON.parse(Buffer.from(token.split('.')[1]!, 'base64url').toString());
      expect(payload.iss).toBe('my-service');
      expect(payload.aud).toBe('my-client');
    });

    it('should embed custom claims', () => {
      const token = signToken(
        { sub: 'user123' },
        {
          privateKey: keyPair.privateKey,
          claims: { role: 'admin', org: 'acme' },
        }
      );
      const payload = JSON.parse(Buffer.from(token.split('.')[1]!, 'base64url').toString());
      expect(payload.role).toBe('admin');
      expect(payload.org).toBe('acme');
    });

    it('should throw on missing private key', () => {
      expect(() =>
        signToken({ sub: 'user' }, { privateKey: '' })
      ).toThrow();
    });

    it('should throw on invalid algorithm', () => {
      expect(() =>
        signToken({ sub: 'user' }, { privateKey: keyPair.privateKey, algorithm: 'HS256' as any })
      ).toThrow();
    });
  });

  // ── verifyToken ───────────────────────────────────────────────────────────

  describe('verifyToken', () => {
    it('should verify a valid token', () => {
      const token = signToken({ sub: 'user123' }, { privateKey: keyPair.privateKey });
      const result = verifyToken(token, { publicKey: keyPair.publicKey });
      expect(result.valid).toBe(true);
      expect(result.payload?.sub).toBe('user123');
    });

    it('should return valid=false for a tampered token', () => {
      const token = signToken({ sub: 'user123' }, { privateKey: keyPair.privateKey });
      const parts = token.split('.');

      // Tamper with the payload
      const tamperedPayload = Buffer.from(
        JSON.stringify({ sub: 'admin', iat: Date.now() / 1000 })
      ).toString('base64url');

      const tampered = `${parts[0]}.${tamperedPayload}.${parts[2]}`;
      const result = verifyToken(tampered, { publicKey: keyPair.publicKey });
      expect(result.valid).toBe(false);
    });

    it('should return valid=false for a token signed by a different key', () => {
      const otherKey = generateKeyPair();
      const token = signToken({ sub: 'user123' }, { privateKey: otherKey.privateKey });
      const result = verifyToken(token, { publicKey: keyPair.publicKey });
      expect(result.valid).toBe(false);
    });

    it('should reject an expired token', async () => {
      const token = signToken(
        { sub: 'user123' },
        { privateKey: keyPair.privateKey, expiresIn: -1 } // expired 1 second ago
      );

      // Wait a moment to ensure expiry
      await new Promise((r) => setTimeout(r, 100));

      const result = verifyToken(token, {
        publicKey: keyPair.publicKey,
        clockSkew: 0,
      });
      expect(result.valid).toBe(false);
      expect(result.error).toContain('expired');
    });

    it('should accept within clock skew tolerance', async () => {
      const token = signToken(
        { sub: 'user123' },
        { privateKey: keyPair.privateKey, expiresIn: -5 }
      );

      const result = verifyToken(token, {
        publicKey: keyPair.publicKey,
        clockSkew: 60, // generous tolerance
      });
      expect(result.valid).toBe(true);
    });

    it('should reject wrong issuer', () => {
      const token = signToken(
        { sub: 'user123' },
        { privateKey: keyPair.privateKey, issuer: 'real-issuer' }
      );
      const result = verifyToken(token, {
        publicKey: keyPair.publicKey,
        issuer: 'expected-issuer',
      });
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Issuer');
    });

    it('should reject wrong audience', () => {
      const token = signToken(
        { sub: 'user123' },
        { privateKey: keyPair.privateKey, audience: 'client-a' }
      );
      const result = verifyToken(token, {
        publicKey: keyPair.publicKey,
        audience: 'client-b',
      });
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Audience');
    });

    it('should handle array audiences', () => {
      const token = signToken(
        { sub: 'user123' },
        { privateKey: keyPair.privateKey, audience: ['client-a', 'client-b'] }
      );
      const result = verifyToken(token, {
        publicKey: keyPair.publicKey,
        audience: 'client-b',
      });
      expect(result.valid).toBe(true);
    });

    it('should return valid=false for malformed token', () => {
      const result = verifyToken('not.a.valid.jwt.format', { publicKey: keyPair.publicKey });
      expect(result.valid).toBe(false);
    });

    it('should return valid=false for empty token', () => {
      const result = verifyToken('', { publicKey: keyPair.publicKey });
      expect(result.valid).toBe(false);
    });
  });

  // ── Key Rotation ──────────────────────────────────────────────────────────

  describe('Key Rotation (PublicKeySet)', () => {
    it('should verify with current key from a key set', () => {
      const currentKey = generateKeyPair({ kid: 'current-2024' });
      const previousKey = generateKeyPair({ kid: 'previous-2023' });

      const keySet = buildKeySet([
        exportPublicKey(currentKey),
        exportPublicKey(previousKey),
      ]);

      const token = signToken(
        { sub: 'user123' },
        { privateKey: currentKey.privateKey, kid: currentKey.kid }
      );

      const result = verifyToken(token, { publicKey: keySet });
      expect(result.valid).toBe(true);
      expect(result.kid).toBe('current-2024');
    });

    it('should verify token signed by previous key (rotation safety)', () => {
      const currentKey = generateKeyPair({ kid: 'current-2024' });
      const previousKey = generateKeyPair({ kid: 'previous-2023' });

      const keySet = buildKeySet([
        exportPublicKey(currentKey),
        exportPublicKey(previousKey),
      ]);

      // Token was signed before rotation
      const oldToken = signToken(
        { sub: 'user123' },
        { privateKey: previousKey.privateKey, kid: previousKey.kid }
      );

      const result = verifyToken(oldToken, { publicKey: keySet });
      expect(result.valid).toBe(true);
    });

    it('should return key not found error for unknown kid', () => {
      const kp = generateKeyPair({ kid: 'known-key' });
      const keySet = buildKeySet([exportPublicKey(kp)]);

      const otherKey = generateKeyPair({ kid: 'unknown-key' });
      const token = signToken(
        { sub: 'user123' },
        { privateKey: otherKey.privateKey, kid: 'unknown-key' }
      );

      const result = verifyToken(token, { publicKey: keySet });
      expect(result.valid).toBe(false);
    });
  });

  // ── decodeToken ───────────────────────────────────────────────────────────

  describe('decodeToken (UNSAFE)', () => {
    it('should decode payload without verifying', () => {
      const token = signToken({ sub: 'user123', role: 'admin' }, { privateKey: keyPair.privateKey });
      const payload = decodeToken(token);
      expect(payload?.sub).toBe('user123');
      expect(payload?.role).toBe('admin');
    });

    it('should return null for invalid format', () => {
      expect(decodeToken('not-a-token')).toBeNull();
    });

    it('should decode even a tampered token (no verification)', () => {
      const token = signToken({ sub: 'user123' }, { privateKey: keyPair.privateKey });
      const parts = token.split('.');
      const tamperedPayload = Buffer.from(JSON.stringify({ sub: 'hacker' })).toString('base64url');
      const tampered = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

      const payload = decodeToken(tampered);
      expect(payload?.sub).toBe('hacker'); // decoded, not verified!
    });
  });

  // ── hashit.token API ──────────────────────────────────────────────────────

  describe('hashit.token interface', () => {
    it('should sign and verify via hashit interface', () => {
      const token = hashit.token.sign({ sub: 'test' }, { privateKey: keyPair.privateKey });
      const result = hashit.token.verify(token, { publicKey: keyPair.publicKey });
      expect(result.valid).toBe(true);
    });

    it('should decode via hashit interface', () => {
      const token = hashit.token.sign({ sub: 'decode-test' }, { privateKey: keyPair.privateKey });
      const payload = hashit.token.decode(token);
      expect(payload?.sub).toBe('decode-test');
    });
  });
});
