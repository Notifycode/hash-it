import { seal, open } from '../src/core/encrypt.js';
import { createSession, verifySession, rotateSession } from '../src/core/session.js';
import { generateApiToken, verifyApiToken, maskToken } from '../src/core/apiToken.js';
import { generateKeyPair } from '../src/core/keys.js';
import { randomBytes, safeEqual, parseDuration, fingerprint } from '../src/utils/helpers.js';
import { HashItError } from '../src/utils/errors.js';
import { hashit } from '../src/hashit.js';

describe('Encryption — hashit.encrypt', () => {
  describe('seal & open (AES-256-GCM)', () => {
    it('should encrypt and decrypt correctly', () => {
      const sealed = seal('hello world', 'secret-key-123');
      const opened = open(sealed, 'secret-key-123');
      expect(opened).toBe('hello world');
    });

    it('should use aes-256-gcm by default', () => {
      const sealed = seal('test', 'key12345');
      expect(sealed.algorithm).toBe('aes-256-gcm');
    });

    it('should produce different ciphertext for same plaintext', () => {
      const s1 = seal('same-text', 'same-key-here');
      const s2 = seal('same-text', 'same-key-here');
      expect(s1.ciphertext).not.toBe(s2.ciphertext);
    });

    it('should include iv and auth tag', () => {
      const sealed = seal('data', 'key12345678');
      expect(sealed.iv).toBeTruthy();
      expect(sealed.tag).toBeTruthy();
    });

    it('should fail to decrypt with wrong key', () => {
      const sealed = seal('secret', 'correct-key-123');
      expect(() => open(sealed, 'wrong-key-1234')).toThrow(HashItError);
    });

    it('should fail on tampered ciphertext', () => {
      const sealed = seal('data', 'key12345678');
      const tampered = { ...sealed, ciphertext: 'tampered-data-here' };
      expect(() => open(tampered, 'key12345678')).toThrow();
    });

    it('should throw when key is too short', () => {
      expect(() => seal('data', 'short')).toThrow(HashItError);
    });
  });

  describe('AES-256-CBC mode', () => {
    it('should encrypt and decrypt with CBC', () => {
      const sealed = seal('cbc-test', 'my-cbc-secret-key', { algorithm: 'aes-256-cbc' });
      expect(sealed.algorithm).toBe('aes-256-cbc');
      const opened = open(sealed, 'my-cbc-secret-key');
      expect(opened).toBe('cbc-test');
    });

    it('should detect tampered CBC ciphertext (HMAC)', () => {
      const sealed = seal('data', 'cbc-key-here-1234', { algorithm: 'aes-256-cbc' });
      const tampered = { ...sealed, ciphertext: 'tampered.tampered' };
      expect(() => open(tampered, 'cbc-key-here-1234')).toThrow();
    });
  });

  describe('hashit.encrypt interface', () => {
    it('should seal and open via hashit interface', () => {
      const s = hashit.encrypt.seal('hashit-test', 'my-hashit-key123');
      const o = hashit.encrypt.open(s, 'my-hashit-key123');
      expect(o).toBe('hashit-test');
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('Session Management — hashit.session', () => {
  let keyPair: ReturnType<typeof generateKeyPair>;

  beforeAll(() => {
    keyPair = generateKeyPair();
  });

  describe('createSession', () => {
    it('should return access and refresh tokens', () => {
      const session = createSession(keyPair, { sub: 'user_123' });
      expect(session.accessToken).toBeTruthy();
      expect(session.refreshToken).toBeTruthy();
      expect(session.tokenType).toBe('Bearer');
    });

    it('should set accessExpiresAt and refreshExpiresAt', () => {
      const session = createSession(keyPair, { sub: 'user_123' });
      expect(session.accessExpiresAt).toBeGreaterThan(Date.now() / 1000);
      expect(session.refreshExpiresAt).toBeGreaterThan(session.accessExpiresAt);
    });

    it('should embed type=access in access token', () => {
      const session = createSession(keyPair, { sub: 'user_123' });
      const result = verifySession(session.accessToken, keyPair.publicKey);
      expect(result.valid).toBe(true);
      expect(result.payload?.type).toBe('access');
    });

    it('should embed type=refresh in refresh token', () => {
      const session = createSession(keyPair, { sub: 'user_123' });
      const result = verifySession(session.refreshToken, keyPair.publicKey);
      expect(result.valid).toBe(true);
      expect(result.payload?.type).toBe('refresh');
    });

    it('should embed custom claims in access token', () => {
      const session = createSession(keyPair, {
        sub: 'user_123',
        claims: { role: 'admin', org: 'acme' },
      });
      const result = verifySession(session.accessToken, keyPair.publicKey);
      expect(result.payload?.role).toBe('admin');
      expect(result.payload?.org).toBe('acme');
    });

    it('should throw when sub is missing', () => {
      expect(() => createSession(keyPair, { sub: '' })).toThrow(HashItError);
    });

    it('should respect custom expiry durations', () => {
      const session = createSession(keyPair, {
        sub: 'user_123',
        accessExpiresIn: '5m',
        refreshExpiresIn: '30d',
      });
      const now = Math.floor(Date.now() / 1000);
      expect(session.accessExpiresAt).toBeCloseTo(now + 300, -2);
      expect(session.refreshExpiresAt).toBeCloseTo(now + 30 * 86400, -2);
    });
  });

  describe('verifySession', () => {
    it('should verify a valid access token', () => {
      const session = createSession(keyPair, { sub: 'user_123' });
      const result = verifySession(session.accessToken, keyPair.publicKey);
      expect(result.valid).toBe(true);
      expect(result.payload?.sub).toBe('user_123');
    });

    it('should reject a token from a different key', () => {
      const otherKey = generateKeyPair();
      const session = createSession(otherKey, { sub: 'user_123' });
      const result = verifySession(session.accessToken, keyPair.publicKey);
      expect(result.valid).toBe(false);
    });
  });

  describe('rotateSession', () => {
    it('should issue a new session from a valid refresh token', () => {
      const session = createSession(keyPair, { sub: 'user_123' });
      const newSession = rotateSession(session.refreshToken, keyPair, { sub: 'user_123' });
      expect(newSession.accessToken).toBeTruthy();
      expect(newSession.refreshToken).toBeTruthy();
      // New tokens should be different
      expect(newSession.accessToken).not.toBe(session.accessToken);
    });

    it('should throw when given an access token instead of refresh', () => {
      const session = createSession(keyPair, { sub: 'user_123' });
      expect(() =>
        rotateSession(session.accessToken, keyPair, { sub: 'user_123' })
      ).toThrow(HashItError);
    });

    it('should throw on invalid refresh token', () => {
      expect(() =>
        rotateSession('invalid.token.here', keyPair, { sub: 'user_123' })
      ).toThrow(HashItError);
    });
  });

  describe('hashit.session interface', () => {
    it('should create, verify, and rotate via hashit', () => {
      const session = hashit.session.create(keyPair, { sub: 'test-user' });
      const verified = hashit.session.verify(session.accessToken, keyPair.publicKey);
      expect(verified.valid).toBe(true);

      const rotated = hashit.session.rotate(session.refreshToken, keyPair, { sub: 'test-user' });
      expect(rotated.accessToken).toBeTruthy();
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('API Tokens — hashit.apiToken', () => {
  let keyPair: ReturnType<typeof generateKeyPair>;

  beforeAll(() => {
    keyPair = generateKeyPair();
  });

  describe('generateApiToken', () => {
    it('should generate a token with default hsh_ prefix', () => {
      const { token } = generateApiToken(keyPair);
      expect(token).toMatch(/^hsh_/);
    });

    it('should support custom prefix', () => {
      const { token } = generateApiToken(keyPair, { prefix: 'myapp_' });
      expect(token).toMatch(/^myapp_/);
    });

    it('should include a masked version', () => {
      const { masked } = generateApiToken(keyPair);
      expect(masked).toMatch(/^hsh_\*\*\*\*/);
    });

    it('should set expiresAt when expiresIn provided', () => {
      const { expiresAt } = generateApiToken(keyPair, { expiresIn: '90d' });
      expect(expiresAt).toBeGreaterThan(Date.now() / 1000);
    });

    it('should set expiresAt=null when no expiry', () => {
      const { expiresAt } = generateApiToken(keyPair, { expiresIn: null });
      expect(expiresAt).toBeNull();
    });

    it('should embed custom claims', () => {
      const { token } = generateApiToken(keyPair, {
        sub: 'org_123',
        claims: { scopes: ['read', 'write'] },
      });
      const result = verifyApiToken(token, keyPair.publicKey);
      expect(result.valid).toBe(true);
      expect(result.payload?.sub).toBe('org_123');
      expect(result.payload?.scopes).toEqual(['read', 'write']);
    });
  });

  describe('verifyApiToken', () => {
    it('should verify a valid API token', () => {
      const { token } = generateApiToken(keyPair);
      const result = verifyApiToken(token, keyPair.publicKey);
      expect(result.valid).toBe(true);
    });

    it('should reject a tampered token', () => {
      const { token } = generateApiToken(keyPair);
      const result = verifyApiToken(token + 'tampered', keyPair.publicKey);
      expect(result.valid).toBe(false);
    });
  });

  describe('maskToken', () => {
    it('should mask preserving prefix and last 4 chars', () => {
      const masked = maskToken('hsh_abcdefghijklmnop', 'hsh_');
      expect(masked).toBe('hsh_****mnop');
    });

    it('should auto-detect prefix', () => {
      const masked = maskToken('sk_live_abcdef123456');
      expect(masked).toMatch(/\*\*\*\*/);
    });
  });

  describe('hashit.apiToken interface', () => {
    it('should generate, verify, and mask via hashit', () => {
      const api = hashit.apiToken.generate(keyPair, { prefix: 'test_' });
      expect(api.token).toMatch(/^test_/);
      const result = hashit.apiToken.verify(api.token, keyPair.publicKey);
      expect(result.valid).toBe(true);
      const masked = hashit.apiToken.mask(api.token);
      expect(masked).toMatch(/\*\*\*\*/);
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('Utilities — hashit.utils', () => {
  describe('randomBytes', () => {
    it('should return a non-empty base64url string', () => {
      const bytes = randomBytes();
      expect(typeof bytes).toBe('string');
      expect(bytes.length).toBeGreaterThan(0);
    });

    it('should be unpredictable (no two equal)', () => {
      const a = randomBytes();
      const b = randomBytes();
      expect(a).not.toBe(b);
    });

    it('should throw for length < 8', () => {
      expect(() => randomBytes(4)).toThrow(HashItError);
    });

    it('should respect custom length', () => {
      const bytes = randomBytes(64);
      // 64 bytes → base64url string length
      expect(Buffer.from(bytes, 'base64url').length).toBe(64);
    });
  });

  describe('safeEqual', () => {
    it('should return true for identical strings', () => {
      expect(safeEqual('abc', 'abc')).toBe(true);
    });

    it('should return false for different strings', () => {
      expect(safeEqual('abc', 'def')).toBe(false);
    });

    it('should return false for different length strings', () => {
      expect(safeEqual('ab', 'abc')).toBe(false);
    });

    it('should return false for non-string inputs', () => {
      expect(safeEqual(null as unknown as string, 'abc')).toBe(false);
      expect(safeEqual('abc', undefined as unknown as string)).toBe(false);
    });
  });

  describe('parseDuration', () => {
    it('should parse seconds', () => expect(parseDuration('30s')).toBe(30));
    it('should parse minutes', () => expect(parseDuration('15m')).toBe(900));
    it('should parse hours', () => expect(parseDuration('1h')).toBe(3600));
    it('should parse days', () => expect(parseDuration('7d')).toBe(604800));
    it('should parse weeks', () => expect(parseDuration('2w')).toBe(1209600));
    it('should pass through numbers', () => expect(parseDuration(3600)).toBe(3600));
    it('should throw for invalid format', () => {
      expect(() => parseDuration('1y')).toThrow(HashItError);
    });
  });

  describe('fingerprint', () => {
    it('should return a fingerprint object', () => {
      const fp = fingerprint('user-agent:chrome');
      expect(fp.fingerprint).toBeTruthy();
      expect(fp.algorithm).toBe('sha256');
      expect(typeof fp.createdAt).toBe('number');
    });

    it('should support sha512', () => {
      const fp = fingerprint('data', 'sha512');
      expect(fp.algorithm).toBe('sha512');
    });

    it('should produce different fingerprints each call (HMAC with random key)', () => {
      const fp1 = fingerprint('same-data');
      const fp2 = fingerprint('same-data');
      expect(fp1.fingerprint).not.toBe(fp2.fingerprint);
    });
  });

  describe('hashit.utils interface', () => {
    it('should expose all utility functions', () => {
      expect(typeof hashit.utils.randomBytes).toBe('function');
      expect(typeof hashit.utils.safeEqual).toBe('function');
      expect(typeof hashit.utils.parseDuration).toBe('function');
      expect(typeof hashit.utils.fingerprint).toBe('function');
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('End-to-End Integration', () => {
  it('should complete a full authentication flow', async () => {
    // 1. Generate key pair (issuer holds this)
    const keyPair = hashit.keys.generate({ algorithm: 'ES256' });

    // 2. Hash user password
    const { hash } = await hashit.password.hash('user-password-123');

    // 3. Simulate login: verify password
    const { valid: passwordValid } = await hashit.password.verify('user-password-123', hash);
    expect(passwordValid).toBe(true);

    // 4. Issue session tokens
    const session = hashit.session.create(keyPair, {
      sub: 'user_abc',
      issuer: 'auth-service',
      claims: { role: 'user' },
    });

    // 5. Verify access token (API service only needs public key)
    const publicKey = keyPair.publicKey; // Only the public key!
    const verified = hashit.token.verify(session.accessToken, {
      publicKey,
      issuer: 'auth-service',
    });
    expect(verified.valid).toBe(true);
    expect(verified.payload?.sub).toBe('user_abc');
    expect(verified.payload?.role).toBe('user');

    // 6. Rotate session
    const newSession = hashit.session.rotate(session.refreshToken, keyPair, {
      sub: 'user_abc',
      issuer: 'auth-service',
    });
    expect(newSession.accessToken).not.toBe(session.accessToken);

    // 7. Generate API token
    const api = hashit.apiToken.generate(keyPair, {
      sub: 'user_abc',
      prefix: 'api_',
      expiresIn: '90d',
      claims: { scopes: ['read'] },
    });

    const apiVerified = hashit.apiToken.verify(api.token, publicKey);
    expect(apiVerified.valid).toBe(true);
    expect(apiVerified.payload?.scopes).toEqual(['read']);

    // 8. Encrypt sensitive data
    const sealed = hashit.encrypt.seal('user-secret-data', 'encryption-key-here');
    const decrypted = hashit.encrypt.open(sealed, 'encryption-key-here');
    expect(decrypted).toBe('user-secret-data');
  });

  it('should work with key rotation', () => {
    const oldKey = hashit.keys.generate({ kid: 'key-2023' });
    const newKey = hashit.keys.generate({ kid: 'key-2024' });

    // Token issued before rotation (signed with old key)
    const oldToken = hashit.token.sign(
      { sub: 'user123' },
      { privateKey: oldKey.privateKey, kid: oldKey.kid, expiresIn: '1h' }
    );

    // New token signed with new key
    const newToken = hashit.token.sign(
      { sub: 'user123' },
      { privateKey: newKey.privateKey, kid: newKey.kid, expiresIn: '1h' }
    );

    // Build key set with both keys
    const keySet = hashit.keys.buildKeySet([
      hashit.keys.exportPublic(newKey),
      hashit.keys.exportPublic(oldKey),
    ]);

    // Both tokens should verify against the key set
    const oldResult = hashit.token.verify(oldToken, { publicKey: keySet });
    const newResult = hashit.token.verify(newToken, { publicKey: keySet });

    expect(oldResult.valid).toBe(true);
    expect(newResult.valid).toBe(true);
  });
});
