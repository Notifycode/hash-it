import { generateKeyPair, exportPublicKey, buildKeySet, findKeyInSet } from '../src/core/keys.js';
import { InvalidKeyError } from '../src/utils/errors.js';
import { hashit } from '../src/hashit.js';
import { SignatureAlgorithm } from '../src/index.js';

describe('Key Management — hashit.keys', () => {
  describe('generateKeyPair', () => {
    it('should generate an ECDSA P-256 key pair by default', () => {
      const kp = generateKeyPair();
      expect(kp.algorithm).toBe('ES256');
      expect(kp.privateKey).toContain('-----BEGIN PRIVATE KEY-----');
      expect(kp.publicKey).toContain('-----BEGIN PUBLIC KEY-----');
      expect(kp.kid).toBeTruthy();
      expect(kp.createdAt).toBeTruthy();
    });

    it('should generate ES384 key pair', () => {
      const kp = generateKeyPair({ algorithm: 'ES384' });
      expect(kp.algorithm).toBe('ES384');
    });

    it('should generate ES512 key pair', () => {
      const kp = generateKeyPair({ algorithm: 'ES512' });
      expect(kp.algorithm).toBe('ES512');
    });

    it('should generate RS256 (RSA-4096) key pair', () => {
      const kp = generateKeyPair({ algorithm: 'RS256' });
      expect(kp.algorithm).toBe('RS256');
      expect(kp.privateKey).toContain('PRIVATE KEY');
    }, 30000); // RSA-4096 takes longer

    it('should use a custom kid when provided', () => {
      const kp = generateKeyPair({ kid: 'my-custom-key-id' });
      expect(kp.kid).toBe('my-custom-key-id');
    });

    it('should generate unique kids for each key pair', () => {
      const kp1 = generateKeyPair();
      const kp2 = generateKeyPair();
      expect(kp1.kid).not.toBe(kp2.kid);
    });

    it('should throw on unsupported algorithm', () => {
      expect(() => generateKeyPair({ algorithm: 'HS256' as SignatureAlgorithm })).toThrow(InvalidKeyError);
    });

    it('should set createdAt as a valid ISO date string', () => {
      const kp = generateKeyPair();
      expect(() => new Date(kp.createdAt)).not.toThrow();
      expect(new Date(kp.createdAt).getFullYear()).toBeGreaterThanOrEqual(2024);
    });
  });

  describe('exportPublicKey', () => {
    it('should export public key as PublicKeyEntry', () => {
      const kp = generateKeyPair({ kid: 'test-key' });
      const entry = exportPublicKey(kp);

      expect(entry.kid).toBe('test-key');
      expect(entry.algorithm).toBe('ES256');
      expect(entry.publicKey).toContain('-----BEGIN PUBLIC KEY-----');
      expect(entry.createdAt).toBe(kp.createdAt);
    });

    it('should NOT include private key in exported entry', () => {
      const kp = generateKeyPair();
      const entry = exportPublicKey(kp);
      expect(JSON.stringify(entry)).not.toContain('PRIVATE KEY');
    });
  });

  describe('buildKeySet', () => {
    it('should build a key set from multiple entries', () => {
      const kp1 = generateKeyPair({ kid: 'key-1' });
      const kp2 = generateKeyPair({ kid: 'key-2' });

      const keySet = buildKeySet([exportPublicKey(kp1), exportPublicKey(kp2)]);

      expect(keySet.keys).toHaveLength(2);
      expect(keySet.keys[0]?.kid).toBe('key-1');
      expect(keySet.keys[1]?.kid).toBe('key-2');
    });

    it('should throw on empty key array', () => {
      expect(() => buildKeySet([])).toThrow(InvalidKeyError);
    });
  });

  describe('findKeyInSet', () => {
    it('should find a key by kid', () => {
      const kp = generateKeyPair({ kid: 'find-me' });
      const keySet = buildKeySet([exportPublicKey(kp)]);

      const found = findKeyInSet(keySet, 'find-me');
      expect(found).not.toBeNull();
      expect(found?.kid).toBe('find-me');
    });

    it('should return null for missing kid', () => {
      const kp = generateKeyPair({ kid: 'existing' });
      const keySet = buildKeySet([exportPublicKey(kp)]);

      const found = findKeyInSet(keySet, 'missing');
      expect(found).toBeNull();
    });
  });

  describe('hashit.keys interface', () => {
    it('should expose generate, exportPublic, buildKeySet', () => {
      expect(typeof hashit.keys.generate).toBe('function');
      expect(typeof hashit.keys.exportPublic).toBe('function');
      expect(typeof hashit.keys.buildKeySet).toBe('function');
    });
  });
});
