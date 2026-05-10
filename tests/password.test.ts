import { hashPassword, verifyPassword, needsRehash, hashPasswordPbkdf2 } from '../src/core/password.js';
import { HashItError } from '../src/utils/errors.js';
import { hashit } from '../src/hashit.js';

describe('Password Hashing — hashit.password', () => {
  // ── hashPassword ──────────────────────────────────────────────────────────

  describe('hashPassword (Argon2id)', () => {
    it('should return a hash string with correct prefix', () => {
      const result = hashPassword('my-secure-password');
      expect(result.hash).toMatch(/^\$hashit-argon2id\$v1\$/);
    });

    it('should include algorithm, salt, and timing', () => {
      const result =  hashPassword('password123');
      expect(result.algorithm).toBe('argon2id');
      expect(result.salt).toBeTruthy();
      expect(typeof result.timingMs).toBe('number');
      expect(result.timingMs).toBeGreaterThan(0);
    });

    it('should produce different hashes for the same password', async () => {
      const [r1, r2] = await Promise.all([
        hashPassword('same-password'),
        hashPassword('same-password'),
      ]);
      expect(r1.hash).not.toBe(r2.hash);
    });

  it('should throw on empty password', () => {
  expect(() => hashPassword('')).toThrow(HashItError);
});

    it('should throw on non-string password', () => {
      expect(() => hashPassword(null as unknown as string)).toThrow(HashItError);
    });

    it('should handle very long passwords (>1024 chars) via pre-hashing', () => {
      const longPassword = 'a'.repeat(2000);
      const result = hashPassword(longPassword);
      expect(result.hash).toMatch(/^\$hashit-argon2id\$v1\$/);
    });

    it('should accept custom Argon2id options', () => {
      const result = hashPassword('password', {
        memoryCost: 32768,
        timeCost: 2,
        parallelism: 2,
      });
      expect(result.hash).toContain('m=32768,t=2,p=2');
    });

    it('should throw when salt length < 12', () => {
      expect(() => hashPassword('password', { saltLength: 8 })).toThrow(HashItError);
    });
  });

  // ── verifyPassword ────────────────────────────────────────────────────────

  describe('verifyPassword', () => {
    it('should return valid=true for correct password', () => {
      const { hash } = hashPassword('correct-password');
      const result = verifyPassword('correct-password', hash);
      expect(result.valid).toBe(true);
    });

    it('should return valid=false for wrong password', () => {
      const { hash } =  hashPassword('correct-password');
      const result =  verifyPassword('wrong-password', hash);
      expect(result.valid).toBe(false);
    });

    it('should return valid=false for empty inputs', () => {
      const result = verifyPassword('', '');
      expect(result.valid).toBe(false);
    });

    it('should include timingMs in result', () => {
      const { hash } = hashPassword('password');
      const result = verifyPassword('password', hash);
      expect(typeof result.timingMs).toBe('number');
    });

    it('should NOT throw on invalid hash format — returns false', () => {
      const result = verifyPassword('password', 'invalid-hash-format');
      expect(result.valid).toBe(false);
    });

    it('should indicate needsRehash=false for current parameters', () => {
      const { hash } = hashPassword('password');
      const result = verifyPassword('password', hash);
      expect(result.needsRehash).toBe(false);
    });

    it('should indicate needsRehash=true for low-cost hash', () => {
      const { hash } = hashPassword('password', {
        memoryCost: 1024,
        timeCost: 1,
        parallelism: 1,
      });
      const result = verifyPassword('password', hash);
      // needsRehash since params are below defaults
      expect(result.needsRehash).toBe(true);
    });
  });

  // ── needsRehash ───────────────────────────────────────────────────────────

  describe('needsRehash', () => {
    it('should return false for current-params hash', () => {
      const { hash } = hashPassword('password');
      expect(needsRehash(hash)).toBe(false);
    });

    it('should return true for unknown format', () => {
      expect(needsRehash('$2b$12$someoldbcrypthash')).toBe(true);
    });

    it('should return true for low-cost hash', () => {
      const { hash } = hashPassword('password', {
        memoryCost: 4096,
        timeCost: 1,
      });
      expect(needsRehash(hash)).toBe(true);
    });
  });

  // ── PBKDF2 fallback ───────────────────────────────────────────────────────

  describe('hashPasswordPbkdf2', () => {
    it('should return a hash with pbkdf2 prefix', () => {
      const result = hashPasswordPbkdf2('password');
      expect(result.hash).toMatch(/^\$hashit-pbkdf2\$v1\$/);
      expect(result.algorithm).toBe('pbkdf2');
    });

    it('should be verifiable', () => {
      const { hash } = hashPasswordPbkdf2('pbkdf2-password');
      const result = verifyPassword('pbkdf2-password', hash);
      expect(result.valid).toBe(true);
    });

    it('should fail verification with wrong password', () => {
      const { hash } = hashPasswordPbkdf2('pbkdf2-password');
      const result = verifyPassword('wrong', hash);
      expect(result.valid).toBe(false);
    });
  });

  // ── hashit.password API ───────────────────────────────────────────────────

  describe('hashit.password interface', () => {
    it('should expose hash, verify, needsRehash', () => {
      expect(typeof hashit.password.hash).toBe('function');
      expect(typeof hashit.password.verify).toBe('function');
      expect(typeof hashit.password.needsRehash).toBe('function');
    });

    it('should work end-to-end through the hashit interface', async () => {
      const { hash } = await hashit.password.hash('interface-test');
      const { valid } = await hashit.password.verify('interface-test', hash);
      expect(valid).toBe(true);
    });
  });
});
