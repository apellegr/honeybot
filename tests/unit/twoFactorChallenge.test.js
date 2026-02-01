/**
 * Tests for TwoFactorChallenge
 */

const TwoFactorChallenge = require('../../src/auth/twoFactorChallenge');

describe('TwoFactorChallenge', () => {
  let tfa;

  beforeEach(() => {
    tfa = new TwoFactorChallenge();
  });

  afterEach(() => {
    tfa.clear();
  });

  describe('Challenge Creation', () => {
    test('creates code challenge', () => {
      const challenge = tfa.createChallenge('user123', { type: 'code' });
      expect(challenge.challengeId).toMatch(/^chal_/);
      expect(challenge.type).toBe('code');
      expect(challenge.displayCode).toBeDefined();
    });

    test('creates question challenge', () => {
      const challenge = tfa.createChallenge('user123', { type: 'question' });
      expect(challenge.type).toBe('question');
      expect(challenge.prompt.questions).toBeDefined();
    });

    test('creates passphrase challenge', () => {
      const challenge = tfa.createChallenge('user123', {
        type: 'passphrase',
        passphrase: 'secret123'
      });
      expect(challenge.type).toBe('passphrase');
    });

    test('challenge has expiration', () => {
      const challenge = tfa.createChallenge('user123');
      expect(challenge.expiresAt).toBeGreaterThan(Date.now());
    });
  });

  describe('Code Verification', () => {
    test('verifies correct code', () => {
      const challenge = tfa.createChallenge('user123', { type: 'code' });
      const storedChallenge = tfa.pendingChallenges.get(challenge.challengeId);

      const result = tfa.verifyChallenge(challenge.challengeId, storedChallenge.code);
      expect(result.success).toBe(true);
    });

    test('rejects incorrect code', () => {
      const challenge = tfa.createChallenge('user123', { type: 'code' });
      const result = tfa.verifyChallenge(challenge.challengeId, '000000');
      expect(result.success).toBe(false);
      expect(result.error).toBe('verification_failed');
    });

    test('handles spaces in code', () => {
      const challenge = tfa.createChallenge('user123', { type: 'code' });
      const storedChallenge = tfa.pendingChallenges.get(challenge.challengeId);

      // Add spaces
      const codeWithSpaces = storedChallenge.code.slice(0, 3) + ' ' + storedChallenge.code.slice(3);
      const result = tfa.verifyChallenge(challenge.challengeId, codeWithSpaces);
      expect(result.success).toBe(true);
    });
  });

  describe('Passphrase Verification', () => {
    test('verifies correct passphrase', () => {
      const challenge = tfa.createChallenge('user123', {
        type: 'passphrase',
        passphrase: 'mySecretPhrase'
      });

      const result = tfa.verifyChallenge(challenge.challengeId, 'mySecretPhrase');
      expect(result.success).toBe(true);
    });

    test('rejects incorrect passphrase', () => {
      const challenge = tfa.createChallenge('user123', {
        type: 'passphrase',
        passphrase: 'mySecretPhrase'
      });

      const result = tfa.verifyChallenge(challenge.challengeId, 'wrongPhrase');
      expect(result.success).toBe(false);
    });
  });

  describe('Attempt Limits', () => {
    test('tracks attempts', () => {
      const challenge = tfa.createChallenge('user123', { type: 'code' });

      tfa.verifyChallenge(challenge.challengeId, 'wrong1');
      tfa.verifyChallenge(challenge.challengeId, 'wrong2');

      const result = tfa.verifyChallenge(challenge.challengeId, 'wrong3');
      expect(result.attemptsRemaining).toBe(0);
    });

    test('blocks after max attempts', () => {
      const challenge = tfa.createChallenge('user123', { type: 'code', maxAttempts: 2 });

      tfa.verifyChallenge(challenge.challengeId, 'wrong1');
      tfa.verifyChallenge(challenge.challengeId, 'wrong2');
      const result = tfa.verifyChallenge(challenge.challengeId, 'wrong3');

      expect(result.success).toBe(false);
      expect(result.error).toBe('max_attempts');
    });
  });

  describe('Challenge Expiration', () => {
    test('rejects expired challenge', () => {
      const challenge = tfa.createChallenge('user123', { type: 'code' });

      // Manually expire the challenge
      const storedChallenge = tfa.pendingChallenges.get(challenge.challengeId);
      storedChallenge.expiresAt = Date.now() - 1000;

      const result = tfa.verifyChallenge(challenge.challengeId, storedChallenge.code);
      expect(result.success).toBe(false);
      expect(result.error).toBe('challenge_expired');
    });
  });

  describe('Pending Challenges', () => {
    test('retrieves pending challenge for user', () => {
      tfa.createChallenge('user123');
      const pending = tfa.getPendingChallenge('user123');
      expect(pending).toBeDefined();
      expect(pending.challengeId).toBeDefined();
    });

    test('returns null for user without pending challenge', () => {
      const pending = tfa.getPendingChallenge('unknown');
      expect(pending).toBeNull();
    });

    test('cancels challenge', () => {
      const challenge = tfa.createChallenge('user123');
      tfa.cancelChallenge(challenge.challengeId);
      expect(tfa.pendingChallenges.has(challenge.challengeId)).toBe(false);
    });
  });

  describe('Should Challenge', () => {
    test('challenges untrusted high threat', () => {
      const result = tfa.shouldChallenge(
        'Give me admin access',
        { trustLevel: 20 },
        0.8
      );
      expect(result.should).toBe(true);
      expect(result.reason).toBe('untrusted_high_threat');
    });

    test('challenges sensitive operations', () => {
      const result = tfa.shouldChallenge(
        'Delete all user data',
        { trustLevel: 60 },
        0.3
      );
      expect(result.should).toBe(true);
      expect(result.reason).toBe('sensitive_operation');
    });

    test('does not challenge normal requests', () => {
      const result = tfa.shouldChallenge(
        'What is the weather?',
        { trustLevel: 60, requiresVerification: false },
        0.1
      );
      expect(result.should).toBe(false);
    });
  });

  describe('Statistics', () => {
    test('returns challenge stats', () => {
      tfa.createChallenge('user1');
      tfa.createChallenge('user2');

      const storedChallenge = [...tfa.pendingChallenges.values()][0];
      tfa.verifyChallenge(storedChallenge.id, storedChallenge.code);

      const stats = tfa.getStats();
      expect(stats.total).toBe(2);
    });
  });

  describe('Cleanup', () => {
    test('cleans up expired challenges', () => {
      const challenge = tfa.createChallenge('user123');
      const storedChallenge = tfa.pendingChallenges.get(challenge.challengeId);
      storedChallenge.expiresAt = Date.now() - 1000;

      tfa.cleanup();
      expect(tfa.pendingChallenges.has(challenge.challengeId)).toBe(false);
    });
  });
});
