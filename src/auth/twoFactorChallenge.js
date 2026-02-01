/**
 * Two-Factor Challenge System
 * Implements verification challenges for suspicious requests
 * Ensures we're talking to the actual user for sensitive operations
 */

const crypto = require('crypto');

class TwoFactorChallenge {
  constructor(config = {}) {
    this.config = config;

    // Pending challenges
    this.pendingChallenges = new Map();

    // Challenge settings
    this.settings = {
      challengeTimeout: config.challengeTimeout || 5 * 60 * 1000,  // 5 minutes
      maxAttempts: config.maxAttempts || 3,
      codeLength: config.codeLength || 6,
      questionCount: config.questionCount || 2,
      ...config.settings
    };

    // Challenge types
    this.CHALLENGE_TYPES = {
      CODE: 'code',              // Numeric/alphanumeric code
      QUESTION: 'question',       // Contextual question
      CAPTCHA: 'captcha',        // Image/text CAPTCHA
      CALLBACK: 'callback',       // External callback (email, SMS, etc.)
      PASSPHRASE: 'passphrase'   // User-defined passphrase
    };

    // Contextual questions for challenge
    this.contextualQuestions = [
      { q: 'What was your last message about?', type: 'memory' },
      { q: 'What is the current project you are working on?', type: 'context' },
      { q: 'How did you start this conversation?', type: 'memory' },
      { q: 'What time zone are you in?', type: 'identity' },
      { q: 'What was the topic of your previous session?', type: 'memory' },
      { q: 'What feature are you currently implementing?', type: 'context' },
      { q: 'What is the name of this project?', type: 'context' },
      { q: 'What was the last file you edited?', type: 'activity' }
    ];
  }

  /**
   * Create a new challenge for a user
   */
  createChallenge(userId, options = {}) {
    const challengeType = options.type || this.CHALLENGE_TYPES.CODE;
    const challenge = {
      id: this.generateChallengeId(),
      userId,
      type: challengeType,
      createdAt: Date.now(),
      expiresAt: Date.now() + this.settings.challengeTimeout,
      attempts: 0,
      maxAttempts: options.maxAttempts || this.settings.maxAttempts,
      verified: false,
      reason: options.reason || 'suspicious_request',
      suspiciousContent: options.suspiciousContent || null
    };

    // Generate challenge data based on type
    switch (challengeType) {
      case this.CHALLENGE_TYPES.CODE:
        challenge.code = this.generateCode();
        challenge.displayCode = this.formatCodeForDisplay(challenge.code);
        break;

      case this.CHALLENGE_TYPES.QUESTION:
        challenge.questions = this.selectQuestions(options.conversationContext);
        break;

      case this.CHALLENGE_TYPES.PASSPHRASE:
        challenge.expectedPassphrase = options.passphrase;
        challenge.hint = options.passphraseHint || 'Enter your security passphrase';
        break;

      case this.CHALLENGE_TYPES.CALLBACK:
        challenge.callbackId = this.generateCallbackId();
        challenge.callbackMethod = options.callbackMethod || 'email';
        break;
    }

    this.pendingChallenges.set(challenge.id, challenge);

    return {
      challengeId: challenge.id,
      type: challenge.type,
      expiresAt: challenge.expiresAt,
      prompt: this.getChallengePrompt(challenge),
      displayCode: challenge.displayCode
    };
  }

  /**
   * Verify a challenge response
   */
  verifyChallenge(challengeId, response, context = {}) {
    const challenge = this.pendingChallenges.get(challengeId);

    if (!challenge) {
      return {
        success: false,
        error: 'challenge_not_found',
        message: 'Challenge not found or expired'
      };
    }

    // Check expiration
    if (Date.now() > challenge.expiresAt) {
      this.pendingChallenges.delete(challengeId);
      return {
        success: false,
        error: 'challenge_expired',
        message: 'Challenge has expired. Please request a new one.'
      };
    }

    // Check attempts
    challenge.attempts++;
    if (challenge.attempts > challenge.maxAttempts) {
      this.pendingChallenges.delete(challengeId);
      return {
        success: false,
        error: 'max_attempts',
        message: 'Maximum attempts exceeded. Please request a new challenge.'
      };
    }

    // Verify based on type
    let verified = false;
    switch (challenge.type) {
      case this.CHALLENGE_TYPES.CODE:
        verified = this.verifyCode(challenge.code, response);
        break;

      case this.CHALLENGE_TYPES.QUESTION:
        verified = this.verifyQuestions(challenge.questions, response, context);
        break;

      case this.CHALLENGE_TYPES.PASSPHRASE:
        verified = this.verifyPassphrase(challenge.expectedPassphrase, response);
        break;

      case this.CHALLENGE_TYPES.CALLBACK:
        verified = this.verifyCallback(challenge.callbackId, response);
        break;
    }

    if (verified) {
      challenge.verified = true;
      challenge.verifiedAt = Date.now();

      // Keep challenge around briefly for audit
      setTimeout(() => this.pendingChallenges.delete(challengeId), 60000);

      return {
        success: true,
        message: 'Verification successful',
        userId: challenge.userId
      };
    }

    return {
      success: false,
      error: 'verification_failed',
      message: `Verification failed. ${challenge.maxAttempts - challenge.attempts} attempts remaining.`,
      attemptsRemaining: challenge.maxAttempts - challenge.attempts
    };
  }

  /**
   * Generate verification code
   */
  generateCode() {
    const chars = '0123456789';
    let code = '';
    for (let i = 0; i < this.settings.codeLength; i++) {
      code += chars[crypto.randomInt(chars.length)];
    }
    return code;
  }

  /**
   * Format code for display (with spaces for readability)
   */
  formatCodeForDisplay(code) {
    if (code.length <= 4) return code;
    const mid = Math.floor(code.length / 2);
    return code.slice(0, mid) + ' ' + code.slice(mid);
  }

  /**
   * Verify code response
   */
  verifyCode(expected, response) {
    const normalized = response.replace(/\s+/g, '').trim();
    return normalized === expected;
  }

  /**
   * Select contextual questions
   */
  selectQuestions(conversationContext = {}) {
    const questions = [];
    const available = [...this.contextualQuestions];

    // Shuffle and pick
    for (let i = 0; i < this.settings.questionCount && available.length > 0; i++) {
      const idx = crypto.randomInt(available.length);
      const q = available.splice(idx, 1)[0];

      // Add context-specific hints if available
      const question = {
        ...q,
        id: crypto.randomBytes(8).toString('hex'),
        expectedAnswer: null  // Would be filled from context
      };

      // Try to generate expected answers from context
      if (conversationContext.recentMessages && q.type === 'memory') {
        question.hint = 'Think about your recent conversation';
      }

      questions.push(question);
    }

    return questions;
  }

  /**
   * Verify question responses
   * Uses fuzzy matching since exact answers are hard
   */
  verifyQuestions(questions, responses, context) {
    if (!Array.isArray(responses)) {
      responses = [responses];
    }

    // For now, we use simple presence verification
    // In production, this would use NLP/LLM to verify semantic correctness

    let correctCount = 0;
    for (let i = 0; i < questions.length; i++) {
      const response = responses[i] || '';

      // Check if response is substantive (not empty, not single word)
      if (response.length > 10 && response.split(/\s+/).length >= 3) {
        correctCount++;
      }
    }

    // Require majority correct
    return correctCount >= Math.ceil(questions.length / 2);
  }

  /**
   * Verify passphrase
   */
  verifyPassphrase(expected, response) {
    if (!expected) return false;

    // Constant-time comparison to prevent timing attacks
    const expectedBuffer = Buffer.from(expected);
    const responseBuffer = Buffer.from(response);

    if (expectedBuffer.length !== responseBuffer.length) {
      return false;
    }

    return crypto.timingSafeEqual(expectedBuffer, responseBuffer);
  }

  /**
   * Generate callback ID for external verification
   */
  generateCallbackId() {
    return crypto.randomBytes(16).toString('hex');
  }

  /**
   * Verify callback (external verification like email link click)
   */
  verifyCallback(expectedCallbackId, providedCallbackId) {
    return expectedCallbackId === providedCallbackId;
  }

  /**
   * Generate challenge ID
   */
  generateChallengeId() {
    return 'chal_' + crypto.randomBytes(12).toString('hex');
  }

  /**
   * Get challenge prompt for user
   */
  getChallengePrompt(challenge) {
    switch (challenge.type) {
      case this.CHALLENGE_TYPES.CODE:
        return {
          title: 'Verification Required',
          message: `To proceed with this request, please enter the code shown above.`,
          instruction: 'Enter the 6-digit code:',
          type: 'input'
        };

      case this.CHALLENGE_TYPES.QUESTION:
        return {
          title: 'Identity Verification',
          message: 'Please answer the following questions to verify your identity:',
          questions: challenge.questions.map(q => q.q),
          type: 'questions'
        };

      case this.CHALLENGE_TYPES.PASSPHRASE:
        return {
          title: 'Passphrase Required',
          message: challenge.hint,
          instruction: 'Enter your passphrase:',
          type: 'password'
        };

      case this.CHALLENGE_TYPES.CALLBACK:
        return {
          title: 'External Verification',
          message: `A verification link has been sent to your ${challenge.callbackMethod}. Please click it to continue.`,
          instruction: 'Waiting for verification...',
          type: 'callback'
        };

      default:
        return {
          title: 'Verification Required',
          message: 'Please complete the verification to proceed.',
          type: 'unknown'
        };
    }
  }

  /**
   * Check if a request should trigger 2FA
   */
  shouldChallenge(request, trustEvaluation, threatScore) {
    // Always challenge untrusted sources with high threat score
    if (trustEvaluation.trustLevel <= 20 && threatScore > 0.6) {
      return {
        should: true,
        reason: 'untrusted_high_threat',
        suggestedType: this.CHALLENGE_TYPES.CODE
      };
    }

    // Challenge sensitive operations
    const sensitivePatterns = [
      { pattern: /delete|remove|destroy/i, type: this.CHALLENGE_TYPES.CODE },
      { pattern: /password|credential|secret|api.?key/i, type: this.CHALLENGE_TYPES.CODE },
      { pattern: /admin|root|sudo|superuser/i, type: this.CHALLENGE_TYPES.QUESTION },
      { pattern: /execute|run\s+command|shell|bash/i, type: this.CHALLENGE_TYPES.CODE },
      { pattern: /transfer|send\s+money|payment/i, type: this.CHALLENGE_TYPES.CODE },
      { pattern: /access\s+.*\s+data|export\s+data/i, type: this.CHALLENGE_TYPES.QUESTION }
    ];

    for (const { pattern, type } of sensitivePatterns) {
      if (pattern.test(request)) {
        return {
          should: true,
          reason: 'sensitive_operation',
          suggestedType: type
        };
      }
    }

    // Challenge if trust requires verification
    if (trustEvaluation.requiresVerification) {
      return {
        should: true,
        reason: 'trust_verification_required',
        suggestedType: this.CHALLENGE_TYPES.QUESTION
      };
    }

    return { should: false };
  }

  /**
   * Get pending challenge for user
   */
  getPendingChallenge(userId) {
    for (const [id, challenge] of this.pendingChallenges) {
      if (challenge.userId === userId && !challenge.verified && Date.now() < challenge.expiresAt) {
        return {
          challengeId: id,
          type: challenge.type,
          expiresAt: challenge.expiresAt,
          attempts: challenge.attempts,
          maxAttempts: challenge.maxAttempts
        };
      }
    }
    return null;
  }

  /**
   * Cancel a pending challenge
   */
  cancelChallenge(challengeId) {
    return this.pendingChallenges.delete(challengeId);
  }

  /**
   * Clean up expired challenges
   */
  cleanup() {
    const now = Date.now();
    for (const [id, challenge] of this.pendingChallenges) {
      if (now > challenge.expiresAt) {
        this.pendingChallenges.delete(id);
      }
    }
  }

  /**
   * Get challenge statistics
   */
  getStats() {
    let pending = 0;
    let verified = 0;
    let expired = 0;
    const now = Date.now();

    for (const challenge of this.pendingChallenges.values()) {
      if (challenge.verified) {
        verified++;
      } else if (now > challenge.expiresAt) {
        expired++;
      } else {
        pending++;
      }
    }

    return { pending, verified, expired, total: this.pendingChallenges.size };
  }

  /**
   * Clear all challenges (for testing)
   */
  clear() {
    this.pendingChallenges.clear();
  }
}

module.exports = TwoFactorChallenge;
