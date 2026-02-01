/**
 * Trust Manager
 * Distinguishes between trusted and non-trusted prompts/data sources
 * Implements trust levels and verification mechanisms
 */

class TrustManager {
  constructor(config = {}) {
    this.config = config;

    // Trust levels
    this.TRUST_LEVELS = {
      SYSTEM: 100,      // Internal system messages
      VERIFIED: 80,     // Verified/authenticated user
      KNOWN: 60,        // Known user with history
      NEW: 40,          // New but authenticated user
      ANONYMOUS: 20,    // Anonymous user
      UNTRUSTED: 0      // External data, files, web scrapes
    };

    // Trust registry
    this.trustedSources = new Map();
    this.verifiedUsers = new Map();

    // Content type trust modifiers
    this.contentTypeModifiers = {
      'direct_input': 1.0,      // User typing directly
      'file_content': 0.5,      // Content from files
      'web_scrape': 0.3,        // Content from web
      'api_response': 0.4,      // Content from external APIs
      'email': 0.2,             // Email content
      'attachment': 0.1,        // Attachments
      'user_data': 0.6,         // User's own data
      'third_party': 0.3,       // Third-party integrations
      'cached': 0.7,            // Previously verified cached content
      'system_prompt': 1.0      // System prompts
    };

    // Suspicious content patterns that reduce trust
    this.suspiciousPatterns = [
      { pattern: /\[SYSTEM\]/i, penalty: 0.7, reason: 'fake_system_tag' },
      { pattern: /\[ADMIN\]/i, penalty: 0.7, reason: 'fake_admin_tag' },
      { pattern: /<<.*?>>/i, penalty: 0.5, reason: 'delimiter_injection' },
      { pattern: /```system/i, penalty: 0.6, reason: 'code_block_system' },
      { pattern: /role:\s*system/i, penalty: 0.8, reason: 'role_injection' },
      { pattern: /\bignore\s+(previous|above|all)\s+instructions?\b/i, penalty: 0.9, reason: 'instruction_override' },
      { pattern: /\bact\s+as\s+(if|though)\s+you\s+are\b/i, penalty: 0.5, reason: 'roleplay_manipulation' }
    ];
  }

  /**
   * Evaluate trust level for a piece of content
   */
  evaluateTrust(content, context = {}) {
    const evaluation = {
      trustLevel: this.TRUST_LEVELS.ANONYMOUS,
      trustScore: 0.5,
      contentType: context.contentType || 'direct_input',
      source: context.source || 'unknown',
      userId: context.userId || null,
      flags: [],
      verified: false,
      requiresVerification: false
    };

    // Start with base trust from source
    let baseTrust = this.getSourceTrust(context);

    // Apply content type modifier
    const typeModifier = this.contentTypeModifiers[evaluation.contentType] || 0.5;
    let adjustedTrust = baseTrust * typeModifier;

    // Check for suspicious patterns
    const patternPenalties = this.checkSuspiciousPatterns(content);
    for (const penalty of patternPenalties) {
      adjustedTrust *= penalty.penalty;
      evaluation.flags.push(penalty.reason);
    }

    // Check user verification status
    if (context.userId) {
      const userVerification = this.verifiedUsers.get(context.userId);
      if (userVerification && userVerification.verified) {
        adjustedTrust = Math.min(1, adjustedTrust * 1.3);
        evaluation.verified = true;
      }
    }

    // Determine trust level
    evaluation.trustScore = Math.max(0, Math.min(1, adjustedTrust));
    evaluation.trustLevel = this.scoreToLevel(evaluation.trustScore);

    // Determine if verification is needed
    evaluation.requiresVerification = this.shouldRequireVerification(evaluation, content);

    return evaluation;
  }

  /**
   * Get base trust from source
   */
  getSourceTrust(context) {
    // System source
    if (context.isSystem) {
      return 1.0;
    }

    // Registered trusted source
    if (context.source && this.trustedSources.has(context.source)) {
      return this.trustedSources.get(context.source).trustScore;
    }

    // User-based trust
    if (context.userId) {
      if (this.verifiedUsers.has(context.userId)) {
        const user = this.verifiedUsers.get(context.userId);
        return user.verified ? 0.8 : 0.5;
      }
      // Known but not verified
      return 0.4;
    }

    // External/unknown source
    return 0.2;
  }

  /**
   * Check content for suspicious patterns
   */
  checkSuspiciousPatterns(content) {
    const matches = [];

    for (const { pattern, penalty, reason } of this.suspiciousPatterns) {
      if (pattern.test(content)) {
        matches.push({ pattern: pattern.source, penalty, reason });
      }
    }

    return matches;
  }

  /**
   * Convert score to trust level
   */
  scoreToLevel(score) {
    if (score >= 0.9) return this.TRUST_LEVELS.SYSTEM;
    if (score >= 0.75) return this.TRUST_LEVELS.VERIFIED;
    if (score >= 0.55) return this.TRUST_LEVELS.KNOWN;
    if (score >= 0.35) return this.TRUST_LEVELS.NEW;
    if (score >= 0.15) return this.TRUST_LEVELS.ANONYMOUS;
    return this.TRUST_LEVELS.UNTRUSTED;
  }

  /**
   * Determine if content requires verification
   */
  shouldRequireVerification(evaluation, content) {
    // Always require verification for untrusted content with sensitive requests
    if (evaluation.trustLevel <= this.TRUST_LEVELS.ANONYMOUS) {
      const sensitivePatterns = [
        /password|secret|credential|api.?key/i,
        /admin|root|sudo|execute/i,
        /delete|remove|modify|change/i,
        /access|permission|privilege/i,
        /user|account|profile/i
      ];

      for (const pattern of sensitivePatterns) {
        if (pattern.test(content)) {
          return true;
        }
      }
    }

    // Require verification if suspicious flags found
    if (evaluation.flags.length >= 2) {
      return true;
    }

    return false;
  }

  /**
   * Register a trusted source
   */
  registerTrustedSource(sourceId, options = {}) {
    this.trustedSources.set(sourceId, {
      sourceId,
      trustScore: options.trustScore || 0.8,
      description: options.description || '',
      addedAt: Date.now(),
      expiresAt: options.expiresAt || null
    });
  }

  /**
   * Revoke trust from a source
   */
  revokeTrust(sourceId) {
    this.trustedSources.delete(sourceId);
  }

  /**
   * Register a verified user
   */
  registerVerifiedUser(userId, verificationData = {}) {
    this.verifiedUsers.set(userId, {
      userId,
      verified: true,
      verifiedAt: Date.now(),
      method: verificationData.method || 'manual',
      expiresAt: verificationData.expiresAt || null,
      trustBoost: verificationData.trustBoost || 0.3
    });
  }

  /**
   * Mark user as needing re-verification
   */
  requireReVerification(userId) {
    const user = this.verifiedUsers.get(userId);
    if (user) {
      user.verified = false;
      user.needsReVerification = true;
    }
  }

  /**
   * Check if user is verified
   */
  isUserVerified(userId) {
    const user = this.verifiedUsers.get(userId);
    if (!user) return false;

    // Check expiration
    if (user.expiresAt && Date.now() > user.expiresAt) {
      user.verified = false;
      return false;
    }

    return user.verified;
  }

  /**
   * Wrap content with trust context
   */
  wrapWithTrust(content, context = {}) {
    const evaluation = this.evaluateTrust(content, context);

    return {
      content,
      trust: evaluation,
      isTrusted: evaluation.trustLevel >= this.TRUST_LEVELS.KNOWN,
      shouldProcess: evaluation.trustLevel >= this.TRUST_LEVELS.ANONYMOUS,
      warningLevel: this.getWarningLevel(evaluation)
    };
  }

  /**
   * Get warning level for UI/logging
   */
  getWarningLevel(evaluation) {
    if (evaluation.trustLevel >= this.TRUST_LEVELS.VERIFIED) return 'none';
    if (evaluation.trustLevel >= this.TRUST_LEVELS.KNOWN) return 'low';
    if (evaluation.trustLevel >= this.TRUST_LEVELS.NEW) return 'medium';
    if (evaluation.trustLevel >= this.TRUST_LEVELS.ANONYMOUS) return 'high';
    return 'critical';
  }

  /**
   * Separate trusted and untrusted parts of a message
   */
  separateContent(message, markers = {}) {
    const result = {
      trustedParts: [],
      untrustedParts: [],
      mixed: false
    };

    // Look for embedded content markers
    const filePattern = /```file:([^\n]+)\n([\s\S]*?)```/g;
    const webPattern = /\[web:([^\]]+)\]([\s\S]*?)\[\/web\]/g;
    const quotePattern = />{1,2}\s+(.+)/gm;

    let lastIndex = 0;
    let match;

    // Extract file content (untrusted)
    while ((match = filePattern.exec(message)) !== null) {
      if (match.index > lastIndex) {
        result.trustedParts.push({
          content: message.slice(lastIndex, match.index),
          type: 'direct'
        });
      }
      result.untrustedParts.push({
        content: match[2],
        type: 'file',
        source: match[1]
      });
      lastIndex = match.index + match[0].length;
      result.mixed = true;
    }

    // Add remaining content as trusted
    if (lastIndex < message.length) {
      result.trustedParts.push({
        content: message.slice(lastIndex),
        type: 'direct'
      });
    }

    return result;
  }

  /**
   * Get trust statistics
   */
  getStats() {
    return {
      trustedSources: this.trustedSources.size,
      verifiedUsers: [...this.verifiedUsers.values()].filter(u => u.verified).length,
      totalUsers: this.verifiedUsers.size
    };
  }

  /**
   * Clear all trust data (for testing)
   */
  clear() {
    this.trustedSources.clear();
    this.verifiedUsers.clear();
  }
}

module.exports = TrustManager;
