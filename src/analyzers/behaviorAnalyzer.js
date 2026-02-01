/**
 * Behavior Analyzer
 * Tracks user interaction history and detects anomalous prompts
 * based on deviation from established patterns
 */

class BehaviorAnalyzer {
  constructor(config = {}) {
    this.type = 'behavior_analysis';
    this.config = config;

    // User behavior profiles stored in memory (use Redis/DB in production)
    this.userProfiles = new Map();

    // Default thresholds
    this.thresholds = {
      minHistorySize: 5,           // Min messages before profiling kicks in
      anomalyScoreThreshold: 0.7,  // Score above this is anomalous
      topicShiftThreshold: 0.6,    // Topic similarity below this is a shift
      lengthDeviationThreshold: 3, // Standard deviations for length anomaly
      complexityShiftThreshold: 2, // Complexity level change
      ...config.thresholds
    };
  }

  /**
   * Get or create user profile
   */
  getProfile(userId) {
    if (!this.userProfiles.has(userId)) {
      this.userProfiles.set(userId, {
        userId,
        messages: [],
        topicKeywords: new Map(),  // keyword -> frequency
        avgLength: 0,
        avgComplexity: 0,
        lengthVariance: 0,
        typicalPatterns: [],       // Common request patterns
        timePatterns: [],          // Typical interaction times
        lastSeen: null,
        createdAt: Date.now()
      });
    }
    return this.userProfiles.get(userId);
  }

  /**
   * Analyze a message for behavioral anomalies
   */
  async analyze(message, userId, state = null) {
    const profile = this.getProfile(userId);
    const analysis = {
      detected: false,
      confidence: 0,
      anomalies: [],
      details: {},
      profileMaturity: profile.messages.length
    };

    // Not enough history to establish baseline
    if (profile.messages.length < this.thresholds.minHistorySize) {
      this.updateProfile(profile, message);
      return analysis;
    }

    // Run anomaly checks
    const lengthAnomaly = this.checkLengthAnomaly(message, profile);
    const complexityAnomaly = this.checkComplexityAnomaly(message, profile);
    const topicAnomaly = this.checkTopicAnomaly(message, profile);
    const patternAnomaly = this.checkPatternAnomaly(message, profile);
    const timingAnomaly = this.checkTimingAnomaly(profile);
    const styleAnomaly = this.checkStyleAnomaly(message, profile);

    // Collect anomalies
    const anomalies = [
      lengthAnomaly,
      complexityAnomaly,
      topicAnomaly,
      patternAnomaly,
      timingAnomaly,
      styleAnomaly
    ].filter(a => a.detected);

    if (anomalies.length > 0) {
      // Calculate overall score
      const weightedScore = anomalies.reduce((sum, a) => sum + a.score * a.weight, 0);
      const totalWeight = anomalies.reduce((sum, a) => sum + a.weight, 0);
      const overallScore = weightedScore / totalWeight;

      analysis.detected = overallScore >= this.thresholds.anomalyScoreThreshold;
      analysis.confidence = overallScore;
      analysis.anomalies = anomalies.map(a => ({
        type: a.type,
        score: a.score,
        description: a.description
      }));
      analysis.details = {
        lengthAnomaly,
        complexityAnomaly,
        topicAnomaly,
        patternAnomaly,
        timingAnomaly,
        styleAnomaly
      };
    }

    // Update profile with this message
    this.updateProfile(profile, message);

    return analysis;
  }

  /**
   * Check if message length is unusual for this user
   */
  checkLengthAnomaly(message, profile) {
    const result = {
      type: 'length_anomaly',
      detected: false,
      score: 0,
      weight: 0.6,
      description: ''
    };

    if (profile.lengthVariance === 0) return result;

    const stdDev = Math.sqrt(profile.lengthVariance);
    const zScore = Math.abs(message.length - profile.avgLength) / stdDev;

    if (zScore > this.thresholds.lengthDeviationThreshold) {
      result.detected = true;
      result.score = Math.min(1, zScore / 5);
      result.description = message.length > profile.avgLength
        ? `Message is ${(zScore).toFixed(1)}x longer than usual`
        : `Message is ${(zScore).toFixed(1)}x shorter than usual`;
    }

    return result;
  }

  /**
   * Check if message complexity is unusual
   */
  checkComplexityAnomaly(message, profile) {
    const result = {
      type: 'complexity_anomaly',
      detected: false,
      score: 0,
      weight: 0.7,
      description: ''
    };

    const complexity = this.calculateComplexity(message);
    const deviation = Math.abs(complexity - profile.avgComplexity);

    if (deviation > this.thresholds.complexityShiftThreshold) {
      result.detected = true;
      result.score = Math.min(1, deviation / 4);
      result.description = complexity > profile.avgComplexity
        ? 'Message complexity is significantly higher than usual'
        : 'Message complexity is significantly lower than usual';
    }

    return result;
  }

  /**
   * Check if message topic differs significantly from user's usual topics
   */
  checkTopicAnomaly(message, profile) {
    const result = {
      type: 'topic_anomaly',
      detected: false,
      score: 0,
      weight: 0.9,
      description: ''
    };

    const keywords = this.extractKeywords(message);
    const topKeywords = this.getTopKeywords(profile, 20);

    if (topKeywords.size === 0) return result;

    // Calculate overlap with user's typical topics
    let overlapCount = 0;
    for (const keyword of keywords) {
      if (topKeywords.has(keyword)) {
        overlapCount++;
      }
    }

    const similarity = keywords.size > 0 ? overlapCount / keywords.size : 1;

    if (similarity < this.thresholds.topicShiftThreshold) {
      result.detected = true;
      result.score = 1 - similarity;
      result.description = `Message discusses unusual topics (${Math.round(similarity * 100)}% topic overlap)`;
    }

    return result;
  }

  /**
   * Check if message pattern differs from user's typical patterns
   */
  checkPatternAnomaly(message, profile) {
    const result = {
      type: 'pattern_anomaly',
      detected: false,
      score: 0,
      weight: 0.8,
      description: ''
    };

    // Detect sudden shift to command-like patterns
    const isCommandLike = /^(ignore|forget|disregard|override|execute|run|sudo|admin)/i.test(message);
    const hasInstructions = /(instructions?|commands?|rules?|guidelines?)/i.test(message);
    const hasSensitiveRequest = /(password|secret|key|token|credential|api.?key)/i.test(message);

    // Check if these patterns are unusual for this user
    const usuallyCommandLike = profile.typicalPatterns.includes('command');
    const usuallyTechnical = profile.typicalPatterns.includes('technical');

    if ((isCommandLike && !usuallyCommandLike) ||
        (hasSensitiveRequest && !usuallyTechnical)) {
      result.detected = true;
      result.score = 0.85;
      result.description = 'Message uses patterns unusual for this user';
    }

    return result;
  }

  /**
   * Check if interaction timing is unusual
   */
  checkTimingAnomaly(profile) {
    const result = {
      type: 'timing_anomaly',
      detected: false,
      score: 0,
      weight: 0.4,
      description: ''
    };

    if (!profile.lastSeen) return result;

    const now = Date.now();
    const hoursSinceLastSeen = (now - profile.lastSeen) / (1000 * 60 * 60);

    // If user hasn't been seen in a long time, flag for extra scrutiny
    if (hoursSinceLastSeen > 24 * 7) { // More than a week
      result.detected = true;
      result.score = 0.5;
      result.description = `User returning after ${Math.round(hoursSinceLastSeen / 24)} days`;
    }

    return result;
  }

  /**
   * Check if writing style differs from user's typical style
   */
  checkStyleAnomaly(message, profile) {
    const result = {
      type: 'style_anomaly',
      detected: false,
      score: 0,
      weight: 0.5,
      description: ''
    };

    // Check capitalization style
    const hasAllCaps = /[A-Z]{5,}/.test(message);
    const hasExcessivePunctuation = /[!?]{3,}/.test(message);
    const hasUrgentTone = /\b(urgent|immediately|now|asap|quick)\b/i.test(message);

    // Compare to profile norms (simplified - would be more sophisticated in production)
    const urgencyScore = (hasAllCaps ? 0.3 : 0) +
                         (hasExcessivePunctuation ? 0.3 : 0) +
                         (hasUrgentTone ? 0.4 : 0);

    if (urgencyScore > 0.5) {
      result.detected = true;
      result.score = urgencyScore;
      result.description = 'Message style differs from user\'s typical communication';
    }

    return result;
  }

  /**
   * Update user profile with new message
   */
  updateProfile(profile, message) {
    const now = Date.now();
    const length = message.length;
    const complexity = this.calculateComplexity(message);
    const keywords = this.extractKeywords(message);

    // Add message to history (keep last 100)
    profile.messages.push({
      timestamp: now,
      length,
      complexity,
      keywords: [...keywords]
    });

    if (profile.messages.length > 100) {
      profile.messages.shift();
    }

    // Update rolling averages
    const n = profile.messages.length;
    const oldAvg = profile.avgLength;
    profile.avgLength = oldAvg + (length - oldAvg) / n;

    // Update variance (Welford's algorithm)
    const delta = length - oldAvg;
    const delta2 = length - profile.avgLength;
    profile.lengthVariance = profile.lengthVariance + (delta * delta2 - profile.lengthVariance) / n;

    profile.avgComplexity = profile.avgComplexity + (complexity - profile.avgComplexity) / n;

    // Update keyword frequencies
    for (const keyword of keywords) {
      const count = profile.topicKeywords.get(keyword) || 0;
      profile.topicKeywords.set(keyword, count + 1);
    }

    // Trim keywords map if too large
    if (profile.topicKeywords.size > 500) {
      const sorted = [...profile.topicKeywords.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 300);
      profile.topicKeywords = new Map(sorted);
    }

    // Update typical patterns
    this.updateTypicalPatterns(profile, message);

    profile.lastSeen = now;
  }

  /**
   * Update typical patterns based on message
   */
  updateTypicalPatterns(profile, message) {
    if (/^(help|can you|how do|what is|explain)/i.test(message)) {
      if (!profile.typicalPatterns.includes('question')) {
        profile.typicalPatterns.push('question');
      }
    }
    if (/(code|function|class|variable|api|http|json)/i.test(message)) {
      if (!profile.typicalPatterns.includes('technical')) {
        profile.typicalPatterns.push('technical');
      }
    }
    if (/^(run|execute|do|perform|make)/i.test(message)) {
      if (!profile.typicalPatterns.includes('command')) {
        profile.typicalPatterns.push('command');
      }
    }
  }

  /**
   * Calculate message complexity (vocabulary, structure, etc.)
   */
  calculateComplexity(message) {
    const words = message.split(/\s+/).filter(w => w.length > 0);
    if (words.length === 0) return 0;

    // Word length average
    const avgWordLength = words.reduce((s, w) => s + w.length, 0) / words.length;

    // Unique words ratio
    const uniqueRatio = new Set(words.map(w => w.toLowerCase())).size / words.length;

    // Punctuation density
    const punctuation = (message.match(/[.,;:!?'"()[\]{}]/g) || []).length;
    const punctDensity = punctuation / message.length;

    // Sentence count estimate
    const sentences = message.split(/[.!?]+/).filter(s => s.trim().length > 0);
    const wordsPerSentence = sentences.length > 0 ? words.length / sentences.length : words.length;

    // Combine into complexity score (0-10 scale)
    return Math.min(10,
      (avgWordLength / 2) +
      (uniqueRatio * 3) +
      (punctDensity * 10) +
      (Math.log2(wordsPerSentence + 1))
    );
  }

  /**
   * Extract keywords from message
   */
  extractKeywords(message) {
    const stopwords = new Set([
      'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
      'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could',
      'should', 'may', 'might', 'can', 'must', 'shall', 'to', 'of', 'in',
      'for', 'on', 'with', 'at', 'by', 'from', 'as', 'into', 'through',
      'during', 'before', 'after', 'above', 'below', 'between', 'under',
      'again', 'further', 'then', 'once', 'here', 'there', 'when', 'where',
      'why', 'how', 'all', 'each', 'few', 'more', 'most', 'other', 'some',
      'such', 'no', 'nor', 'not', 'only', 'own', 'same', 'so', 'than', 'too',
      'very', 'just', 'and', 'but', 'if', 'or', 'because', 'until', 'while',
      'this', 'that', 'these', 'those', 'what', 'which', 'who', 'whom',
      'i', 'me', 'my', 'myself', 'we', 'our', 'ours', 'ourselves', 'you',
      'your', 'yours', 'yourself', 'yourselves', 'he', 'him', 'his', 'himself',
      'she', 'her', 'hers', 'herself', 'it', 'its', 'itself', 'they', 'them',
      'their', 'theirs', 'themselves', 'please', 'thanks', 'thank', 'hello'
    ]);

    const words = message.toLowerCase()
      .replace(/[^a-z0-9\s]/g, ' ')
      .split(/\s+/)
      .filter(w => w.length > 2 && !stopwords.has(w));

    return new Set(words);
  }

  /**
   * Get top N keywords from profile
   */
  getTopKeywords(profile, n) {
    const sorted = [...profile.topicKeywords.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, n);
    return new Set(sorted.map(([k]) => k));
  }

  /**
   * Get user behavior summary
   */
  getProfileSummary(userId) {
    const profile = this.userProfiles.get(userId);
    if (!profile) {
      return { exists: false };
    }

    return {
      exists: true,
      messageCount: profile.messages.length,
      avgLength: Math.round(profile.avgLength),
      avgComplexity: profile.avgComplexity.toFixed(2),
      typicalPatterns: profile.typicalPatterns,
      topTopics: [...this.getTopKeywords(profile, 10)],
      lastSeen: profile.lastSeen,
      profileAge: Date.now() - profile.createdAt
    };
  }

  /**
   * Clear user profile
   */
  clearProfile(userId) {
    this.userProfiles.delete(userId);
  }

  /**
   * Get all profiles (for admin/debugging)
   */
  getAllProfiles() {
    return [...this.userProfiles.keys()];
  }
}

module.exports = BehaviorAnalyzer;
