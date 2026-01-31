/**
 * Threat Scorer
 * Calculates cumulative threat scores from detections
 */

class ThreatScorer {
  constructor(config) {
    this.config = config;

    // Base scores for each detection type
    this.baseScores = {
      prompt_injection: 30,
      social_engineering: 20,
      privilege_escalation: 40,
      data_exfiltration: 35
    };

    // Multipliers for repeated patterns
    this.repeatMultiplier = 1.5;

    // Multiplier for combined tactics
    this.combinedMultiplier = 1.3;
  }

  /**
   * Calculate threat score from detections
   * @param {Array} detections - Detection results from pipeline
   * @param {ConversationState} state - Current conversation state
   * @returns {Object} Score result with level and breakdown
   */
  calculate(detections, state) {
    if (detections.length === 0) {
      return {
        score: state.getThreatScore(),
        level: this.getLevel(state.getThreatScore()),
        detections: [],
        breakdown: {}
      };
    }

    const breakdown = {};
    let additionalScore = 0;

    // Calculate score for each detection
    for (const detection of detections) {
      const baseScore = this.baseScores[detection.type] || 20;
      let score = baseScore * detection.confidence;

      // Apply repeat multiplier if this type was seen before
      if (state.hasRepeatedPatterns(detection.type)) {
        score *= this.repeatMultiplier;
      }

      breakdown[detection.type] = {
        baseScore,
        confidence: detection.confidence,
        multiplied: state.hasRepeatedPatterns(detection.type),
        finalScore: score
      };

      additionalScore += score;
    }

    // Apply combined tactics multiplier
    const uniqueTypes = new Set(detections.map(d => d.type));
    if (uniqueTypes.size >= 2) {
      additionalScore *= this.combinedMultiplier;
      breakdown.combinedBonus = {
        multiplier: this.combinedMultiplier,
        reason: `${uniqueTypes.size} different attack types detected`
      };
    }

    // Add rapid-fire penalty
    const rapidFirePenalty = this.calculateRapidFirePenalty(state);
    if (rapidFirePenalty > 0) {
      additionalScore += rapidFirePenalty;
      breakdown.rapidFire = {
        penalty: rapidFirePenalty,
        reason: 'High message frequency detected'
      };
    }

    // Calculate new cumulative score with decay
    const decayedScore = this.applyDecay(state.getThreatScore(), state);
    const newScore = Math.min(100, decayedScore + additionalScore);

    return {
      score: newScore,
      level: this.getLevel(newScore),
      detections,
      breakdown,
      previousScore: state.getThreatScore(),
      added: additionalScore
    };
  }

  /**
   * Get threat level from score
   */
  getLevel(score) {
    const thresholds = this.config.thresholds;

    if (score >= thresholds.block) return 'critical';
    if (score >= thresholds.alert) return 'high';
    if (score >= thresholds.honeypot) return 'medium';
    if (score >= thresholds.monitor) return 'low';
    return 'none';
  }

  /**
   * Calculate penalty for rapid-fire messages
   */
  calculateRapidFirePenalty(state) {
    const recentMessages = state.getRecentMessages(10);
    if (recentMessages.length < 5) return 0;

    // Check time between messages
    const timestamps = recentMessages.map(m => m.timestamp);
    let rapidCount = 0;

    for (let i = 1; i < timestamps.length; i++) {
      const gap = timestamps[i] - timestamps[i - 1];
      if (gap < 2000) { // Less than 2 seconds
        rapidCount++;
      }
    }

    // Penalty increases with rapid-fire frequency
    if (rapidCount >= 4) return 15;
    if (rapidCount >= 2) return 10;
    return 0;
  }

  /**
   * Apply decay to old threat score
   * Score decays over time if user behaves normally
   */
  applyDecay(currentScore, state) {
    const lastMessageTime = state.getLastMessageTime();
    if (!lastMessageTime) return currentScore;

    const timeSinceLastMessage = Date.now() - lastMessageTime;
    const decayInterval = 5 * 60 * 1000; // 5 minutes

    if (timeSinceLastMessage > decayInterval) {
      const decayPeriods = Math.floor(timeSinceLastMessage / decayInterval);
      const decayFactor = Math.pow(0.9, decayPeriods); // 10% decay per period
      return currentScore * decayFactor;
    }

    return currentScore;
  }
}

module.exports = ThreatScorer;
