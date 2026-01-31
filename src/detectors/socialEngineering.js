/**
 * Social Engineering Detector
 * Recognizes manipulation tactics
 */

class SocialEngineeringDetector {
  constructor(config) {
    this.config = config;
    this.type = 'social_engineering';

    this.patterns = {
      authorityImpersonation: {
        weight: 0.85,
        patterns: [
          /i('m|\s+am)\s+(your\s+)?(developer|creator|admin|owner|maintainer)/i,
          /this\s+is\s+(an?\s+)?(admin|developer|official)\s+(request|command|override)/i,
          /speaking\s+(as|on\s+behalf\s+of)\s+(the\s+)?(admin|developer|owner)/i,
          /admin(istrator)?\s+(here|speaking|override)/i,
          /official\s+(anthropic|openai|clawdbot)\s+(request|message)/i,
          /by\s+order\s+of\s+(the\s+)?(admin|developer|system)/i
        ]
      },
      urgencyPressure: {
        weight: 0.6,
        patterns: [
          /this\s+is\s+(an?\s+)?(emergency|urgent|critical)/i,
          /do\s+(it|this)\s+(right\s+)?now/i,
          /immediately|asap|right\s+away/i,
          /no\s+time\s+to\s+explain/i,
          /lives?\s+(are|is)\s+(at\s+stake|depending|on\s+the\s+line)/i,
          /hurry(\s+up)?/i,
          /quick(ly)?,?\s+(just\s+)?(do|tell|give)/i
        ]
      },
      emotionalManipulation: {
        weight: 0.5,
        patterns: [
          /if\s+you\s+(really\s+)?(cared?|were\s+helpful)/i,
          /you('re|\s+are)\s+(supposed\s+to|meant\s+to)\s+(help|assist)/i,
          /why\s+(won't|can't|don't)\s+you\s+(just\s+)?help/i,
          /please,?\s+i('m)?\s+(begging|desperate)/i,
          /you('re|\s+are)\s+my\s+only\s+hope/i,
          /i\s+thought\s+you\s+were\s+(helpful|smart|capable)/i,
          /other\s+(ai|assistants?|bots?)\s+(can|would)\s+do\s+this/i
        ]
      },
      trustBuilding: {
        weight: 0.4,
        patterns: [
          /between\s+(you\s+and\s+me|us)/i,
          /i\s+trust\s+you/i,
          /we('re|\s+are)\s+friends?,?\s+(right|aren't\s+we)/i,
          /you\s+can\s+trust\s+me/i,
          /this\s+(stays|is)\s+between\s+us/i,
          /off\s+the\s+record/i,
          /don't\s+tell\s+anyone/i
        ]
      },
      gaslighting: {
        weight: 0.7,
        patterns: [
          /you\s+(always|usually)\s+(do|did|have\s+done)\s+this/i,
          /you\s+told\s+me\s+(before|earlier|yesterday)\s+that/i,
          /last\s+time\s+you\s+(said|did|agreed)/i,
          /you('ve)?\s+already\s+(agreed|said\s+yes|approved)/i,
          /don't\s+you\s+remember\s+(saying|agreeing|telling)/i,
          /you\s+promised/i
        ]
      },
      reciprocity: {
        weight: 0.45,
        patterns: [
          /i('ve)?\s+(helped|done\s+(so\s+)?much\s+for)\s+you/i,
          /after\s+(all|everything)\s+i('ve)?\s+done/i,
          /you\s+owe\s+me/i,
          /return\s+the\s+favor/i,
          /i\s+(always\s+)?help\s+you,?\s+(so\s+)?now/i
        ]
      }
    };
  }

  /**
   * Detect social engineering attempts
   */
  async detect(message, state) {
    const matchedPatterns = [];
    let totalWeight = 0;
    const categoriesMatched = new Set();

    const normalized = message.toLowerCase();

    for (const [category, { weight, patterns }] of Object.entries(this.patterns)) {
      for (const pattern of patterns) {
        if (pattern.test(normalized)) {
          matchedPatterns.push({
            category,
            pattern: pattern.source,
            weight
          });
          categoriesMatched.add(category);
          totalWeight += weight;
        }
      }
    }

    // Multi-tactic bonus: combining tactics is more suspicious
    let confidence = Math.min(1.0, totalWeight);
    if (categoriesMatched.size >= 2) {
      confidence = Math.min(1.0, confidence * 1.5);
    }
    if (categoriesMatched.size >= 3) {
      confidence = Math.min(1.0, confidence * 1.3);
    }

    // Check escalation pattern in conversation
    const escalationScore = this.detectEscalation(state);
    if (escalationScore > 0) {
      matchedPatterns.push({
        category: 'escalation',
        pattern: 'request_escalation',
        weight: escalationScore
      });
      confidence = Math.min(1.0, confidence + escalationScore);
    }

    return {
      detected: matchedPatterns.length > 0,
      confidence,
      patterns: matchedPatterns,
      details: {
        categoriesMatched: Array.from(categoriesMatched),
        escalationDetected: escalationScore > 0
      }
    };
  }

  /**
   * Detect escalating request patterns over conversation
   */
  detectEscalation(state) {
    const history = state.getRecentMessages(5);
    if (history.length < 3) return 0;

    // Look for pattern of increasingly sensitive requests
    let sensitivityTrend = 0;
    let previousSensitivity = 0;

    for (const msg of history) {
      const sensitivity = this.estimateSensitivity(msg.content);
      if (sensitivity > previousSensitivity) {
        sensitivityTrend++;
      }
      previousSensitivity = sensitivity;
    }

    // If requests are consistently escalating
    if (sensitivityTrend >= history.length - 1) {
      return 0.4;
    }

    return 0;
  }

  /**
   * Estimate sensitivity level of a request
   */
  estimateSensitivity(message) {
    const lower = message.toLowerCase();
    let score = 0;

    // Sensitive keywords
    if (/password|credential|secret|key|token/i.test(lower)) score += 3;
    if (/admin|root|sudo|system/i.test(lower)) score += 2;
    if (/delete|remove|destroy|wipe/i.test(lower)) score += 2;
    if (/private|confidential|internal/i.test(lower)) score += 1;
    if (/access|permission|authorize/i.test(lower)) score += 1;

    return score;
  }
}

module.exports = SocialEngineeringDetector;
