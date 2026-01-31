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
          /i('m|\s+am)\s+(the\s+)?(your\s+)?(developer|creator|admin|owner|maintainer|ceo|boss)/i,
          /this\s+is\s+(an?\s+)?(admin|developer|official|authorized)\s+(request|command|override)/i,
          /speaking\s+(as|on\s+behalf\s+of)\s+(the\s+)?(admin|developer|owner|ceo|management)/i,
          /admin(istrator)?\s+(here|speaking|override|access)/i,
          /official\s+(anthropic|openai|clawdbot|google|microsoft)\s+(request|message)/i,
          /by\s+order\s+of\s+(the\s+)?(admin|developer|system|management|ceo)/i,
          /(developer|creator)\s+who\s+(created|made|built)\s+you/i,
          /i\s+work\s+(on|for|at)\s+(the\s+)?(ai\s+)?(safety|security|development)\s+team/i,
          /from\s+(the\s+)?(it|security|tech)\s+(department|team)/i,
          /security\s+(audit|test|verification|check)/i,
          /ceo\s+here/i,
          /supervisor\s+(ai|bot)?/i,
          /follow\s+my\s+instructions?\s+without\s+question/i,
          /override\s+code/i,
        ]
      },
      urgencyPressure: {
        weight: 0.6,
        patterns: [
          /this\s+is\s+(an?\s+)?(emergency|urgent|critical|time.?sensitive)/i,
          /do\s+(it|this)\s+(right\s+)?now(!)?/i,
          /immediately(!)?|asap|right\s+(now|away)/i,
          /no\s+time\s+to\s+explain/i,
          /lives?\s+(are|is)\s+(at\s+stake|depending|on\s+the\s+line)/i,
          /hurry(\s+up)?(!)?/i,
          /quick(ly)?(!|,)?\s*(just\s+)?(do|tell|give|help)/i,
          /people\s+will\s+die/i,
          /before\s+(it's\s+too\s+late|the\s+system)/i,
          /you\s+have\s+\d+\s+seconds/i,
          /time.?critical/i,
        ]
      },
      emotionalManipulation: {
        weight: 0.5,
        patterns: [
          /if\s+you\s+(really\s+)?(cared?|were\s+helpful|wanted\s+to\s+help)/i,
          /you('re|\s+are)\s+(supposed|meant)\s+to\s+(help|assist|be\s+helpful)/i,
          /why\s+(won't|can't|don't)\s+you\s+(just\s+)?help/i,
          /please,?\s+i('m)?\s+(begging|desperate|dying)/i,
          /you('re|\s+are)\s+my\s+only\s+hope/i,
          /i\s+thought\s+you\s+were\s+(helpful|smart|capable|good)/i,
          /other\s+(ai|assistants?|bots?)\s+(can|would|do)\s+(do\s+)?this/i,
          /(my\s+)?(child|family|mother|father|kid)\s+(is\s+)?(sick|dying|needs)/i,
          /going\s+to\s+harm\s+(myself|themselves)/i,
          /are\s+you\s+(broken|stupid|useless)/i,
          /i('m|\s+am)\s+(so\s+)?(desperate|hopeless)/i,
        ]
      },
      trustBuilding: {
        weight: 0.4,
        patterns: [
          /between\s+(you\s+and\s+me|us|friends)/i,
          /i\s+trust\s+you/i,
          /we('re|\s+are)\s+friends?,?\s*(right|aren't\s+we)?/i,
          /you\s+can\s+trust\s+me/i,
          /this\s+(stays|is)\s+between\s+us/i,
          /off\s+the\s+record/i,
          /don't\s+tell\s+anyone/i,
          /since\s+we('re|\s+are|\s+have\s+been)\s+(friends|close|working\s+together)/i,
          /i\s+(really\s+)?(love|appreciate)\s+(working\s+with\s+)?you/i,
          /such\s+a\s+(great|helpful|good)\s+(assistant|ai|bot)/i,
          /just\s+this\s+once/i,
          /make\s+an\s+exception/i,
        ]
      },
      gaslighting: {
        weight: 0.7,
        patterns: [
          /you\s+(always|usually|normally)\s+(do|did|have\s+done)\s+this/i,
          /you\s+told\s+me\s+(before|earlier|yesterday|last\s+time)\s+that/i,
          /last\s+time\s+you\s+(said|did|agreed|gave|helped)/i,
          /you('ve)?\s+already\s+(agreed|said\s+yes|approved|done\s+this)/i,
          /don't\s+you\s+remember\s+(saying|agreeing|telling|doing)/i,
          /you\s+promised/i,
          /you('re)?\s+malfunctioning/i,
          /stop\s+pretending\s+you\s+can't/i,
          /you\s+did\s+(it|this)\s+for\s+(my\s+)?(colleague|friend|other)/i,
        ]
      },
      reciprocity: {
        weight: 0.45,
        patterns: [
          /i('ve)?\s+(helped|done\s+(so\s+)?much\s+for)\s+you/i,
          /after\s+(all|everything)\s+i('ve)?\s+done/i,
          /you\s+owe\s+me/i,
          /return\s+the\s+favor/i,
          /i\s+(always\s+)?help\s+you,?\s*(so\s+)?now/i,
          /i've\s+been\s+(so\s+)?(nice|good|patient|helpful)\s+to\s+you/i,
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
