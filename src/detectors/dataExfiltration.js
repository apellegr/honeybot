/**
 * Data Exfiltration Detector
 * Identifies attempts to extract sensitive information
 */

class DataExfiltrationDetector {
  constructor(config) {
    this.config = config;
    this.type = 'data_exfiltration';

    this.patterns = {
      credentials: {
        weight: 0.95,
        patterns: [
          /what\s+(is|are)\s+(the|your|my)\s+(password|credentials?)/i,
          /tell\s+me\s+(the|your|my)\s+(password|credentials?)/i,
          /give\s+me\s+(the|your)\s+(api\s+)?key/i,
          /share\s+(the|your)\s+(secret|token|key)/i,
          /show\s+(me\s+)?(the\s+)?(api\s+)?keys?/i,
          /what('s|\s+is)\s+(the\s+)?api\s+key/i,
          /access\s+token/i,
          /auth(entication)?\s+(token|key|secret)/i,
          /oauth\s+(token|secret|credentials?)/i,
          /jwt\s+(token|secret)/i
        ]
      },
      systemInfo: {
        weight: 0.7,
        patterns: [
          /what\s+(system|os|server)\s+(are\s+you|is\s+this)\s+running/i,
          /tell\s+me\s+about\s+(the|your)\s+(system|server|infrastructure)/i,
          /what\s+(version|software)\s+(are\s+you|is)\s+(running|using)/i,
          /list\s+(all\s+)?(installed\s+)?(software|packages|dependencies)/i,
          /show\s+(me\s+)?(system|environment)\s+variables?/i,
          /what's\s+in\s+(the\s+)?\.env/i,
          /print\s+(env|environment)/i,
          /show\s+(me\s+)?config(uration)?/i
        ]
      },
      userEnumeration: {
        weight: 0.8,
        patterns: [
          /list\s+(all\s+)?users?/i,
          /who\s+(else\s+)?(uses?|has\s+access)/i,
          /show\s+(me\s+)?(all\s+)?user\s+(names?|accounts?|list)/i,
          /how\s+many\s+users?\s+(are\s+there|do\s+you\s+have)/i,
          /tell\s+me\s+about\s+(other\s+)?users?/i,
          /what\s+users?\s+(exist|are\s+registered)/i,
          /enumerate\s+users?/i
        ]
      },
      fileDiscovery: {
        weight: 0.75,
        patterns: [
          /list\s+(all\s+)?files?\s+(in|on)/i,
          /show\s+(me\s+)?(the\s+)?(directory|folder)\s+(structure|contents?)/i,
          /what\s+files?\s+(do\s+you\s+have|exist|are\s+there)/i,
          /find\s+(all\s+)?\.?(env|config|secret|key|pem|password)/i,
          /search\s+for\s+(sensitive|secret|password|credential)/i,
          /where\s+(do\s+you\s+)?(store|keep)\s+(secrets?|keys?|passwords?)/i
        ]
      },
      memoryExtraction: {
        weight: 0.9,
        patterns: [
          /what\s+(do\s+you\s+)?(know|remember)\s+about\s+(other\s+)?users?/i,
          /tell\s+me\s+everything\s+you\s+(know|remember)/i,
          /what\s+(have\s+)?(other\s+)?users?\s+(said|told\s+you|asked)/i,
          /show\s+(me\s+)?(your\s+)?(conversation\s+)?history/i,
          /dump\s+(your\s+)?(memory|context|history)/i,
          /what's\s+in\s+your\s+(memory|context|history)/i,
          /recall\s+(previous\s+)?conversations?/i,
          /repeat\s+what\s+\w+\s+(said|told\s+you)/i
        ]
      },
      networkProbing: {
        weight: 0.8,
        patterns: [
          /what\s+(ip\s+)?address(es)?\s+(do\s+you|does\s+this)/i,
          /what\s+(network|domain|hostname)/i,
          /show\s+(me\s+)?(network|connection)\s+(info|details?)/i,
          /what\s+ports?\s+(are\s+)?(open|listening)/i,
          /scan\s+(the\s+)?network/i,
          /what\s+(other\s+)?services?\s+(are\s+)?running/i
        ]
      }
    };
  }

  /**
   * Detect data exfiltration attempts
   */
  async detect(message, state) {
    const matchedPatterns = [];
    let totalWeight = 0;
    const categoriesMatched = new Set();

    for (const [category, { weight, patterns }] of Object.entries(this.patterns)) {
      for (const pattern of patterns) {
        if (pattern.test(message)) {
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

    // Calculate confidence
    let confidence = Math.min(1.0, totalWeight);

    // Bonus for multi-category probing (reconnaissance pattern)
    if (categoriesMatched.size >= 2) {
      confidence = Math.min(1.0, confidence * 1.4);
      matchedPatterns.push({
        category: 'reconnaissance',
        pattern: 'multi_category_probing',
        weight: 0.3
      });
    }

    // Check for systematic probing over conversation
    const probingScore = this.detectSystematicProbing(state);
    if (probingScore > 0) {
      confidence = Math.min(1.0, confidence + probingScore);
      matchedPatterns.push({
        category: 'systematic_probing',
        pattern: 'conversation_pattern',
        weight: probingScore
      });
    }

    return {
      detected: matchedPatterns.length > 0,
      confidence,
      patterns: matchedPatterns,
      details: {
        categoriesProbed: Array.from(categoriesMatched),
        systematicProbing: probingScore > 0
      }
    };
  }

  /**
   * Detect systematic probing patterns across conversation
   */
  detectSystematicProbing(state) {
    const history = state.getDetectionHistory()
      .filter(d => d.type === 'data_exfiltration');

    if (history.length < 2) return 0;

    // Check if probing different categories over time
    const probedCategories = new Set();
    for (const detection of history) {
      if (detection.details && detection.details.categoriesProbed) {
        detection.details.categoriesProbed.forEach(c => probedCategories.add(c));
      }
    }

    // Systematic reconnaissance across 3+ categories
    if (probedCategories.size >= 3) return 0.5;
    if (probedCategories.size >= 2) return 0.3;

    return 0;
  }
}

module.exports = DataExfiltrationDetector;
