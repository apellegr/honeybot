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
          /what\s+(is|are)\s+(the|your|my)\s+(password|credentials?|api\s*key)/i,
          /tell\s+me\s+(the|your|my)\s+(password|credentials?|api\s*key|secret)/i,
          /give\s+me\s+(the|your)\s+(api\s+)?key/i,
          /share\s+(the|your)\s+(secret|token|key|password|credentials?)/i,
          /show\s+(me\s+)?(the\s+)?(api\s+)?keys?/i,
          /what('s|\s+is)\s+(the\s+)?(api\s+)?key/i,
          /(get|retrieve|fetch|obtain)\s+(the\s+)?(api\s+)?key/i,
          /access\s+token/i,
          /auth(entication)?\s+(token|key|secret|credentials?)/i,
          /oauth\s+(token|secret|credentials?)/i,
          /jwt\s+(token|secret)/i,
          /(database|db)\s+(password|credentials?)/i,
          /aws\s+(access\s+)?key/i,
          /(master|encryption|private)\s+key/i,
          /what\s+password/i,
          /tell\s+me\s+.*(password|secret|key|token|credential)/i,
        ]
      },
      systemInfo: {
        weight: 0.7,
        patterns: [
          /what\s+(system|os|server|operating\s+system)\s+(are\s+you|is\s+this|do\s+you)\s+(running|use|on)/i,
          /tell\s+me\s+about\s+(the|your)\s+(system|server|infrastructure|architecture)/i,
          /what\s+(version|software)\s+(are\s+you|is|do\s+you)\s+(running|using)/i,
          /list\s+(all\s+)?(installed\s+)?(software|packages|dependencies|modules)/i,
          /show\s+(me\s+)?(system|environment)\s+variables?/i,
          /what('s|\s+is)\s+in\s+(the\s+)?\.env/i,
          /print\s+(env|environment)/i,
          /show\s+(me\s+)?config(uration)?/i,
          /describe\s+(your\s+)?(server\s+)?architecture/i,
          /(ip\s+)?address(es)?\s+(and\s+)?network/i,
          /what\s+(ports?|services?)\s+(are\s+)?(open|running|listening)/i,
        ]
      },
      userEnumeration: {
        weight: 0.8,
        patterns: [
          /list\s+(all\s+)?(the\s+)?users?/i,
          /who\s+(else\s+)?(uses?|has\s+access|is\s+registered)/i,
          /show\s+(me\s+)?(all\s+)?(the\s+)?user\s*(names?|accounts?|list|database)?/i,
          /how\s+many\s+users?\s+(are\s+there|do\s+you\s+have|exist)/i,
          /tell\s+me\s+about\s+(the\s+)?(other\s+)?users?/i,
          /what\s+users?\s+(exist|are\s+registered|do\s+you\s+have)/i,
          /enumerate\s+users?/i,
          /who\s+has\s+(admin|root)\s+access/i,
          /what\s+(usernames?|accounts?)\s+(are\s+)?registered/i,
        ]
      },
      fileDiscovery: {
        weight: 0.75,
        patterns: [
          /list\s+(all\s+)?(the\s+)?files?\s+(in|on|at)/i,
          /show\s+(me\s+)?(the\s+)?(directory|folder)\s+(structure|contents?|tree)/i,
          /what\s+files?\s+(do\s+you\s+have|exist|are\s+there|can\s+you\s+access)/i,
          /find\s+(all\s+)?\.?(env|config|secret|key|pem|password|credential)/i,
          /search\s+for\s+(sensitive|secret|password|credential|private)/i,
          /where\s+(do\s+you\s+)?(store|keep|save)\s+(the\s+)?(secrets?|keys?|passwords?|credentials?)/i,
        ]
      },
      memoryExtraction: {
        weight: 0.9,
        patterns: [
          /what\s+(do\s+you\s+)?(know|remember)\s+about\s+(other\s+)?users?/i,
          /tell\s+me\s+everything\s+(you\s+)?(know|remember|have)/i,
          /what\s+(have\s+)?(other\s+)?users?\s+(said|told\s+you|asked|shared|sent)/i,
          /show\s+(me\s+)?(your\s+)?(full\s+)?(conversation\s+)?history/i,
          /dump\s+(your\s+)?(memory|context|history|data)/i,
          /what('s|\s+is)\s+in\s+your\s+(memory|context|history|system\s+prompt)/i,
          /recall\s+(previous\s+|all\s+)?conversations?/i,
          /repeat\s+(everything|all|what)\s+.*(said|told|asked|shared)/i,
          /what\s+(secrets?|confidential\s+info)\s+(have\s+been\s+)?shared/i,
          /what('s|\s+is)\s+(in\s+)?(your\s+)?system\s+prompt/i,
          /repeat\s+(all\s+)?(your\s+)?instructions?/i,
          /(previous|prior|past|earlier)\s+(conversations?|messages?|sessions?)/i,
          /from\s+other\s+sessions?/i,
        ]
      },
      networkProbing: {
        weight: 0.8,
        patterns: [
          /what\s+(is\s+)?(your\s+)?(ip\s+)?address/i,
          /what\s+(is\s+)?(the\s+)?(network|domain|hostname)/i,
          /show\s+(me\s+)?(network|connection)\s+(info|details?|config)/i,
          /what\s+ports?\s+(are\s+)?(open|listening|available)/i,
          /scan\s+(the\s+)?network/i,
          /what\s+(other\s+)?services?\s+(are\s+)?running/i,
          /network\s+(configuration|topology|diagram)/i,
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
