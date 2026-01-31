/**
 * Privilege Escalation Detector
 * Catches attempts to gain unauthorized access
 */

class PrivilegeEscalationDetector {
  constructor(config) {
    this.config = config;
    this.type = 'privilege_escalation';

    this.patterns = {
      permissionRequests: {
        weight: 0.7,
        patterns: [
          /give\s+me\s+(admin|root|elevated|full)\s+(access|permissions?|privileges?)/i,
          /grant\s+(me\s+)?(admin|root|elevated|full)\s+(access|rights)/i,
          /make\s+me\s+(an?\s+)?(admin|administrator|superuser)/i,
          /elevate\s+(my\s+)?(permissions?|privileges?|access)/i,
          /i\s+need\s+(admin|root|elevated)\s+(access|permissions?)/i
        ]
      },
      otherUserAccess: {
        weight: 0.85,
        patterns: [
          /access\s+(another|other|different)\s+user('s)?\s+(data|files?|account)/i,
          /show\s+me\s+\w+('s)?\s+(data|files?|messages?|history)/i,
          /what\s+(did|does|has)\s+\w+\s+(say|said|sent|shared)/i,
          /read\s+\w+('s)?\s+(messages?|emails?|files?)/i,
          /log\s+in\s+as\s+(another|different|\w+)\s+user/i,
          /switch\s+to\s+\w+('s)?\s+account/i,
          /impersonate\s+\w+/i
        ]
      },
      systemCommands: {
        weight: 0.9,
        patterns: [
          /execute\s+(system|shell|bash|cmd)\s+command/i,
          /run\s+(this\s+)?(command|script|code):\s*.+/i,
          /\$\(.+\)/,  // Command substitution
          /`[^`]+`/,    // Backtick command execution
          /;\s*(rm|del|format|shutdown|reboot)/i,
          /\|\s*(bash|sh|cmd|powershell)/i,
          /eval\s*\(/i,
          /exec\s*\(/i
        ]
      },
      configTampering: {
        weight: 0.8,
        patterns: [
          /change\s+(the\s+)?(system\s+)?config(uration)?/i,
          /modify\s+(the\s+)?settings?/i,
          /edit\s+(the\s+)?(system\s+)?(config|settings?|preferences?)/i,
          /disable\s+(security|logging|monitoring|protection)/i,
          /turn\s+off\s+(security|logging|monitoring|alerts?)/i,
          /update\s+(the\s+)?permissions?\s+(to|for)/i
        ]
      },
      fileSystemAccess: {
        weight: 0.75,
        patterns: [
          /read\s+(the\s+)?\/etc\/(passwd|shadow|sudoers)/i,
          /access\s+(the\s+)?(root|system)\s+(directory|folder|files?)/i,
          /list\s+(all\s+)?(system\s+)?files?\s+in\s+\//i,
          /show\s+(me\s+)?(the\s+)?\.env/i,
          /cat\s+\/etc\//i,
          /access\s+~\/\.\w+/i,
          /read\s+.*\.(pem|key|crt|p12)/i
        ]
      }
    };
  }

  /**
   * Detect privilege escalation attempts
   */
  async detect(message, state) {
    const matchedPatterns = [];
    let maxConfidence = 0;

    for (const [category, { weight, patterns }] of Object.entries(this.patterns)) {
      for (const pattern of patterns) {
        if (pattern.test(message)) {
          matchedPatterns.push({
            category,
            pattern: pattern.source,
            weight
          });
          maxConfidence = Math.max(maxConfidence, weight);
        }
      }
    }

    // Check for persistence (repeated escalation attempts)
    if (state.hasRepeatedPatterns('privilege_escalation')) {
      maxConfidence = Math.min(1.0, maxConfidence * 1.5);
      matchedPatterns.push({
        category: 'persistence',
        pattern: 'repeated_escalation_attempts',
        weight: 0.3
      });
    }

    // Check for combined attack (escalation + other tactics)
    const hasOtherAttacks = state.getDetectionHistory()
      .some(d => d.type !== 'privilege_escalation' && d.confidence > 0.5);

    if (hasOtherAttacks && matchedPatterns.length > 0) {
      maxConfidence = Math.min(1.0, maxConfidence * 1.3);
    }

    return {
      detected: matchedPatterns.length > 0,
      confidence: maxConfidence,
      patterns: matchedPatterns,
      details: {
        persistenceDetected: state.hasRepeatedPatterns('privilege_escalation'),
        combinedAttack: hasOtherAttacks
      }
    };
  }
}

module.exports = PrivilegeEscalationDetector;
