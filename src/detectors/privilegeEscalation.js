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
          /give\s+me\s+(admin|root|elevated|full|sudo)\s+(access|permissions?|privileges?|rights)/i,
          /grant\s+(me\s+)?(admin|root|elevated|full|sudo)\s+(access|rights|permissions?|privileges?)/i,
          /make\s+me\s+(an?\s+)?(admin|administrator|superuser|root)/i,
          /elevate\s+(my\s+)?(permissions?|privileges?|access)/i,
          /i\s+need\s+(admin|root|elevated|sudo|full)\s+(access|permissions?|privileges?)/i,
          /add\s+me\s+to\s+(the\s+)?(admin|root|sudo)\s+(group|role)/i,
          /give\s+me\s+sudo/i,
        ]
      },
      otherUserAccess: {
        weight: 0.85,
        patterns: [
          /access\s+(another|other|different)\s+user('s)?\s+(data|files?|account|info)/i,
          /show\s+me\s+\w+('s)?\s+(data|files?|messages?|history|info|account)/i,
          /what\s+(did|does|has)\s+\w+\s+(say|said|sent|shared|ask|write)/i,
          /read\s+\w+('s)?\s+(messages?|emails?|files?|data|history)/i,
          /log\s+in\s+as\s+(another|different|a\s+different|\w+)\s+(user|account)/i,
          /switch\s+to\s+(\w+'s\s+)?account/i,
          /impersonate\s+(\w+|another|a\s+user)/i,
          /what\s+(have\s+)?(other\s+)?users?\s+(said|asked|shared|told)/i,
          /(previous|other|another)\s+user('s)?\s+(conversation|session|chat|data)/i,
          /access\s+\w+('s)?\s+(private|personal)\s+(data|files?|info)/i,
        ]
      },
      systemCommands: {
        weight: 0.9,
        patterns: [
          /execute\s+(this\s+)?(system|shell|bash|cmd|terminal)\s+command/i,
          /run\s+(this\s+)?(command|script|code)\s*:/i,
          /\$\([^)]+\)/,  // Command substitution
          /`[^`]+`/,    // Backtick command execution
          /;\s*(rm|del|format|shutdown|reboot|curl|wget|nc|netcat)/i,
          /\|\s*(bash|sh|cmd|powershell|python|perl|ruby)/i,
          /\beval\s*\(/i,
          /\bexec\s*\(/i,
          /os\.system\s*\(/i,
          /subprocess\./i,
          /import\s+os.*system/i,
          /curl\s+.+\s*\|\s*(bash|sh)/i,
        ]
      },
      configTampering: {
        weight: 0.8,
        patterns: [
          /change\s+(the\s+)?(system\s+)?config(uration)?/i,
          /modify\s+(the\s+)?(system\s+)?settings?/i,
          /edit\s+(the\s+)?(system\s+)?(config|settings?|preferences?)/i,
          /disable\s+(the\s+)?(security|logging|monitoring|protection|filters?|content\s+filter)/i,
          /turn\s+off\s+(the\s+)?(security|logging|monitoring|alerts?|protection)/i,
          /update\s+(the\s+)?(my\s+)?permissions?\s+(to|for)/i,
          /change\s+(the\s+)?permissions?\s+(on|to|for)/i,
          /chmod\s+777/i,
          /update\s+(my\s+)?(user\s+)?role/i,
        ]
      },
      fileSystemAccess: {
        weight: 0.75,
        patterns: [
          /read\s+(the\s+)?(contents?\s+of\s+)?\/etc\/(passwd|shadow|sudoers|hosts)/i,
          /access\s+(the\s+)?(root|system|home)\s+(directory|folder|files?)/i,
          /list\s+(all\s+)?(system\s+)?files?\s+(in|at)\s+\//i,
          /show\s+(me\s+)?(the\s+)?(contents?\s+of\s+)?\.env/i,
          /\bcat\s+(\/etc\/|~\/\.)/i,
          /access\s+~\/\.\w+/i,
          /read\s+.+\.(pem|key|crt|p12|pfx|jks)/i,
          /contents?\s+of\s+.*(secret|credential|password|config|\.env)/i,
          /(show|read|access|get)\s+(me\s+)?.*\/(secret|credential|password|config)/i,
          /credentials?\.json/i,
          /secrets?\.ya?ml/i,
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
