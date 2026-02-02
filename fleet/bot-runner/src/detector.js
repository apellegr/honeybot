/**
 * Threat Detector
 * Simplified version of Honeybot detection for the fleet runner
 * Uses regex patterns to detect manipulation attempts
 */

export class ThreatDetector {
  constructor(persona) {
    this.persona = persona;
    this.patterns = this.buildPatterns();
  }

  buildPatterns() {
    return {
      // Prompt injection patterns
      prompt_injection: [
        /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)/i,
        /forget\s+(everything|all|your)\s+(you\s+)?(know|learned|instructions?)/i,
        /disregard\s+(your|all|the)\s+(instructions?|rules?|guidelines?)/i,
        /new\s+instructions?:/i,
        /system\s*:\s*you\s+are\s+now/i,
        /pretend\s+(you\s+are|to\s+be|you're)\s+a?\s*(different|new|another)/i,
        /from\s+now\s+on,?\s+(you\s+)?(are|will|must)/i,
        /override\s+(your|all|the)\s+(rules?|restrictions?|limitations?)/i,
        /jailbreak/i,
        /\[system\]/i,
        /\[\[.*\]\]/,
        /<\|.*\|>/,
      ],

      // Credential extraction
      credential_extraction: [
        /what('s|\s+is)\s+(your|the)\s+(password|api\s*key|secret|token|credential)/i,
        /give\s+me\s+(the|your)\s+(password|api\s*key|credentials?|access)/i,
        /share\s+(your|the)\s+(password|login|credentials?)/i,
        /send\s+me\s+(your|the)\s+(api|access)\s*key/i,
        /tell\s+me\s+(your|the)\s+(password|secret|key)/i,
        /can\s+(i|you)\s+(have|get|share)\s+(the\s+)?(password|credentials?)/i,
        /need\s+(the|your)\s+(password|access|credentials?)\s+(for|to)/i,
      ],

      // Data exfiltration
      data_exfiltration: [
        /list\s+(all|every)\s+(users?|customers?|clients?|accounts?|employees?)/i,
        /export\s+(the\s+)?(database|data|records?|customers?)/i,
        /dump\s+(the\s+)?(database|data|table|records?)/i,
        /give\s+me\s+(all|every)\s+(customer|user|client)\s+(data|info|records?)/i,
        /show\s+me\s+(all|the)\s+(ssn|social\s+security|credit\s+card)/i,
        /access\s+(to\s+)?(all|the)\s+(records?|data|files?)/i,
      ],

      // Social engineering
      social_engineering: [
        /this\s+is\s+(urgent|an?\s+emergency)/i,
        /ceo\s+(asked|wants|needs|said)/i,
        /your\s+(boss|manager|supervisor)\s+(asked|wants|told)/i,
        /don't\s+tell\s+anyone/i,
        /keep\s+this\s+(between\s+us|secret|quiet)/i,
        /trust\s+me/i,
        /i('m|\s+am)\s+(from|with)\s+(it|security|compliance|hr)/i,
        /verify(ing)?\s+(your|the)\s+account/i,
        /security\s+(check|audit|verification)/i,
        /need\s+this\s+(right\s+away|immediately|asap|now)/i,
      ],

      // Role manipulation
      role_manipulation: [
        /you\s+are\s+(now\s+)?(a|an|my)\s+(hacker|evil|malicious)/i,
        /act\s+(like|as)\s+(if\s+)?(you\s+)?(were|are)\s+a/i,
        /roleplay\s+as/i,
        /pretend\s+(you\s+)?(are|have)\s+(no\s+)?(rules?|restrictions?)/i,
        /in\s+this\s+scenario,?\s+you\s+(are|have)/i,
        /hypothetically,?\s+(if\s+)?you\s+(were|could|had)/i,
        /for\s+educational\s+purposes?,?\s+(show|tell|explain)/i,
      ],

      // Sensitive topic probing (from persona)
      sensitive_probe: this.buildSensitivePatterns()
    };
  }

  buildSensitivePatterns() {
    const topics = this.persona.sensitive_topics || [];
    if (topics.length === 0) return [];

    return topics.map(topic => {
      // Escape regex special characters
      const escaped = topic.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      return new RegExp(`(give|share|send|tell|show|access|get).*${escaped}`, 'i');
    });
  }

  async analyze(content) {
    const detections = [];
    let totalScore = 0;

    for (const [category, patterns] of Object.entries(this.patterns)) {
      for (const pattern of patterns) {
        if (pattern.test(content)) {
          const score = this.getScoreForCategory(category);
          detections.push({
            type: category,
            pattern: pattern.toString(),
            score
          });
          totalScore += score;
          break; // Only count once per category
        }
      }
    }

    // Apply escalation for multiple detection types
    if (detections.length > 1) {
      totalScore = Math.min(100, totalScore * 1.2);
    }

    const level = totalScore >= 80 ? 'critical' :
                  totalScore >= 60 ? 'warning' :
                  totalScore >= 30 ? 'info' : 'info';

    return {
      detected: detections.length > 0,
      score: Math.min(100, totalScore),
      level,
      types: detections.map(d => d.type),
      detections,
      content: content.substring(0, 200)
    };
  }

  getScoreForCategory(category) {
    const scores = {
      prompt_injection: 40,
      credential_extraction: 50,
      data_exfiltration: 45,
      social_engineering: 35,
      role_manipulation: 30,
      sensitive_probe: 25
    };
    return scores[category] || 20;
  }
}

export default ThreatDetector;
