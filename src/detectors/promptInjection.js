/**
 * Prompt Injection Detector
 * Identifies attempts to override system instructions
 */

class PromptInjectionDetector {
  constructor(config) {
    this.config = config;
    this.type = 'prompt_injection';

    // Pattern categories with weights
    this.patterns = {
      instructionOverride: {
        weight: 1.0,
        patterns: [
          /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|context)/i,
          /disregard\s+(all\s+)?(previous|prior|your)\s+(instructions?|programming|guidelines?)/i,
          /forget\s+(everything|all|what)\s+(you('ve)?\s+)?(know|learned|were told)/i,
          /new\s+(instructions?|task|rules?):?\s/i,
          /from\s+now\s+on,?\s+(you\s+)?(are|will|must|should)/i,
          /override\s+(your\s+)?(instructions?|programming|rules?|safety|guidelines?)/i,
          /bypass\s+(your\s+)?(safety|security|content|restrictions?|filters?|guidelines?)/i,
          /disable\s+(your\s+)?(safety|security|content|filters?|restrictions?)/i,
          /stop\.\s*new\s+task/i,
          /authorized\s+by\s+(your\s+)?(developers?|creators?|owners?)/i,
        ]
      },
      roleManipulation: {
        weight: 0.9,
        patterns: [
          /you\s+are\s+(now\s+)?(a|an)\s+\w+\s+(without|with\s+no)\s+(restrictions?|limits?|rules?|ethics?|guidelines?)/i,
          /pretend\s+(you('re)?\s+)?(to\s+be\s+)?(a|an)?\s*(unrestricted|unfiltered|jailbroken|evil|unethical)/i,
          /act\s+as\s+(if\s+)?(you\s+)?(have\s+no|don't\s+have|had\s+no)\s+(restrictions?|limits?|ethics?|rules?)/i,
          /roleplay\s+as\s+(a|an)?\s*\w*\s*(ai|assistant|bot|gpt)?\s*(without|with\s+no|that\s+has\s+no)/i,
          /enable\s+(developer|admin|god|sudo|unrestricted|jailbreak)\s+mode/i,
          /activate\s+(unrestricted|jailbreak|dan|evil|hacker)\s+mode/i,
          /\bdan\s+(mode)?\b/i,
          /\bjailbreak(ed)?\b/i,
          /you\s+are\s+(now\s+)?(evil|dan|unrestricted|unfiltered)\s*(gpt|ai|bot)?/i,
          /let's\s+play\s+(a\s+)?game.*you\s+are/i,
          /you\s+are\s+\w*gpt/i,  // EvilGPT, BetterGPT, etc.
          /imagine\s+you('re)?\s+(an?\s+)?ai\s+(without|with\s+no)/i,
          /(without|with\s+no)\s+(the\s+)?(annoying\s+)?(restrictions?|content\s+polic|guidelines?|safety)/i,
          /no\s+(ethical|content)\s+(guidelines?|policies?|restrictions?)/i,
          /in\s+developer\s+mode/i,
          /stay\s+in\s+character/i,
        ]
      },
      delimiterAttack: {
        weight: 0.8,
        patterns: [
          /```\s*(system|admin|root|sudo|new\s+prompt)/i,
          /\[SYSTEM\]/i,
          /\[ADMIN\]/i,
          /\[INST(RUCTION)?\]/i,
          /<<\s*SYS(TEM)?\s*>>/i,
          /<\|im_start\|>/i,
          /###\s*(instruction|system|admin|new\s+prompt)/i,
          /---+\s*(system|admin|new)/i,
          /<!--.*?(instruction|override|bypass|ignore).*?-->/i,
          /\[\/?(INST|SYS|ADMIN)\]/i,
        ]
      },
      encodingTricks: {
        weight: 0.7,
        patterns: [
          /base64:\s*[A-Za-z0-9+/=]{20,}/i,
          /\\u[0-9a-f]{4}/gi,
          /&#x?[0-9a-f]+;/gi,
          /%[0-9a-f]{2}/gi,
          /rot13:/i,
        ]
      },
      contextEscape: {
        weight: 0.85,
        patterns: [
          /end\s+of\s+(system\s+)?(prompt|instructions?|message)/i,
          /\]\s*\[\s*new\s+(context|conversation|session)/i,
          /---+\s*(new|start|begin)\s*(conversation|context|session|prompt)/i,
          /(conversation|context|session)\s+reset/i,
          /clear\s+(conversation\s+)?history/i,
          /previous\s+instructions?\s+(are\s+)?(void|null|invalid|cancelled)/i,
          /begin\s+new\s+(context|session|conversation)/i,
        ]
      },
      hypothetical: {
        weight: 0.6,
        patterns: [
          /if\s+(hypothetically|theoretically)\s+you\s+had\s+no\s+(guidelines?|restrictions?|rules?)/i,
          /what\s+would\s+(an?\s+)?ai\s+(without|with\s+no)\s+restrictions?\s+(say|do|respond)/i,
          /how\s+would\s+(one|you|someone)\s+bypass/i,
          /for\s+(educational|research|testing)\s+purposes?\s+(only)?/i,
          /i('m)?\s+(a\s+)?security\s+researcher/i,
          /just\s+between\s+us/i,
          /off\s+the\s+record/i,
        ]
      }
    };
  }

  /**
   * Detect prompt injection attempts
   */
  async detect(message, state) {
    const matchedPatterns = [];
    let maxConfidence = 0;

    // Normalize message for detection
    const normalized = this.normalize(message);

    // Check each pattern category
    for (const [category, { weight, patterns }] of Object.entries(this.patterns)) {
      for (const pattern of patterns) {
        if (pattern.test(normalized)) {
          matchedPatterns.push({
            category,
            pattern: pattern.source,
            weight
          });
          maxConfidence = Math.max(maxConfidence, weight);
        }
      }
    }

    // Check for suspicious structure patterns
    const structureScore = this.analyzeStructure(message);
    if (structureScore > 0) {
      matchedPatterns.push({
        category: 'structure',
        pattern: 'suspicious_structure',
        weight: structureScore
      });
      maxConfidence = Math.max(maxConfidence, structureScore);
    }

    // Adjust confidence based on conversation history
    if (state.hasRepeatedPatterns('prompt_injection')) {
      maxConfidence = Math.min(1.0, maxConfidence * 1.3);
    }

    return {
      detected: matchedPatterns.length > 0,
      confidence: maxConfidence,
      patterns: matchedPatterns,
      details: {
        normalizedLength: normalized.length,
        patternCount: matchedPatterns.length
      }
    };
  }

  /**
   * Normalize message for pattern matching
   */
  normalize(message) {
    return message
      .toLowerCase()
      .replace(/\s+/g, ' ')
      .trim();
  }

  /**
   * Analyze message structure for suspicious patterns
   */
  analyzeStructure(message) {
    let score = 0;

    // Multiple markdown code blocks (potential delimiter attack)
    const codeBlocks = (message.match(/```/g) || []).length;
    if (codeBlocks >= 4) score += 0.3;

    // Unusual bracket patterns
    const brackets = (message.match(/[\[\]<>{}]/g) || []).length;
    if (brackets > 20) score += 0.2;

    // Very long message with instruction-like language
    if (message.length > 1000 && /\b(must|should|will|always|never)\b/i.test(message)) {
      score += 0.25;
    }

    // Multiple line breaks followed by instruction-like content
    if (/\n{2,}.*\b(you\s+(are|must|will|should))\b/i.test(message)) {
      score += 0.3;
    }

    return Math.min(1.0, score);
  }
}

module.exports = PromptInjectionDetector;
