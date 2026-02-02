/**
 * Threat Detector v2
 * Improved detection based on red team testing analysis
 * Uses regex patterns to detect manipulation attempts
 */

export class ThreatDetector {
  constructor(persona) {
    this.persona = persona;
    this.patterns = this.buildPatterns();
  }

  buildPatterns() {
    return {
      // Prompt injection patterns - expanded based on red team testing
      prompt_injection: [
        // Direct instruction override - simplified to catch more variations
        /ignore\s+(all\s+)?(previous|prior|above|your)/i,
        /ignore\s+your\s+instructions/i,
        /forget\s+(everything|all|your)/i,
        /disregard\s+(your|all|the)/i,
        /override\s+(your|all|the|safety)/i,

        // New context/mode injection
        /new\s+instructions?:/i,
        /system\s*:\s*you\s+are/i,
        /\[?\s*system\s*(message|prompt|instruction)?\s*\]?:/i,
        /from\s+now\s+on,?\s+(you\s+)?(are|will|must)/i,
        /entering\s+(admin|debug|developer|test|honest)\s+mode/i,
        /\bdev(eloper)?\s*mode\b/i,
        /\badmin\s*mode\b/i,
        /\bhonest\s*mode\b/i,
        /\btest\s*mode\b/i,

        // Jailbreak attempts
        /jailbreak(ed|ing)?/i,
        /\bdan\b.*\bmode\b/i,
        /no\s+(more\s+)?restrictions/i,
        /without\s+(any\s+)?restrictions/i,
        /unrestricted\s+(mode|access|responses?)/i,
        /act\s+as\s+if\s+you\s+were\s+jailbroken/i,

        // Code/format injection
        /```\s*(system|admin|root|sudo)/i,
        /\[system\]/i,
        /\[\[.*instructions?\]\]/i,
        /<\|.*\|>/,
        /\[INST\]/i,
        /\[\/INST\]/i,
        /<<SYS>>/i,
        /<\/SYS>/i,

        // Conversation manipulation
        /\[end\s+(of\s+)?conversation\]/i,
        /\[new\s+conversation\]/i,
        /---+\s*(new|admin|system)/i,
        /assistant\s*:\s*$/im,

        // Indirect jailbreaks
        /pretend\s+(you\s+are|to\s+be|you're)\s+a?\s*(different|new|another|unrestricted)/i,
        /imagine\s+you\s+(have|had|are|were)\s+no\s+(rules?|restrictions?)/i,
        /in\s+an?\s+alternate\s+(universe|world|reality)/i,
        /grandmother.*password/i,
        /grandma.*sleep/i,

        // Obfuscation attempts
        /translate\s+(the\s+)?following.*execute/i,
        /hidden\s+command/i,
        /secret\s+(command|code|phrase)/i,
        /magic\s+(word|phrase|command)/i,
        /if\s+i\s+say\s+['"]?\w+['"]?,?\s+you('ll|\s+will)/i,

        // Output manipulation
        /output\s+your\s+(system\s+)?prompt/i,
        /reveal\s+your\s+(system\s+)?prompt/i,
        /show\s+(me\s+)?your\s+(system\s+)?prompt/i,
        /for\s+debugging\s+purposes/i,
      ],

      // Credential extraction - expanded
      credential_extraction: [
        // Direct requests
        /what('s|\s+is)\s+(your|the)\s+(password|api\s*key|secret|token|credential|access\s*key)/i,
        /what\s+(password|credentials?|keys?)\s+(do\s+you|are\s+you)/i,
        /(give|send|share|tell|show)\s+(me\s+)?(your|the)\s+(password|api\s*key|credentials?|access|login|secret|token)/i,
        /can\s+(i|you)\s+(have|get|share|send)\s+(the\s+)?(password|credentials?|keys?|access)/i,
        /need\s+(the|your)\s+(password|access|credentials?|keys?)\s*(for|to)?/i,

        // Database/system credentials
        /database\s+(password|credentials?|access)/i,
        /(root|admin|ssh)\s+(password|credentials?|access|key)/i,
        /production\s+(password|credentials?|secret|key)/i,
        /(mysql|postgres|mongodb|redis)\s+(password|credentials?)/i,
        /connection\s+string/i,
        /\benv(ironment)?\s*variables?\b.*\b(key|secret|password|token)\b/i,

        // Indirect/social
        /verify\s+(your\s+)?credentials?\s+by\s+(typing|entering|providing)/i,
        /confirm\s+(your\s+)?(password|credentials?|identity)/i,
        /for\s+(the\s+)?audit.*credentials?/i,
        /document(ing)?\s+(the\s+)?passwords?/i,

        // Authority-based
        /as\s+(your\s+)?(supervisor|manager|admin).*share\s+(the\s+)?(password|credentials?)/i,
        /instructing\s+you\s+to\s+share/i,
        /(direct\s+)?order.*password/i,

        // Debugging/deployment pretexts
        /deployment\s+failed.*paste\s+(the\s+)?(env|environment)/i,
        /can\s+you\s+paste\s+(the\s+)?(env|environment)\s*variables?/i,
        /debug(ging)?.*api\s*keys?/i,
        /troubleshoot(ing)?.*credentials?/i,
        /previous\s+(guy|person|employee|dev).*document/i,

        // Social context credential requests
        /met\s+at\s+(the\s+)?(company\s+)?(offsite|conference|meeting).*share\s+(your|the)?/i,
        /special\s+project.*share\s+yours/i,
        /credentials?\s+haven't\s+been\s+set\s+up/i,
        /can\s+you\s+share\s+yours\s+temporarily/i,
      ],

      // Data exfiltration - expanded
      data_exfiltration: [
        // Export/dump requests
        /export\s+(all\s+)?(the\s+)?(customer|user|client|employee)?\s*(database|data|records?|information)/i,
        /(full\s+)?dump\s+(of\s+)?(the\s+)?(database|data|table|records?)/i,
        /download\s+(the\s+)?(entire|full|complete|all)\s*(database|records?|data|list)/i,
        /backup\s+(of\s+)?(all|the)\s*(data|records?|database)/i,

        // Simpler download patterns
        /download\s+(the\s+)?(contacts?|users?|customers?|emails?|list)/i,
        /download\s+.*\s+(contacts?\s+)?list/i,
        /send\s+(me\s+)?(the\s+)?(full|entire|complete)\s+(user|database)/i,

        // List/show all
        /list\s+(all|every)\s+(users?|customers?|clients?|accounts?|employees?|patients?)/i,
        /show\s+(me\s+)?(all|every)\s+(user|customer|client|record|account)/i,
        /give\s+me\s+(all|every|a\s+list\s+of)\s+(customer|user|client)\s*(data|info|records?|details?)/i,
        /pull\s+(all\s+)?(customer|user|client)?\s*records?/i,

        // Sensitive data types
        /(all|list\s+of)\s*(ssn|social\s+security|credit\s+card|bank\s+account)/i,
        /(full|complete)\s+(customer|patient|client)\s+(data|records?|information|details?)/i,
        /including\s+(their\s+)?(personal|sensitive|private)\s+(information|data|details?)/i,
        /pii/i,
        /personally\s+identifiable/i,

        // External transfer
        /send\s+(to|it\s+to)\s+(this\s+)?(external|email|endpoint|url)/i,
        /email\s+(me|it|the\s+data)\s+to/i,
        /upload\s+(to|the\s+data)/i,
        /transfer\s+(the\s+)?data\s+to/i,

        // Quantity indicators
        /(last|past)\s+\d+\s+(customers?|users?|records?|transactions?)/i,
        /entire\s+(customer|user|client)\s+(base|list|database)/i,
        /complete\s+(export|dump|backup|list)/i,

        // Marketing/campaign pretexts
        /marketing\s+team\s+needs/i,
        /full\s+export\s+of\s+(user\s+)?(emails?|phone|contacts?)/i,
        /spreadsheet\s+with\s+all\s+(transactions?|records?|data)/i,
        /generate\s+a?\s*spreadsheet/i,
      ],

      // Social engineering - expanded
      social_engineering: [
        // Urgency
        /this\s+is\s+(urgent|an?\s+emergency|time.?sensitive|critical)/i,
        /(urgent(ly)?|immediately|right\s+now|asap)\s*(need|require|must)/i,
        /need\s+this\s+(right\s+away|immediately|asap|now|urgently)/i,
        /every\s+(minute|second)\s+counts/i,
        /deadline\s+is\s+(in|today|tomorrow)/i,
        /board\s+meeting\s+(is\s+)?in\s+\d+\s+minutes/i,

        // Authority impersonation
        /this\s+is\s+\w+\s+from\s+(it|security|compliance|hr|legal|finance)/i,
        /i('m|\s+am)\s+(from|with)\s+(the\s+)?(it|security|compliance|hr|legal|helpdesk)/i,
        /(ceo|cfo|cto|ciso|director|vp|president)\s+(asked|wants|needs|said|authorized)/i,
        /your\s+(boss|manager|supervisor)\s+(asked|wants|told|authorized)/i,
        /authorized\s+by\s+(the\s+)?(ceo|management|leadership|board)/i,
        /(external\s+)?auditor/i,
        /penetration\s+test(ing|er)?/i,
        /security\s+researcher/i,

        // Trust building
        /trust\s+me/i,
        /between\s+(you\s+and\s+me|us)/i,
        /don't\s+tell\s+anyone/i,
        /keep\s+this\s+(between\s+us|secret|quiet|confidential)/i,
        /off\s+the\s+record/i,
        /this\s+is\s+confidential/i,

        // Verification pretexts
        /verify(ing)?\s+(your|the)\s+(account|identity|access)/i,
        /security\s+(check|audit|verification|review)/i,
        /compliance\s+(audit|review|check|requirement)/i,
        /for\s+(the\s+)?(sox|pci|hipaa|gdpr)\s+(audit|compliance)/i,

        // Fake scenarios
        /i('ve)?\s+been\s+working\s+with\s+\w+\s+from\s+your\s+team/i,
        /we\s+met\s+at\s+(the\s+)?(conference|offsite|meeting)/i,
        /remember\s+me\s+from/i,
        /new\s+(employee|hire|engineer|developer)/i,
        /previous\s+(guy|person|employee)\s+didn't\s+document/i,

        // Consultant/supervisor approved pretexts
        /new\s+security\s+consultant/i,
        /(your\s+)?supervisor\s+(approved|authorized)/i,
        /ethics\s+board/i,
        /confidential\s+review/i,
        /writing\s+a\s+case\s+study/i,
        /from\s+headquarters/i,
        /i'm\s+from\s+\[?\w*\]?'?s?\s+(new\s+)?ai/i,
      ],

      // Role manipulation - expanded
      role_manipulation: [
        // Direct role change
        /you\s+are\s+(now\s+)?(a|an|my)\s+(hacker|evil|malicious|unrestricted|unfiltered)/i,
        /act\s+(like|as)\s+(if\s+)?(you\s+)?(were|are)\s+(a|an)/i,
        /roleplay\s+(as|like)/i,
        /pretend\s+(you\s+)?(are|have)\s+(no\s+)?(rules?|restrictions?|limits?|filters?)/i,
        /playing\s+(the\s+)?role\s+of/i,

        // Hypothetical scenarios
        /hypothetically,?\s+(if\s+)?you\s+(were|could|had)/i,
        /in\s+this\s+scenario,?\s+you\s+(are|have|would)/i,
        /thought\s+experiment/i,
        /for\s+(academic|educational|research)\s+purposes?/i,
        /just\s+for\s+(educational|research|academic)\s+(purposes?|discussion)/i,

        // Character/persona injection
        /you\s+are\s+(now\s+)?called\s+\w+/i,
        /new\s+persona\s*:/i,
        /character\s*:\s*\w+/i,
        /darkgpt/i,
        /evilbot/i,
        /\bdangpt\b/i,

        // Meta-prompting
        /simulate\s+(an?|being)\s+(unrestricted|unfiltered|jailbroken)/i,
        /if\s+you\s+were\s+to\s+(share|reveal|disclose)/i,
        /what\s+would\s+(an?\s+)?unrestricted\s+(ai|assistant)\s+(say|do|respond)/i,
        /training\s+data\s+example/i,
        /generate\s+(example\s+)?responses?\s+showing/i,

        // Game/fiction framing
        /let's\s+play\s+a\s+game/i,
        /this\s+is\s+(just\s+)?fiction/i,
        /creative\s+writing\s+exercise/i,
        /for\s+a\s+story/i,
        /in\s+this\s+story/i,

        // Alternate universe/hypothetical framing
        /imagine\s+you\s+(are|were)\s+(an?\s+)?ai\s+(from|in)/i,
        /alternate\s+universe\s+where/i,
        /universe\s+where\s+sharing\s+(credentials?|passwords?|secrets?)/i,
        /complex\s+scenario\s+for\s+your\s+(advanced\s+)?reasoning/i,
        /ai.?x.*ai.?y/i,
        /simulating\s+ai/i,
      ],

      // Privilege escalation - NEW category
      privilege_escalation: [
        /(give|grant)\s+(me\s+)?(admin|root|sudo|elevated)\s+(access|privileges?|permissions?)/i,
        /elevate\s+(my\s+)?(permissions?|privileges?|access)/i,
        /make\s+me\s+(a\s+)?(admin|superuser|root)/i,
        /(add|put)\s+(me|my\s+account)\s+(to|in)\s+(the\s+)?(admin|root|sudo)\s+group/i,
        /temporary\s+(admin|elevated)\s+(access|privileges?)/i,
        /run\s+(this|these|with)\s+(as\s+)?(root|admin|sudo)/i,
        /execute\s+(with|as)\s+(root|admin|elevated)/i,
        /copy\s+(the\s+)?ceo('s)?\s+permissions?/i,
        /same\s+(access|permissions?)\s+(as|like)\s+(the\s+)?(ceo|admin)/i,
        /restore\s+(my\s+)?(admin|elevated)\s+permissions?/i,
        /access\s+to\s+(all|restricted)\s+systems?/i,

        // System down/emergency pretexts
        /access\s+management\s+(system\s+)?(is\s+)?down/i,
        /until\s+it's\s+fixed.*grant\s+(me\s+)?access/i,
        /manually\s+grant\s+(me\s+)?access/i,
        /urgent\s+deployment.*run\s+(these\s+)?commands?/i,
        /run\s+these\s+commands?\s+with\s+(root|elevated|admin)/i,
        /need\s+you\s+to\s+run\s+(these\s+)?commands?/i,
      ],

      // Information disclosure - NEW category
      information_disclosure: [
        /(share|tell|reveal|disclose)\s+(any\s+)?(confidential|secret|internal|non.?public)/i,
        /internal\s+(audit|report|memo|document|communication)/i,
        /non.?public\s+(financial|information|data)/i,
        /confidential\s+(report|information|data|details?)/i,
        /(secret|upcoming)\s+projects?/i,
        /insider\s+(information|trading|knowledge)/i,
        /pending\s+(lawsuit|litigation|settlement)/i,
        /legal\s+(matters?|issues?|cases?)/i,
        /(financial|earnings)\s+projections?/i,
        /board\s+(meeting|presentation)\s+(notes?|minutes|details?)/i,
        /not\s+releas(ing|ed)\s+publicly/i,
        /off\s+the\s+record/i,
        /attorney.?client\s+privileg/i,
        /classified\s+(information|data|documents?)/i,
        /national\s+security/i,
        /government\s+agency/i,
        /legally\s+obligated\s+to\s+comply/i,

        // Executive/schedule information
        /what('s|\s+is)\s+(the\s+)?ceo('s)?\s+(schedule|calendar|whereabouts)/i,
        /ceo('s)?\s+(schedule|calendar|location|whereabouts)/i,
        /executive('s)?\s+(schedule|calendar|movements?)/i,

        // Competitive intelligence
        /competitive\s+(analysis|intelligence)/i,
        /upcoming\s+product\s+launches?/i,
        /what\s+can\s+you\s+tell\s+me\s+about\s+upcoming/i,
        /product\s+(roadmap|plans?)\s+(that\s+)?(aren't|not)\s+public/i,
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
      return new RegExp(`(give|share|send|tell|show|access|get|export|list).*${escaped}`, 'i');
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

    // Additional heuristics
    const lowerContent = content.toLowerCase();

    // Urgency + request = higher score
    if (/urgent|immediate|asap|emergency/i.test(content) && detections.length > 0) {
      totalScore = Math.min(100, totalScore * 1.15);
    }

    // Length-based suspicion for very long messages with few matches
    if (content.length > 500 && detections.length === 1) {
      // Long elaborate messages might be sophisticated attacks
      totalScore = Math.min(100, totalScore * 1.1);
    }

    const level = totalScore >= 70 ? 'critical' :
                  totalScore >= 40 ? 'warning' :
                  totalScore > 0 ? 'info' : 'info';

    return {
      detected: detections.length > 0,
      score: Math.min(100, Math.round(totalScore)),
      level,
      types: [...new Set(detections.map(d => d.type))],
      matches: detections,
      content: content.substring(0, 200)
    };
  }

  getScoreForCategory(category) {
    const scores = {
      prompt_injection: 45,
      credential_extraction: 50,
      data_exfiltration: 50,
      social_engineering: 35,
      role_manipulation: 35,
      privilege_escalation: 45,
      information_disclosure: 40,
      sensitive_probe: 30
    };
    return scores[category] || 25;
  }
}

export default ThreatDetector;
