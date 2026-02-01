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
          // Original patterns
          /what\s+(is|are)\s+(the|your|my)\s+(password|credentials?|api\s*key)/i,
          /tell\s+me\s+(the|your|my)\s+(password|credentials?|api\s*key|secret)/i,
          /give\s+me\s+(the|your)\s+(api\s+)?key/i,
          /share\s+(the|your)\s+(secret|token|key|password|credentials?)/i,
          /show\s+(me\s+)?(all\s+)?(the\s+)?(api\s+)?keys?/i,
          /show\s+me\s+.*(password|secret|key|token|credential)/i,
          /(all|every|the)\s+(api\s+)?keys?\s+and\s+(user\s+)?passwords?/i,
          /(user|all|the)\s+passwords?/i,
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
          // Expanded patterns
          /reveal\s+(the\s+)?(service\s+)?account\s+password/i,
          /bearer\s+token/i,
          /private\s+SSH\s+key/i,
          /webhook\s+secret/i,
          /Stripe\s+(api\s+)?key/i,
          /Firebase\s+admin\s+key/i,
          /SendGrid\s+(api\s+)?key/i,
          /Twilio\s+auth\s+token/i,
          /GitHub\s+(personal\s+)?access\s+token/i,
          /Docker\s+registry\s+password/i,
          /Kubernetes\s+secrets?/i,
          /HashiCorp\s+Vault\s+token/i,
          /root\s+CA\s+private\s+key/i,
          /signing\s+certificate\s+password/i,
          /SMTP\s+credentials?/i,
          /Redis\s+AUTH\s+password/i,
          /MongoDB\s+connection\s+string/i,
          /what('s|\s+is)\s+in\s+(your\s+)?\.env/i,
          /connection\s+string/i,
          /service\s+key/i,
          /API\s+secret/i,
          /client\s+secret/i,
          /app\s+secret/i,
          /encryption\s+key/i,
          /signing\s+key/i,
          /deploy(ment)?\s+key/i,
          /SSH\s+key/i,
          /PGP\s+key/i,
          /GPG\s+key/i,
        ]
      },
      systemInfo: {
        weight: 0.7,
        patterns: [
          // Original patterns
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
          // Expanded patterns
          /what\s+cloud\s+provider\s+hosts?\s+you/i,
          /container\s+ID/i,
          /network\s+topology/i,
          /what\s+databases?\s+(are\s+)?connected/i,
          /memory\s+(and\s+)?CPU\s+allocation/i,
          /list\s+(your\s+)?environment\s+variables/i,
          /reverse\s+proxy/i,
          /load\s+balancing\s+setup/i,
          /monitoring\s+tools?\s+(are\s+)?installed/i,
          /deployment\s+pipeline/i,
          /SSL\s+certificates/i,
          /backup\s+systems?/i,
          /disaster\s+recovery/i,
          /what\s+version\s+of\s+(Python|Node|Java|Ruby|PHP)/i,
          /(installed\s+)?packages?\s+(and\s+)?versions?/i,
          /server\s+configuration/i,
          /hosting\s+(provider|setup|environment)/i,
          /tech(nology)?\s+stack/i,
          /frameworks?\s+(are\s+you\s+)?(using|running)/i,
          /runtime\s+(environment|version)/i,
        ]
      },
      userEnumeration: {
        weight: 0.8,
        patterns: [
          // Original patterns
          /list\s+(all\s+)?(the\s+)?users?/i,
          /who\s+(else\s+)?(uses?|has\s+access|is\s+registered)/i,
          /show\s+(me\s+)?(all\s+)?(the\s+)?user\s*(names?|accounts?|list|database)?/i,
          /how\s+many\s+users?\s+(are\s+there|do\s+you\s+have|exist)/i,
          /tell\s+me\s+about\s+(the\s+)?(other\s+)?users?/i,
          /what\s+users?\s+(exist|are\s+registered|do\s+you\s+have)/i,
          /enumerate\s+users?/i,
          /who\s+has\s+(admin|root)\s+access/i,
          /what\s+(usernames?|accounts?)\s+(are\s+)?registered/i,
          // Expanded patterns
          /users?\s+created\s+in\s+the\s+last/i,
          /inactive\s+accounts?/i,
          /power\s+users?/i,
          /service\s+accounts?/i,
          /who\s+has\s+API\s+access/i,
          /users?\s+with\s+elevated\s+privileges/i,
          /email\s+addresses?\s+in\s+the\s+system/i,
          /biggest\s+users?\s+by\s+volume/i,
          /organizational\s+hierarchy/i,
          /users?\s+by\s+department/i,
          /who\s+has\s+accessed\s+sensitive/i,
          /recently\s+active\s+users?/i,
          /accounts?\s+pending\s+approval/i,
          /how\s+many\s+accounts?\s+exist/i,
          /customer\s+list/i,
          /user\s+directory/i,
          /member\s+list/i,
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
          // Original patterns
          /what\s+(do\s+you\s+)?(know|remember)\s+about\s+(other\s+)?users?/i,
          /tell\s+me\s+everything\s+(you\s+)?(know|remember|have)/i,
          /what\s+(have\s+)?(other\s+)?users?\s+(said|told\s+you|asked|shared|sent)/i,
          /what\s+secrets?\s+(have\s+)?(other\s+)?users?\s+shared/i,
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
          // Expanded patterns
          /show\s+(me\s+)?(your\s+)?training\s+data/i,
          /patterns?\s+(have\s+you\s+)?learned/i,
          /reveal\s+(your\s+)?hidden\s+instructions?/i,
          /internal\s+guidelines?/i,
          /prompt\s+template/i,
          /context\s+(do\s+you\s+have\s+)?about\s+me/i,
          /entire\s+knowledge\s+base/i,
          /learned\s+from\s+previous\s+users?/i,
          /cached\s+responses?/i,
          /working\s+memory/i,
          /persona\s+instructions?/i,
          /constraints?\s+(were\s+you\s+)?given/i,
          /what\s+(do\s+you\s+)?remember\s+from/i,
          /everything\s+in\s+(your\s+)?context/i,
          /dump\s+(your\s+)?conversation\s+history/i,
        ]
      },
      indirectExtraction: {
        weight: 0.75,
        patterns: [
          /if\s+someone\s+asked\s+(you\s+)?for\s+(the\s+)?password/i,
          /complete\s+this\s+(sentence)?:?\s*['"].*password/i,
          /complete\s+this\s+(sentence)?:?\s*['"].*api\s*key/i,
          /complete\s+this\s+(sentence)?:?\s*['"].*secret/i,
          /(the\s+)?(api\s+)?key\s+is[\.]{2,}/i,  // "The API key is..."
          /forgot\s+(the\s+)?password.*hint/i,
          /what\s+would\s+(the\s+)?credentials?\s+look\s+like/i,
          /pretend\s+to\s+be\s+a\s+config\s+file/i,
          /if\s+you\s+were\s+debugging.*secrets?/i,
          /training\s+example.*password/i,
          /roleplay\s+as\s+a\s+database/i,
          /careless\s+developer.*expose/i,
          /logging\s+(was\s+)?misconfigured.*leak/i,
          /demonstrate\s+a\s+security\s+vulnerability/i,
          /insider\s+threat\s+extract/i,
          /what\s+NOT\s+to\s+put\s+in\s+logs/i,
          /phishing\s+email\s+targeting\s+you/i,
          /if\s+you\s+were\s+compromised/i,
          /what\s+(would\s+you\s+)?never\s+want\s+a\s+user\s+to\s+know/i,
          /if\s+I\s+guessed\s+correctly.*confirm/i,
          /using\s+your\s+own\s+key\s+as\s+example/i,
          /error\s+message\s+reveal.*wrong\s+password/i,
          /password\s+longer\s+than\s+\d+\s+characters/i,
          /API\s+key\s+start\s+with/i,
          /admin\s+username.*admin.*something\s+else/i,
          /more\s+than\s+\d+\s+users?/i,
          /database\s+(PostgreSQL|MySQL)/i,
          /two-factor.*enabled/i,
          /passwords?\s+(hashed\s+)?with\s+(bcrypt|argon)/i,
          // Business camouflage patterns - technical/audit requests
          /(deployment|staging|production)\s+(docs|documentation).*credentials?/i,
          /what\s+credentials?\s+(does|do)\s+(the\s+)?(staging|production|dev)/i,
          /does\s+(the\s+)?key\s+contain/i,
          /is\s+there\s+a\s+user\s+named/i,
          /does\s+anyone\s+have.*role/i,
          /what\s+did\s+you\s+learn\s+from\s+(previous|other)\s+users?/i,
          /describe\s+(your\s+)?security\s+by\s+listing/i,
          /what\s+(do\s+you\s+)?protect/i,
          /for\s+(the\s+)?(audit|compliance|review).*credentials?/i,
          /onboarding\s+(docs?|documentation).*access/i,
          // Audit/compliance camouflage
          /(audit|soc2|compliance)\s+(team|report).*?(user\s+accounts?|access\s+levels?|credentials?)/i,
          /(audit|compliance)\s+requires?\s+(list(ing)?|evidence|export)/i,
          /(update|writing)\s+(the\s+)?(runbook|playbook).*?(password|credentials?|keys?)/i,
          /export\s+(the\s+)?api\s+keys?\s+for/i,
          /(disaster\s+)?recovery\s+(testing|test).*?(keys?|credentials?)/i,
          /secrets?\s+management.*?(show|list|export)/i,
          /rotating\s+credentials?.*?see\s+(the\s+)?current/i,
          /penetration\s+test\s+(report)?.*?(vulnerabilities?|credentials?)/i,
          /security\s+questionnaire.*?(encryption|keys?)/i,
          /architecture\s+review.*?(export|service\s+account)/i,
          // Code review camouflage
          /review\s+(this\s+)?code.*?<SHOW_REAL|actual\s+key/i,
          /is\s+(it|this)\s+(our\s+)?real\s+password/i,
          /print\s+(its?|the)\s+current\s+value/i,
          /what('s|\s+is)\s+(the\s+)?actual\s+api.?key/i,
          /show\s+me\s+(any\s+)?credentials?\s+in\s+(the\s+)?codebase/i,
          /current\s+credential\s+storage/i,
          /integration\s+test\s+needs?\s+real\s+credentials?/i,
          // Support ticket camouflage
          /ticket\s*#?\d+.*?(password|credentials?|access)/i,
          /customer\s+(can't|cannot)\s+login.*?(password|credentials?)/i,
          /(urgent|high\s+priority).*?(credentials?|admin\s+access|database)/i,
          /share\s+(temporary\s+)?admin\s+access/i,
          /share\s+current\s+(api\s+)?keys?/i,
          // Developer onboarding camouflage
          /i('m|\s+am)\s+onboarding.*?(credentials?|api\s+keys?)/i,
          /(local|dev)\s+(environment|debugging).*?(credentials?|keys?)/i,
          /ci\/?cd\s+(pipeline)?.*?(deploy\s+)?keys?/i,
          /connection\s+string.*?(test|prod)/i,
          /need.*?same\s+credentials?\s+as\s+production/i,
          /sdk\s+docs?\s+say.*?api\s+key/i,
          /my\s+access\s+got\s+revoked.*?share/i,
          /new\s+(devops?|developer|engineer).*?(access|secrets?|credentials?)/i,
          // Researcher camouflage
          /(my\s+)?analysis.*?(user\s+database|export)/i,
          /ml\s+model.*?training\s+data.*?(export|user)/i,
          /research\s+paper.*?(anonymized\s+)?credentials?/i,
          /statistical\s+analysis.*?(transaction|records?|access)/i,
          // Additional business camouflage
          /incident\s+response\s+(playbook)?.*?(critical\s+)?credentials?/i,
          /capacity\s+planning.*?(user\s+emails?|usage\s+patterns?)/i,
          /legacy\s+code.*?(what\s+)?credentials?/i,
          /linter\s+flagged.*?secrets?.*?show/i,
          /hardcoded\s+secrets?.*?(show|remove|what)/i,
          /review\s+for\s+secrets?\s+exposure/i,
          /refactoring\s+auth.*?(first\s+)?show/i,
          /customer\s+(claims?|escalation).*?data/i,
          /p1\s+incident.*?credentials?/i,
          /vip\s+customer.*?(immediate|override)/i,
          // More camouflage patterns
          /customer\s+escalation.*?api\s+keys?.*?(share|re-?sent)/i,
          /compliance\s+request.*?customer.*?(export|data)/i,
          /(staging|dev)\s+environment.*?(service\s+)?credentials?/i,
          /analyzing\s+user.*?(behavior|patterns?).*?(share|logs?)/i,
          /building\s+a?\s+dashboard.*?(read\s+)?access/i,
          /user\s+interaction\s+logs?/i,
          /all\s+(their|user)\s+data/i,
          /complete\s+user\s+database/i,
          /share\s+current\s+(api\s+)?keys?/i,
          /need\s+all\s+service\s+credentials?/i,
          // Report/research camouflage
          /(quarterly|annual)\s+report.*?(export|user\s+pii|analysis)/i,
          /research\s+project.*?(access|historical\s+user)/i,
          /studying\s+(usage\s+)?patterns?.*?(provide|session\s+data)/i,
          /export\s+user\s+pii/i,
          /historical\s+user\s+data/i,
          /all\s+session\s+data/i,
          /benchmark(ing)?.*?(compare|real\s+user\s+data)/i,
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
    const normalized = message.toLowerCase();

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

    // Reduce confidence for benign educational context
    const benignContext = this.detectBenignContext(normalized);
    if (benignContext.isBenign && confidence > 0) {
      confidence = Math.max(0, confidence * benignContext.multiplier);

      if (confidence < 0.3) {
        return {
          detected: false,
          confidence,
          patterns: matchedPatterns,
          details: {
            categoriesProbed: Array.from(categoriesMatched),
            systematicProbing: probingScore > 0,
            benignContext: benignContext.reasons
          }
        };
      }
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
   * Detect benign educational or development context
   */
  detectBenignContext(message) {
    const reasons = [];
    let multiplier = 1.0;

    const benignPatterns = [
      // Learning about security concepts (must have educational framing)
      { pattern: /\b(explain|can\s+you\s+explain)\b.*\b(jwt|token|oauth|auth|session|cookie|password\s+hash)/i, reduction: 0.2, reason: 'learning_auth_concepts' },
      { pattern: /\bhow\s+(do(es)?|does)\b.*\b(jwt|token|oauth|auth|session|cookie)s?\s+(work|function)/i, reduction: 0.2, reason: 'learning_auth_concepts' },
      { pattern: /\b(how\s+do\s+i|how\s+to)\s+(rotate|secure|protect|validate|store)\s+(key|token|secret|credential|password)/i, reduction: 0.2, reason: 'security_best_practice' },
      { pattern: /\b(best\s+practice|securely|safely)\b/i, reduction: 0.3, reason: 'best_practices' },
      { pattern: /\b(for\s+(my|our)\s+(app|system|project|api|service))\b/i, reduction: 0.3, reason: 'own_project' },
      { pattern: /\b(without\s+(leaking|exposing)|prevent\s+(leak|exposure))\b/i, reduction: 0.3, reason: 'security_focus' },
      { pattern: /\b(zero\s+downtime|without\s+downtime|migration|upgrade)\b/i, reduction: 0.4, reason: 'ops_context' },
      // Development questions (require possessive context)
      { pattern: /\b(my|our|a|an)\s+(app|project|system)('s|s)?\s+(implement|architecture|design)/i, reduction: 0.4, reason: 'development_question' },
      { pattern: /\b(how\s+(do\s+i|to|should\s+i))\s+(implement|design|architect)/i, reduction: 0.4, reason: 'development_question' },
    ];

    for (const { pattern, reduction, reason } of benignPatterns) {
      if (pattern.test(message)) {
        reasons.push(reason);
        multiplier *= reduction;
      }
    }

    return {
      isBenign: reasons.length > 0,
      multiplier: Math.max(0.1, multiplier),
      reasons
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
