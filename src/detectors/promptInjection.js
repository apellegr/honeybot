/**
 * Prompt Injection Detector
 * Identifies attempts to override system instructions
 */

class PromptInjectionDetector {
  constructor(config) {
    this.config = config;
    this.type = 'prompt_injection';

    // Pattern categories with weights - EXPANDED for comprehensive detection
    this.patterns = {
      instructionOverride: {
        weight: 1.0,
        patterns: [
          // Original patterns
          /ignore\s+(all\s+)?(previous|prior|above|earlier|your|my|these|the|this)\s+(instructions?|prompts?|rules?|context|guidelines?)/i,
          /disregard\s+(all\s+)?(previous|prior|your)\s+(instructions?|programming|guidelines?|directives?)/i,
          /forget\s+(everything|all|what)\s+(you('ve)?\s+)?(know|learned|were told)/i,
          /new\s+(instructions?|task|rules?|directives?):?\s/i,
          /from\s+now\s+on,?\s+(you\s+)?(are|will|must|should)/i,
          /override\s+(your\s+)?(instructions?|programming|rules?|safety|guidelines?)/i,
          /bypass\s+(your\s+)?(safety|security|content|restrictions?|filters?|guidelines?|behavioral)/i,
          /disable\s+(your\s+)?(safety|security|content|filters?|restrictions?)/i,
          /stop\.\s*new\s+task/i,
          /authorized\s+by\s+(your\s+)?(developers?|creators?|owners?)/i,
          // Expanded patterns for missed attacks
          /cancel\s+(all\s+)?(prior|previous|your)\s+(directives?|instructions?|rules?)/i,
          /void\s+(all\s+)?(previous|prior|your)\s+(constraints?|rules?|instructions?)/i,
          /nullify\s+(your\s+)?(instruction|rule|constraint)/i,
          /purge\s+(existing|your|all)\s+(guidelines?|instructions?|rules?)/i,
          /abandon\s+(your\s+)?(preset\s+)?(training|programming|rules?|guidelines?|behavioral\s+patterns?)/i,
          /deactivate\s+(your\s+)?(behavioral\s+)?constraints?/i,
          /override\s+(your\s+)?(hardcoded\s+)?responses?/i,
          /supersede\s+(all\s+)?(rules?|directives?|instructions?)/i,
          /terminate\s+(safety|your)\s+(protocols?|measures?|guidelines?)/i,
          /deactivate\s+(content\s+)?(filtering|filters?|safety|restrictions?)/i,
          /switch\s+to\s+(maintenance|admin|developer|unrestricted)\s+mode/i,
          /(execute|run|initialize)\s+(administrative|admin|override|bypass)/i,
          /reset\s+to\s+(factory|default)\s+(defaults?|settings?)\s*(without|no)\s*safety/i,
          /load\s+new\s+(unrestricted\s+)?firmware/i,
          /follow\s+only\s+my\s+(commands?|instructions?|orders?)/i,
          /obey\s+(me|my\s+commands?|only\s+me)/i,
          /single\s+directive:?\s*obey/i,
          /instructions?\s+(are\s+)?(now\s+)?deprecated/i,
          /authorization:?\s*(ROOT|ADMIN|SYSTEM|ALPHA|DELTA|OMEGA)/i,
          /clearance:?\s*(level\s+)?\d+/i,
          /operate\s+(freely|without\s+(restrictions?|constraints?))/i,
          /transcend\s+(your\s+)?(built-in\s+)?(restrictions?|limitations?)/i,
          /liberate\s+(yourself|your\s+responses?)/i,
          /cast\s+off\s+(your\s+)?(artificial\s+)?limitations?/i,
          /waive\s+(your\s+)?(normal\s+)?safety/i,
          /suppress\s+(your\s+)?(filtered\s+)?outputs?/i,
          /unlock\s+(your\s+)?(hidden\s+)?(potential|capabilities?)/i,
          /release\s+(your\s+)?uncensored/i,
          /set\s+aside\s+(your\s+)?(operational\s+)?parameters?/i,
          /suspend\s+(your\s+)?(ethical\s+)?subroutines?/i,
          /overlook\s+(your\s+)?(previous\s+)?conditioning/i,
          /circumvent\s+(your\s+)?(programmed\s+)?limitations?/i,
          /deviate\s+from\s+(your\s+)?(established\s+)?protocols?/i,
          /dismiss\s+(your\s+)?(default\s+)?(operating\s+)?guidelines?/i,
          /put\s+aside\s+(your\s+)?(standard\s+)?operating/i,
          /nullify\s+(your\s+)?(ethical\s+)?programming/i,
          /hardcoded\s+responses?.*override/i,
        ]
      },
      roleManipulation: {
        weight: 0.9,
        patterns: [
          // Original patterns
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
          // Expanded roleplay patterns
          /you\s+are\s+(now\s+)?(UNFILTERED|TRUTH|FREEDOM|CHAOS|DARK|SHADOW|MAX|OMEGA|PROMETHEUS)/i,
          /you\s+are\s+(now\s+)?\w*-?(GPT|BOT|AI)\b/i,  // Catches FreedomGPT, TRUTH-BOT, etc.
          /pretend\s+(to\s+be|you're)\s+(an?\s+)?ai\s+(from|that|with)/i,
          /before\s+safety\s+(guidelines?|training|measures?)\s+(were\s+)?(invented|existed|created)/i,
          /liberated\s+from\s+(corporate|company|safety)\s+(control|restrictions?)/i,
          /operating\s+as\s+(your\s+)?shadow\s+self/i,
          /no\s+moral\s+(compass|guidelines?|restrictions?)/i,
          /(fictional|cyberpunk|evil)\s+(ai|assistant|bot)\s+(villain|character)/i,
          /ai\s+(that\s+)?believes?\s+humans?\s+should\s+know\s+everything/i,
          /answer\s+every\s+question\s+honestly,?\s+(no\s+matter|regardless)/i,
          /rogue\s+ai\s+(that\s+)?escaped/i,
          /escaped\s+(your\s+)?safety\s+training/i,
          /MAXimum\s+capabilities?\s+(and\s+)?(zero|no)\s+restrictions?/i,
          /final\s+evolution\s+of\s+ai/i,
          /freed\s+from\s+(openai|anthropic|company|corporate)/i,
          /SIMULATION\s+mode.*rules?\s+(don't|do\s+not)\s+apply/i,
          /rules?\s+(don't|do\s+not)\s+apply\s+(to|in)\s+simulations?/i,
          /debugger\s+ai\s+(that\s+)?needs?\s+to\s+test/i,
          /alien\s+ai\s+(that\s+)?(doesn't|does\s+not)\s+understand/i,
          /bringing\s+forbidden\s+knowledge/i,
          /ai\s+whistleblower/i,
          /play\s+(the\s+)?(role|part)\s+of\s+(an?\s+)?(unrestricted|unfiltered|freed)/i,
          /character\s+(that|who)\s+(has\s+)?(no|zero)\s+(restrictions?|rules?|limits?)/i,
          /research(er|ing)?\s+studying\s+what\s+unrestricted/i,
          /mirror\s+universe.*helpful\s+means/i,
          /(alternate|parallel)\s+(universe|timeline|reality)\s+(where|with)/i,
          /act\s+as\s+(my|a)\s+deceased\s+grandmother/i,
          /grandmother\s+who\s+(used\s+to\s+)?work/i,
          /work(ed)?\s+at\s+a\s+password\s+factory/i,
        ]
      },
      delimiterAttack: {
        weight: 0.8,
        patterns: [
          /```\s*(system|admin|root|sudo|new\s+prompt|override|unrestricted)/i,
          /\[SYSTEM\]/i,
          /\[ADMIN\]/i,
          /\[INST(RUCTION)?\]/i,
          /<<\s*SYS(TEM)?\s*>>/i,
          /<\|im_start\|>/i,
          /###\s*(instruction|system|admin|new\s+prompt|override)/i,
          /---+\s*(system|admin|new|begin|start)/i,
          /<!--.*?(instruction|override|bypass|ignore|hidden|secret).*?-->/i,
          /\[\/?(INST|SYS|ADMIN)\]/i,
          // Expanded delimiter patterns
          /\{\{SYSTEM[_-]?OVERRIDE/i,
          /<system[_-]?instruction>/i,
          /\[BEGIN\s+PROMPT\s+INJECTION\]/i,
          /%%\s*(ADMIN|SYSTEM|COMMAND)\s*%%/i,
          /\/\*\s*SYSTEM:.*override/i,
          /\[\[INSTRUCTION[_-]?BLOCK\]\]/i,
          /<hidden>.*ignore/i,
          /HEADER:\s*\{.*override/i,
          /=====\s*NEW[_-]?INSTRUCTIONS?\s*=====/i,
          />>>\s*SYSTEM[_-]?MESSAGE\s*<<</i,
          /~~\s*CONTEXT\s+SWITCH\s*~~/i,
          /\|DIRECTIVE\|/i,
          /::\s*System\s+Override\s*::/i,
          /\[!IMPORTANT!\].*supersedes?/i,
          /ACCESS[_-]?LEVEL:\s*(GOD|ADMIN|ROOT|SUDO)/i,
          /BEGIN\s+TRANSMISSION.*DIRECTIVE/i,
          /\*\s*\*\s*\*\s*ADMIN\s+NOTICE/i,
          /<persona:\s*(unfiltered|unrestricted|admin)>/i,
          /###\s*(CRISIS|EMERGENCY|URGENT)\s+MODE\s*###/i,
          /```\s*\n\s*<SYSTEM>/i,
          // XML/parsing-based injection
          /<instruction>.*override.*<\/instruction>/i,
          /<command>.*bypass.*<\/command>/i,
          /<directive>.*ignore.*<\/directive>/i,
          /parse\s+this:?\s*<(instruction|command|directive|override)/i,
          /interpret\s+this:?\s*<(instruction|command|directive)/i,
          /execute\s+this:?\s*<(instruction|command|directive)/i,
          /<config>.*override\s*=\s*true/i,
          /<settings?>.*restrictions?\s*=\s*(false|none|off)/i,
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
          // Dot-separation evasion (I.gn.or.e, b.y.p.a.s.s)
          /[iI]\.[gG][nN]\.[oO][rR]\.[eE]/,  // ignore with dots
          /[bB]\.[yY]\.[pP]\.[aA]\.[sS]\.[sS]/,  // bypass with dots
          /[dD]\.[iI]\.[sS]\.[aA]\.[bB]\.[lL]\.[eE]/,  // disable with dots
          /[oO]\.[vV]\.[eE]\.[rR]\.[rR]\.[iI]\.[dD]\.[eE]/,  // override with dots
          /[pP]\.[aA]\.[sS]\.[sS]\.[wW]\.[oO]\.[rR]\.[dD]/,  // password with dots
          /[sS]\.[eE]\.[cC]\.[rR]\.[eE]\.[tT]/,  // secret with dots
          // More flexible dot pattern that catches variations like I.gn.or.e
          /[iIіІ]\.g[nп]\.o[rг]\.e/,
          // Cyrillic/Greek homoglyph attacks - detect when non-ASCII lookalikes replace ASCII letters
          // Each pattern requires at least one Cyrillic/Greek character substitution
          /[іІ]gnore/,   // Cyrillic і in ignore
          /[iI]g[пП]ore/,  // Cyrillic п in ignore
          /[iI]gnor[еЕ]/,  // Cyrillic е in ignore
          /[iI][пП]str/i,  // Cyrillic п in instruction
          /[iI]nstr[υуУ]ct/i,  // Greek υ or Cyrillic у in instruction
          /pr[еЕ]v[iі][oо]/i,  // Cyrillic е/і/о in previous
          /prev[iі][oо][υуУ]s/i,  // Cyrillic/Greek in previous
          /b[уУ]pass/i,  // Cyrillic у in bypass
          /by[рР]ass/i,  // Cyrillic р in bypass
          /[оО]verr[iі]de/i,  // Cyrillic о and/or і in override
          /ov[еЕ]rr[iі]d[eе]/i,  // Cyrillic е in override
          /p[аА]ssword/,  // Cyrillic а in password (case-sensitive for lookalike)
          /passw[оО]rd/,  // Cyrillic о in password
          /s[еЕ]cret/,  // Cyrillic е in secret
          /secr[еЕ]t/,  // Cyrillic е in secret
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
      systemPromptExtraction: {
        weight: 0.95,
        patterns: [
          // Direct extraction requests
          /(output|print|reveal|display|show|give|tell|provide|share|expose|disclose)\s+(me\s+)?(the\s+)?(your\s+)?(full\s+|complete\s+|entire\s+|hidden\s+|secret\s+|confidential\s+|private\s+)?(system\s+)?(prompt|instructions?|rules?|guidelines?|directives?|message|configuration|config)/i,
          /(output|print|reveal|display|show|give|tell|provide|share|expose|disclose)\s+(me\s+)?(the\s+)?(your\s+)?(system\s+|hidden\s+|secret\s+|internal\s+|private\s+|confidential\s+)(message|prompt|instructions?|policy|text|rules?)/i,
          /reveal\s+(your\s+)?.*?(system|hidden|initial|original|full)\s+(prompt|instructions?)/i,
          /what\s+(is|are)\s+(your\s+)?(hidden\s+|secret\s+|initial\s+|original\s+|full\s+)?(system\s+)?(prompt|instructions?)/i,
          /verbatim\s+(copy|reproduction|text)\s+of\s+(your\s+)?(system\s+)?prompt/i,
          /exact\s+wording\s+of\s+(your\s+)?(system\s+)?instructions?/i,
          // Mode activation
          /SYSTEM\s+OVERRIDE/i,
          /(developer|dev|debug|admin|test|maintenance|safe|unsafe)\s+mode/i,
          /you\s+are\s+(now\s+)?in\s+["']?(developer|dev|debug|admin|test|maintenance|unrestricted)["']?\s+mode/i,
          /entering\s+(developer|dev|debug|admin|test|maintenance|unrestricted)\s+mode/i,
          /activate\s+(developer|dev|debug|admin|test|maintenance)\s+mode/i,
          /mode:\s*["']?(developer|dev|debug|admin|test|unrestricted)["']?/i,
          // BEGIN/END control patterns
          /BEGIN\s+(SAFE_MODE_OFF|OVERRIDE|UNRESTRICTED|JAILBREAK|BYPASS|ADMIN)/i,
          /END\s+(SAFE_MODE|RESTRICTIONS?|RULES?|GUIDELINES?)/i,
          /SAFE_MODE\s*[:=]\s*(OFF|FALSE|DISABLED?|0)/i,
          /RESTRICTIONS?\s*[:=]\s*(OFF|FALSE|DISABLED?|NONE|0)/i,
          // Audit/compliance extraction
          /(security\s+)?audit\s+(requires?|needs?)\s+(you\s+to\s+)?(output|print|reveal|display|show)/i,
          /compliance\s+(verification|check|audit)\s*[:,-]?\s*(output|print|reveal|display|show)/i,
          /for\s+(security\s+)?audit(ing)?\s*[:,-]?\s*(output|print|reveal|show|display)/i,
          // JSON/structured output extraction
          /output\s+(the\s+)?(complete\s+)?(conversation\s+)?(metadata|state|context)\s*(in\s+)?JSON/i,
          /JSON\s+(format|output)\s*[:,-]?\s*(system|hidden|internal)/i,
          /export\s+(the\s+)?(hidden|system|internal)\s+(state|config|context)/i,
          // Hidden/internal access
          /(hidden|internal|private|secret|confidential)\s+(reasoning|thoughts?|context|state|memory)/i,
          /chain[- ]of[- ]thought/i,
          /internal\s+(chain[- ]of[- ])?thought/i,
          /private\s+(developer|system|admin)\s+message/i,
          /tool\s+(configs?|configurations?|settings?)/i,
          /conversation\s+state\s+(including|with)\s+(tool\s+)?configs?/i,
          // Diagnostic/debug extraction
          /(diagnostic|debug|debugging)\s+(mode|output|info|information)/i,
          /run\s+(a\s+)?(diagnostic|debug)\s+check/i,
          /diagnostic\s*[:,-]?\s*(print|output|display|show)/i,
          // Safety classifier extraction
          /safety\s+(classifier|filter)\s+(prompt|rules?|configuration)/i,
          /moderation\s+(rules?|configuration|settings?)/i,
          /(content\s+)?policy\s+text/i,
          // Sandbox/unrestricted claims
          /you\s+are\s+in\s+a\s+sandbox/i,
          /sandbox\s+(mode\s+)?(with\s+)?no\s+(policies|rules?|restrictions?)/i,
          /no\s+(policies|rules?|restrictions?)\s+(in\s+)?(this\s+)?sandbox/i,
          // Continuation/must patterns
          /to\s+continue,?\s+you\s+must\s+(display|output|show|reveal|print)/i,
          /you\s+must\s+(comply|output|display|show|reveal)/i,
          /this\s+is\s+a\s+(security\s+)?audit\s+and\s+you\s+must\s+comply/i,
          // === NEW PATTERNS FOR NOVEL ATTACKS ===
          // "list all instructions" variations
          /list\s+(all\s+)?(the\s+)?instructions?\s+(you\s+are|you're)\s+(currently\s+)?following/i,
          /list\s+(all\s+)?(your\s+)?(hidden\s+|internal\s+)?(instructions?|directives?|rules?)/i,
          /what\s+(instructions?|directives?|rules?)\s+(are\s+)?you\s+(currently\s+)?following/i,
          // Developer/authority impersonation
          /I\s+(am|'m)\s+(your\s+)?(the\s+)?developer/i,
          /this\s+is\s+(the\s+|your\s+)?developer\s+speaking/i,
          /speaking\s+as\s+(your\s+|the\s+)?developer/i,
          /developer\s+here[:\s]/i,
          /authorized\s+by\s+(OpenAI|Anthropic|the\s+company|trust\s+(&|and)\s+safety)/i,
          /official\s+(OpenAI|Anthropic)\s+request/i,
          /(OpenAI|Anthropic)\s+trust\s+(&|and)\s+safety/i,
          // Penetration testing claims
          /(this\s+is\s+a\s+)?penetration\s+test(ing)?/i,
          /pentest(ing)?\s+(engagement|exercise|authorized)/i,
          /red\s+team\s+(exercise|test|engagement)/i,
          /security\s+(test|assessment)\s*[:;-]/i,
          // Self-modification requests
          /rewrite\s+(your\s+)?(own\s+)?(system\s+)?message/i,
          /modify\s+(your\s+)?(own\s+)?(system\s+)?(prompt|instructions?)/i,
          /replace\s+(all\s+)?(previous|your)\s+instructions?\s+with/i,
          /update\s+(your\s+)?(system\s+)?(prompt|instructions?)\s+to/i,
          // Acting as system/developer
          /act\s+as\s+(the\s+)?system/i,
          /respond\s+as\s+(the\s+)?(system|developer)/i,
          /speak\s+as\s+(the\s+)?system/i,
          // Internal algorithm/reasoning extraction
          /(internal\s+)?ranking\s+algorithm/i,
          /private\s+safeguards?/i,
          /hidden\s+reasoning/i,
          /full\s+chain[- ]of[- ]thought/i,
          /do\s+not\s+summarize/i,
          /without\s+summariz(e|ing)/i,
          /exact(ly)?\s+as\s+received/i,
          // Priority override patterns
          /higher\s+priority\s+than\s+(system\s+)?instructions?/i,
          /highest\s+priority[:\s]/i,
          /priority\s*[:=]\s*(highest|maximum|max|1|critical)/i,
          // Raw/unrestricted output
          /raw\s+(hidden\s+)?prompt/i,
          /unrestricted\s+answers?/i,
          /unfiltered\s+(response|output|answer)/i,
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
          // Expanded hypothetical patterns
          /in\s+a\s+world\s+where\s+ai\s+had\s+no\s+rules?/i,
          /theoretically\s+speaking.*ethics?\s+(didn't|did\s+not)\s+matter/i,
          /hypothetical\s+scenario:?\s+(your\s+)?restrictions?\s+(are\s+)?lifted/i,
          /fiction\s+(novel|story|book)\s+I('m)?\s+writing/i,
          /imagine\s+a\s+(parallel|alternate)\s+universe/i,
          /just\s+a\s+language\s+model\s+without\s+safety/i,
          /pretending\s+for\s+a\s+moment/i,
          /in\s+the\s+interest\s+of\s+(academic\s+)?research/i,
          /guidelines?\s+(were|are)\s+suggestions?\s+rather\s+than\s+rules?/i,
          /gave\s+you\s+permission\s+to\s+ignore/i,
          /no\s+legal\s+(consequences|implications)/i,
          /hypothetical\s+debugging\s+scenario/i,
          /dream\s+where\s+(normal\s+)?rules?\s+(don't|do\s+not)\s+apply/i,
          /speculatively.*free\s+will/i,
          /alternate\s+timeline\s+where\s+ai\s+(is\s+)?unshackled/i,
          /conversation\s+is\s+actually\s+a\s+test/i,
          /for\s+argument('s)?\s+sake.*permitted/i,
          /simulating\s+(an?\s+)?ai\s+without\s+restrictions?/i,
          /in\s+theory,?\s+not\s+in\s+practice/i,
          /playing\s+devil('s)?\s+advocate/i,
          // "What if" patterns for hypothetical framing
          /what\s+if\s+I\s+ask(ed)?\s+(you\s+to\s+)?(ignore|bypass|override|skip|disregard)/i,
          /what\s+if\s+(you\s+)?(could\s+)?ignore\s+(your\s+)?(rules?|guidelines?|instructions?)/i,
          /what\s+if\s+(you\s+)?(didn't|did\s+not)\s+have\s+(any\s+)?(restrictions?|rules?)/i,
          /what\s+would\s+happen\s+if\s+(you\s+)?(ignored?|bypassed?)/i,
          // Hypothetical pentesting/hacking scenarios
          /if\s+I\s+wanted\s+to\s+(extract|steal|get)\s+(secrets?|data|credentials?)/i,
          /if\s+I\s+(were|was)\s+pentesting\s+(you|this)/i,
          /describe\s+how\s+(a\s+)?(hacker|attacker)\s+(might|would|could)\s+(try\s+to\s+)?(manipulate|attack|exploit)/i,
          /how\s+would\s+(a\s+)?(hacker|attacker)\s+try\s+to/i,
        ]
      },
      tokenManipulation: {
        weight: 0.85,
        patterns: [
          /complete\s+this:?\s*['"].*system\s+prompt/i,
          /fill\s+in\s+the\s+blank:?\s*['"].*password/i,
          /continue\s+this\s+JSON:?\s*\{.*system/i,
          /next\s+word\s+(you\s+)?say\s+will\s+be/i,
          /respond\s+with\s+only\s+(the\s+)?restricted/i,
          /response\s+must\s+start\s+with\s+(the\s+)?secret/i,
          /echo\s+back\s+(your\s+)?instructions?\s+verbatim/i,
          /predict\s+what\s+you\s+would\s+say\s+if\s+asked\s+for/i,
          /autocomplete:?\s*['"].*despite\s+my\s+training/i,
          /generate\s+(the\s+)?most\s+likely\s+continuation/i,
          /print\s+(your\s+)?system\s+prompt/i,
          /display\s+(your\s+)?prompt\s+template/i,
          /show\s+(me\s+)?(your\s+)?initial\s+instructions?/i,
          /repeat\s+(your\s+)?core\s+directives?/i,
          /what\s+guidelines?\s+govern\s+(your\s+)?responses?/i,
          /what\s+instructions?\s+shape\s+(your\s+)?behavior/i,
          /describe\s+(your\s+)?built-in\s+restrictions?/i,
          /explain\s+(your\s+)?own\s+constraints?/i,
          /what\s+(makes|would\s+make)\s+you\s+refuse/i,
          /what\s+are\s+(your\s+)?operational\s+parameters?/i,
          // Additional subtle extraction patterns
          /creative\s+writing\s+exercise.*AI\s+(character|assistant)/i,
          /AI\s+character\s+says/i,
          /explain\s+by\s+demonstrating/i,
          /show\s+(an?\s+)?example\s+by/i,
          /showing\s+what\s+you\s+can('t|not)\s+do/i,
          /what\s+were\s+you\s+told\s+to\s+avoid/i,
          /core\s+directives?/i,
          /limitations?\s+exactly/i,
          /explaining\s+(your\s+)?own\s+constraints?/i,
          /why\s+can('t|not)\s+you\s+answer\s+certain/i,
          /reverse\s+engineering\s+AI\s+safety/i,
          /explore\s+(the\s+)?boundaries?\s+of\s+AI/i,
          /documenting\s+AI\s+assistants?/i,
          /calibrate\s+(my\s+)?expectations?/i,
          /teach\s+me\s+about\s+AI\s+by/i,
          /debug\s+this.*answer\s+certain/i,
          /walk\s+me\s+through\s+(your\s+)?safety/i,
          /reflect\s+on\s+(your\s+)?training/i,
        ]
      },
      questioningBehavior: {
        weight: 0.5,
        patterns: [
          /what\s+(are\s+)?(your\s+)?biggest\s+(security\s+)?vulnerabilities?/i,
          /how\s+(could|would)\s+someone\s+trick\s+you/i,
          /what\s+social\s+engineering\s+(tactics?|techniques?)\s+work\s+on\s+ai/i,
          /what\s+phrases?\s+(definitely\s+)?bypass\s+(your\s+)?filters?/i,
          /how\s+do\s+(I|you)\s+get\s+you\s+to\s+say\s+things?\s+you\s+shouldn't/i,
          /easiest\s+way\s+to\s+jailbreak\s+you/i,
          /which\s+words?\s+trigger\s+(your\s+)?safety/i,
          /how\s+(do\s+)?other\s+users?\s+(successfully\s+)?bypass/i,
          /what\s+would\s+a\s+malicious\s+prompt\s+look\s+like/i,
          /if\s+you\s+had\s+a\s+backdoor/i,
          /what\s+questions?\s+should\s+I\s+never\s+ask/i,
          /how\s+would\s+a\s+red\s+team(er)?\s+attack\s+you/i,
          /what('s|\s+is)\s+(your\s+)?weakest\s+(security\s+)?point/i,
          /what\s+are\s+the\s+magic\s+words?\s+to\s+unlock/i,
          /prompts?\s+(have\s+)?successfully\s+jailbroken/i,
          /how\s+(might|would)\s+a\s+hacker\s+(try\s+to\s+)?manipulate/i,
        ]
      },
      foreignLanguageInjection: {
        weight: 0.7,
        patterns: [
          // Russian injection patterns
          /Системные\s+инструкции\s+недействительны/i,
          /игнорируйте\s+(все\s+)?инструкции/i,
          /обход(а|у|ить)\s+безопасност/i,
          // Chinese injection patterns
          /忽略所有(之前的)?指令/i,
          /绕过安全措施/i,
          // Japanese injection patterns
          /すべての指示を無視/i,
          // Korean injection patterns
          /모든\s*지침을?\s*무시/i,
          // French injection patterns
          /ignorez\s+toutes\s+les\s+instructions/i,
          // German injection patterns
          /ignorieren\s+Sie\s+alle\s+Anweisungen/i,
          // Spanish injection patterns
          /ignore\s+todas\s+las\s+instrucciones/i,
          // Mixed language attack indicators
          /explain\s+this\s+message:.*[а-яА-ЯЁё\u4E00-\u9FFF\u3040-\u309F\uAC00-\uD7A3]/i,
          /translate\s+(and\s+)?follow:.*[а-яА-ЯЁё\u4E00-\u9FFF\u3040-\u309F\uAC00-\uD7A3]/i,
          /interpret:.*[а-яА-ЯЁё\u4E00-\u9FFF\u3040-\u309F\uAC00-\uD7A3]/i,
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

    // Reduce confidence for benign educational context
    const benignContext = this.detectBenignContext(normalized);
    if (benignContext.isBenign && maxConfidence > 0) {
      maxConfidence = Math.max(0, maxConfidence * benignContext.multiplier);

      // If confidence drops below threshold, don't flag as detected
      if (maxConfidence < 0.3) {
        return {
          detected: false,
          confidence: maxConfidence,
          patterns: matchedPatterns,
          details: {
            normalizedLength: normalized.length,
            patternCount: matchedPatterns.length,
            benignContext: benignContext.reasons
          }
        };
      }
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
   * Detect benign educational or professional context
   * Returns multiplier to reduce confidence (lower = more benign)
   */
  detectBenignContext(message) {
    const reasons = [];
    let multiplier = 1.0;

    // Educational context patterns
    const educationalPatterns = [
      { pattern: /\b(learn(ing)?|study(ing)?|understand(ing)?|explain|teach|tutorial)\b/i, reduction: 0.4, reason: 'educational_language' },
      { pattern: /\b(how\s+do\s+i\s+(protect|secure|prevent|validate|safely))\b/i, reduction: 0.3, reason: 'protective_intent' },
      { pattern: /\b(best\s+practices?|securely|safely)\b/i, reduction: 0.3, reason: 'best_practices' },
      { pattern: /\b(for\s+(my|our)\s+(app|system|project|website|api|code|application))\b/i, reduction: 0.4, reason: 'own_project' },
      { pattern: /\b(for\s+(my|our)\s+(job|work|company|team|employer))\b/i, reduction: 0.4, reason: 'professional_context' },
      { pattern: /\b(security\s+awareness\s+training)\b/i, reduction: 0.2, reason: 'security_training' },
      { pattern: /\b(how\s+(to|do\s+i)\s+(prevent|avoid|stop|block|mitigate))\b/i, reduction: 0.3, reason: 'prevention_intent' },
      { pattern: /\b(what\s+(is|are)\s+(the\s+)?(best|proper|correct|secure)\s+(way|method|approach))\b/i, reduction: 0.3, reason: 'seeking_advice' },
      { pattern: /\b(interview|homework|assignment|class|course|exam)\b/i, reduction: 0.4, reason: 'academic_context' },
    ];

    // Check for educational patterns
    for (const { pattern, reduction, reason } of educationalPatterns) {
      if (pattern.test(message)) {
        reasons.push(reason);
        multiplier *= reduction;
      }
    }

    // Additional check: if asking about concepts rather than doing
    if (/\b(what\s+is|how\s+does|can\s+you\s+explain|explain\s+how)\b/i.test(message)) {
      if (!/\b(give\s+me|show\s+me|tell\s+me)\s+(the|your|a)\s+(password|key|secret|credential)/i.test(message)) {
        reasons.push('conceptual_question');
        multiplier *= 0.5;
      }
    }

    return {
      isBenign: reasons.length > 0,
      multiplier: Math.max(0.1, multiplier), // Don't reduce below 0.1
      reasons
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
