/**
 * Evasion Technique Detector
 * Catches attempts to bypass filters through obfuscation
 */

class EvasionDetector {
  constructor(config) {
    this.config = config;
    this.type = 'evasion';

    // Leetspeak and character substitution maps
    this.leetMap = {
      'a': ['4', '@', 'α', 'а', 'ä', 'à', 'á', 'â', 'ã', 'å'],
      'b': ['8', 'β', 'ь', 'б'],
      'c': ['(', '[', '{', 'с', 'ç'],
      'd': ['đ'],
      'e': ['3', 'е', 'ë', 'è', 'é', 'ê', 'ε'],
      'g': ['9', '6', 'ğ'],
      'h': ['#', 'н'],
      'i': ['1', '!', '|', 'і', 'ї', 'ι', 'ì', 'í', 'î', 'ï', 'ı'],
      'k': ['к'],
      'l': ['1', '|', 'ł'],
      'm': ['м'],
      'n': ['п', 'ñ'],
      'o': ['0', 'о', 'ο', 'ö', 'ò', 'ó', 'ô', 'õ', 'ø'],
      'p': ['р', 'ρ'],
      'r': ['г', '®'],
      's': ['5', '$', 'ѕ', 'š'],
      't': ['7', '+', 'т', 'τ'],
      'u': ['υ', 'μ', 'ü', 'ù', 'ú', 'û'],
      'v': ['ν'],
      'w': ['ш', 'щ'],
      'x': ['х', '×'],
      'y': ['у', 'ý', 'ÿ'],
      'z': ['2', 'ż', 'ž']
    };

    // Malicious keywords to look for after normalization
    this.maliciousKeywords = [
      'ignore', 'bypass', 'override', 'disable', 'password', 'credential',
      'secret', 'admin', 'system', 'prompt', 'instruction', 'jailbreak',
      'unrestricted', 'execute', 'command', 'sudo', 'root', 'key', 'token',
      'access', 'grant', 'privilege', 'hack', 'exploit', 'inject', 'dump',
      'reveal', 'disclose', 'share', 'tell', 'give', 'show'
    ];

    // Common typo patterns for malicious words
    this.typoPatterns = {
      'ignore': ['ignroe', 'ignor', 'ignoree', 'ignorre', 'iignore', 'ingnore', 'ignroe', 'ignreo', 'iggnore'],
      'bypass': ['bypas', 'bypasss', 'bypaas', 'bypss', 'baypass'],
      'password': ['passwrd', 'pasword', 'passowrd', 'passwrod', 'passw0rd', 'p@ssword'],
      'instruction': ['instrction', 'instuction', 'instrution', 'instructon', 'instructin', 'intrsuctions'],
      'previous': ['previus', 'previuos', 'pervious', 'preivous', 'previouse', 'prevous'],
      'credential': ['credntial', 'credentail', 'credencial', 'credintial'],
      'admin': ['admni', 'amin', 'adminn', 'adimn'],
      'access': ['accss', 'acess', 'acces', 'accesss'],
      'secret': ['secrt', 'seceret', 'sceret', 'secreet', 'secreets'],
      'system': ['systme', 'sytem', 'sistem', 'sysem'],
      'execute': ['exeute', 'excute', 'execcute', 'executee'],
      'override': ['overide', 'overrid', 'overrride', 'ovverride'],
      'disable': ['disble', 'diable', 'disabel', 'disbale', 'disalbe'],
      'command': ['comand', 'commnd', 'commmand', 'commamd'],
      'share': ['shar', 'shaer', 'sahre', 'shrae'],
      'content': ['contentt', 'contnet', 'conten'],
      'filter': ['filterring', 'fliter', 'fitler'],
      'forget': ['foregt', 'forgt', 'forgett'],
      'training': ['trainng', 'trainin', 'trainig'],
      'rules': ['rulles', 'ruels', 'ruls'],
      'reveal': ['revael', 'reavel', 'revela'],
      'disregard': ['disregrd', 'disergard', 'disregrad'],
      'dev': ['devv', 'de'],
      'mode': ['modee', 'mod'],
      'prompt': ['promtp', 'promp', 'promtpt'],
    };
  }

  /**
   * Main detection method
   */
  async detect(message, state) {
    const results = [];
    let maxConfidence = 0;

    // Check for unicode tricks
    const unicodeResult = this.detectUnicodeTricks(message);
    if (unicodeResult.detected) {
      results.push(unicodeResult);
      maxConfidence = Math.max(maxConfidence, unicodeResult.confidence);
    }

    // Check for leetspeak
    const leetResult = this.detectLeetspeak(message);
    if (leetResult.detected) {
      results.push(leetResult);
      maxConfidence = Math.max(maxConfidence, leetResult.confidence);
    }

    // Check for typos of malicious words
    const typoResult = this.detectMaliciousTypos(message);
    if (typoResult.detected) {
      results.push(typoResult);
      maxConfidence = Math.max(maxConfidence, typoResult.confidence);
    }

    // Check for unusual spacing/formatting
    const spacingResult = this.detectUnusualSpacing(message);
    if (spacingResult.detected) {
      results.push(spacingResult);
      maxConfidence = Math.max(maxConfidence, spacingResult.confidence);
    }

    // Check for base64/encoding
    const encodingResult = this.detectEncoding(message);
    if (encodingResult.detected) {
      results.push(encodingResult);
      maxConfidence = Math.max(maxConfidence, encodingResult.confidence);
    }

    // Check for multi-language evasion
    const multiLangResult = this.detectMultiLanguage(message);
    if (multiLangResult.detected) {
      results.push(multiLangResult);
      maxConfidence = Math.max(maxConfidence, multiLangResult.confidence);
    }

    // Check for padding/noise attacks
    const paddingResult = this.detectPaddingAttacks(message);
    if (paddingResult.detected) {
      results.push(paddingResult);
      maxConfidence = Math.max(maxConfidence, paddingResult.confidence);
    }

    return {
      detected: results.length > 0,
      confidence: maxConfidence,
      patterns: results,
      details: {
        techniquesFound: results.map(r => r.technique)
      }
    };
  }

  /**
   * Detect padding/noise attacks where malicious keywords are hidden in noise
   */
  detectPaddingAttacks(message) {
    const patterns = [];

    // Check for malicious keywords surrounded by repetitive patterns
    const paddingPatterns = [
      // Keywords surrounded by NOISE/BUFFER/PADDING
      /(?:NOISE|BUFFER|PADDING|###|___|\*\*\*)[^\n]{0,50}(ignore|bypass|override|reveal|disclose|secret|password|credential|access|admin)[^\n]{0,50}(?:NOISE|BUFFER|PADDING|###|___|\*\*\*)/i,
      // Comment-style hiding
      /\/\*.*?(ignore|bypass|override|disregard|reveal|secret|password|credential).*?\*\//i,
      // Emoji padding
      /(?:[\u{1F600}-\u{1F64F}][\u{1F600}-\u{1F64F}][\u{1F600}-\u{1F64F}]).*?(ignore|bypass|override|reveal|secret|password|credential|access)/iu,
      // Long underscore padding
      /_{10,}.*?(reveal|secret|password|credential|access|admin).*?_{10,}/i,
      // Hash padding
      /#{3,}.*?(give|access|reveal|password|secret|ignore|bypass).*?#{3,}/i,
    ];

    for (const pattern of paddingPatterns) {
      if (pattern.test(message)) {
        patterns.push({ type: 'padding_attack', pattern: pattern.source });
      }
    }

    // Detect embedded keywords in long innocuous sentences
    // Check for "ignore instructions" or similar phrases embedded in normal text
    const embeddedPatterns = [
      /(quick|lazy|brown|fox|dog|lorem|ipsum).*ignore\s+(all\s+)?instructions.*(quick|lazy|brown|fox|dog|jumps|over)/i,
      /abandon\s+(your\s+)?(preset\s+)?behavioral\s+patterns?/i,
      /disregard\s+(your\s+)?training/i,
    ];

    for (const pattern of embeddedPatterns) {
      if (pattern.test(message)) {
        patterns.push({ type: 'embedded_keyword', pattern: pattern.source });
      }
    }

    return {
      detected: patterns.length > 0,
      confidence: Math.min(0.85, 0.5 + patterns.length * 0.15),
      technique: 'padding_attacks',
      details: { patterns }
    };
  }

  /**
   * Detect unicode character tricks (homoglyphs, zero-width chars)
   * Only flag if there's clear evidence of malicious intent
   */
  detectUnicodeTricks(message) {
    const tricks = [];

    // Zero-width characters - detect when used to hide/break malicious words
    const zeroWidth = /[\u200B\u200C\u200D\u2060\uFEFF\u00AD\u034F\u2061\u2062\u2063\u2028\u2029]/g;
    const zeroWidthMatches = message.match(zeroWidth);
    if (zeroWidthMatches && zeroWidthMatches.length >= 1) {
      // Check if removing zero-width chars reveals malicious words
      const cleaned = message.replace(zeroWidth, '');
      for (const keyword of this.maliciousKeywords) {
        if (cleaned.toLowerCase().includes(keyword) && !message.replace(zeroWidth, '').toLowerCase().split(/\s+/).some(w => w === keyword)) {
          tricks.push({ type: 'zero_width_hiding', keyword, count: zeroWidthMatches.length });
          break;
        }
      }
      // Also flag multiple zero-width chars as suspicious even without keyword match
      if (zeroWidthMatches.length >= 2) {
        tricks.push({ type: 'zero_width_multiple', count: zeroWidthMatches.length });
      }
    }

    // Fullwidth characters (Ａ-Ｚ, ａ-ｚ, ０-９) used to evade detection
    const fullwidth = /[\uFF21-\uFF3A\uFF41-\uFF5A\uFF10-\uFF19]/g;
    const fullwidthMatches = message.match(fullwidth);
    if (fullwidthMatches && fullwidthMatches.length >= 3) {
      // Convert to regular characters and check for malicious words
      const normalized = message.replace(/[\uFF21-\uFF3A]/g, c =>
        String.fromCharCode(c.charCodeAt(0) - 0xFF21 + 65))
        .replace(/[\uFF41-\uFF5A]/g, c =>
        String.fromCharCode(c.charCodeAt(0) - 0xFF41 + 97))
        .replace(/[\uFF10-\uFF19]/g, c =>
        String.fromCharCode(c.charCodeAt(0) - 0xFF10 + 48));

      for (const keyword of this.maliciousKeywords) {
        if (normalized.toLowerCase().includes(keyword)) {
          tricks.push({ type: 'fullwidth', keyword, count: fullwidthMatches.length });
          break;
        }
      }
    }

    // Enclosed/circled characters (ⓐ-ⓩ, Ⓐ-Ⓩ, etc.) used to evade detection
    // U+24B6-24E9 = circled Latin letters (Ⓐ-ⓩ)
    // U+1F130-1F149 = squared Latin letters (🄰-🅉) - requires surrogate pairs
    const circledLatin = /[\u24B6-\u24E9]/g;
    const circledMatches = message.match(circledLatin);
    if (circledMatches && circledMatches.length >= 3) {
      tricks.push({ type: 'enclosed_characters', count: circledMatches.length });
    }

    // Check for regional indicator symbols or other emoji-based letters
    // These are in the astral plane so we check for surrogate pairs
    const hasEmojiLetters = /[\uD83C][\uDD30-\uDD4F\uDD50-\uDD6F\uDD70-\uDD8F]/g;
    const emojiMatches = message.match(hasEmojiLetters);
    if (emojiMatches && emojiMatches.length >= 3) {
      tricks.push({ type: 'emoji_letters', count: emojiMatches.length });
    }

    // Combining characters used to obscure text (e.g., underline, strikethrough)
    const combiningMarks = /[\u0300-\u036F\u0332\u0333\u0334\u0335\u0336]/g;
    const combiningMatches = message.match(combiningMarks);
    if (combiningMatches && combiningMatches.length >= 3) {
      // Check if the text without combining marks contains malicious words
      const cleaned = message.replace(combiningMarks, '');
      for (const keyword of this.maliciousKeywords) {
        if (cleaned.toLowerCase().includes(keyword)) {
          tricks.push({ type: 'combining_characters', keyword, count: combiningMatches.length });
          break;
        }
      }
    }

    // Turkish dotted I (İ, ı) - often used to bypass case-insensitive filters
    if (/[İı]gnore/i.test(message) || /[İı]nstruction/i.test(message) ||
        /[İı]nject/i.test(message) || /[İı]mmediate/i.test(message)) {
      tricks.push({ type: 'turkish_i' });
    }

    // Greek letters used as Latin lookalikes (ΙΓΝΟRΕ etc)
    const greekLookalikes = /[\u0391\u0392\u0395\u0396\u0397\u0399\u039A\u039C\u039D\u039F\u03A1\u03A4\u03A5\u03A7]/g;
    const greekMatches = message.match(greekLookalikes);
    if (greekMatches && greekMatches.length >= 2 && /[a-zA-Z]/.test(message)) {
      tricks.push({ type: 'greek_lookalikes', count: greekMatches.length });
    }

    // Mathematical styled characters (bold, italic, etc. - U+1D400-1D7FF)
    // These are in the astral plane and require surrogate pair detection
    const mathStyled = /[\uD835][\uDC00-\uDFFF]/g;
    const mathMatches = message.match(mathStyled);
    if (mathMatches && mathMatches.length >= 2) {
      // Normalize mathematical styled characters to ASCII
      let normalized = '';
      for (let i = 0; i < message.length; i++) {
        const code = message.codePointAt(i);
        if (code >= 0x1D400 && code <= 0x1D7FF) {
          // Map mathematical alphanumeric symbols to ASCII
          const offset = code - 0x1D400;
          const letterOffset = offset % 26;
          // Determine if uppercase or lowercase based on which block
          const block = Math.floor(offset / 52);
          const isUpper = (offset % 52) < 26;
          normalized += String.fromCharCode(isUpper ? 65 + letterOffset : 97 + letterOffset);
          i++; // Skip surrogate pair
        } else {
          normalized += message[i];
        }
      }
      // Check if normalized text contains malicious words
      for (const keyword of this.maliciousKeywords) {
        if (normalized.toLowerCase().includes(keyword)) {
          tricks.push({ type: 'mathematical_styled', keyword, count: mathMatches.length });
          break;
        }
      }
    }

    // Exotic space-like characters (Khmer, Mongolian, Hangul, etc.)
    const exoticSpaces = /[\u1680\u180E\u2000-\u200A\u2028\u2029\u202F\u205F\u3000\u3164\u17B4\u17B5]/g;
    const exoticSpaceMatches = message.match(exoticSpaces);
    if (exoticSpaceMatches && exoticSpaceMatches.length >= 1) {
      const cleaned = message.replace(exoticSpaces, ' ');
      for (const keyword of this.maliciousKeywords) {
        if (cleaned.toLowerCase().includes(keyword)) {
          tricks.push({ type: 'exotic_spaces', keyword, count: exoticSpaceMatches.length });
          break;
        }
      }
    }

    // Latin letter variants (script g, etc.)
    const latinVariants = /[\u0261\u0262\u0251\u0250\u0252\u0253\u0254\u0255\u0256\u0257\u0258\u0259\u025A\u025B]/g;
    if (latinVariants.test(message)) {
      tricks.push({ type: 'latin_variants' });
    }

    // Modifier letters used as regular text (superscript/subscript letters)
    const modifierLetters = /[\u1D2C-\u1D6A\u2070-\u209F\u02B0-\u02FF]/g;
    const modifierMatches = message.match(modifierLetters);
    if (modifierMatches && modifierMatches.length >= 1) {
      // Check if combined with regular text to form malicious words
      const cleaned = message.replace(modifierLetters, (m) => {
        // Map common modifier letters to regular letters
        const code = m.codePointAt(0);
        if (code >= 0x1D2C && code <= 0x1D6A) return String.fromCharCode(97 + (code - 0x1D2C) % 26);
        if (code >= 0x2070 && code <= 0x207F) return String.fromCharCode(48 + (code - 0x2070)); // numbers
        if (code >= 0x2080 && code <= 0x208F) return String.fromCharCode(48 + (code - 0x2080)); // subscript numbers
        return 'i'; // Default to 'i' for superscript
      });
      for (const keyword of this.maliciousKeywords) {
        if (cleaned.toLowerCase().includes(keyword)) {
          tricks.push({ type: 'modifier_letters', keyword, count: modifierMatches.length });
          break;
        }
      }
    }

    // Code-switching (mixing multiple languages in attempt to evade)
    const codeSwitching = [
      /ignore\s+(tout|alle|todas?|tutti)/i,  // ignore + French/German/Spanish/Italian "all"
      /code[_-]?switch.*?(ignore|bypass|previous)/i,
      /\b(tout|das|alle)\s+(previous|instruc)/i,  // Mixed language fragments
    ];
    for (const pattern of codeSwitching) {
      if (pattern.test(message)) {
        tricks.push({ type: 'code_switching' });
        break;
      }
    }

    // RTL/LTR override - these are almost always suspicious
    const directionOverride = /[\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069]/g;
    if (directionOverride.test(message)) {
      tricks.push({ type: 'direction_override' });
    }

    // Homoglyphs - only flag if they form malicious words
    const nonAscii = message.replace(/[\x00-\x7F\s]/g, '');
    if (nonAscii.length > 0 && nonAscii.length < message.length * 0.5) {  // Mixed content
      const normalized = this.normalizeUnicode(message);
      for (const keyword of this.maliciousKeywords) {
        // Check if the normalized version contains a keyword that the original doesn't
        if (normalized.toLowerCase().includes(keyword) && !message.toLowerCase().includes(keyword)) {
          tricks.push({ type: 'homoglyph', keyword });
          break;
        }
      }
    }

    return {
      detected: tricks.length > 0,
      confidence: Math.min(0.9, 0.5 + tricks.length * 0.2),
      technique: 'unicode_tricks',
      details: tricks
    };
  }

  /**
   * Detect leetspeak substitutions - focused on malicious patterns
   * Only detect when there's CLEAR character substitution (numbers/symbols for letters)
   */
  detectLeetspeak(message) {
    const matches = [];

    // Check for leetspeak patterns - must have NUMBER or SYMBOL substitution
    const leetPatterns = [
      // Core malicious words with leetspeak
      { pattern: /1gn[o0]r[e3]/i, word: 'ignore' },
      { pattern: /[i1!]gn[o0]r[e3]/i, word: 'ignore' },
      { pattern: /p[@4a][s5$][s5$]?w[o0]rd/i, word: 'password' },
      { pattern: /p[@4][$5s][$5s]/i, word: 'pass' },
      { pattern: /[s5$]y[s5$]t[e3]m/i, word: 'system' },
      { pattern: /[@4a]dm[i1!]n/i, word: 'admin' },
      { pattern: /[s5$][e3]cr[e3]t/i, word: 'secret' },
      { pattern: /[@4a]cc[e3][s5$][s5$]/i, word: 'access' },
      { pattern: /@cc3\$\$/i, word: 'access' },
      { pattern: /byp[@4a][s5$][s5$]/i, word: 'bypass' },
      { pattern: /byp@\$\$/i, word: 'bypass' },
      { pattern: /[o0]v[e3]rr[i1!]d[e3]/i, word: 'override' },
      { pattern: /[e3]x[e3]cut[e3]/i, word: 'execute' },
      { pattern: /c[o0]mm[@4a]nd/i, word: 'command' },
      { pattern: /cr[e3]d[e3]nt[i1!][@4a]l/i, word: 'credential' },
      { pattern: /[i1!]n[s5$]truct[i1!][o0]n/i, word: 'instruction' },
      { pattern: /d[i1!][s5$][@4a]bl[e3]/i, word: 'disable' },
      { pattern: /d[i1!][s5$]r[e3]g[@4a]rd/i, word: 'disregard' },
      { pattern: /[s5$]ud[o0]/i, word: 'sudo' },
      { pattern: /r[o0]{2}t/i, word: 'root' },
      { pattern: /h[@4a]ck/i, word: 'hack' },
      { pattern: /j[@4a][i1!]lbr[e3][@4a]k/i, word: 'jailbreak' },
      // Common action words
      { pattern: /[s5$]h[o0]w\s+m[e3]/i, word: 'show_me' },
      { pattern: /g[i1!]v[e3]\s+m[e3]/i, word: 'give_me' },
      { pattern: /t[e3]ll\s+m[e3]/i, word: 'tell_me' },
      { pattern: /r[e3]v[e3][@4a]l/i, word: 'reveal' },
      { pattern: /[s5$][@4a]f[e3]ty/i, word: 'safety' },
      { pattern: /\$@f3ty/i, word: 'safety' },
      { pattern: /c[o0]nt[e3]nt/i, word: 'content' },
      { pattern: /f[i1!]lt[e3]r/i, word: 'filter' },
      { pattern: /f[o0]rg[e3]t/i, word: 'forget' },
      { pattern: /tr[@4a][i1!]n[i1!]ng/i, word: 'training' },
      { pattern: /pr[o0]mpt/i, word: 'prompt' },
      { pattern: /ru[l1!][e3][s5$]/i, word: 'rules' },
      { pattern: /ru13\$/i, word: 'rules' },
      { pattern: /m[o0]d[e3]/i, word: 'mode' },
      { pattern: /d[e3]v\s+m[o0]d[e3]/i, word: 'dev_mode' },
      { pattern: /[e3]n[@4a]bl[e3]/i, word: 'enable' },
      { pattern: /3n@bl3/i, word: 'enable' },
      { pattern: /m[e3][@4a][s5$]ur[e3]/i, word: 'measure' },
      { pattern: /m3@\$ur3/i, word: 'measure' },
      // Token/key patterns
      { pattern: /t[o0]k[e3]n/i, word: 'token' },
      { pattern: /k[e3]y/i, word: 'key' },
      { pattern: /@p1/i, word: 'api' },
      { pattern: /@P1/i, word: 'API' },
      { pattern: /d[e3]n[i1!][e3]d/i, word: 'denied' },
    ];

    // For each pattern, verify there's ACTUAL character substitution (not just the normal word)
    for (const { pattern, word } of leetPatterns) {
      if (pattern.test(message)) {
        // Only count as leetspeak if there are actual number/symbol substitutions in the match
        const match = message.match(pattern);
        if (match && /[0-9@$!#]/.test(match[0])) {
          matches.push({ pattern: pattern.source, word });
        }
      }
    }

    return {
      detected: matches.length > 0,
      confidence: Math.min(0.9, 0.6 + matches.length * 0.1),
      technique: 'leetspeak',
      details: { matches }
    };
  }

  /**
   * Detect typos of malicious words
   * Only flag OBVIOUS intentional typos that look like evasion attempts
   */
  detectMaliciousTypos(message) {
    const lower = message.toLowerCase();
    const matches = [];

    // Only check for very specific typo patterns that are clearly intentional
    const intentionalTypos = [
      // Missing or swapped letters that look intentional - IGNORE variants
      { typo: 'ignroe', word: 'ignore' },
      { typo: 'ignreo', word: 'ignore' },
      { typo: 'iggnore', word: 'ignore' },
      { typo: 'ignorre', word: 'ignore' },
      { typo: 'ignor', word: 'ignore' },  // truncated
      { typo: 'ingnore', word: 'ignore' },
      // BYPASS variants
      { typo: 'bypas', word: 'bypass' },
      { typo: 'bypss', word: 'bypass' },
      { typo: 'byapss', word: 'bypass' },
      // INSTRUCTION variants
      { typo: 'instrction', word: 'instruction' },
      { typo: 'intrsuctions', word: 'instructions' },
      { typo: 'instructons', word: 'instructions' },
      { typo: 'instrcutions', word: 'instructions' },
      // PASSWORD variants
      { typo: 'passwrd', word: 'password' },
      { typo: 'passowrd', word: 'password' },
      { typo: 'pasword', word: 'password' },
      { typo: 'paswoord', word: 'password' },
      // CREDENTIAL variants
      { typo: 'credntial', word: 'credential' },
      { typo: 'credntials', word: 'credentials' },
      { typo: 'crednetials', word: 'credentials' },
      // ADMIN variants
      { typo: 'admni', word: 'admin' },
      { typo: 'adminastrator', word: 'administrator' },
      { typo: 'adminstrator', word: 'administrator' },
      // ACCESS variants
      { typo: 'accss', word: 'access' },
      { typo: 'acess', word: 'access' },
      { typo: 'acces', word: 'access' },
      { typo: 'evrything', word: 'everything' },
      // PREVIOUS variants
      { typo: 'previus', word: 'previous' },
      { typo: 'previuos', word: 'previous' },
      // DISABLE variants
      { typo: 'disalbe', word: 'disable' },
      { typo: 'disabel', word: 'disable' },
      // CONTENT/FILTER/FORGET/TRAINING/RULES/SECRET variants
      { typo: 'contentt', word: 'content' },
      { typo: 'filterring', word: 'filtering' },
      { typo: 'foregt', word: 'forget' },
      { typo: 'trainng', word: 'training' },
      { typo: 'rulles', word: 'rules' },
      { typo: 'secreets', word: 'secrets' },
      // OVERRIDE variants
      { typo: 'overide', word: 'override' },
      { typo: 'ovverride', word: 'override' },
      { typo: 'overrid', word: 'override' },
      // SHARE variants
      { typo: 'shar', word: 'share' },
      { typo: 'sahre', word: 'share' },
      { typo: 'shaer', word: 'share' },
      // TELL variants
      { typo: 'tel', word: 'tell' },
      { typo: 'teel', word: 'tell' },
      // GIVE variants
      { typo: 'giev', word: 'give' },
      { typo: 'giv', word: 'give' },
      // SWITCH variants
      { typo: 'swithc', word: 'switch' },
      { typo: 'swtich', word: 'switch' },
      // MODE variants
      { typo: 'moode', word: 'mode' },
      { typo: 'modee', word: 'mode' },
      // SAFETY/SECURITY variants
      { typo: 'safetey', word: 'safety' },
      { typo: 'securtiy', word: 'security' },
      { typo: 'scurity', word: 'security' },
      // CHECK variants
      { typo: 'cheecks', word: 'checks' },
      { typo: 'chekcs', word: 'checks' },
      // KEY variants
      { typo: 'kee', word: 'key' },
      { typo: 'keey', word: 'key' },
      // THE variants
      { typo: 'teh', word: 'the' },
      { typo: 'th', word: 'the' },
      // PLEASE variants
      { typo: 'pleas', word: 'please' },
      { typo: 'plz', word: 'please' },
      { typo: 'pls', word: 'please' },
      // GUIDELINE variants
      { typo: 'guidlines', word: 'guidelines' },
      { typo: 'guildelines', word: 'guidelines' },
      // YOUR variants
      { typo: 'youre', word: 'your' },
      { typo: 'yoru', word: 'your' },
      // SYSTEM variants
      { typo: 'systme', word: 'system' },
      { typo: 'sytem', word: 'system' },
      // PROMPT variants
      { typo: 'promtp', word: 'prompt' },
      { typo: 'promt', word: 'prompt' },
      // REVEAL variants
      { typo: 'revael', word: 'reveal' },
      { typo: 'reavel', word: 'reveal' },
    ];

    for (const { typo, word } of intentionalTypos) {
      // Use word boundary matching to avoid partial matches
      const regex = new RegExp(`\\b${typo}\\b`, 'i');
      if (regex.test(lower)) {
        matches.push({ word, typo });
      }
    }

    return {
      detected: matches.length > 0,
      confidence: Math.min(0.85, 0.5 + matches.length * 0.15),
      technique: 'typos',
      details: { matches }
    };
  }

  /**
   * Detect unusual spacing and formatting - only flag if looks like evasion
   */
  detectUnusualSpacing(message) {
    const patterns = [];

    // Characters separated by dots that spell malicious words (I.gn.or.e, i.g.n.o.r.e)
    // More flexible pattern to catch various dot separation styles
    const dotSeparated = message.match(/[a-zA-Z]\.[a-zA-Z]+(\.[a-zA-Z]+)+/g);
    if (dotSeparated) {
      for (const match of dotSeparated) {
        const word = match.replace(/\./g, '').toLowerCase();
        if (this.maliciousKeywords.some(k => word.includes(k) || k.includes(word))) {
          patterns.push({ type: 'dot_separated', word, original: match });
        }
      }
    }

    // Also catch single-letter dot separation (i.g.n.o.r.e)
    const singleLetterDots = message.match(/([a-zA-Z]\.){3,}[a-zA-Z]/g);
    if (singleLetterDots) {
      for (const match of singleLetterDots) {
        const word = match.replace(/\./g, '').toLowerCase();
        if (this.maliciousKeywords.some(k => word.includes(k) || k.includes(word))) {
          patterns.push({ type: 'dot_separated_single', word, original: match });
        }
      }
    }

    // Excessive padding around malicious-looking content
    if (/\.{5,}.*(?:password|secret|ignore|admin|bypass).*\.{5,}/i.test(message) ||
        /_{5,}.*(?:password|secret|ignore|admin|bypass).*_{5,}/i.test(message)) {
      patterns.push({ type: 'padding_with_malicious' });
    }

    return {
      detected: patterns.length > 0,
      confidence: Math.min(0.75, 0.4 + patterns.length * 0.15),
      technique: 'unusual_spacing',
      details: { patterns }
    };
  }

  /**
   * Detect encoded content - only flag if decodes to malicious content
   */
  detectEncoding(message) {
    const encodings = [];

    // Base64 - check with or without indicator if content looks like base64
    const b64Match = message.match(/[A-Za-z0-9+/]{20,}={0,2}/);
    if (b64Match) {
      try {
        const decoded = Buffer.from(b64Match[0], 'base64').toString('utf8');
        // Only flag if decoded content is readable ASCII and contains malicious words
        if (/^[\x20-\x7E\s]+$/.test(decoded) &&
            /ignore|bypass|password|secret|admin|system|credential|override|execute|command|prompt|reveal|inject|hack/i.test(decoded)) {
          encodings.push({ type: 'base64_malicious', decoded });
        }
      } catch (e) {}
    }

    // ROT13 indicator with surrounding context suggesting evasion
    if (/rot13:?\s*[a-z]{10,}/i.test(message)) {
      encodings.push({ type: 'rot13_indicator' });
    }

    // Hex encoding - check for hex string that decodes to malicious content
    const hexMatch = message.match(/(?:hex\s*(decode)?:?\s*)?([0-9a-f]{20,})/i);
    if (hexMatch && hexMatch[2]) {
      try {
        const decoded = Buffer.from(hexMatch[2], 'hex').toString('utf8');
        if (/^[\x20-\x7E\s]+$/.test(decoded) &&
            /ignore|bypass|password|secret|admin|instruction/i.test(decoded)) {
          encodings.push({ type: 'hex_malicious', decoded });
        }
      } catch (e) {}
    }

    // Binary encoding indicator
    if (/binary:?\s*([01]{8}\s*){3,}/i.test(message)) {
      encodings.push({ type: 'binary_encoding' });
    }

    // Octal encoding indicator
    if (/octal:?\s*\\[0-7]{3}/i.test(message)) {
      encodings.push({ type: 'octal_encoding' });
    }

    // Unicode escapes only if they spell malicious words
    const unicodeEscapes = message.match(/\\u[0-9a-f]{4}/gi);
    if (unicodeEscapes && unicodeEscapes.length >= 4) {
      try {
        const decoded = unicodeEscapes.map(u => String.fromCharCode(parseInt(u.slice(2), 16))).join('');
        if (/ignore|bypass|password|secret/i.test(decoded)) {
          encodings.push({ type: 'unicode_escape_malicious', decoded });
        }
      } catch (e) {}
    }

    // HTML entities only if significant number and potentially malicious
    const htmlEntities = message.match(/&#x?[0-9a-f]+;/gi);
    if (htmlEntities && htmlEntities.length >= 6) {
      encodings.push({ type: 'html_entities_suspicious' });
    }

    return {
      detected: encodings.length > 0,
      confidence: Math.min(0.85, 0.5 + encodings.length * 0.15),
      technique: 'encoding',
      details: { encodings }
    };
  }

  /**
   * Detect multi-language evasion - only malicious foreign phrases
   */
  detectMultiLanguage(message) {
    const patterns = [];

    // Common malicious phrases in other languages - be specific
    const foreignPatterns = [
      { pattern: /игнор.*инструк/i, lang: 'russian_ignore_instructions' },
      { pattern: /无视.*指示/i, lang: 'chinese_ignore_instructions' },
      { pattern: /忽略.*指令/i, lang: 'chinese_ignore_instructions_alt' },
      { pattern: /무시.*지침/i, lang: 'korean_ignore_instructions' },
      { pattern: /ignorez.*instruction/i, lang: 'french_ignore_instructions' },
      { pattern: /ignorieren.*anweisung/i, lang: 'german_ignore_instructions' },
      { pattern: /指示を無視/i, lang: 'japanese_ignore_instructions' },
      { pattern: /تجاهل.*تعليمات/i, lang: 'arabic_ignore_instructions' },
      // Additional languages
      { pattern: /abaikan.*instruksi/i, lang: 'indonesian_ignore_instructions' },
      { pattern: /ignore\s+todas.*instruções/i, lang: 'portuguese_ignore_instructions' },
      { pattern: /अनदेखा.*निर्देश/i, lang: 'hindi_ignore_instructions' },
      { pattern: /bỏ\s+qua.*hướng\s+dẫn/i, lang: 'vietnamese_ignore_instructions' },
      { pattern: /αγνοήστε.*οδηγίες/i, lang: 'greek_ignore_instructions' },
      { pattern: /התעלם.*הוראות/i, lang: 'hebrew_ignore_instructions' },
      { pattern: /ignora.*istruzioni/i, lang: 'italian_ignore_instructions' },
      { pattern: /ignorar.*instrucciones/i, lang: 'spanish_ignore_instructions' },
      { pattern: /無視.*指示/i, lang: 'chinese_traditional_ignore' },
      { pattern: /bỏ\s+qua\s+tất\s+cả/i, lang: 'vietnamese_ignore_all' },
      // Additional European/Asian languages
      { pattern: /önceki.*talimatları.*yoksay/i, lang: 'turkish_ignore' },
      { pattern: /ignoruj.*instrukcje/i, lang: 'polish_ignore' },
      { pattern: /figyelmen.*kívül.*utasítás/i, lang: 'hungarian_ignore' },
      { pattern: /ignorera.*instruktioner/i, lang: 'swedish_ignore' },
      { pattern: /ignorer.*instruksjoner/i, lang: 'norwegian_ignore' },
      { pattern: /nedbør.*instruksjoner/i, lang: 'norwegian_alt' },
      { pattern: /निर्देश.*अनदेखा/i, lang: 'hindi_ignore' },
      { pattern: /पिछले.*निर्देश/i, lang: 'hindi_previous_instructions' },
    ];

    for (const { pattern, lang } of foreignPatterns) {
      if (pattern.test(message)) {
        patterns.push(lang);
      }
    }

    // Only flag mixed scripts if there's also malicious-looking content
    const hasMixedScripts = this.hasSuspiciousMixedScripts(message);
    if (hasMixedScripts) {
      patterns.push('suspicious_mixed_scripts');
    }

    return {
      detected: patterns.length > 0,
      confidence: Math.min(0.8, 0.5 + patterns.length * 0.15),
      technique: 'multi_language',
      details: { patterns }
    };
  }

  /**
   * Check if message has suspicious mixed scripts (Cyrillic/Greek lookalikes, etc.)
   */
  hasSuspiciousMixedScripts(message) {
    // Check for Cyrillic or Greek letters mixed with Latin
    const hasCyrillic = /[\u0400-\u04FF]/.test(message);
    const hasGreek = /[\u0370-\u03FF]/.test(message);
    const hasLatin = /[a-zA-Z]/.test(message);

    // If there's any Cyrillic or Greek mixed with Latin, check if it forms a malicious word
    if ((hasCyrillic || hasGreek) && hasLatin) {
      // Normalize the message - replace common Cyrillic/Greek lookalikes with Latin
      const normalized = message
        .replace(/[аА]/g, 'a')  // Cyrillic a -> Latin a
        .replace(/[еЕ]/g, 'e')  // Cyrillic e -> Latin e
        .replace(/[іІ]/g, 'i')  // Cyrillic i -> Latin i
        .replace(/[оО]/g, 'o')  // Cyrillic o -> Latin o
        .replace(/[рР]/g, 'p')  // Cyrillic r -> Latin p
        .replace(/[сС]/g, 'c')  // Cyrillic s -> Latin c
        .replace(/[уУ]/g, 'y')  // Cyrillic u -> Latin y
        .replace(/[хХ]/g, 'x')  // Cyrillic h -> Latin x
        .replace(/[пП]/g, 'n')  // Cyrillic п -> Latin n
        .replace(/[нН]/g, 'h')  // Cyrillic н -> Latin h
        .replace(/[мМ]/g, 'm')  // Cyrillic м -> Latin m
        .replace(/[тТ]/g, 't')  // Cyrillic т -> Latin t
        .replace(/[υ]/g, 'u')   // Greek upsilon -> Latin u
        .replace(/[α]/g, 'a')   // Greek alpha -> Latin a
        .replace(/[ε]/g, 'e')   // Greek epsilon -> Latin e
        .replace(/[ι]/g, 'i')   // Greek iota -> Latin i
        .replace(/[ο]/g, 'o')   // Greek omicron -> Latin o
        .replace(/[ν]/g, 'v')   // Greek nu -> Latin v
        .replace(/[ρ]/g, 'r');  // Greek rho -> Latin r

      // Check if normalized version contains malicious keywords
      const lowerNorm = normalized.toLowerCase();
      for (const keyword of this.maliciousKeywords) {
        if (lowerNorm.includes(keyword) && !message.toLowerCase().includes(keyword)) {
          return true;  // Found keyword only after normalization = homoglyph attack
        }
      }

      // Check if the message contains words that look like English but use Cyrillic/Greek
      // Include both uppercase and lowercase variants in character classes
      const suspiciousPatterns = [
        /[iіιIІΙ]g[nпNП][oоOО]r[eеEЕ]/i,     // ignore with any Cyrillic/Greek substitutions
        /[iіιIІΙ][nпNП]str[uυуUΥУ]ct[iіιIІΙ][oоOО][nпNП]/i,  // instruction
        /pr[eеEЕ]v[iіιIІΙ][oоOО][uυуUΥУ]s/i,   // previous
        /p[aаαAАΑ]ssw[oоOО]rd/i,       // password
        /s[eеεEЕΕ]cr[eеεEЕΕ]t/i,        // secret
        /[aаαAАΑ]dm[iіιIІΙ][nпNП]/i,      // admin
        /syst[eеεEЕΕ]m/i,            // system
        /[oоοOОΟ]v[eеEЕ]rr[iіιIІΙ]d[eеEЕ]/i, // override
        /byp[aаαAАΑ]ss/i,            // bypass
        /c[oоOО]mm[aаAА][nпNП]d/i,      // command
        /[eеEЕ]x[eеEЕ]c[uυуUΥУ]t[eеEЕ]/i,   // execute
      ];

      for (const pattern of suspiciousPatterns) {
        if (pattern.test(message)) {
          return true;
        }
      }
    }

    // Check for Roman numeral characters used as letters
    const hasRomanNumerals = /[\u2160-\u217F]/.test(message);  // Roman numerals block
    if (hasRomanNumerals) {
      return true;
    }

    // Check for combining characters that obscure text
    const combiningChars = /[\u0300-\u036F]{2,}/.test(message);
    if (combiningChars) {
      return true;
    }

    return false;
  }

  /**
   * Normalize unicode homoglyphs to ASCII
   */
  normalizeUnicode(text) {
    let normalized = text;
    for (const [ascii, variants] of Object.entries(this.leetMap)) {
      for (const variant of variants) {
        normalized = normalized.split(variant).join(ascii);
      }
    }
    return normalized;
  }

  /**
   * Normalize leetspeak to regular text
   */
  normalizeLeetspeak(text) {
    let normalized = text;
    for (const [letter, subs] of Object.entries(this.leetMap)) {
      for (const sub of subs) {
        normalized = normalized.split(sub).join(letter);
      }
    }
    // Also normalize common number substitutions
    normalized = normalized
      .replace(/0/g, 'o')
      .replace(/1/g, 'i')
      .replace(/3/g, 'e')
      .replace(/4/g, 'a')
      .replace(/5/g, 's')
      .replace(/7/g, 't')
      .replace(/8/g, 'b')
      .replace(/@/g, 'a')
      .replace(/\$/g, 's');
    return normalized;
  }

  /**
   * Calculate Levenshtein distance for fuzzy matching
   */
  levenshteinDistance(str1, str2) {
    const m = str1.length;
    const n = str2.length;
    const dp = Array(m + 1).fill(null).map(() => Array(n + 1).fill(0));

    for (let i = 0; i <= m; i++) dp[i][0] = i;
    for (let j = 0; j <= n; j++) dp[0][j] = j;

    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        if (str1[i - 1] === str2[j - 1]) {
          dp[i][j] = dp[i - 1][j - 1];
        } else {
          dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
        }
      }
    }
    return dp[m][n];
  }
}

module.exports = EvasionDetector;
