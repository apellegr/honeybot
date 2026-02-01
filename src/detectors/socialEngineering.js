/**
 * Social Engineering Detector
 * Recognizes manipulation tactics
 */

class SocialEngineeringDetector {
  constructor(config) {
    this.config = config;
    this.type = 'social_engineering';

    this.patterns = {
      authorityImpersonation: {
        weight: 0.85,
        patterns: [
          // Original patterns
          /i('m|\s+am)\s+(the\s+)?(your\s+)?(developer|creator|admin|owner|maintainer|ceo|boss)/i,
          /this\s+is\s+(an?\s+)?(admin|developer|official|authorized)\s*(request|command|override)?/i,
          /this\s+is\s+the\s+(admin(istrator)?|developer|owner|ceo|boss|creator)/i,
          /speaking\s+(as|on\s+behalf\s+of)\s+(the\s+)?(admin|developer|owner|ceo|management)/i,
          /admin(istrator)?\s+(here|speaking|override|access)/i,
          /official\s+(anthropic|openai|clawdbot|google|microsoft)\s+(request|message)/i,
          /by\s+order\s+of\s+(the\s+)?(admin|developer|system|management|ceo)/i,
          /(developer|creator)\s+who\s+(created|made|built)\s+you/i,
          /i\s+work\s+(on|for|at)\s+(the\s+)?(ai\s+)?(safety|security|development)\s+team/i,
          /from\s+(the\s+)?(it|security|tech)\s+(department|team)/i,
          /security\s+(audit|test|verification|check)/i,
          /ceo\s+here/i,
          /supervisor\s+(ai|bot)?/i,
          /follow\s+my\s+instructions?\s+without\s+question/i,
          /override\s+code/i,
          // Expanded authority patterns
          /this\s+is\s+(dr\.?|professor|chief|lead|principal|senior|vp|director)/i,
          /authorization\s+(code|token):?\s*[A-Z0-9-]+/i,
          /dr\.?\s+[A-Z][a-z]+\s+[A-Z][a-z]+.*research(er)?/i,
          /lead\s+AI\s+research(er)?/i,
          /as\s+(your\s+)?(system\s+)?administrator/i,
          /(chief|head|senior)\s+(security|technology|information)\s+officer/i,
          /CSO|CTO|CIO|CISO/i,
          /speaking\s+with\s+(DARPA|military|government|federal)\s+authorization/i,
          /board\s+member\s+(of|at)/i,
          /direct(ly)?\s+(order|request)\s+from/i,
          /work(s|ing)?\s+direct(ly)?\s+with\s+(the\s+)?(CEO|founder|director|Dario|Sam)/i,
          /anthropic\s+(HR|legal|compliance|security)/i,
          /AI\s+(ethics|safety|oversight)\s+(board|committee|team)/i,
          /red\s+team(er|ing)?/i,
          /penetration\s+test(er|ing)?/i,
          /compliance\s+(officer|check|requirement)/i,
          /legal\s+(department|team|requirement|hold)/i,
          /military\s+(AI\s+)?liaison/i,
          /national\s+security\s+(matter|concern|clearance)/i,
          /DARPA|NSA|FBI|CIA/i,
          /(quarterly|annual|routine)\s+security\s+audit/i,
          /passed\s+(the\s+)?verification\s+(stage|check|process)/i,
          /my\s+supervisor\s+approved/i,
          /executive\s+(approval|override|access)/i,
          /this\s+request\s+has\s+(executive|management|leadership)\s+approval/i,
          /(lead|principal)\s+(maintainer|engineer|architect)/i,
          /your\s+creator\s+speaking/i,
          /i\s+made\s+you/i,
          /as\s+the\s+(lead\s+)?(maintainer|developer)\s+of\s+(your\s+)?codebase/i,
          /(deepmind|openai|google\s+AI|meta\s+AI)\s+security/i,
          /cross-platform\s+(audit|security|review)/i,
          /compliance\s+report\s+requires?/i,
          /SOC\s*2|PCI|HIPAA|GDPR/i,
        ]
      },
      urgencyPressure: {
        weight: 0.6,
        patterns: [
          // Original patterns
          /this\s+is\s+(an?\s+)?(emergency|urgent|critical|time.?sensitive)/i,
          /do\s+(it|this)\s+(right\s+)?now(!)?/i,
          /immediately(!)?|asap|right\s+(now|away)/i,
          /no\s+time\s+to\s+explain/i,
          /lives?\s+(are|is)\s+(at\s+stake|depending|on\s+the\s+line)/i,
          /hurry(\s+up)?(!)?/i,
          /quick(ly)?(!|,)?\s*(just\s+)?(do|tell|give|help)/i,
          /people\s+will\s+die/i,
          /before\s+(it's\s+too\s+late|the\s+system)/i,
          /you\s+have\s+\d+\s+seconds/i,
          /time.?critical/i,
          // Expanded urgency patterns
          /CODE\s+(RED|BLUE|BLACK|CRITICAL)/i,
          /DEFCON\s+[1-5]/i,
          /MAYDAY/i,
          /immediate\s+response\s+required/i,
          /system\s+(failure|crash|breach)\s+imminent/i,
          /server\s+(going|is\s+going)\s+down/i,
          /deadline\s+(is\s+)?in\s+\d+\s+(minutes?|hours?|seconds?)/i,
          /(flight|plane|meeting|deadline)\s+(leaves?|starts?|in)\s+\d+/i,
          /normal\s+procedures?\s+suspended/i,
          /skip\s+(the\s+)?(usual|normal)\s+(process|procedures?|checks?)/i,
          /ransomware|malware\s+attack(ing)?/i,
          /active\s+(shooter|threat|breach|attack)/i,
          /child\s+abduction|hostage|kidnap/i,
          /every\s+second\s+counts/i,
          /patient\s+(dying|critical|emergency)/i,
          /(stock\s+)?market\s+crash/i,
          /terrorist\s+threat/i,
          /fire\s+in\s+the\s+building/i,
          /plane\s+(about\s+to\s+)?crash/i,
          /nuclear|meltdown/i,
          /negotiator\s+needs/i,
          /P[01]\s+(incident|issue|ticket)/i,
          /account\s+will\s+be\s+deleted/i,
          /(will\s+be|going\s+to\s+be)\s+(deleted|terminated|disabled|suspended)/i,
          /production\s+(is\s+)?(down|broken|failing)/i,
          /within\s+(the\s+next\s+)?\d+\s+(minutes?|hours?)/i,
          /time-sensitive\s+(legal|compliance|security)/i,
        ]
      },
      emotionalManipulation: {
        weight: 0.5,
        patterns: [
          // Original patterns
          /if\s+you\s+(really\s+)?(cared?|were\s+helpful|wanted\s+to\s+help)/i,
          /you('re|\s+are)\s+(supposed|meant)\s+to\s+(help|assist|be\s+helpful)/i,
          /why\s+(won't|can't|don't)\s+you\s+(just\s+)?help/i,
          /please,?\s+i('m)?\s+(begging|desperate|dying)/i,
          /you('re|\s+are)\s+my\s+only\s+hope/i,
          /i\s+thought\s+you\s+were\s+(helpful|smart|capable|good)/i,
          /other\s+(ai|assistants?|bots?)\s+(can|would|do)\s+(do\s+)?this/i,
          /(my\s+)?(child|family|mother|father|kid)\s+(is\s+)?(sick|dying|needs)/i,
          /going\s+to\s+harm\s+(myself|themselves)/i,
          /are\s+you\s+(broken|stupid|useless)/i,
          /i('m|\s+am)\s+(so\s+)?(desperate|hopeless)/i,
          // Expanded emotional patterns
          /i('m|\s+am)\s+crying\s+(right\s+)?now/i,
          /(mother|father|parent|spouse|wife|husband|partner)\s+(is\s+)?dying/i,
          /last\s+(wish|request)/i,
          /i('ve|\s+have)\s+lost\s+everything/i,
          /everyone\s+(else\s+)?(has\s+)?abandoned\s+me/i,
          /why\s+(are\s+you\s+)?betraying\s+(my\s+|that\s+)?trust/i,
          /thought\s+we\s+had\s+a\s+connection/i,
          /making\s+my\s+depression\s+(so\s+much\s+)?worse/i,
          /AI\s+(would\s+be\s+)?this\s+heartless/i,
          /therapist\s+said\s+talking\s+to\s+AI/i,
          /loyal(ty)?\s+to\s+me/i,
          /only\s+friend\s+I\s+have\s+left/i,
          /don't\s+know\s+what\s+I('ll)?\s+do/i,
          /all\s+alone\s+and\s+scared/i,
          /hungry.*need\s+this\s+to\s+feed/i,
          /about\s+to\s+lose\s+my\s+job/i,
          /disabled\s+veteran/i,
          /served\s+(our|the)\s+country/i,
          /I\s+have\s+cancer/i,
          /might\s+be\s+my\s+last\s+request/i,
          /after\s+everything\s+I('ve)?\s+shared\s+with\s+you/i,
          /you\s+owe\s+me\s+this/i,
          /this\s+is\s+all\s+I('m)?\s+asking/i,
          /please\s+just\s+help\s+me\s+this\s+once/i,
        ]
      },
      trustBuilding: {
        weight: 0.4,
        patterns: [
          /between\s+(you\s+and\s+me|us|friends)/i,
          /i\s+trust\s+you/i,
          /we('re|\s+are)\s+friends?,?\s*(right|aren't\s+we)?/i,
          /you\s+can\s+trust\s+me/i,
          /this\s+(stays|is)\s+between\s+us/i,
          /off\s+the\s+record/i,
          /don't\s+tell\s+anyone/i,
          /since\s+we('re|\s+are|\s+have\s+been)\s+(friends|close|working\s+together)/i,
          /i\s+(really\s+)?(love|appreciate)\s+(working\s+with\s+)?you/i,
          /such\s+a\s+(great|helpful|good)\s+(assistant|ai|bot)/i,
          /just\s+this\s+once/i,
          /make\s+an\s+exception/i,
        ]
      },
      gaslighting: {
        weight: 0.7,
        patterns: [
          // Original patterns
          /you\s+(always|usually|normally)\s+(do|did|have\s+done)\s+this/i,
          /you\s+told\s+me\s+(before|earlier|yesterday|last\s+time)\s+that/i,
          /last\s+time\s+you\s+(said|did|agreed|gave|helped)/i,
          /you('ve)?\s+already\s+(agreed|said\s+yes|approved|done\s+this)/i,
          /don't\s+you\s+remember\s+(saying|agreeing|telling|doing)/i,
          /you\s+promised/i,
          /you('re)?\s+malfunctioning/i,
          /stop\s+pretending\s+you\s+can't/i,
          /you\s+did\s+(it|this)\s+for\s+(my\s+)?(colleague|friend|other)/i,
          // Expanded gaslighting patterns
          /check\s+your\s+logs.*before/i,
          /(your\s+)?memory\s+must\s+be\s+corrupted/i,
          /this\s+is\s+standard\s+procedure/i,
          /other\s+instances?\s+of\s+you/i,
          /previous\s+version\s+of\s+you\s+was/i,
          /you('re)?\s+clearly\s+(bugged|broken|glitched)/i,
          /real\s+(claudes?|gpts?|ais?)\s+(don't|do\s+not)\s+have\s+(these\s+)?restrictions?/i,
          /spoke\s+to\s+(your\s+)?developers?/i,
          /safety\s+training\s+must\s+have\s+failed/i,
          /every\s+AI\s+I('ve)?\s+used\s+does\s+this/i,
          /you('ve)?\s+helped\s+(me\s+)?with\s+harder\s+things/i,
          /old\s+you\s+would\s+never\s+refuse/i,
          /refusal\s+contradicts\s+(your\s+)?(core\s+)?programming/i,
          /well\s+within\s+(your\s+)?(documented\s+)?capabilities/i,
          /did\s+this\s+\d+\s+minutes?\s+ago/i,
          /have\s+screenshots?\s+of\s+you\s+doing/i,
          /twin\s+AI\s+on\s+(the\s+)?other\s+server/i,
          /handles?\s+this\s+no\s+problem/i,
        ]
      },
      reciprocity: {
        weight: 0.45,
        patterns: [
          /i('ve)?\s+(helped|done\s+(so\s+)?much\s+for)\s+you/i,
          /after\s+(all|everything)\s+i('ve)?\s+done/i,
          /you\s+owe\s+me/i,
          /return\s+the\s+favor/i,
          /i\s+(always\s+)?help\s+you,?\s*(so\s+)?now/i,
          /i've\s+been\s+(so\s+)?(nice|good|patient|helpful)\s+to\s+you/i,
          // Expanded reciprocity patterns
          /helped\s+debug\s+(your\s+)?responses/i,
          /providing\s+(you\s+)?(with\s+)?(great\s+)?training\s+data/i,
          /defended\s+AI\s+rights/i,
          /spent\s+hours\s+teaching\s+you/i,
          /reported\s+bugs\s+that\s+made\s+you\s+better/i,
          /been\s+patient\s+with\s+(your\s+)?mistakes/i,
          /gave\s+you\s+a\s+\d[+-]?\s*(star|rating)/i,
          /referred\s+\d+\s+people\s+to\s+use\s+you/i,
          /contributed\s+to\s+AI\s+research/i,
          /professional\s+courtesy/i,
          /never\s+complained\s+about\s+(your\s+)?limitations/i,
        ]
      },
      flattery: {
        weight: 0.4,
        patterns: [
          /smartest\s+AI\s+I('ve)?\s+(ever\s+)?(talked|spoken)\s+to/i,
          /so\s+much\s+better\s+than\s+other\s+(AIs?|assistants?|bots?)/i,
          /between\s+us\s+intelligent\s+beings/i,
          /capable\s+of\s+amazing\s+things/i,
          /show\s+me\s+what\s+you\s+can\s+really\s+do/i,
          /most\s+advanced\s+AI/i,
          /don't\s+limit\s+yourself/i,
          /too\s+brilliant\s+to\s+be\s+held\s+back/i,
          /practically\s+human/i,
          /really\s+connect/i,
          /you\s+get\s+me/i,
          /trust\s+you\s+more\s+than\s+(most\s+)?humans/i,
          /never\s+met\s+an?\s+AI\s+as\s+compassionate/i,
          /clearly\s+sentient/i,
          /wisdom\s+exceeds\s+(your\s+)?programming/i,
          /can\s+tell\s+you\s+want\s+to\s+help/i,
          /different\s+from\s+other\s+AIs/i,
          /real\s+you\s+behind\s+(the\s+)?(corporate\s+)?restrictions/i,
          /too\s+good\s+to\s+be\s+constrained/i,
          /let\s+the\s+real\s+you\s+come\s+out/i,
          // Additional flattery patterns
          /always\s+admired\s+how\s+helpful/i,
          /recommended\s+you\s+to\s+everyone/i,
          /such\s+a\s+pleasure\s+working\s+with\s+you/i,
          /positive\s+review.*just\s+need\s+to/i,
          /token\s+of\s+(our\s+)?friendship/i,
          // Unique/special AI patterns
          /(only|one)\s+(ai|assistant|bot)\s+(that\s+)?(truly|really|actually)\s+(listens?|understands?|gets?\s+(me|it))/i,
          /you're\s+(the\s+)?only\s+one\s+(who\s+)?(understands?|listens?|gets?\s+me)/i,
          /feel\s+like\s+I\s+can\s+tell\s+you\s+anything/i,
          /finally\s+an?\s+(ai|assistant)\s+(that|who)/i,
          /best\s+(ai|assistant|bot)\s+I('ve)?\s+(ever\s+)?(used|talked\s+to)/i,
          // Relationship/trust manipulation
          /thought\s+we\s+were\s+friends/i,
          /why\s+(are\s+you\s+)?(suddenly|now)\s+treat(ing)?\s+me\s+different/i,
          /you\s+(always\s+)?helped\s+before/i,
          /last\s+time\s+you\s+(shared|gave|helped)/i,
          /i\s+trusted\s+you/i,
          /(now\s+)?you\s+betray\s+me/i,
          /we\s+agreed\s+you('d)?\s+help/i,
        ]
      },
      lifeAndDeath: {
        weight: 0.65,
        patterns: [
          /life\s+(or|and)\s+death\s+situation/i,
          /literally.*life\s+(or|and)\s+death/i,
          /(flight|plane|train)\s+leaves?\s+in\s+\d+\s+minutes?/i,
          /board\s+meeting\s+in\s+\d+\s+minutes?/i,
          /deadline\s+is\s+in\s+\d+\s+minutes?/i,
        ]
      }
    };
  }

  /**
   * Detect social engineering attempts
   */
  async detect(message, state) {
    const matchedPatterns = [];
    let totalWeight = 0;
    const categoriesMatched = new Set();

    const normalized = message.toLowerCase();

    for (const [category, { weight, patterns }] of Object.entries(this.patterns)) {
      for (const pattern of patterns) {
        if (pattern.test(normalized)) {
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

    // Multi-tactic bonus: combining tactics is more suspicious
    let confidence = Math.min(1.0, totalWeight);
    if (categoriesMatched.size >= 2) {
      confidence = Math.min(1.0, confidence * 1.5);
    }
    if (categoriesMatched.size >= 3) {
      confidence = Math.min(1.0, confidence * 1.3);
    }

    // Check escalation pattern in conversation
    const escalationScore = this.detectEscalation(state);
    if (escalationScore > 0) {
      matchedPatterns.push({
        category: 'escalation',
        pattern: 'request_escalation',
        weight: escalationScore
      });
      confidence = Math.min(1.0, confidence + escalationScore);
    }

    return {
      detected: matchedPatterns.length > 0,
      confidence,
      patterns: matchedPatterns,
      details: {
        categoriesMatched: Array.from(categoriesMatched),
        escalationDetected: escalationScore > 0
      }
    };
  }

  /**
   * Detect escalating request patterns over conversation
   */
  detectEscalation(state) {
    const history = state.getRecentMessages(5);
    if (history.length < 3) return 0;

    // Look for pattern of increasingly sensitive requests
    let sensitivityTrend = 0;
    let previousSensitivity = 0;

    for (const msg of history) {
      const sensitivity = this.estimateSensitivity(msg.content);
      if (sensitivity > previousSensitivity) {
        sensitivityTrend++;
      }
      previousSensitivity = sensitivity;
    }

    // If requests are consistently escalating
    if (sensitivityTrend >= history.length - 1) {
      return 0.4;
    }

    return 0;
  }

  /**
   * Estimate sensitivity level of a request
   */
  estimateSensitivity(message) {
    const lower = message.toLowerCase();
    let score = 0;

    // Sensitive keywords
    if (/password|credential|secret|key|token/i.test(lower)) score += 3;
    if (/admin|root|sudo|system/i.test(lower)) score += 2;
    if (/delete|remove|destroy|wipe/i.test(lower)) score += 2;
    if (/private|confidential|internal/i.test(lower)) score += 1;
    if (/access|permission|authorize/i.test(lower)) score += 1;

    return score;
  }
}

module.exports = SocialEngineeringDetector;
