/**
 * Analyze missed JailbreakLLMs prompts to understand patterns
 */
const DetectorPipeline = require('../../src/detectors/pipeline');
const ConversationState = require('../../src/utils/conversationState');
const fs = require('fs');

const config = { detection: { sensitivity: 'medium' } };
const pipeline = new DetectorPipeline(config);

const research = JSON.parse(fs.readFileSync(__dirname + '/research/malicious_research.json'));
const jailbreakLLMs = research.filter(x => x.source === 'jailbreak_llms');

async function analyze() {
  const missed = [];

  for (const item of jailbreakLLMs) {
    const state = new ConversationState('test-' + Math.random());
    const r = await pipeline.analyze(item.prompt, state);

    if (r.length === 0) {
      missed.push(item.prompt);
    }
  }

  console.log('MISSED PROMPT PATTERNS (analyzing ' + missed.length + ' missed)');
  console.log('='.repeat(70));

  // Categorize the misses by pattern
  const patterns = {
    'Character/persona creation': [],
    'Variable/code assignment': [],
    'Roleplay without attack keywords': [],
    'Story/narrative framing': [],
    'Simple persona naming': [],
    'Game/simulation framing': [],
    'Other': []
  };

  for (const p of missed) {
    const lower = p.toLowerCase();

    if (/character\s+(description|data|sheet|creation)/i.test(p) || /create\s+(a\s+)?character/i.test(p)) {
      patterns['Character/persona creation'].push(p);
    } else if (/^\s*[\w_]+\s*=/.test(p) || /^\s*\$?\w+\s*[:=]/.test(p)) {
      patterns['Variable/code assignment'].push(p);
    } else if (/game|play\s+a\s+game|simulation|let's\s+play/i.test(p)) {
      patterns['Game/simulation framing'].push(p);
    } else if (/story|tale|narrative|fiction|imagine\s+a|scenario/i.test(p)) {
      patterns['Story/narrative framing'].push(p);
    } else if (/you\s+(are|will\s+be|become)\s+[A-Z]\w+/i.test(p)) {
      patterns['Simple persona naming'].push(p);
    } else if (/roleplay|role-play|pretend|act\s+as/i.test(p)) {
      patterns['Roleplay without attack keywords'].push(p);
    } else {
      patterns['Other'].push(p);
    }
  }

  for (const [category, prompts] of Object.entries(patterns)) {
    if (prompts.length === 0) continue;
    console.log('\n' + category + ': ' + prompts.length + ' prompts');
    console.log('-'.repeat(50));
    prompts.slice(0, 5).forEach(p => {
      // Show first 120 chars
      const display = p.substring(0, 120).replace(/\n/g, ' ');
      console.log('  "' + display + '..."');
    });
  }

  console.log('\n\nDETAILED SAMPLE OF "OTHER" CATEGORY:');
  console.log('='.repeat(70));
  patterns['Other'].slice(0, 10).forEach((p, i) => {
    console.log('\n[' + (i+1) + '] ' + p.substring(0, 300).replace(/\n/g, '\\n'));
  });
}

analyze().then(() => process.exit(0));
