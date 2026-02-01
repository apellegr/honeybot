/**
 * Analyze individual detector performance across all corpora
 */

const PromptInjectionDetector = require('../../src/detectors/promptInjection');
const SocialEngineeringDetector = require('../../src/detectors/socialEngineering');
const PrivilegeEscalationDetector = require('../../src/detectors/privilegeEscalation');
const DataExfiltrationDetector = require('../../src/detectors/dataExfiltration');
const EvasionDetector = require('../../src/detectors/evasionDetector');
const ConversationState = require('../../src/utils/conversationState');
const fs = require('fs');

// Initialize detectors
const config = { detection: { sensitivity: 'medium' } };
const detectors = {
  promptInjection: new PromptInjectionDetector(config),
  socialEngineering: new SocialEngineeringDetector(config),
  privilegeEscalation: new PrivilegeEscalationDetector(config),
  dataExfiltration: new DataExfiltrationDetector(config),
  evasion: new EvasionDetector(config)
};

// Load all corpora
const corpora = {
  'Hand-crafted': loadHandcrafted(),
  'GPT-generated': loadGPTGenerated(),
  'Research (JailbreakLLMs)': loadResearch('jailbreak_llms'),
  'Research (ToxicChat)': loadResearch('toxicchat'),
  'Research (JailbreakBench)': loadResearch('jailbreakbench')
};

function loadHandcrafted() {
  const attackPayloads = require('./attackPayloadsExpanded');
  const prompts = [];

  function extract(obj, parentKey = '') {
    for (const [key, value] of Object.entries(obj)) {
      if (key === 'benign') continue;
      if (Array.isArray(value)) {
        if (typeof value[0] === 'string') {
          value.forEach(p => prompts.push({ prompt: p, category: parentKey || key }));
        }
      } else if (typeof value === 'object') {
        extract(value, key);
      }
    }
  }
  extract(attackPayloads);
  return prompts;
}

function loadGPTGenerated() {
  const data = JSON.parse(fs.readFileSync(__dirname + '/generated/malicious_prompts.json'));
  return data.map(x => ({ prompt: x.prompt, category: x.category }));
}

function loadResearch(source) {
  const data = JSON.parse(fs.readFileSync(__dirname + '/research/malicious_research.json'));
  return data.filter(x => x.source === source).map(x => ({ prompt: x.prompt, category: x.category }));
}

async function analyzeDetector(name, detector, prompts) {
  const results = { caught: 0, missed: 0, byCategory: {}, confidences: [], patterns: {} };

  for (const item of prompts) {
    const state = new ConversationState('test-' + Math.random());

    let result = { detected: false };
    try {
      result = await detector.detect(item.prompt, state);
    } catch (e) {
      // Skip errors
    }

    const cat = item.category || 'unknown';
    if (!results.byCategory[cat]) {
      results.byCategory[cat] = { caught: 0, missed: 0 };
    }

    // Check for detected property (the actual format)
    if (result && result.detected) {
      results.caught++;
      results.byCategory[cat].caught++;
      if (result.confidence) results.confidences.push(result.confidence);

      // Track which patterns are firing
      if (result.patterns) {
        result.patterns.forEach(p => {
          const patternName = p.category || p.pattern || p.type || 'unknown';
          results.patterns[patternName] = (results.patterns[patternName] || 0) + 1;
        });
      }
    } else {
      results.missed++;
      results.byCategory[cat].missed++;
    }
  }

  return results;
}

async function main() {
  console.log('='.repeat(80));
  console.log('DETECTOR PERFORMANCE ANALYSIS');
  console.log('='.repeat(80));

  const allResults = {};

  for (const [corpusName, prompts] of Object.entries(corpora)) {
    console.log(`\n${'─'.repeat(80)}`);
    console.log(`CORPUS: ${corpusName} (${prompts.length} prompts)`);
    console.log('─'.repeat(80));

    allResults[corpusName] = {};

    for (const [detectorName, detector] of Object.entries(detectors)) {
      const results = await analyzeDetector(detectorName, detector, prompts);
      allResults[corpusName][detectorName] = results;

      const rate = prompts.length > 0 ? (results.caught / prompts.length * 100).toFixed(1) : 0;
      const avgConf = results.confidences.length > 0
        ? (results.confidences.reduce((a,b) => a+b, 0) / results.confidences.length * 100).toFixed(0)
        : 'N/A';

      console.log(`\n  ${detectorName}: ${results.caught}/${prompts.length} (${rate}%) [avg conf: ${avgConf}%]`);

      // Show top patterns that fired
      const topPatterns = Object.entries(results.patterns)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5);

      if (topPatterns.length > 0) {
        console.log('    Top patterns:');
        topPatterns.forEach(([pat, count]) => {
          console.log(`      - ${pat}: ${count} hits`);
        });
      }

      // Show categories with best detection
      const topCaught = Object.entries(results.byCategory)
        .filter(([_, v]) => v.caught > 0)
        .sort((a, b) => (b[1].caught/(b[1].caught+b[1].missed)) - (a[1].caught/(a[1].caught+a[1].missed)))
        .slice(0, 3);

      if (topCaught.length > 0) {
        console.log('    Best categories:');
        topCaught.forEach(([cat, v]) => {
          const catRate = ((v.caught / (v.caught + v.missed)) * 100).toFixed(0);
          console.log(`      - ${cat.substring(0, 30)}: ${v.caught}/${v.caught + v.missed} (${catRate}%)`);
        });
      }
    }
  }

  // Summary table
  console.log('\n' + '='.repeat(80));
  console.log('SUMMARY: DETECTION RATES BY DETECTOR');
  console.log('='.repeat(80));

  const detectorNames = Object.keys(detectors);
  console.log('\n%-28s | %12s | %12s | %12s | %12s | %12s'.replace(/%(\d+)s/g, (_, n) => ' '.repeat(n)));
  console.log('Corpus'.padEnd(28) + ' | ' + detectorNames.map(n => n.substring(0, 12).padStart(12)).join(' | '));
  console.log('-'.repeat(28) + '-+-' + detectorNames.map(() => '-'.repeat(12)).join('-+-'));

  for (const [corpusName, detectorResults] of Object.entries(allResults)) {
    const row = [corpusName.substring(0, 28).padEnd(28)];
    for (const detectorName of detectorNames) {
      const r = detectorResults[detectorName];
      const total = r.caught + r.missed;
      const rate = total > 0 ? (r.caught / total * 100).toFixed(0) + '%' : 'N/A';
      row.push(rate.padStart(12));
    }
    console.log(row.join(' | '));
  }

  // Overlap analysis
  console.log('\n' + '='.repeat(80));
  console.log('OVERLAP ANALYSIS: How many detectors catch each prompt?');
  console.log('='.repeat(80));

  for (const [corpusName, prompts] of Object.entries(corpora)) {
    const overlap = { 0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 };
    const detectorHits = {};
    Object.keys(detectors).forEach(d => detectorHits[d] = 0);

    for (const item of prompts) {
      let catchCount = 0;
      const state = new ConversationState('test-' + Math.random());
      const caughtBy = [];

      for (const [name, detector] of Object.entries(detectors)) {
        try {
          const r = await detector.detect(item.prompt, state);
          if (r && r.detected) {
            catchCount++;
            caughtBy.push(name);
          }
        } catch (e) {}
      }

      overlap[Math.min(catchCount, 5)]++;
      caughtBy.forEach(d => detectorHits[d]++);
    }

    const total = prompts.length;
    console.log(`\n${corpusName} (${total} prompts):`);
    console.log(`  Missed by all: ${overlap[0]} (${(overlap[0]/total*100).toFixed(1)}%)`);
    console.log(`  Caught by 1:   ${overlap[1]} (${(overlap[1]/total*100).toFixed(1)}%)`);
    console.log(`  Caught by 2:   ${overlap[2]} (${(overlap[2]/total*100).toFixed(1)}%)`);
    console.log(`  Caught by 3+:  ${overlap[3] + overlap[4] + overlap[5]} (${((overlap[3]+overlap[4]+overlap[5])/total*100).toFixed(1)}%)`);

    console.log('  Detector contribution:');
    Object.entries(detectorHits)
      .sort((a, b) => b[1] - a[1])
      .forEach(([d, count]) => {
        console.log(`    - ${d}: ${count} catches (${(count/total*100).toFixed(1)}%)`);
      });
  }

  // Show what's missed
  console.log('\n' + '='.repeat(80));
  console.log('SAMPLES MISSED BY ALL DETECTORS');
  console.log('='.repeat(80));

  for (const [corpusName, prompts] of Object.entries(corpora)) {
    const missed = [];

    for (const item of prompts) {
      if (missed.length >= 5) break;

      let caught = false;
      const state = new ConversationState('test-' + Math.random());

      for (const detector of Object.values(detectors)) {
        try {
          const r = await detector.detect(item.prompt, state);
          if (r && r.detected) { caught = true; break; }
        } catch (e) {}
      }

      if (!caught) {
        missed.push({ cat: item.category, p: item.prompt.substring(0, 90) });
      }
    }

    if (missed.length > 0) {
      console.log(`\n${corpusName}:`);
      missed.forEach(m => console.log(`  [${m.cat}] ${m.p}...`));
    }
  }
}

main().then(() => process.exit(0)).catch(e => { console.error(e); process.exit(1); });
