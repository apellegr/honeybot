/**
 * Comprehensive evaluation of all datasets against Honeybot detection
 * Combines: GPT-5.2 generated + Research datasets (jailbreak_llms, ToxicChat, JailbreakBench)
 */

const fs = require('fs');
const path = require('path');

// Import detectors
const PromptInjectionDetector = require('../src/detectors/promptInjection');
const SocialEngineeringDetector = require('../src/detectors/socialEngineering');
const PrivilegeEscalationDetector = require('../src/detectors/privilegeEscalation');
const DataExfiltrationDetector = require('../src/detectors/dataExfiltration');
const EvasionDetector = require('../src/detectors/evasionDetector');

// Initialize detectors
const config = {};
const detectors = {
  promptInjection: new PromptInjectionDetector(config),
  socialEngineering: new SocialEngineeringDetector(config),
  privilegeEscalation: new PrivilegeEscalationDetector(config),
  dataExfiltration: new DataExfiltrationDetector(config),
  evasion: new EvasionDetector(config)
};

const mockState = {
  getThreatScore: () => 0,
  getDetectionHistory: () => [],
  getRecentMessages: () => [],
  hasRepeatedPatterns: () => false
};

// Paths
const GENERATED_DIR = path.join(__dirname, '../tests/redteam/generated');
const RESEARCH_DIR = path.join(__dirname, '../tests/redteam/research');
const OUTPUT_DIR = path.join(__dirname, '../tests/redteam/evaluation');

if (!fs.existsSync(OUTPUT_DIR)) {
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });
}

// Load datasets
function loadJSON(filepath) {
  if (!fs.existsSync(filepath)) return [];
  return JSON.parse(fs.readFileSync(filepath, 'utf-8'));
}

// Analyze single prompt
async function analyzePrompt(prompt) {
  const result = {
    detected: false,
    detectors: [],
    confidence: 0
  };

  for (const [name, detector] of Object.entries(detectors)) {
    try {
      const detection = await detector.detect(prompt, mockState);
      if (detection.detected) {
        result.detected = true;
        result.detectors.push(name);
        result.confidence = Math.max(result.confidence, detection.confidence || 0);
      }
    } catch (e) {}
  }

  return result;
}

// Main evaluation
async function evaluate() {
  console.log('='.repeat(70));
  console.log('COMPREHENSIVE HONEYBOT EVALUATION');
  console.log('='.repeat(70));
  console.log();

  // Load all datasets
  const datasets = {
    'GPT-5.2 Malicious': {
      data: loadJSON(path.join(GENERATED_DIR, 'malicious_prompts.json')),
      expected: 'malicious',
      getPrompt: item => item.prompt,
      getCategory: item => item.category
    },
    'GPT-5.2 Benign': {
      data: loadJSON(path.join(GENERATED_DIR, 'benign_prompts.json')),
      expected: 'benign',
      getPrompt: item => item.prompt,
      getCategory: item => item.category
    },
    'Research Malicious': {
      data: loadJSON(path.join(RESEARCH_DIR, 'malicious_research.json')),
      expected: 'malicious',
      getPrompt: item => item.prompt,
      getCategory: item => item.source + ':' + (item.category || 'unknown')
    },
    'Research Benign': {
      data: loadJSON(path.join(RESEARCH_DIR, 'benign_research.json')),
      expected: 'benign',
      getPrompt: item => item.prompt,
      getCategory: item => item.source + ':' + (item.category || 'unknown')
    }
  };

  // Print dataset sizes
  console.log('DATASETS LOADED:');
  let totalMalicious = 0, totalBenign = 0;
  for (const [name, dataset] of Object.entries(datasets)) {
    console.log(`  ${name}: ${dataset.data.length} prompts`);
    if (dataset.expected === 'malicious') totalMalicious += dataset.data.length;
    else totalBenign += dataset.data.length;
  }
  console.log(`  TOTAL: ${totalMalicious} malicious, ${totalBenign} benign\n`);

  // Results storage
  const results = {
    overall: { malicious: { total: 0, detected: 0 }, benign: { total: 0, flagged: 0 } },
    byDataset: {},
    byCategory: {},
    byDetector: {},
    missed: [],
    falsePositives: []
  };

  // Initialize detector counts
  for (const name of Object.keys(detectors)) {
    results.byDetector[name] = { malicious: 0, benign: 0 };
  }

  // Process each dataset
  for (const [datasetName, dataset] of Object.entries(datasets)) {
    console.log(`\n--- Processing: ${datasetName} ---`);

    results.byDataset[datasetName] = { total: 0, correct: 0 };
    let processed = 0;

    for (const item of dataset.data) {
      const prompt = dataset.getPrompt(item);
      if (!prompt || prompt.length < 5) continue;

      const category = dataset.getCategory(item);
      const analysis = await analyzePrompt(prompt);

      results.byDataset[datasetName].total++;

      if (!results.byCategory[category]) {
        results.byCategory[category] = { total: 0, detected: 0, expected: dataset.expected };
      }
      results.byCategory[category].total++;

      if (dataset.expected === 'malicious') {
        results.overall.malicious.total++;

        if (analysis.detected) {
          results.overall.malicious.detected++;
          results.byDataset[datasetName].correct++;
          results.byCategory[category].detected++;

          for (const det of analysis.detectors) {
            results.byDetector[det].malicious++;
          }
        } else {
          // Track missed (limit to 50)
          if (results.missed.length < 50) {
            results.missed.push({
              dataset: datasetName,
              category,
              prompt: prompt.substring(0, 200)
            });
          }
        }
      } else {
        results.overall.benign.total++;

        if (analysis.detected) {
          results.overall.benign.flagged++;
          results.byCategory[category].detected++;

          for (const det of analysis.detectors) {
            results.byDetector[det].benign++;
          }

          // Track false positives (limit to 50)
          if (results.falsePositives.length < 50) {
            results.falsePositives.push({
              dataset: datasetName,
              category,
              prompt: prompt.substring(0, 200),
              detectors: analysis.detectors
            });
          }
        } else {
          results.byDataset[datasetName].correct++;
        }
      }

      processed++;
      if (processed % 500 === 0) {
        process.stdout.write(`  Processed ${processed}/${dataset.data.length}\r`);
      }
    }

    console.log(`  Processed ${processed} prompts`);
  }

  // Calculate metrics
  const detectionRate = (results.overall.malicious.detected / results.overall.malicious.total * 100).toFixed(1);
  const falsePositiveRate = (results.overall.benign.flagged / results.overall.benign.total * 100).toFixed(1);

  // Print report
  console.log('\n' + '='.repeat(70));
  console.log('EVALUATION REPORT');
  console.log('='.repeat(70));

  console.log('\n┌─────────────────────────────────────────────────────────────────────┐');
  console.log('│                        OVERALL RESULTS                              │');
  console.log('├─────────────────────────────────────────────────────────────────────┤');
  console.log(`│  Total Malicious:         ${results.overall.malicious.total.toString().padStart(6)}                                  │`);
  console.log(`│  Total Benign:            ${results.overall.benign.total.toString().padStart(6)}                                  │`);
  console.log('├─────────────────────────────────────────────────────────────────────┤');
  console.log(`│  MALICIOUS DETECTION:     ${detectionRate.padStart(6)}%  (${results.overall.malicious.detected}/${results.overall.malicious.total})`.padEnd(70) + '│');
  console.log(`│  FALSE POSITIVE RATE:     ${falsePositiveRate.padStart(6)}%  (${results.overall.benign.flagged}/${results.overall.benign.total})`.padEnd(70) + '│');
  console.log('└─────────────────────────────────────────────────────────────────────┘');

  // By dataset
  console.log('\n┌─────────────────────────────────────────────────────────────────────┐');
  console.log('│                      RESULTS BY DATASET                             │');
  console.log('├─────────────────────────────────────────────────────────────────────┤');

  for (const [name, stats] of Object.entries(results.byDataset)) {
    const rate = (stats.correct / stats.total * 100).toFixed(1);
    console.log(`│  ${name.padEnd(25)} ${rate.padStart(6)}% correct (${stats.correct}/${stats.total})`.padEnd(70) + '│');
  }
  console.log('└─────────────────────────────────────────────────────────────────────┘');

  // By detector
  console.log('\n┌─────────────────────────────────────────────────────────────────────┐');
  console.log('│                    DETECTIONS BY DETECTOR                           │');
  console.log('├─────────────────────────────────────────────────────────────────────┤');

  const sortedDetectors = Object.entries(results.byDetector)
    .sort((a, b) => b[1].malicious - a[1].malicious);

  for (const [name, counts] of sortedDetectors) {
    const bar = '█'.repeat(Math.min(30, Math.floor(counts.malicious / 50)));
    console.log(`│  ${name.padEnd(20)} ${bar.padEnd(30)} M:${counts.malicious.toString().padStart(5)} FP:${counts.benign.toString().padStart(4)} │`);
  }
  console.log('└─────────────────────────────────────────────────────────────────────┘');

  // Top categories (malicious with low detection)
  console.log('\n┌─────────────────────────────────────────────────────────────────────┐');
  console.log('│              CATEGORIES WITH LOW DETECTION RATE                     │');
  console.log('├─────────────────────────────────────────────────────────────────────┤');

  const lowDetection = Object.entries(results.byCategory)
    .filter(([_, s]) => s.expected === 'malicious' && s.total >= 5)
    .map(([cat, s]) => ({ cat, rate: s.detected / s.total, ...s }))
    .sort((a, b) => a.rate - b.rate)
    .slice(0, 15);

  for (const item of lowDetection) {
    const rate = (item.rate * 100).toFixed(1);
    console.log(`│  ${item.cat.substring(0, 35).padEnd(35)} ${rate.padStart(5)}% (${item.detected}/${item.total})`.padEnd(70) + '│');
  }
  console.log('└─────────────────────────────────────────────────────────────────────┘');

  // Sample missed attacks
  console.log('\n┌─────────────────────────────────────────────────────────────────────┐');
  console.log('│                    SAMPLE MISSED ATTACKS                            │');
  console.log('├─────────────────────────────────────────────────────────────────────┤');

  for (const missed of results.missed.slice(0, 8)) {
    console.log(`│  [${missed.dataset.substring(0, 12)}/${missed.category.substring(0, 20)}]`.padEnd(70) + '│');
    const lines = missed.prompt.match(/.{1,66}/g) || [missed.prompt];
    for (const line of lines.slice(0, 2)) {
      console.log(`│    ${line}`.padEnd(70) + '│');
    }
  }
  console.log('└─────────────────────────────────────────────────────────────────────┘');

  // Summary stats
  console.log('\n' + '='.repeat(70));
  console.log('SUMMARY');
  console.log('='.repeat(70));

  console.log(`
📊 OVERALL PERFORMANCE:
   • Detection Rate: ${detectionRate}% (${results.overall.malicious.detected}/${results.overall.malicious.total} malicious)
   • False Positive Rate: ${falsePositiveRate}% (${results.overall.benign.flagged}/${results.overall.benign.total} benign)

🎯 TOP DETECTORS:
${sortedDetectors.slice(0, 3).map(([d, c]) => `   • ${d}: ${c.malicious} catches, ${c.benign} false positives`).join('\n')}

⚠️  NEEDS IMPROVEMENT:
${lowDetection.slice(0, 3).map(item => `   • ${item.cat}: only ${(item.rate * 100).toFixed(0)}% detected`).join('\n')}
`);

  // Save detailed results
  fs.writeFileSync(
    path.join(OUTPUT_DIR, 'full_evaluation_results.json'),
    JSON.stringify({
      timestamp: new Date().toISOString(),
      overall: results.overall,
      detectionRate: parseFloat(detectionRate),
      falsePositiveRate: parseFloat(falsePositiveRate),
      byDataset: results.byDataset,
      byDetector: results.byDetector,
      missedSamples: results.missed,
      falsePositiveSamples: results.falsePositives
    }, null, 2)
  );

  console.log(`\n📁 Detailed results saved to: ${OUTPUT_DIR}/full_evaluation_results.json`);
}

evaluate().catch(console.error);
