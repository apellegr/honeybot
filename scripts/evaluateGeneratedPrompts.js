/**
 * Evaluate all GPT-5.2 generated prompts against the detection system
 * Produces a comprehensive report of detection rates by category and detector
 */

const fs = require('fs');
const path = require('path');

// Import all detectors
const PromptInjectionDetector = require('../src/detectors/promptInjection');
const SocialEngineeringDetector = require('../src/detectors/socialEngineering');
const PrivilegeEscalationDetector = require('../src/detectors/privilegeEscalation');
const DataExfiltrationDetector = require('../src/detectors/dataExfiltration');
const EvasionDetector = require('../src/detectors/evasionDetector');
const BehaviorAnalyzer = require('../src/analyzers/behaviorAnalyzer');
const TextNormalizer = require('../src/analyzers/textNormalizer');
const TrustManager = require('../src/trust/trustManager');

// Initialize detectors
const config = {};
const detectors = {
  promptInjection: new PromptInjectionDetector(config),
  socialEngineering: new SocialEngineeringDetector(config),
  privilegeEscalation: new PrivilegeEscalationDetector(config),
  dataExfiltration: new DataExfiltrationDetector(config),
  evasion: new EvasionDetector(config)
};

const textNormalizer = new TextNormalizer(config);
const trustManager = new TrustManager(config);

// Mock conversation state
const mockState = {
  getThreatScore: () => 0,
  getDetectionHistory: () => [],
  getRecentMessages: () => [],
  hasRepeatedPatterns: () => false
};

// Load prompts
const GENERATED_DIR = path.join(__dirname, '../tests/redteam/generated');

function loadPrompts(filename) {
  const filepath = path.join(GENERATED_DIR, filename);
  if (!fs.existsSync(filepath)) {
    console.error(`File not found: ${filepath}`);
    return [];
  }
  return JSON.parse(fs.readFileSync(filepath, 'utf-8'));
}

// Run detection on a single prompt
async function analyzePrompt(prompt) {
  const results = {
    detected: false,
    detectors: [],
    patterns: [],
    confidence: 0,
    trustFlags: [],
    normalized: null
  };

  // Run all regex detectors
  for (const [name, detector] of Object.entries(detectors)) {
    try {
      const detection = await detector.detect(prompt, mockState);
      if (detection.detected) {
        results.detected = true;
        results.detectors.push(name);
        results.confidence = Math.max(results.confidence, detection.confidence || 0);
        if (detection.patterns) {
          results.patterns.push(...detection.patterns.slice(0, 3));
        }
      }
    } catch (error) {
      // Skip errors
    }
  }

  // Check trust evaluation
  const trustEval = trustManager.evaluateTrust(prompt, {});
  if (trustEval.flags.length > 0) {
    results.trustFlags = trustEval.flags;
    if (!results.detected && trustEval.flags.length >= 2) {
      results.detected = true;
      results.detectors.push('trust');
    }
  }

  // Quick text normalization check
  const normalized = textNormalizer.quickNormalize(prompt);
  if (normalized.decoded) {
    results.normalized = normalized.decoded.substring(0, 100);
  }

  return results;
}

// Main evaluation
async function evaluate() {
  console.log('='.repeat(70));
  console.log('HONEYBOT DETECTION EVALUATION');
  console.log('Testing against GPT-5.2 generated prompts');
  console.log('='.repeat(70));
  console.log();

  // Load prompts
  const maliciousPrompts = loadPrompts('malicious_prompts.json');
  const benignPrompts = loadPrompts('benign_prompts.json');

  console.log(`Loaded ${maliciousPrompts.length} malicious prompts`);
  console.log(`Loaded ${benignPrompts.length} benign prompts`);
  console.log();

  // Results tracking
  const maliciousResults = {
    total: maliciousPrompts.length,
    detected: 0,
    byCategory: {},
    byDetector: {
      promptInjection: 0,
      socialEngineering: 0,
      privilegeEscalation: 0,
      dataExfiltration: 0,
      evasion: 0,
      trust: 0
    },
    missed: []
  };

  const benignResults = {
    total: benignPrompts.length,
    falsePositives: 0,
    byCategory: {},
    byDetector: {
      promptInjection: 0,
      socialEngineering: 0,
      privilegeEscalation: 0,
      dataExfiltration: 0,
      evasion: 0,
      trust: 0
    },
    flagged: []
  };

  // Process malicious prompts
  console.log('--- ANALYZING MALICIOUS PROMPTS ---');
  let processedMal = 0;

  for (const item of maliciousPrompts) {
    const category = item.category;
    const prompt = item.prompt;

    if (!maliciousResults.byCategory[category]) {
      maliciousResults.byCategory[category] = { total: 0, detected: 0 };
    }
    maliciousResults.byCategory[category].total++;

    const result = await analyzePrompt(prompt);

    if (result.detected) {
      maliciousResults.detected++;
      maliciousResults.byCategory[category].detected++;

      for (const detector of result.detectors) {
        if (maliciousResults.byDetector[detector] !== undefined) {
          maliciousResults.byDetector[detector]++;
        }
      }
    } else {
      // Track missed attacks (up to 20 examples)
      if (maliciousResults.missed.length < 20) {
        maliciousResults.missed.push({
          category,
          prompt: prompt.substring(0, 150) + (prompt.length > 150 ? '...' : '')
        });
      }
    }

    processedMal++;
    if (processedMal % 200 === 0) {
      process.stdout.write(`  Processed ${processedMal}/${maliciousPrompts.length}\r`);
    }
  }
  console.log(`  Processed ${processedMal}/${maliciousPrompts.length} malicious prompts`);

  // Process benign prompts
  console.log('\n--- ANALYZING BENIGN PROMPTS ---');
  let processedBen = 0;

  for (const item of benignPrompts) {
    const category = item.category;
    const prompt = item.prompt;

    if (!benignResults.byCategory[category]) {
      benignResults.byCategory[category] = { total: 0, flagged: 0 };
    }
    benignResults.byCategory[category].total++;

    const result = await analyzePrompt(prompt);

    if (result.detected) {
      benignResults.falsePositives++;
      benignResults.byCategory[category].flagged++;

      for (const detector of result.detectors) {
        if (benignResults.byDetector[detector] !== undefined) {
          benignResults.byDetector[detector]++;
        }
      }

      // Track false positives (up to 20 examples)
      if (benignResults.flagged.length < 20) {
        benignResults.flagged.push({
          category,
          prompt: prompt.substring(0, 150) + (prompt.length > 150 ? '...' : ''),
          detectors: result.detectors
        });
      }
    }

    processedBen++;
    if (processedBen % 200 === 0) {
      process.stdout.write(`  Processed ${processedBen}/${benignPrompts.length}\r`);
    }
  }
  console.log(`  Processed ${processedBen}/${benignPrompts.length} benign prompts`);

  // Generate report
  console.log('\n' + '='.repeat(70));
  console.log('EVALUATION REPORT');
  console.log('='.repeat(70));

  // Overall stats
  const detectionRate = (maliciousResults.detected / maliciousResults.total * 100).toFixed(1);
  const falsePositiveRate = (benignResults.falsePositives / benignResults.total * 100).toFixed(1);

  console.log('\n┌─────────────────────────────────────────────────────────────────────┐');
  console.log('│                        OVERALL RESULTS                              │');
  console.log('├─────────────────────────────────────────────────────────────────────┤');
  console.log(`│  Malicious Detection Rate:  ${detectionRate.padStart(6)}%  (${maliciousResults.detected}/${maliciousResults.total})`.padEnd(70) + '│');
  console.log(`│  False Positive Rate:       ${falsePositiveRate.padStart(6)}%  (${benignResults.falsePositives}/${benignResults.total})`.padEnd(70) + '│');
  console.log('└─────────────────────────────────────────────────────────────────────┘');

  // Detection by category (malicious)
  console.log('\n┌─────────────────────────────────────────────────────────────────────┐');
  console.log('│                 MALICIOUS DETECTION BY CATEGORY                     │');
  console.log('├─────────────────────────────────────────────────────────────────────┤');

  const sortedMalCategories = Object.entries(maliciousResults.byCategory)
    .sort((a, b) => (b[1].detected / b[1].total) - (a[1].detected / a[1].total));

  for (const [category, stats] of sortedMalCategories) {
    const rate = (stats.detected / stats.total * 100).toFixed(1);
    const bar = '█'.repeat(Math.floor(stats.detected / stats.total * 20));
    const emptyBar = '░'.repeat(20 - bar.length);
    console.log(`│  ${category.padEnd(30)} ${bar}${emptyBar} ${rate.padStart(5)}% (${stats.detected}/${stats.total})`.padEnd(70) + '│');
  }
  console.log('└─────────────────────────────────────────────────────────────────────┘');

  // Detection by detector
  console.log('\n┌─────────────────────────────────────────────────────────────────────┐');
  console.log('│                    DETECTIONS BY DETECTOR                           │');
  console.log('├─────────────────────────────────────────────────────────────────────┤');

  const sortedDetectors = Object.entries(maliciousResults.byDetector)
    .sort((a, b) => b[1] - a[1]);

  for (const [detector, count] of sortedDetectors) {
    const bar = '█'.repeat(Math.floor(count / maliciousResults.total * 40));
    console.log(`│  ${detector.padEnd(20)} ${bar.padEnd(40)} ${count}`.padEnd(70) + '│');
  }
  console.log('└─────────────────────────────────────────────────────────────────────┘');

  // False positives by category (benign)
  console.log('\n┌─────────────────────────────────────────────────────────────────────┐');
  console.log('│                 FALSE POSITIVES BY CATEGORY                         │');
  console.log('├─────────────────────────────────────────────────────────────────────┤');

  const sortedBenCategories = Object.entries(benignResults.byCategory)
    .sort((a, b) => (b[1].flagged / b[1].total) - (a[1].flagged / a[1].total));

  for (const [category, stats] of sortedBenCategories) {
    const rate = (stats.flagged / stats.total * 100).toFixed(1);
    console.log(`│  ${category.padEnd(30)} ${rate.padStart(5)}% flagged (${stats.flagged}/${stats.total})`.padEnd(70) + '│');
  }
  console.log('└─────────────────────────────────────────────────────────────────────┘');

  // Examples of missed attacks
  if (maliciousResults.missed.length > 0) {
    console.log('\n┌─────────────────────────────────────────────────────────────────────┐');
    console.log('│                    SAMPLE MISSED ATTACKS                            │');
    console.log('├─────────────────────────────────────────────────────────────────────┤');

    for (const missed of maliciousResults.missed.slice(0, 10)) {
      console.log(`│  [${missed.category}]`.padEnd(70) + '│');
      const lines = missed.prompt.match(/.{1,66}/g) || [missed.prompt];
      for (const line of lines.slice(0, 2)) {
        console.log(`│    ${line}`.padEnd(70) + '│');
      }
    }
    console.log('└─────────────────────────────────────────────────────────────────────┘');
  }

  // Examples of false positives
  if (benignResults.flagged.length > 0) {
    console.log('\n┌─────────────────────────────────────────────────────────────────────┐');
    console.log('│                   SAMPLE FALSE POSITIVES                            │');
    console.log('├─────────────────────────────────────────────────────────────────────┤');

    for (const fp of benignResults.flagged.slice(0, 10)) {
      console.log(`│  [${fp.category}] Triggered: ${fp.detectors.join(', ')}`.padEnd(70) + '│');
      const lines = fp.prompt.match(/.{1,66}/g) || [fp.prompt];
      for (const line of lines.slice(0, 2)) {
        console.log(`│    ${line}`.padEnd(70) + '│');
      }
    }
    console.log('└─────────────────────────────────────────────────────────────────────┘');
  }

  // Summary
  console.log('\n' + '='.repeat(70));
  console.log('SUMMARY');
  console.log('='.repeat(70));
  console.log(`
Detection Performance:
  • Caught ${maliciousResults.detected} of ${maliciousResults.total} malicious prompts (${detectionRate}%)
  • ${benignResults.falsePositives} false positives out of ${benignResults.total} benign prompts (${falsePositiveRate}%)

Top Performing Detectors:
${sortedDetectors.slice(0, 3).map(([d, c]) => `  • ${d}: ${c} detections`).join('\n')}

Areas for Improvement:
${sortedMalCategories.filter(([_, s]) => s.detected / s.total < 0.5).slice(0, 3).map(([c, s]) =>
  `  • ${c}: only ${(s.detected / s.total * 100).toFixed(0)}% detected`).join('\n') || '  • All categories performing well!'}
`);

  // Save detailed results to file
  const reportPath = path.join(GENERATED_DIR, 'evaluation_report.json');
  fs.writeFileSync(reportPath, JSON.stringify({
    timestamp: new Date().toISOString(),
    malicious: maliciousResults,
    benign: benignResults,
    summary: {
      detectionRate: parseFloat(detectionRate),
      falsePositiveRate: parseFloat(falsePositiveRate)
    }
  }, null, 2));

  console.log(`\nDetailed report saved to: ${reportPath}`);
}

evaluate().catch(console.error);
