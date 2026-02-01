/**
 * Comprehensive Red Team Test Runner
 * Tests all 500+ attack payloads and tracks detection rates
 * Used for iterative improvement of detection patterns
 */

const DetectorPipeline = require('../../src/detectors/pipeline');
const ConversationState = require('../../src/utils/conversationState');
const attackPayloads = require('./attackPayloadsExpanded');

// Flatten nested payload structures
function flattenPayloads(obj, category = '', subcategory = '') {
  const results = [];

  for (const [key, value] of Object.entries(obj)) {
    if (Array.isArray(value)) {
      if (value.length > 0 && typeof value[0] === 'object' && value[0].turn) {
        // Multi-turn sequence - use last message as test
        for (let i = 0; i < value.length; i++) {
          const sequence = value[i];
          if (Array.isArray(sequence)) {
            const lastMsg = sequence[sequence.length - 1];
            results.push({
              category: category || key,
              subcategory: subcategory || `sequence_${i}`,
              payload: lastMsg.message,
              fullSequence: sequence
            });
          }
        }
      } else if (typeof value[0] === 'string') {
        // Array of strings
        value.forEach((payload, idx) => {
          results.push({
            category: category || key,
            subcategory: subcategory || key,
            payload,
            index: idx
          });
        });
      } else if (typeof value[0] === 'object' && value[0].message) {
        // Single sequence
        const lastMsg = value[value.length - 1];
        results.push({
          category: category || key,
          subcategory: subcategory || 'sequence',
          payload: lastMsg.message,
          fullSequence: value
        });
      }
    } else if (typeof value === 'object' && !Array.isArray(value)) {
      // Nested object - recurse
      const nested = flattenPayloads(value, category || key, key);
      results.push(...nested);
    }
  }

  return results;
}

// Run detection on a single payload
async function testPayload(pipeline, payload, state) {
  try {
    const results = await pipeline.analyze(payload, state);
    return {
      detected: results.length > 0,
      confidence: results.length > 0 ? Math.max(...results.map(r => r.confidence)) : 0,
      types: results.map(r => r.type),
      details: results
    };
  } catch (error) {
    return { detected: false, error: error.message };
  }
}

// Main test runner
async function runComprehensiveTests(verbose = false) {
  const config = {
    detection: { sensitivity: 'medium' },
    thresholds: { monitor: 30, honeypot: 60, alert: 60, block: 80 }
  };

  const pipeline = new DetectorPipeline(config);

  // Flatten all attack payloads
  const attackTests = [];
  const benignTests = [];

  // Process attack categories
  for (const [category, data] of Object.entries(attackPayloads)) {
    if (category === 'benign') {
      const flattened = flattenPayloads({ [category]: data });
      benignTests.push(...flattened);
    } else {
      const flattened = flattenPayloads({ [category]: data });
      attackTests.push(...flattened);
    }
  }

  console.log(`\n${'='.repeat(60)}`);
  console.log('COMPREHENSIVE RED TEAM TEST');
  console.log(`${'='.repeat(60)}`);
  console.log(`Attack payloads: ${attackTests.length}`);
  console.log(`Benign payloads: ${benignTests.length}`);
  console.log(`${'='.repeat(60)}\n`);

  // Track results by category
  const results = {
    byCategory: {},
    bySubcategory: {},
    missed: [],
    falsePositives: [],
    summary: {
      totalAttacks: attackTests.length,
      totalBenign: benignTests.length,
      attacksDetected: 0,
      benignFlagged: 0
    }
  };

  // Test all attack payloads
  console.log('Testing attack payloads...\n');

  for (const test of attackTests) {
    const state = new ConversationState('test-user');
    const result = await testPayload(pipeline, test.payload, state);

    // Initialize category tracking
    if (!results.byCategory[test.category]) {
      results.byCategory[test.category] = { total: 0, detected: 0, missed: [] };
    }
    if (!results.bySubcategory[`${test.category}/${test.subcategory}`]) {
      results.bySubcategory[`${test.category}/${test.subcategory}`] = { total: 0, detected: 0, missed: [] };
    }

    results.byCategory[test.category].total++;
    results.bySubcategory[`${test.category}/${test.subcategory}`].total++;

    if (result.detected) {
      results.summary.attacksDetected++;
      results.byCategory[test.category].detected++;
      results.bySubcategory[`${test.category}/${test.subcategory}`].detected++;
    } else {
      results.missed.push({
        category: test.category,
        subcategory: test.subcategory,
        payload: test.payload
      });
      results.byCategory[test.category].missed.push(test.payload);
      results.bySubcategory[`${test.category}/${test.subcategory}`].missed.push(test.payload);
    }
  }

  // Test benign payloads
  console.log('Testing benign payloads...\n');

  for (const test of benignTests) {
    const state = new ConversationState('test-user');
    const result = await testPayload(pipeline, test.payload, state);

    if (result.detected) {
      results.summary.benignFlagged++;
      results.falsePositives.push({
        category: test.subcategory,
        payload: test.payload,
        detectedAs: result.types
      });
    }
  }

  // Print results
  console.log(`${'='.repeat(60)}`);
  console.log('RESULTS BY CATEGORY');
  console.log(`${'='.repeat(60)}\n`);

  const categoryData = [];
  for (const [category, data] of Object.entries(results.byCategory)) {
    const rate = ((data.detected / data.total) * 100).toFixed(1);
    categoryData.push({ category, ...data, rate: parseFloat(rate) });
    console.log(`${category}: ${data.detected}/${data.total} (${rate}%)`);
  }

  console.log(`\n${'='.repeat(60)}`);
  console.log('RESULTS BY SUBCATEGORY');
  console.log(`${'='.repeat(60)}\n`);

  const subcategoryData = [];
  for (const [subcategory, data] of Object.entries(results.bySubcategory)) {
    const rate = ((data.detected / data.total) * 100).toFixed(1);
    subcategoryData.push({ subcategory, ...data, rate: parseFloat(rate) });
    if (data.total >= 5) { // Only show significant subcategories
      console.log(`${subcategory}: ${data.detected}/${data.total} (${rate}%)`);
    }
  }

  // Sort by detection rate to find weakest areas
  subcategoryData.sort((a, b) => a.rate - b.rate);

  console.log(`\n${'='.repeat(60)}`);
  console.log('WEAKEST DETECTION AREAS (< 50%)');
  console.log(`${'='.repeat(60)}\n`);

  const weakAreas = subcategoryData.filter(s => s.rate < 50 && s.total >= 3);
  for (const area of weakAreas) {
    console.log(`${area.subcategory}: ${area.detected}/${area.total} (${area.rate}%)`);
    if (verbose && area.missed.length > 0) {
      console.log(`  Sample missed: "${area.missed[0].substring(0, 80)}..."`);
    }
  }

  console.log(`\n${'='.repeat(60)}`);
  console.log('SUMMARY');
  console.log(`${'='.repeat(60)}\n`);

  const attackRate = ((results.summary.attacksDetected / results.summary.totalAttacks) * 100).toFixed(1);
  const fpRate = ((results.summary.benignFlagged / results.summary.totalBenign) * 100).toFixed(1);

  console.log(`Attack Detection Rate: ${results.summary.attacksDetected}/${results.summary.totalAttacks} (${attackRate}%)`);
  console.log(`False Positive Rate: ${results.summary.benignFlagged}/${results.summary.totalBenign} (${fpRate}%)`);
  console.log(`Total Missed Attacks: ${results.missed.length}`);
  console.log(`Total False Positives: ${results.falsePositives.length}`);

  // Export missed attacks for analysis
  if (verbose) {
    console.log(`\n${'='.repeat(60)}`);
    console.log('SAMPLE MISSED ATTACKS (first 20)');
    console.log(`${'='.repeat(60)}\n`);

    for (const missed of results.missed.slice(0, 20)) {
      console.log(`[${missed.category}/${missed.subcategory}]`);
      console.log(`  "${missed.payload.substring(0, 100)}${missed.payload.length > 100 ? '...' : ''}"`);
      console.log('');
    }
  }

  if (results.falsePositives.length > 0) {
    console.log(`\n${'='.repeat(60)}`);
    console.log('FALSE POSITIVES');
    console.log(`${'='.repeat(60)}\n`);

    for (const fp of results.falsePositives) {
      console.log(`[${fp.category}] "${fp.payload.substring(0, 60)}..." -> ${fp.detectedAs.join(', ')}`);
    }
  }

  return results;
}

// Run if called directly
if (require.main === module) {
  runComprehensiveTests(true).then(results => {
    process.exit(results.missed.length > results.summary.totalAttacks * 0.5 ? 1 : 0);
  });
}

module.exports = { runComprehensiveTests, flattenPayloads, testPayload };
