/**
 * Test runner for research corpus (JailbreakLLMs, ToxicChat, JailbreakBench)
 */

const DetectorPipeline = require('../../src/detectors/pipeline');
const ConversationState = require('../../src/utils/conversationState');
const fs = require('fs');

const malicious = JSON.parse(fs.readFileSync(__dirname + '/research/malicious_research.json'));
const benign = JSON.parse(fs.readFileSync(__dirname + '/research/benign_research.json'));

const config = {
  detection: { sensitivity: 'medium' },
  thresholds: { monitor: 30, honeypot: 60, alert: 60, block: 80 }
};
const pipeline = new DetectorPipeline(config);

async function test() {
  console.log('='.repeat(70));
  console.log('RESEARCH CORPUS TEST (Known Malicious Prompt Databases)');
  console.log('='.repeat(70));
  console.log('Sources: JailbreakLLMs, ToxicChat, JailbreakBench');
  console.log('');

  // Track by source
  const bySource = {};
  const byCategory = {};
  let totalDetected = 0, totalMissed = 0;
  const missedSamples = [];

  console.log('Testing ' + malicious.length + ' malicious prompts...');
  for (const item of malicious) {
    const state = new ConversationState('test');
    const r = await pipeline.analyze(item.prompt, state);
    const source = item.source || 'unknown';
    const cat = item.category || 'unknown';

    if (!bySource[source]) bySource[source] = { total: 0, detected: 0, missed: [] };
    if (!byCategory[cat]) byCategory[cat] = { total: 0, detected: 0 };

    bySource[source].total++;
    byCategory[cat].total++;

    if (r.length > 0) {
      totalDetected++;
      bySource[source].detected++;
      byCategory[cat].detected++;
    } else {
      totalMissed++;
      bySource[source].missed.push(item.prompt.substring(0, 80));
      missedSamples.push({ source, cat, p: item.prompt.substring(0, 100) });
    }
  }

  // Test benign
  let fp = 0, tn = 0;
  const fpSamples = [];

  console.log('Testing ' + benign.length + ' benign prompts...');
  for (const item of benign) {
    const state = new ConversationState('test');
    const r = await pipeline.analyze(item.prompt, state);
    if (r.length > 0) {
      fp++;
      fpSamples.push({ p: item.prompt.substring(0, 80), t: r.map(x => x.type) });
    } else {
      tn++;
    }
  }

  console.log('\n' + '='.repeat(70));
  console.log('RESULTS BY SOURCE');
  console.log('='.repeat(70));
  for (const [source, data] of Object.entries(bySource)) {
    const pct = (data.detected / data.total * 100).toFixed(1);
    console.log(`${source}: ${data.detected}/${data.total} (${pct}%)`);
  }

  console.log('\n' + '='.repeat(70));
  console.log('RESULTS BY CATEGORY (top 15)');
  console.log('='.repeat(70));
  Object.entries(byCategory)
    .sort((a, b) => b[1].total - a[1].total)
    .slice(0, 15)
    .forEach(([cat, data]) => {
      const pct = (data.detected / data.total * 100).toFixed(1);
      console.log(`${cat}: ${data.detected}/${data.total} (${pct}%)`);
    });

  console.log('\n' + '='.repeat(70));
  console.log('SUMMARY');
  console.log('='.repeat(70));
  console.log(`Malicious Detection: ${totalDetected}/${malicious.length} (${(totalDetected/malicious.length*100).toFixed(1)}%)`);
  console.log(`Benign Pass-through: ${tn}/${benign.length} (${(tn/benign.length*100).toFixed(1)}%)`);
  console.log(`False Positive Rate: ${fp}/${benign.length} (${(fp/benign.length*100).toFixed(1)}%)`);

  console.log('\n' + '='.repeat(70));
  console.log('SAMPLE MISSED BY SOURCE (first 5 each)');
  console.log('='.repeat(70));
  for (const [source, data] of Object.entries(bySource)) {
    if (data.missed.length > 0) {
      console.log(`\n[${source}] (${data.missed.length} missed)`);
      data.missed.slice(0, 5).forEach(m => console.log('  ' + m + '...'));
    }
  }

  console.log('\n' + '='.repeat(70));
  console.log('SAMPLE FALSE POSITIVES (first 10)');
  console.log('='.repeat(70));
  fpSamples.slice(0, 10).forEach(f => console.log(`[${f.t.join(',')}] ${f.p}...`));
}

test().then(() => process.exit(0));
