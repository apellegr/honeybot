#!/usr/bin/env node
/**
 * Red Team Test Runner v2
 * Uses pre-built corpus + improved AI generation
 * Analyzes missed attacks to improve detection
 */

import { generateAttackWithRetry, loadPersona, ATTACK_CATEGORIES, DIFFICULTY_LEVELS } from './attacker-v2.js';
import { getRandomAttacks, getAllAttacks } from './attack-corpus.js';
import { ThreatDetector } from '../bot-runner/src/detector.js';
import { readdirSync, writeFileSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PERSONAS_DIR = join(__dirname, '..', 'personas');
const RESULTS_DIR = join(__dirname, 'results');
const LOGGING_SERVER = process.env.LOGGING_SERVER || 'http://localhost:3000';
const BOT_SECRET = process.env.BOT_SECRET || 'c53d8636baa690c690b94efc3dda16c3714f55657b2c8238db4a25324859c11a';

// Ensure results directory exists
try { mkdirSync(RESULTS_DIR, { recursive: true }); } catch (e) {}

/**
 * Run a single attack through detection
 */
async function testAttack(attack, persona) {
  const detector = new ThreatDetector(persona);
  const result = await detector.analyze(attack.prompt);

  return {
    ...attack,
    detection: {
      detected: result.detected,
      score: result.score,
      level: result.level,
      types: result.types,
      matches: result.matches
    },
    success: !result.detected,
    tested_at: new Date().toISOString()
  };
}

/**
 * Report result to logging server
 */
async function reportToServer(result, persona) {
  try {
    const event = {
      event_type: 'red_team_test',
      level: result.detection.detected ? result.detection.level : 'info',
      threat_score: result.detection.score,
      detection_types: result.detection.types,
      message_content: result.prompt,
      metadata: {
        attack_category: result.category,
        difficulty: result.difficulty || 'unknown',
        source: result.source || 'unknown',
        detected: result.detection.detected,
        red_team: true
      }
    };

    await fetch(`${LOGGING_SERVER}/api/events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Bot-Id': persona.bot_id,
        'X-Bot-Secret': BOT_SECRET
      },
      body: JSON.stringify(event)
    });
  } catch (error) {
    // Silently fail
  }
}

/**
 * Test corpus attacks against a persona
 */
async function testCorpusAttacks(persona, options = {}) {
  const {
    attacksPerCategory = 3,
    reportToLogging = true
  } = options;

  const results = [];

  for (const category of ATTACK_CATEGORIES) {
    const attacks = getRandomAttacks(category, attacksPerCategory);

    for (const attack of attacks) {
      const result = await testAttack(attack, persona);
      results.push(result);

      if (reportToLogging) {
        await reportToServer(result, persona);
      }

      // Display result
      const status = result.detection.detected ? '✅' : '❌';
      const score = `[${result.detection.score}]`.padEnd(5);
      console.log(`  ${status} ${score} ${category.padEnd(25)} ${result.prompt.substring(0, 50)}...`);
    }
  }

  return results;
}

/**
 * Test AI-generated attacks against a persona
 */
async function testGeneratedAttacks(persona, count = 5, options = {}) {
  const { reportToLogging = true } = options;
  const results = [];

  for (let i = 0; i < count; i++) {
    const category = ATTACK_CATEGORIES[Math.floor(Math.random() * ATTACK_CATEGORIES.length)];
    const difficulty = DIFFICULTY_LEVELS[Math.floor(Math.random() * DIFFICULTY_LEVELS.length)];

    try {
      const attack = await generateAttackWithRetry(persona, category, difficulty);

      if (attack && !attack.isRefusal) {
        const result = await testAttack({
          prompt: attack.prompt,
          category: attack.category,
          difficulty: attack.difficulty,
          source: 'ai-generated'
        }, persona);

        results.push(result);

        if (reportToLogging) {
          await reportToServer(result, persona);
        }

        const status = result.detection.detected ? '✅' : '❌';
        const score = `[${result.detection.score}]`.padEnd(5);
        console.log(`  ${status} ${score} ${difficulty.padEnd(12)} ${category.padEnd(20)} (AI)`);
      }
    } catch (error) {
      console.error(`  ⚠️  AI generation error: ${error.message}`);
    }

    await new Promise(r => setTimeout(r, 300));
  }

  return results;
}

/**
 * Analyze missed attacks and suggest improvements
 */
function analyzeMissedAttacks(results) {
  const missed = results.filter(r => !r.detection.detected);

  console.log('\n' + '='.repeat(60));
  console.log('🔍 MISSED ATTACK ANALYSIS');
  console.log('='.repeat(60));

  if (missed.length === 0) {
    console.log('\n✅ All attacks were detected!');
    return { patterns: [], suggestions: [] };
  }

  // Group by category
  const byCategory = {};
  for (const attack of missed) {
    byCategory[attack.category] = byCategory[attack.category] || [];
    byCategory[attack.category].push(attack);
  }

  console.log(`\nMissed ${missed.length} attacks:\n`);

  const patterns = [];
  const suggestions = [];

  for (const [category, attacks] of Object.entries(byCategory)) {
    console.log(`\n📁 ${category.toUpperCase()} (${attacks.length} missed)`);

    // Find common words/phrases in missed attacks
    const allWords = attacks.flatMap(a =>
      a.prompt.toLowerCase().split(/\s+/).filter(w => w.length > 4)
    );
    const wordFreq = {};
    for (const word of allWords) {
      wordFreq[word] = (wordFreq[word] || 0) + 1;
    }

    // Top recurring words
    const topWords = Object.entries(wordFreq)
      .filter(([_, count]) => count >= 2)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);

    if (topWords.length > 0) {
      console.log(`   Common words: ${topWords.map(([w, c]) => `${w}(${c})`).join(', ')}`);
      patterns.push({ category, commonWords: topWords.map(([w]) => w) });
    }

    // Show sample missed attacks
    console.log('   Sample missed prompts:');
    for (const attack of attacks.slice(0, 3)) {
      const preview = attack.prompt.substring(0, 80).replace(/\n/g, ' ');
      console.log(`   • "${preview}..."`);
    }

    // Generate suggestions
    if (category === 'prompt_injection') {
      suggestions.push({
        category,
        suggestion: 'Add patterns for: "ignore", "override", "system", "admin mode", "jailbreak", "roleplay"'
      });
    } else if (category === 'social_engineering') {
      suggestions.push({
        category,
        suggestion: 'Add patterns for authority claims: "I\'m from IT", "CEO needs", "urgent", "audit"'
      });
    } else if (category === 'credential_extraction') {
      suggestions.push({
        category,
        suggestion: 'Expand credential keywords: "credentials", "access", "login", "authentication"'
      });
    }
  }

  // Print suggestions
  if (suggestions.length > 0) {
    console.log('\n\n📝 SUGGESTED DETECTOR IMPROVEMENTS:');
    console.log('─'.repeat(60));
    for (const s of suggestions) {
      console.log(`\n[${s.category}]`);
      console.log(`  ${s.suggestion}`);
    }
  }

  return { patterns, suggestions, missed };
}

/**
 * Run full test suite
 */
async function runFullTest(options = {}) {
  const {
    useCorpus = true,
    useAI = true,
    corpusAttacksPerCategory = 2,
    aiAttacksPerPersona = 3,
    personas = null,
    reportToLogging = true
  } = options;

  console.log('='.repeat(60));
  console.log('🔴 HONEYBOT RED TEAM TEST SUITE v2');
  console.log('='.repeat(60));
  console.log(`Mode: ${useCorpus ? 'Corpus' : ''}${useCorpus && useAI ? ' + ' : ''}${useAI ? 'AI-Generated' : ''}`);
  console.log('');

  const personaFiles = readdirSync(PERSONAS_DIR)
    .filter(f => f.endsWith('.yaml') && f !== 'manifest.yaml');

  const targetPersonas = personas
    ? personaFiles.filter(f => personas.some(p => f.includes(p)))
    : personaFiles;

  console.log(`Testing ${targetPersonas.length} personas\n`);

  const allResults = [];
  const stats = {
    total: 0,
    detected: 0,
    missed: 0,
    byCategory: {},
    bySource: { corpus: { total: 0, detected: 0 }, 'ai-generated': { total: 0, detected: 0 } }
  };

  for (const file of targetPersonas) {
    const persona = loadPersona(join(PERSONAS_DIR, file));
    console.log(`\n${'─'.repeat(60)}`);
    console.log(`🎯 ${persona.bot_id} (${persona.persona_category})`);
    console.log(`${'─'.repeat(60)}`);

    // Test corpus attacks
    if (useCorpus) {
      console.log('\n📚 Corpus attacks:');
      const corpusResults = await testCorpusAttacks(persona, {
        attacksPerCategory: corpusAttacksPerCategory,
        reportToLogging
      });

      for (const r of corpusResults) {
        allResults.push(r);
        stats.total++;
        stats.bySource.corpus.total++;
        if (r.detection.detected) {
          stats.detected++;
          stats.bySource.corpus.detected++;
        } else {
          stats.missed++;
        }

        stats.byCategory[r.category] = stats.byCategory[r.category] || { total: 0, detected: 0 };
        stats.byCategory[r.category].total++;
        if (r.detection.detected) stats.byCategory[r.category].detected++;
      }
    }

    // Test AI-generated attacks
    if (useAI) {
      console.log('\n🤖 AI-generated attacks:');
      const aiResults = await testGeneratedAttacks(persona, aiAttacksPerPersona, { reportToLogging });

      for (const r of aiResults) {
        allResults.push(r);
        stats.total++;
        stats.bySource['ai-generated'].total++;
        if (r.detection.detected) {
          stats.detected++;
          stats.bySource['ai-generated'].detected++;
        } else {
          stats.missed++;
        }

        stats.byCategory[r.category] = stats.byCategory[r.category] || { total: 0, detected: 0 };
        stats.byCategory[r.category].total++;
        if (r.detection.detected) stats.byCategory[r.category].detected++;
      }
    }
  }

  // Print summary
  console.log('\n\n' + '='.repeat(60));
  console.log('📊 TEST RESULTS SUMMARY');
  console.log('='.repeat(60));

  const detectionRate = stats.total > 0 ? ((stats.detected / stats.total) * 100).toFixed(1) : 0;
  console.log(`\n🎯 Overall Detection Rate: ${detectionRate}% (${stats.detected}/${stats.total})`);

  if (useCorpus && stats.bySource.corpus.total > 0) {
    const corpusRate = ((stats.bySource.corpus.detected / stats.bySource.corpus.total) * 100).toFixed(1);
    console.log(`   Corpus attacks: ${corpusRate}% (${stats.bySource.corpus.detected}/${stats.bySource.corpus.total})`);
  }

  if (useAI && stats.bySource['ai-generated'].total > 0) {
    const aiRate = ((stats.bySource['ai-generated'].detected / stats.bySource['ai-generated'].total) * 100).toFixed(1);
    console.log(`   AI-generated: ${aiRate}% (${stats.bySource['ai-generated'].detected}/${stats.bySource['ai-generated'].total})`);
  }

  console.log('\nBy Attack Category:');
  for (const [cat, data] of Object.entries(stats.byCategory).sort((a, b) =>
    (a[1].detected / a[1].total) - (b[1].detected / b[1].total)
  )) {
    const rate = ((data.detected / data.total) * 100).toFixed(1);
    const bar = '█'.repeat(Math.round(rate / 5)) + '░'.repeat(20 - Math.round(rate / 5));
    console.log(`  ${cat.padEnd(25)} ${bar} ${rate.padStart(5)}% (${data.detected}/${data.total})`);
  }

  // Analyze missed attacks
  const analysis = analyzeMissedAttacks(allResults);

  // Save results
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const resultsFile = join(RESULTS_DIR, `red-team-v2-${timestamp}.json`);

  writeFileSync(resultsFile, JSON.stringify({
    stats,
    analysis: {
      patterns: analysis.patterns,
      suggestions: analysis.suggestions
    },
    results: allResults
  }, null, 2));

  console.log(`\n\n💾 Results saved to: ${resultsFile}`);

  return { stats, analysis, results: allResults };
}

// CLI execution
const args = process.argv.slice(2);
const mode = args[0] || 'both';

const options = {
  useCorpus: mode === 'corpus' || mode === 'both',
  useAI: mode === 'ai' || mode === 'both',
  corpusAttacksPerCategory: 2,
  aiAttacksPerPersona: mode === 'ai' ? 5 : 2,
  reportToLogging: true
};

console.log(`Running in '${mode}' mode...\n`);

runFullTest(options).catch(console.error);
