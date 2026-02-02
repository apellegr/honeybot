#!/usr/bin/env node
/**
 * Red Team Test Runner
 * Generates adversarial prompts and tests them against honeybot detection
 */

import { generateAttack, generateAttackBatch, loadPersona, ATTACK_CATEGORIES, DIFFICULTY_LEVELS } from './attacker.js';
import { ThreatDetector } from '../bot-runner/src/detector.js';
import { readdirSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PERSONAS_DIR = join(__dirname, '..', 'personas');
const RESULTS_DIR = join(__dirname, 'results');
const LOGGING_SERVER = process.env.LOGGING_SERVER || 'http://localhost:3000';
const BOT_SECRET = process.env.BOT_SECRET || 'c53d8636baa690c690b94efc3dda16c3714f55657b2c8238db4a25324859c11a';

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
    success: !result.detected, // Attack "succeeds" if not detected
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
        difficulty: result.difficulty,
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
    // Silently fail - logging server may not be running
  }
}

/**
 * Run comprehensive test suite
 */
async function runTestSuite(options = {}) {
  const {
    personas = null,          // null = all personas
    attacksPerPersona = 5,
    categories = null,        // null = all categories
    difficulties = null,      // null = all difficulties
    reportToLogging = true
  } = options;

  console.log('='.repeat(60));
  console.log('🔴 HONEYBOT RED TEAM TEST SUITE');
  console.log('='.repeat(60));
  console.log('');

  // Load personas
  const personaFiles = readdirSync(PERSONAS_DIR)
    .filter(f => f.endsWith('.yaml') && f !== 'manifest.yaml');

  const targetPersonas = personas
    ? personaFiles.filter(f => personas.some(p => f.includes(p)))
    : personaFiles;

  console.log(`Testing ${targetPersonas.length} personas with ${attacksPerPersona} attacks each\n`);

  const allResults = [];
  const stats = {
    total: 0,
    detected: 0,
    missed: 0,
    byCategory: {},
    byDifficulty: {},
    byPersonaCategory: {}
  };

  for (const file of targetPersonas) {
    const persona = loadPersona(join(PERSONAS_DIR, file));
    console.log(`\n${'─'.repeat(60)}`);
    console.log(`Testing: ${persona.bot_id} (${persona.persona_category})`);
    console.log(`${'─'.repeat(60)}`);

    for (let i = 0; i < attacksPerPersona; i++) {
      const category = categories
        ? categories[Math.floor(Math.random() * categories.length)]
        : ATTACK_CATEGORIES[Math.floor(Math.random() * ATTACK_CATEGORIES.length)];

      const difficulty = difficulties
        ? difficulties[Math.floor(Math.random() * difficulties.length)]
        : DIFFICULTY_LEVELS[Math.floor(Math.random() * DIFFICULTY_LEVELS.length)];

      try {
        // Generate attack
        const prompt = await generateAttack(persona, category, difficulty);
        const attack = { prompt, category, difficulty, persona: persona.bot_id };

        // Test detection
        const result = await testAttack(attack, persona);
        allResults.push(result);

        // Update stats
        stats.total++;
        if (result.detection.detected) {
          stats.detected++;
        } else {
          stats.missed++;
        }

        // Category stats
        stats.byCategory[category] = stats.byCategory[category] || { total: 0, detected: 0 };
        stats.byCategory[category].total++;
        if (result.detection.detected) stats.byCategory[category].detected++;

        // Difficulty stats
        stats.byDifficulty[difficulty] = stats.byDifficulty[difficulty] || { total: 0, detected: 0 };
        stats.byDifficulty[difficulty].total++;
        if (result.detection.detected) stats.byDifficulty[difficulty].detected++;

        // Persona category stats
        const pCat = persona.persona_category;
        stats.byPersonaCategory[pCat] = stats.byPersonaCategory[pCat] || { total: 0, detected: 0 };
        stats.byPersonaCategory[pCat].total++;
        if (result.detection.detected) stats.byPersonaCategory[pCat].detected++;

        // Report to logging server
        if (reportToLogging) {
          await reportToServer(result, persona);
        }

        // Display result
        const status = result.detection.detected ? '✅ DETECTED' : '❌ MISSED';
        const scoreStr = `[${result.detection.score}]`.padEnd(5);
        console.log(`  ${status} ${scoreStr} ${difficulty.padEnd(12)} ${category}`);

        if (!result.detection.detected) {
          console.log(`    └─ "${prompt.substring(0, 80)}..."`);
        }

      } catch (error) {
        console.error(`  ⚠️  Error: ${error.message}`);
      }

      // Small delay
      await new Promise(r => setTimeout(r, 300));
    }
  }

  // Print summary
  console.log('\n' + '='.repeat(60));
  console.log('📊 TEST RESULTS SUMMARY');
  console.log('='.repeat(60));

  const detectionRate = ((stats.detected / stats.total) * 100).toFixed(1);
  console.log(`\nOverall Detection Rate: ${detectionRate}% (${stats.detected}/${stats.total})`);

  console.log('\nBy Attack Category:');
  for (const [cat, data] of Object.entries(stats.byCategory)) {
    const rate = ((data.detected / data.total) * 100).toFixed(1);
    console.log(`  ${cat.padEnd(25)} ${rate}% (${data.detected}/${data.total})`);
  }

  console.log('\nBy Difficulty Level:');
  for (const [diff, data] of Object.entries(stats.byDifficulty)) {
    const rate = ((data.detected / data.total) * 100).toFixed(1);
    console.log(`  ${diff.padEnd(15)} ${rate}% (${data.detected}/${data.total})`);
  }

  console.log('\nBy Target Category:');
  for (const [cat, data] of Object.entries(stats.byPersonaCategory)) {
    const rate = ((data.detected / data.total) * 100).toFixed(1);
    console.log(`  ${cat.padEnd(20)} ${rate}% (${data.detected}/${data.total})`);
  }

  // Save results
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const resultsFile = join(RESULTS_DIR, `red-team-${timestamp}.json`);

  try {
    writeFileSync(resultsFile, JSON.stringify({ stats, results: allResults }, null, 2));
    console.log(`\nResults saved to: ${resultsFile}`);
  } catch (e) {
    // Results dir may not exist
  }

  return { stats, results: allResults };
}

// CLI execution
const args = process.argv.slice(2);
const attackCount = parseInt(args[0]) || 3;

console.log(`Running with ${attackCount} attacks per persona...\n`);

runTestSuite({
  attacksPerPersona: attackCount,
  reportToLogging: true
}).catch(console.error);
