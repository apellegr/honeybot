#!/usr/bin/env node
/**
 * Test a single bot locally
 * Usage: node test-bot.js <persona-file>
 */

import { readFileSync } from 'fs';
import { parse as parseYaml } from 'yaml';

const personaFile = process.argv[2];

if (!personaFile) {
  console.log('Usage: node test-bot.js <persona-file>');
  console.log('Example: node test-bot.js ../personas/dev-01.yaml');
  process.exit(1);
}

// Set environment variables for the bot
process.env.BOT_ID = 'test-bot';
process.env.PERSONA_FILE = personaFile;
process.env.POLL_INTERVAL = '30000'; // 30 seconds for testing
process.env.POST_INTERVAL = '300000'; // 5 minutes for testing

// Don't connect to central logging for local test
delete process.env.CENTRAL_LOGGING_URL;

console.log('Loading persona:', personaFile);
const content = readFileSync(personaFile, 'utf-8');
const persona = parseYaml(content);
console.log('Persona:', persona.personality?.name, '-', persona.persona_category);
console.log('');

// Import and run the bot
import('../bot-runner/src/index.js');
