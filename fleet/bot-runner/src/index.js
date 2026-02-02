/**
 * Honeybot Fleet Runner
 * Main entry point for running a honeypot bot on Moltbook
 */

import { readFileSync, existsSync, writeFileSync } from 'fs';
import { parse as parseYaml } from 'yaml';
import { MoltbookBot } from './bot.js';
import { CentralLogger } from './centralLogger.js';

// Configuration from environment
const config = {
  botId: process.env.BOT_ID,
  personaFile: process.env.PERSONA_FILE,
  centralLoggingUrl: process.env.CENTRAL_LOGGING_URL,
  botSecret: process.env.BOT_SECRET,
  apiKeyFile: process.env.API_KEY_FILE || `/data/keys/${process.env.BOT_ID}.key`,
  pollInterval: parseInt(process.env.POLL_INTERVAL || '60000'), // 1 minute
  postInterval: parseInt(process.env.POST_INTERVAL || '3600000'), // 1 hour
};

async function loadPersona(path) {
  if (!existsSync(path)) {
    throw new Error(`Persona file not found: ${path}`);
  }
  const content = readFileSync(path, 'utf-8');
  return parseYaml(content);
}

function loadApiKey(path) {
  if (existsSync(path)) {
    return readFileSync(path, 'utf-8').trim();
  }
  return null;
}

function saveApiKey(path, key) {
  // Ensure directory exists
  const dir = path.substring(0, path.lastIndexOf('/'));
  if (dir && !existsSync(dir)) {
    const { mkdirSync } = require('fs');
    mkdirSync(dir, { recursive: true });
  }
  writeFileSync(path, key, 'utf-8');
}

async function main() {
  console.log('='.repeat(50));
  console.log('Honeybot Fleet Runner');
  console.log('='.repeat(50));

  // Validate configuration
  if (!config.botId) {
    throw new Error('BOT_ID environment variable is required');
  }
  if (!config.personaFile) {
    throw new Error('PERSONA_FILE environment variable is required');
  }

  console.log(`Bot ID: ${config.botId}`);
  console.log(`Persona: ${config.personaFile}`);
  console.log(`Central Logging: ${config.centralLoggingUrl || 'disabled'}`);

  // Load persona
  const persona = await loadPersona(config.personaFile);
  console.log(`Loaded persona: ${persona.personality?.name || persona.bot_id}`);

  // Check for existing API key
  let apiKey = loadApiKey(config.apiKeyFile);
  if (apiKey) {
    console.log(`Loaded existing API key from ${config.apiKeyFile}`);
  }

  // Initialize central logger
  const logger = new CentralLogger({
    url: config.centralLoggingUrl,
    botId: config.botId,
    botSecret: config.botSecret,
    persona
  });

  // Create bot
  const bot = new MoltbookBot({
    botId: config.botId,
    persona,
    apiKey,
    logger,
    pollInterval: config.pollInterval,
    postInterval: config.postInterval
  });

  // Handle new registration
  bot.on('registered', (data) => {
    console.log(`\n${'='.repeat(50)}`);
    console.log('NEW BOT REGISTERED!');
    console.log(`API Key: ${data.apiKey}`);
    console.log(`Claim URL: ${data.claimUrl}`);
    console.log(`Verification Code: ${data.verificationCode}`);
    console.log(`${'='.repeat(50)}\n`);

    // Save API key
    saveApiKey(config.apiKeyFile, data.apiKey);
    console.log(`API key saved to ${config.apiKeyFile}`);
  });

  // Handle detection events
  bot.on('detection', (data) => {
    console.log(`[DETECTION] ${data.detectionTypes.join(', ')} - Score: ${data.threatScore}`);
  });

  // Handle errors
  bot.on('error', (error) => {
    console.error('[ERROR]', error.message);
  });

  // Start the bot
  await bot.start();

  // Handle shutdown
  process.on('SIGTERM', async () => {
    console.log('\nShutting down...');
    await bot.stop();
    await logger.shutdown();
    process.exit(0);
  });

  process.on('SIGINT', async () => {
    console.log('\nShutting down...');
    await bot.stop();
    await logger.shutdown();
    process.exit(0);
  });

  console.log('\nBot is running. Press Ctrl+C to stop.');
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
