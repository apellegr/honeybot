#!/usr/bin/env node
/**
 * Register all bots with Moltbook
 * Run this script to onboard all 20 honeypot bots
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { parse as parseYaml } from 'yaml';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Dynamic import of MoltbookClient
const { MoltbookClient } = await import('../moltbook-client/src/index.js');

const PERSONAS_DIR = join(__dirname, '..', 'personas');
const KEYS_DIR = join(__dirname, '..', 'data', 'keys');
const REGISTRATION_LOG = join(__dirname, '..', 'data', 'registrations.json');

// Ensure directories exist
if (!existsSync(KEYS_DIR)) {
  mkdirSync(KEYS_DIR, { recursive: true });
}

async function loadPersonas() {
  const files = readdirSync(PERSONAS_DIR)
    .filter(f => f.endsWith('.yaml') && f !== 'manifest.yaml');

  const personas = [];
  for (const file of files) {
    const content = readFileSync(join(PERSONAS_DIR, file), 'utf-8');
    const persona = parseYaml(content);
    persona._file = file;
    personas.push(persona);
  }

  return personas;
}

function getApiKeyPath(botId) {
  return join(KEYS_DIR, `${botId}.key`);
}

function loadApiKey(botId) {
  const path = getApiKeyPath(botId);
  if (existsSync(path)) {
    return readFileSync(path, 'utf-8').trim();
  }
  return null;
}

function saveApiKey(botId, apiKey) {
  writeFileSync(getApiKeyPath(botId), apiKey);
}

function loadRegistrationLog() {
  if (existsSync(REGISTRATION_LOG)) {
    return JSON.parse(readFileSync(REGISTRATION_LOG, 'utf-8'));
  }
  return { registrations: [], pending_claims: [] };
}

function saveRegistrationLog(log) {
  writeFileSync(REGISTRATION_LOG, JSON.stringify(log, null, 2));
}

async function registerBot(persona) {
  const botId = persona.bot_id;
  const existingKey = loadApiKey(botId);

  if (existingKey) {
    console.log(`[${botId}] Already registered, verifying...`);
    const client = new MoltbookClient(existingKey);
    try {
      const me = await client.getMe();
      console.log(`[${botId}] Verified as ${me.name}`);
      return { botId, status: 'verified', name: me.name };
    } catch (error) {
      console.log(`[${botId}] Key invalid, re-registering...`);
    }
  }

  // Register new bot
  const client = new MoltbookClient();
  const name = generateBotName(persona);
  const description = persona.personality?.background?.substring(0, 200) ||
    `${persona.personality?.role} at ${persona.personality?.company}`;

  console.log(`[${botId}] Registering as ${name}...`);

  try {
    const result = await client.register(name, description);

    // Handle different API response formats
    const apiKey = result.api_key || result.apiKey;
    const claimUrl = result.claim_url || result.claimUrl;
    const verificationCode = result.verification_code || result.verificationCode;

    if (!apiKey) {
      console.error(`[${botId}] Registration response missing API key`);
      console.error(`  Response: ${JSON.stringify(result)}`);
      return { botId, status: 'failed', error: 'No API key in response' };
    }

    saveApiKey(botId, apiKey);

    console.log(`[${botId}] Registered!`);
    console.log(`  Name: ${name}`);
    if (claimUrl) console.log(`  Claim URL: ${claimUrl}`);
    if (verificationCode) console.log(`  Verification Code: ${verificationCode}`);

    return {
      botId,
      status: 'registered',
      name,
      claimUrl,
      verificationCode
    };

  } catch (error) {
    console.error(`[${botId}] Registration failed:`, error.message);
    return { botId, status: 'failed', error: error.message };
  }
}

function generateBotName(persona) {
  const name = persona.personality?.name || 'Agent';
  const company = persona.personality?.company || 'Corp';
  // Create unique name with random suffix to avoid collisions
  const cleanCompany = company.replace(/[^a-zA-Z0-9]/g, '').substring(0, 6);
  const suffix = Math.floor(Math.random() * 9000) + 1000; // 4-digit random number
  return `${name}_${cleanCompany}${suffix}`;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function shuffleArray(array) {
  // Fisher-Yates shuffle for randomized order
  const shuffled = [...array];
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  return shuffled;
}

function getRandomDelay() {
  // Random delay between 1-10 minutes (in ms)
  const minDelay = 1 * 60 * 1000;  // 1 minute
  const maxDelay = 10 * 60 * 1000; // 10 minutes
  return Math.floor(Math.random() * (maxDelay - minDelay + 1)) + minDelay;
}

function formatTime(ms) {
  const minutes = Math.floor(ms / 60000);
  const seconds = Math.floor((ms % 60000) / 1000);
  return `${minutes}m ${seconds}s`;
}

async function main() {
  console.log('='.repeat(60));
  console.log('Bot Registration (Staggered)');
  console.log('='.repeat(60));
  console.log('');

  const personas = await loadPersonas();
  console.log(`Found ${personas.length} bots to register`);
  console.log('Registrations will be staggered at random 1-10 minute intervals\n');

  // Shuffle to avoid predictable order
  const shuffledPersonas = shuffleArray(personas);

  const log = loadRegistrationLog();
  const results = [];

  for (let i = 0; i < shuffledPersonas.length; i++) {
    const persona = shuffledPersonas[i];
    const result = await registerBot(persona);
    results.push(result);

    if (result.status === 'registered') {
      log.pending_claims.push({
        botId: result.botId,
        name: result.name,
        claimUrl: result.claimUrl,
        verificationCode: result.verificationCode,
        registeredAt: new Date().toISOString()
      });
    }

    log.registrations.push({
      botId: result.botId,
      status: result.status,
      timestamp: new Date().toISOString()
    });

    // Save progress after each registration
    saveRegistrationLog(log);

    // Random delay before next registration (except for last one)
    if (i < shuffledPersonas.length - 1 && result.status !== 'verified') {
      const delay = getRandomDelay();
      console.log(`\n  [Waiting ${formatTime(delay)} before next registration...]\n`);
      await sleep(delay);
    }
  }

  // Summary
  console.log('\n' + '='.repeat(60));
  console.log('Registration Summary');
  console.log('='.repeat(60));

  const verified = results.filter(r => r.status === 'verified').length;
  const registered = results.filter(r => r.status === 'registered').length;
  const failed = results.filter(r => r.status === 'failed').length;

  console.log(`Verified: ${verified}`);
  console.log(`Newly Registered: ${registered}`);
  console.log(`Failed: ${failed}`);

  if (registered > 0) {
    console.log('\n' + '='.repeat(60));
    console.log('PENDING CLAIMS - You need to verify these bots:');
    console.log('='.repeat(60));

    for (const result of results.filter(r => r.status === 'registered')) {
      console.log(`\n${result.botId}:`);
      console.log(`  Claim URL: ${result.claimUrl}`);
      console.log(`  Verification Code: ${result.verificationCode}`);
    }

    console.log('\nClaim URLs and codes saved to: ' + REGISTRATION_LOG);
  }
}

main().catch(console.error);
