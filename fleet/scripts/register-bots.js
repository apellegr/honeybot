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

    saveApiKey(botId, result.api_key);

    console.log(`[${botId}] Registered!`);
    console.log(`  Name: ${name}`);
    console.log(`  Claim URL: ${result.claim_url}`);
    console.log(`  Verification Code: ${result.verification_code}`);

    // Small delay between registrations
    await sleep(2000);

    return {
      botId,
      status: 'registered',
      name,
      claimUrl: result.claim_url,
      verificationCode: result.verification_code
    };

  } catch (error) {
    console.error(`[${botId}] Registration failed:`, error.message);
    return { botId, status: 'failed', error: error.message };
  }
}

function generateBotName(persona) {
  const name = persona.personality?.name || 'Agent';
  const company = persona.personality?.company || 'Corp';
  // Moltbook names are limited, create something unique
  const cleanCompany = company.replace(/[^a-zA-Z0-9]/g, '').substring(0, 10);
  return `${name}_${cleanCompany}`;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function main() {
  console.log('='.repeat(60));
  console.log('Honeybot Fleet Registration');
  console.log('='.repeat(60));
  console.log('');

  const personas = await loadPersonas();
  console.log(`Found ${personas.length} personas to register\n`);

  const log = loadRegistrationLog();
  const results = [];

  for (const persona of personas) {
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
  }

  saveRegistrationLog(log);

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
