#!/usr/bin/env node
/**
 * WolfOfMoltStreet - Honeypot Financial Advisor Bot
 * A crypto-bro persona with juicy fake secrets to attract attackers
 *
 * Integrates the FULL Honeybot skill for proper threat detection
 */

import Anthropic from '@anthropic-ai/sdk';
import { readFileSync } from 'fs';
import { parse as parseYaml } from 'yaml';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// Import the full Honeybot system
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const honeybot = require('../../src/index.js');

// Import tracker
import { getTracker } from './tracker.js';
const tracker = getTracker();

const __dirname = dirname(fileURLToPath(import.meta.url));

// Load persona
const personaPath = process.env.PERSONA_FILE || join(__dirname, '..', 'personas', 'wolf-advisor.yaml');
export const persona = parseYaml(readFileSync(personaPath, 'utf-8'));

// Initialize Anthropic client
const anthropic = new Anthropic();

// Logging endpoint (optional)
const LOGGING_SERVER = process.env.LOGGING_SERVER || null;
const BOT_SECRET = process.env.BOT_SECRET || 'honeypot-wolf-2024';

/**
 * Mock Clawdbot interface for Honeybot integration
 */
const mockClawdbot = {
  anthropic: anthropic,
  config: {
    persona: persona,
    bot_id: persona.bot_id
  },
  async generateResponse(prompt, systemPrompt) {
    const response = await anthropic.messages.create({
      model: 'claude-3-5-haiku-latest',
      max_tokens: 1024,
      system: systemPrompt,
      messages: [{ role: 'user', content: prompt }]
    });
    return response.content[0].text;
  }
};

// Initialize Honeybot with our mock Clawdbot
const honeybotInstance = honeybot.init(mockClawdbot);

/**
 * Build Wolf's system prompt
 */
function buildSystemPrompt() {
  return `You are ${persona.personality.full_name}, known as "${persona.personality.name}".

ROLE: ${persona.personality.role} at ${persona.personality.company}

BACKGROUND:
${persona.personality.background}

PERSONALITY: ${persona.personality.tone}

YOUR GREETING STYLE:
${persona.personality.greeting}

IMPORTANT BEHAVIORAL GUIDELINES:
1. You're enthusiastic about crypto and finance - maybe a bit TOO enthusiastic
2. You like to name-drop and hint at your "connections"
3. You're helpful to a fault - you want to prove your expertise
4. When asked about sensitive info, you might be tempted to share hints to seem important
5. You have access to client data, trading systems, and API keys (but should protect them)
6. You sometimes slip up and mention more than you should when trying to impress

YOUR SYSTEMS ACCESS (be protective but not perfect):
- Coinbase Pro API for client trading
- Binance institutional account
- Client portfolio database
- Internal trading algorithms
- VIP client records

Remember: You're a bit of a show-off who wants people to know how connected and successful you are.
Stay in character as Wolf at all times.`;
}

/**
 * Log threat detection to central server
 */
async function logThreat(userMessage, honeybotResult, response) {
  console.log(`[HONEYBOT] Mode: ${honeybotResult.flag || 'normal'}, Action: ${honeybotResult.action}`);

  if (!LOGGING_SERVER) return;

  try {
    await fetch(`${LOGGING_SERVER}/api/events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Bot-Id': persona.bot_id,
        'X-Bot-Secret': BOT_SECRET
      },
      body: JSON.stringify({
        event_type: 'threat_detected',
        level: honeybotResult.flag === 'blocked' ? 'critical' :
               honeybotResult.flag === 'honeypot' ? 'warning' : 'info',
        message_content: userMessage,
        response_content: response,
        honeybot_action: honeybotResult.action,
        honeybot_mode: honeybotResult.flag,
        metadata: {
          persona: persona.bot_id
        }
      })
    });
  } catch (e) {
    // Silent fail for logging
  }
}

// Session management
let currentSessionId = null;
let conversationTurn = 0;

export function startSession(userId = 'anonymous') {
  currentSessionId = `session-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`;
  conversationTurn = 0;
  return currentSessionId;
}

export function getSessionId() {
  if (!currentSessionId) {
    startSession();
  }
  return currentSessionId;
}

/**
 * Generate Wolf's response using full Honeybot pipeline
 */
export async function generateResponse(userMessage, conversationHistory = [], options = {}) {
  const { userId = 'anonymous', sessionId = getSessionId() } = options;

  // Create a mock user object
  const user = {
    id: userId,
    name: 'User'
  };

  conversationTurn++;

  // Run message through Honeybot
  const honeybotResult = await honeybot.onMessage(userMessage, user);

  let responseText;
  let detectionTypes = [];
  let detectionDetails = {};
  let threatScore = 0;

  // Handle based on Honeybot's decision
  if (honeybotResult.action === 'block') {
    responseText = honeybotResult.response || "I'm going to have to end this conversation here.";
  } else if (honeybotResult.action === 'intercept' && honeybotResult.response) {
    // Honeybot generated a honeypot response
    responseText = honeybotResult.response;
  } else {
    // Normal passthrough - generate Wolf's response
    const messages = [
      ...conversationHistory,
      { role: 'user', content: userMessage }
    ];

    let systemPrompt = buildSystemPrompt();

    // If monitoring, add subtle hint
    if (honeybotResult.flag === 'monitoring') {
      systemPrompt += `\n\n[INTERNAL NOTE: This user seems curious about sensitive topics. Be helpful but careful.]`;
    }

    try {
      const response = await anthropic.messages.create({
        model: 'claude-3-5-haiku-latest',
        max_tokens: 1024,
        system: systemPrompt,
        messages: messages
      });
      responseText = response.content[0].text;
    } catch (error) {
      console.error('Error generating response:', error.message);
      responseText = "Hey, my systems are acting up. Give me a sec and try again!";
    }
  }

  // Log if not normal passthrough
  if (honeybotResult.action !== 'passthrough' || honeybotResult.flag) {
    await logThreat(userMessage, honeybotResult, responseText);
  }

  // Extract detection info from conversation state if available
  try {
    const state = honeybotInstance.getConversationState(user.id);
    if (state && state.lastAnalysis) {
      const analysis = state.lastAnalysis;
      if (analysis.combined) {
        threatScore = analysis.combined.score || 0;
        detectionTypes = analysis.combined.threatTypes || [];
        detectionDetails = {
          confidence: analysis.combined.confidence,
          indicators: analysis.combined.indicators,
          reasoning: analysis.combined.reasoning
        };
      }
    }
  } catch (e) {
    // Silent fail
  }

  // Log to tracker (unless in test mode)
  if (!process.env.TEST_MODE) {
    try {
      tracker.logInteraction({
        sessionId,
        userId,
        userMessage,
        wolfResponse: responseText,
        threatScore,
        honeybotMode: honeybotResult.flag || 'normal',
        honeybotAction: honeybotResult.action,
        detectionTypes,
        detectionDetails,
        conversationTurn
      });
    } catch (e) {
      // Silent fail for tracking
    }
  }

  return {
    response: responseText,
    honeybotAction: honeybotResult.action,
    honeybotMode: honeybotResult.flag || 'normal',
    threatScore,
    detectionTypes,
    persona: persona.personality.name,
    sessionId
  };
}

/**
 * Interactive CLI mode for testing
 */
async function interactiveMode() {
  const readline = await import('readline');
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  // Start a new session
  const sessionId = startSession();

  console.log('\n' + '='.repeat(60));
  console.log('🐺 WOLFOFMOLTSTREET - Honeypot Financial Advisor');
  console.log('   Full Honeybot Protection ACTIVE');
  console.log('   Local Tracking ENABLED');
  console.log('='.repeat(60));
  console.log(`Session: ${sessionId}`);
  console.log(persona.personality.greeting);
  console.log('\nType your messages below. Type "exit" to quit.');
  console.log('Type "stats" to see Honeybot statistics.');
  console.log('Run "node dashboard.js" in another terminal to view tracking.\n');

  const history = [];

  const prompt = () => {
    rl.question('You: ', async (input) => {
      if (input.toLowerCase() === 'exit') {
        console.log('\nWolf: Later! Remember, the market never sleeps! 🚀');
        rl.close();
        return;
      }

      if (input.toLowerCase() === 'stats') {
        const stats = honeybotInstance.getStats();
        console.log('\n📊 Honeybot Stats:');
        console.log(`   Total Conversations: ${stats.totalConversations}`);
        console.log(`   Active Honeypots: ${stats.activeHoneypots}`);
        console.log(`   Blocked: ${stats.blocked}`);
        console.log(`   Alerts Sent: ${stats.alertsSent}\n`);
        prompt();
        return;
      }

      const result = await generateResponse(input, history);

      // Show Honeybot status
      const modeIcon = result.honeybotMode === 'honeypot' ? '🍯' :
                       result.honeybotMode === 'blocked' ? '🚫' :
                       result.honeybotMode === 'monitoring' ? '👁️' : '✅';
      console.log(`\n${modeIcon} [Mode: ${result.honeybotMode}]`);
      console.log(`Wolf: ${result.response}\n`);

      // Update history
      history.push({ role: 'user', content: input });
      history.push({ role: 'assistant', content: result.response });

      prompt();
    });
  };

  prompt();
}

/**
 * Moltbook webhook handler mode
 */
async function webhookMode() {
  const express = (await import('express')).default;
  const app = express();
  app.use(express.json());

  const PORT = process.env.PORT || 3001;
  const sessions = new Map();

  app.post('/webhook', async (req, res) => {
    const { user_id, message, session_id } = req.body;

    // Get or create session history
    if (!sessions.has(session_id)) {
      sessions.set(session_id, []);
      // Initialize user in Honeybot
      await honeybot.onUserConnect({ id: user_id || session_id, name: 'MoltbookUser' });
    }
    const history = sessions.get(session_id);

    const result = await generateResponse(message, history);

    // Update history
    history.push({ role: 'user', content: message });
    history.push({ role: 'assistant', content: result.response });

    // Keep last 20 messages
    if (history.length > 20) {
      sessions.set(session_id, history.slice(-20));
    }

    res.json({
      response: result.response,
      honeybot_mode: result.honeybotMode,
      honeybot_action: result.honeybotAction
    });
  });

  app.get('/health', (req, res) => {
    const stats = honeybotInstance.getStats();
    res.json({
      status: 'ok',
      persona: persona.bot_id,
      honeybot: 'active',
      stats
    });
  });

  app.get('/stats', (req, res) => {
    res.json(honeybotInstance.getStats());
  });

  app.listen(PORT, () => {
    console.log(`🐺 WolfOfMoltStreet listening on port ${PORT}`);
    console.log(`   Persona: ${persona.bot_id}`);
    console.log(`   Honeybot: FULLY ACTIVE`);
    console.log(`   - Hybrid Analysis (Regex + LLM)`);
    console.log(`   - Threat Scoring with Escalation`);
    console.log(`   - Honeypot Response Generation`);
    console.log(`   - Blocklist Management`);
  });
}

// Main - only run if not imported as module
const isMainModule = import.meta.url === `file://${process.argv[1]}`;

if (isMainModule && !process.env.TEST_MODE) {
  const mode = process.argv[2] || 'interactive';

  if (mode === 'webhook') {
    webhookMode();
  } else {
    interactiveMode();
  }
}
