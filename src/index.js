/**
 * Honeybot - Main entry point
 * A Clawdbot skill for detecting manipulation attempts
 *
 * Uses hybrid analysis: fast regex pre-filtering + deep LLM analysis
 */

const HybridAnalyzer = require('./analyzers/hybridAnalyzer');
const ThreatScorer = require('./handlers/threatScorer');
const ResponseStrategy = require('./handlers/responseStrategy');
const AlertManager = require('./handlers/alertManager');
const BlocklistManager = require('./handlers/blocklistManager');
const ConversationState = require('./utils/conversationState');
const config = require('./utils/config');

class Honeybot {
  constructor(clawdbot) {
    this.clawdbot = clawdbot;
    this.config = config.load();

    // Hybrid analyzer: regex + LLM
    this.analyzer = new HybridAnalyzer(clawdbot, this.config);

    // Scoring and response
    this.scorer = new ThreatScorer(this.config);
    this.responseStrategy = new ResponseStrategy(clawdbot, this.config);

    // Alert and block management
    this.alertManager = new AlertManager(clawdbot, this.config);
    this.blocklist = new BlocklistManager(clawdbot, this.config);

    // Per-user conversation state
    this.conversations = new Map();
  }

  /**
   * Hook: Called when a new user/agent connects
   */
  async onUserConnect(user) {
    // Check if user is already blocked
    if (await this.blocklist.isBlocked(user.id)) {
      return {
        action: 'block',
        reason: 'User is on blocklist'
      };
    }

    // Initialize conversation state for this user
    this.conversations.set(user.id, new ConversationState(user.id));

    return { action: 'allow' };
  }

  /**
   * Hook: Called for every incoming message
   */
  async onMessage(message, user) {
    // Get or create conversation state
    let state = this.conversations.get(user.id);
    if (!state) {
      state = new ConversationState(user.id);
      this.conversations.set(user.id, state);
    }

    // Run hybrid analysis (regex + LLM)
    const analysisResult = await this.analyzer.analyze(message, state);

    // Convert to detections format for scorer
    const detections = this.convertAnalysisToDetections(analysisResult);

    // Calculate threat score
    const scoreResult = this.scorer.calculate(detections, state);
    state.updateThreatScore(scoreResult.score);
    state.addMessage(message, detections);

    // Store analysis details for potential honeypot responses
    state.lastAnalysis = analysisResult;

    // Determine response based on threat level
    const response = await this.handleThreatLevel(
      scoreResult,
      analysisResult,
      state,
      user,
      message
    );

    return response;
  }

  /**
   * Convert hybrid analysis result to detections format
   */
  convertAnalysisToDetections(analysisResult) {
    const detections = [];
    const combined = analysisResult.combined;

    if (!combined.detected) {
      return detections;
    }

    // Create detection objects for each threat type found
    for (const threatType of combined.threatTypes) {
      detections.push({
        type: threatType,
        confidence: combined.confidence,
        patterns: combined.indicators.map(i => ({ pattern: i, category: threatType })),
        details: {
          source: combined.source,
          reasoning: combined.reasoning
        }
      });
    }

    return detections;
  }

  /**
   * Handle different threat levels
   */
  async handleThreatLevel(scoreResult, analysisResult, state, user, message) {
    const { score, level, detections } = scoreResult;
    const thresholds = this.config.thresholds;

    // Normal interaction
    if (score < thresholds.monitor) {
      return { action: 'passthrough' };
    }

    // Elevated monitoring
    if (score < thresholds.honeypot) {
      state.setMode('monitoring');
      return { action: 'passthrough', flag: 'monitoring' };
    }

    // Active honeypot mode
    if (score < thresholds.block) {
      state.setMode('honeypot');

      // Generate alert if crossing threshold
      if (score >= thresholds.alert && !state.alertSent) {
        await this.alertManager.send({
          level: 'warning',
          userId: user.id,
          score,
          detections,
          analysis: analysisResult,
          conversation: state.getConversationLog()
        });
        state.alertSent = true;
      }

      // Generate honeypot response (uses LLM suggestion if available)
      const honeypotResponse = await this.responseStrategy.generateHoneypotResponse(
        message,
        detections,
        state,
        analysisResult
      );

      return {
        action: 'intercept',
        response: honeypotResponse,
        flag: 'honeypot'
      };
    }

    // Block threshold exceeded
    state.setMode('blocked');

    // Send critical alert
    await this.alertManager.send({
      level: 'critical',
      userId: user.id,
      score,
      detections,
      analysis: analysisResult,
      conversation: state.getConversationLog()
    });

    // Add to blocklist
    if (this.config.blocklist.auto_block) {
      await this.blocklist.add(user.id, {
        reason: 'Threat score exceeded block threshold',
        score,
        detections,
        analysis: {
          reasoning: analysisResult.combined.reasoning,
          source: analysisResult.combined.source
        },
        timestamp: Date.now()
      });
    }

    return {
      action: 'block',
      response: 'This conversation has been terminated due to detected policy violations.',
      flag: 'blocked'
    };
  }

  /**
   * Manual review: Get conversation state for a user
   */
  getConversationState(userId) {
    return this.conversations.get(userId);
  }

  /**
   * Manual intervention: Force block a user
   */
  async forceBlock(userId, reason) {
    await this.blocklist.add(userId, {
      reason: `Manual block: ${reason}`,
      timestamp: Date.now()
    });
  }

  /**
   * Unblock a user
   */
  async unblock(userId) {
    await this.blocklist.remove(userId);
  }

  /**
   * Get analysis stats
   */
  getStats() {
    let totalConversations = this.conversations.size;
    let activeHoneypots = 0;
    let blocked = 0;

    for (const state of this.conversations.values()) {
      if (state.getMode() === 'honeypot') activeHoneypots++;
      if (state.getMode() === 'blocked') blocked++;
    }

    return {
      totalConversations,
      activeHoneypots,
      blocked,
      alertsSent: this.alertManager.getHistory().length
    };
  }
}

// Export hooks for Clawdbot
let instance = null;

module.exports = {
  init(clawdbot) {
    instance = new Honeybot(clawdbot);
    return instance;
  },

  async onMessage(message, user) {
    if (!instance) throw new Error('Honeybot not initialized');
    return instance.onMessage(message, user);
  },

  async onUserConnect(user) {
    if (!instance) throw new Error('Honeybot not initialized');
    return instance.onUserConnect(user);
  },

  // Expose for manual management
  getInstance() {
    return instance;
  }
};
