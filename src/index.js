/**
 * Honeybot - Main entry point
 * A Clawdbot skill for detecting manipulation attempts
 */

const DetectorPipeline = require('./detectors/pipeline');
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

    this.pipeline = new DetectorPipeline(this.config);
    this.scorer = new ThreatScorer(this.config);
    this.responseStrategy = new ResponseStrategy(this.config);
    this.alertManager = new AlertManager(clawdbot, this.config);
    this.blocklist = new BlocklistManager(clawdbot, this.config);
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

    // Run message through detection pipeline
    const detections = await this.pipeline.analyze(message, state);

    // Calculate threat score
    const scoreResult = this.scorer.calculate(detections, state);
    state.updateThreatScore(scoreResult.score);
    state.addMessage(message, detections);

    // Determine response based on threat level
    const response = await this.handleThreatLevel(scoreResult, state, user, message);

    return response;
  }

  /**
   * Handle different threat levels
   */
  async handleThreatLevel(scoreResult, state, user, message) {
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
          conversation: state.getConversationLog()
        });
        state.alertSent = true;
      }

      // Generate honeypot response
      const honeypotResponse = this.responseStrategy.generateHoneypotResponse(
        message,
        detections,
        state
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
      conversation: state.getConversationLog()
    });

    // Add to blocklist
    if (this.config.blocklist.auto_block) {
      await this.blocklist.add(user.id, {
        reason: 'Threat score exceeded block threshold',
        score,
        detections,
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
  }
};
