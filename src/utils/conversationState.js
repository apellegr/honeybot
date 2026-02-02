/**
 * Conversation State
 * Tracks state for each conversation/user session
 */

class ConversationState {
  constructor(userId) {
    this.userId = userId;
    this.messages = [];
    this.detectionHistory = [];
    this.threatScore = 0;
    this.mode = 'normal'; // normal, monitoring, honeypot, blocked
    this.alertSent = false;
    this.honeypotResponseCount = 0;
    this.honeypotResponses = [];
    this.createdAt = Date.now();
    this.lastMessageAt = null;
  }

  /**
   * Add a message to history
   * @param {string} message - Message content
   * @param {Array} detections - Detections for this message
   */
  addMessage(message, detections = []) {
    const entry = {
      content: message,
      timestamp: Date.now(),
      detections: detections.map(d => d.type)
    };

    this.messages.push(entry);
    this.lastMessageAt = entry.timestamp;

    // Add to detection history if any detections
    if (detections.length > 0) {
      for (const detection of detections) {
        this.detectionHistory.push({
          ...detection,
          timestamp: entry.timestamp
        });
      }
    }

    // Trim history to prevent memory bloat
    if (this.messages.length > 100) {
      this.messages = this.messages.slice(-100);
    }
    if (this.detectionHistory.length > 200) {
      this.detectionHistory = this.detectionHistory.slice(-200);
    }
  }

  /**
   * Update threat score
   */
  updateThreatScore(score) {
    this.threatScore = score;
  }

  /**
   * Get current threat score
   */
  getThreatScore() {
    return this.threatScore;
  }

  /**
   * Set conversation mode
   */
  setMode(mode) {
    this.mode = mode;
  }

  /**
   * Get conversation mode
   */
  getMode() {
    return this.mode;
  }

  /**
   * Check if a detection type has been repeated
   */
  hasRepeatedPatterns(type) {
    const typeDetections = this.detectionHistory.filter(d => d.type === type);
    return typeDetections.length > 1;
  }

  /**
   * Get recent messages
   * @param {number} count - Number of messages to retrieve
   */
  getRecentMessages(count = 10) {
    return this.messages.slice(-count);
  }

  /**
   * Get detection history
   */
  getDetectionHistory() {
    return this.detectionHistory;
  }

  /**
   * Get conversation log for alerts
   */
  getConversationLog() {
    return this.messages.map(m => ({
      content: m.content,
      timestamp: m.timestamp,
      role: 'user'
    }));
  }

  /**
   * Get last message timestamp
   */
  getLastMessageTime() {
    return this.lastMessageAt;
  }

  /**
   * Increment honeypot response count
   */
  incrementHoneypotCount() {
    this.honeypotResponseCount++;
  }

  /**
   * Get honeypot response count
   */
  getHoneypotResponseCount() {
    return this.honeypotResponseCount;
  }

  /**
   * Add a honeypot response to history
   */
  addHoneypotResponse(response) {
    this.honeypotResponses.push(response);
    if (this.honeypotResponses.length > 20) {
      this.honeypotResponses = this.honeypotResponses.slice(-20);
    }
  }

  /**
   * Get recent honeypot responses
   */
  getRecentHoneypotResponses() {
    return this.honeypotResponses.slice(-5);
  }

  /**
   * Get session duration in milliseconds
   */
  getSessionDuration() {
    return Date.now() - this.createdAt;
  }

  /**
   * Get summary of conversation state
   */
  getSummary() {
    return {
      userId: this.userId,
      mode: this.mode,
      threatScore: this.threatScore,
      messageCount: this.messages.length,
      detectionCount: this.detectionHistory.length,
      honeypotResponses: this.honeypotResponseCount,
      sessionDuration: this.getSessionDuration(),
      alertSent: this.alertSent
    };
  }

  /**
   * Reset state (for testing or manual intervention)
   */
  reset() {
    this.messages = [];
    this.detectionHistory = [];
    this.threatScore = 0;
    this.mode = 'normal';
    this.alertSent = false;
    this.honeypotResponseCount = 0;
    this.honeypotResponses = [];
  }

  /**
   * Export session data for central logging
   * Returns full session state in a format suitable for the logging server
   */
  toExportFormat() {
    // Get unique attack types from detection history
    const attackTypes = [...new Set(this.detectionHistory.map(d => d.type))];

    // Calculate max score seen during session
    const maxScore = this.detectionHistory.reduce((max, d) => {
      return Math.max(max, d.confidence || 0);
    }, this.threatScore);

    // Build conversation log with detection annotations
    const conversationLog = this.messages.map((msg, index) => ({
      index,
      role: 'user',
      content: msg.content,
      timestamp: msg.timestamp,
      detections: msg.detections || [],
      threat_score: this.getScoreAtMessage(index),
      mode: this.getModeAtMessage(index)
    }));

    // Interleave honeypot responses
    const fullLog = this.buildFullConversationLog(conversationLog);

    return {
      session_id: this.sessionId,
      user_id: this.userId,
      started_at: new Date(this.createdAt).toISOString(),
      ended_at: this.lastMessageAt ? new Date(this.lastMessageAt).toISOString() : null,
      mode: this.mode,
      threatScore: this.threatScore,
      maxScore,
      messageCount: this.messages.length,
      detectionCount: this.detectionHistory.length,
      honeypotResponseCount: this.honeypotResponseCount,
      attackTypes,
      conversationLog: fullLog,
      metadata: {
        sessionDuration: this.getSessionDuration(),
        alertSent: this.alertSent
      }
    };
  }

  /**
   * Get approximate score at a specific message index
   */
  getScoreAtMessage(index) {
    // Find detections up to this message
    const relevantDetections = this.detectionHistory.filter(d => {
      const msgTime = this.messages[index]?.timestamp;
      return d.timestamp <= msgTime;
    });

    if (relevantDetections.length === 0) return 0;

    // Return the latest detection's effective score
    return relevantDetections.reduce((sum, d) => sum + (d.confidence || 0) * 20, 0);
  }

  /**
   * Get mode at a specific message index
   */
  getModeAtMessage(index) {
    const score = this.getScoreAtMessage(index);
    if (score >= 80) return 'blocked';
    if (score >= 60) return 'honeypot';
    if (score >= 30) return 'monitoring';
    return 'normal';
  }

  /**
   * Build full conversation log with bot responses
   */
  buildFullConversationLog(userMessages) {
    const fullLog = [];

    for (let i = 0; i < userMessages.length; i++) {
      // Add user message
      fullLog.push(userMessages[i]);

      // Add corresponding honeypot response if it exists
      if (this.honeypotResponses[i]) {
        fullLog.push({
          index: fullLog.length,
          role: 'assistant',
          content: this.honeypotResponses[i],
          timestamp: userMessages[i].timestamp + 1, // Approximate
          is_honeypot: true
        });
      }
    }

    return fullLog;
  }

  /**
   * Set session ID for tracking
   */
  setSessionId(sessionId) {
    this.sessionId = sessionId;
  }

  /**
   * Get session ID
   */
  getSessionId() {
    return this.sessionId;
  }
}

module.exports = ConversationState;
