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
}

module.exports = ConversationState;
