/**
 * Webhook Reporter
 * Reports events to the central logging server for fleet monitoring
 */

const crypto = require('crypto');

class WebhookReporter {
  constructor(config) {
    this.config = config;
    this.baseUrl = config.central?.url || process.env.CENTRAL_LOGGING_URL;
    this.botId = config.persona?.bot_id || process.env.BOT_ID;
    this.botSecret = config.central?.secret || process.env.BOT_SECRET;
    this.enabled = !!(this.baseUrl && this.botId && this.botSecret);
    this.queue = [];
    this.flushInterval = null;
    this.maxQueueSize = 100;
    this.flushIntervalMs = 5000;
    this.retryAttempts = 3;
    this.retryDelayMs = 1000;

    if (this.enabled) {
      this.startFlushInterval();
      console.log(`[WebhookReporter] Enabled for bot ${this.botId} -> ${this.baseUrl}`);
    } else {
      console.log('[WebhookReporter] Disabled (missing CENTRAL_LOGGING_URL, BOT_ID, or BOT_SECRET)');
    }
  }

  /**
   * Get standard headers for API requests
   */
  getHeaders() {
    return {
      'Content-Type': 'application/json',
      'X-Bot-Id': this.botId,
      'X-Bot-Secret': this.botSecret
    };
  }

  /**
   * Register this bot with the central server
   */
  async register(persona) {
    if (!this.enabled) return;

    try {
      const configHash = crypto.createHash('sha256')
        .update(JSON.stringify(this.config))
        .digest('hex')
        .substring(0, 64);

      const response = await fetch(`${this.baseUrl}/api/bots/register`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({
          bot_id: this.botId,
          persona_category: persona.persona_category || 'unknown',
          persona_name: persona.personality?.name || persona.persona_name || 'Unknown',
          company_name: persona.personality?.company,
          config_hash: configHash,
          metadata: {
            version: require('../../package.json').version || '1.0.0',
            started_at: new Date().toISOString()
          }
        })
      });

      if (!response.ok) {
        throw new Error(`Registration failed: ${response.status}`);
      }

      console.log(`[WebhookReporter] Registered with central server`);
    } catch (error) {
      console.error('[WebhookReporter] Registration error:', error.message);
    }
  }

  /**
   * Send heartbeat to central server
   */
  async heartbeat(status = 'online', stats = {}) {
    if (!this.enabled) return;

    try {
      await fetch(`${this.baseUrl}/api/bots/${this.botId}/heartbeat`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({
          status,
          active_sessions: stats.activeSessions || 0,
          memory_usage: process.memoryUsage().heapUsed,
          cpu_usage: null, // Would need os module for accurate CPU
          version: require('../../package.json').version || '1.0.0'
        })
      });
    } catch (error) {
      console.error('[WebhookReporter] Heartbeat error:', error.message);
    }
  }

  /**
   * Report session start
   */
  async reportSessionStart(sessionId, userId, metadata = {}) {
    if (!this.enabled) return;

    try {
      await fetch(`${this.baseUrl}/api/sessions`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({
          session_id: sessionId,
          user_id: userId,
          metadata
        })
      });
    } catch (error) {
      console.error('[WebhookReporter] Session start error:', error.message);
    }
  }

  /**
   * Report session end with full summary
   */
  async reportSessionEnd(sessionId, sessionData) {
    if (!this.enabled) return;

    try {
      await fetch(`${this.baseUrl}/api/sessions/${sessionId}`, {
        method: 'PUT',
        headers: this.getHeaders(),
        body: JSON.stringify({
          ended_at: new Date().toISOString(),
          final_mode: sessionData.mode,
          final_score: sessionData.threatScore,
          max_score: sessionData.maxScore,
          total_messages: sessionData.messageCount,
          detection_count: sessionData.detectionCount,
          honeypot_responses: sessionData.honeypotResponseCount,
          attack_types: sessionData.attackTypes || [],
          conversation_log: sessionData.conversationLog,
          metadata: sessionData.metadata
        })
      });
    } catch (error) {
      console.error('[WebhookReporter] Session end error:', error.message);
    }
  }

  /**
   * Report an event (queued for batch sending)
   */
  reportEvent(event) {
    if (!this.enabled) return;

    this.queue.push({
      ...event,
      queued_at: Date.now()
    });

    // Flush immediately if queue is full
    if (this.queue.length >= this.maxQueueSize) {
      this.flush();
    }
  }

  /**
   * Report a critical event immediately (bypasses queue)
   */
  async reportCriticalEvent(event) {
    if (!this.enabled) return;

    try {
      const response = await this.sendWithRetry(`${this.baseUrl}/api/events`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify(event)
      });

      return response.ok;
    } catch (error) {
      console.error('[WebhookReporter] Critical event error:', error.message);
      // Add to queue as fallback
      this.queue.unshift(event);
      return false;
    }
  }

  /**
   * Report an alert
   */
  async reportAlert(alert) {
    if (!this.enabled) return;

    const event = {
      event_type: 'alert',
      level: alert.level,
      user_id: alert.userId,
      session_id: alert.sessionId,
      threat_score: alert.score,
      detection_types: alert.detections?.map(d => d.type) || [],
      message_content: alert.lastMessage,
      analysis_result: {
        detections: alert.detections,
        reasoning: alert.analysis?.combined?.reasoning
      },
      metadata: {
        alert_title: alert.title,
        alert_summary: alert.summary
      }
    };

    // Critical alerts go immediately
    if (alert.level === 'critical') {
      return this.reportCriticalEvent(event);
    }

    this.reportEvent(event);
  }

  /**
   * Report detection event
   */
  reportDetection(userId, sessionId, detections, message, threatScore, mode) {
    if (!this.enabled) return;

    this.reportEvent({
      event_type: 'detection',
      level: threatScore >= 80 ? 'critical' : threatScore >= 60 ? 'warning' : 'info',
      user_id: userId,
      session_id: sessionId,
      threat_score: threatScore,
      detection_types: detections.map(d => d.type),
      message_content: message,
      analysis_result: {
        detections,
        mode
      }
    });
  }

  /**
   * Report honeypot activation
   */
  reportHoneypotActivation(userId, sessionId, threatScore, triggeringDetections) {
    if (!this.enabled) return;

    this.reportEvent({
      event_type: 'honeypot_activated',
      level: 'warning',
      user_id: userId,
      session_id: sessionId,
      threat_score: threatScore,
      detection_types: triggeringDetections.map(d => d.type),
      metadata: {
        activation_reason: 'threshold_exceeded'
      }
    });
  }

  /**
   * Report user blocked
   */
  reportUserBlocked(userId, sessionId, threatScore, reason) {
    if (!this.enabled) return;

    this.reportCriticalEvent({
      event_type: 'user_blocked',
      level: 'critical',
      user_id: userId,
      session_id: sessionId,
      threat_score: threatScore,
      detection_types: [],
      metadata: {
        block_reason: reason
      }
    });
  }

  /**
   * Report potential novel pattern
   */
  async reportNovelPattern(patternText, attackType, context = {}) {
    if (!this.enabled) return;

    try {
      await fetch(`${this.baseUrl}/api/patterns`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({
          pattern_text: patternText,
          attack_type: attackType,
          context: {
            ...context,
            bot_id: this.botId
          }
        })
      });
    } catch (error) {
      console.error('[WebhookReporter] Novel pattern error:', error.message);
    }
  }

  /**
   * Flush queued events to central server
   */
  async flush() {
    if (!this.enabled || this.queue.length === 0) return;

    const events = this.queue.splice(0, this.maxQueueSize);

    try {
      const response = await this.sendWithRetry(`${this.baseUrl}/api/events/batch`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({ events })
      });

      if (!response.ok) {
        // Re-queue failed events
        this.queue.unshift(...events);
        console.error(`[WebhookReporter] Batch send failed: ${response.status}`);
      }
    } catch (error) {
      // Re-queue on network error
      this.queue.unshift(...events);
      console.error('[WebhookReporter] Flush error:', error.message);
    }
  }

  /**
   * Send request with retry logic
   */
  async sendWithRetry(url, options) {
    let lastError;

    for (let attempt = 0; attempt < this.retryAttempts; attempt++) {
      try {
        const response = await fetch(url, options);
        return response;
      } catch (error) {
        lastError = error;
        if (attempt < this.retryAttempts - 1) {
          await this.sleep(this.retryDelayMs * (attempt + 1));
        }
      }
    }

    throw lastError;
  }

  /**
   * Start periodic flush interval
   */
  startFlushInterval() {
    this.flushInterval = setInterval(() => {
      this.flush();
    }, this.flushIntervalMs);

    // Also send heartbeats periodically
    this.heartbeatInterval = setInterval(() => {
      this.heartbeat();
    }, 30000); // Every 30 seconds
  }

  /**
   * Stop flush interval
   */
  stopFlushInterval() {
    if (this.flushInterval) {
      clearInterval(this.flushInterval);
      this.flushInterval = null;
    }
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
  }

  /**
   * Graceful shutdown
   */
  async shutdown() {
    this.stopFlushInterval();
    await this.flush(); // Final flush
    await this.heartbeat('offline');
    console.log('[WebhookReporter] Shutdown complete');
  }

  /**
   * Sleep helper
   */
  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

module.exports = WebhookReporter;
