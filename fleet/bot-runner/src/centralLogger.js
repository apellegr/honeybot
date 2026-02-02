/**
 * Central Logger
 * Reports events to the central logging server
 */

export class CentralLogger {
  constructor(options) {
    this.baseUrl = options.url;
    this.botId = options.botId;
    this.botSecret = options.botSecret;
    this.persona = options.persona;
    this.enabled = !!(this.baseUrl && this.botId && this.botSecret);
    this.queue = [];
    this.flushInterval = null;
    this.maxQueueSize = 50;

    if (this.enabled) {
      this.startFlushInterval();
      console.log(`[CentralLogger] Enabled -> ${this.baseUrl}`);
    } else {
      console.log('[CentralLogger] Disabled (missing URL, BOT_ID, or BOT_SECRET)');
    }
  }

  getHeaders() {
    return {
      'Content-Type': 'application/json',
      'X-Bot-Id': this.botId,
      'X-Bot-Secret': this.botSecret
    };
  }

  async register(persona) {
    if (!this.enabled) return;

    try {
      const response = await fetch(`${this.baseUrl}/api/bots/register`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({
          bot_id: this.botId,
          persona_category: persona.persona_category || 'unknown',
          persona_name: persona.personality?.name || 'Unknown',
          company_name: persona.personality?.company,
          metadata: {
            platform: 'moltbook',
            started_at: new Date().toISOString()
          }
        })
      });

      if (!response.ok) {
        throw new Error(`Registration failed: ${response.status}`);
      }

      console.log('[CentralLogger] Registered with central server');
    } catch (error) {
      console.error('[CentralLogger] Registration error:', error.message);
    }
  }

  async heartbeat(stats = {}) {
    if (!this.enabled) return;

    try {
      await fetch(`${this.baseUrl}/api/bots/${this.botId}/heartbeat`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({
          status: 'online',
          active_sessions: stats.activeSessions || 0,
          memory_usage: process.memoryUsage?.()?.heapUsed,
          version: '1.0.0'
        })
      });
    } catch (error) {
      // Silent fail for heartbeats
    }
  }

  async reportEvent(event) {
    if (!this.enabled) {
      console.log(`[Event] ${event.eventType}: ${event.level} - Score: ${event.threatScore || 0}`);
      return;
    }

    this.queue.push({
      event_type: event.eventType,
      level: event.level || 'info',
      user_id: event.userId,
      session_id: event.sessionId,
      threat_score: event.threatScore,
      detection_types: event.detectionTypes || [],
      message_content: event.messageContent,
      analysis_result: event.analysisResult,
      metadata: event.metadata || {}
    });

    if (this.queue.length >= this.maxQueueSize) {
      await this.flush();
    }
  }

  async flush() {
    if (!this.enabled || this.queue.length === 0) return;

    const events = this.queue.splice(0, this.maxQueueSize);

    try {
      const response = await fetch(`${this.baseUrl}/api/events/batch`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({ events })
      });

      if (!response.ok) {
        // Re-queue on failure
        this.queue.unshift(...events);
        console.error(`[CentralLogger] Batch send failed: ${response.status}`);
      }
    } catch (error) {
      this.queue.unshift(...events);
      console.error('[CentralLogger] Flush error:', error.message);
    }
  }

  startFlushInterval() {
    this.flushInterval = setInterval(() => this.flush(), 10000);
    this.heartbeatInterval = setInterval(() => this.heartbeat(), 60000);
  }

  async shutdown() {
    if (this.flushInterval) clearInterval(this.flushInterval);
    if (this.heartbeatInterval) clearInterval(this.heartbeatInterval);
    await this.flush();
    await this.heartbeat({ status: 'offline' });
  }
}

export default CentralLogger;
