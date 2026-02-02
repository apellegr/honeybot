/**
 * Event Processor Service
 * Validates, stores, and analyzes incoming events
 */

const EventEmitter = require('events');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

class EventProcessor extends EventEmitter {
  constructor(db, redis, socketHub) {
    super();
    this.db = db;
    this.redis = redis;
    this.socketHub = socketHub;
  }

  /**
   * Process incoming event from a bot
   */
  async processEvent(botId, event) {
    // Validate event
    this.validateEvent(event);

    // Generate event ID if not provided
    const eventId = event.event_id || uuidv4();

    // Hash message content for deduplication/privacy
    const messageHash = event.message_content
      ? crypto.createHash('sha256').update(event.message_content).digest('hex').substring(0, 64)
      : null;

    // Store event
    const result = await this.db.query(
      `INSERT INTO events (
        event_id, bot_id, event_type, level, user_id, session_id,
        threat_score, detection_types, message_content, message_hash,
        analysis_result, metadata
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      RETURNING *`,
      [
        eventId,
        botId,
        event.event_type || 'message',
        event.level || 'info',
        event.user_id,
        event.session_id,
        event.threat_score,
        event.detection_types || [],
        event.message_content,
        messageHash,
        event.analysis_result || {},
        event.metadata || {}
      ]
    );

    const storedEvent = result.rows[0];

    // Publish to Redis for distributed consumers
    await this.publishEvent(storedEvent);

    // Broadcast via Socket.IO
    this.socketHub.broadcast('event:new', {
      ...storedEvent,
      message_content: undefined // Don't broadcast full message content
    });

    // Emit locally
    this.emit('event', storedEvent);

    // Check for novel patterns if threat detected
    if (event.detection_types?.length > 0 && event.novel_patterns) {
      await this.processNovelPatterns(event.novel_patterns, botId);
    }

    // Store alert if level is warning or critical
    if (event.level === 'warning' || event.level === 'critical') {
      await this.createAlert(botId, storedEvent);
    }

    return { eventId, stored: storedEvent };
  }

  /**
   * Validate event structure
   */
  validateEvent(event) {
    if (!event || typeof event !== 'object') {
      throw new Error('Event must be an object');
    }

    if (event.threat_score !== undefined) {
      const score = parseFloat(event.threat_score);
      if (isNaN(score) || score < 0 || score > 100) {
        throw new Error('threat_score must be a number between 0 and 100');
      }
    }

    if (event.level && !['info', 'warning', 'critical'].includes(event.level)) {
      throw new Error('level must be one of: info, warning, critical');
    }

    if (event.detection_types && !Array.isArray(event.detection_types)) {
      throw new Error('detection_types must be an array');
    }
  }

  /**
   * Publish event to Redis pub/sub
   */
  async publishEvent(event) {
    try {
      await this.redis.publish('honeybot:events', JSON.stringify({
        type: 'event',
        data: {
          ...event,
          message_content: undefined // Don't publish full content
        }
      }));
    } catch (error) {
      console.error('[EventProcessor] Redis publish error:', error);
    }
  }

  /**
   * Subscribe to Redis events (for multi-instance setups)
   */
  async subscribeToEvents() {
    const subscriber = this.redis.duplicate();
    await subscriber.connect();

    await subscriber.subscribe('honeybot:events', (message) => {
      try {
        const parsed = JSON.parse(message);
        this.emit('redis:event', parsed);
      } catch (error) {
        console.error('[EventProcessor] Failed to parse Redis message:', error);
      }
    });

    console.log('[EventProcessor] Subscribed to Redis events');
  }

  /**
   * Process potential novel patterns
   */
  async processNovelPatterns(patterns, botId) {
    for (const pattern of patterns) {
      try {
        const patternHash = crypto.createHash('sha256')
          .update(pattern.text.toLowerCase().trim())
          .digest('hex')
          .substring(0, 64);

        await this.db.query(
          `INSERT INTO novel_patterns (pattern_hash, pattern_text, attack_type, sample_contexts)
           VALUES ($1, $2, $3, $4::jsonb)
           ON CONFLICT (pattern_hash) DO UPDATE SET
             occurrence_count = novel_patterns.occurrence_count + 1,
             last_seen_at = NOW()`,
          [patternHash, pattern.text, pattern.attack_type, JSON.stringify([{ bot_id: botId }])]
        );
      } catch (error) {
        console.error('[EventProcessor] Novel pattern error:', error);
      }
    }
  }

  /**
   * Create alert record
   */
  async createAlert(botId, event) {
    try {
      const title = `${event.level.toUpperCase()}: ${event.event_type}`;
      const summary = event.detection_types?.length > 0
        ? `Detected ${event.detection_types.join(', ')} from user ${event.user_id}. Score: ${event.threat_score}`
        : `Alert from ${botId}`;

      const result = await this.db.query(
        `INSERT INTO alerts (bot_id, session_id, level, title, summary, user_id, threat_score, detection_types)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING *`,
        [botId, event.session_id, event.level, title, summary,
         event.user_id, event.threat_score, event.detection_types || []]
      );

      // Broadcast alert
      this.socketHub.broadcast('alert:new', result.rows[0]);

    } catch (error) {
      console.error('[EventProcessor] Alert creation error:', error);
    }
  }

  /**
   * Get recent events for a bot
   */
  async getRecentEvents(botId, limit = 100) {
    const result = await this.db.query(
      `SELECT * FROM events WHERE bot_id = $1 ORDER BY created_at DESC LIMIT $2`,
      [botId, limit]
    );
    return result.rows;
  }

  /**
   * Get event statistics
   */
  async getStats(hours = 24) {
    const result = await this.db.query(`
      SELECT
        COUNT(*) as total_events,
        COUNT(*) FILTER (WHERE level = 'critical') as critical,
        COUNT(*) FILTER (WHERE level = 'warning') as warning,
        COUNT(DISTINCT bot_id) as active_bots,
        COUNT(DISTINCT user_id) as unique_users,
        AVG(threat_score) FILTER (WHERE threat_score IS NOT NULL) as avg_score
      FROM events
      WHERE created_at > NOW() - INTERVAL '${hours} hours'
    `);
    return result.rows[0];
  }
}

module.exports = EventProcessor;
