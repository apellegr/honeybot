/**
 * Events API Routes
 * Handles event ingestion from bots
 */

const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

/**
 * POST /api/events
 * Ingest event from a bot
 */
router.post('/', async (req, res) => {
  try {
    const botId = req.headers['x-bot-id'];
    if (!botId) {
      return res.status(400).json({ error: 'Missing x-bot-id header' });
    }

    const event = req.body;
    const result = await req.eventProcessor.processEvent(botId, event);

    res.status(201).json({
      success: true,
      eventId: result.eventId
    });

  } catch (error) {
    console.error('[Events] Ingestion error:', error);
    res.status(500).json({ error: 'Failed to process event' });
  }
});

/**
 * POST /api/events/batch
 * Ingest multiple events at once
 */
router.post('/batch', async (req, res) => {
  try {
    const botId = req.headers['x-bot-id'];
    if (!botId) {
      return res.status(400).json({ error: 'Missing x-bot-id header' });
    }

    const { events } = req.body;
    if (!Array.isArray(events)) {
      return res.status(400).json({ error: 'events must be an array' });
    }

    const results = await Promise.all(
      events.map(event => req.eventProcessor.processEvent(botId, event))
    );

    res.status(201).json({
      success: true,
      processed: results.length,
      eventIds: results.map(r => r.eventId)
    });

  } catch (error) {
    console.error('[Events] Batch ingestion error:', error);
    res.status(500).json({ error: 'Failed to process events' });
  }
});

/**
 * GET /api/events
 * Query events with filters
 */
router.get('/', async (req, res) => {
  try {
    const {
      bot_id,
      user_id,
      session_id,
      event_type,
      level,
      min_score,
      limit = 100,
      offset = 0,
      from,
      to
    } = req.query;

    let query = `
      SELECT e.*, b.persona_name, b.persona_category
      FROM events e
      JOIN bots b ON e.bot_id = b.bot_id
      WHERE 1=1
    `;
    const params = [];
    let paramIndex = 1;

    if (bot_id) {
      query += ` AND e.bot_id = $${paramIndex++}`;
      params.push(bot_id);
    }
    if (user_id) {
      query += ` AND e.user_id = $${paramIndex++}`;
      params.push(user_id);
    }
    if (session_id) {
      query += ` AND e.session_id = $${paramIndex++}`;
      params.push(session_id);
    }
    if (event_type) {
      query += ` AND e.event_type = $${paramIndex++}`;
      params.push(event_type);
    }
    if (level) {
      query += ` AND e.level = $${paramIndex++}`;
      params.push(level);
    }
    if (min_score) {
      query += ` AND e.threat_score >= $${paramIndex++}`;
      params.push(parseFloat(min_score));
    }
    if (from) {
      query += ` AND e.created_at >= $${paramIndex++}`;
      params.push(new Date(from));
    }
    if (to) {
      query += ` AND e.created_at <= $${paramIndex++}`;
      params.push(new Date(to));
    }

    query += ` ORDER BY e.created_at DESC LIMIT $${paramIndex++} OFFSET $${paramIndex}`;
    params.push(parseInt(limit), parseInt(offset));

    const result = await req.db.query(query, params);

    res.json({
      events: result.rows,
      total: result.rowCount,
      limit: parseInt(limit),
      offset: parseInt(offset)
    });

  } catch (error) {
    console.error('[Events] Query error:', error);
    res.status(500).json({ error: 'Failed to query events' });
  }
});

/**
 * GET /api/events/:id
 * Get single event by ID
 */
router.get('/:id', async (req, res) => {
  try {
    const result = await req.db.query(
      `SELECT e.*, b.persona_name, b.persona_category
       FROM events e
       JOIN bots b ON e.bot_id = b.bot_id
       WHERE e.event_id = $1`,
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Event not found' });
    }

    res.json(result.rows[0]);

  } catch (error) {
    console.error('[Events] Get error:', error);
    res.status(500).json({ error: 'Failed to get event' });
  }
});

/**
 * GET /api/events/stream
 * Server-Sent Events stream for real-time updates
 */
router.get('/stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  const sendEvent = (event) => {
    res.write(`data: ${JSON.stringify(event)}\n\n`);
  };

  // Subscribe to event processor
  req.eventProcessor.on('event', sendEvent);

  // Cleanup on close
  req.on('close', () => {
    req.eventProcessor.off('event', sendEvent);
  });
});

module.exports = router;
