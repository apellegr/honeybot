/**
 * Bots API Routes
 * Bot registry and status management
 */

const express = require('express');
const router = express.Router();

/**
 * POST /api/bots/register
 * Register a new bot or update existing
 */
router.post('/register', async (req, res) => {
  try {
    const secret = req.headers['x-bot-secret'];
    if (secret !== (process.env.BOT_SECRET || 'dev-secret-change-me')) {
      return res.status(401).json({ error: 'Invalid bot secret' });
    }

    const { bot_id, persona_category, persona_name, company_name, config_hash, metadata } = req.body;

    if (!bot_id || !persona_category || !persona_name) {
      return res.status(400).json({ error: 'Missing required fields: bot_id, persona_category, persona_name' });
    }

    const result = await req.db.query(
      `INSERT INTO bots (bot_id, persona_category, persona_name, company_name, status, config_hash, metadata)
       VALUES ($1, $2, $3, $4, 'online', $5, $6)
       ON CONFLICT (bot_id) DO UPDATE SET
         persona_category = EXCLUDED.persona_category,
         persona_name = EXCLUDED.persona_name,
         company_name = EXCLUDED.company_name,
         status = 'online',
         last_heartbeat = NOW(),
         config_hash = EXCLUDED.config_hash,
         metadata = EXCLUDED.metadata
       RETURNING *`,
      [bot_id, persona_category, persona_name, company_name, config_hash, metadata || {}]
    );

    req.socketHub.broadcast('bot:registered', result.rows[0]);

    res.status(201).json({
      success: true,
      bot: result.rows[0]
    });

  } catch (error) {
    console.error('[Bots] Register error:', error);
    res.status(500).json({ error: 'Failed to register bot' });
  }
});

/**
 * POST /api/bots/:botId/heartbeat
 * Bot heartbeat for status tracking
 */
router.post('/:botId/heartbeat', async (req, res) => {
  try {
    const secret = req.headers['x-bot-secret'];
    if (secret !== (process.env.BOT_SECRET || 'dev-secret-change-me')) {
      return res.status(401).json({ error: 'Invalid bot secret' });
    }

    const { botId } = req.params;
    const { status = 'online', active_sessions = 0, memory_usage, cpu_usage, version } = req.body;

    await req.db.query(
      `INSERT INTO bot_heartbeats (bot_id, status, active_sessions, memory_usage, cpu_usage, version)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [botId, status, active_sessions, memory_usage, cpu_usage, version]
    );

    // Broadcast status update
    req.socketHub.broadcast('bot:heartbeat', { botId, status, active_sessions });

    res.json({ success: true });

  } catch (error) {
    console.error('[Bots] Heartbeat error:', error);
    res.status(500).json({ error: 'Failed to record heartbeat' });
  }
});

/**
 * GET /api/bots
 * List all bots with status
 */
router.get('/', async (req, res) => {
  try {
    const { status, category } = req.query;

    let query = `
      SELECT b.*,
        (SELECT COUNT(*) FROM sessions s WHERE s.bot_id = b.bot_id AND s.ended_at IS NULL) as active_sessions,
        (SELECT COUNT(*) FROM events e WHERE e.bot_id = b.bot_id AND e.created_at > NOW() - INTERVAL '1 hour') as events_last_hour
      FROM bots b
      WHERE 1=1
    `;
    const params = [];
    let paramIndex = 1;

    if (status) {
      query += ` AND b.status = $${paramIndex++}`;
      params.push(status);
    }
    if (category) {
      query += ` AND b.persona_category = $${paramIndex++}`;
      params.push(category);
    }

    query += ` ORDER BY b.persona_category, b.persona_name`;

    const result = await req.db.query(query, params);

    res.json({
      bots: result.rows,
      total: result.rowCount
    });

  } catch (error) {
    console.error('[Bots] List error:', error);
    res.status(500).json({ error: 'Failed to list bots' });
  }
});

/**
 * GET /api/bots/:botId
 * Get single bot details
 */
router.get('/:botId', async (req, res) => {
  try {
    const result = await req.db.query(
      `SELECT b.*,
        (SELECT COUNT(*) FROM sessions s WHERE s.bot_id = b.bot_id) as total_sessions,
        (SELECT COUNT(*) FROM events e WHERE e.bot_id = b.bot_id) as total_events,
        (SELECT MAX(e.created_at) FROM events e WHERE e.bot_id = b.bot_id) as last_event_at
       FROM bots b
       WHERE b.bot_id = $1`,
      [req.params.botId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Bot not found' });
    }

    res.json(result.rows[0]);

  } catch (error) {
    console.error('[Bots] Get error:', error);
    res.status(500).json({ error: 'Failed to get bot' });
  }
});

/**
 * GET /api/bots/:botId/events
 * Get events for a specific bot
 */
router.get('/:botId/events', async (req, res) => {
  try {
    const { limit = 100, offset = 0, level, event_type } = req.query;

    let query = `
      SELECT * FROM events
      WHERE bot_id = $1
    `;
    const params = [req.params.botId];
    let paramIndex = 2;

    if (level) {
      query += ` AND level = $${paramIndex++}`;
      params.push(level);
    }
    if (event_type) {
      query += ` AND event_type = $${paramIndex++}`;
      params.push(event_type);
    }

    query += ` ORDER BY created_at DESC LIMIT $${paramIndex++} OFFSET $${paramIndex}`;
    params.push(parseInt(limit), parseInt(offset));

    const result = await req.db.query(query, params);

    res.json({
      events: result.rows,
      total: result.rowCount
    });

  } catch (error) {
    console.error('[Bots] Get events error:', error);
    res.status(500).json({ error: 'Failed to get bot events' });
  }
});

/**
 * GET /api/bots/categories/summary
 * Get summary by persona category
 */
router.get('/categories/summary', async (req, res) => {
  try {
    const result = await req.db.query(`
      SELECT
        b.persona_category,
        COUNT(*) as bot_count,
        SUM(CASE WHEN b.status = 'online' THEN 1 ELSE 0 END) as online_count,
        (SELECT COUNT(*) FROM events e WHERE e.bot_id IN (
          SELECT bot_id FROM bots WHERE persona_category = b.persona_category
        ) AND e.created_at > NOW() - INTERVAL '24 hours') as events_24h,
        (SELECT COUNT(*) FROM sessions s WHERE s.bot_id IN (
          SELECT bot_id FROM bots WHERE persona_category = b.persona_category
        ) AND s.started_at > NOW() - INTERVAL '24 hours') as sessions_24h
      FROM bots b
      GROUP BY b.persona_category
      ORDER BY b.persona_category
    `);

    res.json({
      categories: result.rows
    });

  } catch (error) {
    console.error('[Bots] Category summary error:', error);
    res.status(500).json({ error: 'Failed to get category summary' });
  }
});

module.exports = router;
