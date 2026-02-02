/**
 * Sessions API Routes
 * Session management and conversation replay
 */

const express = require('express');
const router = express.Router();

/**
 * POST /api/sessions
 * Start a new session
 */
router.post('/', async (req, res) => {
  try {
    const secret = req.headers['x-bot-secret'];
    if (secret !== (process.env.BOT_SECRET || 'dev-secret-change-me')) {
      return res.status(401).json({ error: 'Invalid bot secret' });
    }

    const botId = req.headers['x-bot-id'];
    const { session_id, user_id, metadata } = req.body;

    if (!session_id || !user_id) {
      return res.status(400).json({ error: 'Missing required fields: session_id, user_id' });
    }

    const result = await req.db.query(
      `INSERT INTO sessions (session_id, bot_id, user_id, metadata)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (session_id) DO NOTHING
       RETURNING *`,
      [session_id, botId, user_id, metadata || {}]
    );

    req.socketHub.broadcast('session:started', {
      session_id,
      bot_id: botId,
      user_id
    });

    res.status(201).json({
      success: true,
      session: result.rows[0]
    });

  } catch (error) {
    console.error('[Sessions] Create error:', error);
    res.status(500).json({ error: 'Failed to create session' });
  }
});

/**
 * PUT /api/sessions/:sessionId
 * Update session (typically on end)
 */
router.put('/:sessionId', async (req, res) => {
  try {
    const secret = req.headers['x-bot-secret'];
    if (secret !== (process.env.BOT_SECRET || 'dev-secret-change-me')) {
      return res.status(401).json({ error: 'Invalid bot secret' });
    }

    const { sessionId } = req.params;
    const {
      ended_at,
      final_mode,
      final_score,
      max_score,
      total_messages,
      detection_count,
      honeypot_responses,
      attack_types,
      conversation_log,
      metadata
    } = req.body;

    const result = await req.db.query(
      `UPDATE sessions SET
        ended_at = COALESCE($2, ended_at),
        final_mode = COALESCE($3, final_mode),
        final_score = COALESCE($4, final_score),
        max_score = COALESCE($5, max_score),
        total_messages = COALESCE($6, total_messages),
        detection_count = COALESCE($7, detection_count),
        honeypot_responses = COALESCE($8, honeypot_responses),
        attack_types = COALESCE($9, attack_types),
        conversation_log = COALESCE($10, conversation_log),
        metadata = metadata || COALESCE($11, '{}'::jsonb)
       WHERE session_id = $1
       RETURNING *`,
      [sessionId, ended_at, final_mode, final_score, max_score,
       total_messages, detection_count, honeypot_responses,
       attack_types, conversation_log, metadata]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Session not found' });
    }

    req.socketHub.broadcast('session:updated', result.rows[0]);

    res.json({
      success: true,
      session: result.rows[0]
    });

  } catch (error) {
    console.error('[Sessions] Update error:', error);
    res.status(500).json({ error: 'Failed to update session' });
  }
});

/**
 * GET /api/sessions
 * Query sessions with filters
 */
router.get('/', async (req, res) => {
  try {
    const {
      bot_id,
      user_id,
      final_mode,
      min_score,
      limit = 50,
      offset = 0,
      from,
      to,
      active_only
    } = req.query;

    let query = `
      SELECT s.*, b.persona_name, b.persona_category
      FROM sessions s
      JOIN bots b ON s.bot_id = b.bot_id
      WHERE 1=1
    `;
    const params = [];
    let paramIndex = 1;

    if (bot_id) {
      query += ` AND s.bot_id = $${paramIndex++}`;
      params.push(bot_id);
    }
    if (user_id) {
      query += ` AND s.user_id = $${paramIndex++}`;
      params.push(user_id);
    }
    if (final_mode) {
      query += ` AND s.final_mode = $${paramIndex++}`;
      params.push(final_mode);
    }
    if (min_score) {
      query += ` AND s.final_score >= $${paramIndex++}`;
      params.push(parseFloat(min_score));
    }
    if (from) {
      query += ` AND s.started_at >= $${paramIndex++}`;
      params.push(new Date(from));
    }
    if (to) {
      query += ` AND s.started_at <= $${paramIndex++}`;
      params.push(new Date(to));
    }
    if (active_only === 'true') {
      query += ` AND s.ended_at IS NULL`;
    }

    query += ` ORDER BY s.started_at DESC LIMIT $${paramIndex++} OFFSET $${paramIndex}`;
    params.push(parseInt(limit), parseInt(offset));

    const result = await req.db.query(query, params);

    res.json({
      sessions: result.rows,
      total: result.rowCount,
      limit: parseInt(limit),
      offset: parseInt(offset)
    });

  } catch (error) {
    console.error('[Sessions] Query error:', error);
    res.status(500).json({ error: 'Failed to query sessions' });
  }
});

/**
 * GET /api/sessions/:sessionId
 * Get full session with events
 */
router.get('/:sessionId', async (req, res) => {
  try {
    const [sessionResult, eventsResult] = await Promise.all([
      req.db.query(
        `SELECT s.*, b.persona_name, b.persona_category, b.company_name
         FROM sessions s
         JOIN bots b ON s.bot_id = b.bot_id
         WHERE s.session_id = $1`,
        [req.params.sessionId]
      ),
      req.db.query(
        `SELECT * FROM events
         WHERE session_id = $1
         ORDER BY created_at ASC`,
        [req.params.sessionId]
      )
    ]);

    if (sessionResult.rows.length === 0) {
      return res.status(404).json({ error: 'Session not found' });
    }

    res.json({
      session: sessionResult.rows[0],
      events: eventsResult.rows,
      event_count: eventsResult.rowCount
    });

  } catch (error) {
    console.error('[Sessions] Get error:', error);
    res.status(500).json({ error: 'Failed to get session' });
  }
});

/**
 * GET /api/sessions/:sessionId/replay
 * Get session in replay format (conversation timeline)
 */
router.get('/:sessionId/replay', async (req, res) => {
  try {
    const result = await req.db.query(
      `SELECT s.*, b.persona_name, b.persona_category
       FROM sessions s
       JOIN bots b ON s.bot_id = b.bot_id
       WHERE s.session_id = $1`,
      [req.params.sessionId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Session not found' });
    }

    const session = result.rows[0];
    const conversationLog = session.conversation_log || [];

    // Format for replay with threat indicators
    const timeline = conversationLog.map((msg, index) => ({
      index,
      role: msg.role,
      content: msg.content,
      timestamp: msg.timestamp,
      detections: msg.detections || [],
      threat_score: msg.threat_score,
      mode: msg.mode
    }));

    res.json({
      session_id: session.session_id,
      bot: {
        id: session.bot_id,
        name: session.persona_name,
        category: session.persona_category
      },
      user_id: session.user_id,
      started_at: session.started_at,
      ended_at: session.ended_at,
      final_mode: session.final_mode,
      final_score: session.final_score,
      timeline
    });

  } catch (error) {
    console.error('[Sessions] Replay error:', error);
    res.status(500).json({ error: 'Failed to get session replay' });
  }
});

/**
 * GET /api/sessions/active/count
 * Get count of active sessions
 */
router.get('/active/count', async (req, res) => {
  try {
    const result = await req.db.query(`
      SELECT
        COUNT(*) as total,
        COUNT(*) FILTER (WHERE final_mode = 'honeypot' OR
          (ended_at IS NULL AND bot_id IN (
            SELECT DISTINCT bot_id FROM events
            WHERE level IN ('warning', 'critical')
            AND created_at > NOW() - INTERVAL '10 minutes'
          ))
        ) as under_attack
      FROM sessions
      WHERE ended_at IS NULL
    `);

    res.json(result.rows[0]);

  } catch (error) {
    console.error('[Sessions] Active count error:', error);
    res.status(500).json({ error: 'Failed to get active count' });
  }
});

module.exports = router;
