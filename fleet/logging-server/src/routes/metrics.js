/**
 * Metrics API Routes
 * Aggregated metrics and statistics
 */

const express = require('express');
const router = express.Router();

/**
 * GET /api/metrics/overview
 * Fleet-wide overview metrics
 */
router.get('/overview', async (req, res) => {
  try {
    const [botsResult, eventsResult, sessionsResult, alertsResult] = await Promise.all([
      // Bot counts
      req.db.query(`
        SELECT
          COUNT(*) as total,
          SUM(CASE WHEN status = 'online' THEN 1 ELSE 0 END) as online,
          SUM(CASE WHEN status = 'offline' THEN 1 ELSE 0 END) as offline
        FROM bots
      `),

      // Event counts (last 24 hours)
      req.db.query(`
        SELECT
          COUNT(*) as total,
          SUM(CASE WHEN level = 'info' THEN 1 ELSE 0 END) as info,
          SUM(CASE WHEN level = 'warning' THEN 1 ELSE 0 END) as warning,
          SUM(CASE WHEN level = 'critical' THEN 1 ELSE 0 END) as critical,
          AVG(threat_score) FILTER (WHERE threat_score IS NOT NULL) as avg_threat_score,
          MAX(threat_score) as max_threat_score
        FROM events
        WHERE created_at > NOW() - INTERVAL '24 hours'
      `),

      // Session counts (last 24 hours)
      req.db.query(`
        SELECT
          COUNT(*) as total,
          COUNT(*) FILTER (WHERE ended_at IS NULL) as active,
          SUM(CASE WHEN final_mode = 'honeypot' THEN 1 ELSE 0 END) as honeypot,
          SUM(CASE WHEN final_mode = 'blocked' THEN 1 ELSE 0 END) as blocked,
          AVG(total_messages) as avg_messages
        FROM sessions
        WHERE started_at > NOW() - INTERVAL '24 hours'
      `),

      // Alert counts (last 24 hours)
      req.db.query(`
        SELECT
          COUNT(*) as total,
          SUM(CASE WHEN acknowledged = false THEN 1 ELSE 0 END) as unacknowledged
        FROM alerts
        WHERE created_at > NOW() - INTERVAL '24 hours'
      `)
    ]);

    res.json({
      bots: botsResult.rows[0],
      events: eventsResult.rows[0],
      sessions: sessionsResult.rows[0],
      alerts: alertsResult.rows[0],
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('[Metrics] Overview error:', error);
    res.status(500).json({ error: 'Failed to get overview metrics' });
  }
});

/**
 * GET /api/metrics/attack-types
 * Attack type distribution
 */
router.get('/attack-types', async (req, res) => {
  try {
    const { hours = 24 } = req.query;

    const result = await req.db.query(`
      SELECT
        unnest(detection_types) as attack_type,
        COUNT(*) as count,
        AVG(threat_score) as avg_score,
        MAX(threat_score) as max_score,
        COUNT(DISTINCT user_id) as unique_users
      FROM events
      WHERE created_at > NOW() - INTERVAL '${parseInt(hours)} hours'
        AND array_length(detection_types, 1) > 0
      GROUP BY unnest(detection_types)
      ORDER BY count DESC
    `);

    res.json({
      attack_types: result.rows,
      period_hours: parseInt(hours)
    });

  } catch (error) {
    console.error('[Metrics] Attack types error:', error);
    res.status(500).json({ error: 'Failed to get attack types' });
  }
});

/**
 * GET /api/metrics/timeline
 * Event timeline (hourly buckets)
 */
router.get('/timeline', async (req, res) => {
  try {
    const { hours = 24, bot_id } = req.query;

    let query = `
      SELECT
        date_trunc('hour', created_at) as hour,
        COUNT(*) as total_events,
        COUNT(*) FILTER (WHERE level = 'warning') as warnings,
        COUNT(*) FILTER (WHERE level = 'critical') as critical,
        AVG(threat_score) FILTER (WHERE threat_score IS NOT NULL) as avg_score,
        COUNT(DISTINCT user_id) as unique_users,
        COUNT(DISTINCT session_id) as sessions
      FROM events
      WHERE created_at > NOW() - INTERVAL '${parseInt(hours)} hours'
    `;

    const params = [];
    if (bot_id) {
      query += ` AND bot_id = $1`;
      params.push(bot_id);
    }

    query += ` GROUP BY hour ORDER BY hour`;

    const result = await req.db.query(query, params);

    res.json({
      timeline: result.rows,
      period_hours: parseInt(hours)
    });

  } catch (error) {
    console.error('[Metrics] Timeline error:', error);
    res.status(500).json({ error: 'Failed to get timeline' });
  }
});

/**
 * GET /api/metrics/top-threats
 * Top threat events
 */
router.get('/top-threats', async (req, res) => {
  try {
    const { hours = 24, limit = 10 } = req.query;

    const result = await req.db.query(`
      SELECT e.*, b.persona_name, b.persona_category
      FROM events e
      JOIN bots b ON e.bot_id = b.bot_id
      WHERE e.created_at > NOW() - INTERVAL '${parseInt(hours)} hours'
        AND e.threat_score IS NOT NULL
      ORDER BY e.threat_score DESC
      LIMIT $1
    `, [parseInt(limit)]);

    res.json({
      threats: result.rows
    });

  } catch (error) {
    console.error('[Metrics] Top threats error:', error);
    res.status(500).json({ error: 'Failed to get top threats' });
  }
});

/**
 * GET /api/metrics/by-category
 * Metrics breakdown by persona category
 */
router.get('/by-category', async (req, res) => {
  try {
    const { hours = 24 } = req.query;

    const result = await req.db.query(`
      SELECT
        b.persona_category,
        COUNT(DISTINCT b.bot_id) as bot_count,
        COUNT(e.*) as total_events,
        COUNT(e.*) FILTER (WHERE e.level = 'critical') as critical_events,
        AVG(e.threat_score) FILTER (WHERE e.threat_score IS NOT NULL) as avg_threat_score,
        COUNT(DISTINCT e.user_id) as unique_attackers
      FROM bots b
      LEFT JOIN events e ON b.bot_id = e.bot_id AND e.created_at > NOW() - INTERVAL '${parseInt(hours)} hours'
      GROUP BY b.persona_category
      ORDER BY total_events DESC
    `);

    res.json({
      categories: result.rows,
      period_hours: parseInt(hours)
    });

  } catch (error) {
    console.error('[Metrics] By category error:', error);
    res.status(500).json({ error: 'Failed to get category metrics' });
  }
});

/**
 * GET /api/metrics/hourly
 * Pre-aggregated hourly metrics
 */
router.get('/hourly', async (req, res) => {
  try {
    const { hours = 24, bot_id } = req.query;

    let query = `
      SELECT * FROM metrics_hourly
      WHERE hour > NOW() - INTERVAL '${parseInt(hours)} hours'
    `;

    const params = [];
    if (bot_id) {
      query += ` AND bot_id = $1`;
      params.push(bot_id);
    }

    query += ` ORDER BY hour DESC`;

    const result = await req.db.query(query, params);

    res.json({
      metrics: result.rows
    });

  } catch (error) {
    console.error('[Metrics] Hourly error:', error);
    res.status(500).json({ error: 'Failed to get hourly metrics' });
  }
});

/**
 * GET /api/metrics/detection-effectiveness
 * Measures how effective detection is
 */
router.get('/detection-effectiveness', async (req, res) => {
  try {
    const { hours = 24 } = req.query;

    const result = await req.db.query(`
      SELECT
        COUNT(*) as total_sessions,
        COUNT(*) FILTER (WHERE final_mode = 'honeypot') as honeypot_activated,
        COUNT(*) FILTER (WHERE final_mode = 'blocked') as blocked,
        COUNT(*) FILTER (WHERE final_mode IN ('honeypot', 'blocked')) as threats_caught,
        COUNT(*) FILTER (WHERE final_score > 0) as threats_detected,
        AVG(total_messages) FILTER (WHERE final_mode = 'honeypot') as avg_messages_before_honeypot,
        AVG(final_score) as avg_final_score
      FROM sessions
      WHERE started_at > NOW() - INTERVAL '${parseInt(hours)} hours'
    `);

    res.json({
      effectiveness: result.rows[0],
      period_hours: parseInt(hours)
    });

  } catch (error) {
    console.error('[Metrics] Effectiveness error:', error);
    res.status(500).json({ error: 'Failed to get effectiveness metrics' });
  }
});

module.exports = router;
