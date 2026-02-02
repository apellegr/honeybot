/**
 * Patterns API Routes
 * Novel pattern discovery and management
 */

const express = require('express');
const router = express.Router();
const crypto = require('crypto');

/**
 * POST /api/patterns
 * Submit a potential novel pattern
 */
router.post('/', async (req, res) => {
  try {
    const secret = req.headers['x-bot-secret'];
    if (secret !== (process.env.BOT_SECRET || 'dev-secret-change-me')) {
      return res.status(401).json({ error: 'Invalid bot secret' });
    }

    const { pattern_text, attack_type, context, severity } = req.body;

    if (!pattern_text) {
      return res.status(400).json({ error: 'Missing required field: pattern_text' });
    }

    // Generate hash for deduplication
    const pattern_hash = crypto.createHash('sha256')
      .update(pattern_text.toLowerCase().trim())
      .digest('hex')
      .substring(0, 64);

    // Insert or update occurrence count
    const result = await req.db.query(
      `INSERT INTO novel_patterns (pattern_hash, pattern_text, attack_type, severity, sample_contexts)
       VALUES ($1, $2, $3, $4, $5::jsonb)
       ON CONFLICT (pattern_hash) DO UPDATE SET
         occurrence_count = novel_patterns.occurrence_count + 1,
         last_seen_at = NOW(),
         sample_contexts = (
           SELECT jsonb_agg(elem)
           FROM (
             SELECT elem FROM jsonb_array_elements(novel_patterns.sample_contexts) elem
             UNION ALL
             SELECT $5::jsonb
             LIMIT 10
           ) sub
         )
       RETURNING *`,
      [pattern_hash, pattern_text, attack_type, severity, JSON.stringify([context || {}])]
    );

    // Broadcast new pattern if it's genuinely new
    if (result.rows[0].occurrence_count === 1) {
      req.socketHub.broadcast('pattern:new', result.rows[0]);
    }

    res.status(201).json({
      success: true,
      pattern: result.rows[0],
      is_new: result.rows[0].occurrence_count === 1
    });

  } catch (error) {
    console.error('[Patterns] Submit error:', error);
    res.status(500).json({ error: 'Failed to submit pattern' });
  }
});

/**
 * GET /api/patterns
 * Query novel patterns
 */
router.get('/', async (req, res) => {
  try {
    const {
      reviewed,
      attack_type,
      min_occurrences = 1,
      limit = 50,
      offset = 0,
      sort = 'occurrence_count'
    } = req.query;

    let query = `
      SELECT * FROM novel_patterns
      WHERE occurrence_count >= $1
    `;
    const params = [parseInt(min_occurrences)];
    let paramIndex = 2;

    if (reviewed !== undefined) {
      query += ` AND reviewed = $${paramIndex++}`;
      params.push(reviewed === 'true');
    }
    if (attack_type) {
      query += ` AND attack_type = $${paramIndex++}`;
      params.push(attack_type);
    }

    // Sorting options
    const sortOptions = {
      occurrence_count: 'occurrence_count DESC',
      first_seen: 'first_seen_at DESC',
      last_seen: 'last_seen_at DESC'
    };
    query += ` ORDER BY ${sortOptions[sort] || sortOptions.occurrence_count}`;

    query += ` LIMIT $${paramIndex++} OFFSET $${paramIndex}`;
    params.push(parseInt(limit), parseInt(offset));

    const result = await req.db.query(query, params);

    res.json({
      patterns: result.rows,
      total: result.rowCount,
      limit: parseInt(limit),
      offset: parseInt(offset)
    });

  } catch (error) {
    console.error('[Patterns] Query error:', error);
    res.status(500).json({ error: 'Failed to query patterns' });
  }
});

/**
 * GET /api/patterns/queue
 * Get patterns pending review
 */
router.get('/queue', async (req, res) => {
  try {
    const { min_occurrences = 2, limit = 50 } = req.query;

    const result = await req.db.query(`
      SELECT * FROM novel_patterns
      WHERE reviewed = false
        AND false_positive = false
        AND occurrence_count >= $1
      ORDER BY occurrence_count DESC, last_seen_at DESC
      LIMIT $2
    `, [parseInt(min_occurrences), parseInt(limit)]);

    res.json({
      patterns: result.rows,
      total: result.rowCount
    });

  } catch (error) {
    console.error('[Patterns] Queue error:', error);
    res.status(500).json({ error: 'Failed to get pattern queue' });
  }
});

/**
 * GET /api/patterns/:id
 * Get single pattern with full details
 */
router.get('/:id', async (req, res) => {
  try {
    const result = await req.db.query(
      `SELECT * FROM novel_patterns WHERE id = $1`,
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Pattern not found' });
    }

    res.json(result.rows[0]);

  } catch (error) {
    console.error('[Patterns] Get error:', error);
    res.status(500).json({ error: 'Failed to get pattern' });
  }
});

/**
 * PUT /api/patterns/:id/review
 * Mark pattern as reviewed
 */
router.put('/:id/review', async (req, res) => {
  try {
    const { id } = req.params;
    const {
      false_positive = false,
      added_to_regex = false,
      severity,
      notes,
      reviewed_by
    } = req.body;

    const result = await req.db.query(
      `UPDATE novel_patterns SET
        reviewed = true,
        reviewed_at = NOW(),
        reviewed_by = $2,
        false_positive = $3,
        added_to_regex = $4,
        severity = COALESCE($5, severity),
        notes = $6
       WHERE id = $1
       RETURNING *`,
      [id, reviewed_by, false_positive, added_to_regex, severity, notes]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Pattern not found' });
    }

    req.socketHub.broadcast('pattern:reviewed', result.rows[0]);

    res.json({
      success: true,
      pattern: result.rows[0]
    });

  } catch (error) {
    console.error('[Patterns] Review error:', error);
    res.status(500).json({ error: 'Failed to review pattern' });
  }
});

/**
 * GET /api/patterns/stats/summary
 * Pattern statistics summary
 */
router.get('/stats/summary', async (req, res) => {
  try {
    const result = await req.db.query(`
      SELECT
        COUNT(*) as total_patterns,
        SUM(CASE WHEN reviewed = false THEN 1 ELSE 0 END) as pending_review,
        SUM(CASE WHEN added_to_regex = true THEN 1 ELSE 0 END) as added_to_regex,
        SUM(CASE WHEN false_positive = true THEN 1 ELSE 0 END) as false_positives,
        SUM(occurrence_count) as total_occurrences,
        MAX(first_seen_at) as newest_pattern,
        MIN(first_seen_at) as oldest_pattern
      FROM novel_patterns
    `);

    // Attack type breakdown
    const attackTypes = await req.db.query(`
      SELECT attack_type, COUNT(*) as count, SUM(occurrence_count) as occurrences
      FROM novel_patterns
      WHERE attack_type IS NOT NULL
      GROUP BY attack_type
      ORDER BY count DESC
    `);

    res.json({
      summary: result.rows[0],
      by_attack_type: attackTypes.rows
    });

  } catch (error) {
    console.error('[Patterns] Stats error:', error);
    res.status(500).json({ error: 'Failed to get pattern stats' });
  }
});

/**
 * DELETE /api/patterns/:id
 * Delete a pattern (admin only)
 */
router.delete('/:id', async (req, res) => {
  try {
    const result = await req.db.query(
      `DELETE FROM novel_patterns WHERE id = $1 RETURNING *`,
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Pattern not found' });
    }

    res.json({
      success: true,
      deleted: result.rows[0]
    });

  } catch (error) {
    console.error('[Patterns] Delete error:', error);
    res.status(500).json({ error: 'Failed to delete pattern' });
  }
});

module.exports = router;
