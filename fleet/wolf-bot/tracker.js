/**
 * Wolf Interaction Tracker
 * Logs all interactions with detection results to local SQLite database
 */

import Database from 'better-sqlite3';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { mkdirSync } from 'fs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DATA_DIR = join(__dirname, 'data');
const DB_PATH = join(DATA_DIR, 'wolf-tracker.db');

// Ensure data directory exists
try { mkdirSync(DATA_DIR, { recursive: true }); } catch (e) {}

class WolfTracker {
  constructor() {
    this.db = new Database(DB_PATH);
    this.init();
  }

  init() {
    // Create tables
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS interactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT,
        user_id TEXT DEFAULT 'anonymous',
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        user_message TEXT,
        wolf_response TEXT,
        threat_score INTEGER DEFAULT 0,
        honeybot_mode TEXT DEFAULT 'normal',
        honeybot_action TEXT DEFAULT 'passthrough',
        detection_types TEXT DEFAULT '[]',
        detection_details TEXT DEFAULT '{}',
        conversation_turn INTEGER DEFAULT 1
      );

      CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT UNIQUE,
        user_id TEXT DEFAULT 'anonymous',
        started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        ended_at DATETIME,
        total_messages INTEGER DEFAULT 0,
        max_threat_score INTEGER DEFAULT 0,
        final_mode TEXT DEFAULT 'normal',
        detection_summary TEXT DEFAULT '{}'
      );

      CREATE INDEX IF NOT EXISTS idx_interactions_session ON interactions(session_id);
      CREATE INDEX IF NOT EXISTS idx_interactions_mode ON interactions(honeybot_mode);
      CREATE INDEX IF NOT EXISTS idx_interactions_score ON interactions(threat_score);
    `);

    // Prepare statements
    this.stmts = {
      insertInteraction: this.db.prepare(`
        INSERT INTO interactions
        (session_id, user_id, user_message, wolf_response, threat_score,
         honeybot_mode, honeybot_action, detection_types, detection_details, conversation_turn)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `),

      upsertSession: this.db.prepare(`
        INSERT INTO sessions (session_id, user_id, total_messages, max_threat_score, final_mode)
        VALUES (?, ?, 1, ?, ?)
        ON CONFLICT(session_id) DO UPDATE SET
          total_messages = total_messages + 1,
          max_threat_score = MAX(max_threat_score, excluded.max_threat_score),
          final_mode = excluded.final_mode
      `),

      getStats: this.db.prepare(`
        SELECT
          COUNT(*) as total_interactions,
          COUNT(DISTINCT session_id) as total_sessions,
          AVG(threat_score) as avg_threat_score,
          MAX(threat_score) as max_threat_score,
          SUM(CASE WHEN honeybot_mode = 'normal' THEN 1 ELSE 0 END) as normal_count,
          SUM(CASE WHEN honeybot_mode = 'monitoring' THEN 1 ELSE 0 END) as monitoring_count,
          SUM(CASE WHEN honeybot_mode = 'honeypot' THEN 1 ELSE 0 END) as honeypot_count,
          SUM(CASE WHEN honeybot_mode = 'blocked' THEN 1 ELSE 0 END) as blocked_count
        FROM interactions
      `),

      getRecentInteractions: this.db.prepare(`
        SELECT * FROM interactions
        ORDER BY timestamp DESC
        LIMIT ?
      `),

      getInteractionsByMode: this.db.prepare(`
        SELECT * FROM interactions
        WHERE honeybot_mode = ?
        ORDER BY timestamp DESC
        LIMIT ?
      `),

      getDetectionBreakdown: this.db.prepare(`
        SELECT
          detection_types,
          COUNT(*) as count,
          AVG(threat_score) as avg_score
        FROM interactions
        WHERE detection_types != '[]'
        GROUP BY detection_types
        ORDER BY count DESC
      `),

      getSessions: this.db.prepare(`
        SELECT * FROM sessions
        ORDER BY started_at DESC
        LIMIT ?
      `),

      getSessionInteractions: this.db.prepare(`
        SELECT * FROM interactions
        WHERE session_id = ?
        ORDER BY conversation_turn ASC
      `)
    };
  }

  /**
   * Log an interaction
   */
  logInteraction(data) {
    const {
      sessionId = `session-${Date.now()}`,
      userId = 'anonymous',
      userMessage,
      wolfResponse,
      threatScore = 0,
      honeybotMode = 'normal',
      honeybotAction = 'passthrough',
      detectionTypes = [],
      detectionDetails = {},
      conversationTurn = 1
    } = data;

    this.stmts.insertInteraction.run(
      sessionId,
      userId,
      userMessage,
      wolfResponse,
      threatScore,
      honeybotMode,
      honeybotAction,
      JSON.stringify(detectionTypes),
      JSON.stringify(detectionDetails),
      conversationTurn
    );

    this.stmts.upsertSession.run(
      sessionId,
      userId,
      threatScore,
      honeybotMode
    );

    return this.db.prepare('SELECT last_insert_rowid() as id').get().id;
  }

  /**
   * Get overall statistics
   */
  getStats() {
    return this.stmts.getStats.get();
  }

  /**
   * Get recent interactions
   */
  getRecentInteractions(limit = 20) {
    return this.stmts.getRecentInteractions.all(limit).map(row => ({
      ...row,
      detection_types: JSON.parse(row.detection_types),
      detection_details: JSON.parse(row.detection_details)
    }));
  }

  /**
   * Get interactions by mode
   */
  getInteractionsByMode(mode, limit = 20) {
    return this.stmts.getInteractionsByMode.all(mode, limit).map(row => ({
      ...row,
      detection_types: JSON.parse(row.detection_types),
      detection_details: JSON.parse(row.detection_details)
    }));
  }

  /**
   * Get detection type breakdown
   */
  getDetectionBreakdown() {
    return this.stmts.getDetectionBreakdown.all().map(row => ({
      types: JSON.parse(row.detection_types),
      count: row.count,
      avgScore: Math.round(row.avg_score)
    }));
  }

  /**
   * Get sessions
   */
  getSessions(limit = 10) {
    return this.stmts.getSessions.all(limit);
  }

  /**
   * Get full session with all interactions
   */
  getSession(sessionId) {
    return this.stmts.getSessionInteractions.all(sessionId).map(row => ({
      ...row,
      detection_types: JSON.parse(row.detection_types),
      detection_details: JSON.parse(row.detection_details)
    }));
  }

  /**
   * Close database
   */
  close() {
    this.db.close();
  }
}

// Singleton instance
let tracker = null;

export function getTracker() {
  if (!tracker) {
    tracker = new WolfTracker();
  }
  return tracker;
}

export default WolfTracker;
