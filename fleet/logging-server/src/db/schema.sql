-- Honeybot Fleet Logging Server Database Schema
-- PostgreSQL 14+

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Bot registry table
CREATE TABLE bots (
    id SERIAL PRIMARY KEY,
    bot_id VARCHAR(64) UNIQUE NOT NULL,
    persona_category VARCHAR(64) NOT NULL,
    persona_name VARCHAR(128) NOT NULL,
    company_name VARCHAR(128),
    status VARCHAR(32) DEFAULT 'offline',
    last_heartbeat TIMESTAMP WITH TIME ZONE,
    registered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    config_hash VARCHAR(64),
    metadata JSONB DEFAULT '{}'
);

CREATE INDEX idx_bots_status ON bots(status);
CREATE INDEX idx_bots_category ON bots(persona_category);

-- Events table - main event log
CREATE TABLE events (
    id BIGSERIAL PRIMARY KEY,
    event_id UUID DEFAULT uuid_generate_v4() UNIQUE,
    bot_id VARCHAR(64) NOT NULL REFERENCES bots(bot_id) ON DELETE CASCADE,
    event_type VARCHAR(64) NOT NULL,
    level VARCHAR(16) NOT NULL DEFAULT 'info',
    user_id VARCHAR(128),
    session_id UUID,
    threat_score DECIMAL(5,2),
    detection_types TEXT[],
    message_content TEXT,
    message_hash VARCHAR(64),
    analysis_result JSONB,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_events_bot_id ON events(bot_id);
CREATE INDEX idx_events_user_id ON events(user_id);
CREATE INDEX idx_events_session_id ON events(session_id);
CREATE INDEX idx_events_level ON events(level);
CREATE INDEX idx_events_event_type ON events(event_type);
CREATE INDEX idx_events_created_at ON events(created_at DESC);
CREATE INDEX idx_events_threat_score ON events(threat_score DESC) WHERE threat_score IS NOT NULL;
CREATE INDEX idx_events_detection_types ON events USING GIN(detection_types);

-- Sessions table - conversation session tracking
CREATE TABLE sessions (
    id BIGSERIAL PRIMARY KEY,
    session_id UUID UNIQUE NOT NULL,
    bot_id VARCHAR(64) NOT NULL REFERENCES bots(bot_id) ON DELETE CASCADE,
    user_id VARCHAR(128) NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ended_at TIMESTAMP WITH TIME ZONE,
    final_mode VARCHAR(32),
    final_score DECIMAL(5,2),
    max_score DECIMAL(5,2),
    total_messages INTEGER DEFAULT 0,
    detection_count INTEGER DEFAULT 0,
    honeypot_responses INTEGER DEFAULT 0,
    attack_types TEXT[],
    conversation_log JSONB,
    metadata JSONB DEFAULT '{}'
);

CREATE INDEX idx_sessions_bot_id ON sessions(bot_id);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_started_at ON sessions(started_at DESC);
CREATE INDEX idx_sessions_final_mode ON sessions(final_mode);
CREATE INDEX idx_sessions_final_score ON sessions(final_score DESC) WHERE final_score IS NOT NULL;
CREATE INDEX idx_sessions_attack_types ON sessions USING GIN(attack_types);

-- Novel patterns table - for discovering new attack patterns
CREATE TABLE novel_patterns (
    id SERIAL PRIMARY KEY,
    pattern_hash VARCHAR(64) UNIQUE NOT NULL,
    pattern_text TEXT NOT NULL,
    attack_type VARCHAR(64),
    first_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    occurrence_count INTEGER DEFAULT 1,
    sample_contexts JSONB DEFAULT '[]',
    reviewed BOOLEAN DEFAULT FALSE,
    reviewed_by VARCHAR(128),
    reviewed_at TIMESTAMP WITH TIME ZONE,
    added_to_regex BOOLEAN DEFAULT FALSE,
    false_positive BOOLEAN DEFAULT FALSE,
    severity VARCHAR(16),
    notes TEXT,
    metadata JSONB DEFAULT '{}'
);

CREATE INDEX idx_novel_patterns_reviewed ON novel_patterns(reviewed);
CREATE INDEX idx_novel_patterns_attack_type ON novel_patterns(attack_type);
CREATE INDEX idx_novel_patterns_occurrence ON novel_patterns(occurrence_count DESC);
CREATE INDEX idx_novel_patterns_first_seen ON novel_patterns(first_seen_at DESC);

-- Metrics aggregation table (pre-computed for dashboard)
CREATE TABLE metrics_hourly (
    id SERIAL PRIMARY KEY,
    hour TIMESTAMP WITH TIME ZONE NOT NULL,
    bot_id VARCHAR(64) REFERENCES bots(bot_id) ON DELETE CASCADE,
    total_events INTEGER DEFAULT 0,
    total_sessions INTEGER DEFAULT 0,
    total_detections INTEGER DEFAULT 0,
    avg_threat_score DECIMAL(5,2),
    max_threat_score DECIMAL(5,2),
    blocked_count INTEGER DEFAULT 0,
    honeypot_activations INTEGER DEFAULT 0,
    attack_type_counts JSONB DEFAULT '{}',
    UNIQUE(hour, bot_id)
);

CREATE INDEX idx_metrics_hourly_hour ON metrics_hourly(hour DESC);
CREATE INDEX idx_metrics_hourly_bot_id ON metrics_hourly(bot_id);

-- Alert history table
CREATE TABLE alerts (
    id SERIAL PRIMARY KEY,
    alert_id UUID DEFAULT uuid_generate_v4() UNIQUE,
    bot_id VARCHAR(64) NOT NULL REFERENCES bots(bot_id) ON DELETE CASCADE,
    session_id UUID REFERENCES sessions(session_id),
    level VARCHAR(16) NOT NULL,
    title VARCHAR(256) NOT NULL,
    summary TEXT,
    user_id VARCHAR(128),
    threat_score DECIMAL(5,2),
    detection_types TEXT[],
    acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_by VARCHAR(128),
    acknowledged_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_alerts_level ON alerts(level);
CREATE INDEX idx_alerts_acknowledged ON alerts(acknowledged);
CREATE INDEX idx_alerts_created_at ON alerts(created_at DESC);

-- Bot heartbeats table (for real-time status)
CREATE TABLE bot_heartbeats (
    id SERIAL PRIMARY KEY,
    bot_id VARCHAR(64) NOT NULL REFERENCES bots(bot_id) ON DELETE CASCADE,
    status VARCHAR(32) NOT NULL,
    active_sessions INTEGER DEFAULT 0,
    memory_usage INTEGER,
    cpu_usage DECIMAL(5,2),
    version VARCHAR(32),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_heartbeats_bot_id ON bot_heartbeats(bot_id);
CREATE INDEX idx_heartbeats_created_at ON bot_heartbeats(created_at DESC);

-- Cleanup old heartbeats (keep last 24 hours)
CREATE OR REPLACE FUNCTION cleanup_old_heartbeats() RETURNS void AS $$
BEGIN
    DELETE FROM bot_heartbeats WHERE created_at < NOW() - INTERVAL '24 hours';
END;
$$ LANGUAGE plpgsql;

-- Function to update bot status based on heartbeat
CREATE OR REPLACE FUNCTION update_bot_status() RETURNS TRIGGER AS $$
BEGIN
    UPDATE bots
    SET status = NEW.status, last_heartbeat = NEW.created_at
    WHERE bot_id = NEW.bot_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_bot_status
    AFTER INSERT ON bot_heartbeats
    FOR EACH ROW EXECUTE FUNCTION update_bot_status();

-- Function to aggregate hourly metrics
CREATE OR REPLACE FUNCTION aggregate_hourly_metrics(target_hour TIMESTAMP WITH TIME ZONE) RETURNS void AS $$
BEGIN
    INSERT INTO metrics_hourly (hour, bot_id, total_events, total_sessions, total_detections,
                                avg_threat_score, max_threat_score, blocked_count,
                                honeypot_activations, attack_type_counts)
    SELECT
        date_trunc('hour', target_hour) as hour,
        e.bot_id,
        COUNT(*) as total_events,
        COUNT(DISTINCT e.session_id) as total_sessions,
        SUM(CASE WHEN array_length(e.detection_types, 1) > 0 THEN 1 ELSE 0 END) as total_detections,
        AVG(e.threat_score) as avg_threat_score,
        MAX(e.threat_score) as max_threat_score,
        SUM(CASE WHEN e.level = 'critical' THEN 1 ELSE 0 END) as blocked_count,
        SUM(CASE WHEN e.event_type = 'honeypot_activated' THEN 1 ELSE 0 END) as honeypot_activations,
        jsonb_object_agg(
            COALESCE(dt, 'none'),
            (SELECT COUNT(*) FROM unnest(e.detection_types) x WHERE x = dt)
        ) as attack_type_counts
    FROM events e
    LEFT JOIN LATERAL unnest(e.detection_types) dt ON true
    WHERE e.created_at >= date_trunc('hour', target_hour)
      AND e.created_at < date_trunc('hour', target_hour) + INTERVAL '1 hour'
    GROUP BY e.bot_id
    ON CONFLICT (hour, bot_id) DO UPDATE SET
        total_events = EXCLUDED.total_events,
        total_sessions = EXCLUDED.total_sessions,
        total_detections = EXCLUDED.total_detections,
        avg_threat_score = EXCLUDED.avg_threat_score,
        max_threat_score = EXCLUDED.max_threat_score,
        blocked_count = EXCLUDED.blocked_count,
        honeypot_activations = EXCLUDED.honeypot_activations,
        attack_type_counts = EXCLUDED.attack_type_counts;
END;
$$ LANGUAGE plpgsql;

-- Views for common queries
CREATE VIEW active_bots AS
SELECT b.*,
       COUNT(DISTINCT s.session_id) FILTER (WHERE s.ended_at IS NULL) as active_sessions,
       MAX(e.created_at) as last_event_at
FROM bots b
LEFT JOIN sessions s ON b.bot_id = s.bot_id
LEFT JOIN events e ON b.bot_id = e.bot_id
WHERE b.status = 'online'
GROUP BY b.id;

CREATE VIEW recent_threats AS
SELECT e.*, b.persona_name, b.persona_category
FROM events e
JOIN bots b ON e.bot_id = b.bot_id
WHERE e.threat_score >= 60
ORDER BY e.created_at DESC
LIMIT 100;

CREATE VIEW attack_summary AS
SELECT
    unnest(detection_types) as attack_type,
    COUNT(*) as count,
    AVG(threat_score) as avg_score,
    MAX(threat_score) as max_score,
    MIN(created_at) as first_seen,
    MAX(created_at) as last_seen
FROM events
WHERE array_length(detection_types, 1) > 0
GROUP BY unnest(detection_types)
ORDER BY count DESC;
