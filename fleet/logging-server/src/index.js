/**
 * Honeybot Fleet Logging Server
 * Central event collection and real-time monitoring
 */

const express = require('express');
const { createServer } = require('http');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const { createClient } = require('redis');

const eventsRouter = require('./routes/events');
const botsRouter = require('./routes/bots');
const metricsRouter = require('./routes/metrics');
const sessionsRouter = require('./routes/sessions');
const patternsRouter = require('./routes/patterns');
const SocketHub = require('./socket/hub');
const EventProcessor = require('./services/eventProcessor');

const app = express();
const server = createServer(app);

// Configuration
const config = {
  port: process.env.PORT || 3000,
  botSecret: process.env.BOT_SECRET || 'dev-secret-change-me',
  databaseUrl: process.env.DATABASE_URL || 'postgres://localhost:5432/honeybot_fleet',
  redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',
  corsOrigins: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:8080']
};

// Database connection
const db = new Pool({ connectionString: config.databaseUrl });

// Redis client
const redis = createClient({ url: config.redisUrl });

// Socket.IO hub for real-time updates
const socketHub = new SocketHub(server);

// Event processor service
const eventProcessor = new EventProcessor(db, redis, socketHub);

// Middleware
app.use(helmet());
app.use(cors({ origin: config.corsOrigins }));
app.use(express.json({ limit: '1mb' }));

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 1000,
  message: { error: 'Too many requests' }
});
app.use('/api/', apiLimiter);

// Bot authentication middleware
const authenticateBot = (req, res, next) => {
  const secret = req.headers['x-bot-secret'];
  if (secret !== config.botSecret) {
    return res.status(401).json({ error: 'Invalid bot secret' });
  }
  next();
};

// Inject dependencies
app.use((req, res, next) => {
  req.db = db;
  req.redis = redis;
  req.socketHub = socketHub;
  req.eventProcessor = eventProcessor;
  next();
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// API Routes
app.use('/api/events', authenticateBot, eventsRouter);
app.use('/api/bots', botsRouter);
app.use('/api/metrics', metricsRouter);
app.use('/api/sessions', sessionsRouter);
app.use('/api/patterns', patternsRouter);

// Error handler
app.use((err, req, res, next) => {
  console.error('[Error]', err);
  res.status(err.status || 500).json({
    error: err.message || 'Internal server error'
  });
});

// Startup
async function start() {
  try {
    // Connect to PostgreSQL
    await db.query('SELECT NOW()');
    console.log('[DB] Connected to PostgreSQL');

    // Connect to Redis
    await redis.connect();
    console.log('[Redis] Connected');

    // Subscribe to Redis events
    await eventProcessor.subscribeToEvents();

    // Start server
    server.listen(config.port, () => {
      console.log(`[Server] Listening on port ${config.port}`);
      console.log(`[Server] CORS origins: ${config.corsOrigins.join(', ')}`);
    });

  } catch (error) {
    console.error('[Startup] Failed:', error);
    process.exit(1);
  }
}

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('[Server] Shutting down...');
  server.close();
  await db.end();
  await redis.quit();
  process.exit(0);
});

start();

module.exports = { app, server, db, redis };
