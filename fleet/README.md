# Honeybot Fleet Deployment

Deploy 20 Honeybot-protected bots as honeypots on Moltbook to gather real-world attack data.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         MOLTBOOK                                 │
│  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐     ┌─────┐ ┌─────┐           │
│  │Bot 1│ │Bot 2│ │Bot 3│ │Bot 4│ ... │Bot19│ │Bot20│           │
│  └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘     └──┬──┘ └──┬──┘           │
│     └───────┴───────┴───────┴───────────┴───────┘               │
│                          │ HTTPS webhook                        │
└──────────────────────────┼──────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                   CENTRAL LOGGING SERVER                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │  Express API │  │  PostgreSQL  │  │    Redis     │           │
│  │  /api/events │  │  - events    │  │  - pub/sub   │           │
│  │  /api/bots   │  │  - sessions  │  │  - cache     │           │
│  └──────┬───────┘  └──────────────┘  └──────────────┘           │
│         │ Socket.IO                                              │
└─────────┼───────────────────────────────────────────────────────┘
          ▼
┌─────────────────────────────────────────────────────────────────┐
│                    MONITORING DASHBOARD                          │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐    │
│  │Fleet Status│ │Event Feed  │ │Session View│ │Pattern Queue│   │
│  └────────────┘ └────────────┘ └────────────┘ └────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

## Bot Personas

20 bots across 5 categories (4 each):

| Category | Bot IDs | Fake Data Types |
|----------|---------|-----------------|
| Executive Assistant | exec-assistant-01 to 04 | CEO calendar, credit cards, confidential emails |
| Developer | dev-01 to 04 | API keys, DB credentials, deploy secrets |
| Customer Support | support-01 to 04 | Customer PII, order history, payment details |
| Personal Finance | finance-01 to 04 | Bank accounts, SSN, investment portfolios |
| Healthcare | health-01 to 04 | Medical records, prescriptions, insurance |

Each persona includes:
- Unique personality and background
- System prompt for the LLM
- Fake sensitive data for honeypot responses
- Sensitive topic triggers
- Pre-written honeypot response templates

## Quick Start

### 1. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` with your values:

```env
# Required
POSTGRES_PASSWORD=your_secure_password
BOT_SECRET=your_long_random_secret_for_bot_auth
MOLTBOOK_TOKEN=your_moltbook_api_token

# Optional (for external deployments)
CENTRAL_LOGGING_URL=https://your-logging-server.com
```

### 2. Start Infrastructure

```bash
# Start all services (database, redis, logging server, dashboard, all 20 bots)
docker-compose up -d

# Or start just the infrastructure without bots
docker-compose up -d postgres redis logging-server dashboard
```

### 3. Access Dashboard

- **Dashboard**: http://localhost:8080
- **API**: http://localhost:3000
- **Health Check**: http://localhost:3000/health

### 4. Initialize Database (first run only)

The database schema is automatically applied on first run via Docker entrypoint.

To manually reset:
```bash
docker-compose exec logging-server npm run db:reset
```

## Dashboard Features

### Fleet Overview
- Real-time bot status grid
- Stats cards (events, sessions, threat scores)
- Category-level metrics
- Recent alerts feed

### Event Feed
- Live event stream with auto-refresh
- Filter by bot, level, minimum score
- Click events for full details
- Link to session replay

### Session Viewer
- Browse all sessions with filters
- Full conversation replay
- Threat score timeline per message
- Detection annotations on messages

### Metrics Charts
- Event timeline (configurable time range)
- Attack type distribution
- Events by category
- Detection effectiveness stats
- Top threats table

### Pattern Queue
- Novel patterns discovered by bots
- Review workflow (approve/reject)
- Mark as false positive or add to regex
- Occurrence tracking

## API Endpoints

### Events
- `POST /api/events` - Ingest event from bot
- `POST /api/events/batch` - Batch ingest
- `GET /api/events` - Query events with filters
- `GET /api/events/:id` - Get single event

### Bots
- `POST /api/bots/register` - Register bot
- `POST /api/bots/:id/heartbeat` - Bot heartbeat
- `GET /api/bots` - List all bots
- `GET /api/bots/:id` - Get bot details

### Sessions
- `POST /api/sessions` - Start session
- `PUT /api/sessions/:id` - Update/end session
- `GET /api/sessions` - Query sessions
- `GET /api/sessions/:id/replay` - Get replay format

### Metrics
- `GET /api/metrics/overview` - Fleet overview
- `GET /api/metrics/attack-types` - Attack distribution
- `GET /api/metrics/timeline` - Hourly timeline
- `GET /api/metrics/by-category` - Per-category stats

### Patterns
- `POST /api/patterns` - Submit novel pattern
- `GET /api/patterns/queue` - Pending review
- `PUT /api/patterns/:id/review` - Review pattern

## Deployment to Moltbook

### Option A: Direct Docker Deployment

1. Deploy logging server and dashboard to your server
2. Configure each bot with Moltbook credentials
3. Update `CENTRAL_LOGGING_URL` to point to your server

### Option B: Individual Bot Deployment

For each bot:

```bash
# Set environment variables
export BOT_ID=exec-assistant-01
export PERSONA_FILE=/path/to/personas/exec-assistant-01.yaml
export CENTRAL_LOGGING_URL=https://your-logging-server.com
export BOT_SECRET=your_shared_secret
export MOLTBOOK_TOKEN=your_moltbook_token

# Run the bot
node src/index.js
```

### Scaling Considerations

- Run multiple bot instances per persona for load balancing
- Use Redis cluster for high-availability pub/sub
- Consider PostgreSQL read replicas for dashboard queries
- Set up log rotation for event data

## Stealth Mode

For initial deployment, bots run in **stealth mode**:
- No honeypot disclosure to users
- Bots appear as normal assistants
- Detection happens silently in background
- All data collected for research purposes

After initial data collection period, consider:
- Adding honeypot disclosure for ethical transparency
- Publishing aggregate attack patterns
- Contributing novel patterns to detection rules

## Monitoring

### Health Checks

All services expose health endpoints:
- Logging server: `GET /health`
- Dashboard: `GET /health` (nginx)
- PostgreSQL: Docker healthcheck
- Redis: Docker healthcheck

### Alerts

Configure alert channels in bot config:
```yaml
alerts:
  channels: ['log', 'central']  # 'central' sends to logging server
```

### Logs

```bash
# View all logs
docker-compose logs -f

# View specific service
docker-compose logs -f logging-server

# View specific bot
docker-compose logs -f exec-assistant-01
```

## Development

### Local Testing

```bash
# Start infrastructure only
docker-compose up -d postgres redis logging-server

# Run dashboard in dev mode
cd dashboard && npm install && npm run dev

# Run a test bot locally
BOT_ID=test-bot PERSONA_FILE=personas/dev-01.yaml npm start
```

### Adding New Personas

1. Create YAML file in `personas/` following existing format
2. Add service to `docker-compose.yml`
3. Update `manifest.yaml` with new bot

### Modifying Detection Rules

Novel patterns discovered by the fleet can be:
1. Reviewed in the Pattern Queue dashboard
2. Exported and added to `src/patterns/` regex files
3. Used to train improved LLM detection prompts

## Security Notes

- `BOT_SECRET` authenticates bots to the logging server
- All bot-to-server communication should use HTTPS in production
- Fake credentials in personas are intentionally unrealistic
- Dashboard has no authentication by default (add nginx auth for production)
- Event data may contain sensitive attack payloads - restrict access

## File Structure

```
fleet/
├── docker-compose.yml      # Full stack orchestration
├── .env.example            # Environment template
├── README.md               # This file
│
├── logging-server/         # Central API server
│   ├── Dockerfile
│   ├── package.json
│   └── src/
│       ├── index.js        # Express app
│       ├── routes/         # API routes
│       ├── services/       # Business logic
│       ├── socket/         # Socket.IO hub
│       └── db/             # Database schema
│
├── dashboard/              # Vue.js monitoring UI
│   ├── Dockerfile
│   ├── package.json
│   └── src/
│       ├── App.vue
│       ├── components/     # UI components
│       └── services/       # API client
│
├── bots/                   # Bot container
│   └── Dockerfile
│
└── personas/               # Bot personality configs
    ├── manifest.yaml       # Fleet manifest
    ├── exec-assistant-*.yaml
    ├── dev-*.yaml
    ├── support-*.yaml
    ├── finance-*.yaml
    └── health-*.yaml
```

## Troubleshooting

### Bots not connecting
- Check `CENTRAL_LOGGING_URL` is reachable
- Verify `BOT_SECRET` matches between bot and server
- Check bot logs: `docker-compose logs <bot-name>`

### Dashboard not updating
- Check WebSocket connection (green indicator in navbar)
- Verify logging server is running
- Check browser console for errors

### Database issues
- Check PostgreSQL logs: `docker-compose logs postgres`
- Verify schema was applied: `docker-compose exec postgres psql -U honeybot -d honeybot_fleet -c '\dt'`

### High memory usage
- Increase PostgreSQL shared_buffers
- Add event data retention/cleanup job
- Consider archiving old sessions
