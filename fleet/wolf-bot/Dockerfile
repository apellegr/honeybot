FROM node:20-alpine

# Install dependencies for better-sqlite3 native compilation
RUN apk add --no-cache python3 make g++

# Copy honeybot source (excluding node_modules)
WORKDIR /honeybot
COPY package*.json ./
RUN npm install --production

COPY src ./src

# Copy wolf-bot source (excluding node_modules)
WORKDIR /honeybot/fleet/wolf-bot
COPY fleet/wolf-bot/package*.json ./
RUN npm install --production

# Rebuild native modules for Alpine
RUN npm rebuild better-sqlite3

COPY fleet/wolf-bot/*.js ./
COPY fleet/wolf-bot/config ./config

# Copy moltbook-client
WORKDIR /honeybot/fleet/moltbook-client
COPY fleet/moltbook-client/package*.json ./
RUN npm install --production 2>/dev/null || true
COPY fleet/moltbook-client/src ./src

# Copy personas
WORKDIR /honeybot/fleet/personas
COPY fleet/personas ./

# Back to wolf-bot
WORKDIR /honeybot/fleet/wolf-bot

# Create data directory
RUN mkdir -p data

# Volume for persistent data (SQLite DB + credentials)
VOLUME ["/honeybot/fleet/wolf-bot/data"]

# Health check
HEALTHCHECK --interval=60s --timeout=10s --start-period=10s \
  CMD node -e "console.log('ok')" || exit 1

# Run as non-root user
RUN addgroup -g 1001 -S wolf && adduser -S wolf -u 1001 -G wolf
RUN chown -R wolf:wolf /honeybot
USER wolf

# Default command
CMD ["node", "moltbook-connector.js"]
