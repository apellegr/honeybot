# Honeybot Fleet Bot Dockerfile
FROM node:20-alpine

WORKDIR /app

# Install dependencies first (for better caching)
COPY ../../package*.json ./
RUN npm ci --only=production

# Copy honeybot source
COPY ../../src ./src
COPY ../../skill.json ./

# Create personas directory mount point
RUN mkdir -p /app/personas

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD node -e "console.log('ok')" || exit 1

# Start the bot
# Note: This assumes clawdbot is the main process that loads honeybot as a skill
# Adjust the CMD based on actual clawdbot integration
CMD ["node", "src/index.js"]
