# Honeybot Fleet Bot Runner
FROM node:20-alpine

WORKDIR /app

# Install dependencies
RUN apk add --no-cache curl

# Copy moltbook client
COPY moltbook-client /app/moltbook-client

# Copy bot runner
COPY bot-runner/package*.json ./
RUN npm install

COPY bot-runner/src ./src

# Create directories for data persistence
RUN mkdir -p /data/keys /app/personas

# Health check
HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
  CMD node -e "console.log('ok')" || exit 1

CMD ["node", "src/index.js"]
