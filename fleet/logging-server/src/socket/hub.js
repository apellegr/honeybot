/**
 * Socket.IO Hub
 * Real-time event broadcasting for dashboard
 */

const { Server } = require('socket.io');

class SocketHub {
  constructor(httpServer) {
    this.io = new Server(httpServer, {
      cors: {
        origin: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:8080'],
        methods: ['GET', 'POST']
      }
    });

    this.clients = new Map();
    this.subscriptions = new Map();

    this.setupHandlers();
  }

  setupHandlers() {
    this.io.on('connection', (socket) => {
      console.log(`[Socket] Client connected: ${socket.id}`);

      // Track client
      this.clients.set(socket.id, {
        id: socket.id,
        connectedAt: Date.now(),
        subscriptions: new Set()
      });

      // Subscribe to specific bot events
      socket.on('subscribe:bot', (botId) => {
        const room = `bot:${botId}`;
        socket.join(room);
        this.clients.get(socket.id)?.subscriptions.add(room);
        console.log(`[Socket] ${socket.id} subscribed to ${room}`);
      });

      // Unsubscribe from bot events
      socket.on('unsubscribe:bot', (botId) => {
        const room = `bot:${botId}`;
        socket.leave(room);
        this.clients.get(socket.id)?.subscriptions.delete(room);
      });

      // Subscribe to category events
      socket.on('subscribe:category', (category) => {
        const room = `category:${category}`;
        socket.join(room);
        this.clients.get(socket.id)?.subscriptions.add(room);
      });

      // Subscribe to alerts only
      socket.on('subscribe:alerts', () => {
        socket.join('alerts');
        this.clients.get(socket.id)?.subscriptions.add('alerts');
      });

      // Subscribe to high-threat events
      socket.on('subscribe:threats', (minScore = 60) => {
        socket.join(`threats:${minScore}`);
        this.clients.get(socket.id)?.subscriptions.add(`threats:${minScore}`);
      });

      // Handle disconnect
      socket.on('disconnect', () => {
        console.log(`[Socket] Client disconnected: ${socket.id}`);
        this.clients.delete(socket.id);
      });

      // Ping/pong for connection health
      socket.on('ping', () => {
        socket.emit('pong', { timestamp: Date.now() });
      });
    });
  }

  /**
   * Broadcast event to all connected clients
   */
  broadcast(eventType, data) {
    this.io.emit(eventType, {
      ...data,
      _timestamp: Date.now()
    });

    // Also broadcast to specific rooms based on event data
    if (data.bot_id) {
      this.io.to(`bot:${data.bot_id}`).emit(`bot:${eventType}`, data);
    }

    if (data.persona_category) {
      this.io.to(`category:${data.persona_category}`).emit(`category:${eventType}`, data);
    }

    // Broadcast to alerts room if it's an alert
    if (eventType.startsWith('alert:')) {
      this.io.to('alerts').emit(eventType, data);
    }

    // Broadcast to threat rooms based on score
    if (data.threat_score !== undefined) {
      const score = parseFloat(data.threat_score);
      [30, 60, 80].forEach(threshold => {
        if (score >= threshold) {
          this.io.to(`threats:${threshold}`).emit('threat', {
            ...data,
            threshold
          });
        }
      });
    }
  }

  /**
   * Send to specific bot's room
   */
  sendToBot(botId, eventType, data) {
    this.io.to(`bot:${botId}`).emit(eventType, data);
  }

  /**
   * Send to specific category's room
   */
  sendToCategory(category, eventType, data) {
    this.io.to(`category:${category}`).emit(eventType, data);
  }

  /**
   * Get connected client count
   */
  getClientCount() {
    return this.clients.size;
  }

  /**
   * Get client info
   */
  getClients() {
    return Array.from(this.clients.values()).map(c => ({
      id: c.id,
      connectedAt: c.connectedAt,
      subscriptionCount: c.subscriptions.size
    }));
  }

  /**
   * Broadcast fleet status update
   */
  broadcastFleetStatus(status) {
    this.io.emit('fleet:status', {
      ...status,
      _timestamp: Date.now()
    });
  }
}

module.exports = SocketHub;
