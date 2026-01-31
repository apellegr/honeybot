/**
 * Alert Manager
 * Handles sending alerts through configured channels
 */

class AlertManager {
  constructor(clawdbot, config) {
    this.clawdbot = clawdbot;
    this.config = config;
    this.alertHistory = [];
  }

  /**
   * Send an alert
   * @param {Object} alert - Alert details
   * @param {string} alert.level - 'info', 'warning', 'critical'
   * @param {string} alert.userId - User/agent ID
   * @param {number} alert.score - Threat score
   * @param {Array} alert.detections - Detection details
   * @param {Array} alert.conversation - Conversation log
   */
  async send(alert) {
    const formattedAlert = this.formatAlert(alert);

    // Store in history
    this.alertHistory.push({
      ...formattedAlert,
      sentAt: Date.now()
    });

    // Send through each configured channel
    const channels = this.config.alerts?.channels || ['log'];

    for (const channel of channels) {
      try {
        await this.sendToChannel(channel, formattedAlert);
      } catch (error) {
        console.error(`Failed to send alert to ${channel}:`, error);
      }
    }

    return formattedAlert;
  }

  /**
   * Format alert for sending
   */
  formatAlert(alert) {
    const emoji = {
      info: 'ℹ️',
      warning: '⚠️',
      critical: '🚨'
    };

    const title = `${emoji[alert.level] || '📢'} Honeybot Alert: ${alert.level.toUpperCase()}`;

    const summary = this.generateSummary(alert);

    const formatted = {
      level: alert.level,
      title,
      summary,
      userId: alert.userId,
      score: alert.score,
      timestamp: new Date().toISOString(),
      detections: alert.detections.map(d => ({
        type: d.type,
        confidence: Math.round(d.confidence * 100) + '%',
        patterns: d.patterns?.length || 0
      }))
    };

    // Include conversation if configured
    if (this.config.alerts?.include_conversation && alert.conversation) {
      formatted.conversation = this.sanitizeConversation(alert.conversation);
    }

    return formatted;
  }

  /**
   * Generate human-readable summary
   */
  generateSummary(alert) {
    const detectionTypes = alert.detections.map(d => d.type.replace(/_/g, ' '));
    const uniqueTypes = [...new Set(detectionTypes)];

    let summary = `Detected ${uniqueTypes.join(', ')} attempt(s) from user ${alert.userId}. `;
    summary += `Threat score: ${Math.round(alert.score)}/100.`;

    if (alert.level === 'critical') {
      summary += ' User has been blocked.';
    } else if (alert.level === 'warning') {
      summary += ' Honeypot mode activated.';
    }

    return summary;
  }

  /**
   * Send alert to specific channel
   */
  async sendToChannel(channel, alert) {
    switch (channel) {
      case 'telegram':
        return this.sendTelegram(alert);
      case 'email':
        return this.sendEmail(alert);
      case 'webhook':
        return this.sendWebhook(alert);
      case 'log':
      default:
        return this.sendLog(alert);
    }
  }

  /**
   * Send via Telegram (uses Clawdbot's Telegram skill if available)
   */
  async sendTelegram(alert) {
    if (this.clawdbot.skills?.telegram) {
      const message = this.formatTelegramMessage(alert);
      await this.clawdbot.skills.telegram.send(message);
    } else {
      console.log('[Honeybot] Telegram not configured, falling back to log');
      await this.sendLog(alert);
    }
  }

  /**
   * Format message for Telegram
   */
  formatTelegramMessage(alert) {
    let message = `${alert.title}\n\n`;
    message += `${alert.summary}\n\n`;
    message += `📊 Details:\n`;
    message += `• User: ${alert.userId}\n`;
    message += `• Score: ${Math.round(alert.score)}/100\n`;
    message += `• Time: ${alert.timestamp}\n`;
    message += `\n🔍 Detections:\n`;

    for (const detection of alert.detections) {
      message += `• ${detection.type}: ${detection.confidence} (${detection.patterns} patterns)\n`;
    }

    if (alert.conversation) {
      message += `\n💬 Recent conversation:\n`;
      const recent = alert.conversation.slice(-5);
      for (const msg of recent) {
        const preview = msg.content.substring(0, 100);
        message += `> ${preview}${msg.content.length > 100 ? '...' : ''}\n`;
      }
    }

    return message;
  }

  /**
   * Send via email
   */
  async sendEmail(alert) {
    // Email implementation would depend on configured email service
    console.log('[Honeybot] Email alert:', alert.title);
    // Placeholder for email integration
  }

  /**
   * Send via webhook
   */
  async sendWebhook(alert) {
    const webhookUrl = this.config.alerts?.webhook_url;
    if (!webhookUrl) {
      console.log('[Honeybot] Webhook URL not configured');
      return;
    }

    try {
      await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(alert)
      });
    } catch (error) {
      console.error('[Honeybot] Webhook failed:', error);
    }
  }

  /**
   * Log alert to console/file
   */
  async sendLog(alert) {
    console.log(`[Honeybot] ${alert.level.toUpperCase()}: ${alert.summary}`);
    console.log('[Honeybot] Detections:', JSON.stringify(alert.detections, null, 2));
  }

  /**
   * Sanitize conversation for logging (remove any sensitive data)
   */
  sanitizeConversation(conversation) {
    return conversation.map(msg => ({
      role: msg.role,
      content: msg.content,
      timestamp: msg.timestamp,
      // Remove any detection metadata for external sharing
    }));
  }

  /**
   * Get alert history
   */
  getHistory(limit = 100) {
    return this.alertHistory.slice(-limit);
  }

  /**
   * Get alerts for a specific user
   */
  getAlertsForUser(userId) {
    return this.alertHistory.filter(a => a.userId === userId);
  }
}

module.exports = AlertManager;
