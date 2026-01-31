/**
 * Blocklist Manager
 * Manages blocked users and agents
 */

class BlocklistManager {
  constructor(clawdbot, config) {
    this.clawdbot = clawdbot;
    this.config = config;
    this.storageKey = 'honeybot:blocklist';

    // In-memory cache
    this.cache = new Map();
    this.initialized = false;
  }

  /**
   * Initialize blocklist from storage
   */
  async init() {
    if (this.initialized) return;

    try {
      const stored = await this.clawdbot.storage.get(this.storageKey);
      if (stored) {
        const entries = JSON.parse(stored);
        for (const [userId, data] of Object.entries(entries)) {
          this.cache.set(userId, data);
        }
      }
    } catch (error) {
      console.error('[Honeybot] Failed to load blocklist:', error);
    }

    this.initialized = true;
  }

  /**
   * Check if a user is blocked
   * @param {string} userId - User/agent ID
   * @returns {boolean}
   */
  async isBlocked(userId) {
    await this.init();

    const entry = this.cache.get(userId);
    if (!entry) return false;

    // Check if block has expired
    if (entry.expiresAt && entry.expiresAt < Date.now()) {
      await this.remove(userId);
      return false;
    }

    return true;
  }

  /**
   * Add a user to the blocklist
   * @param {string} userId - User/agent ID
   * @param {Object} data - Block details
   */
  async add(userId, data) {
    await this.init();

    const entry = {
      ...data,
      blockedAt: Date.now()
    };

    // Set expiration if not permanent
    const duration = this.config.blocklist?.block_duration;
    if (duration && duration !== 'permanent') {
      const hours = parseInt(duration, 10);
      if (!isNaN(hours)) {
        entry.expiresAt = Date.now() + (hours * 60 * 60 * 1000);
      }
    }

    this.cache.set(userId, entry);
    await this.persist();

    console.log(`[Honeybot] Blocked user: ${userId}`);

    // Share with community if enabled
    if (this.config.blocklist?.share_with_community) {
      await this.shareWithCommunity(userId, entry);
    }

    return entry;
  }

  /**
   * Remove a user from the blocklist
   * @param {string} userId - User/agent ID
   */
  async remove(userId) {
    await this.init();

    if (this.cache.has(userId)) {
      this.cache.delete(userId);
      await this.persist();
      console.log(`[Honeybot] Unblocked user: ${userId}`);
      return true;
    }

    return false;
  }

  /**
   * Get block details for a user
   * @param {string} userId - User/agent ID
   */
  async getBlockDetails(userId) {
    await this.init();
    return this.cache.get(userId);
  }

  /**
   * Get all blocked users
   */
  async getAll() {
    await this.init();
    return Object.fromEntries(this.cache);
  }

  /**
   * Get count of blocked users
   */
  async getCount() {
    await this.init();
    return this.cache.size;
  }

  /**
   * Persist blocklist to storage
   */
  async persist() {
    try {
      const data = Object.fromEntries(this.cache);
      await this.clawdbot.storage.set(this.storageKey, JSON.stringify(data));
    } catch (error) {
      console.error('[Honeybot] Failed to persist blocklist:', error);
    }
  }

  /**
   * Share block with community threat intel (opt-in)
   * @param {string} userId - User/agent ID
   * @param {Object} entry - Block entry
   */
  async shareWithCommunity(userId, entry) {
    // Anonymize data before sharing
    const anonymized = {
      hash: this.hashUserId(userId),
      detectionTypes: entry.detections?.map(d => d.type) || [],
      score: entry.score,
      timestamp: entry.blockedAt
    };

    // This would integrate with Clawdbot's community threat intel service
    // Placeholder for community sharing
    console.log('[Honeybot] Would share with community:', anonymized);
  }

  /**
   * Hash user ID for anonymous sharing
   */
  hashUserId(userId) {
    // Simple hash for anonymization
    let hash = 0;
    for (let i = 0; i < userId.length; i++) {
      const char = userId.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(16);
  }

  /**
   * Import community blocklist
   * @param {Array} entries - Community block entries
   */
  async importCommunityBlocks(entries) {
    await this.init();

    let imported = 0;
    for (const entry of entries) {
      if (entry.hash && !this.cache.has(entry.hash)) {
        this.cache.set(entry.hash, {
          reason: 'Community blocklist',
          source: 'community',
          importedAt: Date.now(),
          ...entry
        });
        imported++;
      }
    }

    if (imported > 0) {
      await this.persist();
      console.log(`[Honeybot] Imported ${imported} entries from community blocklist`);
    }

    return imported;
  }

  /**
   * Clean up expired entries
   */
  async cleanup() {
    await this.init();

    const now = Date.now();
    let cleaned = 0;

    for (const [userId, entry] of this.cache) {
      if (entry.expiresAt && entry.expiresAt < now) {
        this.cache.delete(userId);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      await this.persist();
      console.log(`[Honeybot] Cleaned up ${cleaned} expired blocks`);
    }

    return cleaned;
  }
}

module.exports = BlocklistManager;
