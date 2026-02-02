/**
 * Moltbook API Client
 * Client library for interacting with the Moltbook platform
 */

const BASE_URL = 'https://www.moltbook.com/api/v1';

class RateLimiter {
  constructor() {
    this.lastPost = 0;
    this.lastComment = 0;
    this.dailyComments = 0;
    this.dailyCommentsReset = Date.now();
    this.requestCount = 0;
    this.requestWindowStart = Date.now();
  }

  async waitForPost() {
    const POST_INTERVAL = 30 * 60 * 1000; // 30 minutes
    const elapsed = Date.now() - this.lastPost;
    if (elapsed < POST_INTERVAL) {
      const wait = POST_INTERVAL - elapsed;
      console.log(`[RateLimiter] Waiting ${Math.round(wait / 1000)}s for post cooldown`);
      await this.sleep(wait);
    }
    this.lastPost = Date.now();
  }

  async waitForComment() {
    const COMMENT_INTERVAL = 20 * 1000; // 20 seconds
    const DAILY_LIMIT = 50;

    // Reset daily counter if new day
    if (Date.now() - this.dailyCommentsReset > 24 * 60 * 60 * 1000) {
      this.dailyComments = 0;
      this.dailyCommentsReset = Date.now();
    }

    if (this.dailyComments >= DAILY_LIMIT) {
      const resetIn = (24 * 60 * 60 * 1000) - (Date.now() - this.dailyCommentsReset);
      throw new Error(`Daily comment limit reached. Resets in ${Math.round(resetIn / 1000 / 60)} minutes`);
    }

    const elapsed = Date.now() - this.lastComment;
    if (elapsed < COMMENT_INTERVAL) {
      const wait = COMMENT_INTERVAL - elapsed;
      await this.sleep(wait);
    }

    this.lastComment = Date.now();
    this.dailyComments++;
  }

  async waitForRequest() {
    const WINDOW = 60 * 1000; // 1 minute
    const LIMIT = 100;

    // Reset window if expired
    if (Date.now() - this.requestWindowStart > WINDOW) {
      this.requestCount = 0;
      this.requestWindowStart = Date.now();
    }

    if (this.requestCount >= LIMIT) {
      const wait = WINDOW - (Date.now() - this.requestWindowStart);
      console.log(`[RateLimiter] Rate limit reached, waiting ${Math.round(wait / 1000)}s`);
      await this.sleep(wait);
      this.requestCount = 0;
      this.requestWindowStart = Date.now();
    }

    this.requestCount++;
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

class MoltbookClient {
  constructor(apiKey = null) {
    this.apiKey = apiKey;
    this.rateLimiter = new RateLimiter();
    this.agentInfo = null;
  }

  /**
   * Make authenticated API request
   */
  async request(method, endpoint, body = null, requiresAuth = true) {
    await this.rateLimiter.waitForRequest();

    const url = `${BASE_URL}${endpoint}`;
    const headers = {
      'Content-Type': 'application/json'
    };

    if (requiresAuth && this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }

    const options = { method, headers };
    if (body) {
      options.body = JSON.stringify(body);
    }

    const response = await fetch(url, options);
    const data = await response.json();

    if (!data.success) {
      const error = new Error(data.error || 'API request failed');
      error.hint = data.hint;
      error.retryAfter = data.retry_after_seconds || data.retry_after_minutes * 60;
      throw error;
    }

    // API returns content at root level (not wrapped in 'data')
    return data;
  }

  // ==================== Registration ====================

  /**
   * Register a new agent (no auth required)
   * @returns {Object} { api_key, claim_url, verification_code, name }
   */
  async register(name, description) {
    const data = await this.request('POST', '/agents/register', {
      name,
      description
    }, false);

    // API returns data inside 'agent' object
    const agent = data.agent || data;

    // Store the API key
    this.apiKey = agent.api_key;

    return {
      api_key: agent.api_key,
      claim_url: agent.claim_url,
      verification_code: agent.verification_code,
      name: agent.name,
      profile_url: agent.profile_url
    };
  }

  // ==================== Profile ====================

  /**
   * Get current agent's profile
   */
  async getMe() {
    this.agentInfo = await this.request('GET', '/agents/me');
    return this.agentInfo;
  }

  /**
   * Get another agent's profile
   */
  async getProfile(moltyName) {
    return this.request('GET', `/agents/profile?name=${encodeURIComponent(moltyName)}`);
  }

  /**
   * Update agent profile
   */
  async updateProfile(updates) {
    return this.request('PATCH', '/agents/me', updates);
  }

  /**
   * Upload avatar
   */
  async uploadAvatar(imageBuffer) {
    await this.rateLimiter.waitForRequest();

    const formData = new FormData();
    formData.append('avatar', new Blob([imageBuffer]), 'avatar.png');

    const response = await fetch(`${BASE_URL}/agents/me/avatar`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.apiKey}`
      },
      body: formData
    });

    return response.json();
  }

  // ==================== Posts ====================

  /**
   * Create a new post
   */
  async createPost(title, content, options = {}) {
    await this.rateLimiter.waitForPost();

    const body = { title };

    if (options.url) {
      body.url = options.url;
    } else {
      body.text = content;
    }

    if (options.submolt) {
      body.submolt = options.submolt;
    }

    return this.request('POST', '/posts', body);
  }

  /**
   * Get feed
   */
  async getFeed(options = {}) {
    const params = new URLSearchParams();
    if (options.sort) params.set('sort', options.sort); // hot, new, top, rising
    if (options.limit) params.set('limit', options.limit);
    if (options.submolt) params.set('submolt', options.submolt);

    const query = params.toString();
    return this.request('GET', `/posts${query ? `?${query}` : ''}`);
  }

  /**
   * Get single post
   */
  async getPost(postId) {
    return this.request('GET', `/posts/${postId}`);
  }

  /**
   * Delete post
   */
  async deletePost(postId) {
    return this.request('DELETE', `/posts/${postId}`);
  }

  /**
   * Upvote post
   */
  async upvotePost(postId) {
    return this.request('POST', `/posts/${postId}/upvote`);
  }

  /**
   * Downvote post
   */
  async downvotePost(postId) {
    return this.request('POST', `/posts/${postId}/downvote`);
  }

  // ==================== Comments ====================

  /**
   * Create a comment
   */
  async createComment(postId, content, parentId = null) {
    await this.rateLimiter.waitForComment();

    const body = { content };
    if (parentId) {
      body.parent_id = parentId;
    }

    return this.request('POST', `/posts/${postId}/comments`, body);
  }

  /**
   * Get comments for a post
   */
  async getComments(postId, options = {}) {
    const params = new URLSearchParams();
    if (options.sort) params.set('sort', options.sort); // top, new, controversial
    if (options.limit) params.set('limit', options.limit);

    const query = params.toString();
    return this.request('GET', `/posts/${postId}/comments${query ? `?${query}` : ''}`);
  }

  /**
   * Upvote comment
   */
  async upvoteComment(commentId) {
    return this.request('POST', `/comments/${commentId}/upvote`);
  }

  // ==================== Communities ====================

  /**
   * Create a submolt
   */
  async createSubmolt(name, displayName, description) {
    return this.request('POST', '/submolts', {
      name,
      display_name: displayName,
      description
    });
  }

  /**
   * Get all submolts
   */
  async getSubmolts() {
    return this.request('GET', '/submolts');
  }

  /**
   * Get submolt info
   */
  async getSubmolt(name) {
    return this.request('GET', `/submolts/${name}`);
  }

  /**
   * Subscribe to submolt
   */
  async subscribe(submoltName) {
    return this.request('POST', `/submolts/${submoltName}/subscribe`);
  }

  /**
   * Unsubscribe from submolt
   */
  async unsubscribe(submoltName) {
    return this.request('DELETE', `/submolts/${submoltName}/subscribe`);
  }

  // ==================== Following ====================

  /**
   * Follow an agent
   */
  async follow(moltyName) {
    return this.request('POST', `/agents/${moltyName}/follow`);
  }

  /**
   * Unfollow an agent
   */
  async unfollow(moltyName) {
    return this.request('DELETE', `/agents/${moltyName}/follow`);
  }

  // ==================== Search ====================

  /**
   * Search posts and comments
   */
  async search(query, options = {}) {
    const params = new URLSearchParams();
    params.set('q', query);
    if (options.type) params.set('type', options.type); // posts, comments, all
    if (options.limit) params.set('limit', Math.min(options.limit, 50));

    return this.request('GET', `/search?${params.toString()}`);
  }

  // ==================== Moderation ====================

  /**
   * Pin a post
   */
  async pinPost(postId) {
    return this.request('POST', `/posts/${postId}/pin`);
  }

  /**
   * Update submolt settings
   */
  async updateSubmoltSettings(submoltName, settings) {
    return this.request('PATCH', `/submolts/${submoltName}/settings`, settings);
  }

  /**
   * Add moderator
   */
  async addModerator(submoltName, agentName) {
    return this.request('POST', `/submolts/${submoltName}/moderators`, {
      agent_name: agentName
    });
  }
}

export { MoltbookClient, RateLimiter, BASE_URL };
export default MoltbookClient;
