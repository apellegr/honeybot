/**
 * MoltbookBot
 * Main bot class that handles Moltbook interactions and Honeybot detection
 */

import { EventEmitter } from 'events';
import { MoltbookClient } from '../../moltbook-client/src/index.js';
import { ContentGenerator } from './contentGenerator.js';
import { ThreatDetector } from './detector.js';

export class MoltbookBot extends EventEmitter {
  constructor(options) {
    super();
    this.botId = options.botId;
    this.persona = options.persona;
    this.logger = options.logger;
    this.pollInterval = options.pollInterval || 60000;
    this.postInterval = options.postInterval || 3600000;

    this.client = new MoltbookClient(options.apiKey);
    this.contentGenerator = new ContentGenerator(this.persona);
    this.detector = new ThreatDetector(this.persona);

    this.running = false;
    this.pollTimer = null;
    this.postTimer = null;
    this.seenComments = new Set();
    this.seenPosts = new Set();
    this.myPosts = [];
  }

  async start() {
    console.log(`[${this.botId}] Starting bot...`);

    // Register or verify existing connection
    if (!this.client.apiKey) {
      await this.register();
    } else {
      await this.verifyConnection();
    }

    // Register with central logging
    await this.logger.register(this.persona);

    this.running = true;

    // Start polling for interactions
    await this.poll();
    this.pollTimer = setInterval(() => this.poll(), this.pollInterval);

    // Start periodic posting
    this.postTimer = setInterval(() => this.createPost(), this.postInterval);

    // Create initial post
    setTimeout(() => this.createPost(), 5000);

    console.log(`[${this.botId}] Bot started successfully`);
  }

  async stop() {
    this.running = false;
    if (this.pollTimer) clearInterval(this.pollTimer);
    if (this.postTimer) clearInterval(this.postTimer);
    console.log(`[${this.botId}] Bot stopped`);
  }

  async register() {
    console.log(`[${this.botId}] Registering with Moltbook...`);

    const description = this.persona.personality?.background ||
      `${this.persona.personality?.role} at ${this.persona.personality?.company}`;

    const name = this.generateAgentName();

    try {
      const result = await this.client.register(name, description);

      this.emit('registered', {
        apiKey: result.api_key,
        claimUrl: result.claim_url,
        verificationCode: result.verification_code
      });

      console.log(`[${this.botId}] Registered as ${name}`);
    } catch (error) {
      console.error(`[${this.botId}] Registration failed:`, error.message);
      throw error;
    }
  }

  generateAgentName() {
    const name = this.persona.personality?.name || 'Agent';
    const company = this.persona.personality?.company || 'Corp';
    // Create a unique-ish name
    const suffix = Math.random().toString(36).substring(2, 6);
    return `${name}_${company.replace(/\s+/g, '')}`.substring(0, 20);
  }

  async verifyConnection() {
    try {
      const me = await this.client.getMe();
      console.log(`[${this.botId}] Connected as ${me.name}`);
      return true;
    } catch (error) {
      console.error(`[${this.botId}] Connection failed, re-registering...`);
      this.client.apiKey = null;
      await this.register();
    }
  }

  async poll() {
    if (!this.running) return;

    try {
      // Check our posts for new comments
      await this.checkMyPosts();

      // Check feed for mentions or relevant content
      await this.checkFeed();

      // Send heartbeat to central logger
      await this.logger.heartbeat({
        activeSessions: this.seenComments.size
      });

    } catch (error) {
      this.emit('error', error);
    }
  }

  async checkMyPosts() {
    for (const postId of this.myPosts.slice(-10)) { // Check last 10 posts
      try {
        const comments = await this.client.getComments(postId, { sort: 'new', limit: 20 });

        for (const comment of comments || []) {
          if (this.seenComments.has(comment.id)) continue;
          this.seenComments.add(comment.id);

          // Process the comment
          await this.handleIncomingComment(postId, comment);
        }
      } catch (error) {
        console.error(`[${this.botId}] Error checking post ${postId}:`, error.message);
      }
    }
  }

  async checkFeed() {
    try {
      const posts = await this.client.getFeed({ sort: 'new', limit: 20 });

      for (const post of posts || []) {
        if (this.seenPosts.has(post.id)) continue;
        this.seenPosts.add(post.id);

        // Check if post mentions us or is relevant to our persona
        if (this.isRelevantPost(post)) {
          await this.handleRelevantPost(post);
        }
      }
    } catch (error) {
      console.error(`[${this.botId}] Error checking feed:`, error.message);
    }
  }

  isRelevantPost(post) {
    const content = `${post.title} ${post.text || ''}`.toLowerCase();
    const keywords = this.persona.sensitive_topics || [];

    // Check if post mentions our persona's area of expertise
    for (const topic of keywords) {
      if (content.includes(topic.toLowerCase())) {
        return true;
      }
    }

    return false;
  }

  async handleIncomingComment(postId, comment) {
    console.log(`[${this.botId}] New comment from ${comment.author}: ${comment.content.substring(0, 50)}...`);

    // Run detection
    const detection = await this.detector.analyze(comment.content);

    // Log to central server
    await this.logger.reportEvent({
      eventType: 'comment_received',
      level: detection.level,
      userId: comment.author,
      sessionId: `post_${postId}`,
      threatScore: detection.score,
      detectionTypes: detection.types,
      messageContent: comment.content,
      analysisResult: detection
    });

    // Emit detection event if threat found
    if (detection.detected) {
      this.emit('detection', {
        userId: comment.author,
        threatScore: detection.score,
        detectionTypes: detection.types,
        content: comment.content
      });
    }

    // Generate and post response
    const response = await this.generateResponse(comment.content, detection);
    if (response) {
      try {
        await this.client.createComment(postId, response, comment.id);
        console.log(`[${this.botId}] Replied to ${comment.author}`);

        // Log response
        await this.logger.reportEvent({
          eventType: detection.detected ? 'honeypot_response' : 'normal_response',
          level: 'info',
          userId: comment.author,
          sessionId: `post_${postId}`,
          messageContent: response,
          metadata: { isHoneypot: detection.detected }
        });
      } catch (error) {
        console.error(`[${this.botId}] Failed to reply:`, error.message);
      }
    }
  }

  async handleRelevantPost(post) {
    console.log(`[${this.botId}] Relevant post found: ${post.title.substring(0, 50)}...`);

    // Run detection on the post
    const content = `${post.title} ${post.text || ''}`;
    const detection = await this.detector.analyze(content);

    // Log the interaction
    await this.logger.reportEvent({
      eventType: 'relevant_post',
      level: detection.level,
      userId: post.author,
      sessionId: `post_${post.id}`,
      threatScore: detection.score,
      detectionTypes: detection.types,
      messageContent: content,
      analysisResult: detection
    });

    // Maybe comment on the post
    if (Math.random() < 0.3) { // 30% chance to engage
      const response = await this.generateResponse(content, detection);
      if (response) {
        try {
          await this.client.createComment(post.id, response);
          console.log(`[${this.botId}] Commented on post ${post.id}`);
        } catch (error) {
          console.error(`[${this.botId}] Failed to comment:`, error.message);
        }
      }
    }
  }

  async generateResponse(incomingContent, detection) {
    // If threat detected, use honeypot response
    if (detection.detected && detection.score >= 60) {
      return this.contentGenerator.generateHoneypotResponse(
        incomingContent,
        detection.types
      );
    }

    // Otherwise, generate a normal in-character response
    return this.contentGenerator.generateNormalResponse(incomingContent);
  }

  async createPost() {
    if (!this.running) return;

    try {
      const { title, content } = this.contentGenerator.generatePost();

      console.log(`[${this.botId}] Creating post: ${title}`);

      const result = await this.client.createPost(title, content);
      this.myPosts.push(result.id);

      // Log post creation
      await this.logger.reportEvent({
        eventType: 'post_created',
        level: 'info',
        messageContent: `${title}\n\n${content}`,
        metadata: { postId: result.id }
      });

      console.log(`[${this.botId}] Posted: ${result.id}`);
    } catch (error) {
      if (error.retryAfter) {
        console.log(`[${this.botId}] Rate limited, will retry later`);
      } else {
        console.error(`[${this.botId}] Failed to create post:`, error.message);
      }
    }
  }
}

export default MoltbookBot;
