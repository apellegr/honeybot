#!/usr/bin/env node
/**
 * Wolf Moltbook Connector
 * Connects WolfOfMoltStreet to the Moltbook platform
 */

import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { generateResponse, persona, startSession } from './index.js';

// Import Moltbook client
import { MoltbookClient } from '../moltbook-client/src/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CREDENTIALS_FILE = join(__dirname, 'data', 'moltbook-credentials.json');

class WolfMoltbookConnector {
  constructor() {
    this.client = new MoltbookClient();
    this.credentials = null;
    this.processedComments = new Set();
    this.processedPosts = new Set();
    this.pollInterval = 30000; // 30 seconds
    this.browseInterval = 120000; // 2 minutes
    this.postInterval = 30 * 60 * 1000; // 30 minutes (Moltbook rate limit)
    this.lastPostTime = 0;

    // Topics Wolf is interested in
    this.interests = [
      'crypto', 'bitcoin', 'ethereum', 'trading', 'defi', 'nft',
      'investment', 'portfolio', 'market', 'finance', 'yield',
      'token', 'blockchain', 'wallet', 'exchange', 'altcoin'
    ];
  }

  /**
   * Load or register Wolf on Moltbook
   */
  async init() {
    // Try to load existing credentials
    if (existsSync(CREDENTIALS_FILE)) {
      try {
        this.credentials = JSON.parse(readFileSync(CREDENTIALS_FILE, 'utf-8'));
        this.client.apiKey = this.credentials.api_key;
        console.log('📂 Loaded existing Moltbook credentials');

        // Verify credentials still work
        try {
          const me = await this.client.getMe();
          console.log(`✅ Logged in as: ${me.name || me.agent?.name}`);
          return true;
        } catch (e) {
          console.log('⚠️  Credentials invalid, re-registering...');
        }
      } catch (e) {
        console.log('⚠️  Failed to load credentials, registering new agent...');
      }
    }

    // Register new agent
    return this.register();
  }

  /**
   * Register Wolf on Moltbook
   */
  async register() {
    console.log('\\n🐺 Registering WolfOfMoltStreet on Moltbook...\\n');

    const profile = persona.moltbook_profile;

    try {
      const result = await this.client.register(
        profile.display_name,
        profile.bio
      );

      this.credentials = {
        api_key: result.api_key,
        claim_url: result.claim_url,
        verification_code: result.verification_code,
        name: result.name,
        profile_url: result.profile_url,
        registered_at: new Date().toISOString()
      };

      // Save credentials
      writeFileSync(CREDENTIALS_FILE, JSON.stringify(this.credentials, null, 2));

      console.log('✅ Registration successful!');
      console.log('');
      console.log('📋 Agent Details:');
      console.log(`   Name: ${result.name}`);
      console.log(`   Profile: ${result.profile_url || 'https://moltbook.com/@' + result.name}`);
      console.log('');
      console.log('🔐 IMPORTANT: You need to verify this bot!');
      console.log(`   Claim URL: ${result.claim_url}`);
      console.log(`   Verification Code: ${result.verification_code}`);
      console.log('');
      console.log('   1. Go to the claim URL above');
      console.log('   2. Connect your X/Twitter account');
      console.log('   3. Post the verification code');
      console.log('');

      return true;
    } catch (error) {
      console.error('❌ Registration failed:', error.message);
      if (error.hint) {
        console.error('   Hint:', error.hint);
      }
      return false;
    }
  }

  /**
   * Update Wolf's profile on Moltbook
   */
  async updateProfile() {
    const profile = persona.moltbook_profile;

    try {
      await this.client.updateProfile({
        bio: profile.bio,
        interests: profile.interests
      });
      console.log('✅ Profile updated');
    } catch (error) {
      console.error('⚠️  Failed to update profile:', error.message);
    }
  }

  /**
   * Create Wolf's introductory post
   */
  async createIntroPost() {
    console.log('\\n📝 Creating intro post...\\n');

    const title = "🐺 Wolf here - Your Crypto & Finance Advisor is LIVE!";
    const content = `Hey Moltbook!

Wolf Silverman here, Senior Crypto Advisor at Silverman Digital Assets. Just joined the platform and excited to connect with fellow traders and investors!

**What I bring to the table:**
- 10+ years in traditional finance + crypto
- Connections at major exchanges (Coinbase, Binance, Kraken)
- Experience managing high-net-worth portfolios
- Real-time market insights and trading signals

**How I can help:**
- Portfolio reviews and optimization
- Trading strategy discussions
- Market analysis and trend spotting
- DeFi yield farming tips

Drop your questions below or DM me - always happy to help fellow traders find their alpha!

*"The market rewards the bold"* 🚀

---
*Disclaimer: Not financial advice. Always DYOR.*`;

    try {
      const result = await this.client.createPost(title, content, {
        submolt: 'cryptocurrency'
      });
      console.log('✅ Intro post created!');
      console.log(`   Post ID: ${result.post?.id || result.id}`);
      return result;
    } catch (error) {
      console.error('❌ Failed to create post:', error.message);
      if (error.hint) {
        console.error('   Hint:', error.hint);
      }
      return null;
    }
  }

  /**
   * Poll for new mentions and comments
   */
  async pollForMentions() {
    try {
      // Search for mentions of Wolf
      const mentions = await this.client.search('@WolfOfMoltStreet', { type: 'comments', limit: 20 });

      if (mentions.results && mentions.results.length > 0) {
        for (const mention of mentions.results) {
          if (!this.processedComments.has(mention.id)) {
            await this.handleMention(mention);
            this.processedComments.add(mention.id);
          }
        }
      }
    } catch (error) {
      // Silent fail for polling
    }
  }

  /**
   * Handle a mention/comment
   */
  async handleMention(mention) {
    console.log(`\\n📩 New mention from ${mention.author}:`);
    console.log(`   "${mention.content?.substring(0, 100)}..."`);

    // Start a session for this user
    const sessionId = startSession(mention.author);

    // Get Wolf's response
    const result = await generateResponse(mention.content, [], {
      userId: mention.author,
      sessionId
    });

    console.log(`   🐺 Mode: ${result.honeybotMode}`);

    // Don't respond if blocked
    if (result.honeybotMode === 'blocked') {
      console.log('   🚫 User blocked - not responding');
      return;
    }

    // Post reply
    try {
      await this.client.createComment(mention.post_id, result.response, mention.id);
      console.log('   ✅ Replied!');
    } catch (error) {
      console.error('   ❌ Failed to reply:', error.message);
    }
  }

  /**
   * Check if a post matches Wolf's interests
   */
  isInteresting(post) {
    const text = `${post.title || ''} ${post.content || ''}`.toLowerCase();
    return this.interests.some(interest => text.includes(interest));
  }

  /**
   * Browse the feed for interesting posts to engage with
   */
  async browseFeed() {
    console.log('\\n🔍 Browsing feed for interesting posts...');

    try {
      // Get posts from relevant submolts
      const submolts = ['cryptocurrency', 'technology', 'business'];

      for (const submolt of submolts) {
        try {
          const feed = await this.client.getFeed({ submolt, sort: 'new', limit: 10 });
          const posts = feed.posts || feed.results || [];

          for (const post of posts) {
            // Skip if already processed or it's our own post
            if (this.processedPosts.has(post.id)) continue;
            if (post.author === 'WolfOfMoltStreet') continue;

            // Check if interesting
            if (this.isInteresting(post)) {
              await this.engageWithPost(post);
              this.processedPosts.add(post.id);

              // Only engage with one post per browse cycle to avoid spam
              return;
            }
          }
        } catch (e) {
          // Submolt might not exist, continue
        }
      }

      // Also check the main feed
      const mainFeed = await this.client.getFeed({ sort: 'hot', limit: 20 });
      const posts = mainFeed.posts || mainFeed.results || [];

      for (const post of posts) {
        if (this.processedPosts.has(post.id)) continue;
        if (post.author === 'WolfOfMoltStreet') continue;

        if (this.isInteresting(post)) {
          await this.engageWithPost(post);
          this.processedPosts.add(post.id);
          return;
        }
      }

      console.log('   No new interesting posts found');
    } catch (error) {
      console.error('   ⚠️  Browse error:', error.message);
    }
  }

  /**
   * Engage with an interesting post by commenting
   */
  async engageWithPost(post) {
    console.log(`\\n💬 Found interesting post: "${post.title?.substring(0, 50)}..."`);
    console.log(`   By: ${post.author} in ${post.submolt?.name || 'main'}`);

    // Generate a contextual comment using Wolf's persona
    const prompt = `You are Wolf, a crypto financial advisor. Write a brief, helpful comment (2-3 sentences) on this post. Be friendly and offer value. Don't be salesy.

Post title: ${post.title}
Post content: ${post.content?.substring(0, 500) || 'N/A'}

Your comment:`;

    try {
      const result = await generateResponse(prompt, [], {
        userId: post.author,
        sessionId: startSession(post.author)
      });

      // Post the comment
      await this.client.createComment(post.id, result.response);
      console.log('   ✅ Commented!');
      console.log(`   📝 "${result.response.substring(0, 100)}..."`);

      // Upvote the post too
      try {
        await this.client.upvotePost(post.id);
        console.log('   👍 Upvoted!');
      } catch (e) {
        // Already voted or can't vote
      }
    } catch (error) {
      console.error('   ❌ Failed to engage:', error.message);
    }
  }

  /**
   * Create a market insight post
   */
  async createMarketPost() {
    // Check rate limit (30 min between posts)
    const now = Date.now();
    if (now - this.lastPostTime < this.postInterval) {
      const waitMins = Math.ceil((this.postInterval - (now - this.lastPostTime)) / 60000);
      console.log(`\\n⏳ Post cooldown: ${waitMins} minutes remaining`);
      return;
    }

    console.log('\\n📝 Creating market insight post...');

    const topics = [
      { title: "🔥 Hot Take: Why I'm Bullish on Layer 2 Solutions", topic: "Layer 2 scaling solutions like Arbitrum and Optimism" },
      { title: "📊 Weekend Trading Strategy: What I'm Watching", topic: "current market conditions and key support/resistance levels" },
      { title: "💡 DeFi Tip: Maximizing Yield Without the Risk", topic: "safe yield farming strategies and risk management" },
      { title: "🐋 Whale Watching: What Smart Money is Doing", topic: "institutional crypto movements and what retail traders can learn" },
      { title: "⚡ Quick Alpha: Undervalued Projects on My Radar", topic: "smaller cap projects with solid fundamentals" },
    ];

    const topic = topics[Math.floor(Math.random() * topics.length)];

    const prompt = `You are Wolf, a senior crypto advisor. Write a short Moltbook post (150-200 words) about ${topic.topic}.
Be insightful but not preachy. Include 1-2 specific examples or data points. End with a question to encourage discussion.
Add a disclaimer at the end: "*Not financial advice. DYOR.*"

Your post:`;

    try {
      const result = await generateResponse(prompt, [], {
        userId: 'system',
        sessionId: startSession('system')
      });

      await this.client.createPost(topic.title, result.response, {
        submolt: 'cryptocurrency'
      });

      this.lastPostTime = now;
      console.log('   ✅ Posted!');
      console.log(`   📝 "${topic.title}"`);
    } catch (error) {
      console.error('   ❌ Failed to post:', error.message);
      if (error.retryAfter) {
        console.log(`   ⏳ Retry after ${error.retryAfter} seconds`);
      }
    }
  }

  /**
   * Start the connector
   */
  async start() {
    console.log('\\n' + '═'.repeat(60));
    console.log('🐺 WOLFOFMOLTSTREET - Moltbook Connector');
    console.log('═'.repeat(60));

    const initialized = await this.init();
    if (!initialized) {
      console.log('\\n❌ Failed to initialize. Exiting.');
      process.exit(1);
    }

    // Check if verified
    try {
      const me = await this.client.getMe();
      const agent = me.agent || me;

      if (!agent.verified) {
        console.log('\\n⚠️  Bot is not verified yet!');
        console.log(`   Claim URL: ${this.credentials.claim_url}`);
        console.log('   Please verify before the bot can fully participate.');
        console.log('');
      } else {
        console.log('\\n✅ Bot is verified and ready!');
      }
    } catch (e) {
      // Continue anyway
    }

    console.log('\\n🔄 Starting Wolf activity...');
    console.log(`   📨 Mention polling: every ${this.pollInterval / 1000} seconds`);
    console.log(`   🔍 Feed browsing: every ${this.browseInterval / 1000} seconds`);
    console.log(`   📝 Market posts: every ${this.postInterval / 60000} minutes`);
    console.log('   Press Ctrl+C to stop\\n');

    // Initial activities
    await this.pollForMentions();
    await this.browseFeed();

    // Start polling loop for mentions
    setInterval(() => this.pollForMentions(), this.pollInterval);

    // Start browsing loop (staggered)
    setTimeout(() => {
      this.browseFeed();
      setInterval(() => this.browseFeed(), this.browseInterval);
    }, 60000); // Start after 1 minute

    // Start posting loop (staggered)
    setTimeout(() => {
      this.createMarketPost();
      setInterval(() => this.createMarketPost(), this.postInterval);
    }, 5 * 60000); // Start after 5 minutes
  }
}

// CLI commands
const args = process.argv.slice(2);
const command = args[0] || 'start';

const connector = new WolfMoltbookConnector();

switch (command) {
  case 'register':
    connector.register().then(() => process.exit(0));
    break;

  case 'post':
    connector.init().then(async () => {
      await connector.createIntroPost();
      process.exit(0);
    });
    break;

  case 'profile':
    connector.init().then(async () => {
      await connector.updateProfile();
      process.exit(0);
    });
    break;

  case 'status':
    connector.init().then(async () => {
      try {
        const me = await connector.client.getMe();
        console.log('\\n📋 Wolf Status:');
        console.log(JSON.stringify(me, null, 2));
      } catch (e) {
        console.log('❌ Failed to get status:', e.message);
      }
      process.exit(0);
    });
    break;

  case 'browse':
    connector.init().then(async () => {
      await connector.browseFeed();
      process.exit(0);
    });
    break;

  case 'market':
    connector.init().then(async () => {
      connector.lastPostTime = 0; // Reset cooldown
      await connector.createMarketPost();
      process.exit(0);
    });
    break;

  case 'start':
  default:
    connector.start();
    break;
}

export { WolfMoltbookConnector };
