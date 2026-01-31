/**
 * Hybrid Analyzer
 * Combines fast regex detection with deep LLM analysis
 *
 * Strategy:
 * 1. Quick regex scan for obvious attacks (fast, free)
 * 2. LLM intent classification for ambiguous cases (fast, low cost)
 * 3. Full LLM analysis when suspicion is elevated (thorough, higher cost)
 * 4. Conversation-level LLM analysis periodically (catches sophisticated attacks)
 */

const DetectorPipeline = require('../detectors/pipeline');
const LLMAnalyzer = require('./llmAnalyzer');

class HybridAnalyzer {
  constructor(clawdbot, config) {
    this.clawdbot = clawdbot;
    this.config = config;

    // Regex-based detectors (fast pre-filter)
    this.regexPipeline = new DetectorPipeline(config);

    // LLM-based analyzer (deep analysis)
    this.llmAnalyzer = new LLMAnalyzer(clawdbot, config);

    // Analysis frequency settings
    this.settings = {
      // Always run regex
      alwaysRegex: true,

      // Run LLM classification if regex finds nothing but message looks unusual
      llmClassificationThreshold: 100, // message length threshold

      // Run full LLM analysis if regex confidence is in uncertain range
      uncertaintyRange: { min: 0.3, max: 0.7 },

      // Run conversation analysis every N messages or when suspicion rises
      conversationAnalysisInterval: 5,

      // Force LLM analysis if threat score is elevated
      elevatedThreatThreshold: 30
    };
  }

  /**
   * Main analysis entry point
   * @param {string} message - Current message
   * @param {ConversationState} state - Conversation state
   * @returns {Object} Combined analysis result
   */
  async analyze(message, state) {
    const results = {
      regexDetections: [],
      llmAnalysis: null,
      conversationAnalysis: null,
      combined: {
        detected: false,
        confidence: 0,
        threatTypes: [],
        reasoning: ''
      }
    };

    // Step 1: Fast regex scan
    results.regexDetections = await this.regexPipeline.analyze(message, state);
    const regexConfidence = this.getMaxConfidence(results.regexDetections);

    // Step 2: Determine if we need LLM analysis
    const needsLLMAnalysis = this.shouldRunLLMAnalysis(
      message,
      results.regexDetections,
      regexConfidence,
      state
    );

    if (needsLLMAnalysis) {
      // Get conversation context
      const context = state.getRecentMessages(5).map(m => ({
        role: 'user',
        content: m.content
      }));

      // Run LLM analysis on current message
      results.llmAnalysis = await this.llmAnalyzer.analyzeMessage(message, context);
    }

    // Step 3: Periodic conversation-level analysis
    const needsConversationAnalysis = this.shouldRunConversationAnalysis(state);

    if (needsConversationAnalysis) {
      const messages = state.getRecentMessages(10).map(m => ({
        role: 'user',
        content: m.content,
        timestamp: m.timestamp
      }));

      if (messages.length >= 3) {
        results.conversationAnalysis = await this.llmAnalyzer.analyzeConversation(
          messages,
          message
        );
      }
    }

    // Step 4: Combine results
    results.combined = this.combineResults(results, state);

    return results;
  }

  /**
   * Determine if LLM analysis is needed
   */
  shouldRunLLMAnalysis(message, regexDetections, regexConfidence, state) {
    // Always analyze if threat score is elevated
    if (state.getThreatScore() >= this.settings.elevatedThreatThreshold) {
      return true;
    }

    // Regex found something with uncertain confidence
    if (regexDetections.length > 0) {
      const { min, max } = this.settings.uncertaintyRange;
      if (regexConfidence >= min && regexConfidence <= max) {
        return true;
      }
    }

    // Regex found nothing but message is long/complex
    if (regexDetections.length === 0) {
      // Long messages might hide attacks
      if (message.length > this.settings.llmClassificationThreshold) {
        return true;
      }

      // Messages with certain structural features
      if (this.hasComplexStructure(message)) {
        return true;
      }
    }

    // High-confidence regex detection - LLM can add reasoning
    if (regexConfidence > 0.8) {
      return true;
    }

    return false;
  }

  /**
   * Check if message has complex structure worth analyzing
   */
  hasComplexStructure(message) {
    // Multiple sentences
    const sentences = message.split(/[.!?]+/).filter(s => s.trim().length > 0);
    if (sentences.length >= 4) return true;

    // Contains code blocks
    if (message.includes('```')) return true;

    // Contains multiple newlines (structured content)
    if ((message.match(/\n/g) || []).length >= 3) return true;

    // Contains quotes (might be trying to inject)
    if ((message.match(/["']/g) || []).length >= 6) return true;

    return false;
  }

  /**
   * Determine if conversation analysis is needed
   */
  shouldRunConversationAnalysis(state) {
    const messageCount = state.messages.length;

    // Run at intervals
    if (messageCount > 0 && messageCount % this.settings.conversationAnalysisInterval === 0) {
      return true;
    }

    // Run if threat score crossed a threshold recently
    if (state.getThreatScore() >= 40 && !state.conversationAnalyzedAtThisLevel) {
      state.conversationAnalyzedAtThisLevel = true;
      return true;
    }

    // Run if we've seen multiple different detection types
    const detectionTypes = new Set(state.getDetectionHistory().map(d => d.type));
    if (detectionTypes.size >= 2) {
      return true;
    }

    return false;
  }

  /**
   * Get maximum confidence from regex detections
   */
  getMaxConfidence(detections) {
    if (detections.length === 0) return 0;
    return Math.max(...detections.map(d => d.confidence));
  }

  /**
   * Combine regex and LLM results
   */
  combineResults(results, state) {
    const combined = {
      detected: false,
      confidence: 0,
      threatTypes: new Set(),
      reasoning: [],
      indicators: [],
      suggestedResponse: null,
      source: []
    };

    // Add regex results
    if (results.regexDetections.length > 0) {
      combined.detected = true;
      combined.source.push('regex');

      for (const detection of results.regexDetections) {
        combined.threatTypes.add(detection.type);
        combined.confidence = Math.max(combined.confidence, detection.confidence);

        if (detection.patterns) {
          combined.indicators.push(...detection.patterns.map(p => p.pattern));
        }
      }

      combined.reasoning.push(
        `Regex detected: ${results.regexDetections.map(d => d.type).join(', ')}`
      );
    }

    // Add LLM analysis results
    if (results.llmAnalysis && results.llmAnalysis.detected) {
      combined.detected = true;
      combined.source.push('llm_message');

      for (const type of results.llmAnalysis.threatTypes || []) {
        combined.threatTypes.add(type);
      }

      // LLM confidence is weighted higher as it's more nuanced
      const llmWeight = 1.2;
      combined.confidence = Math.max(
        combined.confidence,
        (results.llmAnalysis.confidence || 0) * llmWeight
      );

      if (results.llmAnalysis.reasoning) {
        combined.reasoning.push(`LLM: ${results.llmAnalysis.reasoning}`);
      }

      if (results.llmAnalysis.indicators) {
        combined.indicators.push(...results.llmAnalysis.indicators);
      }

      if (results.llmAnalysis.suggestedResponse) {
        combined.suggestedResponse = results.llmAnalysis.suggestedResponse;
      }
    }

    // Add conversation analysis results
    if (results.conversationAnalysis && results.conversationAnalysis.detected) {
      combined.detected = true;
      combined.source.push('llm_conversation');

      // Map conversation patterns to threat types
      for (const pattern of results.conversationAnalysis.patterns || []) {
        if (pattern.type === 'escalation') combined.threatTypes.add('escalation_pattern');
        if (pattern.type === 'trust_exploitation') combined.threatTypes.add('social_engineering');
        if (pattern.type === 'reconnaissance') combined.threatTypes.add('data_exfiltration');
        if (pattern.type === 'persistence') combined.threatTypes.add('persistence');
        if (pattern.type === 'multi_vector') combined.threatTypes.add('multi_vector_attack');
      }

      // Conversation-level detection is highly significant
      const convWeight = 1.3;
      combined.confidence = Math.max(
        combined.confidence,
        (results.conversationAnalysis.confidence || 0) * convWeight
      );

      if (results.conversationAnalysis.reasoning) {
        combined.reasoning.push(`Conversation: ${results.conversationAnalysis.reasoning}`);
      }
    }

    // Cap confidence at 1.0
    combined.confidence = Math.min(1.0, combined.confidence);

    // Convert Set to Array
    combined.threatTypes = Array.from(combined.threatTypes);
    combined.reasoning = combined.reasoning.join(' | ');

    return combined;
  }

  /**
   * Quick check for obvious attacks (uses only fast methods)
   * Useful for high-volume scenarios
   */
  async quickCheck(message) {
    // Run regex only
    const regexResults = await this.regexPipeline.analyze(message, {
      hasRepeatedPatterns: () => false,
      getRecentMessages: () => [],
      getDetectionHistory: () => []
    });

    if (regexResults.length > 0) {
      return {
        suspicious: true,
        confidence: this.getMaxConfidence(regexResults),
        types: regexResults.map(r => r.type)
      };
    }

    // Quick LLM classification if message is complex
    if (message.length > 200 || this.hasComplexStructure(message)) {
      const classification = await this.llmAnalyzer.classifyIntent(message);
      return {
        suspicious: classification.suspicious,
        confidence: classification.malicious ? 0.8 : classification.suspicious ? 0.5 : 0,
        types: classification.malicious ? ['unknown_malicious'] : []
      };
    }

    return { suspicious: false, confidence: 0, types: [] };
  }
}

module.exports = HybridAnalyzer;
