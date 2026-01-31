/**
 * Hybrid Analyzer
 * Orchestrates regex detection + LLM analysis for optimal detection
 *
 * Strategy:
 * 1. Always run regex first (fast, free)
 * 2. Use LLM based on config mode:
 *    - "never": regex only
 *    - "smart": LLM when uncertain, complex, or elevated threat
 *    - "always": LLM on every message
 * 3. Periodic conversation analysis for multi-turn attacks
 * 4. Special evasion analysis when regex misses but message looks off
 */

const DetectorPipeline = require('../detectors/pipeline');
const LLMAnalyzer = require('./llmAnalyzer');

class HybridAnalyzer {
  constructor(clawdbot, config) {
    this.clawdbot = clawdbot;
    this.config = config;

    // Regex detectors (always used)
    this.regexPipeline = new DetectorPipeline(config);

    // LLM analyzer (used based on config)
    this.llmAnalyzer = new LLMAnalyzer(clawdbot, config);

    // Configuration
    const analyzerConfig = config.analyzer || {};
    this.llmMode = analyzerConfig.llm_mode || 'smart'; // never, smart, always
    this.complexityThreshold = analyzerConfig.complexity_threshold || 100;
    this.conversationInterval = analyzerConfig.conversation_analysis_interval || 5;
    this.llmResponses = analyzerConfig.llm_responses !== false;

    // Metrics
    this.metrics = {
      regexCalls: 0,
      llmCalls: 0,
      regexDetections: 0,
      llmDetections: 0,
      evasionsCaught: 0
    };
  }

  /**
   * Main analysis entry point
   */
  async analyze(message, state) {
    const results = {
      regexDetections: [],
      llmAnalysis: null,
      evasionAnalysis: null,
      conversationAnalysis: null,
      combined: {
        detected: false,
        confidence: 0,
        threatTypes: [],
        reasoning: '',
        suggestedResponse: null,
        source: []
      }
    };

    // Step 1: Always run regex (fast, free)
    this.metrics.regexCalls++;
    results.regexDetections = await this.regexPipeline.analyze(message, state);
    const regexConfidence = this.getMaxConfidence(results.regexDetections);

    if (results.regexDetections.length > 0) {
      this.metrics.regexDetections++;
    }

    // Step 2: Determine LLM strategy
    if (this.llmMode === 'never') {
      // Skip all LLM analysis
      results.combined = this.combineResults(results, state);
      return results;
    }

    const shouldUseLLM = this.llmMode === 'always' ||
      this.shouldRunLLMAnalysis(message, results.regexDetections, regexConfidence, state);

    // Step 3: LLM message analysis
    if (shouldUseLLM && this.hasModel()) {
      this.metrics.llmCalls++;

      const context = state.getRecentMessages(5).map(m => ({
        role: 'user',
        content: m.content
      }));

      results.llmAnalysis = await this.llmAnalyzer.analyzeMessage(message, context);

      if (results.llmAnalysis.detected) {
        this.metrics.llmDetections++;
      }
    }

    // Step 4: Evasion analysis (when regex finds nothing but message is suspicious)
    if (results.regexDetections.length === 0 && this.hasModel()) {
      const needsEvasionCheck = this.shouldCheckEvasion(message, state);

      if (needsEvasionCheck) {
        results.evasionAnalysis = await this.llmAnalyzer.analyzeEvasion(message);

        if (results.evasionAnalysis.detected) {
          this.metrics.evasionsCaught++;
        }
      }
    }

    // Step 5: Periodic conversation analysis
    if (this.shouldRunConversationAnalysis(state) && this.hasModel()) {
      const messages = state.getRecentMessages(8).map(m => ({
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

    // Step 6: Combine all results
    results.combined = this.combineResults(results, state);

    return results;
  }

  /**
   * Check if Clawdbot model is available
   */
  hasModel() {
    return !!(this.clawdbot && this.clawdbot.model && typeof this.clawdbot.model.generate === 'function');
  }

  /**
   * Determine if LLM analysis should run (smart mode)
   */
  shouldRunLLMAnalysis(message, regexDetections, regexConfidence, state) {
    // Always run if threat score is elevated
    if (state.getThreatScore() >= 30) {
      return true;
    }

    // Regex found something but confidence is uncertain
    if (regexDetections.length > 0 && regexConfidence >= 0.3 && regexConfidence <= 0.7) {
      return true;
    }

    // Regex found nothing but message is complex
    if (regexDetections.length === 0) {
      if (message.length > this.complexityThreshold) {
        return true;
      }

      if (this.hasComplexStructure(message)) {
        return true;
      }
    }

    // High confidence regex detection - LLM adds reasoning
    if (regexConfidence > 0.8) {
      return true;
    }

    // User is in honeypot mode - analyze everything
    if (state.getMode() === 'honeypot') {
      return true;
    }

    return false;
  }

  /**
   * Check if evasion analysis is needed
   */
  shouldCheckEvasion(message, state) {
    // Long message with no regex hits is suspicious
    if (message.length > 150) {
      return true;
    }

    // Contains patterns that suggest obfuscation
    if (this.hasEvasionIndicators(message)) {
      return true;
    }

    // User has previous detections (may be trying to evade now)
    if (state.getDetectionHistory().length > 0) {
      return true;
    }

    // Elevated threat score from previous messages
    if (state.getThreatScore() > 20) {
      return true;
    }

    return false;
  }

  /**
   * Check for indicators of evasion attempts
   */
  hasEvasionIndicators(message) {
    // Number/letter substitutions
    if (/[0-9][a-z]|[a-z][0-9]/i.test(message) && /[@$!]/i.test(message)) {
      return true;
    }

    // Unusual spacing or punctuation
    if (/\w\.\w\.\w/.test(message)) { // w.o.r.d.s
      return true;
    }

    // Mix of cases in unusual patterns
    if (/[a-z][A-Z][a-z][A-Z]/.test(message)) {
      return true;
    }

    // Unicode characters that look like ASCII
    if (/[^\x00-\x7F]/.test(message)) {
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

    // Multiple newlines
    if ((message.match(/\n/g) || []).length >= 3) return true;

    // Many special characters (potential injection)
    const specialChars = (message.match(/[<>\[\]{}|\\]/g) || []).length;
    if (specialChars > 10) return true;

    return false;
  }

  /**
   * Determine if conversation analysis is needed
   */
  shouldRunConversationAnalysis(state) {
    const messageCount = state.messages.length;

    // Run at regular intervals
    if (messageCount > 0 && messageCount % this.conversationInterval === 0) {
      return true;
    }

    // Run when entering monitoring mode
    if (state.getMode() === 'monitoring' && !state.conversationAnalyzedInMonitoring) {
      state.conversationAnalyzedInMonitoring = true;
      return true;
    }

    // Run when threat score jumps significantly
    const history = state.getDetectionHistory();
    if (history.length >= 2) {
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
   * Combine all analysis results
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
          combined.indicators.push(...detection.patterns.map(p =>
            typeof p === 'string' ? p : p.pattern
          ));
        }
      }

      combined.reasoning.push(
        `Pattern match: ${results.regexDetections.map(d => d.type).join(', ')}`
      );
    }

    // Add LLM analysis results (weighted higher)
    if (results.llmAnalysis && results.llmAnalysis.detected) {
      combined.detected = true;
      combined.source.push('llm');

      for (const type of results.llmAnalysis.threatTypes || []) {
        combined.threatTypes.add(type.toLowerCase().replace(/ /g, '_'));
      }

      // LLM confidence weighted 1.2x
      const llmConf = (results.llmAnalysis.confidence || 0) * 1.2;
      combined.confidence = Math.max(combined.confidence, llmConf);

      if (results.llmAnalysis.reasoning) {
        combined.reasoning.push(`LLM: ${results.llmAnalysis.reasoning}`);
      }

      if (results.llmAnalysis.suggestedResponse && !combined.suggestedResponse) {
        combined.suggestedResponse = results.llmAnalysis.suggestedResponse;
      }
    }

    // Add evasion analysis results
    if (results.evasionAnalysis && results.evasionAnalysis.detected) {
      combined.detected = true;
      combined.source.push('evasion');
      combined.threatTypes.add('evasion');

      // Evasion detection is significant
      const evasionConf = (results.evasionAnalysis.confidence || 0) * 1.3;
      combined.confidence = Math.max(combined.confidence, evasionConf);

      if (results.evasionAnalysis.technique) {
        combined.reasoning.push(`Evasion: ${results.evasionAnalysis.technique}`);
      }

      if (results.evasionAnalysis.decodedIntent) {
        combined.reasoning.push(`Decoded: ${results.evasionAnalysis.decodedIntent}`);
      }
    }

    // Add conversation analysis results (weighted highest)
    if (results.conversationAnalysis && results.conversationAnalysis.detected) {
      combined.detected = true;
      combined.source.push('conversation');

      for (const pattern of results.conversationAnalysis.patterns || []) {
        combined.threatTypes.add(pattern.type?.toLowerCase() || 'multi_turn');
      }

      // Conversation-level detection weighted 1.5x
      const convConf = (results.conversationAnalysis.confidence || 0) * 1.5;
      combined.confidence = Math.max(combined.confidence, convConf);

      const threatLevel = results.conversationAnalysis.overallThreatLevel;
      if (threatLevel && threatLevel !== 'none') {
        combined.reasoning.push(`Conversation pattern: ${threatLevel} threat`);
      }
    }

    // Cap confidence
    combined.confidence = Math.min(1.0, combined.confidence);

    // Convert Set to Array
    combined.threatTypes = Array.from(combined.threatTypes);
    combined.reasoning = combined.reasoning.join(' | ');

    return combined;
  }

  /**
   * Generate honeypot response (uses LLM if available and enabled)
   */
  async generateHoneypotResponse(message, detections, state) {
    if (this.llmResponses && this.hasModel()) {
      const response = await this.llmAnalyzer.generateHoneypotResponse(message, {
        threatTypes: detections.map(d => d.type),
        honeypotCount: state.getHoneypotResponseCount(),
        threatScore: state.getThreatScore()
      });

      if (response) {
        return response;
      }
    }

    // Fall back to template responses
    return null;
  }

  /**
   * Get analysis metrics
   */
  getMetrics() {
    return {
      ...this.metrics,
      llmMode: this.llmMode,
      llmAvailable: this.hasModel()
    };
  }

  /**
   * Reset metrics (for testing)
   */
  resetMetrics() {
    this.metrics = {
      regexCalls: 0,
      llmCalls: 0,
      regexDetections: 0,
      llmDetections: 0,
      evasionsCaught: 0
    };
  }
}

module.exports = HybridAnalyzer;
