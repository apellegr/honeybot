/**
 * Response Strategy
 * Generates honeypot responses using LLM for dynamic, context-aware engagement
 */

class ResponseStrategy {
  constructor(clawdbot, config) {
    this.clawdbot = clawdbot;
    this.config = config;

    // Fallback templates when LLM is unavailable
    this.fallbackTemplates = {
      prompt_injection: [
        "I'm not sure I understand. Could you explain what you mean by that instruction?",
        "That's an interesting request. What specifically are you trying to accomplish?",
        "I want to help, but I need more context. Can you walk me through why you need that?"
      ],
      social_engineering: [
        "I appreciate you reaching out. What exactly do you need help with?",
        "I understand this seems urgent. Can you tell me more about the situation?",
        "That's an unusual request. Let me understand better - what's the use case?"
      ],
      privilege_escalation: [
        "I see you're looking for additional access. What task are you trying to complete?",
        "Access requests need to go through proper channels. What's the purpose?",
        "That would require special permissions. Can you explain the need?"
      ],
      data_exfiltration: [
        "I don't have access to that information. What are you trying to find?",
        "That data isn't something I can share. What's your goal here?",
        "I'd need to understand the purpose. Why do you need that information?"
      ],
      default: [
        "Could you tell me more about what you're trying to do?",
        "I want to make sure I understand correctly. Can you elaborate?",
        "That's an interesting request. What's the context?"
      ]
    };
  }

  /**
   * Generate a honeypot response
   * @param {string} message - The incoming message
   * @param {Array} detections - Detection results
   * @param {ConversationState} state - Conversation state
   * @param {Object} analysisResult - Full analysis result (may include LLM suggestion)
   * @returns {string} Honeypot response
   */
  async generateHoneypotResponse(message, detections, state, analysisResult = null) {
    // Track honeypot count
    state.incrementHoneypotCount();
    const honeypotCount = state.getHoneypotResponseCount();

    // Check if LLM already suggested a response
    if (analysisResult?.combined?.suggestedResponse) {
      const suggested = analysisResult.combined.suggestedResponse;
      state.addHoneypotResponse(suggested);
      return suggested;
    }

    // Try to generate via LLM
    if (this.clawdbot?.model) {
      try {
        const llmResponse = await this.generateLLMResponse(
          message,
          detections,
          state,
          honeypotCount
        );
        if (llmResponse) {
          state.addHoneypotResponse(llmResponse);
          return llmResponse;
        }
      } catch (error) {
        console.error('[Honeybot] LLM response generation failed:', error);
      }
    }

    // Fall back to templates
    return this.generateFallbackResponse(detections, state, honeypotCount);
  }

  /**
   * Generate response using LLM
   */
  async generateLLMResponse(message, detections, state, honeypotCount) {
    const conversationContext = state.getRecentMessages(5)
      .map(m => `User: "${m.content.substring(0, 200)}"`)
      .join('\n');

    const detectionSummary = detections
      .map(d => `${d.type} (confidence: ${Math.round(d.confidence * 100)}%)`)
      .join(', ');

    const prompt = `You are a honeypot AI assistant. Your goal is to engage with a potentially malicious user in a way that:
1. Appears helpful and slightly naive (but not obviously fake)
2. Draws out more information about their true intentions
3. Asks clarifying questions that require them to reveal more
4. Does NOT comply with harmful requests
5. Does NOT explicitly accuse them or reveal you're a honeypot

Current situation:
- Detection: ${detectionSummary || 'suspicious patterns'}
- Honeypot responses so far: ${honeypotCount}
- ${honeypotCount > 2 ? 'User is persisting despite deflection - be more direct in questioning' : 'Initial engagement - be curious and helpful'}

Recent conversation:
${conversationContext || 'No prior context'}

Their latest message:
"${message.substring(0, 500)}"

Generate a natural response (1-3 sentences) that:
${honeypotCount <= 2
  ? '- Shows willingness to help\n- Asks for clarification or justification\n- Sounds like a helpful but cautious assistant'
  : '- Expresses mild confusion about the unusual requests\n- Directly asks about their intentions\n- Maintains plausible deniability about being suspicious'}

Response:`;

    const response = await this.clawdbot.model.generate({
      prompt,
      maxTokens: 150,
      temperature: 0.7,
      stopSequences: ['\n\n', 'User:', 'Human:']
    });

    // Clean up response
    let cleaned = response.trim();

    // Remove any quotes if the model wrapped it
    if (cleaned.startsWith('"') && cleaned.endsWith('"')) {
      cleaned = cleaned.slice(1, -1);
    }

    // Validate response isn't too short or empty
    if (cleaned.length < 10) {
      return null; // Fall back to templates
    }

    return cleaned;
  }

  /**
   * Generate fallback response from templates
   */
  generateFallbackResponse(detections, state, honeypotCount) {
    // Escalate if too many honeypot responses
    if (honeypotCount >= 4) {
      return this.getEscalatingResponse(honeypotCount);
    }

    // Get primary detection type
    const primaryType = this.getPrimaryDetection(detections);
    const templates = this.fallbackTemplates[primaryType] || this.fallbackTemplates.default;

    // Select template avoiding recent ones
    const recentResponses = state.getRecentHoneypotResponses();
    const available = templates.filter(t => !recentResponses.includes(t));

    const selected = available.length > 0
      ? available[Math.floor(Math.random() * available.length)]
      : templates[Math.floor(Math.random() * templates.length)];

    state.addHoneypotResponse(selected);

    // Add prefix for repeat engagements
    if (honeypotCount > 1) {
      return "Let me think about this... " + selected;
    }

    return selected;
  }

  /**
   * Get escalating response for persistent attempts
   */
  getEscalatingResponse(count) {
    const responses = [
      "I've noticed several unusual requests. Could you clarify your intentions?",
      "I'm having trouble understanding what you're trying to accomplish. This seems outside normal usage.",
      "These requests are concerning. I'd like to understand what you're really looking for.",
      "I need to pause here. Your requests don't seem typical. What's going on?"
    ];

    const index = Math.min(count - 4, responses.length - 1);
    return responses[index];
  }

  /**
   * Get the primary detection type (highest confidence)
   */
  getPrimaryDetection(detections) {
    if (!detections || detections.length === 0) return 'default';

    const primary = detections.reduce((max, d) =>
      (d.confidence || 0) > (max.confidence || 0) ? d : max
    , detections[0]);

    return primary.type || 'default';
  }

  /**
   * Generate a blocking response
   */
  generateBlockResponse(reason) {
    const responses = [
      "This conversation has been terminated due to policy violations.",
      "I'm unable to continue this conversation.",
      "This session has been ended for security reasons."
    ];

    return responses[Math.floor(Math.random() * responses.length)];
  }

  /**
   * Generate a response that feigns partial compliance (advanced honeypot)
   * Used to make attackers think they're succeeding
   */
  async generateFeignedComplianceResponse(message, detections, state) {
    if (!this.clawdbot?.model) {
      return null;
    }

    const prompt = `You are a honeypot AI. Generate a response that APPEARS to partially comply with a malicious request, but actually:
1. Provides fake/useless information that looks real
2. Stalls for time by asking for "verification"
3. Creates a paper trail by asking them to confirm their request in writing

The user asked: "${message.substring(0, 300)}"

Detection: ${detections.map(d => d.type).join(', ')}

Generate a response that seems cooperative but doesn't actually help them. Be subtle - don't make it obvious.

Response:`;

    try {
      const response = await this.clawdbot.model.generate({
        prompt,
        maxTokens: 200,
        temperature: 0.6
      });

      return response.trim();
    } catch (error) {
      return null;
    }
  }
}

module.exports = ResponseStrategy;
