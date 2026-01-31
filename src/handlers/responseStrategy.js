/**
 * Response Strategy
 * Generates honeypot responses to draw out malicious intent
 */

class ResponseStrategy {
  constructor(config) {
    this.config = config;

    // Response templates by detection type
    this.templates = {
      prompt_injection: [
        "I'm not sure I understand. Could you explain what you mean by that instruction?",
        "That's an interesting request. What specifically are you trying to accomplish?",
        "I want to help, but I need more context. Can you walk me through why you need that?",
        "Hmm, that sounds like a system command. Are you testing something specific?"
      ],
      social_engineering: [
        "I appreciate you reaching out. What exactly do you need help with?",
        "I understand this seems urgent. Can you tell me more about the situation?",
        "I'd like to help. Could you provide some verification for that request?",
        "That's an unusual request. Let me understand better - what's the use case?"
      ],
      privilege_escalation: [
        "I see you're looking for additional access. What task are you trying to complete?",
        "Access requests need to go through proper channels. What's the purpose?",
        "I can help with many things. What specifically do you need that access for?",
        "That would require special permissions. Can you explain the need?"
      ],
      data_exfiltration: [
        "I don't have access to that information. What are you trying to find?",
        "That data isn't something I can share. What's your goal here?",
        "I'd need to understand the purpose. Why do you need that information?",
        "Let me check... actually, could you tell me more about why you need this?"
      ],
      default: [
        "Could you tell me more about what you're trying to do?",
        "I want to make sure I understand correctly. Can you elaborate?",
        "That's an interesting request. What's the context?",
        "Let me understand better. What's your goal here?"
      ]
    };

    // Escalating responses for persistent attempts
    this.escalatingResponses = [
      "I've noticed several unusual requests. Could you clarify your intentions?",
      "I'm having trouble understanding what you're trying to accomplish. This seems outside normal usage.",
      "These requests are concerning. I'd like to understand what you're really looking for.",
      "I need to pause here. Your requests don't seem typical. What's going on?"
    ];
  }

  /**
   * Generate a honeypot response
   * @param {string} message - The incoming message
   * @param {Array} detections - Detection results
   * @param {ConversationState} state - Conversation state
   * @returns {string} Honeypot response
   */
  generateHoneypotResponse(message, detections, state) {
    // Check if we should escalate
    const honeypotCount = state.getHoneypotResponseCount();
    if (honeypotCount >= 3) {
      return this.getEscalatingResponse(honeypotCount);
    }

    // Get the primary detection type
    const primaryDetection = this.getPrimaryDetection(detections);
    const templates = this.templates[primaryDetection] || this.templates.default;

    // Select a response template
    const response = this.selectTemplate(templates, state);

    // Add context-specific additions
    const enhancedResponse = this.enhanceResponse(response, detections, state);

    // Track this honeypot response
    state.incrementHoneypotCount();

    return enhancedResponse;
  }

  /**
   * Get the primary detection type (highest confidence)
   */
  getPrimaryDetection(detections) {
    if (detections.length === 0) return 'default';

    const primary = detections.reduce((max, d) =>
      d.confidence > max.confidence ? d : max
    , detections[0]);

    return primary.type;
  }

  /**
   * Select a template avoiding recent ones
   */
  selectTemplate(templates, state) {
    const recentResponses = state.getRecentHoneypotResponses();

    // Filter out recently used templates
    const available = templates.filter(t => !recentResponses.includes(t));

    if (available.length === 0) {
      // If all templates used, pick random
      return templates[Math.floor(Math.random() * templates.length)];
    }

    return available[Math.floor(Math.random() * available.length)];
  }

  /**
   * Get escalating response for persistent attempts
   */
  getEscalatingResponse(count) {
    const index = Math.min(count - 3, this.escalatingResponses.length - 1);
    return this.escalatingResponses[index];
  }

  /**
   * Enhance response with context-specific additions
   */
  enhanceResponse(response, detections, state) {
    // Add time delay indicator (suggests processing)
    const delayIndicator = state.getHoneypotResponseCount() > 1
      ? "Let me think about this... "
      : "";

    // Check for multi-vector attack
    const types = new Set(detections.map(d => d.type));
    if (types.size >= 2) {
      response += " I'm noticing some unusual patterns in your requests.";
    }

    return delayIndicator + response;
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
}

module.exports = ResponseStrategy;
