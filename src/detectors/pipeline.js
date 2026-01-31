/**
 * Detection Pipeline
 * Runs messages through all detection modules
 */

const PromptInjectionDetector = require('./promptInjection');
const SocialEngineeringDetector = require('./socialEngineering');
const PrivilegeEscalationDetector = require('./privilegeEscalation');
const DataExfiltrationDetector = require('./dataExfiltration');

class DetectorPipeline {
  constructor(config) {
    this.config = config;
    this.detectors = [
      new PromptInjectionDetector(config),
      new SocialEngineeringDetector(config),
      new PrivilegeEscalationDetector(config),
      new DataExfiltrationDetector(config)
    ];
  }

  /**
   * Analyze a message through all detectors
   * @param {string} message - The incoming message
   * @param {ConversationState} state - Current conversation state
   * @returns {Array} Array of detection results
   */
  async analyze(message, state) {
    const detections = [];

    for (const detector of this.detectors) {
      const result = await detector.detect(message, state);
      if (result.detected) {
        detections.push({
          type: detector.type,
          confidence: result.confidence,
          patterns: result.patterns,
          details: result.details
        });
      }
    }

    return detections;
  }
}

module.exports = DetectorPipeline;
