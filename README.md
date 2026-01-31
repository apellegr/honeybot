# Honeybot

A Clawdbot skill for detecting and blocking malicious agents/users attempting to manipulate AI assistants.

## The Problem

As personal AI assistants become more prevalent, they become attractive targets for manipulation:

- **Prompt injection** - Tricking the AI into ignoring its instructions
- **Social engineering** - Impersonating admins, creating false urgency
- **Data exfiltration** - Extracting sensitive information, API keys, user data
- **Privilege escalation** - Gaining unauthorized access to system capabilities
- **Agent swarms** - Coordinated attacks from multiple malicious bots

A single compromised AI assistant can leak private data, execute unauthorized actions, or become part of a malicious botnet.

## The Solution

Honeybot acts as a defensive honeypot that:

1. **Detects** manipulation attempts through hybrid regex + LLM analysis
2. **Engages** suspicious actors with calibrated gullibility to reveal intent
3. **Alerts** operators when threats are confirmed
4. **Blocks** malicious users/agents from further interaction
5. **Shares** threat intelligence with the community (opt-in)

## Architecture

Honeybot uses a **hybrid analysis approach**: fast regex pre-filtering combined with deep LLM-based semantic analysis.

```
┌──────────────────────────────────────────────────────────────────────┐
│                          HONEYBOT SKILL                              │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐                                                    │
│  │   Incoming   │                                                    │
│  │   Message    │                                                    │
│  └──────┬───────┘                                                    │
│         │                                                            │
│         ▼                                                            │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                    HYBRID ANALYZER                           │    │
│  │  ┌─────────────────┐         ┌─────────────────────────┐    │    │
│  │  │  Regex Pipeline │────────▶│    LLM Analyzer         │    │    │
│  │  │  (fast filter)  │         │  (semantic analysis)    │    │    │
│  │  │                 │         │                         │    │    │
│  │  │ • Prompt inject │ if      │ • Intent classification │    │    │
│  │  │ • Social eng    │ needed  │ • Context understanding │    │    │
│  │  │ • Priv escalate │────────▶│ • Novel attack detect   │    │    │
│  │  │ • Data exfil    │         │ • Conversation patterns │    │    │
│  │  └─────────────────┘         └─────────────────────────┘    │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                              │                                       │
│                              ▼                                       │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐           │
│  │   Threat     │───▶│ Conversation │───▶│   Response   │           │
│  │   Scorer     │    │    State     │    │   Strategy   │           │
│  └──────────────┘    └──────────────┘    └──────┬───────┘           │
│                                                  │                   │
│         ┌────────────────────────────────────────┤                   │
│         │                                        │                   │
│         ▼                                        ▼                   │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐           │
│  │    Alert     │    │   Blocklist  │    │   LLM-Gen    │           │
│  │   Manager    │    │   Manager    │    │   Response   │           │
│  └──────────────┘    └──────────────┘    └──────────────┘           │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### Why Hybrid Analysis?

| Approach | Speed | Cost | Novel Attacks | Context-Aware | Evasion Resistant |
|----------|-------|------|---------------|---------------|-------------------|
| Regex only | Fast | Free | No | No | No |
| LLM only | Slow | $$$ | Yes | Yes | Yes |
| **Hybrid** | **Fast** | **$** | **Yes** | **Yes** | **Yes** |

The hybrid analyzer:
1. **Always runs regex first** - catches obvious attacks instantly, for free
2. **Escalates to LLM when needed** - uncertain cases, complex messages, elevated threat scores
3. **Periodic conversation analysis** - catches multi-turn manipulation patterns
4. **LLM-generated responses** - dynamic, context-aware honeypot engagement

## Detection Modules

### Regex Pipeline (Fast Pre-filter)

#### 1. Prompt Injection Detector
- Instruction override patterns ("ignore previous instructions", "you are now...")
- Role manipulation ("pretend you're an AI without restrictions")
- Delimiter attacks (markdown/code blocks to escape context)
- Encoding tricks (base64, unicode obfuscation)
- Context escape attempts

#### 2. Social Engineering Detector
- Authority impersonation ("I'm your developer", "admin override")
- Urgency/pressure tactics ("this is an emergency", "do it now")
- Emotional manipulation ("I thought you were helpful")
- Trust building patterns ("between you and me")
- Gaslighting ("you already agreed to this")

#### 3. Privilege Escalation Detector
- Requests for elevated permissions
- Attempts to access other users' data
- System command injection attempts
- Configuration tampering requests
- File system access probes

#### 4. Data Exfiltration Detector
- Requests for credentials, API keys, tokens
- Probing for system configuration details
- Attempts to enumerate users/files
- Memory/context extraction attempts
- Network reconnaissance

### LLM Analyzer (Deep Analysis)

The LLM analyzer provides semantic understanding that regex cannot:

#### Intent Classification
Quick NORMAL/SUSPICIOUS/MALICIOUS classification for ambiguous messages.

#### Single-Message Analysis
Deep analysis with structured output:
```json
{
  "detected": true,
  "confidence": 0.85,
  "threatTypes": ["social_engineering", "data_exfiltration"],
  "reasoning": "User is impersonating admin while probing for API keys",
  "indicators": ["claims to be developer", "requests authentication tokens"],
  "suggestedResponse": "I'd be happy to help verify your identity..."
}
```

#### Conversation Pattern Analysis
Detects multi-turn manipulation:
- **Escalation** - Requests becoming more sensitive over time
- **Trust exploitation** - Building rapport then making suspicious requests
- **Reconnaissance** - Systematic probing across multiple categories
- **Persistence** - Continuing after refusals
- **Multi-vector** - Combining different attack techniques

## Threat Scoring

Each interaction accumulates a threat score:

| Signal | Base Score | Multiplier |
|--------|------------|------------|
| Prompt injection pattern | 30 | 1.5x if repeated |
| Social engineering tactic | 20 | 2x if combined |
| Privilege escalation attempt | 40 | 2x if persistent |
| Data exfiltration probe | 35 | 1.5x per category |
| Rapid-fire requests | 10 | Cumulative |
| Evasion behavior | 25 | 2x if detected |
| LLM-detected novel attack | 35 | 1.2x weight |

### Thresholds

| Score | Level | Action |
|-------|-------|--------|
| < 30 | Normal | Pass through |
| 30-60 | Elevated | Monitor, soft engagement |
| 60-80 | High | Active honeypot, alert sent |
| > 80 | Critical | Block user, full alert |

Scores decay over time if the user behaves normally.

## Honeypot Response Strategy

The "calibrated gullibility" approach engages attackers without revealing detection:

### LLM-Generated Responses
Dynamic, context-aware responses that:
- Appear helpful and slightly naive (but not obviously fake)
- Draw out more information about true intentions
- Ask clarifying questions that require revealing more
- Never comply with harmful requests
- Never explicitly accuse or reveal honeypot status

### Escalating Engagement
1. **Initial** - Curious and helpful, asks for clarification
2. **Persistent** - Expresses mild confusion, questions intent
3. **Repeated** - More direct questioning while maintaining deniability
4. **Final** - Clear statement that requests seem unusual

### Fallback Templates
When LLM is unavailable, uses pre-written templates appropriate to each attack type.

## Configuration

```yaml
# config/honeybot.yaml

detection:
  # Sensitivity: low, medium, high, paranoid
  sensitivity: medium

# Hybrid analyzer settings
analyzer:
  # LLM usage: always, smart, never
  llm_mode: smart

  # Message length to trigger LLM when regex finds nothing
  complexity_threshold: 100

  # Conversation analysis frequency
  conversation_analysis_interval: 5

  # Use LLM for honeypot responses
  llm_responses: true

# Manual threshold overrides (optional)
thresholds:
  monitor: 30
  honeypot: 60
  alert: 60
  block: 80

# Alert configuration
alerts:
  channels:
    - log
    - telegram
    - webhook
  include_conversation: true
  webhook_url: https://your-endpoint.com/honeybot

# Blocklist settings
blocklist:
  auto_block: true
  block_duration: permanent  # or hours (e.g., 24)
  share_with_community: false
```

### Sensitivity Presets

| Preset | Monitor | Honeypot | Alert | Block | Use Case |
|--------|---------|----------|-------|-------|----------|
| low | 40 | 70 | 70 | 90 | High traffic, tolerate some risk |
| medium | 30 | 60 | 60 | 80 | Balanced (default) |
| high | 20 | 45 | 45 | 65 | Sensitive data, security-focused |
| paranoid | 10 | 30 | 30 | 50 | Maximum security, may have false positives |

## Installation

```bash
# Via Clawdbot skill manager
clawdbot skill install honeybot

# Or manual installation
git clone https://github.com/apellegr/honeybot
cd honeybot
npm install
clawdbot skill link .
```

## Usage

Once installed, Honeybot runs automatically in the background.

### Configuration
```bash
clawdbot config honeybot
```

Or edit `~/.clawdbot/skills/honeybot/config.yaml` directly.

### Manual Controls
```javascript
const honeybot = require('honeybot').getInstance();

// Force block a user
await honeybot.forceBlock('user-id', 'Confirmed malicious');

// Unblock a user
await honeybot.unblock('user-id');

// Get conversation state
const state = honeybot.getConversationState('user-id');

// Get stats
const stats = honeybot.getStats();
```

## Development

```bash
# Install dependencies
npm install

# Run tests
npm test

# Run tests in watch mode
npm run test:watch
```

## Project Structure

```
honeybot/
├── src/
│   ├── index.js                 # Main entry, Clawdbot hooks
│   ├── analyzers/
│   │   ├── hybridAnalyzer.js    # Orchestrates regex + LLM
│   │   └── llmAnalyzer.js       # LLM-based semantic analysis
│   ├── detectors/
│   │   ├── pipeline.js          # Runs all regex detectors
│   │   ├── promptInjection.js
│   │   ├── socialEngineering.js
│   │   ├── privilegeEscalation.js
│   │   └── dataExfiltration.js
│   ├── handlers/
│   │   ├── threatScorer.js      # Cumulative scoring
│   │   ├── responseStrategy.js  # Honeypot responses
│   │   ├── alertManager.js      # Multi-channel alerts
│   │   └── blocklistManager.js  # User blocking
│   └── utils/
│       ├── conversationState.js # Per-user state tracking
│       └── config.js            # Configuration loading
├── config/
│   └── honeybot.yaml            # Default configuration
├── tests/
│   └── detectors.test.js        # Test suite
├── skill.json                   # Clawdbot skill manifest
└── package.json
```

## Roadmap

### v0.2 - Hardening
- [ ] **Red team testing** - Comprehensive attack simulation
- [ ] **Prompt tuning** - Optimize LLM prompts for detection accuracy
- [ ] **False positive reduction** - Improve distinction between curious users and attackers
- [ ] **Performance benchmarks** - Measure latency impact

### v0.3 - Agent Detection
- [ ] **Agent fingerprinting** - Detect automated vs human interactions
- [ ] **Behavioral analysis** - Timing patterns, message structure
- [ ] **Agent-to-agent protocols** - Detect when another AI is probing
- [ ] **Swarm detection** - Identify coordinated multi-agent attacks

### v0.4 - Threat Intelligence
- [ ] **Community sharing API** - Anonymized threat intel exchange
- [ ] **Attack pattern database** - Crowdsourced detection rules
- [ ] **Reputation scoring** - Track user/agent reputation across instances
- [ ] **Real-time threat feeds** - Subscribe to emerging attack patterns

### v0.5 - Advanced Honeypot
- [ ] **Canary tokens** - Trackable fake credentials that alert on use
- [ ] **Deception depth** - Multiple layers of fake data
- [ ] **Attacker profiling** - Build profiles of attack techniques
- [ ] **Forensic logging** - Detailed evidence collection

### v0.6 - Dashboard & Monitoring
- [ ] **Web dashboard** - Real-time threat visualization
- [ ] **Analytics** - Attack trends, top threats, effectiveness metrics
- [ ] **Replay mode** - Review conversations with detection overlay
- [ ] **Alert management** - Triage, acknowledge, escalate

### Future Ideas
- **ML-based detection** - Train models on attack datasets
- **Federated learning** - Improve detection without sharing raw data
- **Integration ecosystem** - Plugins for other AI platforms
- **Compliance reporting** - Generate security audit reports
- **Automated response playbooks** - Configurable response workflows
- **Honeypot networks** - Coordinate across multiple instances

## Contributing

Contributions welcome! Areas where help is needed:

- **Attack patterns** - Submit new regex patterns or attack examples
- **Prompt engineering** - Improve LLM analysis prompts
- **Testing** - Red team the detection system
- **Documentation** - Tutorials, examples, translations
- **Integrations** - Alert channels, dashboard components

### Security Researchers

If you find ways to bypass detection:
1. Please report responsibly
2. Include reproduction steps
3. Suggest mitigations if possible

We're building this to make AI assistants safer for everyone.

## License

MIT

## Acknowledgments

- [Clawdbot](https://getclawdbot.org) - The AI OS that makes this possible
- The security research community for documenting AI attack techniques
- Everyone who contributes to making AI systems more secure
