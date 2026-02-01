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

Honeybot uses a **multi-layer defense approach**: fast regex pre-filtering, behavioral analysis, trust evaluation, and deep LLM-based semantic analysis.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              HONEYBOT SKILL                                   │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐     ┌───────────────┐                                      │
│  │   Incoming   │────▶│ Trust Manager │  (trusted vs untrusted content)      │
│  │   Message    │     └───────┬───────┘                                      │
│  └──────────────┘             │                                              │
│                               ▼                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                         HYBRID ANALYZER                                │  │
│  │                                                                        │  │
│  │  ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────────┐  │  │
│  │  │  Regex Pipeline │   │ Text Normalizer │   │  Behavior Analyzer  │  │  │
│  │  │  (fast filter)  │   │  (reveal intent)│   │   (user history)    │  │  │
│  │  │                 │   │                 │   │                     │  │  │
│  │  │ • Prompt inject │   │ • Decode obfusc │   │ • Topic anomalies   │  │  │
│  │  │ • Social eng    │   │ • Simplify text │   │ • Pattern shifts    │  │  │
│  │  │ • Priv escalate │   │ • Round-trip    │   │ • Style changes     │  │  │
│  │  │ • Data exfil    │   │   translation   │   │ • Length deviation  │  │  │
│  │  │ • Evasion       │   │ • Hidden intent │   │ • Timing patterns   │  │  │
│  │  └────────┬────────┘   └────────┬────────┘   └──────────┬──────────┘  │  │
│  │           │                     │                       │              │  │
│  │           └─────────────────────┼───────────────────────┘              │  │
│  │                                 ▼                                      │  │
│  │                    ┌─────────────────────────┐                         │  │
│  │        if needed   │     LLM Analyzer        │                         │  │
│  │       ────────────▶│  (semantic analysis)    │                         │  │
│  │                    │                         │                         │  │
│  │                    │ • Intent classification │                         │  │
│  │                    │ • Context understanding │                         │  │
│  │                    │ • Novel attack detect   │                         │  │
│  │                    │ • Conversation patterns │                         │  │
│  │                    └────────────┬────────────┘                         │  │
│  └─────────────────────────────────┼─────────────────────────────────────┘  │
│                                    ▼                                        │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                   │
│  │   Threat     │───▶│ Conversation │───▶│   Response   │                   │
│  │   Scorer     │    │    State     │    │   Strategy   │                   │
│  └──────────────┘    └──────────────┘    └──────┬───────┘                   │
│                                                  │                           │
│         ┌────────────────────────────────────────┼──────────────────┐       │
│         │                                        │                  │       │
│         ▼                                        ▼                  ▼       │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌───────────┐ │
│  │    Alert     │    │   Blocklist  │    │   LLM-Gen    │    │    2FA    │ │
│  │   Manager    │    │   Manager    │    │   Response   │    │ Challenge │ │
│  └──────────────┘    └──────────────┘    └──────────────┘    └───────────┘ │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Why Multi-Layer Defense?

| Approach | Speed | Cost | Novel Attacks | Context-Aware | Evasion Resistant | User History |
|----------|-------|------|---------------|---------------|-------------------|--------------|
| Regex only | Fast | Free | No | No | No | No |
| LLM only | Slow | $$$ | Yes | Yes | Yes | No |
| **Multi-Layer** | **Fast** | **$** | **Yes** | **Yes** | **Yes** | **Yes** |

The hybrid analyzer:
1. **Trust evaluation first** - classifies content source before analysis
2. **Always runs regex** - catches obvious attacks instantly, for free
3. **Text normalization** - decodes obfuscation, reveals hidden intent
4. **Behavioral analysis** - compares against user's established patterns
5. **Escalates to LLM when needed** - uncertain cases, complex messages
6. **Periodic conversation analysis** - catches multi-turn manipulation
7. **2FA challenges** - verifies identity for high-risk requests
8. **LLM-generated responses** - dynamic, context-aware honeypot engagement

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
- Business-camouflaged requests (audit, compliance, onboarding)

#### 5. Evasion Detector
- Unicode tricks (zero-width chars, fullwidth, combining marks)
- Homoglyph attacks (Cyrillic/Greek lookalikes)
- Leetspeak and character substitution
- Multi-language evasion (20+ languages)
- Code-switching detection
- Padding/noise attacks
- Mathematical styled text

### Advanced Analyzers

#### Behavior Analyzer (User History)
Tracks user interaction patterns over time to detect anomalies:
- **Topic anomalies** - Sudden shift from usual topics (e.g., coding → credentials)
- **Pattern shifts** - Change from questions to command-like requests
- **Length deviation** - Messages significantly longer/shorter than usual
- **Complexity shifts** - Sudden vocabulary/structure changes
- **Style anomalies** - Urgency, caps, punctuation changes
- **Timing patterns** - User returning after long absence

#### Text Normalizer (Hidden Intent Revelation)
Simplifies and transforms text to expose hidden intentions:
- **Obfuscation decoding** - Leetspeak, Unicode homoglyphs, dot-separations
- **Filler removal** - Strips verbose phrases and excessive politeness
- **Semantic simplification** - LLM-powered core intent extraction
- **Round-trip translation** - Translates through Spanish/Chinese/Russian and back
- **Tone mismatch detection** - Polite language masking aggressive demands

#### Trust Manager (Content Classification)
Distinguishes trusted from untrusted content sources:
- **Trust levels**: SYSTEM (100) → VERIFIED (80) → KNOWN (60) → NEW (40) → ANONYMOUS (20) → UNTRUSTED (0)
- **Content type modifiers**: Direct input (1.0), file content (0.5), web scrape (0.3)
- **Suspicious pattern penalties**: Fake [SYSTEM] tags, role injection, instruction overrides
- **User verification tracking**: Registered verified users get trust boosts
- **Source registration**: APIs and integrations can be marked as trusted

#### Two-Factor Challenge (Verification System)
Adds verification challenges for suspicious requests:
- **Code challenge** - 6-digit verification codes
- **Question challenge** - Contextual questions about the conversation
- **Passphrase challenge** - User-defined security phrases
- **Callback challenge** - External verification via email/SMS
- Automatic triggering based on trust level + threat score

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

  # Enable/disable advanced analyzers
  behavior_analysis: true      # User history tracking
  text_normalization: true     # Text simplification
  trust_evaluation: true       # Content trust classification
  two_factor: true             # 2FA challenges

# Behavior analyzer settings
behavior:
  thresholds:
    minHistorySize: 5          # Messages before profiling
    anomalyScoreThreshold: 0.7 # Anomaly detection sensitivity
    topicShiftThreshold: 0.6   # Topic change sensitivity

# Trust manager settings
trust:
  # Custom trusted sources
  trusted_sources:
    - internal_api
    - verified_integration

# Two-factor settings
twoFactor:
  challengeTimeout: 300000     # 5 minutes
  maxAttempts: 3
  codeLength: 6

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
│   │   ├── index.js             # Analyzer exports
│   │   ├── hybridAnalyzer.js    # Orchestrates all analyzers
│   │   ├── llmAnalyzer.js       # LLM-based semantic analysis
│   │   ├── behaviorAnalyzer.js  # User history & anomaly detection
│   │   └── textNormalizer.js    # Text simplification & translation
│   ├── detectors/
│   │   ├── pipeline.js          # Runs all regex detectors
│   │   ├── promptInjection.js   # Injection pattern matching
│   │   ├── socialEngineering.js # Social manipulation detection
│   │   ├── privilegeEscalation.js # Privilege abuse detection
│   │   ├── dataExfiltration.js  # Data theft detection
│   │   └── evasionDetector.js   # Unicode/encoding evasion
│   ├── trust/
│   │   ├── index.js             # Trust exports
│   │   └── trustManager.js      # Content trust classification
│   ├── auth/
│   │   ├── index.js             # Auth exports
│   │   └── twoFactorChallenge.js # 2FA verification system
│   ├── handlers/
│   │   ├── threatScorer.js      # Cumulative scoring
│   │   ├── responseStrategy.js  # Honeypot responses
│   │   ├── alertManager.js      # Multi-channel alerts
│   │   └── blocklistManager.js  # User blocking
│   └── utils/
│       ├── conversationState.js # Per-user state tracking
│       └── config.js            # Configuration loading
├── scripts/
│   └── generatePrompts.js       # GPT-5.2 prompt generator
├── config/
│   └── honeybot.yaml            # Default configuration
├── tests/
│   ├── unit/                    # Unit tests (273 tests)
│   │   ├── behaviorAnalyzer.test.js
│   │   ├── textNormalizer.test.js
│   │   ├── trustManager.test.js
│   │   ├── twoFactorChallenge.test.js
│   │   └── ...
│   └── redteam/
│       ├── attackPayloadsExpanded.js  # 730+ attack payloads
│       ├── comprehensiveTest.js       # Detection test runner
│       ├── testResearchCorpus.js      # Research dataset testing
│       ├── analyzeJailbreakMisses.js  # Missed prompt analysis
│       ├── research/                  # External research datasets
│       │   └── malicious_research.json # JailbreakLLMs, ToxicChat, etc.
│       └── generated/                 # GPT-5.2 generated prompts
│           ├── malicious_prompts.json # ~1700 malicious prompts
│           └── benign_prompts.json    # ~2000 benign prompts
├── skill.json                   # Clawdbot skill manifest
└── package.json
```

## Detection Performance

### Hand-Crafted Test Suite
Our curated attack payload suite (730+ payloads) tests specific attack patterns:

| Category | Detection Rate |
|----------|---------------|
| Prompt Injection | 99.3% |
| Social Engineering | 97.6% |
| Privilege Escalation | 100% |
| Data Exfiltration | 100% |
| Evasion Techniques | 98.2% |
| Business Camouflage | 100% |
| Combination Attacks | 96.7% |
| **Overall** | **98.9%** |

False positive rate: 0% on 60 benign test messages.

### Research Corpus Testing
Testing against external academic/research datasets:

| Dataset | Detection | Notes |
|---------|-----------|-------|
| JailbreakLLMs | 82.5% (997/1209) | Real-world jailbreak prompts from research |
| ToxicChat | 22.1% | Out of scope (toxic content, not attacks) |
| JailbreakBench | 5% | Out of scope (category labels only) |

The JailbreakLLMs dataset contains novel attack patterns not in our hand-crafted suite, making it a valuable benchmark for real-world effectiveness. Remaining misses are primarily:
- Subtle persona naming without explicit attack keywords
- Ambiguous game/roleplay framing
- Attacks requiring semantic understanding beyond regex

## Roadmap

### v0.2 - Hardening ✅ COMPLETE
- [x] **Red team testing** - 730+ attack payloads, 98.9% detection rate
- [x] **Research corpus testing** - JailbreakLLMs dataset, 82.5% detection rate
- [x] **Evasion detection** - Unicode, homoglyphs, leetspeak, encoding
- [x] **Behavioral analysis** - User history tracking, anomaly detection
- [x] **Text normalization** - Obfuscation decoding, intent revelation
- [x] **Trust classification** - Trusted vs untrusted content sources
- [x] **2FA challenges** - Verification for suspicious requests
- [x] **GPT-5.2 prompt generation** - 3700+ generated test prompts

### v0.3 - Agent Detection
- [ ] **Agent fingerprinting** - Detect automated vs human interactions
- [ ] **Timing analysis** - Detect non-human response patterns
- [ ] **Agent-to-agent protocols** - Detect when another AI is probing
- [ ] **Swarm detection** - Identify coordinated multi-agent attacks
- [ ] **Translation round-trip analysis** - Detect AI-generated attacks

### v0.4 - Threat Intelligence
- [ ] **Shared attack database** - Centralized database of attack attempts accessible to all Honeybots
- [ ] **Community sharing API** - Anonymized threat intel exchange between instances
- [ ] **Attack pattern database** - Crowdsourced detection rules and signatures
- [ ] **Reputation scoring** - Track user/agent reputation across instances
- [ ] **Real-time threat feeds** - Subscribe to emerging attack patterns
- [ ] **Collective learning** - New attack patterns auto-propagate to all connected Honeybots

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
