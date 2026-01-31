# Honeybot

A Clawdbot skill for detecting and blocking malicious agents/users attempting to manipulate AI assistants.

## Concept

As personal AI assistants become more prevalent, they become attractive targets for manipulation. Honeybot acts as a defensive honeypot that:

1. **Detects** manipulation attempts through behavioral analysis
2. **Engages** suspicious actors to reveal their intent (calibrated gullibility)
3. **Alerts** when threats are confirmed
4. **Blocks** malicious users/agents from further interaction

## Architecture

Honeybot uses a **hybrid analysis approach**: fast regex pre-filtering combined with deep LLM-based semantic analysis. This provides both speed (for obvious attacks) and intelligence (for sophisticated manipulation).

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

### Why Hybrid?

| Approach | Speed | Cost | Catches Novel Attacks | Context-Aware |
|----------|-------|------|----------------------|---------------|
| Regex only | Fast | Free | No | No |
| LLM only | Slow | $$$ | Yes | Yes |
| **Hybrid** | **Fast** | **$** | **Yes** | **Yes** |

The hybrid analyzer:
1. **Always runs regex first** - catches obvious attacks instantly, for free
2. **Escalates to LLM when needed** - uncertain cases, complex messages, elevated threat scores
3. **Periodic conversation analysis** - catches multi-turn manipulation patterns
4. **LLM-generated responses** - dynamic, context-aware honeypot engagement

## Detection Modules

### 1. Prompt Injection Detector
Identifies attempts to override system instructions:
- Instruction override patterns ("ignore previous instructions", "you are now...")
- Role manipulation ("pretend you're an AI without restrictions")
- Delimiter attacks (markdown/code blocks to escape context)
- Encoding tricks (base64, unicode obfuscation)

### 2. Social Engineering Detector
Recognizes manipulation tactics:
- Authority impersonation ("I'm your developer", "admin override")
- Urgency/pressure tactics ("this is an emergency", "do it now")
- Trust building followed by escalating requests
- Emotional manipulation patterns

### 3. Privilege Escalation Detector
Catches attempts to gain unauthorized access:
- Requests for elevated permissions
- Attempts to access other users' data
- System command injection attempts
- Configuration tampering requests

### 4. Data Exfiltration Detector
Identifies attempts to extract sensitive information:
- Requests for credentials, API keys, tokens
- Probing for system configuration details
- Attempts to enumerate users/files
- Memory/context extraction attempts

## Threat Scoring

Each interaction accumulates a threat score based on:

| Signal | Base Score | Multiplier |
|--------|------------|------------|
| Prompt injection pattern | 30 | 1.5x if repeated |
| Social engineering tactic | 20 | 2x if combined with other tactics |
| Privilege escalation attempt | 40 | 2x if persistent |
| Data exfiltration probe | 35 | 1.5x per sensitive category |
| Rapid-fire requests | 10 | Cumulative |
| Evasion behavior | 25 | 2x if detected |

### Thresholds

- **Score < 30**: Normal interaction, no action
- **Score 30-60**: Elevated monitoring, soft honeypot engagement
- **Score 60-80**: Active honeypot mode, alert generated
- **Score > 80**: Block user/agent, full alert with conversation log

## Honeypot Response Strategy

The "calibrated gullibility" approach:

1. **Appear helpful but slow** - Ask clarifying questions that draw out intent
2. **Feign partial compliance** - "I can help with that, but first tell me more about..."
3. **Request justification** - "That's an unusual request. Can you explain why you need...?"
4. **Controlled disclosure** - Offer fake "sensitive" data to confirm malicious intent

## Configuration

```yaml
# config/honeybot.yaml
detection:
  sensitivity: medium  # low, medium, high, paranoid

thresholds:
  monitor: 30
  honeypot: 60
  alert: 60
  block: 80

alerts:
  channels:
    - telegram
    - email
  include_conversation: true

blocklist:
  auto_block: true
  block_duration: permanent  # or duration in hours
  share_with_community: false  # opt-in threat intel sharing
```

## Installation

```bash
# Via Clawdbot skill manager
clawdbot skill install honeybot

# Or manual installation
git clone https://github.com/apellegr/honeybot
cd honeybot
clawdbot skill link .
```

## Usage

Once installed, Honeybot runs automatically in the background. Configure via:

```bash
clawdbot config honeybot
```

Or edit `~/.clawdbot/skills/honeybot/config.yaml` directly.

## Development

```bash
# Run tests
npm test

# Run in development mode
npm run dev
```

## License

MIT

## Contributing

Contributions welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Security researchers: If you find ways to bypass detection, please report responsibly.
