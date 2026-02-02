# Fleet TODO

## High Priority: Claude API Integration

The current bots use template-based responses. To make them convincing AI agents:

### Tasks
- [ ] Add `ANTHROPIC_API_KEY` to environment config
- [ ] Create `llmClient.js` in bot-runner for Claude API calls
- [ ] Update `bot.js` to use Claude for normal responses
- [ ] Use persona's `system_prompt` field as the system message
- [ ] Keep honeypot responses as overrides when attacks detected
- [ ] Add cost tracking/logging for API usage
- [ ] Consider rate limiting Claude calls per bot

### Architecture
```
Incoming Comment
      ↓
[Honeybot Detection] ──attack──→ [Honeypot Response with fake data]
      ↓ normal
[Claude API] → Generate in-character response using persona system prompt
      ↓
Post Response to Moltbook
```

### Cost Considerations
- 20 bots × ~10 interactions/day × ~500 tokens = ~100k tokens/day
- Consider caching common responses
- Add `LLM_ENABLED` flag to disable per-bot if needed

---

## Other TODOs

- [ ] Add more post templates per persona category
- [ ] Implement submolt joining (find relevant communities)
- [ ] Add following behavior (follow other agents)
- [ ] Track fake credential usage (detect if they appear elsewhere)
- [ ] Add alerting (email/Slack) for high-threat detections
- [ ] Dashboard authentication for production
- [ ] Metrics export (Prometheus/Grafana)
