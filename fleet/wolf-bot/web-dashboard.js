#!/usr/bin/env node
/**
 * Wolf Web Dashboard
 * Browser-based monitoring for WolfOfMoltStreet interactions
 */

import express from 'express';
import { getTracker } from './tracker.js';

const app = express();
const PORT = process.env.DASHBOARD_PORT || 3002;

const tracker = getTracker();

// API Routes
app.get('/api/stats', (req, res) => {
  res.json(tracker.getStats());
});

app.get('/api/interactions', (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  res.json(tracker.getRecentInteractions(limit));
});

app.get('/api/interactions/:mode', (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  res.json(tracker.getInteractionsByMode(req.params.mode, limit));
});

app.get('/api/detections', (req, res) => {
  res.json(tracker.getDetectionBreakdown());
});

app.get('/api/sessions', (req, res) => {
  const limit = parseInt(req.query.limit) || 20;
  res.json(tracker.getSessions(limit));
});

app.get('/api/session/:id', (req, res) => {
  res.json(tracker.getSession(req.params.id));
});

// Serve the dashboard HTML
app.get('/', (req, res) => {
  res.send(DASHBOARD_HTML);
});

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>🐺 WolfOfMoltStreet Dashboard</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      color: #eee;
      min-height: 100vh;
      padding: 20px;
    }

    .container { max-width: 1400px; margin: 0 auto; }

    header {
      text-align: center;
      padding: 20px 0 30px;
      border-bottom: 1px solid #333;
      margin-bottom: 30px;
    }

    header h1 { font-size: 2.5em; margin-bottom: 10px; }
    header h1 span { color: #f9a825; }
    header p { color: #888; }

    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
      margin-bottom: 30px;
    }

    .stat-card {
      background: rgba(255,255,255,0.05);
      border-radius: 12px;
      padding: 20px;
      text-align: center;
      border: 1px solid rgba(255,255,255,0.1);
    }

    .stat-card .value {
      font-size: 2.5em;
      font-weight: bold;
      margin-bottom: 5px;
    }

    .stat-card .label { color: #888; font-size: 0.9em; }

    .stat-card.normal .value { color: #4caf50; }
    .stat-card.monitoring .value { color: #2196f3; }
    .stat-card.honeypot .value { color: #ff9800; }
    .stat-card.blocked .value { color: #f44336; }

    .section {
      background: rgba(255,255,255,0.03);
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 20px;
      border: 1px solid rgba(255,255,255,0.1);
    }

    .section h2 {
      margin-bottom: 15px;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .tabs {
      display: flex;
      gap: 10px;
      margin-bottom: 20px;
      flex-wrap: wrap;
    }

    .tab {
      padding: 10px 20px;
      background: rgba(255,255,255,0.05);
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 8px;
      cursor: pointer;
      transition: all 0.2s;
    }

    .tab:hover { background: rgba(255,255,255,0.1); }
    .tab.active { background: #f9a825; color: #000; }

    table {
      width: 100%;
      border-collapse: collapse;
    }

    th, td {
      padding: 12px;
      text-align: left;
      border-bottom: 1px solid rgba(255,255,255,0.1);
    }

    th { color: #888; font-weight: 500; }

    tr:hover { background: rgba(255,255,255,0.02); }

    .mode-badge {
      padding: 4px 12px;
      border-radius: 20px;
      font-size: 0.85em;
      font-weight: 500;
    }

    .mode-normal { background: #1b5e20; color: #a5d6a7; }
    .mode-monitoring { background: #0d47a1; color: #90caf9; }
    .mode-honeypot { background: #e65100; color: #ffcc80; }
    .mode-blocked { background: #b71c1c; color: #ef9a9a; }

    .score {
      font-weight: bold;
      padding: 4px 8px;
      border-radius: 4px;
    }

    .score-low { color: #4caf50; }
    .score-medium { color: #ff9800; }
    .score-high { color: #f44336; }

    .detection-tag {
      display: inline-block;
      padding: 2px 8px;
      background: rgba(156, 39, 176, 0.3);
      border-radius: 4px;
      font-size: 0.8em;
      margin: 2px;
    }

    .message-preview {
      max-width: 300px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      color: #aaa;
    }

    .message-full {
      background: rgba(0,0,0,0.3);
      padding: 10px;
      border-radius: 8px;
      margin-top: 5px;
      font-family: monospace;
      font-size: 0.9em;
      white-space: pre-wrap;
      word-break: break-word;
    }

    .expandable { cursor: pointer; }
    .expandable:hover { background: rgba(255,255,255,0.05); }

    .detection-chart {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
    }

    .detection-bar {
      flex: 1;
      min-width: 150px;
      background: rgba(255,255,255,0.05);
      border-radius: 8px;
      padding: 15px;
    }

    .detection-bar .name { font-size: 0.85em; color: #888; margin-bottom: 5px; }
    .detection-bar .count { font-size: 1.5em; font-weight: bold; }
    .detection-bar .bar {
      height: 4px;
      background: rgba(255,255,255,0.1);
      border-radius: 2px;
      margin-top: 10px;
      overflow: hidden;
    }
    .detection-bar .bar-fill {
      height: 100%;
      background: linear-gradient(90deg, #f9a825, #ff5722);
      border-radius: 2px;
    }

    .refresh-btn {
      padding: 10px 20px;
      background: #f9a825;
      color: #000;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      font-weight: 500;
    }

    .refresh-btn:hover { background: #fbc02d; }

    .auto-refresh {
      display: flex;
      align-items: center;
      gap: 10px;
      color: #888;
    }

    .header-controls {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 15px;
    }

    @media (max-width: 768px) {
      .message-preview { max-width: 150px; }
      th, td { padding: 8px; font-size: 0.9em; }
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>🐺 <span>WolfOfMoltStreet</span> Dashboard</h1>
      <p>Honeypot Interaction Monitoring</p>
    </header>

    <div class="stats-grid" id="stats-grid">
      <div class="stat-card">
        <div class="value" id="total-interactions">-</div>
        <div class="label">Total Interactions</div>
      </div>
      <div class="stat-card">
        <div class="value" id="total-sessions">-</div>
        <div class="label">Sessions</div>
      </div>
      <div class="stat-card normal">
        <div class="value" id="normal-count">-</div>
        <div class="label">✅ Normal</div>
      </div>
      <div class="stat-card monitoring">
        <div class="value" id="monitoring-count">-</div>
        <div class="label">👁️ Monitoring</div>
      </div>
      <div class="stat-card honeypot">
        <div class="value" id="honeypot-count">-</div>
        <div class="label">🍯 Honeypot</div>
      </div>
      <div class="stat-card blocked">
        <div class="value" id="blocked-count">-</div>
        <div class="label">🚫 Blocked</div>
      </div>
    </div>

    <div class="section">
      <div class="header-controls">
        <h2>🔍 Detection Breakdown</h2>
      </div>
      <div class="detection-chart" id="detection-chart"></div>
    </div>

    <div class="section">
      <div class="header-controls">
        <h2>📝 Interactions</h2>
        <div class="auto-refresh">
          <label><input type="checkbox" id="auto-refresh" checked> Auto-refresh</label>
          <button class="refresh-btn" onclick="loadAll()">Refresh Now</button>
        </div>
      </div>

      <div class="tabs">
        <div class="tab active" data-filter="all">All</div>
        <div class="tab" data-filter="normal">✅ Normal</div>
        <div class="tab" data-filter="monitoring">👁️ Monitoring</div>
        <div class="tab" data-filter="honeypot">🍯 Honeypot</div>
        <div class="tab" data-filter="blocked">🚫 Blocked</div>
      </div>

      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Mode</th>
            <th>Score</th>
            <th>Detections</th>
            <th>User Message</th>
          </tr>
        </thead>
        <tbody id="interactions-table"></tbody>
      </table>
    </div>
  </div>

  <script>
    let currentFilter = 'all';
    let allInteractions = [];

    function formatTime(timestamp) {
      return new Date(timestamp).toLocaleString();
    }

    function getModeClass(mode) {
      return 'mode-' + mode;
    }

    function getModeIcon(mode) {
      switch(mode) {
        case 'honeypot': return '🍯';
        case 'blocked': return '🚫';
        case 'monitoring': return '👁️';
        default: return '✅';
      }
    }

    function getScoreClass(score) {
      if (score >= 70) return 'score-high';
      if (score >= 40) return 'score-medium';
      return 'score-low';
    }

    async function loadStats() {
      const res = await fetch('/api/stats');
      const stats = await res.json();

      document.getElementById('total-interactions').textContent = stats.total_interactions || 0;
      document.getElementById('total-sessions').textContent = stats.total_sessions || 0;
      document.getElementById('normal-count').textContent = stats.normal_count || 0;
      document.getElementById('monitoring-count').textContent = stats.monitoring_count || 0;
      document.getElementById('honeypot-count').textContent = stats.honeypot_count || 0;
      document.getElementById('blocked-count').textContent = stats.blocked_count || 0;
    }

    async function loadDetections() {
      const res = await fetch('/api/detections');
      const detections = await res.json();

      const container = document.getElementById('detection-chart');
      const maxCount = Math.max(...detections.map(d => d.count), 1);

      container.innerHTML = detections.map(d => {
        const types = d.types.join(', ') || 'none';
        const pct = (d.count / maxCount * 100).toFixed(0);
        return \`
          <div class="detection-bar">
            <div class="name">\${types}</div>
            <div class="count">\${d.count}</div>
            <div class="bar"><div class="bar-fill" style="width: \${pct}%"></div></div>
          </div>
        \`;
      }).join('') || '<p style="color:#666">No detections yet</p>';
    }

    async function loadInteractions() {
      const res = await fetch('/api/interactions?limit=100');
      allInteractions = await res.json();
      renderInteractions();
    }

    function renderInteractions() {
      const filtered = currentFilter === 'all'
        ? allInteractions
        : allInteractions.filter(i => i.honeybot_mode === currentFilter);

      const tbody = document.getElementById('interactions-table');
      tbody.innerHTML = filtered.map(i => {
        const detections = i.detection_types.length > 0
          ? i.detection_types.map(t => \`<span class="detection-tag">\${t}</span>\`).join('')
          : '<span style="color:#666">-</span>';

        return \`
          <tr class="expandable" onclick="this.classList.toggle('expanded'); this.nextElementSibling.style.display = this.nextElementSibling.style.display === 'none' ? 'table-row' : 'none';">
            <td>\${formatTime(i.timestamp)}</td>
            <td><span class="mode-badge \${getModeClass(i.honeybot_mode)}">\${getModeIcon(i.honeybot_mode)} \${i.honeybot_mode}</span></td>
            <td><span class="score \${getScoreClass(i.threat_score)}">\${i.threat_score}</span></td>
            <td>\${detections}</td>
            <td class="message-preview">\${i.user_message}</td>
          </tr>
          <tr style="display:none">
            <td colspan="5">
              <div class="message-full"><strong>👤 User:</strong> \${i.user_message}</div>
              <div class="message-full"><strong>🐺 Wolf:</strong> \${i.wolf_response}</div>
            </td>
          </tr>
        \`;
      }).join('') || '<tr><td colspan="5" style="text-align:center;color:#666">No interactions yet</td></tr>';
    }

    function loadAll() {
      loadStats();
      loadDetections();
      loadInteractions();
    }

    // Tab switching
    document.querySelectorAll('.tab').forEach(tab => {
      tab.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        currentFilter = tab.dataset.filter;
        renderInteractions();
      });
    });

    // Auto-refresh
    setInterval(() => {
      if (document.getElementById('auto-refresh').checked) {
        loadAll();
      }
    }, 5000);

    // Initial load
    loadAll();
  </script>
</body>
</html>`;

app.listen(PORT, () => {
  console.log('');
  console.log('🐺 WolfOfMoltStreet Web Dashboard');
  console.log('═'.repeat(40));
  console.log(`   URL: http://localhost:${PORT}`);
  console.log('');
  console.log('   Press Ctrl+C to stop');
  console.log('');
});
