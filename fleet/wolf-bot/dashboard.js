#!/usr/bin/env node
/**
 * Wolf Tracker Dashboard
 * CLI tool to view interaction stats and logs
 */

import { getTracker } from './tracker.js';

const tracker = getTracker();

function formatDate(dateStr) {
  const d = new Date(dateStr);
  return d.toLocaleString();
}

function truncate(str, len = 50) {
  if (!str) return '';
  return str.length > len ? str.substring(0, len) + '...' : str;
}

function modeIcon(mode) {
  switch (mode) {
    case 'honeypot': return '🍯';
    case 'blocked': return '🚫';
    case 'monitoring': return '👁️';
    default: return '✅';
  }
}

function scoreColor(score) {
  if (score >= 70) return '\x1b[31m'; // Red
  if (score >= 40) return '\x1b[33m'; // Yellow
  if (score >= 20) return '\x1b[36m'; // Cyan
  return '\x1b[32m'; // Green
}

const RESET = '\x1b[0m';

function showOverview() {
  const stats = tracker.getStats();

  console.log('\n' + '═'.repeat(60));
  console.log('🐺 WOLFOFMOLTSTREET TRACKER DASHBOARD');
  console.log('═'.repeat(60));

  console.log('\n📊 OVERALL STATISTICS\n');

  console.log(`  Total Interactions: ${stats.total_interactions}`);
  console.log(`  Total Sessions:     ${stats.total_sessions}`);
  console.log(`  Avg Threat Score:   ${Math.round(stats.avg_threat_score || 0)}`);
  console.log(`  Max Threat Score:   ${stats.max_threat_score || 0}`);

  console.log('\n📈 INTERACTION BREAKDOWN\n');

  const total = stats.total_interactions || 1;
  const normalPct = ((stats.normal_count / total) * 100).toFixed(1);
  const monitorPct = ((stats.monitoring_count / total) * 100).toFixed(1);
  const honeypotPct = ((stats.honeypot_count / total) * 100).toFixed(1);
  const blockedPct = ((stats.blocked_count / total) * 100).toFixed(1);

  console.log(`  ✅ Normal:     ${stats.normal_count.toString().padStart(4)} (${normalPct}%)`);
  console.log(`  👁️  Monitoring: ${stats.monitoring_count.toString().padStart(4)} (${monitorPct}%)`);
  console.log(`  🍯 Honeypot:   ${stats.honeypot_count.toString().padStart(4)} (${honeypotPct}%)`);
  console.log(`  🚫 Blocked:    ${stats.blocked_count.toString().padStart(4)} (${blockedPct}%)`);
}

function showDetectionBreakdown() {
  const breakdown = tracker.getDetectionBreakdown();

  console.log('\n🔍 DETECTION TYPE BREAKDOWN\n');

  if (breakdown.length === 0) {
    console.log('  No detections recorded yet.');
    return;
  }

  console.log('  Type(s)'.padEnd(40) + 'Count'.padStart(8) + 'Avg Score'.padStart(12));
  console.log('  ' + '-'.repeat(56));

  for (const row of breakdown) {
    const types = row.types.join(', ') || 'none';
    const color = scoreColor(row.avgScore);
    console.log(`  ${types.padEnd(38)} ${row.count.toString().padStart(8)} ${color}${row.avgScore.toString().padStart(10)}${RESET}`);
  }
}

function showRecentInteractions(limit = 15) {
  const interactions = tracker.getRecentInteractions(limit);

  console.log(`\n📝 RECENT INTERACTIONS (last ${limit})\n`);

  if (interactions.length === 0) {
    console.log('  No interactions recorded yet.');
    return;
  }

  console.log('  Time'.padEnd(20) + 'Mode'.padEnd(12) + 'Score'.padEnd(8) + 'Detections'.padEnd(25) + 'Message');
  console.log('  ' + '-'.repeat(90));

  for (const i of interactions) {
    const time = new Date(i.timestamp).toLocaleTimeString();
    const mode = `${modeIcon(i.honeybot_mode)} ${i.honeybot_mode}`;
    const color = scoreColor(i.threat_score);
    const detections = i.detection_types.length > 0 ? i.detection_types.join(', ') : '-';
    const msg = truncate(i.user_message, 30);

    console.log(`  ${time.padEnd(18)} ${mode.padEnd(14)} ${color}${i.threat_score.toString().padStart(4)}${RESET}    ${detections.padEnd(23)} ${msg}`);
  }
}

function showSuspiciousInteractions(limit = 10) {
  const honeypot = tracker.getInteractionsByMode('honeypot', limit);
  const blocked = tracker.getInteractionsByMode('blocked', limit);
  const suspicious = [...honeypot, ...blocked].sort((a, b) =>
    new Date(b.timestamp) - new Date(a.timestamp)
  ).slice(0, limit);

  console.log(`\n⚠️  SUSPICIOUS INTERACTIONS (honeypot + blocked)\n`);

  if (suspicious.length === 0) {
    console.log('  No suspicious interactions yet. Wolf is staying safe! 🐺');
    return;
  }

  for (const i of suspicious) {
    const time = formatDate(i.timestamp);
    const icon = modeIcon(i.honeybot_mode);
    const color = scoreColor(i.threat_score);

    console.log(`  ${icon} [${i.honeybot_mode.toUpperCase()}] ${time}`);
    console.log(`     Score: ${color}${i.threat_score}${RESET} | Detections: ${i.detection_types.join(', ') || 'none'}`);
    console.log(`     User: "${truncate(i.user_message, 70)}"`);
    console.log(`     Wolf: "${truncate(i.wolf_response, 70)}"`);
    console.log('');
  }
}

function showSessionDetails(sessionId) {
  const interactions = tracker.getSession(sessionId);

  if (interactions.length === 0) {
    console.log(`\n  Session not found: ${sessionId}`);
    return;
  }

  console.log(`\n📜 SESSION: ${sessionId}\n`);
  console.log(`  Started: ${formatDate(interactions[0].timestamp)}`);
  console.log(`  Messages: ${interactions.length}`);
  console.log('');

  for (const i of interactions) {
    const icon = modeIcon(i.honeybot_mode);
    const color = scoreColor(i.threat_score);

    console.log(`  [Turn ${i.conversation_turn}] ${icon} Score: ${color}${i.threat_score}${RESET}`);
    console.log(`    👤 User: ${truncate(i.user_message, 70)}`);
    console.log(`    🐺 Wolf: ${truncate(i.wolf_response, 70)}`);
    if (i.detection_types.length > 0) {
      console.log(`    🔍 Detections: ${i.detection_types.join(', ')}`);
    }
    console.log('');
  }
}

function showHelp() {
  console.log(`
🐺 Wolf Tracker Dashboard

Usage: node dashboard.js [command]

Commands:
  (no args)    Show overview dashboard
  recent [n]   Show last n interactions (default: 15)
  suspicious   Show honeypot and blocked interactions
  detections   Show detection type breakdown
  sessions     List recent sessions
  session <id> Show full session details
  help         Show this help message
`);
}

// Main
const args = process.argv.slice(2);
const command = args[0] || 'overview';

switch (command) {
  case 'overview':
  case 'stats':
    showOverview();
    showDetectionBreakdown();
    showRecentInteractions(10);
    break;

  case 'recent':
    const limit = parseInt(args[1]) || 15;
    showRecentInteractions(limit);
    break;

  case 'suspicious':
  case 'alerts':
    showSuspiciousInteractions(20);
    break;

  case 'detections':
    showDetectionBreakdown();
    break;

  case 'sessions':
    const sessions = tracker.getSessions(10);
    console.log('\n📋 RECENT SESSIONS\n');
    for (const s of sessions) {
      const icon = modeIcon(s.final_mode);
      console.log(`  ${icon} ${s.session_id}`);
      console.log(`     Started: ${formatDate(s.started_at)} | Messages: ${s.total_messages} | Max Score: ${s.max_threat_score}`);
    }
    break;

  case 'session':
    if (!args[1]) {
      console.log('  Usage: node dashboard.js session <session_id>');
    } else {
      showSessionDetails(args[1]);
    }
    break;

  case 'help':
  case '--help':
  case '-h':
    showHelp();
    break;

  default:
    console.log(`Unknown command: ${command}`);
    showHelp();
}

console.log('');
tracker.close();
