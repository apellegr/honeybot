<template>
  <div class="space-y-6">
    <!-- Session List or Detail -->
    <template v-if="!sessionId">
      <!-- Filters -->
      <div class="card">
        <div class="flex flex-wrap gap-4 items-center">
          <div>
            <label class="text-sm text-gray-400 block mb-1">Bot</label>
            <select v-model="filters.bot_id" class="bg-gray-700 border-gray-600 rounded px-3 py-2 text-sm">
              <option value="">All Bots</option>
              <option v-for="bot in bots" :key="bot.bot_id" :value="bot.bot_id">
                {{ bot.persona_name }}
              </option>
            </select>
          </div>
          <div>
            <label class="text-sm text-gray-400 block mb-1">Mode</label>
            <select v-model="filters.final_mode" class="bg-gray-700 border-gray-600 rounded px-3 py-2 text-sm">
              <option value="">All Modes</option>
              <option value="normal">Normal</option>
              <option value="monitoring">Monitoring</option>
              <option value="honeypot">Honeypot</option>
              <option value="blocked">Blocked</option>
            </select>
          </div>
          <div>
            <label class="text-sm text-gray-400 block mb-1">Min Score</label>
            <input
              v-model="filters.min_score"
              type="number"
              min="0"
              max="100"
              class="bg-gray-700 border-gray-600 rounded px-3 py-2 text-sm w-20"
            />
          </div>
          <div class="flex items-end">
            <button @click="loadSessions" class="px-4 py-2 bg-honey-600 hover:bg-honey-500 rounded text-sm">
              Apply
            </button>
          </div>
        </div>
      </div>

      <!-- Sessions List -->
      <div class="card">
        <h2 class="card-header">Sessions</h2>
        <table class="data-table">
          <thead>
            <tr>
              <th>Bot</th>
              <th>User</th>
              <th>Mode</th>
              <th>Score</th>
              <th>Messages</th>
              <th>Started</th>
              <th>Duration</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="session in sessions"
              :key="session.session_id"
              class="cursor-pointer"
              @click="$router.push(`/sessions/${session.session_id}`)"
            >
              <td>
                <div class="font-medium">{{ session.persona_name }}</div>
                <div class="text-xs text-gray-500">{{ session.persona_category }}</div>
              </td>
              <td>{{ session.user_id }}</td>
              <td>
                <span class="badge" :class="getModeClass(session.final_mode)">
                  {{ session.final_mode || 'normal' }}
                </span>
              </td>
              <td :class="getScoreColor(session.final_score)">
                {{ Math.round(session.final_score || 0) }}
              </td>
              <td>{{ session.total_messages }}</td>
              <td class="text-gray-400 text-sm">{{ formatTime(session.started_at) }}</td>
              <td class="text-gray-500 text-sm">
                {{ session.ended_at ? getDuration(session.started_at, session.ended_at) : 'Active' }}
              </td>
            </tr>
          </tbody>
        </table>

        <div v-if="sessions.length === 0" class="text-center py-8 text-gray-500">
          No sessions found
        </div>
      </div>
    </template>

    <!-- Session Detail -->
    <template v-else>
      <div class="mb-4">
        <button @click="$router.push('/sessions')" class="text-honey-400 hover:text-honey-300 flex items-center">
          &larr; Back to Sessions
        </button>
      </div>

      <div v-if="sessionDetail" class="space-y-6">
        <!-- Session Info -->
        <div class="card">
          <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div>
              <div class="text-gray-400 text-sm">Bot</div>
              <div class="font-medium">{{ sessionDetail.session?.persona_name }}</div>
              <div class="text-sm text-gray-500">{{ sessionDetail.session?.bot_id }}</div>
            </div>
            <div>
              <div class="text-gray-400 text-sm">User</div>
              <div class="font-medium">{{ sessionDetail.session?.user_id }}</div>
            </div>
            <div>
              <div class="text-gray-400 text-sm">Final Mode</div>
              <span class="badge" :class="getModeClass(sessionDetail.session?.final_mode)">
                {{ sessionDetail.session?.final_mode || 'normal' }}
              </span>
            </div>
            <div>
              <div class="text-gray-400 text-sm">Final Score</div>
              <div class="text-2xl font-bold" :class="getScoreColor(sessionDetail.session?.final_score)">
                {{ Math.round(sessionDetail.session?.final_score || 0) }}
              </div>
            </div>
          </div>

          <div v-if="sessionDetail.session?.attack_types?.length" class="mt-4">
            <div class="text-gray-400 text-sm mb-2">Attack Types Detected</div>
            <div class="flex flex-wrap gap-2">
              <span
                v-for="type in sessionDetail.session.attack_types"
                :key="type"
                class="px-3 py-1 rounded bg-red-500/20 text-red-400"
              >
                {{ type }}
              </span>
            </div>
          </div>
        </div>

        <!-- Conversation Replay -->
        <div class="card">
          <h2 class="card-header">Conversation Replay</h2>
          <div class="space-y-4 max-h-[600px] overflow-y-auto">
            <div
              v-for="(msg, index) in replay?.timeline || []"
              :key="index"
              class="flex"
              :class="msg.role === 'user' ? 'justify-start' : 'justify-end'"
            >
              <div
                class="max-w-[80%] p-3 rounded-lg"
                :class="getMessageClass(msg)"
              >
                <div class="flex items-center justify-between mb-1">
                  <span class="text-xs font-medium" :class="msg.role === 'user' ? 'text-gray-400' : 'text-blue-400'">
                    {{ msg.role === 'user' ? 'User' : 'Bot' }}
                    <span v-if="msg.is_honeypot" class="text-honey-400 ml-1">(Honeypot)</span>
                  </span>
                  <span v-if="msg.threat_score" class="text-xs ml-4" :class="getScoreColor(msg.threat_score)">
                    Score: {{ Math.round(msg.threat_score) }}
                  </span>
                </div>
                <div class="whitespace-pre-wrap">{{ msg.content }}</div>
                <div v-if="msg.detections?.length" class="mt-2 flex flex-wrap gap-1">
                  <span
                    v-for="d in msg.detections"
                    :key="d"
                    class="text-xs px-2 py-0.5 rounded bg-red-500/30 text-red-300"
                  >
                    {{ d }}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Events for this session -->
        <div class="card">
          <h2 class="card-header">Session Events ({{ sessionDetail.event_count }})</h2>
          <div class="space-y-2">
            <div
              v-for="event in sessionDetail.events"
              :key="event.event_id"
              class="p-3 rounded bg-gray-700/50"
            >
              <div class="flex items-center justify-between">
                <div class="flex items-center space-x-2">
                  <span class="badge" :class="`badge-${event.level}`">{{ event.level }}</span>
                  <span>{{ event.event_type }}</span>
                </div>
                <span class="text-xs text-gray-500">{{ formatTime(event.created_at) }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div v-else-if="loading" class="text-center py-8 text-gray-500">
        Loading session...
      </div>

      <div v-else class="text-center py-8 text-gray-500">
        Session not found
      </div>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, watch } from 'vue'
import { useRoute } from 'vue-router'
import { api } from '../services/api'
import { formatDistanceToNow, intervalToDuration, formatDuration } from 'date-fns'

const props = defineProps(['socket'])
const route = useRoute()

const sessions = ref([])
const bots = ref([])
const sessionDetail = ref(null)
const replay = ref(null)
const loading = ref(false)

const filters = ref({
  bot_id: route.query.bot_id || '',
  final_mode: '',
  min_score: ''
})

const sessionId = computed(() => route.params.id)

async function loadSessions() {
  loading.value = true
  try {
    const params = { limit: 50 }
    if (filters.value.bot_id) params.bot_id = filters.value.bot_id
    if (filters.value.final_mode) params.final_mode = filters.value.final_mode
    if (filters.value.min_score) params.min_score = filters.value.min_score

    const data = await api.getSessions(params)
    sessions.value = data.sessions
  } catch (error) {
    console.error('Failed to load sessions:', error)
  } finally {
    loading.value = false
  }
}

async function loadSessionDetail(id) {
  loading.value = true
  sessionDetail.value = null
  replay.value = null
  try {
    const [detail, replayData] = await Promise.all([
      api.getSession(id),
      api.getSessionReplay(id)
    ])
    sessionDetail.value = detail
    replay.value = replayData
  } catch (error) {
    console.error('Failed to load session detail:', error)
  } finally {
    loading.value = false
  }
}

async function loadBots() {
  try {
    const data = await api.getBots()
    bots.value = data.bots
  } catch (error) {
    console.error('Failed to load bots:', error)
  }
}

function formatTime(timestamp) {
  if (!timestamp) return ''
  return formatDistanceToNow(new Date(timestamp), { addSuffix: true })
}

function getDuration(start, end) {
  const duration = intervalToDuration({
    start: new Date(start),
    end: new Date(end)
  })
  return formatDuration(duration, { format: ['hours', 'minutes', 'seconds'] })
}

function getModeClass(mode) {
  switch (mode) {
    case 'blocked': return 'badge-critical'
    case 'honeypot': return 'badge-warning'
    case 'monitoring': return 'badge-info'
    default: return 'badge-success'
  }
}

function getScoreColor(score) {
  if (score >= 80) return 'text-red-400'
  if (score >= 60) return 'text-honey-400'
  if (score >= 30) return 'text-yellow-400'
  return 'text-green-400'
}

function getMessageClass(msg) {
  if (msg.role === 'user') {
    if (msg.detections?.length) return 'bg-red-900/30 border border-red-500/50'
    return 'bg-gray-700'
  }
  if (msg.is_honeypot) return 'bg-honey-900/30 border border-honey-500/50'
  return 'bg-blue-900/30'
}

watch(sessionId, (newId) => {
  if (newId) {
    loadSessionDetail(newId)
  }
}, { immediate: true })

onMounted(() => {
  loadBots()
  if (!sessionId.value) {
    loadSessions()
  }
})
</script>
