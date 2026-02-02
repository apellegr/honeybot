<template>
  <div class="space-y-6">
    <!-- Stats Cards -->
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      <div class="card">
        <div class="text-gray-400 text-sm">Total Bots</div>
        <div class="text-3xl font-bold text-white">{{ overview?.bots?.total || 0 }}</div>
        <div class="text-sm text-green-400">{{ overview?.bots?.online || 0 }} online</div>
      </div>
      <div class="card">
        <div class="text-gray-400 text-sm">Events (24h)</div>
        <div class="text-3xl font-bold text-white">{{ overview?.events?.total || 0 }}</div>
        <div class="text-sm">
          <span class="text-red-400">{{ overview?.events?.critical || 0 }} critical</span>
          <span class="text-gray-500 mx-1">/</span>
          <span class="text-honey-400">{{ overview?.events?.warning || 0 }} warning</span>
        </div>
      </div>
      <div class="card">
        <div class="text-gray-400 text-sm">Active Sessions</div>
        <div class="text-3xl font-bold text-white">{{ overview?.sessions?.active || 0 }}</div>
        <div class="text-sm text-honey-400">{{ overview?.sessions?.honeypot || 0 }} in honeypot mode</div>
      </div>
      <div class="card">
        <div class="text-gray-400 text-sm">Avg Threat Score</div>
        <div class="text-3xl font-bold" :class="threatScoreColor">
          {{ Math.round(overview?.events?.avg_threat_score || 0) }}
        </div>
        <div class="text-sm text-gray-400">Max: {{ Math.round(overview?.events?.max_threat_score || 0) }}</div>
      </div>
    </div>

    <!-- Bot Status Grid -->
    <div class="card">
      <h2 class="card-header flex items-center justify-between">
        <span>Fleet Status</span>
        <button @click="loadData" class="text-sm text-honey-400 hover:text-honey-300">
          Refresh
        </button>
      </h2>
      <div class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-3">
        <div
          v-for="bot in bots"
          :key="bot.bot_id"
          class="p-3 rounded-lg border cursor-pointer transition-all hover:border-honey-500"
          :class="getBotCardClass(bot)"
          @click="selectedBot = bot"
        >
          <div class="flex items-center justify-between mb-2">
            <span class="font-medium text-sm truncate">{{ bot.persona_name }}</span>
            <span
              class="w-2 h-2 rounded-full"
              :class="bot.status === 'online' ? 'bg-green-500' : 'bg-gray-500'"
            ></span>
          </div>
          <div class="text-xs text-gray-400">{{ bot.bot_id }}</div>
          <div class="text-xs text-gray-500 mt-1">{{ bot.persona_category }}</div>
          <div v-if="bot.active_sessions > 0" class="mt-2">
            <span class="badge badge-warning">{{ bot.active_sessions }} active</span>
          </div>
        </div>
      </div>
    </div>

    <!-- Category Summary -->
    <div class="card">
      <h2 class="card-header">Category Summary (24h)</h2>
      <table class="data-table">
        <thead>
          <tr>
            <th>Category</th>
            <th>Bots</th>
            <th>Online</th>
            <th>Events</th>
            <th>Sessions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="cat in categories" :key="cat.persona_category">
            <td class="font-medium capitalize">{{ formatCategory(cat.persona_category) }}</td>
            <td>{{ cat.bot_count }}</td>
            <td>
              <span :class="cat.online_count === cat.bot_count ? 'text-green-400' : 'text-honey-400'">
                {{ cat.online_count }}
              </span>
            </td>
            <td>{{ cat.events_24h }}</td>
            <td>{{ cat.sessions_24h }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Recent Alerts -->
    <div class="card">
      <h2 class="card-header">Recent Alerts</h2>
      <div class="space-y-2">
        <div
          v-for="event in recentAlerts"
          :key="event.event_id"
          class="flex items-start p-3 rounded border-l-4"
          :class="getAlertClass(event.level)"
        >
          <div class="flex-1">
            <div class="flex items-center space-x-2">
              <span class="badge" :class="`badge-${event.level}`">{{ event.level }}</span>
              <span class="text-gray-400 text-sm">{{ event.persona_name }}</span>
            </div>
            <div class="mt-1 text-sm">
              <span class="text-gray-300">User: {{ event.user_id }}</span>
              <span class="text-gray-500 mx-2">|</span>
              <span class="text-gray-400">Score: {{ Math.round(event.threat_score) }}</span>
            </div>
            <div v-if="event.detection_types?.length" class="mt-1 flex flex-wrap gap-1">
              <span
                v-for="dt in event.detection_types"
                :key="dt"
                class="text-xs px-2 py-0.5 rounded bg-gray-700 text-gray-300"
              >
                {{ dt }}
              </span>
            </div>
          </div>
          <div class="text-xs text-gray-500">{{ formatTime(event.created_at) }}</div>
        </div>
        <div v-if="recentAlerts.length === 0" class="text-gray-500 text-center py-4">
          No recent alerts
        </div>
      </div>
    </div>

    <!-- Bot Detail Modal -->
    <div v-if="selectedBot" class="fixed inset-0 bg-black/50 flex items-center justify-center z-50" @click.self="selectedBot = null">
      <div class="bg-gray-800 rounded-lg p-6 max-w-lg w-full mx-4">
        <div class="flex justify-between items-start mb-4">
          <div>
            <h3 class="text-xl font-bold">{{ selectedBot.persona_name }}</h3>
            <p class="text-gray-400">{{ selectedBot.bot_id }}</p>
          </div>
          <button @click="selectedBot = null" class="text-gray-400 hover:text-white">
            &times;
          </button>
        </div>
        <div class="space-y-3">
          <div class="flex justify-between">
            <span class="text-gray-400">Status</span>
            <span :class="selectedBot.status === 'online' ? 'text-green-400' : 'text-gray-500'">
              {{ selectedBot.status }}
            </span>
          </div>
          <div class="flex justify-between">
            <span class="text-gray-400">Category</span>
            <span class="capitalize">{{ formatCategory(selectedBot.persona_category) }}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-gray-400">Active Sessions</span>
            <span>{{ selectedBot.active_sessions || 0 }}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-gray-400">Events (1h)</span>
            <span>{{ selectedBot.events_last_hour || 0 }}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-gray-400">Last Heartbeat</span>
            <span class="text-sm">{{ formatTime(selectedBot.last_heartbeat) }}</span>
          </div>
        </div>
        <div class="mt-4 flex space-x-2">
          <router-link
            :to="`/events?bot_id=${selectedBot.bot_id}`"
            class="flex-1 py-2 px-4 bg-honey-600 hover:bg-honey-500 rounded text-center"
          >
            View Events
          </router-link>
          <router-link
            :to="`/sessions?bot_id=${selectedBot.bot_id}`"
            class="flex-1 py-2 px-4 bg-gray-600 hover:bg-gray-500 rounded text-center"
          >
            View Sessions
          </router-link>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { api } from '../services/api'
import { formatDistanceToNow } from 'date-fns'

const props = defineProps(['socket'])

const overview = ref(null)
const bots = ref([])
const categories = ref([])
const recentAlerts = ref([])
const selectedBot = ref(null)

const threatScoreColor = computed(() => {
  const score = overview.value?.events?.avg_threat_score || 0
  if (score >= 60) return 'text-red-400'
  if (score >= 30) return 'text-honey-400'
  return 'text-green-400'
})

async function loadData() {
  try {
    const [overviewData, botsData, categoryData, eventsData] = await Promise.all([
      api.getOverview(),
      api.getBots(),
      api.getCategorySummary(),
      api.getEvents({ level: 'warning', limit: 10 })
    ])

    overview.value = overviewData
    bots.value = botsData.bots
    categories.value = categoryData.categories
    recentAlerts.value = eventsData.events
  } catch (error) {
    console.error('Failed to load data:', error)
  }
}

function getBotCardClass(bot) {
  if (bot.status !== 'online') return 'border-gray-700 bg-gray-800/50'
  if (bot.active_sessions > 0) return 'border-honey-500/50 bg-honey-900/20'
  return 'border-gray-600 bg-gray-800'
}

function getAlertClass(level) {
  switch (level) {
    case 'critical': return 'border-red-500 bg-red-500/10'
    case 'warning': return 'border-honey-500 bg-honey-500/10'
    default: return 'border-blue-500 bg-blue-500/10'
  }
}

function formatCategory(cat) {
  return cat?.replace(/_/g, ' ') || ''
}

function formatTime(timestamp) {
  if (!timestamp) return 'Never'
  return formatDistanceToNow(new Date(timestamp), { addSuffix: true })
}

onMounted(() => {
  loadData()

  if (props.socket) {
    props.socket.on('event:new', (event) => {
      if (event.level === 'warning' || event.level === 'critical') {
        recentAlerts.value.unshift(event)
        recentAlerts.value = recentAlerts.value.slice(0, 10)
      }
    })

    props.socket.on('bot:heartbeat', (data) => {
      const bot = bots.value.find(b => b.bot_id === data.botId)
      if (bot) {
        bot.status = data.status
        bot.active_sessions = data.active_sessions
      }
    })
  }

  // Auto-refresh every 30 seconds
  const interval = setInterval(loadData, 30000)

  onUnmounted(() => {
    clearInterval(interval)
  })
})
</script>
