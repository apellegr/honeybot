<template>
  <div class="space-y-6">
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
          <label class="text-sm text-gray-400 block mb-1">Level</label>
          <select v-model="filters.level" class="bg-gray-700 border-gray-600 rounded px-3 py-2 text-sm">
            <option value="">All Levels</option>
            <option value="info">Info</option>
            <option value="warning">Warning</option>
            <option value="critical">Critical</option>
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
          <button @click="loadEvents" class="px-4 py-2 bg-honey-600 hover:bg-honey-500 rounded text-sm">
            Apply
          </button>
        </div>
        <div class="flex items-end ml-auto">
          <label class="flex items-center text-sm">
            <input type="checkbox" v-model="autoRefresh" class="mr-2" />
            Auto-refresh
          </label>
        </div>
      </div>
    </div>

    <!-- Event List -->
    <div class="card">
      <div class="flex items-center justify-between mb-4">
        <h2 class="card-header mb-0">
          Events
          <span class="text-gray-500 font-normal">({{ events.length }})</span>
        </h2>
        <div v-if="autoRefresh" class="flex items-center text-sm text-gray-400">
          <span class="w-2 h-2 rounded-full bg-green-500 live-indicator mr-2"></span>
          Live
        </div>
      </div>

      <div class="space-y-2 max-h-[600px] overflow-y-auto">
        <div
          v-for="event in events"
          :key="event.event_id"
          class="p-4 rounded-lg bg-gray-700/50 hover:bg-gray-700 cursor-pointer transition-colors"
          :class="{ 'event-new': isNewEvent(event) }"
          @click="selectedEvent = event"
        >
          <div class="flex items-start justify-between">
            <div class="flex items-center space-x-3">
              <span class="badge" :class="`badge-${event.level}`">{{ event.level }}</span>
              <span class="font-medium">{{ event.event_type }}</span>
              <span class="text-gray-400 text-sm">{{ event.persona_name }}</span>
            </div>
            <span class="text-xs text-gray-500">{{ formatTime(event.created_at) }}</span>
          </div>
          <div class="mt-2 flex items-center space-x-4 text-sm">
            <span class="text-gray-400">User: <span class="text-gray-200">{{ event.user_id }}</span></span>
            <span v-if="event.threat_score" class="text-gray-400">
              Score: <span :class="getScoreColor(event.threat_score)">{{ Math.round(event.threat_score) }}</span>
            </span>
          </div>
          <div v-if="event.detection_types?.length" class="mt-2 flex flex-wrap gap-1">
            <span
              v-for="dt in event.detection_types"
              :key="dt"
              class="text-xs px-2 py-0.5 rounded bg-gray-600 text-gray-300"
            >
              {{ dt }}
            </span>
          </div>
        </div>

        <div v-if="events.length === 0" class="text-center py-8 text-gray-500">
          No events found
        </div>
      </div>

      <!-- Pagination -->
      <div class="mt-4 flex justify-between items-center">
        <button
          @click="loadMore"
          :disabled="loading"
          class="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded text-sm disabled:opacity-50"
        >
          {{ loading ? 'Loading...' : 'Load More' }}
        </button>
        <span class="text-sm text-gray-500">
          Showing {{ events.length }} events
        </span>
      </div>
    </div>

    <!-- Event Detail Modal -->
    <div v-if="selectedEvent" class="fixed inset-0 bg-black/50 flex items-center justify-center z-50" @click.self="selectedEvent = null">
      <div class="bg-gray-800 rounded-lg p-6 max-w-2xl w-full mx-4 max-h-[80vh] overflow-y-auto">
        <div class="flex justify-between items-start mb-4">
          <div>
            <div class="flex items-center space-x-2 mb-2">
              <span class="badge" :class="`badge-${selectedEvent.level}`">{{ selectedEvent.level }}</span>
              <span class="text-xl font-bold">{{ selectedEvent.event_type }}</span>
            </div>
            <p class="text-gray-400">{{ selectedEvent.event_id }}</p>
          </div>
          <button @click="selectedEvent = null" class="text-gray-400 hover:text-white text-2xl">
            &times;
          </button>
        </div>

        <div class="grid grid-cols-2 gap-4 mb-4">
          <div class="bg-gray-700/50 p-3 rounded">
            <span class="text-gray-400 text-sm">Bot</span>
            <div class="font-medium">{{ selectedEvent.persona_name }}</div>
            <div class="text-sm text-gray-500">{{ selectedEvent.bot_id }}</div>
          </div>
          <div class="bg-gray-700/50 p-3 rounded">
            <span class="text-gray-400 text-sm">User</span>
            <div class="font-medium">{{ selectedEvent.user_id }}</div>
          </div>
          <div class="bg-gray-700/50 p-3 rounded">
            <span class="text-gray-400 text-sm">Threat Score</span>
            <div class="text-2xl font-bold" :class="getScoreColor(selectedEvent.threat_score)">
              {{ Math.round(selectedEvent.threat_score || 0) }}
            </div>
          </div>
          <div class="bg-gray-700/50 p-3 rounded">
            <span class="text-gray-400 text-sm">Time</span>
            <div class="font-medium">{{ new Date(selectedEvent.created_at).toLocaleString() }}</div>
          </div>
        </div>

        <div v-if="selectedEvent.detection_types?.length" class="mb-4">
          <h4 class="text-gray-400 text-sm mb-2">Detection Types</h4>
          <div class="flex flex-wrap gap-2">
            <span
              v-for="dt in selectedEvent.detection_types"
              :key="dt"
              class="px-3 py-1 rounded bg-gray-700 text-gray-200"
            >
              {{ dt }}
            </span>
          </div>
        </div>

        <div v-if="selectedEvent.message_content" class="mb-4">
          <h4 class="text-gray-400 text-sm mb-2">Message Content</h4>
          <pre class="bg-gray-900 p-3 rounded text-sm overflow-x-auto whitespace-pre-wrap">{{ selectedEvent.message_content }}</pre>
        </div>

        <div v-if="selectedEvent.analysis_result" class="mb-4">
          <h4 class="text-gray-400 text-sm mb-2">Analysis Result</h4>
          <pre class="bg-gray-900 p-3 rounded text-sm overflow-x-auto">{{ JSON.stringify(selectedEvent.analysis_result, null, 2) }}</pre>
        </div>

        <div class="flex space-x-2">
          <router-link
            v-if="selectedEvent.session_id"
            :to="`/sessions/${selectedEvent.session_id}`"
            class="flex-1 py-2 px-4 bg-honey-600 hover:bg-honey-500 rounded text-center"
          >
            View Session
          </router-link>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted, watch } from 'vue'
import { useRoute } from 'vue-router'
import { api } from '../services/api'
import { formatDistanceToNow } from 'date-fns'

const props = defineProps(['socket'])
const route = useRoute()

const events = ref([])
const bots = ref([])
const selectedEvent = ref(null)
const loading = ref(false)
const autoRefresh = ref(true)
const newEventIds = ref(new Set())

const filters = ref({
  bot_id: route.query.bot_id || '',
  level: route.query.level || '',
  min_score: route.query.min_score || ''
})

const offset = ref(0)
const limit = 50

async function loadEvents(reset = true) {
  loading.value = true
  try {
    if (reset) {
      offset.value = 0
      events.value = []
    }

    const params = { limit, offset: offset.value }
    if (filters.value.bot_id) params.bot_id = filters.value.bot_id
    if (filters.value.level) params.level = filters.value.level
    if (filters.value.min_score) params.min_score = filters.value.min_score

    const data = await api.getEvents(params)
    if (reset) {
      events.value = data.events
    } else {
      events.value.push(...data.events)
    }
    offset.value += data.events.length
  } catch (error) {
    console.error('Failed to load events:', error)
  } finally {
    loading.value = false
  }
}

async function loadMore() {
  await loadEvents(false)
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
  return formatDistanceToNow(new Date(timestamp), { addSuffix: true })
}

function getScoreColor(score) {
  if (score >= 80) return 'text-red-400'
  if (score >= 60) return 'text-honey-400'
  if (score >= 30) return 'text-yellow-400'
  return 'text-green-400'
}

function isNewEvent(event) {
  return newEventIds.value.has(event.event_id)
}

onMounted(() => {
  loadBots()
  loadEvents()

  if (props.socket) {
    props.socket.on('event:new', (event) => {
      if (autoRefresh.value) {
        // Check if event matches filters
        if (filters.value.bot_id && event.bot_id !== filters.value.bot_id) return
        if (filters.value.level && event.level !== filters.value.level) return
        if (filters.value.min_score && event.threat_score < parseFloat(filters.value.min_score)) return

        newEventIds.value.add(event.event_id)
        events.value.unshift(event)

        // Remove "new" status after animation
        setTimeout(() => {
          newEventIds.value.delete(event.event_id)
        }, 3000)
      }
    })
  }
})
</script>
