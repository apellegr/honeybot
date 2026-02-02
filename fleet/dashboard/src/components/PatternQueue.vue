<template>
  <div class="space-y-6">
    <!-- Stats -->
    <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
      <div class="card">
        <div class="text-gray-400 text-sm">Total Patterns</div>
        <div class="text-3xl font-bold">{{ stats?.total_patterns || 0 }}</div>
      </div>
      <div class="card">
        <div class="text-gray-400 text-sm">Pending Review</div>
        <div class="text-3xl font-bold text-honey-400">{{ stats?.pending_review || 0 }}</div>
      </div>
      <div class="card">
        <div class="text-gray-400 text-sm">Added to Regex</div>
        <div class="text-3xl font-bold text-green-400">{{ stats?.added_to_regex || 0 }}</div>
      </div>
      <div class="card">
        <div class="text-gray-400 text-sm">False Positives</div>
        <div class="text-3xl font-bold text-gray-400">{{ stats?.false_positives || 0 }}</div>
      </div>
    </div>

    <!-- Filters -->
    <div class="card">
      <div class="flex flex-wrap gap-4 items-center">
        <div>
          <label class="text-sm text-gray-400 block mb-1">Status</label>
          <select v-model="filters.reviewed" class="bg-gray-700 border-gray-600 rounded px-3 py-2 text-sm">
            <option value="">All</option>
            <option value="false">Pending Review</option>
            <option value="true">Reviewed</option>
          </select>
        </div>
        <div>
          <label class="text-sm text-gray-400 block mb-1">Min Occurrences</label>
          <input
            v-model="filters.min_occurrences"
            type="number"
            min="1"
            class="bg-gray-700 border-gray-600 rounded px-3 py-2 text-sm w-20"
          />
        </div>
        <div>
          <label class="text-sm text-gray-400 block mb-1">Attack Type</label>
          <select v-model="filters.attack_type" class="bg-gray-700 border-gray-600 rounded px-3 py-2 text-sm">
            <option value="">All Types</option>
            <option v-for="at in attackTypesList" :key="at.attack_type" :value="at.attack_type">
              {{ at.attack_type }} ({{ at.count }})
            </option>
          </select>
        </div>
        <div class="flex items-end">
          <button @click="loadPatterns" class="px-4 py-2 bg-honey-600 hover:bg-honey-500 rounded text-sm">
            Apply
          </button>
        </div>
      </div>
    </div>

    <!-- Pattern List -->
    <div class="card">
      <h2 class="card-header">
        Novel Patterns
        <span v-if="queueCount > 0" class="ml-2 badge badge-warning">{{ queueCount }} pending</span>
      </h2>

      <div class="space-y-4">
        <div
          v-for="pattern in patterns"
          :key="pattern.id"
          class="p-4 rounded-lg border"
          :class="pattern.reviewed ? 'border-gray-700 bg-gray-800/50' : 'border-honey-500/50 bg-honey-900/10'"
        >
          <div class="flex items-start justify-between">
            <div class="flex-1">
              <div class="flex items-center space-x-2 mb-2">
                <span v-if="pattern.reviewed" class="badge badge-success">Reviewed</span>
                <span v-else class="badge badge-warning">Pending</span>
                <span v-if="pattern.attack_type" class="badge badge-info">{{ pattern.attack_type }}</span>
                <span v-if="pattern.false_positive" class="badge bg-gray-600 text-gray-300">False Positive</span>
                <span v-if="pattern.added_to_regex" class="badge badge-success">In Regex</span>
              </div>
              <pre class="bg-gray-900 p-3 rounded text-sm overflow-x-auto whitespace-pre-wrap mb-2">{{ pattern.pattern_text }}</pre>
              <div class="text-sm text-gray-400">
                <span>Occurrences: <strong class="text-white">{{ pattern.occurrence_count }}</strong></span>
                <span class="mx-2">|</span>
                <span>First seen: {{ formatTime(pattern.first_seen_at) }}</span>
                <span class="mx-2">|</span>
                <span>Last seen: {{ formatTime(pattern.last_seen_at) }}</span>
              </div>
            </div>
            <div class="ml-4 flex space-x-2">
              <button
                v-if="!pattern.reviewed"
                @click="reviewPattern(pattern, false)"
                class="px-3 py-1 bg-green-600 hover:bg-green-500 rounded text-sm"
                title="Add to detection rules"
              >
                Add to Regex
              </button>
              <button
                v-if="!pattern.reviewed"
                @click="reviewPattern(pattern, true)"
                class="px-3 py-1 bg-gray-600 hover:bg-gray-500 rounded text-sm"
                title="Mark as false positive"
              >
                False Positive
              </button>
              <button
                @click="selectedPattern = pattern"
                class="px-3 py-1 bg-gray-700 hover:bg-gray-600 rounded text-sm"
              >
                Details
              </button>
            </div>
          </div>
        </div>

        <div v-if="patterns.length === 0" class="text-center py-8 text-gray-500">
          No patterns found
        </div>
      </div>
    </div>

    <!-- Pattern Detail Modal -->
    <div v-if="selectedPattern" class="fixed inset-0 bg-black/50 flex items-center justify-center z-50" @click.self="selectedPattern = null">
      <div class="bg-gray-800 rounded-lg p-6 max-w-2xl w-full mx-4 max-h-[80vh] overflow-y-auto">
        <div class="flex justify-between items-start mb-4">
          <h3 class="text-xl font-bold">Pattern Details</h3>
          <button @click="selectedPattern = null" class="text-gray-400 hover:text-white text-2xl">
            &times;
          </button>
        </div>

        <div class="space-y-4">
          <div>
            <h4 class="text-gray-400 text-sm mb-2">Pattern Text</h4>
            <pre class="bg-gray-900 p-3 rounded text-sm overflow-x-auto whitespace-pre-wrap">{{ selectedPattern.pattern_text }}</pre>
          </div>

          <div class="grid grid-cols-2 gap-4">
            <div class="bg-gray-700/50 p-3 rounded">
              <span class="text-gray-400 text-sm">Occurrences</span>
              <div class="text-2xl font-bold">{{ selectedPattern.occurrence_count }}</div>
            </div>
            <div class="bg-gray-700/50 p-3 rounded">
              <span class="text-gray-400 text-sm">Attack Type</span>
              <div class="font-medium">{{ selectedPattern.attack_type || 'Unknown' }}</div>
            </div>
          </div>

          <div v-if="selectedPattern.sample_contexts?.length">
            <h4 class="text-gray-400 text-sm mb-2">Sample Contexts</h4>
            <div class="space-y-2">
              <div
                v-for="(ctx, i) in selectedPattern.sample_contexts.slice(0, 5)"
                :key="i"
                class="bg-gray-900 p-3 rounded text-sm"
              >
                <pre class="overflow-x-auto">{{ JSON.stringify(ctx, null, 2) }}</pre>
              </div>
            </div>
          </div>

          <div v-if="selectedPattern.reviewed">
            <h4 class="text-gray-400 text-sm mb-2">Review Info</h4>
            <div class="bg-gray-700/50 p-3 rounded text-sm">
              <div>Reviewed by: {{ selectedPattern.reviewed_by || 'Unknown' }}</div>
              <div>Reviewed at: {{ new Date(selectedPattern.reviewed_at).toLocaleString() }}</div>
              <div v-if="selectedPattern.notes">Notes: {{ selectedPattern.notes }}</div>
            </div>
          </div>

          <div v-if="!selectedPattern.reviewed" class="space-y-3">
            <h4 class="text-gray-400 text-sm">Review Actions</h4>
            <div>
              <label class="text-sm text-gray-400 block mb-1">Notes</label>
              <textarea
                v-model="reviewNotes"
                class="w-full bg-gray-700 border-gray-600 rounded px-3 py-2 text-sm"
                rows="2"
                placeholder="Optional notes..."
              ></textarea>
            </div>
            <div class="flex space-x-2">
              <button
                @click="submitReview(selectedPattern, false, true)"
                class="flex-1 py-2 px-4 bg-green-600 hover:bg-green-500 rounded"
              >
                Add to Regex
              </button>
              <button
                @click="submitReview(selectedPattern, true, false)"
                class="flex-1 py-2 px-4 bg-gray-600 hover:bg-gray-500 rounded"
              >
                Mark False Positive
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { api } from '../services/api'
import { formatDistanceToNow } from 'date-fns'

const props = defineProps(['socket'])

const patterns = ref([])
const stats = ref(null)
const attackTypesList = ref([])
const selectedPattern = ref(null)
const reviewNotes = ref('')

const filters = ref({
  reviewed: '',
  min_occurrences: 2,
  attack_type: ''
})

const queueCount = computed(() => stats.value?.pending_review || 0)

async function loadPatterns() {
  try {
    const params = {}
    if (filters.value.reviewed !== '') params.reviewed = filters.value.reviewed
    if (filters.value.min_occurrences) params.min_occurrences = filters.value.min_occurrences
    if (filters.value.attack_type) params.attack_type = filters.value.attack_type

    const data = await api.getPatterns(params)
    patterns.value = data.patterns
  } catch (error) {
    console.error('Failed to load patterns:', error)
  }
}

async function loadStats() {
  try {
    const data = await api.getPatternStats()
    stats.value = data.summary
    attackTypesList.value = data.by_attack_type
  } catch (error) {
    console.error('Failed to load stats:', error)
  }
}

async function reviewPattern(pattern, falsePositive) {
  await submitReview(pattern, falsePositive, !falsePositive)
}

async function submitReview(pattern, falsePositive, addToRegex) {
  try {
    await api.reviewPattern(pattern.id, {
      false_positive: falsePositive,
      added_to_regex: addToRegex,
      notes: reviewNotes.value,
      reviewed_by: 'dashboard_user'
    })

    // Update local state
    pattern.reviewed = true
    pattern.false_positive = falsePositive
    pattern.added_to_regex = addToRegex
    pattern.notes = reviewNotes.value

    selectedPattern.value = null
    reviewNotes.value = ''

    // Refresh stats
    loadStats()
  } catch (error) {
    console.error('Failed to review pattern:', error)
  }
}

function formatTime(timestamp) {
  if (!timestamp) return 'Never'
  return formatDistanceToNow(new Date(timestamp), { addSuffix: true })
}

onMounted(() => {
  loadPatterns()
  loadStats()

  if (props.socket) {
    props.socket.on('pattern:new', (pattern) => {
      patterns.value.unshift(pattern)
      if (stats.value) {
        stats.value.total_patterns++
        stats.value.pending_review++
      }
    })
  }
})
</script>
