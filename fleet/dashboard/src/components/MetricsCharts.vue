<template>
  <div class="space-y-6">
    <!-- Time Range Selector -->
    <div class="card">
      <div class="flex items-center space-x-4">
        <span class="text-gray-400">Time Range:</span>
        <div class="flex space-x-2">
          <button
            v-for="h in [6, 12, 24, 48, 72]"
            :key="h"
            @click="hours = h; loadData()"
            class="px-3 py-1 rounded text-sm"
            :class="hours === h ? 'bg-honey-600' : 'bg-gray-700 hover:bg-gray-600'"
          >
            {{ h }}h
          </button>
        </div>
      </div>
    </div>

    <!-- Overview Stats -->
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      <div class="card">
        <div class="text-gray-400 text-sm">Total Events</div>
        <div class="text-3xl font-bold">{{ overview?.events?.total || 0 }}</div>
      </div>
      <div class="card">
        <div class="text-gray-400 text-sm">Threats Caught</div>
        <div class="text-3xl font-bold text-honey-400">
          {{ effectiveness?.threats_caught || 0 }}
        </div>
        <div class="text-sm text-gray-500">
          {{ ((effectiveness?.threats_caught / effectiveness?.total_sessions) * 100 || 0).toFixed(1) }}% of sessions
        </div>
      </div>
      <div class="card">
        <div class="text-gray-400 text-sm">Users Blocked</div>
        <div class="text-3xl font-bold text-red-400">{{ effectiveness?.blocked || 0 }}</div>
      </div>
      <div class="card">
        <div class="text-gray-400 text-sm">Avg Messages Before Honeypot</div>
        <div class="text-3xl font-bold">
          {{ Math.round(effectiveness?.avg_messages_before_honeypot || 0) }}
        </div>
      </div>
    </div>

    <!-- Timeline Chart -->
    <div class="card">
      <h2 class="card-header">Event Timeline</h2>
      <div class="h-64">
        <Line :data="timelineChartData" :options="chartOptions" />
      </div>
    </div>

    <!-- Attack Types Chart -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <div class="card">
        <h2 class="card-header">Attack Types Distribution</h2>
        <div class="h-64">
          <Doughnut :data="attackTypesChartData" :options="pieOptions" />
        </div>
      </div>

      <div class="card">
        <h2 class="card-header">Events by Category</h2>
        <div class="h-64">
          <Bar :data="categoryChartData" :options="barOptions" />
        </div>
      </div>
    </div>

    <!-- Top Threats -->
    <div class="card">
      <h2 class="card-header">Top Threats</h2>
      <table class="data-table">
        <thead>
          <tr>
            <th>Bot</th>
            <th>User</th>
            <th>Score</th>
            <th>Detections</th>
            <th>Time</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="threat in topThreats" :key="threat.event_id">
            <td>
              <div class="font-medium">{{ threat.persona_name }}</div>
              <div class="text-xs text-gray-500">{{ threat.persona_category }}</div>
            </td>
            <td>{{ threat.user_id }}</td>
            <td class="text-red-400 font-bold">{{ Math.round(threat.threat_score) }}</td>
            <td>
              <div class="flex flex-wrap gap-1">
                <span
                  v-for="dt in threat.detection_types?.slice(0, 3)"
                  :key="dt"
                  class="text-xs px-2 py-0.5 rounded bg-gray-700"
                >
                  {{ dt }}
                </span>
              </div>
            </td>
            <td class="text-gray-500 text-sm">{{ formatTime(threat.created_at) }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Attack Type Details -->
    <div class="card">
      <h2 class="card-header">Attack Type Statistics</h2>
      <table class="data-table">
        <thead>
          <tr>
            <th>Attack Type</th>
            <th>Count</th>
            <th>Avg Score</th>
            <th>Max Score</th>
            <th>Unique Users</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="at in attackTypes" :key="at.attack_type">
            <td class="font-medium">{{ at.attack_type }}</td>
            <td>{{ at.count }}</td>
            <td :class="getScoreColor(at.avg_score)">{{ Math.round(at.avg_score) }}</td>
            <td :class="getScoreColor(at.max_score)">{{ Math.round(at.max_score) }}</td>
            <td>{{ at.unique_users }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { api } from '../services/api'
import { formatDistanceToNow } from 'date-fns'
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
} from 'chart.js'
import { Line, Bar, Doughnut } from 'vue-chartjs'

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
)

const props = defineProps(['socket'])

const hours = ref(24)
const overview = ref(null)
const timeline = ref([])
const attackTypes = ref([])
const categoryMetrics = ref([])
const topThreats = ref([])
const effectiveness = ref(null)

const chartOptions = {
  responsive: true,
  maintainAspectRatio: false,
  scales: {
    x: {
      grid: { color: 'rgba(255,255,255,0.1)' },
      ticks: { color: '#9ca3af' }
    },
    y: {
      grid: { color: 'rgba(255,255,255,0.1)' },
      ticks: { color: '#9ca3af' }
    }
  },
  plugins: {
    legend: { labels: { color: '#9ca3af' } }
  }
}

const barOptions = {
  ...chartOptions,
  indexAxis: 'y'
}

const pieOptions = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: {
      position: 'right',
      labels: { color: '#9ca3af' }
    }
  }
}

const timelineChartData = computed(() => ({
  labels: timeline.value.map(t => new Date(t.hour).toLocaleTimeString([], { hour: '2-digit' })),
  datasets: [
    {
      label: 'Total Events',
      data: timeline.value.map(t => t.total_events),
      borderColor: '#3b82f6',
      backgroundColor: 'rgba(59, 130, 246, 0.1)',
      fill: true,
      tension: 0.4
    },
    {
      label: 'Warnings',
      data: timeline.value.map(t => t.warnings),
      borderColor: '#f59e0b',
      backgroundColor: 'rgba(245, 158, 11, 0.1)',
      fill: true,
      tension: 0.4
    },
    {
      label: 'Critical',
      data: timeline.value.map(t => t.critical),
      borderColor: '#ef4444',
      backgroundColor: 'rgba(239, 68, 68, 0.1)',
      fill: true,
      tension: 0.4
    }
  ]
}))

const attackTypesChartData = computed(() => {
  const colors = [
    '#ef4444', '#f59e0b', '#22c55e', '#3b82f6', '#8b5cf6',
    '#ec4899', '#14b8a6', '#f97316', '#06b6d4', '#84cc16'
  ]
  return {
    labels: attackTypes.value.map(a => a.attack_type),
    datasets: [{
      data: attackTypes.value.map(a => a.count),
      backgroundColor: colors.slice(0, attackTypes.value.length),
      borderWidth: 0
    }]
  }
})

const categoryChartData = computed(() => ({
  labels: categoryMetrics.value.map(c => c.persona_category?.replace(/_/g, ' ')),
  datasets: [{
    label: 'Events',
    data: categoryMetrics.value.map(c => c.total_events),
    backgroundColor: '#f59e0b',
    borderRadius: 4
  }]
}))

async function loadData() {
  try {
    const [
      overviewData,
      timelineData,
      attackData,
      categoryData,
      threatsData,
      effectData
    ] = await Promise.all([
      api.getOverview(),
      api.getTimeline(hours.value),
      api.getAttackTypes(hours.value),
      api.getByCategory(hours.value),
      api.getTopThreats(hours.value, 10),
      api.getEffectiveness(hours.value)
    ])

    overview.value = overviewData
    timeline.value = timelineData.timeline
    attackTypes.value = attackData.attack_types
    categoryMetrics.value = categoryData.categories
    topThreats.value = threatsData.threats
    effectiveness.value = effectData.effectiveness
  } catch (error) {
    console.error('Failed to load metrics:', error)
  }
}

function formatTime(timestamp) {
  return formatDistanceToNow(new Date(timestamp), { addSuffix: true })
}

function getScoreColor(score) {
  if (score >= 80) return 'text-red-400'
  if (score >= 60) return 'text-honey-400'
  return 'text-green-400'
}

onMounted(() => {
  loadData()
})
</script>
