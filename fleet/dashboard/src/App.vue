<template>
  <div class="min-h-screen bg-gray-900">
    <!-- Navigation -->
    <nav class="bg-gray-800 border-b border-gray-700">
      <div class="max-w-7xl mx-auto px-4">
        <div class="flex items-center justify-between h-16">
          <div class="flex items-center space-x-8">
            <div class="flex items-center">
              <span class="text-2xl">🍯</span>
              <span class="ml-2 text-xl font-bold text-honey-400">Honeybot Fleet</span>
            </div>
            <div class="flex space-x-4">
              <router-link to="/" class="nav-link" :class="{ active: $route.path === '/' }">
                Overview
              </router-link>
              <router-link to="/events" class="nav-link" :class="{ active: $route.path === '/events' }">
                Events
              </router-link>
              <router-link to="/sessions" class="nav-link" :class="{ active: $route.path.startsWith('/sessions') }">
                Sessions
              </router-link>
              <router-link to="/metrics" class="nav-link" :class="{ active: $route.path === '/metrics' }">
                Metrics
              </router-link>
              <router-link to="/patterns" class="nav-link" :class="{ active: $route.path === '/patterns' }">
                Patterns
              </router-link>
            </div>
          </div>
          <div class="flex items-center space-x-4">
            <div class="flex items-center">
              <span class="w-2 h-2 rounded-full mr-2" :class="connected ? 'bg-green-500 live-indicator' : 'bg-red-500'"></span>
              <span class="text-sm text-gray-400">{{ connected ? 'Live' : 'Disconnected' }}</span>
            </div>
          </div>
        </div>
      </div>
    </nav>

    <!-- Main Content -->
    <main class="max-w-7xl mx-auto px-4 py-6">
      <router-view :socket="socket" />
    </main>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { io } from 'socket.io-client'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000'
const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:3000'

const socket = ref(null)
const connected = ref(false)

onMounted(() => {
  socket.value = io(WS_URL)

  socket.value.on('connect', () => {
    connected.value = true
    console.log('Connected to server')
  })

  socket.value.on('disconnect', () => {
    connected.value = false
    console.log('Disconnected from server')
  })
})

onUnmounted(() => {
  if (socket.value) {
    socket.value.disconnect()
  }
})
</script>

<style scoped>
.nav-link {
  @apply px-3 py-2 text-gray-300 hover:text-white hover:bg-gray-700 rounded-md transition-colors;
}

.nav-link.active {
  @apply text-honey-400 bg-gray-700;
}
</style>
