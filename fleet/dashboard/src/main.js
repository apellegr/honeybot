import { createApp } from 'vue'
import { createPinia } from 'pinia'
import { createRouter, createWebHistory } from 'vue-router'
import App from './App.vue'
import './style.css'

// Components
import FleetOverview from './components/FleetOverview.vue'
import EventFeed from './components/EventFeed.vue'
import SessionViewer from './components/SessionViewer.vue'
import MetricsCharts from './components/MetricsCharts.vue'
import PatternQueue from './components/PatternQueue.vue'

const routes = [
  { path: '/', component: FleetOverview },
  { path: '/events', component: EventFeed },
  { path: '/sessions', component: SessionViewer },
  { path: '/sessions/:id', component: SessionViewer },
  { path: '/metrics', component: MetricsCharts },
  { path: '/patterns', component: PatternQueue }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

const pinia = createPinia()
const app = createApp(App)

app.use(pinia)
app.use(router)
app.mount('#app')
