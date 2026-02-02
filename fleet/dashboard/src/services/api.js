const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000'

async function fetchJson(url, options = {}) {
  const response = await fetch(`${API_URL}${url}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options.headers
    }
  })

  if (!response.ok) {
    throw new Error(`API Error: ${response.status}`)
  }

  return response.json()
}

export const api = {
  // Bots
  getBots: (params = {}) => {
    const query = new URLSearchParams(params).toString()
    return fetchJson(`/api/bots${query ? `?${query}` : ''}`)
  },

  getBot: (botId) => fetchJson(`/api/bots/${botId}`),

  getCategorySummary: () => fetchJson('/api/bots/categories/summary'),

  // Events
  getEvents: (params = {}) => {
    const query = new URLSearchParams(params).toString()
    return fetchJson(`/api/events${query ? `?${query}` : ''}`)
  },

  getEvent: (eventId) => fetchJson(`/api/events/${eventId}`),

  // Sessions
  getSessions: (params = {}) => {
    const query = new URLSearchParams(params).toString()
    return fetchJson(`/api/sessions${query ? `?${query}` : ''}`)
  },

  getSession: (sessionId) => fetchJson(`/api/sessions/${sessionId}`),

  getSessionReplay: (sessionId) => fetchJson(`/api/sessions/${sessionId}/replay`),

  getActiveSessions: () => fetchJson('/api/sessions/active/count'),

  // Metrics
  getOverview: () => fetchJson('/api/metrics/overview'),

  getAttackTypes: (hours = 24) => fetchJson(`/api/metrics/attack-types?hours=${hours}`),

  getTimeline: (hours = 24, botId = null) => {
    const params = { hours }
    if (botId) params.bot_id = botId
    const query = new URLSearchParams(params).toString()
    return fetchJson(`/api/metrics/timeline?${query}`)
  },

  getTopThreats: (hours = 24, limit = 10) =>
    fetchJson(`/api/metrics/top-threats?hours=${hours}&limit=${limit}`),

  getByCategory: (hours = 24) => fetchJson(`/api/metrics/by-category?hours=${hours}`),

  getEffectiveness: (hours = 24) =>
    fetchJson(`/api/metrics/detection-effectiveness?hours=${hours}`),

  // Patterns
  getPatterns: (params = {}) => {
    const query = new URLSearchParams(params).toString()
    return fetchJson(`/api/patterns${query ? `?${query}` : ''}`)
  },

  getPatternQueue: (minOccurrences = 2) =>
    fetchJson(`/api/patterns/queue?min_occurrences=${minOccurrences}`),

  getPattern: (id) => fetchJson(`/api/patterns/${id}`),

  reviewPattern: (id, data) =>
    fetchJson(`/api/patterns/${id}/review`, {
      method: 'PUT',
      body: JSON.stringify(data)
    }),

  getPatternStats: () => fetchJson('/api/patterns/stats/summary')
}
