import ky from 'ky'

// In development, Vite proxies /api to :8000
// In production, FastAPI serves the SPA and API is same origin
const api = ky.create({
  prefix: '/api',
  headers: { Accept: 'application/json' },
  timeout: 30_000,
})

export default api
