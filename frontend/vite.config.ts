/// <reference types="vitest/config" />
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// The dashboard and the API are served from one origin in development: /api (and the WebSocket)
// are proxied to the API process. Cookies are SameSite=Strict with Path=/api, so a same-origin
// proxy is also what lets the session work without any CORS configuration.
const API = process.env.NETGUARD_API_URL ?? 'http://127.0.0.1:8000'

export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    proxy: { '/api': { target: API, ws: true, changeOrigin: false } },
  },
  preview: { host: '127.0.0.1', port: 5173, proxy: { '/api': { target: API, ws: true } } },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test-setup.ts'],
    css: false,
  },
})
