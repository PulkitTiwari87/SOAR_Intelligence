import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  test: { environment: 'jsdom' },
  // `npm run dev` proxies /api to a locally running backend (uvicorn soar.main:app --port 8000),
  // so the browser stays same-origin exactly as it is behind nginx in docker compose.
  server: { port: 5173, proxy: { '/api': { target: 'http://127.0.0.1:8000', changeOrigin: false } } },
})
