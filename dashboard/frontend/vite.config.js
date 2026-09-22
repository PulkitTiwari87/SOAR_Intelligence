import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  test: { environment: 'jsdom' },
  // `npm run dev` proxies /api to a locally running backend (uvicorn soar.main:app --port 8010),
  // so the browser stays same-origin exactly as it is behind nginx in docker compose. 8010/5180 (not
  // 8000/5173) because those default ports are already taken by another project on this machine.
  server: { port: 5180, proxy: { '/api': { target: 'http://127.0.0.1:8010', changeOrigin: false } } },
})
