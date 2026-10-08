import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// 开发模式下把 /api 与 WebSocket 代理到后端 8002 端口；
// 生产构建产物由 FastAPI 直接托管，单端口访问。
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8002',
        changeOrigin: true,
        ws: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    chunkSizeWarningLimit: 900,
  },
})
