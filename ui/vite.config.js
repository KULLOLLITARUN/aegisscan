import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
  build: {
    // Must land inside the Python package: pyproject package-data ships scanner/server/dist/**
    outDir: '../scanner/server/dist',
    emptyOutDir: true,
  },
})
