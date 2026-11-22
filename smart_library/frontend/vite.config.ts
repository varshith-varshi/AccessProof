import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Dev: `npm run dev` serves on :5173 and proxies /api to the FastAPI server on :8000.
// Build: output goes to ../app/web, which FastAPI serves at http://localhost:8000.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: { outDir: "../app/web", emptyOutDir: true, chunkSizeWarningLimit: 900 },
  server: { port: 5173, proxy: { "/api": "http://127.0.0.1:8000" } },
});
