import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, ".", "");
  const proxyTarget = env.VITE_API_PROXY_TARGET || "http://127.0.0.1:8080";

  return {
    plugins: [react(), tailwindcss()],
    build: {
      rollupOptions: {
        output: {
          manualChunks: {
            "react-vendor": ["react", "react-dom", "react-router-dom"],
            "query-vendor": ["@tanstack/react-query", "openapi-fetch"],
            "graph-vendor": ["@xyflow/react", "dagre"],
          },
        },
      },
    },
    server: {
      port: 5173,
      proxy: {
        "/api": {
          target: proxyTarget,
          changeOrigin: true,
        },
        "/healthz": {
          target: proxyTarget,
          changeOrigin: true,
        },
        "/readyz": {
          target: proxyTarget,
          changeOrigin: true,
        },
      },
    },
  };
});
