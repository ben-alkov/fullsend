import path from "node:path";
import { fileURLToPath } from "node:url";
import type { ProxyOptions } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import { defineConfig } from "vitest/config";
import type { Plugin } from "vite";

const repoRoot = path.dirname(fileURLToPath(import.meta.url));
const adminDir = path.join(repoRoot, "web", "admin");

const debugProxy = process.env.ADMIN_DEBUG_PROXY === "1";

/** GitHub App OAuth for local admin: only `process.env` (same shell as `npm run dev` + Wrangler). */
function githubAppClientId(): string {
  return (
    process.env.GITHUB_APP_CLIENT_ID?.trim() ||
    process.env.VITE_GITHUB_APP_CLIENT_ID?.trim() ||
    ""
  );
}

function githubAppClientSecret(): string {
  return process.env.GITHUB_APP_CLIENT_SECRET?.trim() || "";
}

function adminDevEnvLogPlugin(): Plugin {
  return {
    name: "admin-dev-env-log",
    configResolved(config) {
      if (config.command !== "serve" || process.env.VITEST) return;

      const id = githubAppClientId();
      const secret = githubAppClientSecret();

      if (!id) {
        console.error(
          "\n[fullsend-admin] GITHUB_APP_CLIENT_ID is unset or empty. " +
            "Set it in the environment before starting the dev server. Sign-in will fail until this is fixed.\n",
        );
      }

      if (!secret) {
        console.warn(
          "\n[fullsend-admin] GITHUB_APP_CLIENT_SECRET is unset or empty. " +
            "The local OAuth Worker cannot exchange codes until it is set in the environment.\n",
        );
      }

      if (debugProxy) {
        console.info(
          "\n[fullsend-admin] ADMIN_DEBUG_PROXY=1 — logging Vite requests and /api → Worker proxy traffic.\n",
        );
      }
    },
  };
}

/** Log every HTTP request the Vite dev server receives (not Worker-native). */
function adminRequestLogPlugin(): Plugin {
  return {
    name: "admin-request-log",
    configureServer(server) {
      if (!debugProxy) return;
      server.middlewares.use((req, _res, next) => {
        console.info("[vite] request", req.method, req.url);
        next();
      });
    },
  };
}

function apiProxy(): ProxyOptions {
  const base: ProxyOptions = {
    target: "http://127.0.0.1:8787",
    changeOrigin: true,
  };

  if (!debugProxy) return base;

  return {
    ...base,
    configure(proxy) {
      proxy.on("error", (err, req) => {
        console.error("[vite-proxy] error", req?.url, err.message);
      });
      proxy.on("proxyReq", (_proxyReq, req) => {
        console.info("[vite-proxy] → Worker", req.method, req.url);
      });
      proxy.on("proxyRes", (proxyRes, req) => {
        console.info(
          "[vite-proxy] ← Worker",
          proxyRes.statusCode,
          req.url,
        );
      });
    },
  };
}

export default defineConfig(() => {
  const githubClientId = githubAppClientId();

  return {
    root: adminDir,
    base: "/admin/",
    /** Only the client id is exposed to the browser; never `GITHUB_APP_CLIENT_SECRET`. */
    define: {
      "import.meta.env.VITE_GITHUB_APP_CLIENT_ID":
        JSON.stringify(githubClientId),
    },
    plugins: [
      svelte(),
      adminDevEnvLogPlugin(),
      adminRequestLogPlugin(),
    ],
    server: {
      proxy: {
        "/api": apiProxy(),
      },
    },
    test: {
      environment: "jsdom",
      include: ["src/**/*.test.ts"],
      passWithNoTests: true,
    },
  };
});
