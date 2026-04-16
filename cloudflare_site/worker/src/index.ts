/// <reference types="@cloudflare/workers-types" />

/**
 * Site Worker: static assets via `[assets]` plus optional localhost-only OAuth BFF
 * routes for the admin SPA (`/api/oauth/token`, `/api/github/user`).
 */
export interface Env {
  ASSETS?: Fetcher;
  GITHUB_APP_CLIENT_ID: string;
  GITHUB_APP_CLIENT_SECRET: string;
  /** Set to `"1"` via `wrangler dev --var DEBUG_LOG:1` (see root `npm run dev:debug`). */
  DEBUG_LOG?: string;
}

const TOKEN_URL = "https://github.com/login/oauth/access_token";
const GITHUB_USER_URL = "https://api.github.com/user";

function isAdminApiPath(pathname: string): boolean {
  return (
    pathname === "/api/oauth/token" || pathname === "/api/github/user"
  );
}

/** Dev-only: any localhost / 127.0.0.1 HTTP port (Vite may not use 5173). */
function isLocalhostDevOrigin(origin: string): boolean {
  if (!origin) return false;
  try {
    const u = new URL(origin);
    return (
      u.protocol === "http:" &&
      (u.hostname === "localhost" ||
        u.hostname === "127.0.0.1" ||
        u.hostname === "[::1]")
    );
  } catch {
    return false;
  }
}

/**
 * Dev-only: redirect_uri must target the admin SPA entry (or legacy static callback)
 * on loopback, matching the GitHub App registration.
 */
function isLocalhostDevRedirectUri(redirectUri: string): boolean {
  if (!redirectUri) return false;
  try {
    const u = new URL(redirectUri);
    const p = u.pathname;
    const allowedPath =
      p === "/admin/" ||
      p === "/admin" ||
      p === "/admin/oauth/callback.html";
    return (
      u.protocol === "http:" &&
      (u.hostname === "localhost" ||
        u.hostname === "127.0.0.1" ||
        u.hostname === "[::1]") &&
      allowedPath
    );
  } catch {
    return false;
  }
}

/**
 * Browsers often omit `Origin` on same-origin GET `fetch()`, but the dev Worker still
 * needs a loopback origin for CORS + allowlisting. Fall back to `Referer` when safe.
 */
function getEffectiveLoopbackOrigin(request: Request): string | null {
  const originHeader = request.headers.get("Origin") ?? "";
  if (isLocalhostDevOrigin(originHeader)) return originHeader;

  if (!originHeader) {
    const ref = request.headers.get("Referer") ?? "";
    try {
      const o = new URL(ref).origin;
      if (isLocalhostDevOrigin(o)) return o;
    } catch {
      /* ignore */
    }
  }
  return null;
}

function corsHeaders(request: Request): HeadersInit {
  const origin = getEffectiveLoopbackOrigin(request);
  if (!origin) {
    return {};
  }
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers":
      "Content-Type, Authorization, Accept, X-GitHub-Api-Version",
    "Access-Control-Max-Age": "86400",
  };
}

type ExchangeBody = {
  code?: string;
  redirect_uri?: string;
  code_verifier?: string;
};

function requireAllowedOrigin(request: Request): string | null {
  return getEffectiveLoopbackOrigin(request);
}

async function handleOAuthToken(
  request: Request,
  env: Env,
  cors: HeadersInit,
): Promise<Response> {
  if (request.method !== "POST") {
    return new Response(JSON.stringify({ error: "method_not_allowed" }), {
      status: 405,
      headers: { "content-type": "application/json", ...cors },
    });
  }

  const ct = request.headers.get("Content-Type") ?? "";
  if (!ct.includes("application/json")) {
    return new Response(JSON.stringify({ error: "unsupported_media_type" }), {
      status: 415,
      headers: { "content-type": "application/json", ...cors },
    });
  }

  let body: ExchangeBody;
  try {
    body = (await request.json()) as ExchangeBody;
  } catch {
    return new Response(JSON.stringify({ error: "invalid_json" }), {
      status: 400,
      headers: { "content-type": "application/json", ...cors },
    });
  }

  const code = typeof body.code === "string" ? body.code.trim() : "";
  const redirect_uri =
    typeof body.redirect_uri === "string" ? body.redirect_uri.trim() : "";
  const code_verifier =
    typeof body.code_verifier === "string" ? body.code_verifier.trim() : "";

  if (!code || !redirect_uri || !code_verifier) {
    return new Response(JSON.stringify({ error: "missing_fields" }), {
      status: 400,
      headers: { "content-type": "application/json", ...cors },
    });
  }

  if (!isLocalhostDevRedirectUri(redirect_uri)) {
    return new Response(JSON.stringify({ error: "invalid_redirect_uri" }), {
      status: 400,
      headers: { "content-type": "application/json", ...cors },
    });
  }

  const clientId = (env.GITHUB_APP_CLIENT_ID ?? "").trim();
  const clientSecret = (env.GITHUB_APP_CLIENT_SECRET ?? "").trim();
  if (!clientId || !clientSecret) {
    return new Response(JSON.stringify({ error: "server_misconfigured" }), {
      status: 500,
      headers: { "content-type": "application/json", ...cors },
    });
  }

  const ghBody = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    code,
    redirect_uri,
    code_verifier,
  });

  const ghRes = await fetch(TOKEN_URL, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: ghBody.toString(),
  });

  const ghJson: unknown = await ghRes.json().catch(() => ({}));
  const rec = ghJson as Record<string, unknown>;
  const access_token =
    typeof rec.access_token === "string" ? rec.access_token : undefined;
  const error = typeof rec.error === "string" ? rec.error : undefined;
  const error_description =
    typeof rec.error_description === "string"
      ? rec.error_description
      : undefined;

  if (!ghRes.ok || error || !access_token) {
    return new Response(
      JSON.stringify({
        error: error ?? "token_exchange_failed",
        error_description: error_description ?? null,
      }),
      {
        status: 400,
        headers: { "content-type": "application/json", ...cors },
      },
    );
  }

  const token_type =
    typeof rec.token_type === "string" ? rec.token_type : "bearer";
  const expires_in =
    typeof rec.expires_in === "number" ? rec.expires_in : undefined;

  return new Response(
    JSON.stringify({
      access_token,
      token_type,
      expires_in: expires_in ?? null,
    }),
    {
      status: 200,
      headers: { "content-type": "application/json", ...cors },
    },
  );
}

/** Server-side GitHub /user so the browser never hits api.github.com (no CORS). */
async function handleGithubUser(
  request: Request,
  cors: HeadersInit,
): Promise<Response> {
  if (request.method !== "GET") {
    return new Response(JSON.stringify({ error: "method_not_allowed" }), {
      status: 405,
      headers: { "content-type": "application/json", ...cors },
    });
  }

  const auth = request.headers.get("Authorization") ?? "";
  if (!auth.startsWith("Bearer ") || auth.length < 10) {
    return new Response(JSON.stringify({ error: "missing_bearer_token" }), {
      status: 401,
      headers: { "content-type": "application/json", ...cors },
    });
  }

  const accept = request.headers.get("Accept") ?? "application/vnd.github+json";
  const apiVersion = request.headers.get("X-GitHub-Api-Version") ?? "2022-11-28";

  const ghRes = await fetch(GITHUB_USER_URL, {
    headers: {
      Accept: accept,
      Authorization: auth,
      "X-GitHub-Api-Version": apiVersion,
      "User-Agent": "fullsend-admin-oauth-worker",
    },
  });

  const text = await ghRes.text();
  return new Response(text, {
    status: ghRes.status,
    headers: {
      "content-type": ghRes.headers.get("content-type") ?? "application/json",
      ...cors,
    },
  });
}

async function handleAdminApi(
  request: Request,
  env: Env,
  url: URL,
): Promise<Response> {
  if (env.DEBUG_LOG === "1") {
    console.log("[worker]", request.method, url.pathname);
  }

  const cors = corsHeaders(request);

  if (request.method === "OPTIONS") {
    if (!requireAllowedOrigin(request)) {
      return new Response(null, { status: 403 });
    }
    return new Response(null, { status: 204, headers: cors });
  }

  if (!requireAllowedOrigin(request)) {
    return new Response(JSON.stringify({ error: "forbidden_origin" }), {
      status: 403,
      headers: { "content-type": "application/json" },
    });
  }

  if (url.pathname === "/api/oauth/token") {
    return handleOAuthToken(request, env, cors);
  }

  if (url.pathname === "/api/github/user") {
    return handleGithubUser(request, cors);
  }

  return new Response(JSON.stringify({ error: "not_found" }), {
    status: 404,
    headers: { "content-type": "application/json", ...cors },
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (isAdminApiPath(url.pathname)) {
      return handleAdminApi(request, env, url);
    }

    if (url.pathname.startsWith("/api/")) {
      return new Response(JSON.stringify({ error: "not_found" }), {
        status: 404,
        headers: { "content-type": "application/json" },
      });
    }

    if (env.ASSETS != null) {
      return env.ASSETS.fetch(request);
    }
    return new Response("Worker misconfigured: ASSETS binding missing", {
      status: 503,
    });
  },
};
