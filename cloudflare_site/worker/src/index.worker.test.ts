import { env } from "cloudflare:workers";
import {
  createExecutionContext,
  waitOnExecutionContext,
} from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import worker from "./index";

const IncomingRequest = Request;

describe("site worker admin API", () => {
  let originalFetch: typeof fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("OPTIONS returns 204 with CORS headers when Origin is allowed (localhost)", async () => {
    const url = new URL("https://worker.test/api/oauth/token");
    const req = new IncomingRequest(url, {
      method: "OPTIONS",
      headers: { Origin: "http://127.0.0.1:5173" },
    });
    const ctx = createExecutionContext();
    const res = await worker.fetch(req, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(res.status).toBe(204);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe(
      "http://127.0.0.1:5173",
    );
  });

  it("OPTIONS returns 403 without usable CORS origin for admin API", async () => {
    const site = "https://worker.test";
    const url = new URL(`${site}/api/oauth/token`);
    const req = new IncomingRequest(url, {
      method: "OPTIONS",
      headers: {
        Origin: "https://attacker.example",
      },
    });
    const ctx = createExecutionContext();
    const res = await worker.fetch(req, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(res.status).toBe(403);
  });

  it("returns 403 forbidden_origin for token POST when Origin does not match redirect_uri", async () => {
    const site = "https://worker.test";
    const url = new URL(`${site}/api/oauth/token`);
    const req = new IncomingRequest(url, {
      method: "POST",
      headers: {
        Origin: "http://localhost:9999",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        code: "abc",
        redirect_uri: "http://localhost:5173/admin/",
        code_verifier: "verifierverifierverifierverifier01",
        turnstile_token: "dummy",
      }),
    });
    const ctx = createExecutionContext();
    const res = await worker.fetch(req, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error?: string };
    expect(body.error).toBe("forbidden_origin");
  });

  it("returns 503 missing_turnstile_keys when Turnstile vars are empty", async () => {
    const site = "https://worker.test";
    const url = new URL(`${site}/api/oauth/token`);
    const req = new IncomingRequest(url, {
      method: "OPTIONS",
      headers: { Origin: "http://localhost:5173" },
    });
    const ctx = createExecutionContext();
    const strippedEnv = {
      ...env,
      TURNSTILE_SITE_KEY: "",
      TURNSTILE_SECRET_KEY: "",
    };
    const res = await worker.fetch(req, strippedEnv, ctx);
    await waitOnExecutionContext(ctx);
    expect(res.status).toBe(503);
    const body = (await res.json()) as { detail?: string };
    expect(body.detail).toBe("missing_turnstile_keys");
  });

  it("exchanges token with mocked GitHub and Turnstile (no real network)", async () => {
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url.includes("challenges.cloudflare.com/turnstile")) {
        return new Response(JSON.stringify({ success: true }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url.includes("github.com/login/oauth/access_token")) {
        return new Response(
          JSON.stringify({
            access_token: "gho_test_token",
            token_type: "bearer",
            expires_in: 3600,
          }),
          {
            status: 200,
            headers: { "content-type": "application/json" },
          },
        );
      }
      return new Response(`unexpected fetch: ${url}`, { status: 500 });
    }) as typeof fetch;

    const site = "https://worker.test";
    const redirect = "http://localhost:5173/admin/";
    const url = new URL(`${site}/api/oauth/token`);
    const req = new IncomingRequest(url, {
      method: "POST",
      headers: {
        Origin: new URL(redirect).origin,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        code: "exchange-code",
        redirect_uri: redirect,
        code_verifier: "verifierverifierverifierverifier01",
        turnstile_token: "dummy-turnstile",
      }),
    });
    const ctx = createExecutionContext();
    const res = await worker.fetch(req, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { access_token?: string };
    expect(body.access_token).toBe("gho_test_token");
  });

  it("proxies /api/github/user with mocked api.github.com", async () => {
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url.startsWith("https://api.github.com/user")) {
        return new Response(JSON.stringify({ login: "octocat" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response(`unexpected fetch: ${url}`, { status: 500 });
    }) as typeof fetch;

    const site = "https://worker.test";
    const url = new URL(`${site}/api/github/user`);
    const req = new IncomingRequest(url, {
      method: "GET",
      headers: {
        Origin: "http://localhost:5173",
        Authorization: "Bearer gho_fake",
        Accept: "application/vnd.github+json",
      },
    });
    const ctx = createExecutionContext();
    const res = await worker.fetch(req, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { login?: string };
    expect(body.login).toBe("octocat");
  });
});
