import { describe, expect, it } from "vitest";
import { tryParseWorkerExpandedOauthState } from "./oauth";

describe("tryParseWorkerExpandedOauthState", () => {
  it("returns null for raw UUID state", () => {
    expect(
      tryParseWorkerExpandedOauthState("550e8400-e29b-41d4-a716-446655440000"),
    ).toBeNull();
  });

  it("parses worker-expanded base64url JSON state", () => {
    const payload = { v: 1, n: "nonce-value", k: "0x4AAA_sitekey" };
    const bytes = new TextEncoder().encode(JSON.stringify(payload));
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    const b64 = btoa(bin)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    expect(tryParseWorkerExpandedOauthState(b64)).toEqual({
      v: 1,
      n: "nonce-value",
      k: "0x4AAA_sitekey",
    });
  });
});
