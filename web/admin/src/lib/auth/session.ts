import { writable } from "svelte/store";
import { clearSession, loadToken } from "./tokenStore";
import { fetchGitHubUser } from "../github/user";

/** GitHub login for signed-in user, or null. */
export const githubLogin = writable<string | null>(null);

export async function refreshSession(): Promise<void> {
  const t = loadToken();
  if (!t?.accessToken) {
    githubLogin.set(null);
    return;
  }
  try {
    const u = await fetchGitHubUser(t.accessToken);
    githubLogin.set(u.login);
  } catch {
    githubLogin.set(null);
  }
}

export function signOut(): void {
  clearSession();
  githubLogin.set(null);
}
