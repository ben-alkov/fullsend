export type StoredToken = {
  accessToken: string;
  tokenType: string;
  expiresAt: number;
};

const KEY = "fullsend_admin_github_token";

export function saveToken(t: StoredToken): void {
  localStorage.setItem(KEY, JSON.stringify(t));
}

export function loadToken(): StoredToken | null {
  const raw = localStorage.getItem(KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as StoredToken;
  } catch {
    return null;
  }
}

export function clearSession(): void {
  localStorage.removeItem(KEY);
}
