/// <reference types="svelte" />
/// <reference types="vite/client" />

/** Merged with `vite/client` (see root `vite.config.ts` `base` and `define`). */
interface ImportMetaEnv {
  /** Vite `base` (e.g. `/admin/`). */
  readonly BASE: string;
  /** Injected at build from `GITHUB_APP_CLIENT_ID` / `VITE_GITHUB_APP_CLIENT_ID` via root `vite.config.ts` (never the secret). */
  readonly VITE_GITHUB_APP_CLIENT_ID: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
