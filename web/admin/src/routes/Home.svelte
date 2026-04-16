<script lang="ts">
  import { onMount } from "svelte";
  import { githubLogin } from "../lib/auth/session";
  import { loadToken } from "../lib/auth/tokenStore";
  import { fetchGitHubUser } from "../lib/github/user";

  const hash =
    typeof window !== "undefined" ? window.location.hash || "#/" : "#/";

  let apiProof = $state<string>("(not loaded)");
  let apiErr = $state<string | null>(null);

  async function refreshProof(): Promise<void> {
    apiErr = null;
    const t = loadToken();
    if (!t?.accessToken) {
      apiProof = "Sign in to verify GitHub API access.";
      return;
    }
    try {
      const u = await fetchGitHubUser(t.accessToken);
      apiProof = `GET /user → login: ${u.login}${u.name ? `, name: ${u.name}` : ""}`;
    } catch (e) {
      apiErr = e instanceof Error ? e.message : String(e);
      apiProof = "";
    }
  }

  onMount(() => {
    void refreshProof();
    const unsub = githubLogin.subscribe(() => {
      void refreshProof();
    });
    return () => unsub();
  });
</script>

<p>Admin shell is up.</p>
<p>Current hash: <code>{hash}</code></p>

<section class="proof" aria-labelledby="api-proof-h">
  <h2 id="api-proof-h">API access proof</h2>
  {#if $githubLogin}
    <p>Signed in as <strong>{$githubLogin}</strong>.</p>
  {:else}
    <p>Not signed in.</p>
  {/if}
  {#if apiErr}
    <p class="err">{apiErr}</p>
  {:else}
    <p class="mono">{apiProof}</p>
  {/if}
</section>

<style>
  .proof {
    margin-top: 1.5rem;
    padding: 1rem;
    border: 1px solid #ddd;
    border-radius: 8px;
    max-width: 42rem;
  }
  .proof h2 {
    margin: 0 0 0.5rem;
    font-size: 1rem;
  }
  .mono {
    font-family: ui-monospace, monospace;
    font-size: 0.85rem;
    word-break: break-word;
  }
  .err {
    color: #a40000;
  }
</style>
