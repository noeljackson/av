<script lang="ts">
  import { onMount } from "svelte";

  type AuthConfig = {
    mode: "oidc" | "basic" | "oidc_or_basic" | "disabled";
    issuer: string;
    clientId: string;
    scopes: string[];
    authorizationEndpoint?: string;
    tokenEndpoint?: string;
  };

  type Profile = { name: string; environment: string; path: string };
  type Connector = { name: string; kind: string };
  type RuntimeStatus = {
    oidcEnabled: boolean;
    basicEnabled: boolean;
    persistenceEnabled: boolean;
    registrationEnabled: boolean;
    connectors: Connector[];
    profileCount: number;
    proxyRoutes: string[];
    apiRateLimitPerSecond: number;
    apiRateLimitBurst: number;
  };

  let auth: AuthConfig | undefined;
  let runtime: RuntimeStatus | undefined;
  let profiles: Profile[] = [];
  let authorization = "";
  let error = "";
  let busy = true;
  let username = "";
  let password = "";

  onMount(async () => {
    try {
      auth = await fetchJson<AuthConfig>("/v1/auth/config");
      sessionStorage.removeItem("av_oidc_token");
      const token = await finishOidcCallback();
      const candidate = token ? `Bearer ${token}` : auth.mode === "disabled" ? "disabled" : "";
      if (candidate) await loadSession(candidate);
    } catch (cause) {
      error = message(cause);
    } finally {
      busy = false;
    }
  });

  async function loginOidc() {
    if (!auth?.authorizationEndpoint) return;
    const verifier = randomBase64Url(48);
    const challenge = base64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
    const state = randomBase64Url(24);
    sessionStorage.setItem("av_oidc_verifier", verifier);
    sessionStorage.setItem("av_oidc_state", state);
    const url = new URL(auth.authorizationEndpoint);
    url.search = new URLSearchParams({
      response_type: "code",
      client_id: auth.clientId,
      redirect_uri: redirectUri(),
      scope: auth.scopes.join(" "),
      state,
      code_challenge: challenge,
      code_challenge_method: "S256"
    }).toString();
    location.assign(url);
  }

  async function finishOidcCallback(): Promise<string | undefined> {
    const params = new URLSearchParams(location.search);
    const code = params.get("code");
    if (!code) return undefined;
    if (!auth?.tokenEndpoint) throw new Error("OIDC token endpoint is unavailable");
    const state = params.get("state");
    const expectedState = sessionStorage.getItem("av_oidc_state");
    const verifier = sessionStorage.getItem("av_oidc_verifier");
    if (!state || state !== expectedState || !verifier) throw new Error("OIDC callback state was rejected");
    const response = await fetch(auth.tokenEndpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: auth.clientId,
        redirect_uri: redirectUri(),
        code,
        code_verifier: verifier
      })
    });
    if (!response.ok) throw new Error(`OIDC token exchange failed (${response.status})`);
    const token = (await response.json()) as { access_token: string };
    sessionStorage.removeItem("av_oidc_state");
    sessionStorage.removeItem("av_oidc_verifier");
    history.replaceState({}, "", "/");
    return token.access_token;
  }

  async function loginBasic() {
    const candidate = `Basic ${btoa(`${username}:${password}`)}`;
    password = "";
    busy = true;
    error = "";
    try {
      await loadSession(candidate);
    } catch (cause) {
      runtime = undefined;
      profiles = [];
      error = message(cause);
    } finally {
      busy = false;
    }
  }

  async function loadSession(candidate: string) {
    const headers = candidate === "disabled" ? {} : { authorization: candidate };
    const [runtimeStatus, availableProfiles] = await Promise.all([
      fetchJson<RuntimeStatus>("/v1/status", { headers }),
      fetchJson<Profile[]>("/v1/profiles", { headers })
    ]);
    runtime = runtimeStatus;
    profiles = availableProfiles;
    authorization = candidate;
  }

  function logout() {
    sessionStorage.removeItem("av_oidc_token");
    authorization = "";
    runtime = undefined;
    profiles = [];
    username = "";
    password = "";
    error = "";
  }

  function redirectUri() {
    return `${location.origin}/`;
  }

  function randomBase64Url(length: number) {
    return base64Url(crypto.getRandomValues(new Uint8Array(length)));
  }

  function base64Url(value: Uint8Array) {
    return btoa(String.fromCharCode(...value)).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
  }

  async function fetchJson<T>(input: string, init?: RequestInit): Promise<T> {
    const response = await fetch(input, { cache: "no-store", ...init });
    if (!response.ok) throw new Error(`request failed (${response.status})`);
    return (await response.json()) as T;
  }

  function message(cause: unknown) {
    return cause instanceof Error ? cause.message : "request failed";
  }
</script>

<svelte:head>
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; connect-src 'self' https:; script-src 'self'; style-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self' https:" />
</svelte:head>

<main class:connected={Boolean(authorization)}>
  <nav class="topline" aria-label="AV status">
    <a class="brand" href="/" aria-label="AV home"><span>~/</span>av</a>
    <div class:linked={Boolean(authorization)} class="link-state">
      <span class="status-dot"></span>
      {busy ? "negotiating" : authorization ? "identity linked" : "identity required"}
    </div>
  </nav>

  {#if !authorization}
    <section class="secure-screen">
      <header class="secure-heading">
        <span class="lock-mark" aria-hidden="true">[::]</span>
        <div>
          <p class="kicker">restricted</p>
          <h1>authentication required</h1>
          <p>Sign in to continue. Workspace details are unavailable before authentication.</p>
        </div>
      </header>

      <section class="terminal auth-terminal" aria-live="polite">
        <header class="terminal-bar"><span>session://locked</span><span>access denied</span></header>

        {#if busy}
          <div class="terminal-body compact">
            <p class="command"><span>$</span> av auth</p>
            <p class="output pulse">checking session_</p>
          </div>
        {:else}
          <div class="terminal-body auth">
            {#if error}
              <div class="error">
                <p class="command"><span>!</span> authentication failed</p>
                <p class="output">{error}</p>
              </div>
            {/if}

            {#if auth?.mode === "oidc" || auth?.mode === "oidc_or_basic"}
              <button class="primary" onclick={loginOidc}><span>[</span> continue with identity provider <span>]</span></button>
            {/if}

            {#if auth?.mode === "basic" || auth?.mode === "oidc_or_basic"}
              {#if auth.mode === "oidc_or_basic"}<div class="divider"><span>or</span></div>{/if}
              <div class="fields">
                <label><span>user</span><input autocomplete="username" bind:value={username} /></label>
                <label><span>pass</span><input type="password" autocomplete="current-password" bind:value={password} /></label>
              </div>
              <button onclick={loginBasic}><span>[</span> sign in <span>]</span></button>
            {/if}
          </div>
        {/if}
      </section>
    </section>
  {:else}
    <section class="dashboard" aria-live="polite">
      <header class="dashboard-heading">
        <div><p class="kicker">authenticated session</p><h1>runtime</h1></div>
        <button class="quiet" onclick={logout}>disconnect</button>
      </header>

      {#if busy}
        <section class="terminal"><div class="terminal-body compact"><p class="output pulse">loading authorized workspace_</p></div></section>
      {:else if error}
        <section class="terminal"><div class="terminal-body compact error"><p class="command"><span>!</span> session rejected</p><p class="output">{error}</p></div></section>
      {:else if runtime}
        <section class="terminal">
          <section class="runtime-matrix" aria-label="Runtime capabilities">
            <header><span>runtime matrix</span><span>authorized view</span></header>
            <div class="capabilities">
              <div><span>oidc</span><strong class:on={runtime.oidcEnabled}>{runtime.oidcEnabled ? "enabled" : "disabled"}</strong></div>
              <div><span>basic fallback</span><strong class:on={runtime.basicEnabled}>{runtime.basicEnabled ? "enabled" : "disabled"}</strong></div>
              <div><span>persistence</span><strong class:on={runtime.persistenceEnabled}>{runtime.persistenceEnabled ? "enabled" : "disabled"}</strong></div>
              <div><span>registration</span><strong class:on={runtime.registrationEnabled}>{runtime.registrationEnabled ? "enabled" : "disabled"}</strong></div>
              <div><span>profiles</span><strong class:on={runtime.profileCount > 0}>{runtime.profileCount} exposed</strong></div>
              <div><span>tier 2 proxy</span><strong class:on={runtime.proxyRoutes.length > 0}>{runtime.proxyRoutes.length > 0 ? `${runtime.proxyRoutes.length} enabled` : "disabled"}</strong></div>
              <div><span>api limiter</span><strong class:on={runtime.apiRateLimitPerSecond > 0}>{runtime.apiRateLimitPerSecond}/s // burst {runtime.apiRateLimitBurst}</strong></div>
            </div>
            <div class="connector-line">
              <span>connectors</span>
              {#each runtime.connectors as connector}<code><i></i>{connector.name} / {connector.kind}</code>{:else}<code class="offline">none</code>{/each}
            </div>
            {#if runtime.proxyRoutes.length > 0}
              <div class="connector-line routes"><span>proxy routes</span>{#each runtime.proxyRoutes as route}<code><i></i>{route}</code>{/each}</div>
            {/if}
          </section>

          <div class="terminal-body connected">
            <div class="session-row"><div><p class="command"><span>$</span> av profiles --available</p><p class="output"><span class="verified">verified</span> // ephemeral session active</p></div></div>
            <div class="profiles">
              {#each profiles as profile, index}
                <article class="profile">
                  <div class="profile-index">{String(index + 1).padStart(2, "0")}</div>
                  <div class="profile-name"><h2>{profile.name}</h2><p>{profile.environment} // {profile.path}</p></div>
                  <code>av {profile.name} -- command</code>
                </article>
              {:else}
                <p class="empty">no profiles available_</p>
              {/each}
            </div>
          </div>
        </section>
      {/if}
    </section>
  {/if}
</main>
