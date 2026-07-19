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

  let auth: AuthConfig | undefined;
  let profiles: Profile[] = [];
  let authorization = "";
  let error = "";
  let busy = true;
  let username = "";
  let password = "";

  onMount(async () => {
    try {
      auth = await fetchJson<AuthConfig>("/v1/auth/config");
      await finishOidcCallback();
      const token = sessionStorage.getItem("av_oidc_token");
      if (token) authorization = `Bearer ${token}`;
      if (auth.mode === "disabled") authorization = "disabled";
      if (authorization) await loadProfiles();
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

  async function finishOidcCallback() {
    const params = new URLSearchParams(location.search);
    const code = params.get("code");
    if (!code) return;
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
    sessionStorage.setItem("av_oidc_token", token.access_token);
    sessionStorage.removeItem("av_oidc_state");
    sessionStorage.removeItem("av_oidc_verifier");
    history.replaceState({}, "", "/");
  }

  async function loginBasic() {
    authorization = `Basic ${btoa(`${username}:${password}`)}`;
    password = "";
    try {
      await loadProfiles();
    } catch (cause) {
      authorization = "";
      error = message(cause);
    }
  }

  async function loadProfiles() {
    profiles = await fetchJson<Profile[]>("/v1/profiles", {
      headers: authorization === "disabled" ? {} : { authorization }
    });
  }

  function logout() {
    sessionStorage.removeItem("av_oidc_token");
    authorization = "";
    profiles = [];
    username = "";
    password = "";
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

<main>
  <header>
    <div class="mark">av</div>
    <div>
      <h1>Credentials without a credential database.</h1>
      <p>OIDC decides who you are. Connectors decide what you may lease. Secrets remain in Infisical.</p>
    </div>
  </header>

  {#if busy}
    <section class="panel">Loading policy…</section>
  {:else if error}
    <section class="panel error">{error}</section>
  {/if}

  {#if auth && !authorization}
    <section class="panel auth">
      <h2>Authenticate</h2>
      {#if auth.mode === "oidc" || auth.mode === "oidc_or_basic"}
        <button class="primary" onclick={loginOidc}>Continue with Zitadel</button>
      {/if}
      {#if auth.mode === "basic" || auth.mode === "oidc_or_basic"}
        <div class="divider"><span>optional fallback</span></div>
        <label>Username <input autocomplete="username" bind:value={username} /></label>
        <label>Password <input type="password" autocomplete="current-password" bind:value={password} /></label>
        <button onclick={loginBasic}>Sign in with password</button>
      {/if}
    </section>
  {/if}

  {#if authorization}
    <section class="toolbar">
      <span>Authenticated</span>
      <button onclick={logout}>End session</button>
    </section>
    <section class="profiles">
      {#each profiles as profile}
        <article class="panel profile">
          <div class="pill">{profile.environment}</div>
          <h2>{profile.name}</h2>
          <p>Infisical path <code>{profile.path}</code></p>
          <pre><code>av {profile.name} -- your-command</code></pre>
        </article>
      {:else}
        <article class="panel">No profiles are configured for this service.</article>
      {/each}
    </section>
  {/if}
</main>
