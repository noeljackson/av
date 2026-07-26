let auth;
let authorization = "";

const lockedScreen = document.querySelector("#locked-screen");
const dashboard = document.querySelector("#dashboard");
const authProgress = document.querySelector("#auth-progress");
const authError = document.querySelector("#auth-error");
const oidcLogin = document.querySelector("#oidc-login");
const basicLogin = document.querySelector("#basic-login");
const authDivider = document.querySelector("#auth-divider");
const basicForm = document.querySelector("#basic-form");
const sessionPanel = document.querySelector("#session-panel");
const linkState = document.querySelector("#link-state");
const linkLabel = document.querySelector("#link-label");

void initialize();

async function initialize() {
  try {
    auth = await fetchJson("/v1/auth/config");
    const token = await finishOidcCallback();
    if (token) {
      await loadSession(`Bearer ${token}`);
      return;
    }
    if (auth.mode === "disabled") {
      await loadSession("disabled");
      return;
    }
    showLogin();
  } catch (cause) {
    showError(message(cause));
  }
}

function showLogin() {
  authProgress.hidden = true;
  const oidcEnabled = auth.mode === "oidc" || auth.mode === "oidc_or_basic";
  const basicEnabled = auth.mode === "basic" || auth.mode === "oidc_or_basic";
  oidcLogin.hidden = !oidcEnabled;
  basicLogin.hidden = !basicEnabled;
  authDivider.hidden = !(oidcEnabled && basicEnabled);
}

oidcLogin.addEventListener("click", async () => {
  try {
    if (!auth.authorizationEndpoint) throw new Error("OIDC authorization endpoint is unavailable");
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
  } catch (cause) {
    showError(message(cause));
  }
});

basicForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const username = document.querySelector("#username").value;
  const password = document.querySelector("#password");
  const candidate = basicAuthorization(username, password.value);
  password.value = "";
  try {
    await loadSession(candidate);
  } catch (cause) {
    showError(message(cause));
  }
});

document.querySelector("#logout").addEventListener("click", () => {
  authorization = "";
  sessionPanel.replaceChildren();
  dashboard.hidden = true;
  lockedScreen.hidden = false;
  linkState.classList.remove("linked");
  linkLabel.textContent = "identity required";
  authError.hidden = true;
  showLogin();
});

async function finishOidcCallback() {
  const params = new URLSearchParams(location.search);
  const code = params.get("code");
  if (!code) return undefined;
  if (!auth.tokenEndpoint) throw new Error("OIDC token endpoint is unavailable");
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
  const token = await response.json();
  sessionStorage.removeItem("av_oidc_state");
  sessionStorage.removeItem("av_oidc_verifier");
  history.replaceState({}, "", "/");
  return token.access_token;
}

async function loadSession(candidate) {
  const headers = candidate === "disabled" ? {} : { authorization: candidate };
  const response = await fetch("/ui/session", { cache: "no-store", headers });
  if (!response.ok) throw new Error(`authentication failed (${response.status})`);
  authorization = candidate;
  sessionPanel.innerHTML = await response.text();
  window.htmx.process(sessionPanel);
  lockedScreen.hidden = true;
  dashboard.hidden = false;
  linkState.classList.add("linked");
  linkLabel.textContent = "identity linked";
  if (sessionPanel.querySelector("#owner-panel[data-managed]")) {
    window.htmx.ajax("GET", "/ui/owner", { target: "#owner-panel", swap: "innerHTML" });
  }
}

document.body.addEventListener("htmx:configRequest", (event) => {
  if (authorization && event.detail.path.startsWith("/ui/")) {
    event.detail.headers.authorization = authorization;
  }
});

function redirectUri() {
  return `${location.origin}/`;
}

function randomBase64Url(length) {
  return base64Url(crypto.getRandomValues(new Uint8Array(length)));
}

function base64Url(value) {
  return btoa(String.fromCharCode(...value)).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function basicAuthorization(username, password) {
  const bytes = new TextEncoder().encode(`${username}:${password}`);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return `Basic ${btoa(binary)}`;
}

async function fetchJson(input) {
  const response = await fetch(input, { cache: "no-store" });
  if (!response.ok) throw new Error(`request failed (${response.status})`);
  return response.json();
}

function showError(value) {
  authProgress.hidden = true;
  authError.textContent = value;
  authError.hidden = false;
  showLogin();
}

function message(cause) {
  return cause instanceof Error ? cause.message : "request failed";
}
