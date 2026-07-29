#!/usr/bin/env python3
import base64
import hashlib
import json
import os
import pathlib
import time
import urllib.parse
import urllib.error
import urllib.request

AV_URL = os.environ["AV_URL"].rstrip("/")
AUTH = "Basic " + base64.b64encode(b"operator:password").decode()
CREDENTIAL_FILE = pathlib.Path("/credentials/database-credentials.json")
RESULTS = pathlib.Path("/results")


def record_log_canary(name, value):
    path = RESULTS / name
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write(value)


def request(path, method="GET", auth=True, origin=None, body=None, headers=None, accepted=(200,)):
    headers = dict(headers or {})
    if auth and "Authorization" not in headers:
        headers["Authorization"] = AUTH
    if origin:
        headers["Origin"] = origin
    req = urllib.request.Request(AV_URL + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            status = response.status
            raw = response.read()
            response_headers = dict(response.headers.items())
    except urllib.error.HTTPError as error:
        status = error.code
        raw = error.read()
        response_headers = dict(error.headers.items())
    if status not in accepted:
        raise RuntimeError(f"{method} {path} returned HTTP {status}")
    normalized_headers = {key.lower(): value for key, value in response_headers.items()}
    content_type = normalized_headers.get("content-type", "").split(";", 1)[0]
    content = json.loads(raw) if raw and content_type == "application/json" else raw
    return status, content, normalized_headers


def connect(service, method, message, authorization=AUTH, accepted=(200,)):
    return request(
        f"/av.v1.{service}/{method}",
        method="POST",
        auth=False,
        body=json.dumps(message).encode(),
        headers={
            "Authorization": authorization,
            "Content-Type": "application/json",
            "Connect-Protocol-Version": "1",
        },
        accepted=accepted,
    )


def wait_for_av():
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            request("/healthz", auth=False)
            return
        except Exception:
            time.sleep(1)
    raise RuntimeError("AV did not become ready")


def main():
    wait_for_av()
    initial_database_credential = hashlib.sha256(CREDENTIAL_FILE.read_bytes()).digest()
    _, _, _ = request("/v1/status", auth=False, accepted=(401,))
    _, status, headers = request("/v1/status")
    assert status["basicEnabled"] is True
    assert status["persistenceEnabled"] is True
    assert status["registrationEnabled"] is False
    assert status["connectors"] == [
        {"name": "infisical", "kind": "infisical"},
        {"name": "openbao", "kind": "openbao"},
    ]
    assert headers["cache-control"] == "no-store"
    assert headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in headers["content-security-policy"]

    _, _, unauthorized_headers = request("/v1/profiles", auth=False, accepted=(401,))
    assert "Basic" in unauthorized_headers["www-authenticate"]

    request("/ui/owner", auth=False, accepted=(401,))
    _, owner, _ = request("/ui/owner")
    assert b"access management" in owner
    assert b"operator" in owner
    assert b"integration-only" not in owner
    form_headers = {"Content-Type": "application/x-www-form-urlencoded"}
    ui_password = "managed-ui-password"
    _, owner, _ = request(
        "/ui/owner/basic-users",
        method="POST",
        body=urllib.parse.urlencode(
            {"username": "managed-ui", "password": ui_password}
        ).encode(),
        headers=form_headers,
    )
    assert b"managed-ui" in owner
    assert ui_password.encode() not in owner
    request(
        "/ui/owner/basic-users/enabled",
        method="POST",
        body=urllib.parse.urlencode(
            {"username": "managed-ui", "enabled": "false"}
        ).encode(),
        headers=form_headers,
    )
    request(
        "/ui/owner/basic-users/enabled",
        method="POST",
        origin="https://hostile.example",
        body=urllib.parse.urlencode(
            {"username": "managed-ui", "enabled": "true"}
        ).encode(),
        headers=form_headers,
        accepted=(403,),
    )
    _, profiles, _ = request("/v1/profiles")
    assert profiles == [
        {"name": "infisical-integration", "environment": "dev", "path": "/"},
        {"name": "openbao-dynamic", "environment": "", "path": "database/creds/av"},
        {"name": "openbao-integration", "environment": "", "path": "secret/data/av-integration"},
    ]
    _, destinations, _ = connect(
        "SessionService",
        "ListProxyDestinations",
        {},
    )
    assert destinations["destinations"] == [
        {
            "name": "credentialless-upstream",
            "profile": "openbao-integration",
            "host": "upstream-tunnel",
            "mode": "tunnel",
        },
        {
            "name": "openbao-basic",
            "profile": "openbao-integration",
            "host": "upstream-basic",
            "mode": "injecting",
        },
        {
            "name": "openbao-body",
            "profile": "openbao-integration",
            "host": "upstream-body",
            "mode": "injecting",
        },
        {
            "name": "openbao-dynamic-buffered",
            "profile": "openbao-dynamic",
            "host": "upstream-dynamic",
            "mode": "injecting",
        },
        {
            "name": "openbao-dynamic-error",
            "profile": "openbao-dynamic",
            "host": "upstream",
            "mode": "injecting",
        },
        {
            "name": "openbao-dynamic-stream",
            "profile": "openbao-dynamic",
            "host": "upstream-dynamic-stream",
            "mode": "injecting",
        },
        {
            "name": "openbao-stream",
            "profile": "openbao-integration",
            "host": "upstream-stream",
            "mode": "injecting",
        },
        {
            "name": "openbao-upstream",
            "profile": "openbao-integration",
            "host": "upstream-auth",
            "mode": "injecting",
        },
        {
            "name": "openbao-x-api",
            "profile": "openbao-integration",
            "host": "upstream-x-api",
            "mode": "injecting",
        },
    ]
    _, missing_api, _ = request("/v1/register", auth=False, accepted=(404,))
    assert b"api endpoint not found" in missing_api

    _, infisical, _ = request("/v1/profiles/infisical-integration/secrets")
    assert infisical == {"INFISICAL_MARKER": "infisical-ok"}
    _, openbao, _ = request("/v1/profiles/openbao-integration/secrets")
    assert openbao == {"OPENBAO_MARKER": "openbao+ok"}
    request("/v1/profiles/ungranted-integration/secrets", accepted=(403,))
    request(
        "/ui/owner/grants",
        method="POST",
        body=urllib.parse.urlencode(
            {"subject": "basic:operator", "profile": "ungranted-integration"}
        ).encode(),
        headers=form_headers,
    )
    _, granted, _ = request("/v1/profiles/ungranted-integration/secrets")
    assert granted == {"OPENBAO_MARKER": "openbao+ok"}
    request(
        "/ui/owner/grants/revoke",
        method="POST",
        body=urllib.parse.urlencode(
            {"subject": "basic:operator", "profile": "ungranted-integration"}
        ).encode(),
        headers=form_headers,
    )
    request("/v1/profiles/ungranted-integration/secrets", accepted=(403,))

    # Named agents receive one-time credentials and independently scoped
    # capabilities. A proxy-only grant must never become an environment lease,
    # and disabling an agent must take effect on its very next request.
    _, agent, _ = connect(
        "ControlService",
        "CreateAgent",
        {"name": "integration-agent"},
    )
    assert agent["name"] == "integration-agent"
    assert agent["enabled"] is True
    assert agent["token"].startswith("av_agent_")
    record_log_canary("agent-token", agent["token"])
    agent_auth = "Agent " + agent["token"]
    connect(
        "ControlService",
        "GrantProfile",
        {
            "profile": "openbao-integration",
            "subject": "agent:integration-agent",
            "mode": "proxy",
        },
    )
    request(
        "/v1/profiles/openbao-integration/secrets",
        auth=False,
        headers={"Authorization": agent_auth},
        accepted=(403,),
    )
    _, agent_proxy, _ = request(
        "/v1/proxy/openbao-upstream/verify?source=integration",
        auth=False,
        headers={"Authorization": agent_auth},
    )
    assert agent_proxy == {"injection": "accepted"}
    connect(
        "ControlService",
        "SetAgentEnabled",
        {"name": "integration-agent", "enabled": False},
    )
    request(
        "/v1/proxy/openbao-upstream/verify?source=integration",
        auth=False,
        headers={"Authorization": agent_auth},
        accepted=(401,),
    )

    # Role changes are owner-only and the final owner is protected even when
    # a caller tries to demote itself.
    connect(
        "ControlService",
        "SetPrincipalRole",
        {"subject": "oidc:integration-owner", "role": "user"},
    )
    connect(
        "ControlService",
        "SetPrincipalRole",
        {"subject": "basic:operator", "role": "user"},
        accepted=(400,),
    )
    _, roles, _ = connect("ControlService", "ListPrincipalRoles", {})
    assert {"subject": "basic:operator", "role": "owner"} in roles["roles"]

    # Exercise the PostgreSQL sliding-session transaction through the release
    # ConnectRPC service, including subject-bound renewal and explicit revoke.
    _, proxy_session, _ = connect(
        "SessionService",
        "CreateProxySession",
        {"profile": "openbao-integration"},
    )
    assert proxy_session["token"]
    record_log_canary("proxy-session-token", proxy_session["token"])
    proxy_expiry = int(proxy_session["expiresUnixSeconds"])
    assert proxy_expiry > int(time.time())
    _, renewed_session, _ = connect(
        "SessionService",
        "RenewProxySession",
        {"sessionId": proxy_session["sessionId"]},
    )
    assert renewed_session["sessionId"] == proxy_session["sessionId"]
    assert int(renewed_session["expiresUnixSeconds"]) >= proxy_expiry
    _, revoked_session, _ = connect(
        "SessionService",
        "RevokeProxySession",
        {"sessionId": proxy_session["sessionId"]},
    )
    assert revoked_session["revoked"] is True
    connect(
        "SessionService",
        "RenewProxySession",
        {"sessionId": proxy_session["sessionId"]},
        accepted=(404,),
    )

    _, proxy, proxy_headers = request(
        "/v1/proxy/openbao-upstream/verify?source=integration",
        headers={
            "X-Forwarded-Host": "hostile.example",
            "X-HTTP-Method-Override": "DELETE",
            "X-Original-URL": "/admin",
        },
    )
    assert proxy == {"injection": "accepted"}
    assert proxy_headers["x-reflected-secret"] == "[REDACTED]"
    assert "location" not in proxy_headers
    _, x_header, _ = request(
        "/v1/proxy/openbao-x-api/x-header",
        headers={"X-Api-Key": "attacker-controlled"},
    )
    assert x_header == {"singleHeader": "accepted"}
    _, basic, basic_headers = request("/v1/proxy/openbao-basic/basic")
    assert b"openbao+ok" not in basic
    assert b"[REDACTED]" in basic
    assert basic_headers["x-reflected-secret"] == "Bearer [REDACTED]"
    _, substituted, _ = request(
        "/v1/proxy/openbao-body/body",
        method="POST",
        body=b'{"token":"__AV_SECRET_TOKEN__"}',
        headers={"Content-Type": "application/json"},
    )
    assert substituted == {"token": "[REDACTED]"}
    _, rejected_canary, rejected_canary_headers = request(
        "/v1/proxy/openbao-body/body",
        method="POST",
        body=b'{"token":"__AV_SECRET_TOKEN__","canary":"av-request-body-canary-9e8c"}',
        headers={
            "Content-Type": "application/json",
            "X-Canary": "av-sensitive-header-canary-7d31",
        },
        accepted=(403,),
    )
    assert b"av-request-body-canary-9e8c" not in rejected_canary
    assert b"av-sensitive-header-canary-7d31" not in rejected_canary
    assert all(
        "av-request-body-canary-9e8c" not in value
        and "av-sensitive-header-canary-7d31" not in value
        for value in rejected_canary_headers.values()
    )
    request(
        "/v1/proxy/openbao-body/body",
        method="POST",
        body=b'{"token":"missing"}',
        headers={"Content-Type": "application/json"},
        accepted=(502,),
    )
    request(
        "/v1/proxy/openbao-body/body",
        method="POST",
        body=b'{"a":"__AV_SECRET_TOKEN__","b":"__AV_SECRET_TOKEN__"}',
        headers={"Content-Type": "application/json"},
        accepted=(502,),
    )
    request("/v1/proxy/ungranted-upstream/verify", accepted=(403,))
    _, encoded, _ = request(
        "/v1/proxy/openbao-upstream/encoded?source=integration"
    )
    assert b"openbao+ok" not in encoded
    assert base64.b64encode(b"openbao+ok") not in encoded
    assert b"openbao%2Bok" not in encoded
    assert encoded.count(b"[REDACTED]") == 3

    stream_request = urllib.request.Request(
        AV_URL + "/v1/proxy/openbao-stream/stream",
        headers={"Authorization": AUTH, "Accept": "text/event-stream"},
    )
    started = time.monotonic()
    with urllib.request.urlopen(stream_request, timeout=15) as response:
        first_line = response.readline()
        first_line_elapsed = time.monotonic() - started
        streamed = first_line + response.read()
    assert first_line == b"data: ready\n"
    assert first_line_elapsed < 0.8
    assert b"openbao+ok" not in streamed
    assert b"[REDACTED]" in streamed
    request(
        "/v1/proxy/openbao-upstream/verify?undeclared=value",
        accepted=(403,),
    )
    request(
        "/v1/proxy/openbao-upstream/verify?source=one&source=two",
        accepted=(403,),
    )
    request(
        "/v1/proxy/openbao-upstream/verify?source=integration",
        method="POST",
        accepted=(403,),
    )
    request(
        "/v1/proxy/openbao-upstream/verify?source=integration",
        method="POST",
        body=b"x" * (4 * 1024 * 1024 + 1),
        accepted=(413,),
    )
    request(
        "/v1/proxy/openbao-upstream/verify/%2e%2e?source=integration",
        accepted=(403, 404),
    )
    request(
        "/v1/proxy/openbao-upstream/verify?source=integration",
        origin="https://hostile.example",
        accepted=(403,),
    )
    request(
        "/v1/proxy/openbao-upstream/verify?source=integration",
        headers={"Sec-Fetch-Site": "same-site"},
        accepted=(403,),
    )

    # OpenBao Agent must replace the leased PostgreSQL login after its maximum
    # TTL, and AV must switch pools without an application restart or outage.
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if hashlib.sha256(CREDENTIAL_FILE.read_bytes()).digest() != initial_database_credential:
            break
        time.sleep(1)
    else:
        raise RuntimeError("OpenBao Agent did not rotate the database credential file")
    _, status_after_rotation, _ = request("/v1/status")
    assert status_after_rotation["persistenceEnabled"] is True

    print("connector_integration=ok")


if __name__ == "__main__":
    main()
