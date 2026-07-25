#!/usr/bin/env python3
import base64
import json
import os
import time
import urllib.parse
import urllib.error
import urllib.request

AV_URL = os.environ["AV_URL"].rstrip("/")
AUTH = "Basic " + base64.b64encode(b"operator:password").decode()


def request(path, method="GET", auth=True, origin=None, body=None, headers=None, accepted=(200,)):
    headers = dict(headers or {})
    if auth:
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
    assert b"managed control plane" in owner
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
        {"name": "openbao-integration", "environment": "", "path": "secret/data/av-integration"},
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

    _, proxy, proxy_headers = request(
        "/v1/proxy/openbao-upstream/verify?source=integration",
        headers={
            "X-Forwarded-Host": "hostile.example",
            "X-HTTP-Method-Override": "DELETE",
            "X-Original-URL": "/admin",
        },
    )
    assert proxy == {"injection": "accepted"}
    assert proxy_headers["x-reflected-secret"] == "Bearer [REDACTED]"
    assert "location" not in proxy_headers
    _, x_header, _ = request(
        "/v1/proxy/openbao-x-api/x-header",
        headers={"X-Api-Key": "attacker-controlled"},
    )
    assert x_header == {"singleHeader": "accepted"}
    request("/v1/proxy/ungranted-upstream/verify", accepted=(403,))
    _, encoded, _ = request(
        "/v1/proxy/openbao-upstream/encoded?source=integration"
    )
    assert b"openbao+ok" not in encoded
    assert base64.b64encode(b"openbao+ok") not in encoded
    assert b"openbao%2Bok" not in encoded
    assert encoded.count(b"[REDACTED]") == 3
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
    print("connector_integration=ok")


if __name__ == "__main__":
    main()
