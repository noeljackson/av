#!/usr/bin/env python3
import base64
import json
import os
import pathlib
import time
import urllib.error
import urllib.request

AV_URL = os.environ["AV_URL"].rstrip("/")
PASSWORD = pathlib.Path("/state/av-password").read_text(encoding="utf-8").strip()
AUTH = "Basic " + base64.b64encode(f"operator:{PASSWORD}".encode()).decode()


def request(path, method="GET", auth=True, origin=None, body=None, accepted=(200,)):
    headers = {}
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
    content = json.loads(raw) if raw and raw.lstrip().startswith((b"{", b"[")) else raw
    return status, content, {key.lower(): value for key, value in response_headers.items()}


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
    _, status, headers = request("/v1/status", auth=False)
    assert status["basicEnabled"] is True
    assert status["persistenceEnabled"] is False
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
    _, missing_api, _ = request("/v1/register", auth=False, accepted=(404,))
    assert b"api endpoint not found" in missing_api

    _, infisical, _ = request("/v1/profiles/infisical-integration/secrets")
    assert infisical == {"INFISICAL_MARKER": "infisical-ok"}
    _, openbao, _ = request("/v1/profiles/openbao-integration/secrets")
    assert openbao == {"OPENBAO_MARKER": "openbao-ok"}

    _, proxy, _ = request("/v1/proxy/openbao-upstream/verify?source=integration")
    assert proxy == {"injection": "accepted"}
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
    print("connector_integration=ok")


if __name__ == "__main__":
    main()
