#!/usr/bin/env python3
import json
import os
import pathlib
import time
import urllib.error
import urllib.request

INFISICAL_URL = os.environ["INFISICAL_URL"].rstrip("/")
OPENBAO_URL = os.environ["OPENBAO_URL"].rstrip("/")
OPENBAO_ROOT_TOKEN = os.environ["OPENBAO_ROOT_TOKEN"]
STATE = pathlib.Path("/state")


def request(base, path, method="GET", payload=None, token=None, accepted=(200,)):
    body = None if payload is None else json.dumps(payload).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(base + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            status = response.status
            raw = response.read()
    except urllib.error.HTTPError as error:
        status = error.code
        raw = error.read()
    if status not in accepted:
        raise RuntimeError(f"{method} {path} returned HTTP {status}")
    return json.loads(raw) if raw else {}


def bao_request(path, method="GET", payload=None, accepted=(200, 204)):
    body = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(
        OPENBAO_URL + path,
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Vault-Token": OPENBAO_ROOT_TOKEN,
        },
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            status = response.status
            raw = response.read()
    except urllib.error.HTTPError as error:
        status = error.code
        raw = error.read()
    if status not in accepted:
        raise RuntimeError(f"{method} {path} returned HTTP {status}")
    return json.loads(raw) if raw else {}


def write_secret(name, value):
    path = STATE / name
    path.write_text(value + "\n", encoding="utf-8")
    path.chmod(0o444)


def bootstrap_infisical():
    result = request(
        INFISICAL_URL,
        "/api/v1/admin/bootstrap",
        method="POST",
        payload={
            "email": "av-integration@example.invalid",
            "password": "integration-only-admin-password",
            "organization": "AV Integration",
        },
    )
    token = result["identity"]["credentials"]["token"]
    project = request(
        INFISICAL_URL,
        "/api/v1/projects",
        method="POST",
        token=token,
        payload={
            "projectName": "AV Integration",
            "projectDescription": "Disposable AV connector integration test",
            "slug": "av-integration",
            "template": "default",
            "type": "secret-manager",
            "shouldCreateDefaultEnvs": True,
        },
    )["project"]
    environment = next(
        (entry["slug"] for entry in project.get("environments", []) if entry["slug"] == "dev"),
        None,
    )
    if environment is None:
        environment = "dev"
        request(
            INFISICAL_URL,
            f"/api/v1/projects/{project['id']}/environments",
            method="POST",
            token=token,
            payload={"name": "Development", "slug": environment},
        )
    request(
        INFISICAL_URL,
        "/api/v4/secrets/INFISICAL_MARKER",
        method="POST",
        token=token,
        payload={
            "projectId": project["id"],
            "environment": environment,
            "secretPath": "/",
            "secretValue": "infisical-ok",
        },
    )
    write_secret("infisical-token", token)
    return project["id"], environment


def bootstrap_openbao():
    auth_mounts = bao_request("/v1/sys/auth")
    if "approle/" not in auth_mounts:
        bao_request("/v1/sys/auth/approle", method="POST", payload={"type": "approle"})
    mounts = bao_request("/v1/sys/mounts")
    if "secret/" not in mounts:
        bao_request(
            "/v1/sys/mounts/secret",
            method="POST",
            payload={"type": "kv", "options": {"version": "2"}},
        )
    bao_request(
        "/v1/sys/policies/acl/av-integration",
        method="PUT",
        payload={
            "policy": 'path "secret/data/av-integration" { capabilities = ["read"] }'
        },
    )
    bao_request(
        "/v1/secret/data/av-integration",
        method="POST",
        payload={"data": {"OPENBAO_MARKER": "openbao+ok"}},
    )
    bao_request(
        "/v1/auth/approle/role/av-integration",
        method="POST",
        payload={
            "token_policies": ["av-integration"],
            "token_ttl": "5m",
            "token_max_ttl": "10m",
            "secret_id_ttl": "10m",
        },
    )
    role_id = bao_request("/v1/auth/approle/role/av-integration/role-id")["data"]["role_id"]
    secret_id = bao_request(
        "/v1/auth/approle/role/av-integration/secret-id", method="POST", payload={}
    )["data"]["secret_id"]
    write_secret("openbao-role-id", role_id)
    write_secret("openbao-secret-id", secret_id)

    mounts = bao_request("/v1/sys/mounts")
    if "database/" not in mounts:
        bao_request(
            "/v1/sys/mounts/database",
            method="POST",
            payload={"type": "database"},
        )
    bao_request(
        "/v1/database/config/av",
        method="POST",
        payload={
            "plugin_name": "postgresql-database-plugin",
            "allowed_roles": ["av"],
            "connection_url": "postgresql://{{username}}:{{password}}@postgres:5432/av?sslmode=require",
            "username": "infisical",
            "password": "integration-only",
            "verify_connection": True,
        },
    )
    bao_request(
        "/v1/database/roles/av",
        method="POST",
        payload={
            "db_name": "av",
            "creation_statements": [
                "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' "
                "VALID UNTIL '{{expiration}}' IN ROLE av_owner"
            ],
            "revocation_statements": ['DROP ROLE IF EXISTS "{{name}}"'],
            "default_ttl": "10s",
            "max_ttl": "20s",
        },
    )
    bao_request(
        "/v1/sys/policies/acl/av-database-agent",
        method="PUT",
        payload={
            "policy": 'path "database/creds/av" { capabilities = ["read"] }'
        },
    )
    bao_request(
        "/v1/auth/approle/role/av-database-agent",
        method="POST",
        payload={
            "token_policies": ["av-database-agent"],
            "token_ttl": "5m",
            "token_max_ttl": "10m",
            "secret_id_ttl": "10m",
        },
    )
    database_role_id = bao_request(
        "/v1/auth/approle/role/av-database-agent/role-id"
    )["data"]["role_id"]
    database_secret_id = bao_request(
        "/v1/auth/approle/role/av-database-agent/secret-id",
        method="POST",
        payload={},
    )["data"]["secret_id"]
    write_secret("openbao-agent-role-id", database_role_id)
    write_secret("openbao-agent-secret-id", database_secret_id)
    write_secret(
        "openbao-agent.hcl",
        """
vault {
  address = "http://openbao:8200"
}

auto_auth {
  method "approle" {
    config = {
      role_id_file_path = "/state/openbao-agent-role-id"
      secret_id_file_path = "/state/openbao-agent-secret-id"
      remove_secret_id_file_after_reading = false
    }
  }
}

template {
  contents = "{{ with secret \\"database/creds/av\\" }}{{ .Data | toJSON }}{{ end }}"
  destination = "/credentials/database-credentials.json"
  perms = 0444
}
""".strip(),
    )


def write_config(project_id, environment):
    write_secret(
        "av-password.argon2id",
        "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
    )
    write_secret(
        "av-control-plane-url",
        "postgres://infisical:integration-only@postgres:5432/av?sslmode=require",
    )
    github_client_id = os.environ.get("AV_TEST_GITHUB_CLIENT_ID", "")
    github_owner_id = os.environ.get("AV_TEST_GITHUB_OWNER_ID", "")
    github_secret_path = os.environ.get("AV_TEST_GITHUB_CLIENT_SECRET_FILE", "")
    github_enabled = bool(github_client_id) or bool(github_owner_id)
    if github_enabled and not all((github_client_id, github_owner_id, github_secret_path)):
        raise RuntimeError("local GitHub test configuration requires client ID, owner ID, and client secret file")
    auth = {
        "mode": "basic",
        "issuer": "",
        "client_id": "",
        "audiences": [],
        "scopes": [],
        "signing_algorithms": ["RS256"],
        "allowed_groups": [],
        "group_claim": "groups",
        "basic_users": [],
    }
    initial_owner_subject = "oidc:integration-owner"
    if github_enabled:
        secret = pathlib.Path(github_secret_path).read_text(encoding="utf-8").strip()
        if not secret:
            raise RuntimeError("local GitHub client secret file is empty")
        write_secret("github-client-secret", secret)
        auth = {
            "mode": "github_or_basic",
            "issuer": "",
            "client_id": "",
            "audiences": [],
            "scopes": [],
            "signing_algorithms": ["RS256"],
            "allowed_groups": [],
            "group_claim": "groups",
            "basic_users": [],
            "github": {
                "client_id": github_client_id,
                "client_secret_file": "/state/github-client-secret",
                "allowed_user_ids": [int(github_owner_id)],
                "allowed_organizations": [],
            },
        }
        initial_owner_subject = f"github:{github_owner_id}"
    config = {
        "listen": "0.0.0.0:14322",
        "public_url": "http://127.0.0.1:14322",
        "mode": "managed",
        "managed": {
            "database_credentials_file": "/credentials/database-credentials.json",
            "database_reload_interval_seconds": 1,
            "postgres": {
                "host": "postgres",
                "port": 5432,
                "database": "av",
                "ssl_mode": "require",
                "role": "av_owner",
            },
            "initial_owner_oidc_subject": initial_owner_subject,
        },
        "auth": auth,
        "connectors": {
            "infisical": {
                "kind": "infisical",
                "base_url": INFISICAL_URL,
                "auth": {"type": "token", "token_file": "/state/infisical-token"},
            },
            "openbao": {
                "kind": "openbao",
                "base_url": OPENBAO_URL,
                "auth": {
                    "type": "approle",
                    "role_id_file": "/state/openbao-role-id",
                    "secret_id_file": "/state/openbao-secret-id",
                },
            },
        },
        "profiles": {
            "infisical-integration": {
                "connector": "infisical",
                "project_id": project_id,
                "environment": environment,
                "secret_path": "/",
                "allowed_keys": ["INFISICAL_MARKER"],
            },
            "openbao-integration": {
                "connector": "openbao",
                "secret_path": "secret/data/av-integration",
                "allowed_keys": ["OPENBAO_MARKER"],
            },
            "ungranted-integration": {
                "connector": "openbao",
                "secret_path": "secret/data/av-integration",
                "allowed_keys": ["OPENBAO_MARKER"],
            },
        },
        "proxy_routes": {
            "openbao-upstream": {
                "profile": "openbao-integration",
                "base_url": "http://upstream:8081",
                "secret_key": "OPENBAO_MARKER",
                "header": "Authorization",
                "header_prefix": "Bearer ",
                "allowed_methods": ["GET"],
                "allowed_path_prefixes": ["/verify", "/encoded"],
                "allowed_request_headers": ["accept"],
                "allowed_response_headers": ["content-type", "x-reflected-secret"],
                "allowed_query_parameters": ["source"],
                "allowed_content_types": [],
                "max_body_bytes": 1024,
            },
            "openbao-x-api": {
                "profile": "openbao-integration",
                "base_url": "http://upstream:8081",
                "secret_key": "OPENBAO_MARKER",
                "header": "X-Api-Key",
                "header_prefix": "",
                "allowed_methods": ["GET"],
                "allowed_path_prefixes": ["/x-header"],
                "allowed_request_headers": ["accept"],
                "allowed_response_headers": ["content-type"],
                "allowed_query_parameters": [],
                "allowed_content_types": [],
                "max_body_bytes": 1024,
            },
            "ungranted-upstream": {
                "profile": "ungranted-integration",
                "base_url": "http://upstream:8081",
                "secret_key": "OPENBAO_MARKER",
                "header": "Authorization",
                "header_prefix": "Bearer ",
                "allowed_methods": ["GET"],
                "allowed_path_prefixes": ["/verify"],
                "allowed_request_headers": [],
                "allowed_response_headers": ["content-type"],
                "allowed_query_parameters": [],
                "allowed_content_types": [],
                "max_body_bytes": 1024,
            },
        },
        "max_connector_concurrency": 4,
        "api_rate_limit_per_second": 100,
        "api_rate_limit_burst": 200,
    }
    path = STATE / "config.json"
    path.write_text(json.dumps(config, separators=(",", ":")), encoding="utf-8")
    path.chmod(0o444)


def main():
    STATE.mkdir(parents=True, exist_ok=True)
    project_id, environment = bootstrap_infisical()
    bootstrap_openbao()
    write_config(project_id, environment)
    print("connector_setup=ok")


if __name__ == "__main__":
    main()
