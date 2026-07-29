# Secret backends

AV is a credential broker, not a secrets manager. OpenBao, Infisical, or
Google Secret Manager stores each provider value. AV reads only the fields
named by an immutable profile and releases them through a granted Tier 2 proxy
route or a Tier 3 child process.

The control-plane database never stores connector credentials, secret
resources, fetched values, or a copy of backend configuration. It stores only
identities, grants, session token digests, and redacted audit metadata.

## Profile mappings

Existing Infisical and OpenBao profiles may continue using `allowed_keys`.
New profiles can instead use `exports` to give a remote field a portable local
name:

```json
{
  "profiles": {
    "example-dev": {
      "connector": "openbao",
      "secret_path": "secret/data/apps/example/dev",
      "exports": {
        "EXAMPLE_API_TOKEN": {
          "field": "provider_token"
        }
      }
    }
  }
}
```

`allowed_keys` and `exports` are mutually exclusive. When `exports` is used,
AV fails the request if any configured remote field is absent and discards
unmapped fields.

Google Secret Manager has no path-wide list operation in AV. Every local name
must name one exact version resource:

```json
{
  "connectors": {
    "google": {
      "kind": "google_secret_manager",
      "auth": {
        "type": "adc"
      }
    }
  },
  "profiles": {
    "example-prod": {
      "connector": "google",
      "exports": {
        "EXAMPLE_API_TOKEN": {
          "resource": "projects/example/secrets/provider-token/versions/latest"
        }
      }
    }
  }
}
```

Global and regional resources are accepted:

```text
projects/PROJECT/secrets/SECRET/versions/VERSION
projects/PROJECT/locations/LOCATION/secrets/SECRET/versions/VERSION
```

AV uses Application Default Credentials and the official Google client. In
Kubernetes, use Workload Identity Federation and grant the workload principal
`secretmanager.versions.access` only on the exact secrets referenced by its
profiles. Do not mount a service-account JSON key.

AV requires the payload checksum, verifies CRC32C before decoding, rejects
non-UTF-8 values, and limits each value to 64 KiB. Provider values are never
included in errors, logs, API responses, audit events, or the browser UI.

## Dynamic leases

Dynamic profiles are explicit and export-only. AV will not infer that an
OpenBao path or an Infisical object is dynamic, because doing so could create a
credential without assigning an owner that renews and revokes it.

An OpenBao dynamic profile reads the normal engine role path. `ttl_seconds` is
the requested renewal increment; the engine remains authoritative:

```json
{
  "connector": "openbao",
  "secret_path": "database/creds/example-app",
  "exports": {
    "DATABASE_USER": {"field": "username"},
    "DATABASE_PASSWORD": {"field": "password"}
  },
  "dynamic_secret": {
    "ttl_seconds": 300
  }
}
```

An Infisical dynamic profile names the existing dynamic-secret definition and
uses the project slug required by its lease API. `project_id` is omitted:

```json
{
  "connector": "infisical",
  "environment": "prod",
  "secret_path": "/database",
  "exports": {
    "DATABASE_USER": {"field": "username"},
    "DATABASE_PASSWORD": {"field": "password"}
  },
  "dynamic_secret": {
    "name": "example-app-database",
    "project_slug": "example-app",
    "ttl_seconds": 300
  }
}
```

AV uses OpenBao's per-lease renew and synchronous revoke APIs. For Infisical it
uses create, renew, and non-forced delete through the official dynamic-secret
lease API. Lease IDs and renewal metadata remain only in bounded process
memory; values remain only in the request or child that owns them. The
configured TTL must be between 30 seconds and 24 hours. A shorter backend TTL
is the crash backstop and is always authoritative.

Infisical Dynamic Secrets is a licensed feature. Static Infisical profiles
continue using the existing raw-secrets API and do not require it.

## Choosing a backend

- Use OpenBao for dynamic infrastructure credentials and KV values already
  governed there.
- Use Infisical for existing application and infrastructure projects that
  already use its environments and paths.
- Use Google Secret Manager for workloads whose identity and secret IAM are
  native to Google Cloud.

Profiles and proxy policy remain deployment configuration regardless of the
backend. The UI grants a subject access to those existing capabilities; it
cannot create a backend, alter a resource mapping, or enter a secret value.
