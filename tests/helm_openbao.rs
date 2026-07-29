//! Helm contract tests for OpenBao Agent database credential injection.

use std::{error::Error, process::Command};

#[test]
fn default_chart_renders_a_protected_singleton() -> Result<(), Box<dyn Error>> {
    let output = Command::new("helm")
        .args(["template", "av", "chart/av"])
        .output()?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
    }
    let rendered = String::from_utf8(output.stdout)?;
    for expected in [
        "type: Recreate",
        "revisionHistoryLimit: 2",
        "terminationGracePeriodSeconds: 30",
        "automountServiceAccountToken: false",
        "path: /readyz",
        "path: /healthz",
        "medium: Memory",
        "sizeLimit: 16Mi",
        "kind: PodDisruptionBudget",
        "maxUnavailable: 0",
    ] {
        assert!(
            rendered.contains(expected),
            "rendered chart is missing {expected}"
        );
    }
    Ok(())
}

#[test]
fn chart_rejects_multiple_replicas_until_lease_ownership_is_distributed() {
    let output = Command::new("helm")
        .args(["template", "av", "chart/av", "--set", "replicaCount=2"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("replicaCount must be 1 until distributed dynamic lease ownership")
    );
}

#[test]
fn chart_rejects_unsafe_singleton_lifecycle_overrides() {
    for (key, value, expected) in [
        (
            "deployment.terminationGracePeriodSeconds",
            "10",
            "must be between 25 and 300",
        ),
        (
            "deployment.revisionHistoryLimit",
            "0",
            "must be between 1 and 10",
        ),
        (
            "podDisruptionBudget.maxUnavailable",
            "1",
            "must remain 0 for the singleton deployment",
        ),
    ] {
        let output = Command::new("helm")
            .args([
                "template",
                "av",
                "chart/av",
                "--set",
                &format!("{key}={value}"),
            ])
            .output()
            .unwrap();
        assert!(!output.status.success(), "{key}={value} was accepted");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "{key}={value} did not fail with {expected}"
        );
    }
}

#[test]
fn managed_openbao_agent_renders_ephemeral_rotating_database_credentials()
-> Result<(), Box<dyn Error>> {
    let output = Command::new("helm")
        .args([
            "template",
            "av",
            "chart/av",
            "--set",
            "controlPlane.mode=managed",
            "--set",
            "controlPlane.initialOwnerOidcSubject=oidc:owner",
            "--set",
            "controlPlane.openbaoAgent.enabled=true",
            "--set",
            "controlPlane.openbaoAgent.address=https://openbao-active.openbao.svc:8200",
            "--set",
            "controlPlane.openbaoAgent.role=av",
            "--set",
            "controlPlane.openbaoAgent.secretPath=database/creds/av",
            "--set",
            "controlPlane.openbaoAgent.tlsSecretName=openbao-internal-ca",
            "--set",
            "controlPlane.openbaoAgent.tlsServerName=openbao.openbao.svc",
            "--set",
            "controlPlane.openbaoAgent.postgres.host=postgres.example",
            "--set",
            "controlPlane.openbaoAgent.postgres.database=av",
            "--set",
            "controlPlane.openbaoAgent.postgres.role=av_owner",
        ])
        .output()?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
    }
    let rendered = String::from_utf8(output.stdout)?;
    for expected in [
        "vault.hashicorp.com/agent-inject: \"true\"",
        "vault.hashicorp.com/agent-inject-secret-database-credentials.json: \"database/creds/av\"",
        "{{ .Data | toJSON }}",
        "\\\"database_credentials_file\\\":\\\"/vault/secrets/database-credentials.json\\\"",
        "\\\"database_reload_interval_seconds\\\":5",
        "\\\"role\\\":\\\"av_owner\\\"",
    ] {
        assert!(
            rendered.contains(expected),
            "rendered chart is missing {expected}"
        );
    }
    assert!(
        !rendered.contains("name: control-plane-database"),
        "OpenBao Agent mode must not mount a durable database Secret"
    );
    Ok(())
}

#[test]
fn managed_existing_secret_remains_available_for_local_deployments() -> Result<(), Box<dyn Error>> {
    let output = Command::new("helm")
        .args([
            "template",
            "av",
            "chart/av",
            "--set",
            "controlPlane.mode=managed",
            "--set",
            "controlPlane.initialOwnerOidcSubject=oidc:owner",
            "--set",
            "controlPlane.existingDatabaseSecret.name=av-database",
        ])
        .output()?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
    }
    let rendered = String::from_utf8(output.stdout)?;
    assert!(rendered.contains("secretName: av-database"));
    assert!(!rendered.contains("vault.hashicorp.com/agent-inject:"));
    Ok(())
}

#[test]
fn transparent_proxy_renders_sliding_and_absolute_session_limits() -> Result<(), Box<dyn Error>> {
    let output = Command::new("helm")
        .args([
            "template",
            "av",
            "chart/av",
            "--set",
            "controlPlane.mode=managed",
            "--set",
            "controlPlane.initialOwnerOidcSubject=oidc:owner",
            "--set",
            "controlPlane.existingDatabaseSecret.name=av-database",
            "--set",
            "transparentProxy.enabled=true",
            "--set",
            "transparentProxy.proxyUrl=https://av-proxy.example.test:14323",
            "--set",
            "transparentProxy.transportTlsSecret.name=av-transport",
            "--set",
            "transparentProxy.caSecret.name=av-proxy-ca",
            "--set",
            "transparentProxy.sessionTtlSeconds=300",
            "--set",
            "transparentProxy.sessionMaxLifetimeSeconds=28800",
        ])
        .output()?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
    }
    let rendered = String::from_utf8(output.stdout)?;
    for expected in [
        "\\\"session_ttl_seconds\\\":300",
        "\\\"session_max_lifetime_seconds\\\":28800",
    ] {
        assert!(
            rendered.contains(expected),
            "rendered chart is missing {expected}"
        );
    }
    Ok(())
}
