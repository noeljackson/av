//! Helm contract tests for OpenBao Agent database credential injection.

use std::{error::Error, process::Command};

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
