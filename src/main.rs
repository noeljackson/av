use std::{
    collections::BTreeMap,
    env,
    ffi::OsString,
    fs,
    net::SocketAddr,
    path::Path,
    path::PathBuf,
    process::{Command as ProcessCommand, ExitCode},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use av::{
    av::v1::{
        AgentCredential, AuthConfig as RpcAuthConfig, CreateAgentRequest,
        CreateProxySessionRequest, DeleteAgentRequest, GetAuthConfigRequest,
        GetProfileEnvironmentRequest, GrantProfileRequest, ListAgentsRequest, ListAgentsResponse,
        ListPrincipalRolesRequest, ListPrincipalRolesResponse, ListProfilesRequest,
        ListProfilesResponse, ListProxyDestinationsRequest, ListProxyDestinationsResponse,
        ProfileEnvironment, ProxySessionLease, RenewProxySessionRequest, RevokeProfileRequest,
        RevokeProxySessionRequest, RotateAgentRequest, SetAgentEnabledRequest,
        SetPrincipalRoleRequest,
    },
    config::{AuthConfig, AuthMode, Config, ConfigMode, ManagedConfig, OidcSigningAlgorithm},
    keyring,
    proxy_ca::install_rustls_provider,
    server,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::{CommandFactory, Parser, Subcommand};
use reqwest::{Client, StatusCode, header};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
};
use tokio_rustls::TlsConnector;
use tracing_subscriber::EnvFilter;
use url::Url;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "av", version, about)]
struct Cli {
    #[arg(long, env = "AV_URL", default_value = "https://av.tail.noel.sh")]
    api_url: String,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the connector and proxy service.
    Serve {
        #[arg(long, env = "AV_CONFIG", default_value = "/etc/av/config.json")]
        config: PathBuf,
    },
    /// Authenticate through the OIDC device flow and retain the token in the kernel keyring.
    Login,
    /// Remove the OIDC session from the kernel keyring.
    Logout,
    /// List profiles available to the current identity.
    Profiles,
    /// List injecting routes and credentialless tunnels available to the current identity.
    Routes,
    /// Run a child through a profile-scoped transparent proxy session.
    Run {
        profile: String,
        #[arg(required = true, last = true)]
        command: Vec<OsString>,
    },
    /// Manage named agent identities in a local or managed AV control plane.
    Agents {
        #[command(subcommand)]
        command: AgentCommand,
    },
    /// Manage instance roles. Only an owner may change roles.
    Roles {
        #[command(subcommand)]
        command: RoleCommand,
    },
    /// Initialize a local managed AV instance under XDG directories.
    Local {
        #[command(subcommand)]
        command: LocalCommand,
    },
    /// An unknown first word is treated as a profile: av example-dev -- cargo test.
    #[command(external_subcommand)]
    Profile(Vec<OsString>),
}

#[derive(Subcommand)]
enum LocalCommand {
    /// Create a local SQLite-backed configuration. It never creates or stores connector credentials.
    Init {
        #[arg(long)]
        issuer: String,
        #[arg(long)]
        client_id: String,
        #[arg(long, value_name = "ROLE")]
        allowed_role: String,
        #[arg(long, value_name = "SUBJECT")]
        owner_subject: String,
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum AgentCommand {
    List,
    Create {
        name: String,
        #[arg(long, value_name = "PATH")]
        out: Option<PathBuf>,
    },
    Rotate {
        name: String,
        #[arg(long, value_name = "PATH")]
        out: Option<PathBuf>,
    },
    Enable {
        name: String,
    },
    Disable {
        name: String,
    },
    Delete {
        name: String,
    },
    Grant {
        name: String,
        profile: String,
        #[arg(long, default_value = "proxy")]
        mode: String,
        #[arg(long, default_value_t = 0)]
        expires_unix_seconds: i64,
    },
    Revoke {
        name: String,
        profile: String,
    },
}

#[derive(Subcommand)]
enum RoleCommand {
    List,
    Set { subject: String, role: String },
}

#[derive(Deserialize)]
struct DeviceAuthorization {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default)]
    verification_uri_complete: Option<String>,
    expires_in: u64,
    #[serde(default = "default_poll_interval")]
    interval: u64,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct OAuthError {
    error: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("av: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<u8> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Serve { config }) => {
            init_tracing();
            server::run(Config::load(&config)?).await?;
            Ok(0)
        }
        Some(Command::Login) => {
            login(&cli.api_url).await?;
            Ok(0)
        }
        Some(Command::Logout) => {
            keyring::remove()?;
            println!("OIDC session removed from the kernel keyring");
            Ok(0)
        }
        Some(Command::Profiles) => {
            list_profiles(&cli.api_url).await?;
            Ok(0)
        }
        Some(Command::Routes) => {
            list_proxy_destinations(&cli.api_url).await?;
            Ok(0)
        }
        Some(Command::Run { profile, command }) => {
            run_transparent_proxy(&cli.api_url, profile, command).await
        }
        Some(Command::Agents { command }) => {
            manage_agent(&cli.api_url, command).await?;
            Ok(0)
        }
        Some(Command::Roles { command }) => {
            manage_role(&cli.api_url, command).await?;
            Ok(0)
        }
        Some(Command::Local { command }) => match command {
            LocalCommand::Init {
                issuer,
                client_id,
                allowed_role,
                owner_subject,
                config,
                force,
            } => {
                local_init(
                    config,
                    force,
                    issuer,
                    client_id,
                    allowed_role,
                    owner_subject,
                )?;
                Ok(0)
            }
        },
        Some(Command::Profile(arguments)) => run_profile(&cli.api_url, arguments).await,
        None => {
            Cli::command().print_help()?;
            println!();
            Ok(2)
        }
    }
}

async fn manage_role(api_url: &str, command: RoleCommand) -> Result<()> {
    match command {
        RoleCommand::List => {
            let response: ListPrincipalRolesResponse = connect_request(
                api_url,
                "av.v1.ControlService/ListPrincipalRoles",
                &ListPrincipalRolesRequest::default(),
                true,
            )
            .await?;
            for binding in response.roles {
                println!("{}\t{}", binding.subject, binding.role);
            }
        }
        RoleCommand::Set { subject, role } => {
            let _: av::av::v1::PrincipalRole = connect_request(
                api_url,
                "av.v1.ControlService/SetPrincipalRole",
                &SetPrincipalRoleRequest {
                    subject,
                    role,
                    ..Default::default()
                },
                true,
            )
            .await?;
        }
    }
    Ok(())
}

async fn manage_agent(api_url: &str, command: AgentCommand) -> Result<()> {
    match command {
        AgentCommand::List => {
            let response: ListAgentsResponse = connect_request(
                api_url,
                "av.v1.ControlService/ListAgents",
                &ListAgentsRequest::default(),
                true,
            )
            .await?;
            for agent in response.agents {
                println!(
                    "{}\t{}",
                    agent.name,
                    if agent.enabled { "enabled" } else { "disabled" }
                );
            }
        }
        AgentCommand::Create { name, out } => {
            let credential: AgentCredential = connect_request(
                api_url,
                "av.v1.ControlService/CreateAgent",
                &CreateAgentRequest {
                    name,
                    ..Default::default()
                },
                true,
            )
            .await?;
            emit_agent_token(&credential.token, out.as_deref())?;
        }
        AgentCommand::Rotate { name, out } => {
            let credential: AgentCredential = connect_request(
                api_url,
                "av.v1.ControlService/RotateAgent",
                &RotateAgentRequest {
                    name,
                    ..Default::default()
                },
                true,
            )
            .await?;
            emit_agent_token(&credential.token, out.as_deref())?;
        }
        AgentCommand::Enable { name } => {
            let _: av::av::v1::Agent = connect_request(
                api_url,
                "av.v1.ControlService/SetAgentEnabled",
                &SetAgentEnabledRequest {
                    name,
                    enabled: true,
                    ..Default::default()
                },
                true,
            )
            .await?;
        }
        AgentCommand::Disable { name } => {
            let _: av::av::v1::Agent = connect_request(
                api_url,
                "av.v1.ControlService/SetAgentEnabled",
                &SetAgentEnabledRequest {
                    name,
                    enabled: false,
                    ..Default::default()
                },
                true,
            )
            .await?;
        }
        AgentCommand::Delete { name } => {
            let _: av::av::v1::Agent = connect_request(
                api_url,
                "av.v1.ControlService/DeleteAgent",
                &DeleteAgentRequest {
                    name,
                    ..Default::default()
                },
                true,
            )
            .await?;
        }
        AgentCommand::Grant {
            name,
            profile,
            mode,
            expires_unix_seconds,
        } => {
            let _: av::av::v1::ProfileGrant = connect_request(
                api_url,
                "av.v1.ControlService/GrantProfile",
                &GrantProfileRequest {
                    profile,
                    subject: format!("agent:{name}"),
                    mode,
                    expires_unix_seconds,
                    ..Default::default()
                },
                true,
            )
            .await?;
        }
        AgentCommand::Revoke { name, profile } => {
            let _: av::av::v1::ProfileGrant = connect_request(
                api_url,
                "av.v1.ControlService/RevokeProfile",
                &RevokeProfileRequest {
                    profile,
                    subject: format!("agent:{name}"),
                    ..Default::default()
                },
                true,
            )
            .await?;
        }
    }
    Ok(())
}

fn emit_agent_token(token: &str, output: Option<&Path>) -> Result<()> {
    if let Some(path) = output {
        write_private_file(path, token.as_bytes())?;
        println!("agent token written to {}", path.display());
    } else {
        println!("{token}");
    }
    Ok(())
}

fn local_init(
    config_path: Option<PathBuf>,
    force: bool,
    issuer: String,
    client_id: String,
    allowed_role: String,
    owner_subject: String,
) -> Result<()> {
    if issuer.is_empty()
        || client_id.is_empty()
        || allowed_role.is_empty()
        || owner_subject.is_empty()
    {
        bail!("issuer, client-id, allowed-role, and owner-subject must be non-empty");
    }
    let config_root = xdg_path("XDG_CONFIG_HOME", ".config").join("av");
    let state_root = xdg_path("XDG_STATE_HOME", ".local/state").join("av");
    let data_root = xdg_path("XDG_DATA_HOME", ".local/share").join("av");
    let config_path = config_path.unwrap_or_else(|| config_root.join("bootstrap.json"));
    if config_path.exists() && !force {
        bail!(
            "{} already exists; use --force only after reviewing the existing configuration",
            config_path.display()
        );
    }
    for directory in [
        &config_root,
        &state_root,
        &data_root,
        &data_root.join("secrets"),
    ] {
        fs::create_dir_all(directory).with_context(|| format!("create {}", directory.display()))?;
        restrict_directory(directory)?;
    }
    let database_url_file = data_root.join("secrets/database-url");
    let database_path = state_root.join("av.sqlite3");
    write_private_file(
        &database_url_file,
        format!("sqlite:{}", database_path.display()).as_bytes(),
    )?;
    let config = Config {
        listen: "127.0.0.1:14322".into(),
        public_url: "http://127.0.0.1:14322".into(),
        mode: ConfigMode::Managed,
        managed: Some(ManagedConfig {
            database_url_file: database_url_file.display().to_string(),
            database_credentials_file: String::new(),
            postgres: None,
            database_reload_interval_seconds: 0,
            initial_owner_oidc_subject: owner_subject,
        }),
        auth: AuthConfig {
            mode: AuthMode::Oidc,
            issuer,
            client_id: client_id.clone(),
            audiences: vec![client_id],
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
            signing_algorithms: vec![OidcSigningAlgorithm::Rs256],
            allowed_groups: vec![allowed_role],
            group_claim: "urn:zitadel:iam:org:project:roles".into(),
            basic_users: vec![],
            github: None,
        },
        connectors: BTreeMap::new(),
        profiles: BTreeMap::new(),
        proxy_routes: BTreeMap::new(),
        proxy_tunnels: BTreeMap::new(),
        transparent_proxy: None,
        max_connector_concurrency: 16,
        api_rate_limit_per_second: 50,
        api_rate_limit_burst: 100,
    };
    config.validate()?;
    let rendered = serde_json::to_vec_pretty(&serde_json::json!({
        "listen": config.listen,
        "public_url": config.public_url,
        "mode": "managed",
        "managed": {
            "database_url_file": database_url_file,
            "initial_owner_oidc_subject": config.managed.as_ref().expect("local config has managed settings").initial_owner_oidc_subject,
        },
        "auth": {
            "mode": "oidc",
            "issuer": config.auth.issuer,
            "client_id": config.auth.client_id,
            "audiences": config.auth.audiences,
            "scopes": config.auth.scopes,
            "signing_algorithms": ["RS256"],
            "allowed_groups": config.auth.allowed_groups,
            "group_claim": config.auth.group_claim,
            "basic_users": [],
        },
        "connectors": {},
        "profiles": {},
        "proxy_routes": {},
        "proxy_tunnels": {},
        "transparent_proxy": null,
        "max_connector_concurrency": config.max_connector_concurrency,
        "api_rate_limit_per_second": config.api_rate_limit_per_second,
        "api_rate_limit_burst": config.api_rate_limit_burst,
    }))
    .context("serialize local AV configuration")?;
    write_private_file(&config_path, &rendered)?;
    println!("local AV initialized at {}", config_path.display());
    println!("start it with: av serve --config {}", config_path.display());
    Ok(())
}

fn xdg_path(variable: &str, fallback_suffix: &str) -> PathBuf {
    env::var_os(variable).map(PathBuf::from).unwrap_or_else(|| {
        env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
            .join(fallback_suffix)
    })
}

fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        restrict_directory(parent)?;
    }
    fs::write(path, contents).with_context(|| format!("write {}", path.display()))?;
    restrict_file(path)
}

#[cfg(unix)]
fn restrict_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("restrict {}", path.display()))
}

#[cfg(not(unix))]
fn restrict_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn restrict_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restrict {}", path.display()))
}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) -> Result<()> {
    Ok(())
}

async fn login(api_url: &str) -> Result<()> {
    let client = client(api_url)?;
    let auth: RpcAuthConfig = connect_request(
        api_url,
        "av.v1.SessionService/GetAuthConfig",
        &GetAuthConfigRequest::default(),
        false,
    )
    .await?;
    let device_endpoint = (!auth.device_authorization_endpoint.is_empty())
        .then_some(auth.device_authorization_endpoint.as_str())
        .context("the configured OIDC client does not expose device authorization")?;
    let token_endpoint = (!auth.token_endpoint.is_empty())
        .then_some(auth.token_endpoint.as_str())
        .context("OIDC token endpoint is unavailable")?;
    let response = client
        .post(device_endpoint)
        .form(&[
            ("client_id", auth.client_id.as_str()),
            ("scope", auth.scopes.join(" ").as_str()),
        ])
        .send()
        .await?
        .error_for_status()?
        .json::<DeviceAuthorization>()
        .await?;

    println!(
        "Open {} and enter code {}",
        response.verification_uri, response.user_code
    );
    let open_url = response
        .verification_uri_complete
        .as_deref()
        .unwrap_or(&response.verification_uri);
    let _ = ProcessCommand::new("xdg-open").arg(open_url).status();

    let deadline = Instant::now() + Duration::from_secs(response.expires_in);
    let mut interval = response.interval.max(1);
    while Instant::now() < deadline {
        tokio::time::sleep(Duration::from_secs(interval)).await;
        let token_response = client
            .post(token_endpoint)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", response.device_code.as_str()),
                ("client_id", auth.client_id.as_str()),
            ])
            .send()
            .await?;
        if token_response.status().is_success() {
            let token: TokenResponse = token_response.json().await?;
            keyring::store(&token.access_token)?;
            println!("OIDC session stored in the Linux kernel user keyring");
            return Ok(());
        }
        if token_response.status() == StatusCode::BAD_REQUEST {
            let error: OAuthError = token_response.json().await?;
            match error.error.as_str() {
                "authorization_pending" => continue,
                "slow_down" => {
                    interval += 5;
                    continue;
                }
                "access_denied" => bail!("OIDC login was denied"),
                "expired_token" => bail!("OIDC device code expired"),
                _ => bail!("OIDC login failed: {}", error.error),
            }
        }
        bail!("OIDC token endpoint returned {}", token_response.status());
    }
    bail!("OIDC device code expired")
}

async fn list_profiles(api_url: &str) -> Result<()> {
    let profiles: ListProfilesResponse = connect_request(
        api_url,
        "av.v1.SessionService/ListProfiles",
        &ListProfilesRequest::default(),
        true,
    )
    .await?;
    for profile in profiles.profiles {
        println!(
            "{}\t{}\t{}",
            profile.name, profile.environment, profile.secret_path
        );
    }
    Ok(())
}

async fn list_proxy_destinations(api_url: &str) -> Result<()> {
    let response: ListProxyDestinationsResponse = connect_request(
        api_url,
        "av.v1.SessionService/ListProxyDestinations",
        &ListProxyDestinationsRequest::default(),
        true,
    )
    .await?;
    for destination in response.destinations {
        println!(
            "{}\t{}\t{}\t{}",
            destination.name, destination.mode, destination.profile, destination.host
        );
    }
    Ok(())
}

async fn run_profile(api_url: &str, mut arguments: Vec<OsString>) -> Result<u8> {
    if arguments.len() < 2 {
        bail!("usage: av <profile> -- <command> [args...]");
    }
    let profile = arguments
        .remove(0)
        .into_string()
        .map_err(|_| anyhow::anyhow!("profile must be UTF-8"))?;
    if arguments.first().is_some_and(|argument| argument == "--") {
        arguments.remove(0);
    }
    if arguments.is_empty() {
        bail!("usage: av <profile> -- <command> [args...]");
    }
    let executable = arguments.remove(0);
    let executable_basename = Path::new(&executable)
        .file_name()
        .and_then(|name| name.to_str())
        .context("command name must be valid UTF-8")?
        .to_owned();
    let environment: ProfileEnvironment = connect_request(
        api_url,
        "av.v1.SessionService/GetProfileEnvironment",
        &GetProfileEnvironmentRequest {
            profile,
            executable_basename,
            ..Default::default()
        },
        true,
    )
    .await?;
    let mut secrets = BTreeMap::new();
    for value in environment.values {
        if secrets.insert(value.name.clone(), value.value).is_some() {
            bail!(
                "profile returned duplicate environment variable {}",
                value.name
            );
        }
    }
    for key in secrets.keys() {
        if !valid_env_name(key) {
            bail!("profile contains a key that is not a valid environment variable: {key}");
        }
    }
    let status = profile_command(executable, arguments, secrets)
        .status()
        .context("start child process")?;
    Ok(status.code().unwrap_or(1).clamp(0, 255) as u8)
}

async fn run_transparent_proxy(
    api_url: &str,
    profile: String,
    mut command: Vec<OsString>,
) -> Result<u8> {
    if command.first().is_some_and(|argument| argument == "--") {
        command.remove(0);
    }
    let executable = command
        .first()
        .cloned()
        .context("usage: av run <profile> -- <command> [args...]")?;
    let arguments = command.into_iter().skip(1).collect();
    let lease: ProxySessionLease = connect_request(
        api_url,
        "av.v1.SessionService/CreateProxySession",
        &CreateProxySessionRequest {
            profile,
            ..Default::default()
        },
        true,
    )
    .await?;
    if lease.session_id.is_empty()
        || lease.token.is_empty()
        || lease.proxy_url.is_empty()
        || lease.ca_certificate_pem.is_empty()
    {
        bail!("AV returned an incomplete proxy session");
    }
    let session_id = lease.session_id;
    let initial_expires_unix_seconds = lease.expires_unix_seconds;
    let token = Zeroizing::new(lease.token);
    // From this point forward revocation is mandatory, including failures while
    // writing the public CA or binding loopback. TTL is a backstop, not normal
    // cleanup for a partially initialized helper.
    let status = async {
        let ca = write_proxy_ca(&lease.ca_certificate_pem)?;
        let (shutdown, listener_address, listener) =
            start_loopback_proxy(&lease.proxy_url, token.clone()).await?;
        let proxy_url = format!("http://{listener_address}");
        let listener_task = tokio::spawn(listener);
        let status = tokio::select! {
            status = run_proxy_child(executable, arguments, &proxy_url, &ca.path) => status,
            renewal = renew_proxy_session_loop(
                api_url,
                &session_id,
                initial_expires_unix_seconds,
            ) => {
                renewal?;
                bail!("transparent proxy session renewal stopped unexpectedly")
            }
        };
        let _ = shutdown.send(true);
        let _ = listener_task.await;
        status
    }
    .await;
    let revoke = connect_request::<_, ProxySessionLease>(
        api_url,
        "av.v1.SessionService/RevokeProxySession",
        &RevokeProxySessionRequest {
            session_id,
            ..Default::default()
        },
        true,
    )
    .await;
    match (status, revoke) {
        (Ok(status), Ok(_)) => Ok(status),
        (Err(error), Ok(_)) => Err(error),
        (Ok(_), Err(error)) => Err(error).context("revoke transparent proxy session"),
        (Err(error), Err(revoke_error)) => Err(error).context(format!(
            "proxied child failed and AV session revocation also failed: {revoke_error:#}"
        )),
    }
}

async fn renew_proxy_session_loop(
    api_url: &str,
    session_id: &str,
    mut expires_unix_seconds: i64,
) -> Result<()> {
    if expires_unix_seconds <= 0 {
        bail!("AV returned an invalid proxy session expiry");
    }
    loop {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before Unix epoch")?
            .as_secs();
        let now = i64::try_from(now).context("system clock is outside supported range")?;
        let remaining = expires_unix_seconds
            .checked_sub(now)
            .filter(|remaining| *remaining > 0)
            .context("transparent proxy session expired before renewal")?;
        let delay = u64::try_from((remaining / 2).max(1))
            .context("proxy renewal delay is outside supported range")?;
        tokio::time::sleep(Duration::from_secs(delay)).await;
        let renewed: ProxySessionLease = connect_request(
            api_url,
            "av.v1.SessionService/RenewProxySession",
            &RenewProxySessionRequest {
                session_id: session_id.to_owned(),
                ..Default::default()
            },
            true,
        )
        .await
        .context("renew transparent proxy session")?;
        let renewed_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before Unix epoch")?
            .as_secs();
        let renewed_now =
            i64::try_from(renewed_now).context("system clock is outside supported range")?;
        if renewed.session_id != session_id
            || renewed.revoked
            || renewed.expires_unix_seconds <= renewed_now
        {
            bail!("AV returned an invalid proxy session renewal");
        }
        expires_unix_seconds = renewed.expires_unix_seconds;
    }
}

struct ProxyCaFile {
    // Dropping TempDir removes the temporary certificate after the child exits.
    // The CA private key is never present here.
    _directory: tempfile::TempDir,
    path: PathBuf,
}

fn write_proxy_ca(certificate_pem: &str) -> Result<ProxyCaFile> {
    if !certificate_pem.contains("-----BEGIN CERTIFICATE-----")
        || certificate_pem.len() > 256 * 1024
    {
        bail!("AV returned an invalid proxy CA certificate");
    }
    let directory = tempfile::Builder::new()
        .prefix("av-proxy-")
        .tempdir()
        .context("create private proxy CA directory")?;
    restrict_directory(directory.path())?;
    let path = directory.path().join("proxy-ca.pem");
    write_private_file(&path, certificate_pem.as_bytes())?;
    Ok(ProxyCaFile {
        _directory: directory,
        path,
    })
}

async fn start_loopback_proxy(
    remote_proxy_url: &str,
    token: Zeroizing<String>,
) -> Result<(
    watch::Sender<bool>,
    SocketAddr,
    impl std::future::Future<Output = Result<()>> + use<>,
)> {
    let transport_tls = transport_client_config()?;
    start_loopback_proxy_with_tls(remote_proxy_url, token, transport_tls).await
}

fn transport_client_config() -> Result<std::sync::Arc<ClientConfig>> {
    install_rustls_provider()?;
    let mut roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = std::env::var_os("AV_PROXY_TRANSPORT_CA_FILE") {
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            bail!("AV_PROXY_TRANSPORT_CA_FILE must be an absolute path");
        }
        let pem = fs::read(&path)
            .with_context(|| format!("read proxy transport CA certificate {}", path.display()))?;
        if pem.len() > 256 * 1024 {
            bail!("proxy transport CA certificate is too large");
        }
        let certificates = CertificateDer::pem_slice_iter(&pem)
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("parse proxy transport CA certificate")?;
        if certificates.is_empty() {
            bail!("proxy transport CA certificate is empty");
        }
        for certificate in certificates {
            roots
                .add(certificate)
                .context("proxy transport CA certificate is invalid")?;
        }
    }
    Ok(std::sync::Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

async fn start_loopback_proxy_with_tls(
    remote_proxy_url: &str,
    token: Zeroizing<String>,
    transport_tls: std::sync::Arc<ClientConfig>,
) -> Result<(
    watch::Sender<bool>,
    SocketAddr,
    impl std::future::Future<Output = Result<()>> + use<>,
)> {
    let remote = Url::parse(remote_proxy_url).context("proxy session has an invalid proxy URL")?;
    if remote.scheme() != "https"
        || remote.host_str().is_none()
        || remote
            .host_str()
            .is_some_and(|host| host.parse::<std::net::IpAddr>().is_ok())
        || remote.port().is_none()
        || remote.username() != ""
        || remote.password().is_some()
        || remote.query().is_some()
        || remote.fragment().is_some()
        || !matches!(remote.path(), "" | "/")
    {
        bail!("proxy session has an unsafe proxy URL");
    }
    let remote_host = remote.host_str().expect("checked host");
    let remote_server_name = ServerName::try_from(remote_host.to_owned())
        .context("proxy session has an invalid DNS name")?;
    let remote_address = if remote_host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{remote_host}]:{}", remote.port().expect("checked port"))
    } else {
        format!("{remote_host}:{}", remote.port().expect("checked port"))
    };
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind local proxy helper")?;
    let listener_address = listener
        .local_addr()
        .context("inspect local proxy helper")?;
    let (shutdown, mut stopped) = watch::channel(false);
    let token = std::sync::Arc::new(token);
    let future = async move {
        loop {
            tokio::select! {
                changed = stopped.changed() => {
                    if changed.is_err() || *stopped.borrow() { return Ok(()); }
                }
                accepted = listener.accept() => {
                    let (stream, _) = accepted.context("accept local proxy client")?;
                    let remote_address = remote_address.clone();
                    let remote_server_name = remote_server_name.clone();
                    let transport_tls = transport_tls.clone();
                    let token = token.clone();
                    let stopped = stopped.clone();
                    tokio::spawn(async move {
                        if let Err(error) = proxy_local_connection(
                            stream,
                            &remote_address,
                            remote_server_name,
                            transport_tls,
                            token,
                            stopped,
                        ).await {
                            tracing::debug!(%error, "local proxy helper connection ended");
                        }
                    });
                }
            }
        }
    };
    Ok((shutdown, listener_address, future))
}

async fn proxy_local_connection(
    mut client: TcpStream,
    remote_address: &str,
    remote_server_name: ServerName<'static>,
    transport_tls: std::sync::Arc<ClientConfig>,
    token: std::sync::Arc<Zeroizing<String>>,
    mut stopped: watch::Receiver<bool>,
) -> Result<()> {
    let (header, remaining) = read_proxy_header(&mut client).await?;
    let rewritten = inject_proxy_authorization(&header, token.as_str())?;
    let remote = TcpStream::connect(remote_address)
        .await
        .context("connect private AV proxy")?;
    let mut remote = TlsConnector::from(transport_tls)
        .connect(remote_server_name, remote)
        .await
        .context("verify private AV proxy transport TLS")?;
    remote.write_all(&rewritten).await?;
    let (response, remote_remaining) = read_proxy_header(&mut remote).await?;
    client.write_all(&response).await?;
    if !response.starts_with(b"HTTP/1.1 200") && !response.starts_with(b"HTTP/1.0 200") {
        return Ok(());
    }
    if !remaining.is_empty() {
        remote.write_all(&remaining).await?;
    }
    if !remote_remaining.is_empty() {
        client.write_all(&remote_remaining).await?;
    }
    tokio::select! {
        result = tokio::io::copy_bidirectional(&mut client, &mut remote) => {
            result.context("relay local proxy connection")?;
        }
        changed = stopped.changed() => {
            let _ = changed;
        }
    }
    Ok(())
}

async fn read_proxy_header(stream: &mut (impl AsyncRead + Unpin)) -> Result<(Vec<u8>, Vec<u8>)> {
    const MAX_PROXY_HEADER: usize = 16 * 1024;
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 2048];
    loop {
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let end = index + 4;
            return Ok((bytes[..end].to_vec(), bytes[end..].to_vec()));
        }
        if bytes.len() >= MAX_PROXY_HEADER {
            bail!("proxy request headers are too large");
        }
        let read = stream
            .read(&mut chunk)
            .await
            .context("read proxy headers")?;
        if read == 0 {
            bail!("proxy connection closed before request headers");
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
}

fn inject_proxy_authorization(header: &[u8], token: &str) -> Result<Vec<u8>> {
    if token.is_empty()
        || token
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        bail!("proxy session token is invalid");
    }
    let header = std::str::from_utf8(header).context("proxy request headers are not UTF-8")?;
    let mut lines = header.split("\r\n");
    let request_line = lines
        .next()
        .context("proxy request is missing a request line")?;
    let mut request_parts = request_line.split_ascii_whitespace();
    if request_parts.next() != Some("CONNECT")
        || request_parts.next().is_none()
        || request_parts.next() != Some("HTTP/1.1")
        || request_parts.next().is_some()
    {
        bail!("local proxy helper accepts CONNECT HTTP/1.1 only");
    }
    let mut output = String::with_capacity(header.len() + token.len() + 40);
    output.push_str(request_line);
    output.push_str("\r\n");
    let mut host_count = 0;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if line.starts_with([' ', '\t']) {
            bail!("proxy request contains folded headers");
        }
        let (name, value) = line
            .split_once(':')
            .context("proxy request has an invalid header")?;
        if name.eq_ignore_ascii_case("proxy-authorization") {
            continue;
        }
        if name.eq_ignore_ascii_case("host") {
            host_count += 1;
        }
        if name.is_empty() || value.contains(['\r', '\n']) {
            bail!("proxy request has an invalid header");
        }
        output.push_str(line);
        output.push_str("\r\n");
    }
    if host_count != 1 {
        bail!("proxy CONNECT request requires exactly one Host header");
    }
    output.push_str("Proxy-Authorization: Bearer ");
    output.push_str(token);
    output.push_str("\r\n\r\n");
    Ok(output.into_bytes())
}

async fn run_proxy_child(
    executable: OsString,
    arguments: Vec<OsString>,
    proxy_url: &str,
    ca_path: &Path,
) -> Result<u8> {
    let mut command = tokio::process::Command::from(proxy_child_command(
        executable, arguments, proxy_url, ca_path,
    )?);
    command.kill_on_drop(true);
    let mut child = command.spawn().context("start proxied child process")?;
    let status = tokio::select! {
        status = child.wait() => status.context("wait for proxied child process")?,
        signal = tokio::signal::ctrl_c() => {
            signal.context("wait for interrupt")?;
            let _ = child.kill().await;
            child.wait().await.context("wait for interrupted child process")?
        }
    };
    Ok(status.code().unwrap_or(1).clamp(0, 255) as u8)
}

fn proxy_child_command(
    executable: OsString,
    arguments: Vec<OsString>,
    proxy_url: &str,
    ca_path: &Path,
) -> Result<ProcessCommand> {
    let proxy_url = Url::parse(proxy_url).context("local proxy URL is invalid")?;
    if proxy_url.scheme() != "http"
        || proxy_url.host_str().is_none_or(|host| !is_loopback(host))
        || proxy_url.port().is_none()
        || proxy_url.username() != ""
        || proxy_url.password().is_some()
        || proxy_url.query().is_some()
        || proxy_url.fragment().is_some()
        || !matches!(proxy_url.path(), "" | "/")
    {
        bail!("local proxy URL must be a credential-free loopback HTTP origin");
    }
    let mut command = ProcessCommand::new(executable);
    command
        .args(arguments)
        .env("HTTP_PROXY", proxy_url.as_str())
        .env("HTTPS_PROXY", proxy_url.as_str())
        .env("http_proxy", proxy_url.as_str())
        .env("https_proxy", proxy_url.as_str())
        .env("SSL_CERT_FILE", ca_path)
        .env("NODE_EXTRA_CA_CERTS", ca_path)
        .env("CURL_CA_BUNDLE", ca_path)
        .env("REQUESTS_CA_BUNDLE", ca_path)
        .env("GIT_SSL_CAINFO", ca_path)
        .env("CODEX_CA_CERTIFICATE", ca_path)
        .env_remove("AV_AGENT_TOKEN_FILE")
        .env_remove("AV_AGENT_TOKEN")
        .env_remove("AV_TOKEN")
        .env_remove("AV_BASIC_USER")
        .env_remove("AV_BASIC_PASSWORD")
        .env_remove("AV_PROXY_TRANSPORT_CA_FILE")
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy");
    Ok(command)
}

// Profile credentials are deliberately the only AV-specific material passed to
// a child. `Command` otherwise inherits this process's environment, which
// would expose the wrapper credential that authorizes access to other profiles.
// Remove the reserved names after adding profile values too: a misconfigured
// profile must not be able to reintroduce a wrapper credential.
fn profile_command(
    executable: OsString,
    arguments: Vec<OsString>,
    secrets: BTreeMap<String, String>,
) -> ProcessCommand {
    let mut command = ProcessCommand::new(executable);
    command
        .args(arguments)
        .envs(secrets)
        .env_remove("AV_AGENT_TOKEN_FILE")
        .env_remove("AV_AGENT_TOKEN")
        .env_remove("AV_TOKEN")
        .env_remove("AV_BASIC_USER")
        .env_remove("AV_BASIC_PASSWORD")
        .env_remove("AV_PROXY_TRANSPORT_CA_FILE");
    command
}

async fn connect_request<Request, Response>(
    api_url: &str,
    procedure: &str,
    body: &Request,
    authenticated: bool,
) -> Result<Response>
where
    Request: Serialize,
    Response: DeserializeOwned,
{
    let client = client(api_url)?;
    let mut request = client
        .post(format!("{}/{}", api_url.trim_end_matches('/'), procedure))
        .header(header::CONTENT_TYPE, "application/json")
        .header("connect-protocol-version", "1")
        .json(body);
    if authenticated {
        request = authenticate_request(request)?;
    }
    let response = request.send().await?;
    if response.status() == StatusCode::UNAUTHORIZED {
        bail!("session is unauthorized or expired; run `av login`");
    }
    Ok(response.error_for_status()?.json().await?)
}

fn authenticate_request(request: reqwest::RequestBuilder) -> Result<reqwest::RequestBuilder> {
    if let Ok(path) = std::env::var("AV_AGENT_TOKEN_FILE") {
        let token = read_agent_token(Path::new(&path))?;
        return Ok(request.header(header::AUTHORIZATION, format!("Agent {}", token.as_str())));
    }
    if let Ok(token) = std::env::var("AV_AGENT_TOKEN") {
        return Ok(request.header(header::AUTHORIZATION, format!("Agent {token}")));
    }
    if let Ok(token) = std::env::var("AV_TOKEN") {
        return Ok(request.bearer_auth(token));
    }
    if let (Ok(username), Ok(password)) = (
        std::env::var("AV_BASIC_USER"),
        std::env::var("AV_BASIC_PASSWORD"),
    ) {
        return Ok(request.header(
            header::AUTHORIZATION,
            format!(
                "Basic {}",
                STANDARD.encode(format!("{username}:{password}"))
            ),
        ));
    }
    if let Some(token) = keyring::load()? {
        return Ok(request.bearer_auth(token));
    }
    bail!("not logged in; run `av login` or set AV_AGENT_TOKEN/AV_TOKEN")
}

fn read_agent_token(path: &Path) -> Result<Zeroizing<String>> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("inspect AV agent token file {}", path.display()))?;
    if !metadata.is_file() || metadata.len() > 256 {
        bail!("AV agent token file must be a regular file no larger than 256 bytes");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("AV agent token file must not be accessible by group or other users");
        }
    }
    let raw = Zeroizing::new(
        fs::read_to_string(path)
            .with_context(|| format!("read AV agent token file {}", path.display()))?,
    );
    let token = raw.strip_suffix('\n').unwrap_or(raw.as_str());
    if token.len() != 52
        || !token.starts_with("av_agent_")
        || token.contains(['\r', '\n'])
        || !token[9..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("AV agent token file contains an invalid token");
    }
    Ok(Zeroizing::new(token.to_owned()))
}

fn client(api_url: &str) -> Result<Client> {
    let url = Url::parse(api_url).context("AV_URL must be a URL")?;
    if url.scheme() != "https" && !url.host_str().is_some_and(is_loopback) {
        bail!("AV_URL must use HTTPS unless it is loopback");
    }
    Ok(Client::builder()
        .timeout(Duration::from_secs(30))
        .https_only(url.scheme() == "https")
        .user_agent(concat!("av-cli/", env!("CARGO_PKG_VERSION")))
        .build()?)
}

fn valid_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn default_poll_interval() -> u64 {
    5
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("av=info,tower_http=info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .with_current_span(false)
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_portable_environment_names() {
        assert!(valid_env_name("DATABASE_URL"));
        assert!(valid_env_name("_PRIVATE"));
        assert!(!valid_env_name("1TOKEN"));
        assert!(!valid_env_name("BAD-NAME"));
    }

    #[test]
    fn unknown_subcommand_is_a_profile_wrapper() {
        let cli = Cli::try_parse_from(["av", "example-dev", "--", "cargo", "test"]).unwrap();
        let Some(Command::Profile(arguments)) = cli.command else {
            panic!("expected profile command");
        };
        assert_eq!(arguments[0], OsString::from("example-dev"));
        assert_eq!(arguments[1], OsString::from("--"));
        assert_eq!(arguments[2], OsString::from("cargo"));
        assert_eq!(arguments[3], OsString::from("test"));
    }

    #[test]
    fn management_commands_parse_without_becoming_profile_wrappers() {
        let cli = Cli::try_parse_from([
            "av",
            "agents",
            "grant",
            "builder",
            "example-prod",
            "--mode",
            "proxy",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Agents {
                command: AgentCommand::Grant { .. }
            })
        ));
        let cli = Cli::try_parse_from(["av", "roles", "set", "oidc:operator", "operator"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Roles {
                command: RoleCommand::Set { .. }
            })
        ));
    }

    #[test]
    fn agent_token_files_are_private_and_strictly_parsed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("agent-token");
        let token = format!("av_agent_{}", "A".repeat(43));
        emit_agent_token(&token, Some(&path)).unwrap();
        assert_eq!(read_agent_token(&path).unwrap().as_str(), token);
        std::fs::write(&path, format!("{token}\n\n")).unwrap();
        assert!(read_agent_token(&path).is_err());
    }

    #[test]
    fn profile_child_does_not_inherit_wrapper_credentials() {
        let command = profile_command(
            OsString::from("example"),
            vec![OsString::from("--flag")],
            BTreeMap::from([
                ("PROFILE_SECRET".to_owned(), "value".to_owned()),
                (
                    "AV_AGENT_TOKEN".to_owned(),
                    "must-not-reach-child".to_owned(),
                ),
                ("AV_TOKEN".to_owned(), "must-not-reach-child".to_owned()),
                (
                    "AV_BASIC_USER".to_owned(),
                    "must-not-reach-child".to_owned(),
                ),
                (
                    "AV_BASIC_PASSWORD".to_owned(),
                    "must-not-reach-child".to_owned(),
                ),
            ]),
        );
        let envs: BTreeMap<OsString, Option<OsString>> = command
            .get_envs()
            .map(|(name, value)| (name.to_os_string(), value.map(OsString::from)))
            .collect();

        assert_eq!(envs.get(&OsString::from("AV_AGENT_TOKEN")), Some(&None));
        assert_eq!(
            envs.get(&OsString::from("AV_AGENT_TOKEN_FILE")),
            Some(&None)
        );
        assert_eq!(envs.get(&OsString::from("AV_TOKEN")), Some(&None));
        assert_eq!(envs.get(&OsString::from("AV_BASIC_USER")), Some(&None));
        assert_eq!(envs.get(&OsString::from("AV_BASIC_PASSWORD")), Some(&None));
        assert_eq!(
            envs.get(&OsString::from("PROFILE_SECRET")),
            Some(&Some(OsString::from("value")))
        );
    }

    #[test]
    fn local_helper_replaces_caller_proxy_authorization() {
        let rewritten = inject_proxy_authorization(
            b"CONNECT api.example.test:443 HTTP/1.1\r\nHost: api.example.test:443\r\nProxy-Authorization: Basic caller-controlled\r\nProxy-Authorization: Bearer also-caller-controlled\r\n\r\n",
            "opaque-test-session",
        )
        .unwrap();
        let rewritten = std::str::from_utf8(&rewritten).unwrap();

        assert!(rewritten.starts_with("CONNECT api.example.test:443 HTTP/1.1\r\n"));
        assert!(!rewritten.contains("caller-controlled"));
        assert_eq!(rewritten.matches("Proxy-Authorization:").count(), 1);
        assert!(rewritten.contains("Proxy-Authorization: Bearer opaque-test-session\r\n"));
    }

    #[test]
    fn local_helper_rejects_ambiguous_or_non_connect_requests() {
        assert!(
            inject_proxy_authorization(
                b"GET https://api.example.test/ HTTP/1.1\r\nHost: api.example.test\r\n\r\n",
                "opaque-test-session"
            )
            .is_err()
        );
        assert!(inject_proxy_authorization(
            b"CONNECT api.example.test:443 HTTP/1.1\r\nHost: api.example.test:443\r\nHost: api.example.test:443\r\n\r\n",
            "opaque-test-session"
        )
        .is_err());
    }

    #[test]
    fn proxied_child_gets_only_loopback_proxy_settings() {
        let command = proxy_child_command(
            OsString::from("example"),
            Vec::new(),
            "http://127.0.0.1:42173",
            Path::new("/private/proxy-ca.pem"),
        )
        .unwrap();
        let envs: BTreeMap<OsString, Option<OsString>> = command
            .get_envs()
            .map(|(name, value)| (name.to_os_string(), value.map(OsString::from)))
            .collect();

        for name in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
            assert_eq!(
                envs.get(&OsString::from(name)),
                Some(&Some(OsString::from("http://127.0.0.1:42173/")))
            );
        }
        for name in [
            "AV_AGENT_TOKEN_FILE",
            "AV_AGENT_TOKEN",
            "AV_TOKEN",
            "AV_BASIC_USER",
            "AV_BASIC_PASSWORD",
            "AV_PROXY_TRANSPORT_CA_FILE",
            "NO_PROXY",
            "no_proxy",
            "ALL_PROXY",
            "all_proxy",
        ] {
            assert_eq!(envs.get(&OsString::from(name)), Some(&None));
        }
        for name in [
            "SSL_CERT_FILE",
            "NODE_EXTRA_CA_CERTS",
            "CURL_CA_BUNDLE",
            "REQUESTS_CA_BUNDLE",
            "GIT_SSL_CAINFO",
            "CODEX_CA_CERTIFICATE",
        ] {
            assert_eq!(
                envs.get(&OsString::from(name)),
                Some(&Some(OsString::from("/private/proxy-ca.pem")))
            );
        }
        assert!(
            proxy_child_command(
                OsString::from("example"),
                Vec::new(),
                "http://token@proxy.example.test:14323",
                Path::new("/private/proxy-ca.pem"),
            )
            .is_err()
        );
        assert!(
            proxy_child_command(
                OsString::from("example"),
                Vec::new(),
                "http://proxy.example.test:14323",
                Path::new("/private/proxy-ca.pem"),
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn local_helper_forwards_only_its_opaque_session_credential() {
        install_rustls_provider().unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let server_tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(
                    certificate.der().to_vec(),
                )],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()),
                ),
            )
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(
                certificate.der().to_vec(),
            ))
            .unwrap();
        let client_tls = std::sync::Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let remote_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let remote_address = remote_listener.local_addr().unwrap();
        let (header_sent, header_received) = tokio::sync::oneshot::channel();
        let remote_task = tokio::spawn(async move {
            let (remote, _) = remote_listener.accept().await.unwrap();
            let mut remote = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_tls))
                .accept(remote)
                .await
                .unwrap();
            let (header, _) = read_proxy_header(&mut remote).await.unwrap();
            header_sent.send(header).unwrap();
            remote
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let (shutdown, local_address, local_helper) = start_loopback_proxy_with_tls(
            &format!("https://localhost:{}", remote_address.port()),
            Zeroizing::new("opaque-test-session".to_owned()),
            client_tls,
        )
        .await
        .unwrap();
        let helper_task = tokio::spawn(local_helper);
        let mut client = TcpStream::connect(local_address).await.unwrap();
        client
            .write_all(b"CONNECT api.example.test:443 HTTP/1.1\r\nHost: api.example.test:443\r\nProxy-Authorization: Basic caller-controlled\r\n\r\n")
            .await
            .unwrap();
        let (response, _) = read_proxy_header(&mut client).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 407"));
        drop(client);

        let header = tokio::time::timeout(Duration::from_secs(1), header_received)
            .await
            .unwrap()
            .unwrap();
        let header = std::str::from_utf8(&header).unwrap();
        assert!(!header.contains("caller-controlled"));
        assert_eq!(header.matches("Proxy-Authorization:").count(), 1);
        assert!(header.contains("Proxy-Authorization: Bearer opaque-test-session\r\n"));

        shutdown.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), helper_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        remote_task.await.unwrap();
    }
}
