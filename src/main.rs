use std::{
    collections::BTreeMap,
    env,
    ffi::OsString,
    fs,
    path::Path,
    path::PathBuf,
    process::{Command as ProcessCommand, ExitCode},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use av::{
    av::v1::{
        AuthConfig as RpcAuthConfig, GetAuthConfigRequest, GetProfileEnvironmentRequest,
        ListProfilesRequest, ListProfilesResponse, ProfileEnvironment,
    },
    config::{AuthConfig, AuthMode, Config, ConfigMode, ManagedConfig, OidcSigningAlgorithm},
    keyring, server,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::{CommandFactory, Parser, Subcommand};
use reqwest::{Client, StatusCode, header};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tracing_subscriber::EnvFilter;
use url::Url;

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
        },
        connectors: BTreeMap::new(),
        profiles: BTreeMap::new(),
        proxy_routes: BTreeMap::new(),
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
        .env_remove("AV_TOKEN")
        .env_remove("AV_BASIC_USER")
        .env_remove("AV_BASIC_PASSWORD");
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
    bail!("not logged in; run `av login` or set AV_TOKEN")
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
    fn profile_child_does_not_inherit_wrapper_credentials() {
        let command = profile_command(
            OsString::from("example"),
            vec![OsString::from("--flag")],
            BTreeMap::from([
                ("PROFILE_SECRET".to_owned(), "value".to_owned()),
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

        assert_eq!(envs.get(&OsString::from("AV_TOKEN")), Some(&None));
        assert_eq!(envs.get(&OsString::from("AV_BASIC_USER")), Some(&None));
        assert_eq!(envs.get(&OsString::from("AV_BASIC_PASSWORD")), Some(&None));
        assert_eq!(
            envs.get(&OsString::from("PROFILE_SECRET")),
            Some(&Some(OsString::from("value")))
        );
    }
}
