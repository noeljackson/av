use std::{
    collections::BTreeMap,
    ffi::OsString,
    path::PathBuf,
    process::{Command as ProcessCommand, ExitCode},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use av::{
    config::{Config, PublicAuthConfig},
    keyring, server,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::{CommandFactory, Parser, Subcommand};
use reqwest::{Client, StatusCode, header};
use serde::Deserialize;
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
    /// An unknown first word is treated as a profile: av codewire-dev -- cargo test.
    #[command(external_subcommand)]
    Profile(Vec<OsString>),
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

#[derive(Deserialize)]
struct ProfileSummary {
    name: String,
    environment: String,
    path: String,
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
        Some(Command::Profile(arguments)) => run_profile(&cli.api_url, arguments).await,
        None => {
            Cli::command().print_help()?;
            println!();
            Ok(2)
        }
    }
}

async fn login(api_url: &str) -> Result<()> {
    let client = client(api_url)?;
    let auth: PublicAuthConfig = client
        .get(format!("{}/v1/auth/config", api_url.trim_end_matches('/')))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let device_endpoint = auth
        .device_authorization_endpoint
        .context("the configured OIDC client does not expose device authorization")?;
    let token_endpoint = auth
        .token_endpoint
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
            .post(&token_endpoint)
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
    let response = authenticated_get(api_url, "/v1/profiles").await?;
    let profiles: Vec<ProfileSummary> = response.json().await?;
    for profile in profiles {
        println!(
            "{}\t{}\t{}",
            profile.name, profile.environment, profile.path
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
    let path = format!("/v1/profiles/{profile}/secrets");
    let secrets: BTreeMap<String, String> = authenticated_get(api_url, &path).await?.json().await?;
    for key in secrets.keys() {
        if !valid_env_name(key) {
            bail!("profile contains a key that is not a valid environment variable: {key}");
        }
    }
    let executable = arguments.remove(0);
    let status = ProcessCommand::new(executable)
        .args(arguments)
        .envs(secrets)
        .status()
        .context("start child process")?;
    Ok(status.code().unwrap_or(1).clamp(0, 255) as u8)
}

async fn authenticated_get(api_url: &str, path: &str) -> Result<reqwest::Response> {
    let client = client(api_url)?;
    let mut request = client.get(format!("{}{}", api_url.trim_end_matches('/'), path));
    if let Ok(token) = std::env::var("AV_TOKEN") {
        request = request.bearer_auth(token);
    } else if let (Ok(username), Ok(password)) = (
        std::env::var("AV_BASIC_USER"),
        std::env::var("AV_BASIC_PASSWORD"),
    ) {
        request = request.header(
            header::AUTHORIZATION,
            format!(
                "Basic {}",
                STANDARD.encode(format!("{username}:{password}"))
            ),
        );
    } else if let Some(token) = keyring::load()? {
        request = request.bearer_auth(token);
    } else {
        bail!("not logged in; run `av login` or set AV_TOKEN");
    }
    let response = request.send().await?;
    if response.status() == StatusCode::UNAUTHORIZED {
        bail!("session is unauthorized or expired; run `av login`");
    }
    Ok(response.error_for_status()?)
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
        let cli = Cli::try_parse_from(["av", "codewire-dev", "--", "cargo", "test"]).unwrap();
        let Some(Command::Profile(arguments)) = cli.command else {
            panic!("expected profile command");
        };
        assert_eq!(arguments[0], OsString::from("codewire-dev"));
        assert_eq!(arguments[1], OsString::from("--"));
        assert_eq!(arguments[2], OsString::from("cargo"));
        assert_eq!(arguments[3], OsString::from("test"));
    }
}
