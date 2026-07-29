//! Managed-mode persistence. AV stores policy metadata and audit records here,
//! never connector credentials or fetched secret values.

use std::{
    path::Path,
    str::FromStr,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::{
    PgPool, SqlitePool,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use tokio::time::MissedTickBehavior;
use zeroize::Zeroize;
use zeroize::Zeroizing;

use crate::config::{ManagedConfig, ManagedPostgresConfig, ManagedPostgresSslMode};

#[derive(Clone)]
pub enum Store {
    Postgres(ReloadablePostgres),
    Sqlite(SqlitePool),
}

#[derive(Clone)]
pub struct ReloadablePostgres {
    current: Arc<RwLock<PgPool>>,
    credential_fingerprint: Arc<RwLock<Option<[u8; 32]>>>,
    generation: Arc<AtomicU64>,
}

impl ReloadablePostgres {
    fn new(pool: PgPool, credential_fingerprint: Option<[u8; 32]>) -> Self {
        Self {
            current: Arc::new(RwLock::new(pool)),
            credential_fingerprint: Arc::new(RwLock::new(credential_fingerprint)),
            generation: Arc::new(AtomicU64::new(1)),
        }
    }

    fn pool(&self) -> PgPool {
        self.current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn swap(&self, replacement: PgPool) -> PgPool {
        let mut current = self
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::mem::replace(&mut *current, replacement)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DatabaseCredentials {
    username: String,
    password: String,
}

impl Drop for DatabaseCredentials {
    fn drop(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BasicUser {
    pub username: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Agent {
    pub name: String,
    pub enabled: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PrincipalRole {
    Owner,
    Operator,
    Auditor,
    #[default]
    User,
}

impl PrincipalRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Operator => "operator",
            Self::Auditor => "auditor",
            Self::User => "user",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "owner" => Ok(Self::Owner),
            "operator" => Ok(Self::Operator),
            "auditor" => Ok(Self::Auditor),
            "user" => Ok(Self::User),
            _ => bail!("invalid principal role"),
        }
    }

    pub fn can_operate(self) -> bool {
        matches!(self, Self::Owner | Self::Operator)
    }

    pub fn can_audit(self) -> bool {
        matches!(self, Self::Owner | Self::Auditor)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrincipalRoleBinding {
    pub subject: String,
    pub role: PrincipalRole,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileGrant {
    pub profile: String,
    pub subject: String,
    pub mode: GrantMode,
    pub expires_unix_seconds: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantMode {
    Both,
    Proxy,
    Environment,
}

impl GrantMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Both => "both",
            Self::Proxy => "proxy",
            Self::Environment => "environment",
        }
    }

    fn from_database(value: &str) -> Result<Self> {
        match value {
            "both" => Ok(Self::Both),
            "proxy" => Ok(Self::Proxy),
            "environment" => Ok(Self::Environment),
            _ => bail!("managed store contains an invalid grant mode"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    pub created_unix_seconds: i64,
    pub actor: String,
    pub action: String,
    pub profile: Option<String>,
    pub route: Option<String>,
    pub executable_basename: Option<String>,
}

/// Metadata for an active transparent-proxy session. The random bearer
/// capability is deliberately absent: the database stores only its SHA-256
/// digest, so a database read cannot be replayed as proxy authentication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxySession {
    pub session_id: String,
    pub subject: String,
    pub profile: String,
    pub expires_unix_seconds: i64,
}

type AuditRow = (
    i64,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
);

type ProxySessionRow = (String, String, String, i64);

impl Store {
    pub async fn connect(managed: &ManagedConfig) -> Result<Self> {
        let store = if !managed.database_credentials_file.is_empty() {
            let (pool, fingerprint) = connect_postgres_credentials(managed)
                .await
                .context("connect managed PostgreSQL database")?;
            Self::Postgres(ReloadablePostgres::new(pool, Some(fingerprint)))
        } else {
            let database_url = read_database_url(&managed.database_url_file)?;
            if database_url.starts_with("postgres://") || database_url.starts_with("postgresql://")
            {
                let pool = PgPoolOptions::new()
                    .max_connections(8)
                    .acquire_timeout(Duration::from_secs(10))
                    .connect(&database_url)
                    .await
                    .context("connect managed PostgreSQL database")?;
                Self::Postgres(ReloadablePostgres::new(pool, None))
            } else if database_url.starts_with("sqlite:") {
                let options = SqliteConnectOptions::from_str(&database_url)
                    .context("parse managed SQLite database URL")?
                    .create_if_missing(true)
                    .foreign_keys(true);
                Self::Sqlite(
                    SqlitePoolOptions::new()
                        .max_connections(1)
                        .acquire_timeout(Duration::from_secs(10))
                        .connect_with(options)
                        .await
                        .context("connect managed SQLite database")?,
                )
            } else {
                bail!("managed database URL must use postgres://, postgresql://, or sqlite:");
            }
        };
        store.migrate().await?;
        if !managed.initial_owner_oidc_subject.is_empty() {
            store
                .bootstrap_owner(&managed.initial_owner_oidc_subject)
                .await?;
        }
        if managed.database_reload_interval_seconds > 0 {
            let Self::Postgres(database) = &store else {
                bail!("managed database hot reload is supported only for PostgreSQL");
            };
            spawn_postgres_credential_reloader(
                database.clone(),
                managed.clone(),
                Duration::from_secs(managed.database_reload_interval_seconds),
            );
        }
        Ok(store)
    }

    pub async fn health_check(&self) -> Result<()> {
        match self {
            Self::Postgres(database) => {
                sqlx::query("SELECT 1")
                    .execute(&database.pool())
                    .await
                    .context("check PostgreSQL control-plane health")?;
            }
            Self::Sqlite(database) => {
                sqlx::query("SELECT 1")
                    .execute(database)
                    .await
                    .context("check SQLite control-plane health")?;
            }
        }
        Ok(())
    }

    pub async fn is_owner(&self, subject: &str) -> Result<bool> {
        Ok(self.principal_role(subject).await? == PrincipalRole::Owner)
    }

    pub async fn principal_role(&self, subject: &str) -> Result<PrincipalRole> {
        let role: Option<String> = match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                sqlx::query_scalar("SELECT role FROM av_principal_roles WHERE subject = $1")
                    .bind(subject)
                    .fetch_optional(&pool)
                    .await?
            }
            Self::Sqlite(pool) => {
                sqlx::query_scalar("SELECT role FROM av_principal_roles WHERE subject = ?")
                    .bind(subject)
                    .fetch_optional(pool)
                    .await?
            }
        };
        role.map(|role| PrincipalRole::parse(&role))
            .transpose()
            .map(Option::unwrap_or_default)
    }

    pub async fn list_principal_roles(&self) -> Result<Vec<PrincipalRoleBinding>> {
        let rows: Vec<(String, String)> = match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                sqlx::query_as("SELECT subject, role FROM av_principal_roles ORDER BY subject")
                    .fetch_all(&pool)
                    .await?
            }
            Self::Sqlite(pool) => {
                sqlx::query_as("SELECT subject, role FROM av_principal_roles ORDER BY subject")
                    .fetch_all(pool)
                    .await?
            }
        };
        rows.into_iter()
            .map(|(subject, role)| {
                Ok(PrincipalRoleBinding {
                    subject,
                    role: PrincipalRole::parse(&role)?,
                })
            })
            .collect()
    }

    pub async fn set_principal_role(&self, subject: &str, role: PrincipalRole) -> Result<()> {
        if subject.is_empty() || subject.len() > 1024 || subject.chars().any(char::is_control) {
            bail!("principal subject is invalid");
        }
        match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                let mut transaction = pool.begin().await?;
                let current: Option<String> =
                    sqlx::query_scalar("SELECT role FROM av_principal_roles WHERE subject = $1")
                        .bind(subject)
                        .fetch_optional(&mut *transaction)
                        .await?;
                if current.as_deref() == Some("owner") && role != PrincipalRole::Owner {
                    let owners: i64 = sqlx::query_scalar(
                        "SELECT COUNT(*) FROM av_principal_roles WHERE role = 'owner'",
                    )
                    .fetch_one(&mut *transaction)
                    .await?;
                    if owners <= 1 {
                        bail!("cannot remove the last owner");
                    }
                }
                sqlx::query(
                    "INSERT INTO av_principal_roles (subject, role) VALUES ($1, $2) \
                     ON CONFLICT (subject) DO UPDATE SET role = EXCLUDED.role",
                )
                .bind(subject)
                .bind(role.as_str())
                .execute(&mut *transaction)
                .await?;
                if role == PrincipalRole::Owner {
                    sqlx::query(
                        "INSERT INTO av_owners (subject) VALUES ($1) \
                         ON CONFLICT (subject) DO NOTHING",
                    )
                    .bind(subject)
                    .execute(&mut *transaction)
                    .await?;
                } else {
                    sqlx::query("DELETE FROM av_owners WHERE subject = $1")
                        .bind(subject)
                        .execute(&mut *transaction)
                        .await?;
                }
                transaction.commit().await?;
            }
            Self::Sqlite(pool) => {
                let mut transaction = pool.begin().await?;
                let current: Option<String> =
                    sqlx::query_scalar("SELECT role FROM av_principal_roles WHERE subject = ?")
                        .bind(subject)
                        .fetch_optional(&mut *transaction)
                        .await?;
                if current.as_deref() == Some("owner") && role != PrincipalRole::Owner {
                    let owners: i64 = sqlx::query_scalar(
                        "SELECT COUNT(*) FROM av_principal_roles WHERE role = 'owner'",
                    )
                    .fetch_one(&mut *transaction)
                    .await?;
                    if owners <= 1 {
                        bail!("cannot remove the last owner");
                    }
                }
                sqlx::query(
                    "INSERT INTO av_principal_roles (subject, role) VALUES (?, ?) \
                     ON CONFLICT (subject) DO UPDATE SET role = excluded.role",
                )
                .bind(subject)
                .bind(role.as_str())
                .execute(&mut *transaction)
                .await?;
                if role == PrincipalRole::Owner {
                    sqlx::query(
                        "INSERT INTO av_owners (subject) VALUES (?) \
                         ON CONFLICT (subject) DO NOTHING",
                    )
                    .bind(subject)
                    .execute(&mut *transaction)
                    .await?;
                } else {
                    sqlx::query("DELETE FROM av_owners WHERE subject = ?")
                        .bind(subject)
                        .execute(&mut *transaction)
                        .await?;
                }
                transaction.commit().await?;
            }
        }
        Ok(())
    }

    pub async fn basic_password_hash(&self, username: &str) -> Result<Option<String>> {
        match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                sqlx::query_scalar(
                    "SELECT password_hash FROM av_basic_users WHERE username = $1 AND enabled = TRUE",
                )
                .bind(username)
                .fetch_optional(&pool)
                .await
                .context("read managed Basic user")
            }
            Self::Sqlite(pool) => sqlx::query_scalar(
                "SELECT password_hash FROM av_basic_users WHERE username = ? AND enabled = TRUE",
            )
            .bind(username)
            .fetch_optional(pool)
            .await
            .context("read managed Basic user"),
        }
    }

    pub async fn list_basic_users(&self) -> Result<Vec<BasicUser>> {
        let rows: Vec<(String, bool)> = match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                sqlx::query_as("SELECT username, enabled FROM av_basic_users ORDER BY username")
                    .fetch_all(&pool)
                    .await?
            }
            Self::Sqlite(pool) => {
                sqlx::query_as("SELECT username, enabled FROM av_basic_users ORDER BY username")
                    .fetch_all(pool)
                    .await?
            }
        };
        Ok(rows
            .into_iter()
            .map(|(username, enabled)| BasicUser { username, enabled })
            .collect())
    }

    pub async fn upsert_basic_user(&self, username: &str, password_hash: &str) -> Result<()> {
        match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                sqlx::query(
                    "INSERT INTO av_basic_users (username, password_hash, enabled) VALUES ($1, $2, TRUE) \
                     ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash, enabled = TRUE",
                )
                .bind(username)
                .bind(password_hash)
                .execute(&pool)
                .await?;
            }
            Self::Sqlite(pool) => {
                sqlx::query(
                    "INSERT INTO av_basic_users (username, password_hash, enabled) VALUES (?, ?, TRUE) \
                     ON CONFLICT (username) DO UPDATE SET password_hash = excluded.password_hash, enabled = TRUE",
                )
                .bind(username)
                .bind(password_hash)
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }

    pub async fn set_basic_user_enabled(&self, username: &str, enabled: bool) -> Result<bool> {
        let affected = match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                sqlx::query("UPDATE av_basic_users SET enabled = $1 WHERE username = $2")
                    .bind(enabled)
                    .bind(username)
                    .execute(&pool)
                    .await?
                    .rows_affected()
            }
            Self::Sqlite(pool) => {
                sqlx::query("UPDATE av_basic_users SET enabled = ? WHERE username = ?")
                    .bind(enabled)
                    .bind(username)
                    .execute(pool)
                    .await?
                    .rows_affected()
            }
        };
        Ok(affected == 1)
    }

    pub async fn list_agents(&self) -> Result<Vec<Agent>> {
        let rows: Vec<(String, bool)> = match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                sqlx::query_as("SELECT name, enabled FROM av_agents ORDER BY name")
                    .fetch_all(&pool)
                    .await?
            }
            Self::Sqlite(pool) => {
                sqlx::query_as("SELECT name, enabled FROM av_agents ORDER BY name")
                    .fetch_all(pool)
                    .await?
            }
        };
        Ok(rows
            .into_iter()
            .map(|(name, enabled)| Agent { name, enabled })
            .collect())
    }

    pub async fn create_agent(&self, name: &str, token_hash: &[u8]) -> Result<()> {
        validate_agent_token(name, token_hash)?;
        match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                sqlx::query(
                    "INSERT INTO av_agents (name, token_hash, enabled) VALUES ($1, $2, TRUE)",
                )
                .bind(name)
                .bind(token_hash)
                .execute(&pool)
                .await?;
            }
            Self::Sqlite(pool) => {
                sqlx::query(
                    "INSERT INTO av_agents (name, token_hash, enabled) VALUES (?, ?, TRUE)",
                )
                .bind(name)
                .bind(token_hash)
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }

    pub async fn rotate_agent_token(&self, name: &str, token_hash: &[u8]) -> Result<bool> {
        validate_agent_token(name, token_hash)?;
        let subject = format!("agent:{name}");
        let affected = match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                let mut transaction = pool.begin().await?;
                let affected = sqlx::query(
                    "UPDATE av_agents SET token_hash = $1, enabled = TRUE WHERE name = $2",
                )
                .bind(token_hash)
                .bind(name)
                .execute(&mut *transaction)
                .await?
                .rows_affected();
                sqlx::query(
                    "UPDATE av_proxy_sessions SET revoked = TRUE \
                     WHERE subject = $1 AND revoked = FALSE",
                )
                .bind(&subject)
                .execute(&mut *transaction)
                .await?;
                transaction.commit().await?;
                affected
            }
            Self::Sqlite(pool) => {
                let mut transaction = pool.begin().await?;
                let affected = sqlx::query(
                    "UPDATE av_agents SET token_hash = ?, enabled = TRUE WHERE name = ?",
                )
                .bind(token_hash)
                .bind(name)
                .execute(&mut *transaction)
                .await?
                .rows_affected();
                sqlx::query(
                    "UPDATE av_proxy_sessions SET revoked = TRUE \
                     WHERE subject = ? AND revoked = FALSE",
                )
                .bind(&subject)
                .execute(&mut *transaction)
                .await?;
                transaction.commit().await?;
                affected
            }
        };
        Ok(affected == 1)
    }

    pub async fn set_agent_enabled(&self, name: &str, enabled: bool) -> Result<bool> {
        let subject = format!("agent:{name}");
        let affected = match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                let mut transaction = pool.begin().await?;
                let affected = sqlx::query("UPDATE av_agents SET enabled = $1 WHERE name = $2")
                    .bind(enabled)
                    .bind(name)
                    .execute(&mut *transaction)
                    .await?
                    .rows_affected();
                if !enabled {
                    sqlx::query(
                        "UPDATE av_proxy_sessions SET revoked = TRUE \
                         WHERE subject = $1 AND revoked = FALSE",
                    )
                    .bind(&subject)
                    .execute(&mut *transaction)
                    .await?;
                }
                transaction.commit().await?;
                affected
            }
            Self::Sqlite(pool) => {
                let mut transaction = pool.begin().await?;
                let affected = sqlx::query("UPDATE av_agents SET enabled = ? WHERE name = ?")
                    .bind(enabled)
                    .bind(name)
                    .execute(&mut *transaction)
                    .await?
                    .rows_affected();
                if !enabled {
                    sqlx::query(
                        "UPDATE av_proxy_sessions SET revoked = TRUE \
                         WHERE subject = ? AND revoked = FALSE",
                    )
                    .bind(&subject)
                    .execute(&mut *transaction)
                    .await?;
                }
                transaction.commit().await?;
                affected
            }
        };
        Ok(affected == 1)
    }

    pub async fn delete_agent(&self, name: &str) -> Result<bool> {
        let subject = format!("agent:{name}");
        let affected = match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                let mut transaction = pool.begin().await?;
                sqlx::query("DELETE FROM av_capability_grants WHERE subject = $1")
                    .bind(&subject)
                    .execute(&mut *transaction)
                    .await?;
                sqlx::query(
                    "UPDATE av_proxy_sessions SET revoked = TRUE \
                     WHERE subject = $1 AND revoked = FALSE",
                )
                .bind(&subject)
                .execute(&mut *transaction)
                .await?;
                let affected = sqlx::query("DELETE FROM av_agents WHERE name = $1")
                    .bind(name)
                    .execute(&mut *transaction)
                    .await?
                    .rows_affected();
                transaction.commit().await?;
                affected
            }
            Self::Sqlite(pool) => {
                let mut transaction = pool.begin().await?;
                sqlx::query("DELETE FROM av_capability_grants WHERE subject = ?")
                    .bind(&subject)
                    .execute(&mut *transaction)
                    .await?;
                sqlx::query(
                    "UPDATE av_proxy_sessions SET revoked = TRUE \
                     WHERE subject = ? AND revoked = FALSE",
                )
                .bind(&subject)
                .execute(&mut *transaction)
                .await?;
                let affected = sqlx::query("DELETE FROM av_agents WHERE name = ?")
                    .bind(name)
                    .execute(&mut *transaction)
                    .await?
                    .rows_affected();
                transaction.commit().await?;
                affected
            }
        };
        Ok(affected == 1)
    }

    pub async fn agent_for_token_hash(&self, token_hash: &[u8]) -> Result<Option<String>> {
        if token_hash.len() != 32 {
            return Ok(None);
        }
        match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                sqlx::query_scalar(
                    "SELECT name FROM av_agents WHERE token_hash = $1 AND enabled = TRUE",
                )
                .bind(token_hash)
                .fetch_optional(&pool)
                .await
                .context("authenticate managed agent")
            }
            Self::Sqlite(pool) => sqlx::query_scalar(
                "SELECT name FROM av_agents WHERE token_hash = ? AND enabled = TRUE",
            )
            .bind(token_hash)
            .fetch_optional(pool)
            .await
            .context("authenticate managed agent"),
        }
    }

    pub async fn profile_allowed(&self, subject: &str, profile: &str) -> Result<bool> {
        let now = now_unix_seconds()?;
        let count: i64 = match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                sqlx::query_scalar(
                    "SELECT COUNT(*) FROM av_capability_grants \
                     WHERE subject = $1 AND profile = $2 \
                     AND (expires_unix_seconds IS NULL OR expires_unix_seconds > $3)",
                )
                .bind(subject)
                .bind(profile)
                .bind(now)
                .fetch_one(&pool)
                .await?
            }
            Self::Sqlite(pool) => {
                sqlx::query_scalar(
                    "SELECT COUNT(*) FROM av_capability_grants \
                     WHERE subject = ? AND profile = ? \
                     AND (expires_unix_seconds IS NULL OR expires_unix_seconds > ?)",
                )
                .bind(subject)
                .bind(profile)
                .bind(now)
                .fetch_one(pool)
                .await?
            }
        };
        Ok(count > 0)
    }

    pub async fn profile_allowed_for(
        &self,
        subject: &str,
        profile: &str,
        mode: GrantMode,
    ) -> Result<bool> {
        let now = now_unix_seconds()?;
        let count: i64 = match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                sqlx::query_scalar(
                    "SELECT COUNT(*) FROM av_capability_grants \
                     WHERE subject = $1 AND profile = $2 \
                     AND (expires_unix_seconds IS NULL OR expires_unix_seconds > $3) \
                     AND (mode = 'both' OR mode = $4)",
                )
                .bind(subject)
                .bind(profile)
                .bind(now)
                .bind(mode.as_str())
                .fetch_one(&pool)
                .await?
            }
            Self::Sqlite(pool) => {
                sqlx::query_scalar(
                    "SELECT COUNT(*) FROM av_capability_grants \
                     WHERE subject = ? AND profile = ? \
                     AND (expires_unix_seconds IS NULL OR expires_unix_seconds > ?) \
                     AND (mode = 'both' OR mode = ?)",
                )
                .bind(subject)
                .bind(profile)
                .bind(now)
                .bind(mode.as_str())
                .fetch_one(pool)
                .await?
            }
        };
        Ok(count > 0)
    }

    pub async fn list_allowed_profiles(&self, subject: &str) -> Result<Vec<String>> {
        let now = now_unix_seconds()?;
        match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                sqlx::query_scalar(
                    "SELECT profile FROM av_capability_grants \
                     WHERE subject = $1 \
                     AND (expires_unix_seconds IS NULL OR expires_unix_seconds > $2) \
                     ORDER BY profile",
                )
                .bind(subject)
                .bind(now)
                .fetch_all(&pool)
                .await
                .context("list managed profile grants")
            }
            Self::Sqlite(pool) => sqlx::query_scalar(
                "SELECT profile FROM av_capability_grants \
                 WHERE subject = ? \
                 AND (expires_unix_seconds IS NULL OR expires_unix_seconds > ?) \
                 ORDER BY profile",
            )
            .bind(subject)
            .bind(now)
            .fetch_all(pool)
            .await
            .context("list managed profile grants"),
        }
    }

    pub async fn list_allowed_profiles_for(
        &self,
        subject: &str,
        mode: GrantMode,
    ) -> Result<Vec<String>> {
        let now = now_unix_seconds()?;
        match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                sqlx::query_scalar(
                    "SELECT profile FROM av_capability_grants \
                     WHERE subject = $1 \
                     AND (expires_unix_seconds IS NULL OR expires_unix_seconds > $2) \
                     AND (mode = 'both' OR mode = $3) ORDER BY profile",
                )
                .bind(subject)
                .bind(now)
                .bind(mode.as_str())
                .fetch_all(&pool)
                .await
                .context("list managed profile grants")
            }
            Self::Sqlite(pool) => sqlx::query_scalar(
                "SELECT profile FROM av_capability_grants \
                 WHERE subject = ? \
                 AND (expires_unix_seconds IS NULL OR expires_unix_seconds > ?) \
                 AND (mode = 'both' OR mode = ?) ORDER BY profile",
            )
            .bind(subject)
            .bind(now)
            .bind(mode.as_str())
            .fetch_all(pool)
            .await
            .context("list managed profile grants"),
        }
    }

    pub async fn list_profile_grants(&self, profile: &str) -> Result<Vec<ProfileGrant>> {
        let rows: Vec<(String, String, Option<i64>)> = match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                sqlx::query_as(
                    "SELECT subject, mode, expires_unix_seconds FROM av_capability_grants \
                     WHERE profile = $1 ORDER BY subject",
                )
                .bind(profile)
                .fetch_all(&pool)
                .await?
            }
            Self::Sqlite(pool) => {
                sqlx::query_as(
                    "SELECT subject, mode, expires_unix_seconds FROM av_capability_grants \
                     WHERE profile = ? ORDER BY subject",
                )
                .bind(profile)
                .fetch_all(pool)
                .await?
            }
        };
        rows.into_iter()
            .map(|(subject, mode, expires_unix_seconds)| {
                Ok(ProfileGrant {
                    profile: profile.into(),
                    subject,
                    mode: GrantMode::from_database(&mode)?,
                    expires_unix_seconds,
                })
            })
            .collect()
    }

    pub async fn list_subject_grants(&self, subject: &str) -> Result<Vec<ProfileGrant>> {
        let rows: Vec<(String, String, Option<i64>)> = match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                sqlx::query_as(
                    "SELECT profile, mode, expires_unix_seconds FROM av_capability_grants \
                     WHERE subject = $1 ORDER BY profile",
                )
                .bind(subject)
                .fetch_all(&pool)
                .await?
            }
            Self::Sqlite(pool) => {
                sqlx::query_as(
                    "SELECT profile, mode, expires_unix_seconds FROM av_capability_grants \
                     WHERE subject = ? ORDER BY profile",
                )
                .bind(subject)
                .fetch_all(pool)
                .await?
            }
        };
        rows.into_iter()
            .map(|(profile, mode, expires_unix_seconds)| {
                Ok(ProfileGrant {
                    profile,
                    subject: subject.into(),
                    mode: GrantMode::from_database(&mode)?,
                    expires_unix_seconds,
                })
            })
            .collect()
    }

    pub async fn grant_profile(&self, subject: &str, profile: &str) -> Result<()> {
        self.grant_profile_mode(subject, profile, GrantMode::Both, None)
            .await
    }

    pub async fn grant_profile_mode(
        &self,
        subject: &str,
        profile: &str,
        mode: GrantMode,
        expires_unix_seconds: Option<i64>,
    ) -> Result<()> {
        if let Some(expires) = expires_unix_seconds
            && expires <= now_unix_seconds()?
        {
            bail!("profile grant expiry must be in the future");
        }
        match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                sqlx::query(
                    "INSERT INTO av_capability_grants \
                     (subject, profile, mode, expires_unix_seconds) VALUES ($1, $2, $3, $4) \
                     ON CONFLICT (subject, profile) DO UPDATE SET \
                     mode = EXCLUDED.mode, expires_unix_seconds = EXCLUDED.expires_unix_seconds",
                )
                .bind(subject)
                .bind(profile)
                .bind(mode.as_str())
                .bind(expires_unix_seconds)
                .execute(&pool)
                .await?;
            }
            Self::Sqlite(pool) => {
                sqlx::query(
                    "INSERT INTO av_capability_grants \
                     (subject, profile, mode, expires_unix_seconds) VALUES (?, ?, ?, ?) \
                     ON CONFLICT (subject, profile) DO UPDATE SET \
                     mode = excluded.mode, expires_unix_seconds = excluded.expires_unix_seconds",
                )
                .bind(subject)
                .bind(profile)
                .bind(mode.as_str())
                .bind(expires_unix_seconds)
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }

    pub async fn revoke_profile(&self, subject: &str, profile: &str) -> Result<bool> {
        let affected = match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                sqlx::query("DELETE FROM av_capability_grants WHERE subject = $1 AND profile = $2")
                    .bind(subject)
                    .bind(profile)
                    .execute(&pool)
                    .await?
                    .rows_affected()
            }
            Self::Sqlite(pool) => {
                sqlx::query("DELETE FROM av_capability_grants WHERE subject = ? AND profile = ?")
                    .bind(subject)
                    .bind(profile)
                    .execute(pool)
                    .await?
                    .rows_affected()
            }
        };
        Ok(affected == 1)
    }

    pub async fn list_audit_events(&self, limit: i64) -> Result<Vec<AuditEvent>> {
        let limit = limit.clamp(1, 500);
        let rows: Vec<AuditRow> = match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                sqlx::query_as(
                    "SELECT created_unix_seconds, actor, action, profile, route, executable_basename \
                         FROM av_audit_events ORDER BY created_unix_seconds DESC LIMIT $1",
                )
                .bind(limit)
                .fetch_all(&pool)
                .await?
            }
            Self::Sqlite(pool) => sqlx::query_as(
                "SELECT created_unix_seconds, actor, action, profile, route, executable_basename \
                     FROM av_audit_events ORDER BY created_unix_seconds DESC LIMIT ?",
            )
            .bind(limit)
            .fetch_all(pool)
            .await?,
        };
        Ok(rows
            .into_iter()
            .map(
                |(created_unix_seconds, actor, action, profile, route, executable_basename)| {
                    AuditEvent {
                        created_unix_seconds,
                        actor,
                        action,
                        profile,
                        route,
                        executable_basename,
                    }
                },
            )
            .collect())
    }

    pub async fn record_audit(
        &self,
        actor: &str,
        action: &str,
        profile: Option<&str>,
        route: Option<&str>,
        executable_basename: Option<&str>,
    ) -> Result<()> {
        let created_unix_seconds = now_unix_seconds()?;
        match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                sqlx::query(
                    "INSERT INTO av_audit_events \
                     (created_unix_seconds, actor, action, profile, route, executable_basename) \
                     VALUES ($1, $2, $3, $4, $5, $6)",
                )
                .bind(created_unix_seconds)
                .bind(actor)
                .bind(action)
                .bind(profile)
                .bind(route)
                .bind(executable_basename)
                .execute(&pool)
                .await
                .context("write managed audit event")?;
            }
            Self::Sqlite(pool) => {
                sqlx::query(
                    "INSERT INTO av_audit_events \
                     (created_unix_seconds, actor, action, profile, route, executable_basename) \
                     VALUES (?, ?, ?, ?, ?, ?)",
                )
                .bind(created_unix_seconds)
                .bind(actor)
                .bind(action)
                .bind(profile)
                .bind(route)
                .bind(executable_basename)
                .execute(pool)
                .await
                .context("write managed audit event")?;
            }
        }
        Ok(())
    }

    /// Persist one short-lived proxy session. `token_hash` must be the 32-byte
    /// SHA-256 digest of a randomly generated bearer capability; raw session
    /// capabilities are never accepted by this persistence layer.
    pub async fn create_proxy_session(
        &self,
        session_id: &str,
        token_hash: &[u8],
        subject: &str,
        profile: &str,
        expires_unix_seconds: i64,
        maximum_expires_unix_seconds: i64,
    ) -> Result<()> {
        validate_proxy_session(
            session_id,
            token_hash,
            subject,
            profile,
            expires_unix_seconds,
            maximum_expires_unix_seconds,
        )?;
        match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                let mut transaction = pool.begin().await?;
                sqlx::query(
                    "INSERT INTO av_proxy_sessions \
                     (session_id, token_hash, subject, profile, expires_unix_seconds, revoked) \
                     VALUES ($1, $2, $3, $4, $5, FALSE)",
                )
                .bind(session_id)
                .bind(token_hash)
                .bind(subject)
                .bind(profile)
                .bind(expires_unix_seconds)
                .execute(&mut *transaction)
                .await
                .context("write proxy session")?;
                sqlx::query(
                    "INSERT INTO av_proxy_session_bounds \
                     (session_id, maximum_expires_unix_seconds) VALUES ($1, $2)",
                )
                .bind(session_id)
                .bind(maximum_expires_unix_seconds)
                .execute(&mut *transaction)
                .await
                .context("write proxy session bound")?;
                transaction.commit().await?;
            }
            Self::Sqlite(pool) => {
                let mut transaction = pool.begin().await?;
                sqlx::query(
                    "INSERT INTO av_proxy_sessions \
                     (session_id, token_hash, subject, profile, expires_unix_seconds, revoked) \
                     VALUES (?, ?, ?, ?, ?, FALSE)",
                )
                .bind(session_id)
                .bind(token_hash)
                .bind(subject)
                .bind(profile)
                .bind(expires_unix_seconds)
                .execute(&mut *transaction)
                .await
                .context("write proxy session")?;
                sqlx::query(
                    "INSERT INTO av_proxy_session_bounds \
                     (session_id, maximum_expires_unix_seconds) VALUES (?, ?)",
                )
                .bind(session_id)
                .bind(maximum_expires_unix_seconds)
                .execute(&mut *transaction)
                .await
                .context("write proxy session bound")?;
                transaction.commit().await?;
            }
        }
        Ok(())
    }

    /// Resolve a valid, unrevoked session by its digest. Expired sessions are
    /// intentionally indistinguishable from unknown sessions to the caller.
    pub async fn active_proxy_session(&self, token_hash: &[u8]) -> Result<Option<ProxySession>> {
        if token_hash.len() != 32 {
            return Ok(None);
        }
        let now = now_unix_seconds()?;
        let row: Option<ProxySessionRow> = match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                sqlx::query_as(
                    "SELECT session_id, subject, profile, expires_unix_seconds \
                 FROM av_proxy_sessions \
                 WHERE token_hash = $1 AND revoked = FALSE AND expires_unix_seconds > $2",
                )
                .bind(token_hash)
                .bind(now)
                .fetch_optional(&pool)
                .await?
            }
            Self::Sqlite(pool) => {
                sqlx::query_as(
                    "SELECT session_id, subject, profile, expires_unix_seconds \
                 FROM av_proxy_sessions \
                 WHERE token_hash = ? AND revoked = FALSE AND expires_unix_seconds > ?",
                )
                .bind(token_hash)
                .bind(now)
                .fetch_optional(pool)
                .await?
            }
        };
        Ok(row.map(
            |(session_id, subject, profile, expires_unix_seconds)| ProxySession {
                session_id,
                subject,
                profile,
                expires_unix_seconds,
            },
        ))
    }

    /// Extend one live session without changing its bearer capability. The
    /// caller is bound to the original subject, and the database-enforced
    /// absolute expiry cannot be exceeded.
    pub async fn renew_proxy_session_for_subject(
        &self,
        session_id: &str,
        subject: &str,
        requested_expires_unix_seconds: i64,
    ) -> Result<Option<ProxySession>> {
        if session_id.is_empty()
            || subject.is_empty()
            || session_id.len() > 256
            || subject.len() > 1024
            || session_id.chars().any(char::is_control)
            || subject.chars().any(char::is_control)
        {
            bail!("proxy session identity is invalid");
        }
        let now = now_unix_seconds()?;
        if requested_expires_unix_seconds <= now {
            bail!("proxy session renewal expiry must be in the future");
        }
        let row: Option<ProxySessionRow> = match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                sqlx::query_as(
                    "UPDATE av_proxy_sessions AS sessions \
                     SET expires_unix_seconds = LEAST($3, bounds.maximum_expires_unix_seconds) \
                     FROM av_proxy_session_bounds AS bounds \
                     WHERE sessions.session_id = $1 \
                       AND sessions.subject = $2 \
                       AND sessions.revoked = FALSE \
                       AND sessions.expires_unix_seconds > $4 \
                       AND bounds.session_id = sessions.session_id \
                       AND bounds.maximum_expires_unix_seconds > $4 \
                     RETURNING sessions.session_id, sessions.subject, sessions.profile, \
                               sessions.expires_unix_seconds",
                )
                .bind(session_id)
                .bind(subject)
                .bind(requested_expires_unix_seconds)
                .bind(now)
                .fetch_optional(&pool)
                .await?
            }
            Self::Sqlite(pool) => {
                sqlx::query_as(
                    "UPDATE av_proxy_sessions \
                     SET expires_unix_seconds = MIN(?, (\
                         SELECT maximum_expires_unix_seconds \
                         FROM av_proxy_session_bounds \
                         WHERE session_id = av_proxy_sessions.session_id\
                     )) \
                     WHERE session_id = ? \
                       AND subject = ? \
                       AND revoked = FALSE \
                       AND expires_unix_seconds > ? \
                       AND EXISTS (\
                         SELECT 1 FROM av_proxy_session_bounds \
                         WHERE session_id = av_proxy_sessions.session_id \
                           AND maximum_expires_unix_seconds > ?\
                       ) \
                     RETURNING session_id, subject, profile, expires_unix_seconds",
                )
                .bind(requested_expires_unix_seconds)
                .bind(session_id)
                .bind(subject)
                .bind(now)
                .bind(now)
                .fetch_optional(pool)
                .await?
            }
        };
        Ok(row.map(
            |(session_id, subject, profile, expires_unix_seconds)| ProxySession {
                session_id,
                subject,
                profile,
                expires_unix_seconds,
            },
        ))
    }

    /// Revocation is idempotent from an operator perspective: a missing or
    /// already-revoked session has the same safe effect and returns `false`.
    pub async fn revoke_proxy_session(&self, session_id: &str) -> Result<bool> {
        let affected = match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                sqlx::query(
                    "UPDATE av_proxy_sessions SET revoked = TRUE WHERE session_id = $1 AND revoked = FALSE",
                )
                .bind(session_id)
                .execute(&pool)
                .await?
                .rows_affected()
            }
            Self::Sqlite(pool) => sqlx::query(
                "UPDATE av_proxy_sessions SET revoked = TRUE WHERE session_id = ? AND revoked = FALSE",
            )
            .bind(session_id)
            .execute(pool)
            .await?
            .rows_affected(),
        };
        Ok(affected == 1)
    }

    /// A session holder may revoke only its own proxy capability. Owner-level
    /// administrative revocation is intentionally a separate control
    /// operation, rather than allowing arbitrary session IDs to be killed by
    /// an authenticated peer.
    pub async fn revoke_proxy_session_for_subject(
        &self,
        session_id: &str,
        subject: &str,
    ) -> Result<bool> {
        let affected = match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                sqlx::query(
                    "UPDATE av_proxy_sessions SET revoked = TRUE \
                     WHERE session_id = $1 AND subject = $2 AND revoked = FALSE",
                )
                .bind(session_id)
                .bind(subject)
                .execute(&pool)
                .await?
                .rows_affected()
            }
            Self::Sqlite(pool) => sqlx::query(
                "UPDATE av_proxy_sessions SET revoked = TRUE \
                 WHERE session_id = ? AND subject = ? AND revoked = FALSE",
            )
            .bind(session_id)
            .bind(subject)
            .execute(pool)
            .await?
            .rows_affected(),
        };
        Ok(affected == 1)
    }

    async fn migrate(&self) -> Result<()> {
        const CREATE_OWNERS: &str = "CREATE TABLE IF NOT EXISTS av_owners (\
            subject TEXT PRIMARY KEY\
        )";
        // The singleton row makes the first-owner bootstrap safe when two AV
        // pods happen to start against an empty shared database at once.
        const CREATE_OWNER_BOOTSTRAP: &str = "CREATE TABLE IF NOT EXISTS av_owner_bootstrap (\
            singleton SMALLINT PRIMARY KEY CHECK (singleton = 1),\
            subject TEXT NOT NULL UNIQUE\
        )";
        const CREATE_PRINCIPAL_ROLES: &str = "CREATE TABLE IF NOT EXISTS av_principal_roles (\
            subject TEXT PRIMARY KEY,\
            role TEXT NOT NULL CHECK (role IN ('owner', 'operator', 'auditor', 'user'))\
        )";
        const MIGRATE_OWNERS: &str = "INSERT INTO av_principal_roles (subject, role) \
             SELECT subject, 'owner' FROM av_owners WHERE TRUE \
             ON CONFLICT (subject) DO UPDATE SET role = 'owner'";
        const CREATE_BASIC_USERS: &str = "CREATE TABLE IF NOT EXISTS av_basic_users (\
            username TEXT PRIMARY KEY,\
            password_hash TEXT NOT NULL,\
            enabled BOOLEAN NOT NULL\
        )";
        const CREATE_AGENTS_POSTGRES: &str = "CREATE TABLE IF NOT EXISTS av_agents (\
            name TEXT PRIMARY KEY,\
            token_hash BYTEA NOT NULL UNIQUE,\
            enabled BOOLEAN NOT NULL\
        )";
        const CREATE_AGENTS_SQLITE: &str = "CREATE TABLE IF NOT EXISTS av_agents (\
            name TEXT PRIMARY KEY,\
            token_hash BLOB NOT NULL UNIQUE,\
            enabled BOOLEAN NOT NULL\
        )";
        const CREATE_PROFILE_GRANTS: &str = "CREATE TABLE IF NOT EXISTS av_profile_grants (\
            subject TEXT NOT NULL,\
            profile TEXT NOT NULL,\
            PRIMARY KEY (subject, profile)\
        )";
        const CREATE_CAPABILITY_GRANTS: &str = "CREATE TABLE IF NOT EXISTS av_capability_grants (\
                subject TEXT NOT NULL,\
                profile TEXT NOT NULL,\
                mode TEXT NOT NULL CHECK (mode IN ('both', 'proxy', 'environment')),\
                expires_unix_seconds BIGINT NULL,\
                PRIMARY KEY (subject, profile)\
            )";
        const MIGRATE_PROFILE_GRANTS: &str = "INSERT INTO av_capability_grants \
             (subject, profile, mode, expires_unix_seconds) \
             SELECT subject, profile, 'both', NULL FROM av_profile_grants WHERE TRUE \
             ON CONFLICT (subject, profile) DO NOTHING";
        const CREATE_AUDIT_EVENTS: &str = "CREATE TABLE IF NOT EXISTS av_audit_events (\
            created_unix_seconds BIGINT NOT NULL,\
            actor TEXT NOT NULL,\
            action TEXT NOT NULL,\
            profile TEXT NULL,\
            route TEXT NULL,\
            executable_basename TEXT NULL\
        )";
        const CREATE_AUDIT_INDEX: &str = "CREATE INDEX IF NOT EXISTS av_audit_events_created_idx \
            ON av_audit_events (created_unix_seconds)";
        const CREATE_PROXY_SESSIONS_POSTGRES: &str = "CREATE TABLE IF NOT EXISTS av_proxy_sessions (\
            session_id TEXT PRIMARY KEY,\
            token_hash BYTEA NOT NULL UNIQUE,\
            subject TEXT NOT NULL,\
            profile TEXT NOT NULL,\
            expires_unix_seconds BIGINT NOT NULL,\
            revoked BOOLEAN NOT NULL\
        )";
        const CREATE_PROXY_SESSIONS_SQLITE: &str = "CREATE TABLE IF NOT EXISTS av_proxy_sessions (\
            session_id TEXT PRIMARY KEY,\
            token_hash BLOB NOT NULL UNIQUE,\
            subject TEXT NOT NULL,\
            profile TEXT NOT NULL,\
            expires_unix_seconds BIGINT NOT NULL,\
            revoked BOOLEAN NOT NULL\
        )";
        const CREATE_PROXY_SESSIONS_TOKEN_INDEX: &str = "CREATE INDEX IF NOT EXISTS av_proxy_sessions_token_idx \
            ON av_proxy_sessions (token_hash)";
        const CREATE_PROXY_SESSION_BOUNDS: &str = "CREATE TABLE IF NOT EXISTS av_proxy_session_bounds (\
                session_id TEXT PRIMARY KEY,\
                maximum_expires_unix_seconds BIGINT NOT NULL\
            )";
        match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                sqlx::query(CREATE_OWNERS).execute(&pool).await?;
                sqlx::query(CREATE_OWNER_BOOTSTRAP).execute(&pool).await?;
                sqlx::query(CREATE_PRINCIPAL_ROLES).execute(&pool).await?;
                sqlx::query(MIGRATE_OWNERS).execute(&pool).await?;
                sqlx::query(CREATE_BASIC_USERS).execute(&pool).await?;
                sqlx::query(CREATE_AGENTS_POSTGRES).execute(&pool).await?;
                sqlx::query(CREATE_PROFILE_GRANTS).execute(&pool).await?;
                sqlx::query(CREATE_CAPABILITY_GRANTS).execute(&pool).await?;
                sqlx::query(MIGRATE_PROFILE_GRANTS).execute(&pool).await?;
                sqlx::query(CREATE_AUDIT_EVENTS).execute(&pool).await?;
                sqlx::query(CREATE_AUDIT_INDEX).execute(&pool).await?;
                sqlx::query(CREATE_PROXY_SESSIONS_POSTGRES)
                    .execute(&pool)
                    .await?;
                sqlx::query(CREATE_PROXY_SESSIONS_TOKEN_INDEX)
                    .execute(&pool)
                    .await?;
                sqlx::query(CREATE_PROXY_SESSION_BOUNDS)
                    .execute(&pool)
                    .await?;
            }
            Self::Sqlite(pool) => {
                sqlx::query(CREATE_OWNERS).execute(pool).await?;
                sqlx::query(CREATE_OWNER_BOOTSTRAP).execute(pool).await?;
                sqlx::query(CREATE_PRINCIPAL_ROLES).execute(pool).await?;
                sqlx::query(MIGRATE_OWNERS).execute(pool).await?;
                sqlx::query(CREATE_BASIC_USERS).execute(pool).await?;
                sqlx::query(CREATE_AGENTS_SQLITE).execute(pool).await?;
                sqlx::query(CREATE_PROFILE_GRANTS).execute(pool).await?;
                sqlx::query(CREATE_CAPABILITY_GRANTS).execute(pool).await?;
                sqlx::query(MIGRATE_PROFILE_GRANTS).execute(pool).await?;
                sqlx::query(CREATE_AUDIT_EVENTS).execute(pool).await?;
                sqlx::query(CREATE_AUDIT_INDEX).execute(pool).await?;
                sqlx::query(CREATE_PROXY_SESSIONS_SQLITE)
                    .execute(pool)
                    .await?;
                sqlx::query(CREATE_PROXY_SESSIONS_TOKEN_INDEX)
                    .execute(pool)
                    .await?;
                sqlx::query(CREATE_PROXY_SESSION_BOUNDS)
                    .execute(pool)
                    .await?;
            }
        }
        Ok(())
    }

    async fn bootstrap_owner(&self, subject: &str) -> Result<()> {
        match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                sqlx::query(
                    "WITH inserted AS (\
                        INSERT INTO av_owner_bootstrap (singleton, subject) VALUES (1, $1) \
                        ON CONFLICT (singleton) DO NOTHING RETURNING subject\
                     ) \
                     INSERT INTO av_owners (subject) SELECT subject FROM inserted \
                     ON CONFLICT (subject) DO NOTHING",
                )
                .bind(subject)
                .execute(&pool)
                .await?;
                sqlx::query(
                    "INSERT INTO av_principal_roles (subject, role) \
                     SELECT subject, 'owner' FROM av_owners WHERE subject = $1 \
                     ON CONFLICT (subject) DO UPDATE SET role = 'owner'",
                )
                .bind(subject)
                .execute(&pool)
                .await?;
            }
            Self::Sqlite(pool) => {
                let inserted = sqlx::query(
                    "INSERT INTO av_owner_bootstrap (singleton, subject) VALUES (1, ?) \
                     ON CONFLICT (singleton) DO NOTHING",
                )
                .bind(subject)
                .execute(pool)
                .await?
                .rows_affected();
                if inserted == 1 {
                    sqlx::query("INSERT INTO av_owners (subject) VALUES (?) ON CONFLICT (subject) DO NOTHING")
                        .bind(subject)
                        .execute(pool)
                        .await?;
                }
                sqlx::query(
                    "INSERT INTO av_principal_roles (subject, role) \
                     SELECT subject, 'owner' FROM av_owners WHERE subject = ? \
                     ON CONFLICT (subject) DO UPDATE SET role = 'owner'",
                )
                .bind(subject)
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }
}

async fn connect_postgres_credentials(managed: &ManagedConfig) -> Result<(PgPool, [u8; 32])> {
    let postgres = managed
        .postgres
        .as_ref()
        .context("managed PostgreSQL connection metadata is missing")?;
    let (credentials, fingerprint) = read_database_credentials(&managed.database_credentials_file)?;
    let pool = connect_postgres_with_credentials(postgres, &credentials).await?;
    Ok((pool, fingerprint))
}

async fn connect_postgres_with_credentials(
    postgres: &ManagedPostgresConfig,
    credentials: &DatabaseCredentials,
) -> Result<PgPool> {
    let options = postgres_connect_options(postgres, credentials);
    let role_statement = format!("SET ROLE {}", postgres.role);
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .acquire_timeout(Duration::from_secs(10))
        .after_connect(move |connection, _metadata| {
            let role_statement = role_statement.clone();
            Box::pin(async move {
                sqlx::query(&role_statement).execute(connection).await?;
                Ok(())
            })
        })
        .connect_with(options)
        .await?;
    sqlx::query("SELECT 1").execute(&pool).await?;
    Ok(pool)
}

fn postgres_connect_options(
    postgres: &ManagedPostgresConfig,
    credentials: &DatabaseCredentials,
) -> PgConnectOptions {
    PgConnectOptions::new()
        .host(&postgres.host)
        .port(postgres.port)
        .database(&postgres.database)
        .username(&credentials.username)
        .password(&credentials.password)
        .ssl_mode(match postgres.ssl_mode {
            ManagedPostgresSslMode::Require => PgSslMode::Require,
            ManagedPostgresSslMode::VerifyCa => PgSslMode::VerifyCa,
            ManagedPostgresSslMode::VerifyFull => PgSslMode::VerifyFull,
        })
}

fn read_database_credentials(path: &str) -> Result<(DatabaseCredentials, [u8; 32])> {
    let path = Path::new(path);
    let bytes =
        Zeroizing::new(std::fs::read(path).with_context(|| {
            format!("read managed database credential file {}", path.display())
        })?);
    if bytes.is_empty() || bytes.len() > 64 * 1024 {
        bail!("managed database credential file must be non-empty and at most 64 KiB");
    }
    let credentials: DatabaseCredentials =
        serde_json::from_slice(&bytes).context("parse managed database credential JSON")?;
    if credentials.username.is_empty()
        || credentials.username.len() > 1024
        || credentials.username.chars().any(char::is_control)
        || credentials.password.is_empty()
        || credentials.password.len() > 16 * 1024
    {
        bail!("managed database credentials contain invalid bounded fields");
    }
    let fingerprint = Sha256::digest(bytes.as_slice()).into();
    Ok((credentials, fingerprint))
}

fn spawn_postgres_credential_reloader(
    database: ReloadablePostgres,
    managed: ManagedConfig,
    interval: Duration,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        // The first credentials were validated synchronously during startup.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let result = read_database_credentials(&managed.database_credentials_file);
            let Ok((credentials, fingerprint)) = result else {
                tracing::warn!(
                    "managed PostgreSQL credential update was rejected; retaining current pool"
                );
                continue;
            };
            let unchanged = database
                .credential_fingerprint
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .is_some_and(|current| current == &fingerprint);
            if unchanged {
                continue;
            }
            let Some(postgres) = managed.postgres.as_ref() else {
                tracing::warn!(
                    "managed PostgreSQL credential update was rejected; retaining current pool"
                );
                continue;
            };
            let Ok(replacement) = connect_postgres_with_credentials(postgres, &credentials).await
            else {
                tracing::warn!(
                    "managed PostgreSQL credential update was rejected; retaining current pool"
                );
                continue;
            };

            let old = database.swap(replacement);
            *database
                .credential_fingerprint
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(fingerprint);
            let generation = database.generation.fetch_add(1, Ordering::Relaxed) + 1;
            tracing::info!(
                database_pool_generation = generation,
                "managed PostgreSQL credential pool rotated"
            );
            tokio::spawn(async move {
                old.close().await;
            });
        }
    });
}

fn validate_proxy_session(
    session_id: &str,
    token_hash: &[u8],
    subject: &str,
    profile: &str,
    expires_unix_seconds: i64,
    maximum_expires_unix_seconds: i64,
) -> Result<()> {
    if session_id.is_empty()
        || subject.is_empty()
        || profile.is_empty()
        || session_id.len() > 256
        || subject.len() > 1024
        || profile.len() > 256
        || session_id.chars().any(char::is_control)
        || subject.chars().any(char::is_control)
        || profile.chars().any(char::is_control)
    {
        bail!("proxy session fields must be non-empty bounded text without control characters");
    }
    if token_hash.len() != 32 {
        bail!("proxy session token hash must be exactly 32 bytes");
    }
    if expires_unix_seconds <= now_unix_seconds()? {
        bail!("proxy session expiry must be in the future");
    }
    if maximum_expires_unix_seconds < expires_unix_seconds {
        bail!("proxy session maximum expiry must not precede its sliding expiry");
    }
    Ok(())
}

fn validate_agent_token(name: &str, token_hash: &[u8]) -> Result<()> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("agent name must be 1-128 ASCII letters, digits, hyphens, or underscores");
    }
    if token_hash.len() != 32 {
        bail!("agent token hash must be exactly 32 bytes");
    }
    Ok(())
}

fn read_database_url(path: &str) -> Result<String> {
    let path = Path::new(path);
    let value = std::fs::read_to_string(path)
        .with_context(|| format!("read managed database URL file {}", path.display()))?;
    let value = value.trim();
    if value.is_empty() || value.contains(['\r', '\n']) {
        bail!("managed database URL file must contain one non-empty URL");
    }
    Ok(value.to_owned())
}

fn now_unix_seconds() -> Result<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs()
        .try_into()
        .context("system clock is outside supported audit range")
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn sqlite_store(directory: &tempfile::TempDir, owner: &str) -> Store {
        let database = directory.path().join("av.db");
        let url_file = directory.path().join("database-url");
        std::fs::write(&url_file, format!("sqlite:{}", database.display())).unwrap();
        Store::connect(&ManagedConfig {
            database_url_file: url_file.display().to_string(),
            database_credentials_file: String::new(),
            postgres: None,
            database_reload_interval_seconds: 0,
            initial_owner_oidc_subject: owner.into(),
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn sqlite_store_migrates_and_records_safe_audit_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let store = sqlite_store(&directory, "").await;
        store
            .record_audit(
                "basic:operator",
                "profile_lease",
                Some("dev"),
                None,
                Some("sh"),
            )
            .await
            .unwrap();
        let Store::Sqlite(pool) = store else {
            panic!("expected SQLite store");
        };
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM av_audit_events")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn first_owner_is_immutable_across_restarts() {
        let directory = tempfile::tempdir().unwrap();
        let first = sqlite_store(&directory, "oidc:first-owner").await;
        assert!(first.is_owner("oidc:first-owner").await.unwrap());

        let later = sqlite_store(&directory, "oidc:replacement-owner").await;
        assert!(later.is_owner("oidc:first-owner").await.unwrap());
        assert!(!later.is_owner("oidc:replacement-owner").await.unwrap());
    }

    #[tokio::test]
    async fn principal_roles_protect_the_last_owner() {
        let directory = tempfile::tempdir().unwrap();
        let store = sqlite_store(&directory, "oidc:first-owner").await;
        assert_eq!(
            store.principal_role("oidc:first-owner").await.unwrap(),
            PrincipalRole::Owner
        );
        assert_eq!(
            store.principal_role("oidc:unknown").await.unwrap(),
            PrincipalRole::User
        );
        assert!(
            store
                .set_principal_role("oidc:first-owner", PrincipalRole::Operator)
                .await
                .is_err()
        );

        store
            .set_principal_role("oidc:second-owner", PrincipalRole::Owner)
            .await
            .unwrap();
        store
            .set_principal_role("oidc:first-owner", PrincipalRole::Auditor)
            .await
            .unwrap();
        assert_eq!(
            store.principal_role("oidc:first-owner").await.unwrap(),
            PrincipalRole::Auditor
        );
        assert_eq!(
            store.list_principal_roles().await.unwrap(),
            vec![
                PrincipalRoleBinding {
                    subject: "oidc:first-owner".into(),
                    role: PrincipalRole::Auditor,
                },
                PrincipalRoleBinding {
                    subject: "oidc:second-owner".into(),
                    role: PrincipalRole::Owner,
                },
            ]
        );
    }

    #[tokio::test]
    async fn basic_users_can_be_disabled_without_returning_password_hashes() {
        let directory = tempfile::tempdir().unwrap();
        let store = sqlite_store(&directory, "").await;
        store
            .upsert_basic_user("operator", "$argon2id$placeholder")
            .await
            .unwrap();
        assert_eq!(
            store.list_basic_users().await.unwrap(),
            vec![BasicUser {
                username: "operator".into(),
                enabled: true,
            }]
        );
        assert!(
            store
                .basic_password_hash("operator")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .set_basic_user_enabled("operator", false)
                .await
                .unwrap()
        );
        assert!(
            store
                .basic_password_hash("operator")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn agents_store_only_token_hashes_and_revoke_sessions_when_disabled() {
        let directory = tempfile::tempdir().unwrap();
        let store = sqlite_store(&directory, "").await;
        let raw_token = b"synthetic-agent-token-that-must-not-be-stored";
        let token_hash: [u8; 32] = Sha256::digest(raw_token).into();
        store.create_agent("builder", &token_hash).await.unwrap();
        assert_eq!(
            store.list_agents().await.unwrap(),
            vec![Agent {
                name: "builder".into(),
                enabled: true,
            }]
        );
        assert_eq!(
            store.agent_for_token_hash(&token_hash).await.unwrap(),
            Some("builder".into())
        );

        let expiry = now_unix_seconds().unwrap() + 60;
        store
            .create_proxy_session(
                "agent-session",
                &[9_u8; 32],
                "agent:builder",
                "example",
                expiry,
                expiry + 60,
            )
            .await
            .unwrap();
        assert!(store.set_agent_enabled("builder", false).await.unwrap());
        assert_eq!(store.agent_for_token_hash(&token_hash).await.unwrap(), None);
        assert!(
            store
                .active_proxy_session(&[9_u8; 32])
                .await
                .unwrap()
                .is_none()
        );

        let Store::Sqlite(pool) = &store else {
            panic!("expected SQLite store");
        };
        let stored: Vec<u8> =
            sqlx::query_scalar("SELECT token_hash FROM av_agents WHERE name = 'builder'")
                .fetch_one(pool)
                .await
                .unwrap();
        assert_eq!(stored, token_hash);
        assert_ne!(stored, raw_token);
    }

    #[tokio::test]
    async fn profile_grants_are_exact_and_revocable() {
        let directory = tempfile::tempdir().unwrap();
        let store = sqlite_store(&directory, "").await;
        store
            .grant_profile("oidc:developer", "infra-dev")
            .await
            .unwrap();
        assert!(
            store
                .profile_allowed("oidc:developer", "infra-dev")
                .await
                .unwrap()
        );
        assert!(
            !store
                .profile_allowed("oidc:developer", "infra-prod")
                .await
                .unwrap()
        );
        assert_eq!(
            store.list_allowed_profiles("oidc:developer").await.unwrap(),
            vec!["infra-dev"]
        );
        assert_eq!(
            store.list_profile_grants("infra-dev").await.unwrap(),
            vec![ProfileGrant {
                profile: "infra-dev".into(),
                subject: "oidc:developer".into(),
                mode: GrantMode::Both,
                expires_unix_seconds: None,
            }]
        );
        assert!(
            store
                .revoke_profile("oidc:developer", "infra-dev")
                .await
                .unwrap()
        );
        assert!(
            !store
                .profile_allowed("oidc:developer", "infra-dev")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn capability_grants_enforce_delivery_mode_and_expiry() {
        let directory = tempfile::tempdir().unwrap();
        let store = sqlite_store(&directory, "").await;
        store
            .grant_profile_mode("agent:builder", "example-prod", GrantMode::Proxy, None)
            .await
            .unwrap();
        assert!(
            store
                .profile_allowed_for("agent:builder", "example-prod", GrantMode::Proxy)
                .await
                .unwrap()
        );
        assert!(
            !store
                .profile_allowed_for("agent:builder", "example-prod", GrantMode::Environment)
                .await
                .unwrap()
        );

        store
            .grant_profile_mode(
                "agent:builder",
                "example-prod",
                GrantMode::Environment,
                Some(now_unix_seconds().unwrap() + 60),
            )
            .await
            .unwrap();
        assert!(
            !store
                .profile_allowed_for("agent:builder", "example-prod", GrantMode::Proxy)
                .await
                .unwrap()
        );
        assert!(
            store
                .profile_allowed_for("agent:builder", "example-prod", GrantMode::Environment)
                .await
                .unwrap()
        );
        assert!(
            store
                .grant_profile_mode(
                    "agent:builder",
                    "expired",
                    GrantMode::Both,
                    Some(now_unix_seconds().unwrap() - 1),
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn proxy_sessions_store_only_hashes_and_fail_closed_on_expiry_or_revocation() {
        let directory = tempfile::tempdir().unwrap();
        let store = sqlite_store(&directory, "").await;
        let token_hash = [7_u8; 32];
        let expiry = now_unix_seconds().unwrap() + 60;
        store
            .create_proxy_session(
                "session-1",
                &token_hash,
                "oidc:developer",
                "example-dev",
                expiry,
                expiry + 60,
            )
            .await
            .unwrap();
        assert_eq!(
            store.active_proxy_session(&token_hash).await.unwrap(),
            Some(ProxySession {
                session_id: "session-1".into(),
                subject: "oidc:developer".into(),
                profile: "example-dev".into(),
                expires_unix_seconds: expiry,
            })
        );
        assert!(
            store
                .renew_proxy_session_for_subject("session-1", "oidc:other", expiry + 30)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .renew_proxy_session_for_subject("session-1", "oidc:developer", expiry + 30)
                .await
                .unwrap()
                .unwrap()
                .expires_unix_seconds,
            expiry + 30
        );
        assert_eq!(
            store
                .renew_proxy_session_for_subject("session-1", "oidc:developer", expiry + 600)
                .await
                .unwrap()
                .unwrap()
                .expires_unix_seconds,
            expiry + 60
        );
        assert!(store.revoke_proxy_session("session-1").await.unwrap());
        assert!(!store.revoke_proxy_session("session-1").await.unwrap());
        assert!(
            store
                .active_proxy_session(&token_hash)
                .await
                .unwrap()
                .is_none()
        );

        let owned_hash = [6_u8; 32];
        let owned_expiry = now_unix_seconds().unwrap() + 60;
        store
            .create_proxy_session(
                "owned-session",
                &owned_hash,
                "oidc:developer",
                "example-dev",
                owned_expiry,
                owned_expiry + 60,
            )
            .await
            .unwrap();
        assert!(
            !store
                .revoke_proxy_session_for_subject("owned-session", "oidc:other")
                .await
                .unwrap()
        );
        assert!(
            store
                .revoke_proxy_session_for_subject("owned-session", "oidc:developer")
                .await
                .unwrap()
        );

        let expired_hash = [8_u8; 32];
        let expired = now_unix_seconds().unwrap();
        let error = store
            .create_proxy_session(
                "expired-session",
                &expired_hash,
                "oidc:developer",
                "example-dev",
                expired,
                expired + 60,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("expiry must be in the future"));

        let invalid_hash = [9_u8; 31];
        let invalid_expiry = now_unix_seconds().unwrap() + 60;
        let error = store
            .create_proxy_session(
                "invalid-hash",
                &invalid_hash,
                "oidc:developer",
                "example-dev",
                invalid_expiry,
                invalid_expiry + 60,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("exactly 32 bytes"));
    }
}
