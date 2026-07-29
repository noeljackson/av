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
pub struct ProfileGrant {
    pub profile: String,
    pub subject: String,
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

    pub async fn is_owner(&self, subject: &str) -> Result<bool> {
        let count: i64 = match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                sqlx::query_scalar("SELECT COUNT(*) FROM av_owners WHERE subject = $1")
                    .bind(subject)
                    .fetch_one(&pool)
                    .await?
            }
            Self::Sqlite(pool) => {
                sqlx::query_scalar("SELECT COUNT(*) FROM av_owners WHERE subject = ?")
                    .bind(subject)
                    .fetch_one(pool)
                    .await?
            }
        };
        Ok(count > 0)
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

    pub async fn profile_allowed(&self, subject: &str, profile: &str) -> Result<bool> {
        let count: i64 = match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                sqlx::query_scalar(
                    "SELECT COUNT(*) FROM av_profile_grants WHERE subject = $1 AND profile = $2",
                )
                .bind(subject)
                .bind(profile)
                .fetch_one(&pool)
                .await?
            }
            Self::Sqlite(pool) => {
                sqlx::query_scalar(
                    "SELECT COUNT(*) FROM av_profile_grants WHERE subject = ? AND profile = ?",
                )
                .bind(subject)
                .bind(profile)
                .fetch_one(pool)
                .await?
            }
        };
        Ok(count > 0)
    }

    pub async fn list_allowed_profiles(&self, subject: &str) -> Result<Vec<String>> {
        match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                sqlx::query_scalar(
                    "SELECT profile FROM av_profile_grants WHERE subject = $1 ORDER BY profile",
                )
                .bind(subject)
                .fetch_all(&pool)
                .await
                .context("list managed profile grants")
            }
            Self::Sqlite(pool) => sqlx::query_scalar(
                "SELECT profile FROM av_profile_grants WHERE subject = ? ORDER BY profile",
            )
            .bind(subject)
            .fetch_all(pool)
            .await
            .context("list managed profile grants"),
        }
    }

    pub async fn list_profile_grants(&self, profile: &str) -> Result<Vec<ProfileGrant>> {
        let subjects: Vec<String> = match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                sqlx::query_scalar(
                    "SELECT subject FROM av_profile_grants WHERE profile = $1 ORDER BY subject",
                )
                .bind(profile)
                .fetch_all(&pool)
                .await?
            }
            Self::Sqlite(pool) => {
                sqlx::query_scalar(
                    "SELECT subject FROM av_profile_grants WHERE profile = ? ORDER BY subject",
                )
                .bind(profile)
                .fetch_all(pool)
                .await?
            }
        };
        Ok(subjects
            .into_iter()
            .map(|subject| ProfileGrant {
                profile: profile.into(),
                subject,
            })
            .collect())
    }

    pub async fn grant_profile(&self, subject: &str, profile: &str) -> Result<()> {
        match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                sqlx::query(
                    "INSERT INTO av_profile_grants (subject, profile) VALUES ($1, $2) \
                     ON CONFLICT (subject, profile) DO NOTHING",
                )
                .bind(subject)
                .bind(profile)
                .execute(&pool)
                .await?;
            }
            Self::Sqlite(pool) => {
                sqlx::query(
                    "INSERT INTO av_profile_grants (subject, profile) VALUES (?, ?) \
                     ON CONFLICT (subject, profile) DO NOTHING",
                )
                .bind(subject)
                .bind(profile)
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
                sqlx::query("DELETE FROM av_profile_grants WHERE subject = $1 AND profile = $2")
                    .bind(subject)
                    .bind(profile)
                    .execute(&pool)
                    .await?
                    .rows_affected()
            }
            Self::Sqlite(pool) => {
                sqlx::query("DELETE FROM av_profile_grants WHERE subject = ? AND profile = ?")
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
    ) -> Result<()> {
        validate_proxy_session(
            session_id,
            token_hash,
            subject,
            profile,
            expires_unix_seconds,
        )?;
        match self {
            Self::Postgres(database) => {
                let pool = database.pool();
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
                .execute(&pool)
                .await
                .context("write proxy session")?;
            }
            Self::Sqlite(pool) => {
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
                .execute(pool)
                .await
                .context("write proxy session")?;
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
        const CREATE_BASIC_USERS: &str = "CREATE TABLE IF NOT EXISTS av_basic_users (\
            username TEXT PRIMARY KEY,\
            password_hash TEXT NOT NULL,\
            enabled BOOLEAN NOT NULL\
        )";
        const CREATE_PROFILE_GRANTS: &str = "CREATE TABLE IF NOT EXISTS av_profile_grants (\
            subject TEXT NOT NULL,\
            profile TEXT NOT NULL,\
            PRIMARY KEY (subject, profile)\
        )";
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
        match self {
            Self::Postgres(database) => {
                let pool = database.pool();
                sqlx::query(CREATE_OWNERS).execute(&pool).await?;
                sqlx::query(CREATE_OWNER_BOOTSTRAP).execute(&pool).await?;
                sqlx::query(CREATE_BASIC_USERS).execute(&pool).await?;
                sqlx::query(CREATE_PROFILE_GRANTS).execute(&pool).await?;
                sqlx::query(CREATE_AUDIT_EVENTS).execute(&pool).await?;
                sqlx::query(CREATE_AUDIT_INDEX).execute(&pool).await?;
                sqlx::query(CREATE_PROXY_SESSIONS_POSTGRES)
                    .execute(&pool)
                    .await?;
                sqlx::query(CREATE_PROXY_SESSIONS_TOKEN_INDEX)
                    .execute(&pool)
                    .await?;
            }
            Self::Sqlite(pool) => {
                sqlx::query(CREATE_OWNERS).execute(pool).await?;
                sqlx::query(CREATE_OWNER_BOOTSTRAP).execute(pool).await?;
                sqlx::query(CREATE_BASIC_USERS).execute(pool).await?;
                sqlx::query(CREATE_PROFILE_GRANTS).execute(pool).await?;
                sqlx::query(CREATE_AUDIT_EVENTS).execute(pool).await?;
                sqlx::query(CREATE_AUDIT_INDEX).execute(pool).await?;
                sqlx::query(CREATE_PROXY_SESSIONS_SQLITE)
                    .execute(pool)
                    .await?;
                sqlx::query(CREATE_PROXY_SESSIONS_TOKEN_INDEX)
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
        store
            .create_proxy_session(
                "owned-session",
                &owned_hash,
                "oidc:developer",
                "example-dev",
                now_unix_seconds().unwrap() + 60,
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
        let error = store
            .create_proxy_session(
                "expired-session",
                &expired_hash,
                "oidc:developer",
                "example-dev",
                now_unix_seconds().unwrap(),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("expiry must be in the future"));

        let invalid_hash = [9_u8; 31];
        let error = store
            .create_proxy_session(
                "invalid-hash",
                &invalid_hash,
                "oidc:developer",
                "example-dev",
                now_unix_seconds().unwrap() + 60,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("exactly 32 bytes"));
    }
}
