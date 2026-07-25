//! Managed-mode persistence. AV stores policy metadata and audit records here,
//! never connector credentials or fetched secret values.

use std::{
    path::Path,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use sqlx::{
    PgPool, SqlitePool,
    postgres::PgPoolOptions,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};

use crate::config::ManagedConfig;

#[derive(Clone)]
pub enum Store {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BasicUser {
    pub username: String,
    pub enabled: bool,
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

type AuditRow = (
    i64,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
);

impl Store {
    pub async fn connect(managed: &ManagedConfig) -> Result<Self> {
        let database_url = read_database_url(&managed.database_url_file)?;
        let store = if database_url.starts_with("postgres://")
            || database_url.starts_with("postgresql://")
        {
            Self::Postgres(
                PgPoolOptions::new()
                    .max_connections(8)
                    .acquire_timeout(std::time::Duration::from_secs(10))
                    .connect(&database_url)
                    .await
                    .context("connect managed PostgreSQL database")?,
            )
        } else if database_url.starts_with("sqlite:") {
            let options = SqliteConnectOptions::from_str(&database_url)
                .context("parse managed SQLite database URL")?
                .create_if_missing(true)
                .foreign_keys(true);
            Self::Sqlite(
                SqlitePoolOptions::new()
                    .max_connections(1)
                    .acquire_timeout(std::time::Duration::from_secs(10))
                    .connect_with(options)
                    .await
                    .context("connect managed SQLite database")?,
            )
        } else {
            bail!("managed database URL must use postgres://, postgresql://, or sqlite:");
        };
        store.migrate().await?;
        if !managed.initial_owner_oidc_subject.is_empty() {
            store
                .bootstrap_owner(&managed.initial_owner_oidc_subject)
                .await?;
        }
        Ok(store)
    }

    pub async fn is_owner(&self, subject: &str) -> Result<bool> {
        let count: i64 = match self {
            Self::Postgres(pool) => {
                sqlx::query_scalar("SELECT COUNT(*) FROM av_owners WHERE subject = $1")
                    .bind(subject)
                    .fetch_one(pool)
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
            Self::Postgres(pool) => sqlx::query_scalar(
                "SELECT password_hash FROM av_basic_users WHERE username = $1 AND enabled = TRUE",
            )
            .bind(username)
            .fetch_optional(pool)
            .await
            .context("read managed Basic user"),
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
            Self::Postgres(pool) => {
                sqlx::query_as("SELECT username, enabled FROM av_basic_users ORDER BY username")
                    .fetch_all(pool)
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
            Self::Postgres(pool) => {
                sqlx::query(
                    "INSERT INTO av_basic_users (username, password_hash, enabled) VALUES ($1, $2, TRUE) \
                     ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash, enabled = TRUE",
                )
                .bind(username)
                .bind(password_hash)
                .execute(pool)
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
            Self::Postgres(pool) => {
                sqlx::query("UPDATE av_basic_users SET enabled = $1 WHERE username = $2")
                    .bind(enabled)
                    .bind(username)
                    .execute(pool)
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

    pub async fn list_audit_events(&self, limit: i64) -> Result<Vec<AuditEvent>> {
        let limit = limit.clamp(1, 500);
        let rows: Vec<AuditRow> = match self {
            Self::Postgres(pool) => sqlx::query_as(
                "SELECT created_unix_seconds, actor, action, profile, route, executable_basename \
                     FROM av_audit_events ORDER BY created_unix_seconds DESC LIMIT $1",
            )
            .bind(limit)
            .fetch_all(pool)
            .await?,
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
            Self::Postgres(pool) => {
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
                .execute(pool)
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
        match self {
            Self::Postgres(pool) => {
                sqlx::query(CREATE_OWNERS).execute(pool).await?;
                sqlx::query(CREATE_OWNER_BOOTSTRAP).execute(pool).await?;
                sqlx::query(CREATE_BASIC_USERS).execute(pool).await?;
                sqlx::query(CREATE_AUDIT_EVENTS).execute(pool).await?;
                sqlx::query(CREATE_AUDIT_INDEX).execute(pool).await?;
            }
            Self::Sqlite(pool) => {
                sqlx::query(CREATE_OWNERS).execute(pool).await?;
                sqlx::query(CREATE_OWNER_BOOTSTRAP).execute(pool).await?;
                sqlx::query(CREATE_BASIC_USERS).execute(pool).await?;
                sqlx::query(CREATE_AUDIT_EVENTS).execute(pool).await?;
                sqlx::query(CREATE_AUDIT_INDEX).execute(pool).await?;
            }
        }
        Ok(())
    }

    async fn bootstrap_owner(&self, subject: &str) -> Result<()> {
        match self {
            Self::Postgres(pool) => {
                sqlx::query(
                    "WITH inserted AS (\
                        INSERT INTO av_owner_bootstrap (singleton, subject) VALUES (1, $1) \
                        ON CONFLICT (singleton) DO NOTHING RETURNING subject\
                     ) \
                     INSERT INTO av_owners (subject) SELECT subject FROM inserted \
                     ON CONFLICT (subject) DO NOTHING",
                )
                .bind(subject)
                .execute(pool)
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
}
