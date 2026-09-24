use std::{collections::HashSet, net::IpAddr, str::FromStr, time::Duration};

use ipnet::IpNet;
use peerward_credentials::{
    RotationActivationProof, RotationRequestProof, verify_rotation_activation,
    verify_rotation_request,
};
use peerward_policy::{Action as PolicyAction, Policy, encode_policy_document};
use peerward_types::{
    AttachmentId, CredentialSerial, EventId, MAX_RESERVED_ADDRESSES, MeshId, NetworkEndpoint,
    PeerId, RelayId, RotationId, ServiceId, ServiceProtocol, TicketId, validate_endpoint_list,
};
use rand::{RngCore as _, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Acquire, PgPool, Postgres, Row, Transaction, postgres::PgListener};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

// Migration identity must not change when the release's schema generation advances.
const BASELINE_VERSION: i32 = 1;
const BASELINE: &str = include_str!("../../migrations/0001_core.sql");
const EVENT_CHANNEL: &str = "peerward_events_v1";

/// Store-level validation, conflict, or database error.
#[derive(Debug, Error)]
pub enum StoreError {
    /// `PostgreSQL` operation failed.
    #[error("database operation failed: {0}")]
    Database(#[from] sqlx::Error),
    /// A supplied resource does not exist in the requested mesh.
    #[error("resource not found")]
    NotFound,
    /// A one-time or revisioned operation conflicts with committed state.
    #[error("resource state conflicts with this operation")]
    Conflict,
    /// Explicit repository ownership fences ordinary management edits.
    #[error("configuration ownership does not permit this actor; an administrator must transfer ownership")]
    ConfigurationOwned,
    /// An SSE cursor is well-formed but no longer belongs to the retained event window.
    #[error("event cursor expired")]
    EventCursorExpired,
    /// A signed state attempted to reuse an immutable revision with new bytes.
    #[error("signed {kind} state revision {revision} conflicts with immutable bytes")]
    SignedStateConflict {
        /// Canonical signed-state family.
        kind: &'static str,
        /// Immutable revision that was reused.
        revision: u64,
    },
    /// Input violates a domain invariant.
    #[error("invalid input: {0}")]
    Invalid(&'static str),
    /// The mesh has no usable address remaining.
    #[error("address pool exhausted")]
    PoolExhausted,
    /// An incompatible installation was supplied to the clean-install-only release.
    #[error("legacy_schema_unsupported")]
    LegacySchemaUnsupported,
    /// A newer application already applied a migration unknown to this binary.
    #[error("newer_schema_unsupported: database requires a newer Peerward binary")]
    NewerSchemaUnsupported,
}

/// Shared database handle.
#[derive(Clone)]
pub struct Store {
    pool: PgPool,
    // Keep enrollment lock waiters outside the SQL pool so they cannot starve
    // lifecycle, state publication, and unrelated Mesh traffic.
    join_admission: std::sync::Arc<tokio::sync::Semaphore>,
}

impl Store {
    /// Opens a bounded `PostgreSQL` connection pool.
    pub async fn connect(database_url: &str, max_connections: u32) -> Result<Self, StoreError> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(Duration::from_secs(5))
            .connect(database_url)
            .await?;
        Ok(Self {
            pool,
            join_admission: std::sync::Arc::new(tokio::sync::Semaphore::new(
                usize::try_from((max_connections / 2).max(1)).unwrap_or(1),
            )),
        })
    }

    /// Creates a lazy handle, useful while assembling a process before readiness.
    pub fn connect_lazy(database_url: &str, max_connections: u32) -> Result<Self, StoreError> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(Duration::from_millis(100))
            .connect_lazy(database_url)?;
        Ok(Self {
            pool,
            join_admission: std::sync::Arc::new(tokio::sync::Semaphore::new(
                usize::try_from((max_connections / 2).max(1)).unwrap_or(1),
            )),
        })
    }

    /// Exposes the pool for narrowly scoped typed queries in the control layer.
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Begins a transaction for a typed control-layer mutation.
    pub async fn begin_mutation(&self) -> Result<Transaction<'_, Postgres>, StoreError> {
        Ok(self.pool.begin().await?)
    }

    /// Appends the mandatory audit and outbox records, then commits the mutation.
    pub async fn commit_mutation(
        &self,
        mut transaction: Transaction<'_, Postgres>,
        record: &MutationRecord,
    ) -> Result<EventId, StoreError> {
        append_audit(
            &mut transaction,
            record.mesh_id,
            &record.actor,
            &record.action,
            &record.resource_type,
            record.resource_id,
            &record.result,
            record.metadata.clone(),
        )
        .await?;
        let cursor = append_event_with_correlation(
            &mut transaction,
            record.mesh_id,
            &record.event_type,
            &record.resource_type,
            record.resource_id,
            record.metadata.clone(),
            record.correlation,
        )
        .await?;
        transaction.commit().await?;
        Ok(cursor)
    }

    /// Installs the current Peerward storage baseline under one advisory lock.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        // Own this physical connection: cancellation or any early error closes the session
        // instead of returning a session-level advisory lock to the pool.
        let mut connection = self.pool.acquire().await?.detach();
        sqlx::query("SELECT pg_advisory_lock(hashtextextended('peerward/schema/v2', 0))")
            .execute(&mut connection)
            .await?;
        let core_exists: bool =
            sqlx::query_scalar("SELECT to_regclass('public.meshes') IS NOT NULL")
                .fetch_one(&mut connection)
                .await?;
        let migrations_exist: bool = sqlx::query_scalar(
            "SELECT to_regclass('public.peerward_schema_migrations') IS NOT NULL",
        )
        .fetch_one(&mut connection)
        .await?;
        if migrations_exist {
            let recorded:Option<i32>=sqlx::query_scalar("SELECT max(version) FROM peerward_schema_migrations")
                .fetch_one(&mut connection).await?;
            let known=FOLLOWUP_MIGRATIONS.last().map_or(BASELINE_VERSION, |(version,_)|*version);
            if recorded.is_some_and(|version|version>known) {
                sqlx::query("SELECT pg_advisory_unlock(hashtextextended('peerward/schema/v2', 0))")
                    .execute(&mut connection).await?;
                return Err(StoreError::NewerSchemaUnsupported);
            }
        }
        let install_intent_exists: bool =
            sqlx::query_scalar("SELECT to_regclass('public.peerward_install_intent') IS NOT NULL")
                .fetch_one(&mut connection)
                .await?;
        // A matching historical migration chain is not authorization to upgrade an installation.
        // Inspect only: old data is untouched, even when it has the same baseline checksum.
        if core_exists || install_intent_exists {
            let marker = if install_intent_exists {
                "peerward_install_intent"
            } else {
                "peerward_installation"
            };
            let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
                .bind(format!("public.{marker}"))
                .fetch_one(&mut connection)
                .await?;
            let compatible = if exists {
                sqlx::query_scalar::<_, bool>(&format!(
                    "SELECT EXISTS(SELECT 1 FROM {marker} WHERE singleton=true AND product_major=1 AND wire_major=5)"))
                    .fetch_one(&mut connection).await?
            } else {
                false
            };
            if !compatible {
                sqlx::query("SELECT pg_advisory_unlock(hashtextextended('peerward/schema/v2', 0))")
                    .execute(&mut connection)
                    .await?;
                return Err(StoreError::LegacySchemaUnsupported);
            }
        }
        let baseline_checksum = Sha256::digest(BASELINE.as_bytes()).to_vec();
        let baseline_matches = if migrations_exist {
            sqlx::query_scalar::<_, Option<Vec<u8>>>(
                "SELECT checksum FROM peerward_schema_migrations WHERE version=$1",
            )
            .bind(BASELINE_VERSION)
            .fetch_optional(&mut connection)
            .await?
            .flatten()
            .is_some_and(|checksum| checksum == baseline_checksum)
        } else {
            false
        };
        if core_exists && !baseline_matches && !install_intent_exists {
            let _ =
                sqlx::query("SELECT pg_advisory_unlock(hashtextextended('peerward/schema/v2', 0))")
                    .execute(&mut connection)
                    .await;
            return Err(StoreError::LegacySchemaUnsupported);
        }
        let result: Result<(), sqlx::Error> = async {
            if !baseline_matches && !install_intent_exists {
                // This marker is deliberately separate from the final installation table. It is
                // created before the transactional baseline, so an interrupted clean install can
                // resume without making a legacy database eligible for an upgrade.
                sqlx::raw_sql(
                    "CREATE TABLE peerward_install_intent(
                       singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
                       product_major integer NOT NULL CHECK(product_major=1),
                       wire_major integer NOT NULL CHECK(wire_major=5),
                       created_at timestamptz NOT NULL DEFAULT clock_timestamp());
                     INSERT INTO peerward_install_intent(singleton,product_major,wire_major)
                     VALUES(true,1,5) ON CONFLICT(singleton) DO NOTHING;",
                )
                .execute(&mut connection)
                .await?;
            }
            sqlx::query(
                "CREATE TABLE IF NOT EXISTS peerward_schema_migrations(
                   version integer PRIMARY KEY, checksum bytea NOT NULL,
                   applied_at timestamptz NOT NULL DEFAULT clock_timestamp())",
            )
            .execute(&mut connection)
            .await?;
            if !baseline_matches {
                let mut transaction = connection.begin().await?;
                sqlx::raw_sql(BASELINE).execute(&mut *transaction).await?;
                sqlx::query(
                    "INSERT INTO peerward_schema_migrations(version,checksum) VALUES($1,$2)",
                )
                .bind(BASELINE_VERSION)
                .bind(&baseline_checksum)
                .execute(&mut *transaction)
                .await?;
                transaction.commit().await?;
            }
            apply_followup_migrations(&mut connection).await?;
            let valid_installation: bool = sqlx::query_scalar(
                "SELECT EXISTS(
                   SELECT 1 FROM peerward_installation
                   WHERE singleton=true AND product_major=1 AND wire_major=5)",
            )
            .fetch_one(&mut connection)
            .await?;
            if !valid_installation {
                return Err(sqlx::Error::Protocol(
                    "Peerward installation marker is missing or invalid".into(),
                ));
            }
            sqlx::query("DROP TABLE IF EXISTS peerward_install_intent")
                .execute(&mut connection)
                .await?;
            Ok(())
        }
        .await;
        let unlock =
            sqlx::query("SELECT pg_advisory_unlock(hashtextextended('peerward/schema/v2', 0))")
                .execute(&mut connection)
                .await;
        result?;
        unlock?;
        Ok(())
    }

    /// Verifies that `PostgreSQL` accepts a trivial query.
    pub async fn ready(&self) -> bool {
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .is_ok()
    }
}
