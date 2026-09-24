/// Authenticated control-state family persisted for relay replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignedStateKind {
    /// Signed configuration manifest and independently sequenced authorization lease.
    Configuration,
    /// Root-anchored active and overlap Authority lifecycle.
    Authorities,
    /// Peer identities, addresses, and active credentials.
    Peers,
    /// Relay endpoints and active credentials.
    Relays,
    /// Independently signed sparse/compatibility Relay graph.
    #[serde(rename = "relay_topology")]
    RelayTopology,
    /// Canonical ordered ACL policy.
    Policy,
    /// Peer-published services.
    Services,
    /// Exact credential serial revocations.
    Revocations,
}

impl SignedStateKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Configuration => "configuration",
            Self::Authorities => "authorities",
            Self::Peers => "peers",
            Self::Relays => "relays",
            Self::RelayTopology => "relay_topology",
            Self::Policy => "policy",
            Self::Services => "services",
            Self::Revocations => "revocations",
        }
    }

    fn from_str(value: &str) -> Result<Self, StoreError> {
        match value {
            "configuration" => Ok(Self::Configuration),
            "authorities" => Ok(Self::Authorities),
            "peers" => Ok(Self::Peers),
            "relays" => Ok(Self::Relays),
            "relay_topology" => Ok(Self::RelayTopology),
            "policy" => Ok(Self::Policy),
            "services" => Ok(Self::Services),
            "revocations" => Ok(Self::Revocations),
            _ => Err(StoreError::Invalid("stored signed-state kind")),
        }
    }
}

/// One signed immutable state revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedStateRevision {
    /// Owning mesh.
    pub mesh_id: MeshId,
    /// State family.
    pub kind: SignedStateKind,
    /// Monotonic family revision.
    pub revision: u64,
    /// Family-specific signed encoding.
    pub body: Vec<u8>,
    /// Database publication time.
    pub published_at: OffsetDateTime,
    /// Publication request identity, absent on older rows.
    pub request_id: Option<Uuid>,
    /// Canonical W3C publication context, absent on older rows.
    pub traceparent: Option<String>,
}

impl Store {
    /// Loads every Relay admission fact and event high-water in one read-only snapshot.
    pub async fn relay_admission_snapshot(
        &self,
        mesh_id: MeshId,
    ) -> Result<RelayAdmissionSnapshot, StoreError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *transaction)
            .await?;
        let state_rows = sqlx::query(
            "SELECT DISTINCT ON (kind) mesh_id,kind,revision,body,published_at,
                    request_id,trace_id,span_id,trace_flags
             FROM signed_state_revisions WHERE mesh_id=$1 ORDER BY kind,revision DESC",
        )
        .bind(mesh_id.into_uuid())
        .fetch_all(&mut *transaction)
        .await?;
        let signed_states = state_rows
            .into_iter()
            .map(signed_state_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        let peer_rows = sqlx::query(
            "SELECT c.peer_id,c.serial FROM peer_credentials c JOIN peers p
               ON p.mesh_id=c.mesh_id AND p.id=c.peer_id
             JOIN mesh_authorities a ON a.mesh_id=c.mesh_id AND a.id=c.authority_id
             WHERE c.mesh_id=$1 AND p.administrative_state='enabled' AND c.wireguard_public_key IS NOT NULL
               AND c.lifecycle IN ('active','overlap')
               AND (c.lifecycle='active' OR c.overlap_deadline>clock_timestamp())
               AND c.not_before<=clock_timestamp() AND c.not_after>clock_timestamp()
               AND a.lifecycle IN ('active','overlap')
               AND (a.lifecycle='active' OR a.overlap_deadline>clock_timestamp())
             ORDER BY c.peer_id,c.serial",
        )
        .bind(mesh_id.into_uuid())
        .fetch_all(&mut *transaction)
        .await?;
        let peer_credentials = peer_rows
            .into_iter()
            .map(|row| {
                Ok(PeerCredentialAdmission {
                    peer_id: PeerId::from_uuid(row.try_get("peer_id")?)
                        .map_err(|_| StoreError::Invalid("stored peer ID"))?,
                    serial: CredentialSerial::from_uuid(row.try_get("serial")?)
                        .map_err(|_| StoreError::Invalid("stored credential serial"))?,
                })
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        let relay_rows = sqlx::query(
            "SELECT c.relay_id,c.serial FROM relay_credentials c JOIN relays r
               ON r.mesh_id=c.mesh_id AND r.id=c.relay_id
             JOIN mesh_authorities a ON a.mesh_id=c.mesh_id AND a.id=c.authority_id
             WHERE c.mesh_id=$1 AND r.administrative_state='enabled'
               AND c.lifecycle IN ('active','overlap')
               AND (c.lifecycle='active' OR c.overlap_deadline>clock_timestamp())
               AND c.not_before<=clock_timestamp() AND c.not_after>clock_timestamp()
               AND a.lifecycle IN ('active','overlap')
               AND (a.lifecycle='active' OR a.overlap_deadline>clock_timestamp())
             ORDER BY c.relay_id,c.serial",
        )
        .bind(mesh_id.into_uuid())
        .fetch_all(&mut *transaction)
        .await?;
        let relay_credentials = relay_rows
            .into_iter()
            .map(|row| {
                Ok(RelayCredentialAdmission {
                    relay_id: RelayId::from_uuid(row.try_get("relay_id")?)
                        .map_err(|_| StoreError::Invalid("stored relay ID"))?,
                    serial: CredentialSerial::from_uuid(row.try_get("serial")?)
                        .map_err(|_| StoreError::Invalid("stored credential serial"))?,
                })
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        let presence_rows = sqlx::query(
            "SELECT peer_id,relay_id,attachment_id,role,fencing_generation,lease_deadline
             FROM relay_presence_all WHERE mesh_id=$1 AND lease_deadline>clock_timestamp()
             ORDER BY peer_id,role,relay_id",
        )
        .bind(mesh_id.into_uuid())
        .fetch_all(&mut *transaction)
        .await?;
        let presence = presence_rows
            .into_iter()
            .map(presence_snapshot_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        let runtime_rows = sqlx::query(
            "SELECT relay_id,instance_id,fencing_generation,lease_deadline,wire_capabilities,
                    neighbor_health
             FROM relay_runtime_leases WHERE mesh_id=$1 AND lease_deadline>clock_timestamp()
             ORDER BY relay_id",
        )
        .bind(mesh_id.into_uuid())
        .fetch_all(&mut *transaction)
        .await?;
        let runtimes = runtime_rows
            .into_iter()
            .map(relay_runtime_snapshot_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        let event_high_water: i64 = sqlx::query_scalar(
            "SELECT high_water_sequence FROM event_stream_state WHERE singleton",
        )
        .fetch_one(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(RelayAdmissionSnapshot {
            signed_states,
            peer_credentials,
            relay_credentials,
            presence,
            runtimes,
            event_high_water,
        })
    }

    /// Atomically persists newly signed state families and emits one durable wakeup event.
    pub async fn publish_signed_states(
        &self,
        mesh_id: MeshId,
        states: &[(SignedStateKind, u64, Vec<u8>)],
    ) -> Result<usize, StoreError> {
        self.publish_signed_states_with_context(mesh_id, states, None)
            .await
    }

    /// Persists a publication context with every immutable signed family revision.
    pub async fn publish_signed_states_with_context(
        &self,
        mesh_id: MeshId,
        states: &[(SignedStateKind, u64, Vec<u8>)],
        correlation: Option<peerward_types::CorrelationContext>,
    ) -> Result<usize, StoreError> {
        if states.is_empty()
            || states.len() > 8
            || states.iter().any(|(_, _, body)| {
                body.is_empty() || body.len() > peerward_types::MAX_SIGNED_STATE_BYTES
            })
        {
            return Err(StoreError::Invalid("signed state batch"));
        }
        let mut kinds = HashSet::new();
        if states.iter().any(|(kind, _, _)| !kinds.insert(*kind)) {
            return Err(StoreError::Invalid("duplicate signed-state kind"));
        }
        let mut transaction = self.pool.begin().await?;
        let mut inserted = 0_usize;
        for (kind, revision, body) in states {
            let revision = i64::try_from(*revision)
                .map_err(|_| StoreError::Invalid("signed-state revision"))?;
            let changed = sqlx::query(
                "INSERT INTO signed_state_revisions
                 (mesh_id,kind,revision,body,request_id,trace_id,span_id,trace_flags)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING",
            )
            .bind(mesh_id.into_uuid())
            .bind(kind.as_str())
            .bind(revision)
            .bind(body)
            .bind(correlation.map(|context| context.request_id))
            .bind(correlation.map(|context| context.trace_id.to_vec()))
            .bind(correlation.map(|context| context.span_id.to_vec()))
            .bind(correlation.map(|context| i16::from(context.flags)))
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            if changed == 0 {
                let existing: Vec<u8> = sqlx::query_scalar(
                    "SELECT body FROM signed_state_revisions
                     WHERE mesh_id=$1 AND kind=$2 AND revision=$3",
                )
                .bind(mesh_id.into_uuid())
                .bind(kind.as_str())
                .bind(revision)
                .fetch_one(&mut *transaction)
                .await?;
                if existing != *body {
                    return Err(StoreError::SignedStateConflict {
                        kind: kind.as_str(),
                        revision: u64::try_from(revision).expect("revision was converted from u64"),
                    });
                }
            } else {
                inserted += 1;
            }
        }
        if inserted > 0 {
            append_event_with_correlation(
                &mut transaction,
                Some(mesh_id),
                "state.published",
                "signed_state",
                None,
                json!({"families": inserted}),
                correlation,
            )
            .await?;
        }
        transaction.commit().await?;
        Ok(inserted)
    }

    /// Loads the newest persisted signed revision for one family.
    pub async fn latest_signed_state(
        &self,
        mesh_id: MeshId,
        kind: SignedStateKind,
    ) -> Result<SignedStateRevision, StoreError> {
        let row = sqlx::query(
            "SELECT mesh_id,kind,revision,body,published_at,
                    request_id,trace_id,span_id,trace_flags
             FROM signed_state_revisions WHERE mesh_id=$1 AND kind=$2
             ORDER BY revision DESC LIMIT 1",
        )
        .bind(mesh_id.into_uuid())
        .bind(kind.as_str())
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StoreError::NotFound)?;
        signed_state_from_row(row)
    }

    /// Loads every latest signed family in a single repeatable-read snapshot.
    pub async fn latest_signed_states(
        &self,
        mesh_id: MeshId,
    ) -> Result<Vec<SignedStateRevision>, StoreError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *transaction)
            .await?;
        let rows = sqlx::query(
            "SELECT DISTINCT ON (kind) mesh_id,kind,revision,body,published_at,
                    request_id,trace_id,span_id,trace_flags
             FROM signed_state_revisions WHERE mesh_id=$1
             ORDER BY kind,revision DESC",
        )
        .bind(mesh_id.into_uuid())
        .fetch_all(&mut *transaction)
        .await?;
        transaction.commit().await?;
        rows.into_iter().map(signed_state_from_row).collect()
    }
}

fn signed_state_from_row(row: sqlx::postgres::PgRow) -> Result<SignedStateRevision, StoreError> {
    let mesh: Uuid = row.try_get("mesh_id")?;
    let request_id: Option<Uuid> = row.try_get("request_id")?;
    let correlation = request_id
        .map(|request_id| {
            peerward_types::CorrelationContext::from_parts(
                request_id,
                row.try_get::<Vec<u8>, _>("trace_id")?
                    .try_into()
                    .map_err(|_| StoreError::Invalid("stored trace ID"))?,
                row.try_get::<Vec<u8>, _>("span_id")?
                    .try_into()
                    .map_err(|_| StoreError::Invalid("stored span ID"))?,
                u8::try_from(row.try_get::<i16, _>("trace_flags")?)
                    .map_err(|_| StoreError::Invalid("stored trace flags"))?,
            )
            .map_err(|_| StoreError::Invalid("stored trace context"))
        })
        .transpose()?;
    Ok(SignedStateRevision {
        mesh_id: MeshId::from_uuid(mesh).map_err(|_| StoreError::Invalid("stored mesh ID"))?,
        kind: SignedStateKind::from_str(row.try_get::<String, _>("kind")?.as_str())?,
        revision: u64::try_from(row.try_get::<i64, _>("revision")?)
            .map_err(|_| StoreError::Invalid("stored signed-state revision"))?,
        body: row.try_get("body")?,
        published_at: row.try_get("published_at")?,
        request_id,
        traceparent: correlation.map(peerward_types::CorrelationContext::traceparent),
    })
}

fn presence_snapshot_from_row(row: sqlx::postgres::PgRow) -> Result<PresenceSnapshot, StoreError> {
    Ok(PresenceSnapshot {
        peer_id: PeerId::from_uuid(row.try_get("peer_id")?)
            .map_err(|_| StoreError::Invalid("stored peer ID"))?,
        relay_id: RelayId::from_uuid(row.try_get("relay_id")?)
            .map_err(|_| StoreError::Invalid("stored relay ID"))?,
        attachment_id: AttachmentId::from_uuid(row.try_get("attachment_id")?)
            .map_err(|_| StoreError::Invalid("stored attachment ID"))?,
        role: match row.try_get::<String, _>("role")?.as_str() {
            "primary" => PresenceRole::Primary,
            "standby" => PresenceRole::Standby,
            _ => return Err(StoreError::Invalid("stored presence role")),
        },
        generation: row.try_get("fencing_generation")?,
        lease_deadline: row.try_get("lease_deadline")?,
    })
}

fn relay_runtime_snapshot_from_row(
    row: sqlx::postgres::PgRow,
) -> Result<RelayRuntimeSnapshot, StoreError> {
    let neighbor_health = serde_json::from_value(row.try_get("neighbor_health")?)
        .map_err(|_| StoreError::Invalid("stored Relay neighbor health"))?;
    Ok(RelayRuntimeSnapshot {
        relay_id: RelayId::from_uuid(row.try_get("relay_id")?)
            .map_err(|_| StoreError::Invalid("stored relay ID"))?,
        instance_id: row.try_get("instance_id")?,
        generation: row.try_get("fencing_generation")?,
        lease_deadline: row.try_get("lease_deadline")?,
        wire_capabilities: u64::try_from(row.try_get::<i64, _>("wire_capabilities")?)
            .map_err(|_| StoreError::Invalid("stored Relay capabilities"))?,
        neighbor_health,
    })
}
