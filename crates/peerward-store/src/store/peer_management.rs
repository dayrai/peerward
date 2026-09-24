impl Store {
    /// Processes a device-signed command. Relays cannot invent observations or application receipts.
    pub async fn apply_peer_command(
        &self,
        signed: &peerward_management::SignedPeerCommand,
    ) -> Result<bool, StoreError> {
        use peerward_management::{
            ApplicationResult, ConfigurationDelivery, PeerOperation, content_digest,
        };
        let command = &signed.command;
        let mesh = command.mesh_id.into_uuid();
        let peer = command.peer_id.into_uuid();
        let sequence = i64::try_from(command.sequence)
            .map_err(|_| StoreError::Invalid("peer command sequence"))?;
        let mut tx = self.begin_mutation().await?;
        sqlx::query("SELECT id FROM meshes WHERE id=$1 AND lifecycle='active' FOR UPDATE")
            .bind(mesh)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(StoreError::NotFound)?;
        let key:Vec<u8>=sqlx::query_scalar("SELECT c.identity_public_key FROM peer_credentials c JOIN peers p ON p.mesh_id=c.mesh_id AND p.id=c.peer_id
            JOIN mesh_authorities a ON a.mesh_id=c.mesh_id AND a.id=c.authority_id
            WHERE c.mesh_id=$1 AND c.peer_id=$2 AND c.serial=$3 AND p.administrative_state='enabled'
            AND c.lifecycle IN ('active','overlap') AND (c.lifecycle='active' OR c.overlap_deadline>clock_timestamp())
            AND c.not_before<=clock_timestamp() AND c.not_after>clock_timestamp()
            AND a.lifecycle IN ('active','overlap') AND (a.lifecycle='active' OR a.overlap_deadline>clock_timestamp())
            AND a.not_before<=clock_timestamp() AND a.not_after>clock_timestamp() FOR SHARE OF p,c,a")
            .bind(mesh).bind(peer).bind(command.credential_serial.into_uuid()).fetch_optional(&mut *tx).await?.ok_or(StoreError::Conflict)?;
        let key: [u8; 32] = key
            .try_into()
            .map_err(|_| StoreError::Invalid("peer identity key"))?;
        // A retained duplicate may be acknowledged after its submission freshness window.
        signed
            .verify(&key, command.issued_at)
            .map_err(|_| StoreError::Invalid("peer command signature"))?;
        let digest =
            content_digest(command).map_err(|_| StoreError::Invalid("peer command encoding"))?;
        if let Some(previous)=sqlx::query_scalar::<_,Vec<u8>>("SELECT digest FROM peer_management_requests WHERE mesh_id=$1 AND peer_id=$2 AND request_id=$3")
            .bind(mesh).bind(peer).bind(command.request_id).fetch_optional(&mut *tx).await? {
            return if previous==digest {Ok(false)}else{Err(StoreError::Conflict)};
        }
        let now = u64::try_from(OffsetDateTime::now_utc().unix_timestamp())
            .map_err(|_| StoreError::Invalid("clock"))?;
        signed
            .verify(&key, now)
            .map_err(|_| StoreError::Invalid("peer command freshness"))?;
        sqlx::query("INSERT INTO peer_management_floors(mesh_id,peer_id) VALUES($1,$2) ON CONFLICT DO NOTHING").bind(mesh).bind(peer).execute(&mut *tx).await?;
        let floor:i64=sqlx::query_scalar("SELECT sequence FROM peer_management_floors WHERE mesh_id=$1 AND peer_id=$2 FOR UPDATE")
            .bind(mesh).bind(peer).fetch_one(&mut *tx).await?;
        if sequence <= floor {
            return Err(StoreError::Conflict);
        }
        let mut record_observation = true;
        let action = match &command.operation {
            PeerOperation::DeviceEvidence { .. } => {
                record_observation = store_device_evidence(&mut tx, signed, now).await?;
                "device.evidence_observed"
            }
            PeerOperation::Advertise {
                binding_id,
                binding_version,
                published,
                forwarding_ready,
            } => {
                let binding=sqlx::query("SELECT version,approved FROM gateway_bindings WHERE mesh_id=$1 AND id=$2 AND peer_id=$3 FOR UPDATE")
                    .bind(mesh).bind(binding_id).bind(peer).fetch_optional(&mut *tx).await?.ok_or(StoreError::NotFound)?;
                if u64::try_from(binding.try_get::<i64, _>("version")?).ok()
                    != Some(*binding_version)
                    || (*published && !binding.try_get::<bool, _>("approved")?)
                    || (*forwarding_ready && !published)
                {
                    return Err(StoreError::Conflict);
                }
                sqlx::query("INSERT INTO route_advertisements(mesh_id,binding_id,peer_id,sequence,published,forwarding_ready,valid_until,binding_version)
                    VALUES($1,$2,$3,$4,$5,$6,clock_timestamp()+interval '90 seconds',$7) ON CONFLICT(mesh_id,binding_id) DO UPDATE SET
                    binding_version=EXCLUDED.binding_version,sequence=EXCLUDED.sequence,published=EXCLUDED.published,forwarding_ready=EXCLUDED.forwarding_ready,valid_until=EXCLUDED.valid_until,updated_at=clock_timestamp()")
                    .bind(mesh).bind(binding_id).bind(peer).bind(sequence).bind(published).bind(forwarding_ready).bind(i64::try_from(*binding_version).map_err(|_|StoreError::Invalid("binding version"))?).execute(&mut *tx).await?;
                sqlx::query(
                    "UPDATE meshes SET management_revision=management_revision+1 WHERE id=$1",
                )
                .bind(mesh)
                .execute(&mut *tx)
                .await?;
                "route.advertised"
            }
            PeerOperation::TargetHealth {
                binding_id,
                binding_version,
                resource_version,
                result,
            } => {
                let binding_version = i64::try_from(*binding_version)
                    .map_err(|_| StoreError::Invalid("binding version"))?;
                let resource_version = i64::try_from(*resource_version)
                    .map_err(|_| StoreError::Invalid("resource version"))?;
                // A route/target edit, withdrawal or delayed report cannot attest to current health.
                if now.abs_diff(command.issued_at) > 30 {
                    return Err(StoreError::Conflict);
                }
                let row=sqlx::query("SELECT b.version AS binding_version,r.version AS resource_version,r.definition FROM gateway_bindings b JOIN network_resources r ON r.mesh_id=b.mesh_id AND r.id=b.resource_id WHERE b.mesh_id=$1 AND b.id=$2 AND b.peer_id=$3 AND b.approved FOR SHARE OF b,r")
                    .bind(mesh).bind(binding_id).bind(peer).fetch_optional(&mut *tx).await?.ok_or(StoreError::Conflict)?;
                let definition: peerward_management::ResourceDefinition =
                    serde_json::from_value(row.try_get("definition")?)
                        .map_err(|_| StoreError::Invalid("resource definition"))?;
                if row.try_get::<i64, _>("binding_version")? != binding_version
                    || row.try_get::<i64, _>("resource_version")? != resource_version
                    || definition.health_probe.is_none()
                {
                    return Err(StoreError::Conflict);
                }
                let unchanged:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM target_health_observations WHERE mesh_id=$1 AND binding_id=$2 AND binding_version=$3 AND resource_version=$4 AND result=$5 AND valid_until>clock_timestamp())")
                    .bind(mesh).bind(binding_id).bind(binding_version).bind(resource_version).bind(result.as_str()).fetch_one(&mut *tx).await?;
                record_observation = !unchanged;
                sqlx::query("INSERT INTO target_health_observations(mesh_id,binding_id,binding_version,resource_version,credential_serial,sequence,result) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(mesh_id,binding_id) DO UPDATE SET binding_version=EXCLUDED.binding_version,resource_version=EXCLUDED.resource_version,credential_serial=EXCLUDED.credential_serial,sequence=EXCLUDED.sequence,result=EXCLUDED.result,observed_at=clock_timestamp(),valid_until=clock_timestamp()+interval '90 seconds'")
                    .bind(mesh).bind(binding_id).bind(binding_version).bind(resource_version).bind(command.credential_serial.into_uuid()).bind(sequence).bind(result.as_str()).execute(&mut *tx).await?;
                "target.health_observed"
            }
            PeerOperation::Applied {
                category,
                configuration_version,
                configuration_digest,
                lease_sequence,
                result,
                reason,
            } => {
                let lease_sequence = i64::try_from(*lease_sequence)
                    .map_err(|_| StoreError::Invalid("lease sequence"))?;
                let bytes:Vec<u8>=sqlx::query_scalar("SELECT body FROM signed_state_revisions WHERE mesh_id=$1 AND kind='configuration' AND revision=$2")
                    .bind(mesh).bind(lease_sequence).fetch_optional(&mut *tx).await?.ok_or(StoreError::NotFound)?;
                let delivery: ConfigurationDelivery = serde_json::from_slice(&bytes)
                    .map_err(|_| StoreError::Invalid("configuration"))?;
                if delivery.manifest.manifest.version != *configuration_version
                    || delivery.lease.lease.configuration_digest != *configuration_digest
                {
                    return Err(StoreError::Conflict);
                }
                sqlx::query("INSERT INTO configuration_receipts(mesh_id,peer_id,configuration_version,configuration_digest,lease_sequence,result,reason,category)
                    VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(mesh_id,peer_id,category) DO UPDATE SET configuration_version=EXCLUDED.configuration_version,
                    configuration_digest=EXCLUDED.configuration_digest,lease_sequence=EXCLUDED.lease_sequence,result=EXCLUDED.result,reason=EXCLUDED.reason,received_at=clock_timestamp()
                    WHERE configuration_receipts.lease_sequence<=EXCLUDED.lease_sequence")
                    .bind(mesh).bind(peer).bind(i64::try_from(*configuration_version).map_err(|_|StoreError::Invalid("configuration version"))?)
                    .bind(configuration_digest.as_slice()).bind(lease_sequence).bind(match result{ApplicationResult::Applied=>"applied",ApplicationResult::Rejected=>"rejected"})
                    .bind(reason).bind(category.as_str()).execute(&mut *tx).await?;
                "configuration.receipt"
            }
        };
        sqlx::query(
            "UPDATE peer_management_floors SET sequence=$3 WHERE mesh_id=$1 AND peer_id=$2",
        )
        .bind(mesh)
        .bind(peer)
        .bind(sequence)
        .execute(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO peer_management_requests(request_id,mesh_id,peer_id,sequence,digest) VALUES($1,$2,$3,$4,$5)")
            .bind(command.request_id).bind(mesh).bind(peer).bind(sequence).bind(digest.as_slice()).execute(&mut *tx).await?;
        if record_observation {
            append_audit(
                &mut tx,
                Some(command.mesh_id),
                &command.peer_id.to_string(),
                action,
                "peer",
                Some(peer),
                "success",
                json!({"request_id":command.request_id,"sequence":sequence}),
            )
            .await?;
            append_event(
                &mut tx,
                Some(command.mesh_id),
                action,
                "peer",
                Some(peer),
                json!({"sequence":sequence}),
            )
            .await?;
        }
        tx.commit().await?;
        Ok(true)
    }
}
