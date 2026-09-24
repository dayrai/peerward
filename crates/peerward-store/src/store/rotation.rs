impl Store {
    /// Persists one in-band request only after its current credential is verified in storage.
    pub async fn request_peer_rotation(
        &self,
        id: RotationId,
        mesh_id: MeshId,
        peer_id: PeerId,
        authenticated_serial: CredentialSerial,
        identity_public_key: [u8; 32],
        session_public_key: [u8; 32],
        wireguard_public_key: [u8; 32],
        signature: [u8; 64],
    ) -> Result<(), StoreError> {
        let mut transaction = self.pool.begin().await?;
        if !lock_enabled_peer(&mut transaction, mesh_id, peer_id).await? {
            return Err(StoreError::Conflict);
        }
        let current_identity: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT c.identity_public_key FROM peer_credentials c JOIN peers p
               ON p.mesh_id=c.mesh_id AND p.id=c.peer_id
             WHERE c.mesh_id=$1 AND c.peer_id=$2 AND c.serial=$3
               AND c.wireguard_public_key IS NOT NULL AND c.lifecycle IN ('active','overlap')
               AND (c.lifecycle='active' OR c.overlap_deadline>clock_timestamp())
               AND c.not_before<=clock_timestamp() AND c.not_after>clock_timestamp()
               AND p.administrative_state='enabled' FOR SHARE",
        )
        .bind(mesh_id.into_uuid())
        .bind(peer_id.into_uuid())
        .bind(authenticated_serial.into_uuid())
        .fetch_optional(&mut *transaction)
        .await?;
        let current_identity: [u8; 32] = current_identity
            .ok_or(StoreError::Conflict)?
            .try_into()
            .map_err(|_| StoreError::Invalid("current identity key"))?;
        verify_rotation_request(
            &current_identity,
            &RotationRequestProof {
                mesh_id,
                peer_id,
                rotation_id: id,
                current_serial: authenticated_serial,
                identity_public_key,
                session_public_key,
                wireguard_public_key,
            },
            &signature,
        )
        .map_err(|_| StoreError::Conflict)?;
        // A retried request may name its own issued key, but a new generation
        // cannot reuse any previously registered data key in this Mesh.
        let reused: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM peer_credentials c WHERE c.mesh_id=$1
               AND c.wireguard_public_key=$2 AND NOT EXISTS (
                 SELECT 1 FROM peer_credential_rotation_requests r
                 WHERE r.id=$3 AND r.mesh_id=c.mesh_id AND r.issued_serial=c.serial))
               OR EXISTS(SELECT 1 FROM peer_credential_rotation_requests
                 WHERE mesh_id=$1 AND requested_wireguard_public_key=$2 AND id<>$3)",
        ).bind(mesh_id.into_uuid()).bind(wireguard_public_key.to_vec()).bind(id.into_uuid())
            .fetch_one(&mut *transaction).await?;
        if reused { return Err(StoreError::Conflict); }
        let mut activation_challenge = [0_u8; 32];
        OsRng.fill_bytes(&mut activation_challenge);
        let changed = sqlx::query(
            "INSERT INTO peer_credential_rotation_requests
             (id,mesh_id,peer_id,authenticated_serial,requested_identity_public_key,
              requested_session_public_key,request_signature,activation_challenge,requested_wireguard_public_key)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (id) DO NOTHING",
        )
        .bind(id.into_uuid())
        .bind(mesh_id.into_uuid())
        .bind(peer_id.into_uuid())
        .bind(authenticated_serial.into_uuid())
        .bind(identity_public_key.to_vec())
        .bind(session_public_key.to_vec())
        .bind(signature.to_vec())
        .bind(activation_challenge.to_vec())
        .bind(wireguard_public_key.to_vec())
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed == 0 {
            let exact: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM peer_credential_rotation_requests
                 WHERE id=$1 AND mesh_id=$2 AND peer_id=$3 AND authenticated_serial=$4
                   AND requested_identity_public_key=$5 AND requested_session_public_key=$6
                   AND request_signature=$7 AND requested_wireguard_public_key=$8)",
            )
            .bind(id.into_uuid())
            .bind(mesh_id.into_uuid())
            .bind(peer_id.into_uuid())
            .bind(authenticated_serial.into_uuid())
            .bind(identity_public_key.to_vec())
            .bind(session_public_key.to_vec())
            .bind(signature.to_vec())
            .bind(wireguard_public_key.to_vec())
            .fetch_one(&mut *transaction)
            .await?;
            if !exact {
                return Err(StoreError::Conflict);
            }
        } else {
            append_event(
                &mut transaction,
                Some(mesh_id),
                "peer_credential.rotation_requested",
                "peer_credential",
                Some(id.into_uuid()),
                json!({"peer_id":peer_id,"authenticated_serial":authenticated_serial}),
            )
            .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Returns bounded requests for the mesh online Authority worker.
    pub async fn pending_peer_rotations(
        &self,
        mesh_id: MeshId,
        limit: u16,
    ) -> Result<Vec<PendingPeerRotation>, StoreError> {
        validate_limit(limit)?;
        let rows = sqlx::query(
            "SELECT id,peer_id,authenticated_serial,requested_identity_public_key,
                    requested_session_public_key,activation_challenge,requested_wireguard_public_key
             FROM peer_credential_rotation_requests
             WHERE mesh_id=$1 AND status='pending' AND requested_wireguard_public_key IS NOT NULL ORDER BY created_at,id LIMIT $2",
        )
        .bind(mesh_id.into_uuid())
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                Ok(PendingPeerRotation {
                    id: RotationId::from_uuid(row.try_get("id")?)
                        .map_err(|_| StoreError::Invalid("rotation ID"))?,
                    mesh_id,
                    peer_id: PeerId::from_uuid(row.try_get("peer_id")?)
                        .map_err(|_| StoreError::Invalid("peer ID"))?,
                    authenticated_serial: CredentialSerial::from_uuid(
                        row.try_get("authenticated_serial")?,
                    )
                    .map_err(|_| StoreError::Invalid("credential serial"))?,
                    identity_public_key: row
                        .try_get::<Vec<u8>, _>("requested_identity_public_key")?
                        .try_into()
                        .map_err(|_| StoreError::Invalid("rotation identity key"))?,
                    session_public_key: row
                        .try_get::<Vec<u8>, _>("requested_session_public_key")?
                        .try_into()
                        .map_err(|_| StoreError::Invalid("rotation session key"))?,
                    activation_challenge: row
                        .try_get::<Vec<u8>, _>("activation_challenge")?
                        .try_into()
                        .map_err(|_| StoreError::Invalid("rotation challenge"))?,
                    wireguard_public_key: row
                        .try_get::<Vec<u8>, _>("requested_wireguard_public_key")?
                        .try_into()
                        .map_err(|_| StoreError::Invalid("rotation WireGuard key"))?,
                })
            })
            .collect()
    }

    /// Commits an Authority-issued staged credential and its retriable delivery body atomically.
    pub async fn issue_peer_rotation(
        &self,
        request: &PendingPeerRotation,
        issued: &IssuedPeerCredential,
        encoded_credential: &[u8],
    ) -> Result<(), StoreError> {
        if issued.signature.len() != 64
            || encoded_credential.is_empty()
            || issued.not_before >= issued.not_after
        {
            return Err(StoreError::Invalid("issued rotation credential"));
        }
        let mut transaction = self.pool.begin().await?;
        if !lock_enabled_peer(&mut transaction, request.mesh_id, request.peer_id).await? {
            return Ok(());
        }
        let locked: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM peer_credential_rotation_requests
             WHERE id=$1 AND mesh_id=$2 AND peer_id=$3 AND status='pending' FOR UPDATE)",
        )
        .bind(request.id.into_uuid())
        .bind(request.mesh_id.into_uuid())
        .bind(request.peer_id.into_uuid())
        .fetch_one(&mut *transaction)
        .await?;
        if !locked {
            transaction.rollback().await?;
            return Ok(());
        }
        let authority_valid: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM mesh_authorities WHERE id=$1 AND mesh_id=$2
             AND lifecycle IN ('active','overlap')
             AND ($3::bytea IS NULL OR public_key=$3)
             AND not_before<=clock_timestamp() AND not_after>clock_timestamp())",
        )
        .bind(issued.authority_id)
        .bind(request.mesh_id.into_uuid())
        .bind(&issued.authority_public_key)
        .fetch_one(&mut *transaction)
        .await?;
        if !authority_valid {
            return Err(StoreError::Conflict);
        }
        sqlx::query(
            "INSERT INTO peer_credentials
             (id,mesh_id,peer_id,authority_id,serial,identity_public_key,public_key,
              not_before,not_after,lifecycle,signature,wireguard_public_key)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'staged',$10,$11)",
        )
        .bind(Uuid::new_v4())
        .bind(request.mesh_id.into_uuid())
        .bind(request.peer_id.into_uuid())
        .bind(issued.authority_id)
        .bind(issued.serial.into_uuid())
        .bind(request.identity_public_key.to_vec())
        .bind(request.session_public_key.to_vec())
        .bind(issued.not_before)
        .bind(issued.not_after)
        .bind(&issued.signature)
        .bind(request.wireguard_public_key.to_vec())
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE peer_credential_rotation_requests SET status='issued',issued_serial=$1,
             issued_credential=$2,issued_at=clock_timestamp() WHERE id=$3 AND status='pending'",
        )
        .bind(issued.serial.into_uuid())
        .bind(encoded_credential)
        .bind(request.id.into_uuid())
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE meshes SET directory_revision=directory_revision+1,
             updated_at=clock_timestamp() WHERE id=$1",
        )
        .bind(request.mesh_id.into_uuid())
        .execute(&mut *transaction)
        .await?;
        append_event(
            &mut transaction,
            Some(request.mesh_id),
            "peer_credential.rotation_issued",
            "peer_credential",
            Some(request.id.into_uuid()),
            json!({"peer_id":request.peer_id,"serial":issued.serial}),
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Retrieves an issued replacement repeatedly until the new key authenticates successfully.
    pub async fn issued_peer_rotation(
        &self,
        mesh_id: MeshId,
        peer_id: PeerId,
        authenticated_serial: CredentialSerial,
    ) -> Result<Option<IssuedPeerRotation>, StoreError> {
        let row = sqlx::query(
            "SELECT id,issued_serial,issued_credential,activation_challenge
             FROM peer_credential_rotation_requests
             WHERE mesh_id=$1 AND peer_id=$2 AND authenticated_serial=$3
               AND status IN ('issued','activated')
             ORDER BY issued_at,id LIMIT 1",
        )
        .bind(mesh_id.into_uuid())
        .bind(peer_id.into_uuid())
        .bind(authenticated_serial.into_uuid())
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let rotation = IssuedPeerRotation {
                id: RotationId::from_uuid(row.try_get("id")?)
                    .map_err(|_| StoreError::Invalid("rotation ID"))?,
                serial: CredentialSerial::from_uuid(row.try_get("issued_serial")?)
                    .map_err(|_| StoreError::Invalid("credential serial"))?,
                credential: row.try_get("issued_credential")?,
                activation_challenge: row
                    .try_get::<Vec<u8>, _>("activation_challenge")?
                    .try_into()
                    .map_err(|_| StoreError::Invalid("rotation challenge"))?,
        };
        Ok(Some(rotation))
    }

    /// Activates an issued replacement only after the new identity proves possession.
    pub async fn activate_peer_rotation(
        &self,
        mesh_id: MeshId,
        peer_id: PeerId,
        rotation_id: RotationId,
        serial: CredentialSerial,
        signature: [u8; 64],
    ) -> Result<bool, StoreError> {
        let mut transaction = self.pool.begin().await?;
        if !lock_enabled_peer(&mut transaction, mesh_id, peer_id).await? {
            return Ok(false);
        }
        let request = sqlx::query(
            "SELECT status,requested_identity_public_key,activation_challenge,
                    activation_signature
             FROM peer_credential_rotation_requests
             WHERE id=$1 AND mesh_id=$2 AND peer_id=$3 AND issued_serial=$4
               AND status IN ('issued','activated') FOR UPDATE",
        )
        .bind(rotation_id.into_uuid())
        .bind(mesh_id.into_uuid())
        .bind(peer_id.into_uuid())
        .bind(serial.into_uuid())
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(request) = request else {
            return Ok(false);
        };
        let status: String = request.try_get("status")?;
        if status == "activated" {
            let committed: Option<Vec<u8>> = request.try_get("activation_signature")?;
            transaction.rollback().await?;
            return Ok(committed.as_deref() == Some(signature.as_slice()));
        }
        let identity_public_key: [u8; 32] = request
            .try_get::<Vec<u8>, _>("requested_identity_public_key")?
            .try_into()
            .map_err(|_| StoreError::Invalid("rotation identity key"))?;
        let challenge: [u8; 32] = request
            .try_get::<Vec<u8>, _>("activation_challenge")?
            .try_into()
            .map_err(|_| StoreError::Invalid("rotation challenge"))?;
        verify_rotation_activation(
            &identity_public_key,
            &RotationActivationProof {
                mesh_id,
                peer_id,
                rotation_id,
                issued_serial: serial,
                challenge,
            },
            &signature,
        )
        .map_err(|_| StoreError::Conflict)?;
        let replacement_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM peer_credentials WHERE mesh_id=$1 AND peer_id=$2 AND serial=$3
             AND lifecycle='staged' FOR UPDATE",
        )
        .bind(mesh_id.into_uuid())
        .bind(peer_id.into_uuid())
        .bind(serial.into_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(StoreError::Conflict)?;
        // Keep at most one previous generation. Retirement is exact and is
        // published by the same revocation/directory revision transaction.
        sqlx::query("UPDATE peer_credentials SET lifecycle='revoked'
            WHERE mesh_id=$1 AND peer_id=$2 AND lifecycle='overlap'")
            .bind(mesh_id.into_uuid()).bind(peer_id.into_uuid())
            .execute(&mut *transaction).await?;
        let previous = sqlx::query(
            "UPDATE peer_credentials SET lifecycle='overlap',replacement_id=$1,
             overlap_deadline=LEAST(not_after,clock_timestamp()+make_interval(
               secs => LEAST(m.rotation_overlap_seconds,604800)::double precision))
             FROM meshes m WHERE peer_credentials.mesh_id=$2 AND peer_id=$3
               AND peer_credentials.lifecycle='active' AND m.id=peer_credentials.mesh_id",
        )
        .bind(replacement_id)
        .bind(mesh_id.into_uuid())
        .bind(peer_id.into_uuid())
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if previous != 1 {
            return Err(StoreError::Conflict);
        }
        let activated = sqlx::query(
            "UPDATE peer_credentials SET lifecycle='active',overlap_deadline=NULL
             WHERE id=$1 AND mesh_id=$2 AND lifecycle='staged'",
        )
        .bind(replacement_id)
        .bind(mesh_id.into_uuid())
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if activated != 1 {
            return Err(StoreError::Conflict);
        }
        sqlx::query(
            "UPDATE peer_credential_rotation_requests SET status='activated',
             activation_signature=$1,activated_at=clock_timestamp()
             WHERE id=$2 AND status='issued'",
        )
        .bind(signature.to_vec())
        .bind(rotation_id.into_uuid())
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE meshes SET directory_revision=directory_revision+1,
             service_revision=service_revision+1,revocation_revision=revocation_revision+1,
             updated_at=clock_timestamp() WHERE id=$1",
        )
        .bind(mesh_id.into_uuid())
        .execute(&mut *transaction)
        .await?;
        mutation_records(
            &mut transaction,
            mesh_id,
            "peer-rotation",
            "peer_credential.rotation_activate",
            "peer_credential.rotation_activated",
            "peer_credential",
            replacement_id,
            json!({"peer_id":peer_id,"serial":serial,"rotation_id":rotation_id}),
        )
        .await?;
        transaction.commit().await?;
        Ok(true)
    }
}
