async fn verify_audit_authority_revocation(
    store: &Store,
    mesh: peerward_types::MeshId,
    peer: peerward_types::PeerId,
    root: &RootSigningKey,
    previous: &JoinIssuerConfig,
    identity: &IdentitySigningKey,
) {
    async fn submit(
        store: &Store,
        issuers: &[JoinIssuerConfig],
        mesh: peerward_types::MeshId,
        peer: peerward_types::PeerId,
        recipient: &[u8; 32],
        identity: &IdentitySigningKey,
    ) -> usize {
        let batch = AuditBatchV1 {
            major: PROTOCOL_MAJOR,
            schema_version: 1,
            mesh_id: mesh.as_bytes().to_vec(),
            source_peer: peer.as_bytes().to_vec(),
            batch_id: Uuid::new_v4().as_bytes().to_vec(),
            observed_at: u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).unwrap(),
            events: vec![AuditEventV1 {
                direction: AuditDirectionV1::Egress as i32,
                reason: AuditReasonV1::PolicyDenied as i32,
                count: 1,
            }],
            runtime_health: None,
        };
        let envelope = seal_audit_batch(&batch, recipient, identity, OsRng)
            .unwrap()
            .encode_to_vec();
        assert!(
            store
                .queue_encrypted_audit(mesh, peer, &envelope)
                .await
                .unwrap()
        );
        collect_peer_audits(store, issuers).await.unwrap()
    }
    let now = OffsetDateTime::now_utc();
    let seconds = u64::try_from(now.unix_timestamp()).unwrap();
    let next = AuthoritySigningKey::from_bytes(&[47; 32]);
    let serial = CredentialSerial::new();
    let certificate = root
        .certify(UnsignedAuthority {
            mesh_id: mesh,
            serial,
            public_key: next.public_key(),
            not_before: UnixTime(seconds - 60),
            not_after: UnixTime(seconds + 86_400),
        })
        .unwrap();
    let authority_id = store
        .stage_authority(
            &NewAuthority {
                mesh_id: mesh,
                serial,
                public_key: next.public_key().to_vec(),
                not_before: now - Duration::minutes(1),
                not_after: now + Duration::days(1),
                replaces: Some(previous.authority_id),
                overlap_deadline: Some(now + Duration::hours(1)),
                certificate: certificate.encode(),
            },
            "test",
        )
        .await
        .unwrap();
    store
        .transition_authority(mesh, serial, Lifecycle::Active, "test")
        .await
        .unwrap();
    let current = JoinIssuerConfig {
        authority_id,
        authority_private_key: Some(hex::encode([47; 32])),
        authority_certificate: URL_SAFE_NO_PAD.encode(certificate.encode()),
        ..previous.clone()
    };
    let issuers = [previous.clone(), current];
    let recipient = peerward_wire::audit_recipient_public(
        &hex::decode(&previous.audit_private_key)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(
        submit(store, &issuers, mesh, peer, &recipient, identity).await,
        1,
        "unexpired Authority overlap must still authenticate the Peer audit"
    );
    sqlx::query("UPDATE mesh_authorities SET overlap_deadline=clock_timestamp()-interval '1 second' WHERE id=$1")
        .bind(previous.authority_id).execute(store.pool()).await.unwrap();
    assert_eq!(
        submit(store, &issuers, mesh, peer, &recipient, identity).await,
        0,
        "expired Authority overlap must not authenticate an audit even before expiry reconciliation"
    );
    let old = AuthorityCertificate::decode(
        &URL_SAFE_NO_PAD
            .decode(&previous.authority_certificate)
            .unwrap(),
    )
    .unwrap();
    store
        .transition_authority(mesh, old.serial, Lifecycle::Revoked, "test")
        .await
        .unwrap();
    assert_eq!(
        submit(store, &issuers, mesh, peer, &recipient, identity).await,
        0,
        "known revoked Authority must not authenticate a fresh audit"
    );
}
