use std::env;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey as IdentitySigningKey;
use http_body_util::BodyExt as _;
use peerward_control::{
    AuthConfig, JoinIssuerConfig, collect_peer_audits, publish_enrollment_state,
    router_with_enrollment,
};
use peerward_credentials::{
    AuthorityCertificate, AuthoritySigningKey, DistributionCertificate, JoinClaimProof,
    RootPublicKey, RootSigningKey, RotationActivationProof, RotationRequestProof,
    SignedAuthorityBundle, SubjectCredential, TrustSet, UnsignedAuthority, sign_join_claim,
    sign_rotation_activation, sign_rotation_request,
};
use peerward_directory::{
    DirectoryPublicKey, decode_peer_directory, decode_policy, decode_relay_directory,
    decode_revocations,
};
use peerward_service::{RemoteServiceTable, SignedRemoteServiceSnapshot};
use peerward_store::{
    DefaultPolicy, Lifecycle, NewAuthority, NewMesh, SignedStateKind, Store, secret_digest,
};
use peerward_types::{CredentialSerial, RotationId, UnixTime};
use peerward_wire::{
    AuditBatchV1, AuditDirectionV1, AuditEventV1, AuditReasonV1, PROTOCOL_MAJOR,
    RuntimeDegradedReasonV1, RuntimeHealthV1, seal_audit_batch,
};
use prost::Message as _;
use rand::rngs::OsRng;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use time::{Duration, OffsetDateTime};
use tower::ServiceExt as _;
use uuid::Uuid;

#[path = "join_cases/console_renewal.rs"]
mod console_renewal;

fn database_url() -> String {
    let value = env::var("PEERWARD_TEST_DATABASE_URL")
        .expect("PEERWARD_TEST_DATABASE_URL must identify an ephemeral PostgreSQL database");
    assert!(
        value
            .parse::<sqlx::postgres::PgConnectOptions>()
            .is_ok_and(|options| options.get_database() == Some("peerward_test")),
        "integration test refuses a database not named peerward_test"
    );
    value
}

#[tokio::test]
async fn signed_dual_key_claim_returns_an_exact_rooted_native_trust_bundle() {
    let store = Store::connect(&database_url(), 8).await.unwrap();
    sqlx::raw_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        .execute(store.pool())
        .await
        .unwrap();
    store.migrate().await.unwrap();
    let mesh = store
        .create_mesh(
            &NewMesh {
                name: "mobile-test".into(),
                address_cidr: "10.94.0.0/24".parse().unwrap(),
                gateway: "10.94.0.1".parse().unwrap(),
                dns_suffix: "mobile.test".into(),
                mtu: 1380,
                reserved: Vec::new(),
                default_policy: DefaultPolicy::Deny,
                quarantine_seconds: 60,
                rotation_overlap_seconds: 3_600,
            },
            "admin",
        )
        .await
        .unwrap();
    let root = RootSigningKey::from_bytes(&[11; 32]);
    let authority = AuthoritySigningKey::from_bytes(&[12; 32]);
    let now = OffsetDateTime::now_utc();
    let now_seconds = u64::try_from(now.unix_timestamp()).unwrap();
    let authority_serial = CredentialSerial::new();
    let certificate = root
        .certify(UnsignedAuthority {
            mesh_id: mesh.id,
            serial: authority_serial,
            public_key: authority.public_key(),
            not_before: UnixTime(now_seconds - 60),
            not_after: UnixTime(now_seconds + 86_400),
        })
        .unwrap();
    let authority_id = store
        .stage_authority(
            &NewAuthority {
                mesh_id: mesh.id,
                serial: authority_serial,
                public_key: authority.public_key().to_vec(),
                not_before: now - Duration::minutes(1),
                not_after: now + Duration::days(1),
                replaces: None,
                overlap_deadline: None,
                certificate: certificate.encode(),
            },
            "admin",
        )
        .await
        .unwrap();
    store
        .transition_authority(mesh.id, authority_serial, Lifecycle::Active, "admin")
        .await
        .unwrap();
    let token = b"android-public-claim-ticket-32bytes";
    store
        .create_join_ticket(mesh.id, token, now + Duration::minutes(5), "operator")
        .await
        .unwrap();
    let issuer_config = JoinIssuerConfig {
        mesh_id: mesh.id,
        authority_id,
        authority_private_key: Some(hex::encode([12; 32])),
        root_public_key: hex::encode(root.public_key().to_bytes()),
        authority_certificate: URL_SAFE_NO_PAD.encode(certificate.encode()),
        directory_private_key: hex::encode([13; 32]),
        service_private_key: hex::encode([14; 32]),
        audit_private_key: hex::encode([15; 32]),
        credential_validity_seconds: 3_600,
        stun_servers: vec!["stun.example:3478".parse().unwrap()],
    };
    let application = router_with_enrollment(
        store.clone(),
        AuthConfig {
            oidc: None,
            development_bearer_token: Some("rotation-admin".into()),
            bootstrap_token: None,
        },
        std::slice::from_ref(&issuer_config),
    )
    .unwrap();
    let policy_revision = store.mesh(mesh.id).await.unwrap().policy_revision;
    let validation = application
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/meshes/{}/policy/validate", mesh.id))
                .header("authorization", "Bearer rotation-admin")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"revision": policy_revision + 1, "default_action": "deny", "rules": []})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(validation.status(), StatusCode::OK);
    let validation: Value =
        serde_json::from_slice(&validation.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(validation["valid"], true);
    assert_eq!(validation["canonical_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(
        store.mesh(mesh.id).await.unwrap().policy_revision,
        policy_revision,
        "editor validation must not mutate authoritative policy state",
    );
    let noise_public = [21; 32];
    let identity = IdentitySigningKey::from_bytes(&[20; 32]);
    let identity_public = identity.verifying_key().to_bytes();
    let claim_id = Uuid::new_v4();
    let nonce = [31; 32];
    let claim_signature = sign_join_claim(
        &identity.to_bytes(),
        &JoinClaimProof {
            schema_version: 2,
            claim_id,
            ticket_digest: secret_digest(token),
            identity_public_key: identity_public,
            session_public_key: noise_public,
            client_version: "1.0.0-test",
            supported_wire_major: peerward_wire::PROTOCOL_MAJOR,
            nonce: &nonce,
            device_name: "Alice's Android Phone",
            device_model: "emulator",
            platform: "android",
            platform_version: "34",
            wireguard_public_key: [0x77; 32],
        },
    )
    .unwrap();
    let claim_body = json!({
        "schema_version": 2,
        "claim_id": claim_id,
        "identity_public_key": URL_SAFE_NO_PAD.encode(identity_public),
        "session_public_key": URL_SAFE_NO_PAD.encode(noise_public),
        "wireguard_public_key": URL_SAFE_NO_PAD.encode([0x77; 32]),
        "client_version": "1.0.0-test",
        "supported_wire_major": peerward_wire::PROTOCOL_MAJOR,
        "device_name": "Alice's Android Phone",
        "device_model": "emulator",
        "platform": "android",
        "platform_version": "34",
        "nonce": URL_SAFE_NO_PAD.encode(nonce),
        "signature": URL_SAFE_NO_PAD.encode(claim_signature),
    })
    .to_string();
    let request = Request::post(format!(
        "/api/v1/join/{}/claim",
        URL_SAFE_NO_PAD.encode(token)
    ))
    .header("content-type", "application/json")
    .body(Body::from(claim_body.clone()))
    .unwrap();
    let response = application.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let replay = application
        .clone()
        .oneshot(
            Request::post(format!(
                "/api/v1/join/{}/claim",
                URL_SAFE_NO_PAD.encode(token)
            ))
            .header("content-type", "application/json")
            .body(Body::from(claim_body))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::CREATED);
    assert_eq!(
        replay.into_body().collect().await.unwrap().to_bytes(),
        bytes
    );
    let response: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(response["mesh_id"], mesh.id.to_string());
    assert_eq!(response["mesh_name"], "mobile-test");
    let primary: ipnet::IpNet = response["address"].as_str().unwrap().parse().unwrap();
    let secondary: ipnet::IpNet = response["secondary_address"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(primary.addr().is_ipv4() && secondary.addr().is_ipv6());
    assert!(mesh.secondary_cidr.contains(&secondary.addr()));
    assert_eq!(
        response["routes"],
        json!([
            mesh.address_cidr.to_string(),
            mesh.secondary_cidr.to_string()
        ])
    );
    let assigned: Vec<String> = sqlx::query_scalar("SELECT host(address) FROM peer_addresses WHERE mesh_id=$1 AND state='active' ORDER BY family(address)")
        .bind(mesh.id.into_uuid()).fetch_all(store.pool()).await.unwrap();
    assert_eq!(
        assigned,
        vec![primary.addr().to_string(), secondary.addr().to_string()]
    );
    assert_eq!(response["dns_suffix"], "mobile.test");
    assert_eq!(response["relays"], json!([]));
    let returned_root: [u8; 32] = URL_SAFE_NO_PAD
        .decode(response["root_public_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let returned_certificate = AuthorityCertificate::decode(
        &URL_SAFE_NO_PAD
            .decode(response["authority_certificates"][0].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    let credential = SubjectCredential::decode(
        &URL_SAFE_NO_PAD
            .decode(response["credential"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    let mut trust = TrustSet::new(RootPublicKey::from_bytes(&returned_root).unwrap(), mesh.id);
    trust
        .add_authority(returned_certificate, UnixTime(now_seconds))
        .unwrap();
    trust
        .verify_subject(&credential, UnixTime(now_seconds))
        .unwrap();
    let distribution = DistributionCertificate::decode(
        &URL_SAFE_NO_PAD
            .decode(response["distribution_certificate"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    trust
        .verify_distribution(&distribution, UnixTime(now_seconds))
        .unwrap();
    assert_eq!(
        URL_SAFE_NO_PAD.encode(distribution.directory_public_key),
        response["distribution_public_key"]
    );
    assert_eq!(
        URL_SAFE_NO_PAD.encode(distribution.service_public_key),
        response["service_public_key"]
    );
    assert_eq!(
        URL_SAFE_NO_PAD.encode(distribution.audit_public_key),
        response["audit_public_key"]
    );
    assert_eq!(credential.public_noise_key, noise_public);
    assert_eq!(credential.identity_public_key, identity_public);

    assert_eq!(
        publish_enrollment_state(&store, std::slice::from_ref(&issuer_config))
            .await
            .unwrap(),
        8
    );
    assert_eq!(
        publish_enrollment_state(&store, std::slice::from_ref(&issuer_config))
            .await
            .unwrap(),
        0
    );
    let authorities = store
        .latest_signed_state(mesh.id, SignedStateKind::Authorities)
        .await
        .unwrap();
    let authorities = SignedAuthorityBundle::decode(&authorities.body).unwrap();
    trust
        .install_authority_bundle(&authorities, UnixTime(now_seconds))
        .unwrap();
    assert_eq!(
        trust.authority_revision(),
        Some(authorities.bundle.revision)
    );
    let directory_key = DirectoryPublicKey::from_bytes(&distribution.directory_public_key).unwrap();
    let peers = store
        .latest_signed_state(mesh.id, SignedStateKind::Peers)
        .await
        .unwrap();
    let peers = decode_peer_directory(&peers.body).unwrap();
    directory_key.verify_peers(&peers, mesh.id, None).unwrap();
    assert_eq!(peers.directory.entries.len(), 1);
    assert_eq!(
        peers.directory.entries[0].entry.secondary_address,
        Some(secondary.addr())
    );
    let peer_id = match credential.subject {
        peerward_credentials::SubjectId::Peer(peer) => peer,
        peerward_credentials::SubjectId::Relay(_) => panic!("join returned relay credential"),
    };
    assert_eq!(peers.directory.entries[0].entry.peer_id, peer_id);
    let expected_name = format!(
        "alices-android-phone-{}",
        hex::encode(&Sha256::digest(nonce)[..6]),
    );
    assert_eq!(
        peers.directory.entries[0].entry.labels.get("name"),
        Some(&expected_name),
    );

    verify_management_receipts(
        &store,
        &application,
        &issuer_config,
        mesh.id,
        peer_id,
        &credential,
        &identity,
    )
    .await;
    verify_device_conditions(
        &store,
        &application,
        mesh.id,
        peer_id,
        &credential,
        &identity,
        &issuer_config,
    )
    .await;

    let audit_recipient: [u8; 32] = URL_SAFE_NO_PAD
        .decode(response["audit_public_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let batch_id = Uuid::new_v4();
    let audit = AuditBatchV1 {
        major: PROTOCOL_MAJOR,
        schema_version: 1,
        mesh_id: mesh.id.as_bytes().to_vec(),
        source_peer: peer_id.as_bytes().to_vec(),
        batch_id: batch_id.as_bytes().to_vec(),
        observed_at: u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).unwrap(),
        events: vec![AuditEventV1 {
            direction: AuditDirectionV1::Ingress as i32,
            reason: AuditReasonV1::PolicyDenied as i32,
            count: 3,
        }],
        runtime_health: None,
    };
    let encrypted = seal_audit_batch(&audit, &audit_recipient, &identity, OsRng)
        .unwrap()
        .encode_to_vec();
    assert!(
        store
            .queue_encrypted_audit(mesh.id, peer_id, &encrypted)
            .await
            .unwrap()
    );
    assert_eq!(
        collect_peer_audits(&store, std::slice::from_ref(&issuer_config))
            .await
            .unwrap(),
        1
    );
    let stored_audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE mesh_id=$1 AND target_id=$2
           AND action='peer.security_event' AND metadata->>'batch_id'=$3",
    )
    .bind(mesh.id.into_uuid())
    .bind(peer_id.into_uuid())
    .bind(batch_id.to_string())
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(stored_audits, 1);
    assert!(
        store
            .queue_encrypted_audit(mesh.id, peer_id, &encrypted)
            .await
            .unwrap()
    );
    assert_eq!(
        collect_peer_audits(&store, std::slice::from_ref(&issuer_config))
            .await
            .unwrap(),
        0,
        "a replayed end-to-end batch must not duplicate immutable audit rows",
    );

    let health = AuditBatchV1 {
        major: PROTOCOL_MAJOR,
        schema_version: 1,
        mesh_id: mesh.id.as_bytes().to_vec(),
        source_peer: peer_id.as_bytes().to_vec(),
        batch_id: Uuid::new_v4().as_bytes().to_vec(),
        observed_at: u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).unwrap(),
        events: Vec::new(),
        runtime_health: Some(RuntimeHealthV1 {
            sequence: 1,
            direct_path_count: 2,
            relay_packets: 30,
            direct_packets: 70,
            degraded_reasons: vec![RuntimeDegradedReasonV1::DnsDegraded as i32],
            signed_revision: 11,
        }),
    };
    let encrypted_health = seal_audit_batch(&health, &audit_recipient, &identity, OsRng)
        .unwrap()
        .encode_to_vec();
    store
        .queue_encrypted_audit(mesh.id, peer_id, &encrypted_health)
        .await
        .unwrap();
    assert_eq!(
        collect_peer_audits(&store, std::slice::from_ref(&issuer_config))
            .await
            .unwrap(),
        1
    );
    let current_health: (i64, i32, Vec<String>) = sqlx::query_as(
        "SELECT sequence,direct_path_count,degraded_reasons
         FROM current_peer_runtime_health WHERE mesh_id=$1 AND peer_id=$2",
    )
    .bind(mesh.id.into_uuid())
    .bind(peer_id.into_uuid())
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(current_health, (1, 2, vec!["dns_degraded".to_owned()]));

    let relays = store
        .latest_signed_state(mesh.id, SignedStateKind::Relays)
        .await
        .unwrap();
    directory_key
        .verify_relays(
            &decode_relay_directory(&relays.body).unwrap(),
            mesh.id,
            None,
        )
        .unwrap();
    let policy = store
        .latest_signed_state(mesh.id, SignedStateKind::Policy)
        .await
        .unwrap();
    directory_key
        .verify_policy(&decode_policy(&policy.body).unwrap(), mesh.id, None)
        .unwrap();
    let revocations = store
        .latest_signed_state(mesh.id, SignedStateKind::Revocations)
        .await
        .unwrap();
    directory_key
        .verify_revocations(
            &decode_revocations(&revocations.body).unwrap(),
            mesh.id,
            None,
        )
        .unwrap();
    let services = store
        .latest_signed_state(mesh.id, SignedStateKind::Services)
        .await
        .unwrap();
    let services: SignedRemoteServiceSnapshot = serde_json::from_slice(&services.body).unwrap();
    let mut table = RemoteServiceTable::new(
        mesh.id,
        peerward_service::ServiceSnapshotVerifier::from_bytes(&distribution.service_public_key)
            .unwrap(),
    );
    table.reconcile(&services).unwrap();

    let console_request =
        console_renewal::begin(&store, &application, mesh.id, peer_id, credential.serial).await;
    let rotation_id = RotationId::new();
    let replacement_identity = IdentitySigningKey::from_bytes(&[22; 32]);
    let replacement_identity_public = replacement_identity.verifying_key().to_bytes();
    let replacement_session_public = [23; 32];
    let rotation_signature = sign_rotation_request(
        &identity.to_bytes(),
        &RotationRequestProof {
            mesh_id: mesh.id,
            peer_id,
            rotation_id,
            current_serial: credential.serial,
            identity_public_key: replacement_identity_public,
            session_public_key: replacement_session_public,
            wireguard_public_key: [0x78; 32],
        },
    )
    .unwrap();
    store
        .request_peer_rotation(
            rotation_id,
            mesh.id,
            peer_id,
            credential.serial,
            replacement_identity_public,
            replacement_session_public,
            [0x78; 32],
            rotation_signature,
        )
        .await
        .unwrap();
    assert!(
        publish_enrollment_state(&store, std::slice::from_ref(&issuer_config))
            .await
            .unwrap()
            >= 1
    );
    let issued = store
        .issued_peer_rotation(mesh.id, peer_id, credential.serial)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(issued.id, rotation_id);
    let replacement = SubjectCredential::decode(&issued.credential).unwrap();
    trust
        .verify_subject(&replacement, replacement.not_before)
        .unwrap();
    assert_eq!(replacement.identity_public_key, replacement_identity_public);
    assert_eq!(replacement.public_noise_key, replacement_session_public);
    let peers = decode_peer_directory(
        &store
            .latest_signed_state(mesh.id, SignedStateKind::Peers)
            .await
            .unwrap()
            .body,
    )
    .unwrap();
    directory_key.verify_peers(&peers, mesh.id, None).unwrap();
    assert!(
        !peers.directory.entries[0]
            .entry
            .accepted_credentials
            .iter()
            .any(|binding| binding.serial == replacement.serial),
        "an unactivated replacement must not be installed from the directory",
    );
    let activation_signature = sign_rotation_activation(
        &replacement_identity.to_bytes(),
        &RotationActivationProof {
            mesh_id: mesh.id,
            peer_id,
            rotation_id,
            issued_serial: replacement.serial,
            challenge: issued.activation_challenge,
        },
    );
    assert!(
        store
            .activate_peer_rotation(
                mesh.id,
                peer_id,
                rotation_id,
                replacement.serial,
                activation_signature,
            )
            .await
            .unwrap()
    );
    assert!(
        publish_enrollment_state(&store, std::slice::from_ref(&issuer_config))
            .await
            .unwrap()
            >= 1
    );
    console_renewal::finish(
        &store,
        &application,
        mesh.id,
        peer_id,
        credential.serial,
        replacement.serial,
        console_request,
    )
    .await;
    sqlx::query(
        "UPDATE peer_credentials SET overlap_deadline=clock_timestamp()-interval '1 second'
         WHERE mesh_id=$1 AND peer_id=$2 AND lifecycle='overlap'",
    )
    .bind(mesh.id.into_uuid())
    .bind(peer_id.into_uuid())
    .execute(store.pool())
    .await
    .unwrap();
    assert!(
        publish_enrollment_state(&store, std::slice::from_ref(&issuer_config))
            .await
            .unwrap()
            >= 1
    );
    let peers = decode_peer_directory(
        &store
            .latest_signed_state(mesh.id, SignedStateKind::Peers)
            .await
            .unwrap()
            .body,
    )
    .unwrap();
    let published_peer = peers
        .directory
        .entries
        .iter()
        .find(|entry| entry.entry.peer_id == peer_id)
        .unwrap();
    assert!(
        !published_peer
            .entry
            .accepted_credentials
            .iter()
            .any(|binding| binding.serial == credential.serial)
    );
    assert!(
        published_peer
            .entry
            .accepted_credentials
            .iter()
            .any(|binding| binding.serial == replacement.serial)
    );
    let revocations = decode_revocations(
        &store
            .latest_signed_state(mesh.id, SignedStateKind::Revocations)
            .await
            .unwrap()
            .body,
    )
    .unwrap();
    assert!(revocations.bundle.serials.contains(&credential.serial));
    verify_audit_authority_revocation(
        &store,
        mesh.id,
        peer_id,
        &root,
        &issuer_config,
        &replacement_identity,
    )
    .await;
    assert_eq!(
        store
            .issued_peer_rotation(mesh.id, peer_id, credential.serial)
            .await
            .unwrap()
            .unwrap()
            .id,
        rotation_id
    );

    let second_peer = Uuid::new_v4();
    sqlx::query("INSERT INTO peers(id,mesh_id,name,labels) VALUES($1,$2,'bulk-peer','{}')")
        .bind(second_peer)
        .bind(mesh.id.into_uuid())
        .execute(store.pool())
        .await
        .unwrap();
    let first_version: i64 =
        sqlx::query_scalar("SELECT version FROM peers WHERE mesh_id=$1 AND id=$2")
            .bind(mesh.id.into_uuid())
            .bind(peer_id.into_uuid())
            .fetch_one(store.pool())
            .await
            .unwrap();
    let stale_bulk = json!({
        "family":"peer",
        "items":[
            {"id":peer_id,"version":first_version},
            {"id":second_peer,"version":2}
        ]
    });
    let response = application
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/meshes/{}/bulk/commit", mesh.id))
                .header("authorization", "Bearer rotation-admin")
                .header("content-type", "application/json")
                .body(Body::from(stale_bulk.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let enabled_after_conflict: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM peers WHERE mesh_id=$1 AND id=ANY($2) AND administrative_state='enabled'",
    )
    .bind(mesh.id.into_uuid())
    .bind(vec![peer_id.into_uuid(), second_peer])
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        enabled_after_conflict, 2,
        "bulk conflict must roll back every item"
    );
    let commit = json!({
        "family":"peer",
        "items":[
            {"id":peer_id,"version":first_version},
            {"id":second_peer,"version":1}
        ]
    });
    let response = application
        .oneshot(
            Request::post(format!("/api/v1/meshes/{}/bulk/commit", mesh.id))
                .header("authorization", "Bearer rotation-admin")
                .header("content-type", "application/json")
                .body(Body::from(commit.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let disabled: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM peers WHERE mesh_id=$1 AND id=ANY($2) AND administrative_state='disabled'",
    )
    .bind(mesh.id.into_uuid())
    .bind(vec![peer_id.into_uuid(), second_peer])
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(disabled, 2);
    let safely_quarantined: i64 = sqlx::query_scalar("SELECT count(*) FROM peer_addresses a JOIN mesh_authorization_bounds b ON b.mesh_id=a.mesh_id WHERE a.mesh_id=$1 AND a.peer_id=$2 AND a.state='quarantine' AND a.quarantine_until>=b.valid_until+interval '31 seconds'")
        .bind(mesh.id.into_uuid()).bind(peer_id.into_uuid()).fetch_one(store.pool()).await.unwrap();
    assert_eq!(
        safely_quarantined, 2,
        "the short configured quarantine cannot reuse either family before issued leases expire"
    );
}

include!("join_cases/audit_revocation.rs");

include!("join_cases/management_receipts.rs");
include!("join_cases/target_health.rs");
include!("join_cases/device_conditions.rs");
