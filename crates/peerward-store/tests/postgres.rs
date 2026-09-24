use std::{collections::HashSet, sync::Arc};

use ed25519_dalek::SigningKey as IdentitySigningKey;
use peerward_credentials::{
    RotationActivationProof, RotationRequestProof, sign_rotation_activation, sign_rotation_request,
};
use peerward_policy::{Action as PolicyAction, Policy, encode_policy_document};
use peerward_store::{
    IssuedPeerCredential, JoinClaim, Lifecycle, MaintenancePolicy, NewAuthority, NewOidcFlow,
    PresenceLease, PresenceRole, SignedStateKind, Store, StoreError,
};
use peerward_types::{AttachmentId, CredentialSerial, PeerId, RelayId, RotationId};
use serde_json::json;
use time::{Duration, OffsetDateTime};
use tokio::sync::Barrier;
use uuid::Uuid;

#[path = "postgres_cases/lifecycle.rs"]
mod lifecycle_cases;
#[path = "postgres_cases/maintenance_history.rs"]
mod maintenance_history;
#[path = "postgres_cases/pagination.rs"]
mod pagination_cases;
#[path = "postgres_cases/runtime_health.rs"]
mod runtime_health;
#[path = "postgres_cases/support.rs"]
mod test_support;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn complete_postgresql_invariants() {
    let url = test_support::database_url();
    let store = Store::connect(&url, 64).await.unwrap();
    sqlx::raw_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("CREATE TABLE meshes(id integer PRIMARY KEY)")
        .execute(store.pool())
        .await
        .unwrap();
    assert!(matches!(
        store.migrate().await,
        Err(StoreError::LegacySchemaUnsupported)
    ));

    test_support::assert_legacy_rejected(&store).await;
    store.migrate().await.unwrap();
    store.migrate().await.unwrap();
    let intent_still_exists: bool =
        sqlx::query_scalar("SELECT to_regclass('public.peerward_install_intent') IS NOT NULL")
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert!(!intent_still_exists);
    test_support::assert_followup_migrations(&store).await;
    test_support::assert_wss_endpoints(&store).await;

    let required = [
        "meshes",
        "mesh_authorities",
        "peers",
        "peer_addresses",
        "peer_credentials",
        "relays",
        "relay_credentials",
        "relay_presence",
        "relay_standby_presence_v1",
        "join_tickets",
        "policies",
        "policy_rules",
        "services",
        "audit_log",
        "encrypted_audit_inbox",
        "processed_peer_audit_batches",
        "event_outbox",
        "signed_state_revisions",
        "oidc_flows",
        "web_sessions",
        "bootstrap_state",
        "peer_credential_rotation_requests",
        "current_peer_runtime_health",
    ];
    let installed: Vec<String> = sqlx::query_scalar(
        "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename",
    )
    .fetch_all(store.pool())
    .await
    .unwrap();
    for relation in required {
        assert!(
            installed.iter().any(|value| value == relation),
            "missing {relation}"
        );
    }

    let first_mesh = store
        .create_mesh(&test_support::mesh_request("first", "first.mesh"), "admin")
        .await
        .unwrap();
    let mut ipv6_request = test_support::mesh_request("second", "second.mesh");
    ipv6_request.address_cidr = "fd42:7065:6572::/120".parse().unwrap();
    ipv6_request.gateway = "fd42:7065:6572::1".parse().unwrap();
    ipv6_request.reserved = vec!["fd42:7065:6572::2".parse().unwrap()];
    let second_mesh = store.create_mesh(&ipv6_request, "admin").await.unwrap();
    assert_ne!(first_mesh.id, second_mesh.id);
    assert!(first_mesh.address_cidr.addr().is_ipv4());
    assert!(second_mesh.address_cidr.addr().is_ipv6());
    assert_eq!(first_mesh.policy_revision, 1);
    assert_eq!(first_mesh.service_revision, 1);
    assert_eq!(first_mesh.revocation_revision, 1);
    assert_eq!(first_mesh.authority_revision, 0);
    assert_eq!(first_mesh.directory_revision, 0);
    assert_eq!(first_mesh.relay_revision, 0);

    let mut dispatcher = store.dispatcher(&url).await.unwrap();
    let before_ticket = store.event_replay_start(None).await.unwrap().cursor;
    store
        .create_join_ticket(
            first_mesh.id,
            b"notification-ticket-token",
            OffsetDateTime::now_utc() + Duration::minutes(2),
            "operator",
        )
        .await
        .unwrap();
    let notified =
        tokio::time::timeout(std::time::Duration::from_secs(2), dispatcher.next_cursor())
            .await
            .expect("outbox notification timed out")
            .unwrap();
    assert!(
        store
            .events_after(before_ticket, 500)
            .await
            .unwrap()
            .iter()
            .any(|event| event.cursor == notified)
    );

    let authority = NewAuthority {
        mesh_id: first_mesh.id,
        serial: CredentialSerial::new(),
        public_key: vec![7; 32],
        not_before: OffsetDateTime::now_utc() - Duration::minutes(1),
        not_after: OffsetDateTime::now_utc() + Duration::days(1),
        replaces: None,
        overlap_deadline: None,
        certificate: vec![8; 64],
    };
    let authority_id = store.stage_authority(&authority, "admin").await.unwrap();
    lifecycle_cases::assert_authority_version_precondition(
        &store,
        first_mesh.id,
        authority_id,
        authority.serial,
    )
    .await;
    let ipv6_authority = NewAuthority {
        mesh_id: second_mesh.id,
        serial: CredentialSerial::new(),
        ..authority.clone()
    };
    let ipv6_authority_id = store
        .stage_authority(&ipv6_authority, "admin")
        .await
        .unwrap();
    store
        .transition_authority(
            second_mesh.id,
            ipv6_authority.serial,
            Lifecycle::Active,
            "admin",
        )
        .await
        .unwrap();
    let ipv6_token = b"ipv6-join-ticket-token-value".to_vec();
    // IPv6 has no broadcast address: the last address is usable. The opposite
    // IPv4 pool must still wrap before its broadcast address.
    sqlx::query("UPDATE meshes SET next_address=broadcast(address_cidr), secondary_next_address=broadcast(secondary_cidr) WHERE id=$1")
        .bind(second_mesh.id.into_uuid())
        .execute(store.pool()).await.unwrap();
    store
        .create_join_ticket(
            second_mesh.id,
            &ipv6_token,
            OffsetDateTime::now_utc() + Duration::minutes(2),
            "operator",
        )
        .await
        .unwrap();
    let ipv6_peer = store
        .claim_join(&JoinClaim {
            token: ipv6_token,
            name: "ipv6-peer".into(),
            labels: json!({"family":"ipv6"}),
            claim_id: Uuid::new_v4(),
            request_digest: [5; 32],
            authority_id: ipv6_authority_id,
            serial: CredentialSerial::new(),
            identity_public_key: vec![5; 32],
            public_key: vec![6; 32],
            wireguard_public_key: vec![134; 32],
            not_before: OffsetDateTime::now_utc() - Duration::minutes(1),
            not_after: OffsetDateTime::now_utc() + Duration::hours(1),
            signature: vec![7; 64],
        })
        .await
        .unwrap();
    assert_eq!(ipv6_peer.address.to_string(), "fd42:7065:6572::ff");
    runtime_health::assert_observation_expiry(&store, second_mesh.id, ipv6_peer.peer_id).await;
    let next: String = sqlx::query_scalar("SELECT host(next_address) FROM meshes WHERE id=$1")
        .bind(second_mesh.id.into_uuid())
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(next, "fd42:7065:6572::1");
    let broadcast_allocated: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM peer_addresses a JOIN meshes m ON a.mesh_id=m.id WHERE m.id=$1 AND a.address=broadcast(m.secondary_cidr))")
        .bind(second_mesh.id.into_uuid()).fetch_one(store.pool()).await.unwrap();
    assert!(!broadcast_allocated);
    let replacement = NewAuthority {
        serial: CredentialSerial::new(),
        public_key: vec![9; 32],
        replaces: Some(authority_id),
        overlap_deadline: Some(OffsetDateTime::now_utc() + Duration::minutes(10)),
        ..authority.clone()
    };
    let replacement_id = store.stage_authority(&replacement, "admin").await.unwrap();
    store
        .transition_authority(first_mesh.id, authority.serial, Lifecycle::Overlap, "admin")
        .await
        .unwrap();
    store
        .transition_authority(
            first_mesh.id,
            replacement.serial,
            Lifecycle::Active,
            "admin",
        )
        .await
        .unwrap();
    store
        .transition_authority(first_mesh.id, authority.serial, Lifecycle::Revoked, "admin")
        .await
        .unwrap();

    let mut claims = Vec::new();
    for index in 0..1_000_u32 {
        let index_byte = u8::try_from(index % 251).unwrap();
        let mut public_key = vec![index_byte; 32];
        public_key[..4].copy_from_slice(&index.to_be_bytes());
        let token = format!("ticket-token-that-is-long-{index:04}").into_bytes();
        store
            .create_join_ticket(
                first_mesh.id,
                &token,
                OffsetDateTime::now_utc() + Duration::minutes(5),
                "operator",
            )
            .await
            .unwrap();
        let claim = JoinClaim {
            token,
            name: format!("peer-{index}"),
            labels: json!({"batch":"concurrent"}),
            claim_id: Uuid::new_v4(),
            request_digest: {
                let mut digest = [0_u8; 32];
                digest[..4].copy_from_slice(&index.to_be_bytes());
                digest
            },
            authority_id: replacement_id,
            serial: CredentialSerial::new(),
            identity_public_key: IdentitySigningKey::from_bytes(&[index_byte.max(1); 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
            wireguard_public_key: public_key.iter().map(|byte| byte ^ 128).collect(),
            public_key,
            not_before: OffsetDateTime::now_utc() - Duration::minutes(1),
            not_after: OffsetDateTime::now_utc() + Duration::hours(1),
            signature: vec![index_byte; 64],
        };
        let clone = store.clone();
        claims.push(tokio::spawn(async move {
            clone.claim_join(&claim).await.unwrap()
        }));
    }
    let mut addresses = HashSet::new();
    let mut peers = Vec::new();
    for task in claims {
        let result = task.await.unwrap();
        assert!(addresses.insert(result.address));
        peers.push(result.peer_id);
    }
    assert_eq!(addresses.len(), 1_000);
    assert!(!addresses.contains(&first_mesh.gateway));
    assert!(!addresses.contains(&"10.88.0.2".parse().unwrap()));

    pagination_cases::assert_compound_pagination(&store, first_mesh.id).await;

    sqlx::query("UPDATE policies SET current=false WHERE mesh_id=$1")
        .bind(first_mesh.id.into_uuid())
        .execute(store.pool())
        .await
        .unwrap();
    let policy_document =
        encode_policy_document(&Policy::new(2, PolicyAction::Deny, Vec::new())).unwrap();
    sqlx::query(
        "INSERT INTO policies(mesh_id,revision,default_action,document,current)
         VALUES($1,2,'deny',$2,true)",
    )
    .bind(first_mesh.id.into_uuid())
    .bind(policy_document)
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO policy_rules(id,mesh_id,policy_revision,priority,action,protocol,
         destination_port_ranges)
         VALUES($1,$2,2,10,'allow','tcp',ARRAY[int8range(443,444,'[)')])",
    )
    .bind(Uuid::new_v4())
    .bind(first_mesh.id.into_uuid())
    .execute(store.pool())
    .await
    .unwrap();
    let invalid_ports = sqlx::query(
        "INSERT INTO policy_rules(id,mesh_id,policy_revision,priority,action,protocol,
         destination_port_ranges)
         VALUES($1,$2,2,11,'allow','tcp',ARRAY[int8range(0,1,'[)')])",
    )
    .bind(Uuid::new_v4())
    .bind(first_mesh.id.into_uuid())
    .execute(store.pool())
    .await;
    assert!(invalid_ports.is_err());

    let released_address: String = sqlx::query_scalar(
        "SELECT host(address) FROM peer_addresses WHERE mesh_id=$1 AND peer_id=$2 AND state='active' AND family(address)=4",
    )
    .bind(first_mesh.id.into_uuid())
    .bind(peers[0].into_uuid())
    .fetch_one(store.pool())
    .await
    .unwrap();
    store
        .release_address(first_mesh.id, peers[0], "operator")
        .await
        .unwrap();
    lifecycle_cases::assert_both_families_quarantined(&store, first_mesh.id, peers[0]).await;
    let claim_after_release = |token: &[u8], name: &str| JoinClaim {
        token: token.to_vec(),
        name: name.into(),
        labels: json!({}),
        claim_id: Uuid::new_v4(),
        request_digest: [76; 32],
        authority_id: replacement_id,
        serial: CredentialSerial::new(),
        identity_public_key: vec![76; 32],
        public_key: vec![77; 32],
        wireguard_public_key: {
            let mut key = vec![205; 32];
            key[..16].copy_from_slice(Uuid::new_v4().as_bytes());
            key
        },
        not_before: OffsetDateTime::now_utc() - Duration::minutes(1),
        not_after: OffsetDateTime::now_utc() + Duration::hours(1),
        signature: vec![78; 64],
    };
    let quarantined_token = b"quarantined-address-ticket";
    store
        .create_join_ticket(
            first_mesh.id,
            quarantined_token,
            OffsetDateTime::now_utc() + Duration::minutes(5),
            "operator",
        )
        .await
        .unwrap();
    let while_quarantined = store
        .claim_join(&claim_after_release(quarantined_token, "during-quarantine"))
        .await
        .unwrap();
    assert_ne!(while_quarantined.address.to_string(), released_address);
    sqlx::query(
        "UPDATE peer_addresses SET quarantine_until=clock_timestamp()-interval '1 second'
         WHERE mesh_id=$1 AND peer_id=$2 AND state='quarantine'",
    )
    .bind(first_mesh.id.into_uuid())
    .bind(peers[0].into_uuid())
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query("UPDATE meshes SET next_address=$1::inet WHERE id=$2")
        .bind(&released_address)
        .bind(first_mesh.id.into_uuid())
        .execute(store.pool())
        .await
        .unwrap();
    let reusable_token = b"reusable-address-ticket-token";
    store
        .create_join_ticket(
            first_mesh.id,
            reusable_token,
            OffsetDateTime::now_utc() + Duration::minutes(5),
            "operator",
        )
        .await
        .unwrap();
    let after_quarantine = store
        .claim_join(&claim_after_release(reusable_token, "after-quarantine"))
        .await
        .unwrap();
    assert_eq!(after_quarantine.address.to_string(), released_address);

    let one_use_token = b"one-use-ticket-token-value".to_vec();
    store
        .create_join_ticket(
            first_mesh.id,
            &one_use_token,
            OffsetDateTime::now_utc() + Duration::minutes(5),
            "operator",
        )
        .await
        .unwrap();
    let barrier = Arc::new(Barrier::new(1_000));
    let attempts: Vec<_> = (0..1_000_u32)
        .map(|index| {
            let clone = store.clone();
            let barrier = Arc::clone(&barrier);
            let token = one_use_token.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                clone
                    .claim_join(&JoinClaim {
                        token,
                        name: format!("winner-{index}"),
                        labels: json!({}),
                        claim_id: Uuid::new_v4(),
                        request_digest: {
                            let mut digest = [8_u8; 32];
                            digest[..4].copy_from_slice(&index.to_be_bytes());
                            digest
                        },
                        authority_id: replacement_id,
                        serial: CredentialSerial::new(),
                        identity_public_key: vec![8; 32],
                        wireguard_public_key: {
                            let mut key = vec![u8::try_from(index % 251).unwrap() ^ 128; 32];
                            key[..4].copy_from_slice(&index.to_be_bytes());
                            key
                        },
                        public_key: {
                            let mut key = vec![u8::try_from(index % 251).unwrap(); 32];
                            key[..4].copy_from_slice(&index.to_be_bytes());
                            key
                        },
                        not_before: OffsetDateTime::now_utc() - Duration::minutes(1),
                        not_after: OffsetDateTime::now_utc() + Duration::hours(1),
                        signature: vec![9; 64],
                    })
                    .await
            })
        })
        .collect();
    let mut successes = 0;
    for task in attempts {
        match task.await.unwrap() {
            Ok(_) => successes += 1,
            Err(StoreError::Conflict) => {}
            Err(error) => panic!("unexpected claim error: {error}"),
        }
    }
    assert_eq!(successes, 1);

    let relay_id = RelayId::new();
    sqlx::query("INSERT INTO relays(id,mesh_id,name,peer_endpoints,backbone_endpoints) VALUES($1,$2,'r',ARRAY['tcp://127.0.0.1:1'],ARRAY['tcp://127.0.0.1:2'])")
        .bind(relay_id.into_uuid()).bind(first_mesh.id.into_uuid()).execute(store.pool()).await.unwrap();
    let lease = PresenceLease {
        mesh_id: first_mesh.id,
        peer_id: peers[0],
        relay_id,
        attachment_id: AttachmentId::new(),
        role: PresenceRole::Primary,
        lease_deadline: OffsetDateTime::now_utc() + Duration::minutes(1),
    };
    let generation_one = store.acquire_presence(&lease).await.unwrap();
    let generation_two = store
        .acquire_presence(&PresenceLease {
            attachment_id: AttachmentId::new(),
            ..lease.clone()
        })
        .await
        .unwrap();
    assert_eq!(generation_two, generation_one + 1);
    assert!(matches!(
        store.renew_presence(&lease, generation_one).await,
        Err(StoreError::Conflict)
    ));

    // Releasing and reacquiring either role must never reuse a cached fence,
    // including a retry that carries the exact same attachment ID.
    let peer_version_before: i64 = sqlx::query_scalar("SELECT version FROM peers WHERE id=$1")
        .bind(lease.peer_id.into_uuid())
        .fetch_one(store.pool())
        .await
        .unwrap();
    for role in [PresenceRole::Primary, PresenceRole::Standby] {
        let reconnected = PresenceLease {
            role,
            ..lease.clone()
        };
        let first = store.acquire_presence(&reconnected).await.unwrap();
        store.release_presence(&reconnected, first).await.unwrap();
        let next = store.acquire_presence(&reconnected).await.unwrap();
        assert!(next > first);
        assert!(matches!(
            store.renew_presence(&reconnected, first).await,
            Err(StoreError::Conflict)
        ));
        assert!(matches!(
            store.release_presence(&reconnected, first).await,
            Err(StoreError::Conflict)
        ));
        store.renew_presence(&reconnected, next).await.unwrap();
        if role == PresenceRole::Standby {
            store.release_presence(&reconnected, next).await.unwrap();
        }
    }
    let peer_version_after: i64 = sqlx::query_scalar("SELECT version FROM peers WHERE id=$1")
        .bind(lease.peer_id.into_uuid())
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(peer_version_before, peer_version_after);

    let relay_instance = Uuid::new_v4();
    store
        .acquire_relay_runtime(
            first_mesh.id,
            relay_id,
            relay_instance,
            OffsetDateTime::now_utc() + Duration::minutes(1),
        )
        .await
        .unwrap();
    let peer_online = async || {
        sqlx::query_scalar::<_, bool>(
            "SELECT (peerward_peer_api_json(peer)->>'online')::boolean
             FROM peers peer WHERE peer.mesh_id=$1 AND peer.id=$2",
        )
        .bind(first_mesh.id.into_uuid())
        .bind(peers[0].into_uuid())
        .fetch_one(store.pool())
        .await
        .unwrap()
    };
    let relay_online = async || {
        sqlx::query_scalar::<_, bool>(
            "SELECT (peerward_relay_api_json(relay)->>'online')::boolean
             FROM relays relay WHERE relay.mesh_id=$1 AND relay.id=$2",
        )
        .bind(first_mesh.id.into_uuid())
        .bind(relay_id.into_uuid())
        .fetch_one(store.pool())
        .await
        .unwrap()
    };
    let peer_presence_count = async || {
        sqlx::query_scalar::<_, i32>(
            "SELECT jsonb_array_length(peerward_peer_api_json(peer)->'presence')
             FROM peers peer WHERE peer.mesh_id=$1 AND peer.id=$2",
        )
        .bind(first_mesh.id.into_uuid())
        .bind(peers[0].into_uuid())
        .fetch_one(store.pool())
        .await
        .unwrap()
    };
    let relay_presence_count = async || {
        sqlx::query_scalar::<_, i64>(
            "SELECT (peerward_relay_api_json(relay)->>'presence_count')::bigint
             FROM relays relay WHERE relay.mesh_id=$1 AND relay.id=$2",
        )
        .bind(first_mesh.id.into_uuid())
        .bind(relay_id.into_uuid())
        .fetch_one(store.pool())
        .await
        .unwrap()
    };
    assert!(peer_online().await);
    assert!(relay_online().await);
    assert_eq!(peer_presence_count().await, 1);
    assert_eq!(relay_presence_count().await, 1);

    test_support::assert_two_standbys_coexist(&store, &lease).await;

    sqlx::query("UPDATE relays SET administrative_state='disabled' WHERE id=$1")
        .bind(relay_id.into_uuid())
        .execute(store.pool())
        .await
        .unwrap();
    assert!(!peer_online().await);
    assert!(!relay_online().await);
    assert_eq!(peer_presence_count().await, 0);
    assert_eq!(relay_presence_count().await, 0);
    sqlx::query("UPDATE relays SET administrative_state='enabled' WHERE id=$1")
        .bind(relay_id.into_uuid())
        .execute(store.pool())
        .await
        .unwrap();

    sqlx::query("UPDATE peers SET administrative_state='disabled' WHERE id=$1")
        .bind(peers[0].into_uuid())
        .execute(store.pool())
        .await
        .unwrap();
    assert!(!peer_online().await);
    assert!(relay_online().await);
    assert_eq!(peer_presence_count().await, 0);
    assert_eq!(relay_presence_count().await, 0);
    sqlx::query("UPDATE peers SET administrative_state='enabled' WHERE id=$1")
        .bind(peers[0].into_uuid())
        .execute(store.pool())
        .await
        .unwrap();

    sqlx::query(
        "UPDATE relay_runtime_leases SET lease_deadline=clock_timestamp()-interval '1 second'
         WHERE mesh_id=$1 AND relay_id=$2",
    )
    .bind(first_mesh.id.into_uuid())
    .bind(relay_id.into_uuid())
    .execute(store.pool())
    .await
    .unwrap();
    assert!(!peer_online().await);
    assert!(!relay_online().await);

    let rotating_peer = peers[1];
    let current_serial = CredentialSerial::from_uuid(
        sqlx::query_scalar(
            "SELECT serial FROM peer_credentials
             WHERE mesh_id=$1 AND peer_id=$2 AND lifecycle='active'",
        )
        .bind(first_mesh.id.into_uuid())
        .bind(rotating_peer.into_uuid())
        .fetch_one(store.pool())
        .await
        .unwrap(),
    )
    .unwrap();
    let rotation_id = RotationId::new();
    let new_identity = IdentitySigningKey::from_bytes(&[201; 32]);
    let new_identity_public = new_identity.verifying_key().to_bytes();
    let new_session_public = [202; 32];
    let rotation_signature = sign_rotation_request(
        &[1; 32],
        &RotationRequestProof {
            mesh_id: first_mesh.id,
            peer_id: rotating_peer,
            rotation_id,
            current_serial,
            identity_public_key: new_identity_public,
            session_public_key: new_session_public,
            wireguard_public_key: [0x77; 32],
        },
    )
    .unwrap();
    store
        .request_peer_rotation(
            rotation_id,
            first_mesh.id,
            rotating_peer,
            current_serial,
            new_identity_public,
            new_session_public,
            [0x77; 32],
            rotation_signature,
        )
        .await
        .unwrap();
    let pending = store
        .pending_peer_rotations(first_mesh.id, 10)
        .await
        .unwrap();
    assert_eq!(pending.len(), 1);
    let replacement_serial = CredentialSerial::new();
    let replacement_credential = vec![202; 225];
    store
        .issue_peer_rotation(
            &pending[0],
            &IssuedPeerCredential {
                authority_id: replacement_id,
                authority_public_key: Some(vec![9; 32]),
                serial: replacement_serial,
                not_before: OffsetDateTime::now_utc() - Duration::minutes(1),
                not_after: OffsetDateTime::now_utc() + Duration::hours(1),
                signature: vec![203; 64],
            },
            &replacement_credential,
        )
        .await
        .unwrap();
    let issued = store
        .issued_peer_rotation(first_mesh.id, rotating_peer, current_serial)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(issued.id, rotation_id);
    assert_eq!(issued.serial, replacement_serial);
    assert_eq!(issued.credential, replacement_credential);
    let activation_signature = sign_rotation_activation(
        &new_identity.to_bytes(),
        &RotationActivationProof {
            mesh_id: first_mesh.id,
            peer_id: rotating_peer,
            rotation_id,
            issued_serial: replacement_serial,
            challenge: issued.activation_challenge,
        },
    );
    assert!(
        store
            .activate_peer_rotation(
                first_mesh.id,
                rotating_peer,
                rotation_id,
                replacement_serial,
                activation_signature,
            )
            .await
            .unwrap()
    );
    let lifecycles: Vec<String> = sqlx::query_scalar(
        "SELECT lifecycle FROM peer_credentials WHERE mesh_id=$1 AND peer_id=$2
         ORDER BY CASE lifecycle WHEN 'active' THEN 0 ELSE 1 END",
    )
    .bind(first_mesh.id.into_uuid())
    .bind(rotating_peer.into_uuid())
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert_eq!(lifecycles[0], "active");
    assert!(lifecycles.iter().any(|value| value == "overlap"));
    lifecycle_cases::assert_overlap_expiry(&store, first_mesh.id, rotating_peer, current_serial)
        .await;
    let flow = NewOidcFlow {
        return_to: "/".into(),
        reauthenticate: false,
        state: "state-secret".into(),
        nonce: "mS9FMH5XDZXZv6N8WTkYQ8XrY2vL4aJq".into(),
        pkce_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".into(),
        redirect_uri: "https://console.test/auth/callback".into(),
        expires_at: OffsetDateTime::now_utc() + Duration::minutes(5),
    };
    store.create_oidc_flow(&flow).await.unwrap();
    let consumed = store.consume_oidc_flow("state-secret").await.unwrap();
    assert_eq!(consumed.nonce, flow.nonce);
    assert_eq!(consumed.pkce_verifier, flow.pkce_verifier);
    assert_eq!(consumed.redirect_uri, flow.redirect_uri);
    assert!(matches!(
        store.consume_oidc_flow("state-secret").await,
        Err(StoreError::Conflict)
    ));

    let signed = vec![
        (SignedStateKind::Peers, 7, b"signed-peers".to_vec()),
        (SignedStateKind::Policy, 4, b"signed-policy".to_vec()),
    ];
    assert_eq!(
        store
            .publish_signed_states(first_mesh.id, &signed)
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        store
            .publish_signed_states(first_mesh.id, &signed)
            .await
            .unwrap(),
        0
    );
    assert!(matches!(
        store
            .publish_signed_states(
                first_mesh.id,
                &[(SignedStateKind::Peers, 7, b"different".to_vec())],
            )
            .await,
        Err(StoreError::SignedStateConflict {
            kind: "peers",
            revision: 7
        })
    ));
    let latest = store
        .latest_signed_state(first_mesh.id, SignedStateKind::Peers)
        .await
        .unwrap();
    assert_eq!(latest.revision, 7);
    assert_eq!(latest.body, b"signed-peers");
    assert_eq!(
        store
            .latest_signed_states(first_mesh.id)
            .await
            .unwrap()
            .len(),
        2
    );
    lifecycle_cases::age_address_history(&store, first_mesh.id, &released_address).await;
    let audit_count: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log")
        .fetch_one(store.pool())
        .await
        .unwrap();
    let event_count: i64 = sqlx::query_scalar("SELECT count(*) FROM event_outbox")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert!(audit_count >= 68);
    assert!(event_count >= audit_count);
    let high_water = store.event_replay_start(None).await.unwrap();
    assert!(store.events_after(None, 500).await.unwrap().is_empty());
    sqlx::query("UPDATE event_outbox SET committed_at=clock_timestamp()-interval '2 hours'")
        .execute(store.pool())
        .await
        .unwrap();
    let mut elected_elsewhere = store.begin_mutation().await.unwrap();
    let lock_held: bool = sqlx::query_scalar(
        "SELECT pg_try_advisory_xact_lock(hashtextextended('peerward/maintenance/v1',0))",
    )
    .fetch_one(&mut *elected_elsewhere)
    .await
    .unwrap();
    assert!(lock_held);
    let unelected = store
        .maintain(MaintenancePolicy {
            batch_size: 100,
            event_retention_seconds: 3_600,
            event_max_rows: 10_000,
            signed_state_versions: 2,
            terminal_retention_seconds: 3_600,
        })
        .await
        .unwrap();
    assert!(!unelected.elected);
    elected_elsewhere.rollback().await.unwrap();
    let report = store
        .maintain(MaintenancePolicy {
            batch_size: 100,
            event_retention_seconds: 3_600,
            event_max_rows: 10_000,
            signed_state_versions: 2,
            terminal_retention_seconds: 3_600,
        })
        .await
        .unwrap();
    assert!(report.elected);
    let retained_address_history =
        lifecycle_cases::released_address_history(&store, first_mesh.id, &released_address).await;
    let retained_events: i64 = sqlx::query_scalar("SELECT count(*) FROM event_outbox")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert!(event_count - retained_events <= 100);
    store
        .maintain(MaintenancePolicy {
            batch_size: 100,
            event_retention_seconds: 3_600,
            event_max_rows: 10_000,
            signed_state_versions: 2,
            terminal_retention_seconds: 3_600,
        })
        .await
        .unwrap();
    lifecycle_cases::assert_address_history_removed(&store, retained_address_history).await;
    assert_eq!(
        store.event_replay_start(None).await.unwrap().cursor,
        high_water.cursor
    );
    assert!(
        store
            .event_batch_after_sequence(first_mesh.id, 0, 500)
            .await
            .unwrap()
            .retention_gap
    );
    assert!(matches!(
        store.event_replay_start(Some(notified)).await,
        Err(StoreError::EventCursorExpired)
    ));

    include!("support/postgres_tail.rs");
    maintenance_history::verify(&store, first_mesh.id).await;
}
