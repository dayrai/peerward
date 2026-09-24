use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt as _;
use peerward_control::{AuthConfig, JoinIssuerConfig, router_with_enrollment};
use peerward_credentials::{
    AuthoritySigningKey, JoinClaimProof, RootSigningKey, UnsignedAuthority, sign_join_claim,
};
use peerward_store::{DefaultPolicy, Lifecycle, NewAuthority, NewMesh, Store, secret_digest};
use peerward_types::{CredentialSerial, UnixTime};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use time::{Duration, OffsetDateTime};
use tower::ServiceExt as _;
use uuid::Uuid;
fn database_url() -> String {
    let url = std::env::var("PEERWARD_TEST_DATABASE_URL").unwrap();
    assert!(
        url.parse::<sqlx::postgres::PgConnectOptions>()
            .is_ok_and(|options| options.get_database() == Some("peerward_test"))
    );
    url
}
#[tokio::test]
async fn controlled_enrollment_reservation_approval_and_retained_history() {
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
    exercise_controlled_join(&store, &application, mesh.id).await;
    exercise_device_admission(&store, &application, &issuer_config).await;
    assert_purpose_migration(&store, &application, mesh.id).await;
    exercise_enrollment_groups(&store, &application, mesh.id).await;
}

include!("join_cases/controlled_enrollment.rs");
include!("join_cases/device_admission.rs");

include!("join_cases/enrollment_groups.rs");
