//! Isolated API fixture for Console browser regression tests.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use peerward_control::{AuthConfig, JoinIssuerConfig, OidcConfig, router_with_enrollment};
use peerward_credentials::{AuthoritySigningKey, RootSigningKey, UnsignedAuthority};
use peerward_store::{DefaultPolicy, NewMesh, Store};
use peerward_store::{Lifecycle, NewAuthority};
use peerward_types::{CredentialSerial, UnixTime};
use serde_json::json;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::var("PEERWARD_TEST_DATABASE_URL")?;
    assert!(
        url.parse::<sqlx::postgres::PgConnectOptions>()
            .is_ok_and(|options| options.get_database() == Some("peerward_test")),
        "requires an ephemeral test database"
    );
    let store = Store::connect(&url, 4).await?;
    store.migrate().await?;
    // Scheduling target only: this fixture does not run a Relay or lifecycle executor.
    sqlx::query("INSERT INTO relay_hosts(id,name,certificate_sha256,peer_endpoints,backbone_endpoints,is_default) VALUES($1,'Console test host',$2,ARRAY['tcp://127.0.0.1:7777'],ARRAY['tcp://127.0.0.1:7778'],true) ON CONFLICT DO NOTHING")
        .bind(uuid::Uuid::new_v4()).bind(vec![29_u8;32]).execute(store.pool()).await?;

    let mesh = store
        .create_mesh(
            &NewMesh {
                name: format!("console-{}", Uuid::new_v4()),
                address_cidr: "100.96.195.0/24".parse()?,
                gateway: "100.96.195.1".parse()?,
                dns_suffix: "home.test".into(),
                mtu: 1380,
                reserved: Vec::new(),
                default_policy: DefaultPolicy::Deny,
                quarantine_seconds: 60,
                rotation_overlap_seconds: 3600,
            },
            "fixture",
        )
        .await?;
    let issuer = fixture_enrollment(&store, mesh.id).await?;
    // Offline inventory for maintenance preflight. No host or runtime is simulated
    // as applied: browser tests must observe explicit unavailable blockers.
    for name in [
        "offline-maintenance-source",
        "offline-maintenance-replacement",
    ] {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO relay_hosts(id,name,certificate_sha256,peer_endpoints,backbone_endpoints) VALUES($1,$2,$3,ARRAY['tcp://127.0.0.1:27777'],ARRAY['tcp://127.0.0.1:27778'])")
            .bind(id).bind(name).bind(id.as_bytes().repeat(2)).execute(store.pool()).await?;
    }
    store
        .create_mesh(
            &NewMesh {
                name: "second-console-network".into(),
                address_cidr: "100.96.196.0/24".parse()?,
                gateway: "100.96.196.1".parse()?,
                dns_suffix: "second.test".into(),
                mtu: 1380,
                reserved: vec![],
                default_policy: DefaultPolicy::Deny,
                quarantine_seconds: 60,
                rotation_overlap_seconds: 3600,
            },
            "fixture",
        )
        .await?;
    let peer = Uuid::new_v4();
    sqlx::query("INSERT INTO peers(id,mesh_id,name,display_name,location,labels) VALUES($1,$2,'home-nas','家庭记忆库','家中书房',$3)")
        .bind(peer).bind(mesh.id.into_uuid()).bind(json!({"platform":"linux","device_model":"x86_64"}))
        .execute(store.pool()).await?;
    sqlx::query("INSERT INTO peer_addresses(id,mesh_id,peer_id,address,state) VALUES($1,$2,$3,'100.96.195.2','active')")
        .bind(Uuid::new_v4()).bind(mesh.id.into_uuid()).bind(peer).execute(store.pool()).await?;
    // This assigned identity supports policy simulation only. No real client,
    // credential application or packet connectivity is implied by the fixture.
    let consumer = Uuid::new_v4();
    sqlx::query("INSERT INTO peers(id,mesh_id,name,labels) VALUES($1,$2,'test-consumer',$3)")
        .bind(consumer)
        .bind(mesh.id.into_uuid())
        .bind(json!({"platform":"linux"}))
        .execute(store.pool())
        .await?;
    sqlx::query("INSERT INTO peer_addresses(id,mesh_id,peer_id,address,state) VALUES($1,$2,$3,'100.96.195.3','active')")
        .bind(Uuid::new_v4()).bind(mesh.id.into_uuid()).bind(consumer).execute(store.pool()).await?;
    println!("fixture mesh={}", mesh.id);
    let listen = std::env::var("PEERWARD_CONSOLE_FIXTURE_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:29480".into());
    let address: std::net::SocketAddr = listen.parse()?;
    assert!(address.ip().is_loopback(), "fixture must bind loopback");
    let listener = tokio::net::TcpListener::bind(address).await?;
    let oidc = std::env::var("PEERWARD_CONSOLE_FIXTURE_OIDC_ISSUER")
        .ok()
        .map(|issuer| -> Result<OidcConfig, Box<dyn std::error::Error>> {
            Ok(OidcConfig {
                issuer_url: issuer.parse()?,
                client_id: "peerward-console-e2e".into(),
                client_secret: Some("peerward-console-e2e-secret".into()),
                redirect_uri: std::env::var("PEERWARD_CONSOLE_FIXTURE_OIDC_REDIRECT")?.parse()?,
                scopes: "openid profile email".into(),
                groups_claim: "groups".into(),
                auditor_groups: vec!["peerward-auditor".into()],
                operator_groups: vec!["peerward-operator".into()],
                admin_groups: vec!["peerward-admin".into()],
            })
        })
        .transpose()?;
    axum::serve(
        listener,
        router_with_enrollment(
            store,
            AuthConfig {
                development_bearer_token: Some("console-review-test".into()),
                oidc,
                bootstrap_token: None,
            },
            &[issuer],
        )
        .expect("fixture enrollment router"),
    )
    .await?;
    Ok(())
}

async fn fixture_enrollment(
    store: &Store,
    mesh: peerward_types::MeshId,
) -> Result<JoinIssuerConfig, Box<dyn std::error::Error>> {
    let root = RootSigningKey::from_bytes(&[41; 32]);
    let authority = AuthoritySigningKey::from_bytes(&[42; 32]);
    let now = OffsetDateTime::now_utc();
    let seconds = u64::try_from(now.unix_timestamp())?;
    let serial = CredentialSerial::new();
    let certificate = root.certify(UnsignedAuthority {
        mesh_id: mesh,
        serial,
        public_key: authority.public_key(),
        not_before: UnixTime(seconds - 60),
        not_after: UnixTime(seconds + 86400),
    })?;
    let authority_id = store
        .stage_authority(
            &NewAuthority {
                mesh_id: mesh,
                serial,
                public_key: authority.public_key().to_vec(),
                not_before: now - Duration::minutes(1),
                not_after: now + Duration::days(1),
                replaces: None,
                overlap_deadline: None,
                certificate: certificate.encode(),
            },
            "fixture",
        )
        .await?;
    store
        .transition_authority(mesh, serial, Lifecycle::Active, "fixture")
        .await?;
    Ok(JoinIssuerConfig {
        mesh_id: mesh,
        authority_id,
        authority_private_key: Some(hex::encode([42; 32])),
        root_public_key: hex::encode(root.public_key().to_bytes()),
        authority_certificate: URL_SAFE_NO_PAD.encode(certificate.encode()),
        directory_private_key: hex::encode([43; 32]),
        service_private_key: hex::encode([44; 32]),
        audit_private_key: hex::encode([45; 32]),
        credential_validity_seconds: 3600,
        stun_servers: Vec::new(),
    })
}
