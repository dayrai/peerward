use super::*;
use crate::{
    AuthoritySigningKey, CredentialSerial, IdentitySigningKey, MeshId, NoisePublicKey,
    RootSigningKey, StaticSecret, SubjectId, UnixTime, UnsignedAuthority, UnsignedSubject,
};
use peerward_types::PeerId;

struct Fixture {
    root: PathBuf,
    source: PathBuf,
    layout: Layout,
}
impl Fixture {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("peerward-install-test-{}", uuid::Uuid::new_v4()));
        let source = root.join("joined");
        private_files::private_dir(&source).unwrap();
        let caller = fs::metadata("/proc/self").unwrap();
        let layout = Layout {
            config: root.join("etc/peer.toml"),
            profile: root.join("var/peer"),
            socket: root.join("run/peer.sock"),
            uid: caller.uid(),
            gid: caller.gid(),
        };
        let mesh = MeshId::new();
        let peer = PeerId::new();
        let now = crate::current_unix_time().unwrap();
        let root_key = RootSigningKey::from_bytes(&[1; 32]);
        let authority = AuthoritySigningKey::from_bytes(&[2; 32]);
        let cert = root_key
            .certify(UnsignedAuthority {
                mesh_id: mesh,
                serial: CredentialSerial::new(),
                public_key: authority.public_key(),
                not_before: UnixTime(now - 60),
                not_after: UnixTime(now + 3600),
            })
            .unwrap();
        let noise = StaticSecret::from([3; 32]);
        let data = StaticSecret::from([4; 32]);
        let identity = IdentitySigningKey::from_bytes(&[5; 32]);
        let credential = authority
            .issue(UnsignedSubject {
                subject: SubjectId::Peer(peer),
                mesh_id: mesh,
                identity_public_key: identity.verifying_key().to_bytes(),
                public_noise_key: NoisePublicKey::from(&noise).to_bytes(),
                wireguard_public_key: NoisePublicKey::from(&data).to_bytes(),
                serial: CredentialSerial::new(),
                not_before: UnixTime(now - 30),
                not_after: UnixTime(now + 1800),
            })
            .unwrap();
        let distribution = authority.certify_distribution(mesh, [6; 32], [7; 32], [8; 32]);
        for (name, bytes) in [
            (
                "root.pub",
                hex::encode(root_key.public_key().to_bytes()).into_bytes(),
            ),
            ("authority.cert", cert.encode()),
            ("distribution.cert", distribution.encode().to_vec()),
            ("peer.credential", credential.encode()),
            ("peer.key", hex::encode(noise.to_bytes()).into_bytes()),
            (
                "peer.wireguard.key",
                hex::encode(data.to_bytes()).into_bytes(),
            ),
            (
                "peer.identity.key",
                hex::encode(identity.to_bytes()).into_bytes(),
            ),
        ] {
            write_new(&source.join(name), &bytes).unwrap();
        }
        let path = |s: &str| root.join(s).display().to_string();
        let config = format!(
            r#"config_version = 4
mesh_id = "{mesh}"
peer_id = "{peer}"
credential_file = "peer.credential"
identity_private_key_file = "peer.identity.key"
private_key_file = "peer.key"
wireguard_private_key_file = "peer.wireguard.key"
root_public_key_file = "root.pub"
authority_certificate_files = ["authority.cert"]
distribution_certificate_file = "distribution.cert"
distribution_public_key = "{}"
service_distribution_public_key = "{}"
audit_public_key = "{}"
management_socket = "{}"
service_state_file = "{}"
[[relays]]
relay_id = "81708cad-c18b-4d0f-a580-026c4c285845"
endpoints = ["tcp://127.0.0.1:7777"]
public_key = "{}"
[linux]
interface = "pwd0"
address = "10.42.0.7/24"
routes = ["10.42.0.0/24"]
dns_suffix = "mesh.test"
dns_server = "10.42.0.1"
platform_state_file = "{}"
"#,
            hex::encode([6; 32]),
            hex::encode([7; 32]),
            hex::encode([8; 32]),
            path("run/peer.sock"),
            path("services.json"),
            hex::encode([9; 32]),
            path("network.json")
        );
        write_new(&source.join("peer.toml"), config.as_bytes()).unwrap();
        Self {
            root,
            source,
            layout,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn installs_trusted_identity_preserves_checkpoints_and_keeps_current_state_on_retry() {
    let f = Fixture::new();
    private_files::private_dir(&f.source.join("peer.wireguard-state")).unwrap();
    let checkpoint = f.source.join("peer.wireguard-state/high-water.json");
    write_new(&checkpoint, b"retained trust history").unwrap();
    let source = inspect_saved_configuration(&f.source.join("peer.toml")).unwrap();
    let prefs = peerward_management::SavedClientPreferences::new(source.mesh_id, source.peer_id);
    write_new(
        &f.root.join("network.preferences.json"),
        &serde_json::to_vec(&prefs).unwrap(),
    )
    .unwrap();
    assert!(install_profile(&f.source, &f.layout).unwrap());
    let installed = inspect_saved_configuration(&f.layout.config).unwrap();
    same_identity(&source, &installed).unwrap();
    verify_identity(&installed).unwrap();
    assert_eq!(
        fs::read(
            f.layout
                .profile
                .join("peer.wireguard-state/high-water.json")
        )
        .unwrap(),
        b"retained trust history"
    );
    assert!(
        f.layout
            .profile
            .join("runtime/network-state-v1.preferences.json")
            .exists()
    );
    for name in ["peer.key", "peer.identity.key", "peer.wireguard.key"] {
        let meta = fs::metadata(f.layout.profile.join(name)).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600);
        assert_eq!(meta.uid(), f.layout.uid);
    }
    assert_eq!(
        fs::metadata(&f.layout.config).unwrap().mode() & 0o777,
        0o640
    );
    fs::write(
        f.layout
            .profile
            .join("peer.wireguard-state/high-water.json"),
        b"newer trust history",
    )
    .unwrap();
    assert!(!install_profile(&f.source, &f.layout).unwrap());
    assert_eq!(
        fs::read(
            f.layout
                .profile
                .join("peer.wireguard-state/high-water.json")
        )
        .unwrap(),
        b"newer trust history"
    );
}

#[test]
fn interrupted_config_publication_resumes_without_recopying_old_state() {
    let f = Fixture::new();
    assert!(install_profile(&f.source, &f.layout).unwrap());
    fs::remove_file(&f.layout.config).unwrap();
    write_new(&f.layout.profile.join("after-install"), b"keep").unwrap();
    assert!(install_profile(&f.source, &f.layout).unwrap());
    assert_eq!(
        fs::read(f.layout.profile.join("after-install")).unwrap(),
        b"keep"
    );
}

#[test]
fn foreign_identity_existing_configuration_and_unfinished_network_are_not_overwritten() {
    let f = Fixture::new();
    let other = Fixture::new();
    write_new(&f.root.join("network.exit-guard.json"), b"pending recovery").unwrap();
    assert!(install_profile(&f.source, &f.layout).is_err());
    assert!(!f.layout.config.exists());
    fs::remove_file(f.root.join("network.exit-guard.json")).unwrap();
    assert!(install_profile(&f.source, &f.layout).unwrap());
    let before = fs::read(&f.layout.config).unwrap();
    assert!(install_profile(&other.source, &f.layout).is_err());
    assert_eq!(fs::read(&f.layout.config).unwrap(), before);
}

#[test]
fn running_profiles_symlinks_and_external_identity_paths_are_rejected() {
    let f = Fixture::new();
    let lock = peerward_platform::LocalRuntimeLock::acquire(
        &f.layout.socket.with_extension("runtime.lock"),
    )
    .unwrap();
    assert!(install_profile(&f.source, &f.layout).is_err());
    drop(lock);
    std::os::unix::fs::symlink(f.source.join("peer.key"), f.source.join("linked-key")).unwrap();
    assert!(install_profile(&f.source, &f.layout).is_err());
    assert!(!f.layout.profile.exists());
    fs::remove_file(f.source.join("linked-key")).unwrap();
    let config = fs::read_to_string(f.source.join("peer.toml")).unwrap();
    fs::copy(f.source.join("peer.key"), f.root.join("external.key")).unwrap();
    fs::write(
        f.source.join("peer.toml"),
        config.replace(
            "private_key_file = \"peer.key\"",
            "private_key_file = \"../external.key\"",
        ),
    )
    .unwrap();
    assert!(install_profile(&f.source, &f.layout).is_err());
    assert!(!f.layout.config.exists());
}

#[test]
fn a_terminated_mesh_profile_cannot_be_installed() {
    let f = Fixture::new();
    write_new(
        &f.source.join("peer.mesh-terminated"),
        b"terminal Mesh state",
    )
    .unwrap();
    assert!(install_profile(&f.source, &f.layout).is_err());
    assert!(!f.layout.config.exists());
}
