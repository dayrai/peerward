use super::*;

fn profile_fixture(root: &Path, name: &str, mesh: MeshId, peer: peerward_types::PeerId) -> PathBuf {
    peerward_credentials::private_files::private_dir(root).unwrap();
    let path = root.join(format!("{name}.toml"));
    fs::write(
        &path,
        format!(
            r#"config_version = 4
mesh_id = "{mesh}"
peer_id = "{peer}"
credential_file = "{name}.cert"
identity_private_key_file = "{name}.identity.key"
private_key_file = "{name}.noise.key"
wireguard_private_key_file = "{name}.wireguard.key"
management_socket = "peer.sock"
[[relays]]
relay_id = "81708cad-c18b-4d0f-a580-026c4c285845"
endpoints = ["tcp://127.0.0.1:7777"]
public_key = "00"
[linux]
interface = "peerward-test0"
address = "10.42.0.7/24"
routes = ["10.42.0.0/24"]
dns_suffix = "mesh.test"
dns_server = "10.42.0.1"
platform_state_file = "{name}.network.json"
"#
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

#[test]
fn saved_profiles_select_exact_names_keep_files_and_survive_restart() {
    let root = std::env::temp_dir().join(format!("peerward-catalog-{}", Uuid::new_v4()));
    let catalog = root.join("catalog");
    let a = profile_fixture(&root, "home", MeshId::new(), peerward_types::PeerId::new());
    let b = profile_fixture(
        &root,
        "office",
        MeshId::new(),
        peerward_types::PeerId::new(),
    );
    for (name, config) in [("Home", a.clone()), ("Office", b.clone())] {
        execute_profile_command(ProfileCommand::Save {
            catalog: catalog.clone(),
            name: name.into(),
            config,
        })
        .unwrap();
    }
    let initial = read_saved_catalog(&catalog).unwrap();
    assert_eq!(initial.profiles.len(), 2);
    assert_eq!(initial.active, Some(initial.profiles[0].peer_id));
    execute_profile_command(ProfileCommand::Select {
        catalog: catalog.clone(),
        name: "Office".into(),
    })
    .unwrap();
    let selected = read_saved_catalog(&catalog).unwrap();
    assert_eq!(selected.active, Some(selected.profiles[1].peer_id));
    assert!(
        execute_profile_command(ProfileCommand::Remove {
            catalog: catalog.clone(),
            name: "Office".into()
        })
        .is_err()
    );
    execute_profile_command(ProfileCommand::Remove {
        catalog: catalog.clone(),
        name: "Home".into(),
    })
    .unwrap();
    assert!(
        a.exists() && b.exists(),
        "catalog removal never deletes credentials or configuration"
    );
    execute_profile_command(ProfileCommand::Deactivate {
        catalog: catalog.clone(),
    })
    .unwrap();
    assert!(read_saved_catalog(&catalog).unwrap().active.is_none());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn catalog_and_runtime_locks_fence_switches_but_reading_remains_available() {
    let root = std::env::temp_dir().join(format!("peerward-catalog-{}", Uuid::new_v4()));
    let catalog = root.join("catalog");
    let config = profile_fixture(&root, "home", MeshId::new(), peerward_types::PeerId::new());
    execute_profile_command(ProfileCommand::Save {
        catalog: catalog.clone(),
        name: "Home".into(),
        config: config.clone(),
    })
    .unwrap();
    let (guard, state) = SavedCatalogFile::open(&catalog).unwrap();
    assert!(SavedCatalogFile::open(&catalog).is_err());
    assert_eq!(read_saved_catalog(&catalog).unwrap(), state);
    execute_profile_command(ProfileCommand::List {
        catalog: catalog.clone(),
    })
    .unwrap();
    drop(guard);
    let runtime =
        peerward_platform::LocalRuntimeLock::acquire(&root.join("peer.runtime.lock")).unwrap();
    assert!(
        execute_profile_command(ProfileCommand::Deactivate {
            catalog: catalog.clone()
        })
        .is_err()
    );
    drop(runtime);
    execute_profile_command(ProfileCommand::Deactivate { catalog }).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn persistent_exit_protection_is_not_removed_by_profile_switching() {
    let root = std::env::temp_dir().join(format!("peerward-catalog-{}", Uuid::new_v4()));
    let catalog = root.join("catalog");
    for name in ["home", "office"] {
        let config = profile_fixture(&root, name, MeshId::new(), peerward_types::PeerId::new());
        execute_profile_command(ProfileCommand::Save {
            catalog: catalog.clone(),
            name: name.into(),
            config,
        })
        .unwrap();
    }
    let state = read_saved_catalog(&catalog).unwrap();
    // The real state path uses Path::with_extension, not appended suffixes.
    let protection = state.profiles[0]
        .platform_state_file
        .as_ref()
        .unwrap()
        .with_extension("exit-guard.json");
    fs::write(&protection, "opaque recovery record").unwrap();
    assert!(
        execute_profile_command(ProfileCommand::Select {
            catalog: catalog.clone(),
            name: "office".into()
        })
        .is_err()
    );
    assert!(
        execute_profile_command(ProfileCommand::Deactivate {
            catalog: catalog.clone()
        })
        .is_err()
    );
    assert_eq!(read_saved_catalog(&catalog).unwrap(), state);
    assert!(protection.exists());
    fs::remove_file(protection).unwrap();
    for extension in ["resources.json", "dns.json", "exit-routes.json"] {
        let journal = state.profiles[0]
            .platform_state_file
            .as_ref()
            .unwrap()
            .with_extension(extension);
        fs::write(&journal, "unfinished rollback").unwrap();
        assert!(
            execute_profile_command(ProfileCommand::Select {
                catalog: catalog.clone(),
                name: "office".into()
            })
            .is_err()
        );
        assert_eq!(read_saved_catalog(&catalog).unwrap(), state);
        fs::remove_file(journal).unwrap();
    }
    execute_profile_command(ProfileCommand::Select {
        catalog,
        name: "office".into(),
    })
    .unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn damaged_identity_or_catalog_is_never_silently_replaced() {
    let root = std::env::temp_dir().join(format!("peerward-catalog-{}", Uuid::new_v4()));
    let catalog = root.join("catalog");
    let peer = peerward_types::PeerId::new();
    let config = profile_fixture(&root, "home", MeshId::new(), peer);
    execute_profile_command(ProfileCommand::Save {
        catalog: catalog.clone(),
        name: "Home".into(),
        config: config.clone(),
    })
    .unwrap();
    let original = read_saved_catalog(&catalog).unwrap();
    fs::write(
        &config,
        fs::read_to_string(&config).unwrap().replace(
            &peer.to_string(),
            &peerward_types::PeerId::new().to_string(),
        ),
    )
    .unwrap();
    assert!(load_saved_entry(&original.profiles[0]).is_err());
    assert_eq!(read_saved_catalog(&catalog).unwrap(), original);
    fs::write(catalog.join("profiles.json"), "{broken").unwrap();
    assert!(SavedCatalogFile::open(&catalog).is_err());
    assert_eq!(
        fs::read_to_string(catalog.join("profiles.json")).unwrap(),
        "{broken"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn peer_command_preserves_explicit_config_and_rejects_ambiguous_selection() {
    assert!(Cli::try_parse_from(["peerward", "peer", "run", "--config", "peer.toml"]).is_ok());
    assert!(Cli::try_parse_from(["peerward", "peer", "run", "--catalog", "saved"]).is_ok());
    assert!(Cli::try_parse_from(["peerward", "peer", "run"]).is_err());
    assert!(
        Cli::try_parse_from([
            "peerward",
            "peer",
            "run",
            "--config",
            "peer.toml",
            "--catalog",
            "saved"
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "peerward",
            "client",
            "profiles",
            "select",
            "--catalog",
            "saved",
            "--name",
            "Home"
        ])
        .is_ok()
    );
}
