#[allow(dead_code)]
#[path = "../build.rs"]
mod asset_build;

#[test]
fn client_version_changes_with_sources_and_is_independent_of_checkout_path() {
    let directory = std::env::temp_dir().join(format!("peerward-assets-{}", uuid::Uuid::new_v4()));
    let first = directory.join("native");
    let second = directory.join("wasm");
    for root in [&first, &second] {
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/ui.rs"), "old UI").unwrap();
    }
    let original = asset_build::fingerprint(&first, &["src"]).unwrap();
    assert_eq!(
        original,
        asset_build::fingerprint(&second, &["src"]).unwrap()
    );
    std::fs::write(second.join("src/ui.rs"), "new UI").unwrap();
    assert_ne!(
        original,
        asset_build::fingerprint(&second, &["src"]).unwrap()
    );
    std::fs::write(second.join("src/ui.rs"), "old UI").unwrap();
    std::fs::write(second.join("src/new.rs"), "new component").unwrap();
    assert_ne!(
        original,
        asset_build::fingerprint(&second, &["src"]).unwrap()
    );
    std::fs::remove_dir_all(directory).unwrap();
}
