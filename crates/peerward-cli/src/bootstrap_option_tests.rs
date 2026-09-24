#[cfg(test)]
mod bootstrap_option_tests {
    use super::*;

    async fn generate(args: &[&str]) -> (PathBuf, BootstrapManifest) {
        let output = std::env::temp_dir().join(format!("peerward-options-{}", Uuid::new_v4()));
        let mut arguments = vec![
            "peerward",
            "bootstrap",
            "generate",
            "--output-dir",
            output.to_str().unwrap(),
        ];
        arguments.extend_from_slice(args);
        let cli = Cli::try_parse_from(arguments).expect("bootstrap options must be accepted");
        assert_eq!(execute(cli).await, EXIT_SUCCESS);
        let manifest =
            toml::from_str(&fs::read_to_string(output.join("initialize.toml")).unwrap()).unwrap();
        (output, manifest)
    }

    #[tokio::test]
    async fn supplied_mesh_identity_and_config_reach_verified_bundle() {
        let (output, manifest) = generate(&[
            "--mesh-id",
            "941688bc-1b8f-4e67-9828-601e24c23b92",
            "--name",
            "Managed mesh",
            "--address-cidr",
            "10.44.0.0/24",
            "--gateway",
            "10.44.0.1",
            "--dns-suffix",
            "managed.mesh",
            "--mtu",
            "1420",
            "--default-policy",
            "allow",
            "--quarantine-seconds",
            "123",
            "--rotation-overlap-seconds",
            "456",
            "--reserved",
            "10.44.0.2",
            "--reserved",
            "10.44.0.3",
        ])
        .await;
        let installation = verify_bootstrap_manifest(manifest).unwrap();
        assert_eq!(
            installation.mesh_id.to_string(),
            "941688bc-1b8f-4e67-9828-601e24c23b92"
        );
        assert_eq!(installation.mesh.name, "Managed mesh");
        assert_eq!(installation.mesh.address_cidr.to_string(), "10.44.0.0/24");
        assert_eq!(installation.mesh.gateway.to_string(), "10.44.0.1");
        assert_eq!(installation.mesh.dns_suffix, "managed.mesh");
        assert_eq!(installation.mesh.mtu, 1420);
        assert_eq!(installation.mesh.default_policy, DefaultPolicy::Allow);
        assert_eq!(installation.mesh.quarantine_seconds, 123);
        assert_eq!(installation.mesh.rotation_overlap_seconds, 456);
        assert_eq!(
            installation
                .mesh
                .reserved
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["10.44.0.2", "10.44.0.3"]
        );
        let distribution = DistributionCertificate::decode(
            &fs::read(output.join("relay/identity/distribution.cert")).unwrap(),
        )
        .unwrap();
        assert_eq!(distribution.mesh_id, installation.mesh_id);
        fs::remove_dir_all(output).unwrap();
    }

    #[tokio::test]
    async fn defaults_produce_a_verified_manifest_with_conservative_mtu() {
        let (output, manifest) = generate(&[]).await;
        assert_eq!(manifest.mesh.name, "Peerward Development");
        assert_eq!(manifest.mesh.address_cidr.to_string(), "100.96.0.0/16");
        assert_eq!(manifest.mesh.gateway.to_string(), "100.96.0.1");
        assert_eq!(manifest.mesh.dns_suffix, "peerward.internal");
        assert_eq!(manifest.mesh.mtu, 1280);
        assert_eq!(manifest.mesh.default_policy, DefaultPolicy::Deny);
        assert_eq!(manifest.mesh.quarantine_seconds, 3600);
        assert_eq!(manifest.mesh.rotation_overlap_seconds, 86400);
        assert!(manifest.mesh.reserved.is_empty());
        verify_bootstrap_manifest(manifest).unwrap();
        fs::remove_dir_all(output).unwrap();
    }

    #[tokio::test]
    async fn invalid_configuration_never_installs_bundle() {
        for args in [
            vec!["--name", " "],
            vec!["--gateway", "192.0.2.1"],
            vec!["--reserved", "192.0.2.1"],
            vec!["--dns-suffix", "UPPER.invalid"],
            vec!["--mtu", "1279"],
            vec!["--rotation-overlap-seconds", "604801"],
            vec!["--quarantine-seconds", "18446744073709551615"],
            vec!["--mesh-id", "00000000-0000-0000-0000-000000000000"],
            vec!["--default-policy", "unknown"],
        ] {
            let output = std::env::temp_dir().join(format!("peerward-invalid-{}", Uuid::new_v4()));
            let mut arguments = vec![
                "peerward",
                "bootstrap",
                "generate",
                "--output-dir",
                output.to_str().unwrap(),
            ];
            arguments.extend(args);
            if let Ok(cli) = Cli::try_parse_from(arguments) {
                assert_eq!(execute(cli).await, EXIT_INVALID);
            }
            assert!(!output.exists());
        }
    }
}
