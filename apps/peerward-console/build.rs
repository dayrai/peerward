use std::{env, fs, io, path::Path};

// Both SSR and WASM use the same source identity. Do not include target or
// feature flags: the two builds must reference the same client generation.
const INPUTS: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "apps/peerward-console/Cargo.toml",
    "apps/peerward-console/build.rs",
    "apps/peerward-console/src",
    "apps/peerward-console/i18n",
    "apps/peerward-console/assets",
    "apps/peerward-ui/Cargo.toml",
    "apps/peerward-ui/src",
    "apps/peerward-ui/assets",
    "apps/peerward-ui/i18n",
    "crates/peerward-dioxus/Cargo.toml",
    "crates/peerward-dioxus/src",
    "crates/peerward-api/Cargo.toml",
    "crates/peerward-api/src",
    "crates/peerward-types/Cargo.toml",
    "crates/peerward-types/src",
];

fn main() {
    let manifest =
        env::var_os("CARGO_MANIFEST_DIR").expect("Cargo provides the manifest directory");
    let root = Path::new(&manifest).parent().unwrap().parent().unwrap();
    for input in INPUTS {
        println!("cargo:rerun-if-changed={}", root.join(input).display());
    }
    let version = fingerprint(root, INPUTS).expect("client sources must be readable");
    println!("cargo:rustc-env=PEERWARD_CONSOLE_ASSET_VERSION={version}");
}

/// Deterministic FNV-1a identifier for cache invalidation, not authentication.
pub fn fingerprint(root: &Path, inputs: &[&str]) -> io::Result<String> {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for input in inputs {
        hash_path(root, &root.join(input), &mut hash)?;
    }
    Ok(format!("{hash:016x}"))
}

fn hash_path(root: &Path, path: &Path, hash: &mut u64) -> io::Result<()> {
    if path.is_dir() {
        let mut entries = fs::read_dir(path)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<io::Result<Vec<_>>>()?;
        entries.sort();
        for entry in entries {
            hash_path(root, &entry, hash)?;
        }
    } else {
        let relative = path
            .strip_prefix(root)
            .expect("source path is within workspace");
        hash_bytes(
            hash,
            relative.to_string_lossy().replace('\\', "/").as_bytes(),
        );
        hash_bytes(hash, &fs::read(path)?);
    }
    Ok(())
}

fn hash_bytes(hash: &mut u64, bytes: &[u8]) {
    for byte in (bytes.len() as u64).to_le_bytes().iter().chain(bytes) {
        *hash ^= u64::from(*byte);
        *hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
}
