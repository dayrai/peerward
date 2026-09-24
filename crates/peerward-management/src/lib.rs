//! Platform-independent management state. Resources never impersonate tunnel peers.

mod auto_approval;
mod client_network;
pub use auto_approval::*;
mod collections;
pub use collections::*;
mod configuration;
mod dns;
mod internet_addresses;
pub use internet_addresses::internet_destination;
#[cfg(test)]
mod device_condition_tests;
mod device_conditions;
mod leases;
mod peer_commands;
mod preferences;
mod resource_policy;
mod resources;
mod target_health;
pub use device_conditions::*;
#[cfg(test)]
mod target_health_tests;
pub use target_health::*;
mod selection;
pub use configuration::*;
pub use dns::*;
pub use leases::*;
pub use peer_commands::*;
pub use preferences::*;
pub use resource_policy::*;
pub use resources::*;
pub use selection::*;

#[cfg(test)]
mod collection_tests;
#[cfg(test)]
mod selection_tests;
#[cfg(test)]
mod tests;

/// A bounded, public validation failure; never contains invitation or private material.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManagementError {
    #[error("invalid field: {0}")]
    Invalid(&'static str),
    #[error("conflicting configuration: {0}")]
    Conflict(&'static str),
    #[error("configuration signature is invalid")]
    Signature,
    #[error("configuration dependencies are incomplete")]
    Incomplete,
    #[error("authorization has expired or clock is invalid")]
    Expired,
    #[error("state rollback or sequence reuse")]
    Rollback,
}

/// Shared bounded resource name validation used by management adapters.
pub fn name_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.trim() == name
        && !name.chars().any(char::is_control)
}

/// Content digest over a deterministic, strict typed JSON document.
pub fn content_digest<T: serde::Serialize>(value: &T) -> Result<[u8; 32], ManagementError> {
    use sha2::Digest as _;
    Ok(sha2::Sha256::digest(
        serde_json::to_vec(value).map_err(|_| ManagementError::Invalid("encoding"))?,
    )
    .into())
}

mod addresses;
pub use addresses::validate_assignments;

mod enrollment;
pub use enrollment::*;

mod webhooks;
pub use webhooks::*;

mod credential_renewal;
pub use credential_renewal::*;
