//! Typed `PostgreSQL` persistence, transactional mutations, and event delivery.

/// Persistent schema generation accepted by this clean-install baseline.
pub const SCHEMA_VERSION: u32 = 4;

include!("store/bootstrap.rs");
include!("store/provision.rs");
include!("store/mesh_lifecycle.rs");
include!("store/meshes.rs");
include!("store/mesh_join.rs");
include!("store/join_tickets.rs");
include!("store/join_groups.rs");
include!("store/join_applications.rs");
include!("store/peer_admission.rs");
include!("store/identity_presence.rs");
include!("store/events_auth.rs");
include!("store/maintenance.rs");
include!("store/audit_ingest.rs");
include!("store/signed_state.rs");
include!("store/rotation.rs");
include!("store/service_registry.rs");
include!("store/peer_management.rs");
include!("store/device_evidence.rs");
include!("store/auto_approval.rs");
include!("store/configuration_ownership.rs");
include!("store/audit_writer.rs");
include!("store/model.rs");
include!("store/migrations.rs");
include!("store/support.rs");

#[cfg(test)]
include!("store/identity_presence_tests.rs");

include!("store/console_renewal.rs");
