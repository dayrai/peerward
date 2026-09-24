//! Peerward control-plane HTTP API, authentication, signed state, and runtime.

include!("control/bootstrap.rs");
include!("control/issuer_registry.rs");
include!("control/dynamic_mesh.rs");
include!("control/relay_host_api.rs");
include!("control/relay_capacity.rs");
include!("control/relay_capacity_tests.rs");
include!("control/audit_capacity.rs");
include!("control/console_read.rs");
include!("control/console_policy.rs");
include!("control/console_sharing_write.rs");
include!("control/console_sharing_create.rs");
include!("control/console_network_edit.rs");
include!("control/relay_host_admin.rs");
include!("control/relay_host_renewal.rs");
include!("control/managed_issuers.rs");
include!("control/runtime_serve.rs");
include!("control/publisher.rs");
include!("control/audit_collector.rs");
include!("control/maintenance.rs");
include!("control/maintenance_tasks.rs");
include!("control/maintenance_worker.rs");
include!("control/event_notifications.rs");
include!("control/router.rs");
include!("control/bulk.rs");
include!("control/meshes.rs");
include!("control/mesh_provisioning.rs");
include!("control/mesh_lifecycle_api.rs");
include!("control/peers.rs");
include!("control/relays.rs");
include!("control/lifecycle.rs");
include!("control/join.rs");
include!("control/join_issuance.rs");
include!("control/join_applications.rs");
include!("control/policy.rs");
include!("control/services_events.rs");
include!("control/network_resources.rs");
include!("control/target_health.rs");
include!("control/device_conditions.rs");
include!("control/collection_resolution.rs");
include!("control/collections.rs");
include!("control/dns_management.rs");
include!("control/packet_simulation.rs");
include!("control/configuration_observation.rs");
include!("control/resource_policy_management.rs");
include!("control/gateway_bindings.rs");
include!("control/auto_approval.rs");
include!("control/configuration_ownership.rs");
include!("control/configuration_export.rs");
include!("control/configuration_stage.rs");
include!("control/configuration_bindings.rs");
include!("control/configuration_apply.rs");
include!("control/oidc.rs");
include!("control/machine_credentials.rs");
include!("control/deployment_tasks.rs");
include!("control/deployment_exchange.rs");
include!("control/deployment_upgrade.rs");
include!("control/support.rs");
include!("control/tests.rs");

include!("control/webhooks.rs");

include!("control/webhook_worker.rs");

include!("control/webhook_deliveries.rs");
include!("control/webhook_http_tests.rs");
include!("control/webhook_tls_tests.rs");
include!("control/webhook_worker_tests.rs");

include!("control/configuration_grant_checks.rs");

include!("control/console_matrix.rs");

include!("control/console_grants.rs");
include!("control/console_resource_grants.rs");

include!("control/console_renewal.rs");

include!("control/console_devices.rs");
include!("control/console_routes.rs");
include!("control/console_enrollment_groups.rs");
