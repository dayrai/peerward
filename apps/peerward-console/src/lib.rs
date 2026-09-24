//! Responsive Dioxus management console and typed `/api/v1` client.

use std::collections::{BTreeMap, HashSet, VecDeque};

use dioxus::prelude::*;
use futures_util::StreamExt as _;
pub use peerward_api::{
    ApiErrorBody, AuditResource, AuthSession, AuthorityResource, AuthorityStageRequest,
    BulkCommitResponse, BulkPreviewResponse, BulkRequest, BulkResourceFamily, BulkResourceItem,
    CredentialResource, CredentialRotationRequest, ErrorEnvelope, JoinTicketCreateRequest,
    JoinTicketResource, MeshCreateRequest, MeshDeleteRequest, MeshPatchRequest,
    MeshProvisioningCreateRequest, MeshProvisioningResource, MeshResource, Page, PeerCreateRequest,
    PeerDeleteRequest, PeerPatchRequest, PeerResource, PolicyPutRequest, PolicySimulationRequest,
    PolicySimulationResponse, PolicyValidationResponse, RelayCreateRequest, RelayPatchRequest,
    RelayResource, ResourceSummary, ServiceCreateRequest, ServiceResource, TopologyEdgeItem,
    TopologyNodeItem, TopologyResource, TopologySummary,
};
use peerward_types::{CorrelationContext, CredentialSerial, MeshId, UnixTime};
use peerward_ui::{ErrorNotice, Locale, Message, PreferenceControls, Theme, UiError};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use thiserror::Error;

include!("client.rs");
include!("client_correlation.rs");
include!("console_i18n.rs");
include!("detail_views.rs");
include!("resources.rs");
include!("join_secret.rs");
include!("browser_actions.rs");
include!("invitation_lifecycle.rs");
include!("authority_import.rs");
include!("forms.rs");
include!("resource_editor.rs");
include!("resource_table.rs");
include!("mesh_summary.rs");
include!("bulk_actions.rs");
include!("mesh_provisioning.rs");
include!("navigation.rs");
include!("network_client.rs");
include!("network_panel.rs");
include!("collection_panel.rs");
include!("auto_approval_panel.rs");
include!("resource_policy_form.rs");
include!("resource_policy_panel.rs");
include!("dns_panel.rs");
include!("device_conditions_panel.rs");
include!("ui.rs");
#[cfg(feature = "ssr")]
pub mod server;
#[cfg(test)]
#[path = "tests.rs"]
mod tests;

#[cfg(test)]
mod network_panel_tests;

include!("join_application_panel.rs");
include!("enrollment_complete.rs");

include!("machine_credentials_panel.rs");
include!("configuration_ownership_panel.rs");
include!("configuration_panel.rs");

include!("webhooks_panel.rs");
include!("maintenance_panel.rs");
include!("deployment_panel.rs");
include!("capacity_panel.rs");
include!("operations_panel.rs");
