use crate::{ManagementError, name_valid};
use peerward_types::MeshId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionKind {
    Devices,
    Resources,
}

/// Explicit members OR a nonempty conjunction of controlled labels. No nesting,
/// queries, wildcard identity expansion or implicit "all" for an empty collection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionDefinition {
    pub name: String,
    pub kind: CollectionKind,
    #[serde(default)]
    pub members: BTreeSet<Uuid>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}
impl CollectionDefinition {
    pub fn validate(&self) -> Result<(), ManagementError> {
        if !name_valid(&self.name)
            || self.members.len() > 4096
            || self.labels.len() > 32
            || self.members.iter().any(|id| id.get_version_num() != 4)
            || self.labels.iter().any(|(key, value)| {
                !name_valid(key)
                    || value.is_empty()
                    || value.len() > 256
                    || value.chars().any(char::is_control)
            })
        {
            return Err(ManagementError::Invalid("collection"));
        }
        Ok(())
    }
    /// Candidate identities must already be scoped to this Mesh and eligible.
    pub fn resolve<'a>(
        &self,
        id: Uuid,
        candidates: impl IntoIterator<Item = (Uuid, &'a BTreeMap<String, String>)>,
    ) -> ResolvedCollection {
        ResolvedCollection {
            id,
            kind: self.kind,
            members: candidates
                .into_iter()
                .filter_map(|(member, labels)| {
                    (self.members.contains(&member)
                        || (!self.labels.is_empty()
                            && self
                                .labels
                                .iter()
                                .all(|(key, value)| labels.get(key) == Some(value))))
                    .then_some(member)
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Collection {
    pub id: Uuid,
    pub mesh_id: MeshId,
    pub version: u64,
    pub definition: CollectionDefinition,
}

/// Signed, resolved membership belongs to the same configuration as its rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedCollection {
    pub id: Uuid,
    pub kind: CollectionKind,
    pub members: BTreeSet<Uuid>,
}

pub fn collection_contains(
    collections: &[ResolvedCollection],
    selected: &BTreeSet<Uuid>,
    kind: CollectionKind,
    member: Uuid,
) -> bool {
    collections.iter().any(|collection| {
        collection.kind == kind
            && selected.contains(&collection.id)
            && collection.members.contains(&member)
    })
}
