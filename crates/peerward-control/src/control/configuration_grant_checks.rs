/// Definitions are a union of explicit members and a conjunction of labels.
/// This proof is symbolic, so a later label change cannot invalidate its claim.
fn collection_scope_subset(
    narrow: &peerward_management::CollectionDefinition,
    broad: &peerward_management::CollectionDefinition,
) -> bool {
    narrow.kind == broad.kind
        && narrow.members.is_subset(&broad.members)
        && (narrow.labels.is_empty()
            || (!broad.labels.is_empty()
                && broad
                    .labels
                    .iter()
                    .all(|(key, value)| narrow.labels.get(key) == Some(value))))
}

fn configuration_collections_only_restrict(
    old: &peerward_api::ConfigurationDocument,
    new: &peerward_api::ConfigurationDocument,
) -> bool {
    if new.collections.iter().any(|collection| {
        old.collections
            .iter()
            .find(|prior| prior.id == collection.id)
            .is_none_or(|prior| !collection_scope_subset(&collection.definition, &prior.definition))
    }) {
        return false;
    }
    // Narrowing a Deny selector can grant access through a subsequent Allow.
    // Every collection participating in an old enabled Deny must preserve or
    // expand its scope as well. Collections used for both actions cannot shrink.
    old.resource_policy
        .rules
        .iter()
        .filter(|rule| rule.enabled && rule.action == peerward_management::ResourceAction::Deny)
        .flat_map(|rule| {
            rule.source_collections
                .iter()
                .chain(&rule.resource_collections)
        })
        .all(|id| {
            old.collections
                .iter()
                .find(|c| c.id == *id)
                .zip(new.collections.iter().find(|c| c.id == *id))
                .is_some_and(|(prior, current)| {
                    collection_scope_subset(&prior.definition, &current.definition)
                })
        })
}

#[cfg(test)]
mod configuration_grant_check_tests {
    use super::*;
    #[test]
    fn empty_collection_and_stronger_conjunction_are_subsets_but_broader_or_are_not() {
        use peerward_management::{CollectionDefinition, CollectionKind};
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let broad = CollectionDefinition {
            name: "broad".into(),
            kind: CollectionKind::Devices,
            members: [a, b].into(),
            labels: [("team".into(), "finance".into())].into(),
        };
        let mut narrow = broad.clone();
        narrow.members.remove(&b);
        narrow.labels.insert("managed".into(), "yes".into());
        assert!(collection_scope_subset(&narrow, &broad));
        assert!(!collection_scope_subset(&broad, &narrow));
        narrow.labels.clear();
        assert!(collection_scope_subset(&narrow, &broad));
        narrow.members.clear();
        assert!(collection_scope_subset(&narrow, &broad));
        narrow.labels.insert("unrelated".into(), "value".into());
        assert!(!collection_scope_subset(&narrow, &broad));
        narrow = broad.clone();
        narrow.members.insert(Uuid::new_v4());
        assert!(!collection_scope_subset(&narrow, &broad));
    }
}
