async fn resolve_network_collections(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mesh: Uuid,
) -> Result<Vec<peerward_management::ResolvedCollection>, ApiError> {
    use peerward_management::{CollectionDefinition, CollectionKind};
    type Candidates = Vec<(Uuid, BTreeMap<String, String>)>;
    let definitions: Vec<(Uuid, Value)> = sqlx::query_as(
        "SELECT id,definition FROM network_collections WHERE mesh_id=$1 ORDER BY id",
    )
    .bind(mesh)
    .fetch_all(&mut **tx)
    .await?;
    if definitions.len() > 64 {
        return Err(publisher_error());
    }
    let peers:Vec<(Uuid,Value)>=sqlx::query_as("SELECT id,labels FROM peers WHERE mesh_id=$1 AND administrative_state='enabled' ORDER BY id")
        .bind(mesh).fetch_all(&mut **tx).await?;
    let resources:Vec<(Uuid,Value)>=sqlx::query_as("SELECT id,COALESCE(definition->'labels','{}'::jsonb) FROM network_resources WHERE mesh_id=$1 ORDER BY id")
        .bind(mesh).fetch_all(&mut **tx).await?;
    let decode = |rows: Vec<(Uuid, Value)>| -> Result<Candidates, ApiError> {
        rows.into_iter()
            .map(|(id, labels)| {
                Ok((
                    id,
                    serde_json::from_value(labels).map_err(|_| publisher_error())?,
                ))
            })
            .collect()
    };
    let peers = decode(peers)?;
    let resources = decode(resources)?;
    definitions
        .into_iter()
        .map(|(id, value)| {
            let definition: CollectionDefinition =
                serde_json::from_value(value).map_err(|_| publisher_error())?;
            definition.validate().map_err(management_error)?;
            let rows = match definition.kind {
                CollectionKind::Devices => &peers,
                CollectionKind::Resources => &resources,
            };
            let resolved = definition.resolve(id, rows.iter().map(|(id, labels)| (*id, labels)));
            if resolved.members.len() > 4096 {
                return Err(ApiError::invalid(
                    "collection_too_large",
                    "resolved collection exceeds 4096 members",
                ));
            }
            Ok(resolved)
        })
        .collect()
}

fn validate_rule_collections(
    rule: &peerward_management::ResourceRule,
    collections: &[peerward_management::ResolvedCollection],
) -> Result<(), ApiError> {
    for (ids, kind) in [
        (
            &rule.source_collections,
            peerward_management::CollectionKind::Devices,
        ),
        (
            &rule.resource_collections,
            peerward_management::CollectionKind::Resources,
        ),
    ] {
        if ids.iter().any(|id| {
            !collections
                .iter()
                .any(|collection| collection.id == *id && collection.kind == kind)
        }) {
            return Err(ApiError::invalid(
                "collection_reference",
                "rule references a missing collection or the wrong collection kind",
            ));
        }
    }
    Ok(())
}
