impl ApiClient {
    /// Expands a bounded Relay drill-down into complete, versioned device resources.
    async fn peer_node_resources(
        &self,
        mesh: &str,
        nodes: Vec<TopologyNodeItem>,
    ) -> Result<Vec<ResourceSummary>, ConsoleApiError> {
        use futures_util::TryStreamExt as _;
        futures_util::stream::iter(nodes.into_iter().map(|node| async move {
            let peer: PeerResource = self.request(
                Method::GET,
                &ResourceFamily::Peers.member_path(mesh, &node.id.to_string()),
                None,
            ).await?;
            Ok(ResourceSummary::from(peer))
        })).buffered(4).try_collect().await
    }

    /// Soft-deletes a disabled Peer after exact-name confirmation.
    pub async fn delete_peer(
        &self,
        mesh: &str,
        id: &str,
        body: &PeerDeleteRequest,
        version: u64,
    ) -> Result<Value, ConsoleApiError> {
        let path = format!("{}/delete", ResourceFamily::Peers.member_path(mesh, id));
        self.conditional_request(Method::POST, &path, Some(body_value(body)?), version).await
    }
}
