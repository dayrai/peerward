pub use peerward_management::{ClientPreferenceRequest, ClientPreferenceView};

/// Runtime-owned handler, reached only after the existing local UID authentication.
#[async_trait::async_trait]
pub trait ClientManagement: Send + Sync {
    async fn execute(
        &self,
        request: ClientPreferenceRequest,
    ) -> Result<ClientPreferenceView, String>;
}
impl PeerObservability {
    pub fn set_client_management(&self, handler: Arc<dyn ClientManagement>) {
        *self
            .client_management
            .write()
            .expect("client management lock") = Some(handler);
    }
    async fn client_preferences(&self, request: ClientPreferenceRequest) -> Response {
        let handler = self
            .client_management
            .read()
            .expect("client management lock")
            .clone();
        let Some(handler) = handler else {
            return Response::failure("client_runtime_unavailable");
        };
        match tokio::time::timeout(Duration::from_secs(20), handler.execute(request)).await {
            Ok(Ok(view)) => Response {
                detail: serde_json::to_value(view).expect("typed preference view"),
                ..Response::success()
            },
            Ok(Err(reason)) => Response::failure(&reason),
            Err(_) => Response::failure("client_change_pending_query_before_retry"),
        }
    }
}
