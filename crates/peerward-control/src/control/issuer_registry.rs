/// Readers retain one immutable snapshot through a request; writers replace
/// individual Mesh entries without holding a lock across any await point.
#[derive(Clone, Default)]
struct IssuerRegistry(Arc<std::sync::RwLock<HashMap<MeshId, Vec<Arc<JoinIssuer>>>>>);

impl From<HashMap<MeshId, Vec<Arc<JoinIssuer>>>> for IssuerRegistry {
    fn from(values: HashMap<MeshId, Vec<Arc<JoinIssuer>>>) -> Self {
        Self(Arc::new(std::sync::RwLock::new(values)))
    }
}

impl IssuerRegistry {
    fn snapshot(&self) -> HashMap<MeshId, Vec<Arc<JoinIssuer>>> {
        self.0.read().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
    }
    fn get(&self, mesh: &MeshId) -> Option<Vec<Arc<JoinIssuer>>> {
        self.0.read().unwrap_or_else(std::sync::PoisonError::into_inner).get(mesh).cloned()
    }
    fn install(&self, mesh: MeshId, issuers: Vec<Arc<JoinIssuer>>) {
        self.0.write().unwrap_or_else(std::sync::PoisonError::into_inner).insert(mesh, issuers);
    }
    fn remove(&self, mesh: &MeshId) {
        self.0.write().unwrap_or_else(std::sync::PoisonError::into_inner).remove(mesh);
    }
    fn is_empty(&self) -> bool {
        self.0.read().unwrap_or_else(std::sync::PoisonError::into_inner).is_empty()
    }
    fn keys(&self) -> Vec<MeshId> { self.snapshot().into_keys().collect() }
}
