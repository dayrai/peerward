/// Opaque pre-admission connection ownership; only the carrier can construct it.
pub struct Context {
    owner: Owner,
}
struct ContextStream {
    context: Option<Context>,
    control: BoxStream,
}
impl super::RelayIo for ControlStream {}
impl super::RelayIo for ContextStream {
    fn take_quic(&mut self) -> Option<Context> {
        self.context.take()
    }
    fn is_quic(&self) -> bool {
        true
    }
}
impl AsyncRead for ContextStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.control).poll_read(cx, buf)
    }
}
impl AsyncWrite for ContextStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.control).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.control).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.control).poll_shutdown(cx)
    }
}
impl PendingQuic {
    pub fn into_stream(self) -> BoxStream {
        Box::new(ContextStream {
            context: Some(Context { owner: self.owner }),
            control: self.control,
        })
    }
}
fn shared_budgets(mesh: peerward_types::MeshId) -> io::Result<(Budget, Budget)> {
    use std::collections::BTreeMap;
    use std::sync::{Mutex, OnceLock};
    static PROCESS: OnceLock<Budget> = OnceLock::new();
    static MESHES: OnceLock<Mutex<BTreeMap<peerward_types::MeshId, Budget>>> = OnceLock::new();
    let mut meshes = MESHES
        .get_or_init(Mutex::default)
        .lock()
        .map_err(|_| invalid("QUIC budget registry poisoned"))?;
    meshes.retain(|_, budget| budget.shared());
    if !meshes.contains_key(&mesh) && meshes.len() >= 1024 {
        return Err(invalid("QUIC Mesh budget limit"));
    }
    let mesh = meshes
        .entry(mesh)
        .or_insert_with(|| Budget::new(4 * 1024 * 1024))
        .clone();
    Ok((
        PROCESS
            .get_or_init(|| Budget::new(64 * 1024 * 1024))
            .clone(),
        mesh,
    ))
}
/// Called AFTER the existing Root/Authority/credential/role checks. TCP and WSS
/// retain their Noise codec. QUIC moves Noise ownership into its transport task.
pub async fn activate(
    mut socket: BoxStream,
    transport: super::RecordTransport,
    preface: Option<RelayPreface>,
    now: u64,
) -> io::Result<(BoxStream, super::RecordTransport)> {
    let Some(context) = socket.take_quic() else {
        return Ok((socket, transport));
    };
    let preface = preface.ok_or_else(|| invalid("QUIC requires routed Wire 4 authentication"))?;
    let (process, mesh) = shared_budgets(preface.mesh_id)?;
    let pending = PendingQuic {
        owner: context.owner,
        control: socket,
    };
    let link = pending
        .admit(
            transport.into_noise().map_err(io::Error::other)?,
            preface,
            process,
            mesh,
            now,
        )
        .await?;
    Ok((
        super::quic_bridge::bridge(link),
        super::RecordTransport::local(now),
    ))
}
