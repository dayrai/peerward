#[track_caller]
fn invalid_control_error(context: &str, error: impl std::fmt::Debug) -> PacketPumpError {
    let location = std::panic::Location::caller();
    tracing::error!(context, ?error, file = location.file(), line = location.line(), "Peer control validation failed");
    PacketPumpError::InvalidControl
}

/// Packet-pump failure.
#[derive(Debug, Error)]
pub enum PacketPumpError {
    /// A packet device or transport operation failed.
    #[error("packet I/O failed: {0}")]
    Io(#[from] io::Error),
    /// A Noise record failed validation.
    #[error("encrypted packet record failed")]
    Wire(#[from] peerward_wire::WireError),
    /// A direct-path operation failed.
    #[error("direct packet path failed")]
    Direct(#[from] peerward_p2p::P2pError),
    /// A control message was malformed or belonged to another mesh.
    #[error("direct control message is invalid")]
    InvalidControl,
    /// The first packet started an end-to-end handshake and was intentionally dropped.
    #[error("end-to-end Peer session is pending")]
    SessionPending,
    /// A packet failed strict IP parsing.
    #[error("packet is invalid")]
    InvalidPacket,
    /// A bounded packet-path queue rejected work.
    #[error("packet path queue is full")]
    QueueFull,
    /// No signed destination or usable packet path exists.
    #[error("packet destination has no route")]
    NoRoute,
}

/// Asynchronous source of complete IP packets.
#[async_trait]
pub trait PacketReader: Send {
    /// Reads exactly one packet, returning zero only at end of input.
    async fn read_packet(&mut self, buffer: &mut [u8]) -> Result<usize, PacketPumpError>;
}

/// Asynchronous destination for complete IP packets.
#[async_trait]
pub trait PacketWriter: Send {
    /// Writes one packet without changing its boundaries.
    async fn write_packet(&mut self, packet: &[u8]) -> Result<(), PacketPumpError>;
}

#[async_trait]
impl PacketReader for Box<dyn PacketReader> {
    async fn read_packet(&mut self, buffer: &mut [u8]) -> Result<usize, PacketPumpError> {
        self.as_mut().read_packet(buffer).await
    }
}

#[async_trait]
impl PacketWriter for Box<dyn PacketWriter> {
    async fn write_packet(&mut self, packet: &[u8]) -> Result<(), PacketPumpError> {
        self.as_mut().write_packet(packet).await
    }
}

/// Dynamically selected TUN read half.
pub type BoxPacketReader = Box<dyn PacketReader>;
/// Dynamically selected TUN write half.
pub type BoxPacketWriter = Box<dyn PacketWriter>;
/// Complete prepared packet device.
pub type PreparedTun = (BoxPacketReader, BoxPacketWriter);

/// Authenticated outbound packet path.
#[async_trait]
pub trait PacketSender: Send {
    /// Sends through direct UDP when healthy, otherwise through the relay immediately.
    async fn send_packet(
        &mut self,
        packet: &[u8],
        monotonic_seconds: u64,
    ) -> Result<DataPath, PacketPumpError>;
}

/// Relay capability that accepts only already end-to-end encrypted Peer frames.
#[async_trait]
pub trait OpaqueRelaySender: PacketSender {
    /// Routes one path-independent ciphertext to an exact signed-directory Peer.
    async fn send_opaque(
        &mut self,
        mesh_id: MeshId,
        destination: PeerId,
        ciphertext: &[u8],
    ) -> Result<DataPath, PacketPumpError>;

    /// Routes ciphertext using a stable local flow key when the sender supports multiple Relays.
    async fn send_opaque_on_flow(
        &mut self,
        mesh_id: MeshId,
        destination: PeerId,
        ciphertext: &[u8],
        _flow_key: u64,
    ) -> Result<DataPath, PacketPumpError> {
        self.send_opaque(mesh_id, destination, ciphertext).await
    }
}

/// Authenticated inbound packet path.
#[async_trait]
pub trait PacketReceiver: Send {
    /// Receives one complete, already authenticated packet.
    async fn receive_packet(&mut self) -> Result<(DataPath, Vec<u8>), PacketPumpError>;
}

/// Real adapter for a TUN file descriptor already attached by the Linux backend or supervisor.
///
/// The caller retains responsibility for `TUNSETIFF`; accepting an already attached descriptor
/// keeps unsafe ioctl code outside the protocol core and permits systemd file-descriptor passing.
pub struct AttachedTun;

impl AttachedTun {
    /// Duplicates an attached descriptor into independent async read and write halves.
    pub fn from_file(file: std::fs::File) -> Result<(TunReader, TunWriter), PacketPumpError> {
        let writer = file.try_clone()?;
        Ok((
            TunReader(File::from_std(file)),
            TunWriter(File::from_std(writer)),
        ))
    }
}

/// Read half of an attached Linux TUN descriptor.
pub struct TunReader(File);

/// Write half of an attached Linux TUN descriptor.
pub struct TunWriter(File);

/// Safe in-process Linux TUN owner. Dropping both halves closes the device descriptor.
pub struct InProcessTun;

/// Read half of an in-process Linux TUN.
#[cfg(target_os = "linux")]
pub struct InProcessTunReader(peerward_platform::LinuxTunnelReader);

/// Write half of an in-process Linux TUN.
#[cfg(target_os = "linux")]
pub struct InProcessTunWriter(peerward_platform::LinuxTunnelWriter);

impl InProcessTun {
    /// Creates and attaches a non-persistent Linux TUN using a safe maintained abstraction.
    #[cfg(target_os = "linux")]
    pub fn create(
        interface: &str,
        mtu: u16,
    ) -> Result<(InProcessTunReader, InProcessTunWriter), PacketPumpError> {
        let device = peerward_platform::LinuxTunnelDevice::create(interface, mtu)
            .map_err(io::Error::other)?;
        debug_assert_eq!(device.mtu(), mtu);
        let (reader, writer) = device.split();
        Ok((InProcessTunReader(reader), InProcessTunWriter(writer)))
    }

    /// Reports unsupported operation outside Linux.
    #[cfg(not(target_os = "linux"))]
    pub fn create(_: &str, _: u16) -> Result<(TunReader, TunWriter), PacketPumpError> {
        Err(io::Error::from(io::ErrorKind::Unsupported).into())
    }
}

/// Creates an in-process TUN by default or duplicates the explicitly inherited descriptor path.
pub fn prepare_peer_tun(linux: &crate::LinuxConfig) -> Result<PreparedTun, PacketPumpError> {
    if let Some(path) = &linux.attached_tun_file {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;
        let (reader, writer) = AttachedTun::from_file(file)?;
        return Ok((Box::new(reader), Box::new(writer)));
    }
    #[cfg(target_os = "linux")]
    {
        let (reader, writer) = InProcessTun::create(&linux.interface, linux.mtu)?;
        Ok((Box::new(reader), Box::new(writer)))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(io::Error::from(io::ErrorKind::Unsupported).into())
    }
}

#[async_trait]
impl PacketReader for TunReader {
    async fn read_packet(&mut self, buffer: &mut [u8]) -> Result<usize, PacketPumpError> {
        Ok(self.0.read(buffer).await?)
    }
}

#[async_trait]
impl PacketWriter for TunWriter {
    async fn write_packet(&mut self, packet: &[u8]) -> Result<(), PacketPumpError> {
        self.0.write_all(packet).await?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl PacketReader for InProcessTunReader {
    async fn read_packet(&mut self, buffer: &mut [u8]) -> Result<usize, PacketPumpError> {
        Ok(self.0.read(buffer).await?)
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl PacketWriter for InProcessTunWriter {
    async fn write_packet(&mut self, packet: &[u8]) -> Result<(), PacketPumpError> {
        self.0.write_all(packet).await?;
        Ok(())
    }
}

/// Immutable snapshot of packet counters; packet contents are never retained.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct PacketCounters {
    /// Packets accepted from TUN.
    pub egress_allowed: u64,
    /// Packets denied or malformed at egress.
    pub egress_denied: u64,
    /// Authenticated packets accepted into TUN.
    pub ingress_allowed: u64,
    /// Authenticated packets denied or malformed at ingress.
    pub ingress_denied: u64,
    /// Packets sent over direct UDP.
    pub direct_sent: u64,
    /// Packets sent over an encrypted relay stream.
    pub relay_sent: u64,
}

#[derive(Default)]
struct CounterSet {
    egress_allowed: AtomicU64,
    egress_denied: AtomicU64,
    ingress_allowed: AtomicU64,
    ingress_denied: AtomicU64,
    direct_sent: AtomicU64,
    relay_sent: AtomicU64,
}

impl CounterSet {
    fn snapshot(&self) -> PacketCounters {
        PacketCounters {
            egress_allowed: self.egress_allowed.load(Ordering::Relaxed),
            egress_denied: self.egress_denied.load(Ordering::Relaxed),
            ingress_allowed: self.ingress_allowed.load(Ordering::Relaxed),
            ingress_denied: self.ingress_denied.load(Ordering::Relaxed),
            direct_sent: self.direct_sent.load(Ordering::Relaxed),
            relay_sent: self.relay_sent.load(Ordering::Relaxed),
        }
    }
}

/// Runs bidirectional packet forwarding until shutdown or a permanent I/O failure.
pub async fn run_packet_pump<R, W, S, I, E, N>(
    tun_reader: R,
    tun_writer: W,
    sender: S,
    receiver: I,
    egress: Arc<E>,
    ingress: Arc<N>,
    mtu: usize,
    shutdown: watch::Receiver<bool>,
) -> Result<PacketCounters, PacketPumpError>
where
    R: PacketReader,
    W: PacketWriter,
    S: PacketSender,
    I: PacketReceiver,
    E: PacketPolicy + ?Sized,
    N: PacketPolicy + ?Sized,
{
    run_packet_pump_inner(
        tun_reader, tun_writer, sender, receiver, egress, ingress, mtu, None, None, shutdown,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_packet_pump_inner<R, W, S, I, E, N>(
    mut tun_reader: R,
    mut tun_writer: W,
    mut sender: S,
    mut receiver: I,
    egress: Arc<E>,
    ingress: Arc<N>,
    mtu: usize,
    observability: Option<peerward_service::PeerObservability>,
    audit: Option<mpsc::Sender<peerward_wire::AuditEventV1>>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<PacketCounters, PacketPumpError>
where
    R: PacketReader,
    W: PacketWriter,
    S: PacketSender,
    I: PacketReceiver,
    E: PacketPolicy + ?Sized,
    N: PacketPolicy + ?Sized,
{
    let counters = CounterSet::default();
    let mut device_buffer = vec![0_u8; mtu.max(576)];
    let mut egress_fragments = FragmentReassembler::default();
    let mut ingress_fragments = FragmentReassembler::default();
    loop {
        tokio::select! {
            read = tun_reader.read_packet(&mut device_buffer) => {
                let length = read?;
                if length == 0 {
                    return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
                }
                let now = monotonic_seconds();
                let reassembled = match egress_fragments.push(&device_buffer[..length], now) {
                    Ok(ReassemblyStatus::Pending) => continue,
                    Ok(ReassemblyStatus::Complete(packet)) => packet,
                    Err(_) => {
                        record_packet_audit(
                            audit.as_ref(),
                            peerward_wire::AuditDirectionV1::Egress,
                            peerward_wire::AuditReasonV1::MalformedPacket,
                            1,
                        );
                        counters.egress_denied.fetch_add(1, Ordering::Relaxed);
                        if let Some(observability) = &observability {
                            observability.record_egress(length, false, false);
                            observability.record_invalid_packet();
                        }
                        continue;
                    }
                };
                let parsed = parse_packet(&reassembled.packet);
                let allowed = parsed.as_ref().is_ok_and(|packet| {
                    egress.evaluate_packet(packet, monotonic_seconds()) == Action::Allow
                });
                if !allowed {
                    let denied = u64::try_from(reassembled.original_fragments.len()).unwrap_or(u64::MAX);
                    record_packet_audit(
                        audit.as_ref(),
                        peerward_wire::AuditDirectionV1::Egress,
                        if parsed.is_ok() {
                            peerward_wire::AuditReasonV1::PolicyDenied
                        } else {
                            peerward_wire::AuditReasonV1::MalformedPacket
                        },
                        denied,
                    );
                    counters.egress_denied.fetch_add(denied, Ordering::Relaxed);
                    if let Some(observability) = &observability {
                        observability.record_egress(length, false, false);
                        if parsed.is_err() {
                            observability.record_invalid_packet();
                        }
                    }
                    continue;
                }
                for bytes in reassembled.original_fragments {
                    let path = match sender.send_packet(&bytes, now).await {
                        Ok(path) => path,
                        Err(PacketPumpError::SessionPending | PacketPumpError::NoRoute) => {
                            record_packet_audit(
                                audit.as_ref(),
                                peerward_wire::AuditDirectionV1::Runtime,
                                peerward_wire::AuditReasonV1::SessionUnavailable,
                                1,
                            );
                            counters.egress_denied.fetch_add(1, Ordering::Relaxed);
                            if let Some(observability) = &observability {
                                observability.record_egress(bytes.len(), false, false);
                                observability.record_no_route();
                            }
                            break;
                        }
                        Err(PacketPumpError::QueueFull) => {
                            record_packet_audit(
                                audit.as_ref(),
                                peerward_wire::AuditDirectionV1::Runtime,
                                peerward_wire::AuditReasonV1::SessionUnavailable,
                                1,
                            );
                            counters.egress_denied.fetch_add(1, Ordering::Relaxed);
                            if let Some(observability) = &observability {
                                observability.record_egress(bytes.len(), false, false);
                                observability.record_queue_full();
                            }
                            break;
                        }
                        Err(PacketPumpError::InvalidPacket) => {
                            record_packet_audit(
                                audit.as_ref(),
                                peerward_wire::AuditDirectionV1::Egress,
                                peerward_wire::AuditReasonV1::MalformedPacket,
                                1,
                            );
                            counters.egress_denied.fetch_add(1, Ordering::Relaxed);
                            if let Some(observability) = &observability {
                                observability.record_egress(bytes.len(), false, false);
                                observability.record_invalid_packet();
                            }
                            break;
                        }
                        Err(error) => return Err(error),
                    };
                    counters.egress_allowed.fetch_add(1, Ordering::Relaxed);
                    match path {
                        DataPath::Direct => &counters.direct_sent,
                        DataPath::Relay => &counters.relay_sent,
                    }.fetch_add(1, Ordering::Relaxed);
                    if let Some(observability) = &observability {
                        observability.record_egress(bytes.len(), true, path == DataPath::Direct);
                    }
                }
            }
            incoming = receiver.receive_packet() => {
                let (_, bytes) = incoming?;
                let now = monotonic_seconds();
                let reassembled = match ingress_fragments.push(&bytes, now) {
                    Ok(ReassemblyStatus::Pending) => continue,
                    Ok(ReassemblyStatus::Complete(packet)) => packet,
                    Err(_) => {
                        record_packet_audit(
                            audit.as_ref(),
                            peerward_wire::AuditDirectionV1::Ingress,
                            peerward_wire::AuditReasonV1::MalformedPacket,
                            1,
                        );
                        counters.ingress_denied.fetch_add(1, Ordering::Relaxed);
                        if let Some(observability) = &observability {
                            observability.record_ingress(bytes.len(), false);
                            observability.record_invalid_packet();
                        }
                        continue;
                    }
                };
                let parsed = parse_packet(&reassembled.packet);
                let allowed = parsed
                    .as_ref()
                    .is_ok_and(|packet| ingress.evaluate_packet(packet, now) == Action::Allow);
                if allowed {
                    for original in &reassembled.original_fragments {
                        tun_writer.write_packet(original).await?;
                        counters.ingress_allowed.fetch_add(1, Ordering::Relaxed);
                        if let Some(observability) = &observability {
                            observability.record_ingress(original.len(), true);
                        }
                    }
                } else {
                    let denied = u64::try_from(reassembled.original_fragments.len()).unwrap_or(u64::MAX);
                    record_packet_audit(
                        audit.as_ref(),
                        peerward_wire::AuditDirectionV1::Ingress,
                        if parsed.is_ok() {
                            peerward_wire::AuditReasonV1::PolicyDenied
                        } else {
                            peerward_wire::AuditReasonV1::MalformedPacket
                        },
                        denied,
                    );
                    counters.ingress_denied.fetch_add(denied, Ordering::Relaxed);
                    if let Some(observability) = &observability {
                        observability.record_ingress(bytes.len(), false);
                        if parsed.is_err() {
                            observability.record_invalid_packet();
                        }
                    }
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(counters.snapshot());
                }
            }
        }
    }
}

fn record_packet_audit(
    audit: Option<&mpsc::Sender<peerward_wire::AuditEventV1>>,
    direction: peerward_wire::AuditDirectionV1,
    reason: peerward_wire::AuditReasonV1,
    count: u64,
) {
    let Some(audit) = audit else { return };
    let _ = audit.try_send(peerward_wire::AuditEventV1 {
        direction: direction as i32,
        reason: reason as i32,
        count: u32::try_from(count).unwrap_or(u32::MAX),
    });
}
