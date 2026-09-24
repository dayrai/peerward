/// Relay writer for authenticated control records carrying opaque `WireGuard` datagrams.
#[derive(Clone)]
pub struct NoiseRelaySender {
    writer: Arc<Mutex<WriteHalf<BoxStream>>>,
    transport: Arc<Mutex<StreamTransport>>,
}

/// Relay reader that authenticates Noise records and separates control messages.
pub struct NoiseRelayReceiver {
    reader: ReadHalf<BoxStream>,
    transport: Arc<Mutex<StreamTransport>>,
    controls: mpsc::Sender<ControlEnvelope>,
    // These survive cancellation of receive_packet by the Relay worker's select!.
    frame: Vec<u8>,
    frame_read: usize,
    pending_control: Option<ControlEnvelope>,
}

type RelayConnection = (BoxStream, StreamTransport, HandshakePayload);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkEpochAction {
    Continue,
    Replace,
    FailClosed,
}

fn link_epoch_action(transport: &StreamTransport, now: u64) -> LinkEpochAction {
    if transport.hard_expired(now) {
        LinkEpochAction::FailClosed
    } else if transport.rekey_due(now) {
        LinkEpochAction::Replace
    } else {
        LinkEpochAction::Continue
    }
}

/// Splits an established authenticated relay connection into concurrent packet halves.
pub fn split_noise_relay(
    socket: impl peerward_carrier::RelayIo + 'static,
    transport: StreamTransport,
    controls: mpsc::Sender<ControlEnvelope>,
) -> (NoiseRelaySender, NoiseRelayReceiver) {
    let socket: BoxStream = Box::new(socket);
    let (reader, writer) = tokio::io::split(socket);
    let transport = Arc::new(Mutex::new(transport));
    (
        NoiseRelaySender {
            writer: Arc::new(Mutex::new(writer)),
            transport: Arc::clone(&transport),
        },
        NoiseRelayReceiver {
            reader,
            transport,
            controls,
            frame: vec![0; 4],
            frame_read: 0,
            pending_control: None,
        },
    )
}

enum RelaySlotCommand {
    Control(ControlEnvelope, oneshot::Sender<bool>),
    Wireguard(ControlEnvelope, WireguardSendGuard),
}

#[derive(Clone)]
struct WireguardSendGuard {
    core: std::sync::Weak<Mutex<peerward_peer_core::WireguardRuntime>>,
    authorization: u64,
    expires: Instant,
}

impl WireguardSendGuard {
    async fn current(&self) -> bool {
        if Instant::now() >= self.expires { return false; }
        let Some(core) = self.core.upgrade() else { return false; };
        core.lock().await.delivery_current(self.authorization, UnixTime(wall_clock_seconds()))
    }
}

struct RelayPoolState {
    primary: usize,
    primary_since: u64,
    better_streak: Vec<u8>,
    slots: Vec<mpsc::Sender<RelaySlotCommand>>,
    /// Bounded flow-to-Relay assignments prevent per-packet path changes and reordering.
    flow_assignments: BTreeMap<u64, (usize, u64)>,
}

const MAX_FLOW_ASSIGNMENTS: usize = 4_096;

#[derive(Debug, Default)]
struct RelaySlotHealth {
    connected: bool,
    rtt_ewma_millis: Option<u64>,
    outcomes: VecDeque<bool>,
    reconnects: u16,
    queue_pressure_permyriad: u16,
}

impl RelaySlotHealth {
    fn record_probe(&mut self, success: bool, rtt_millis: Option<u64>) {
        if self.outcomes.len() == 32 {
            self.outcomes.pop_front();
        }
        self.outcomes.push_back(success);
        if let Some(sample) = rtt_millis {
            self.rtt_ewma_millis = Some(self.rtt_ewma_millis.map_or(sample, |current| {
                current.saturating_mul(4).saturating_add(sample) / 5
            }));
        }
    }

    fn score(&self) -> u64 {
        if !self.connected {
            return u64::MAX;
        }
        let misses = self.outcomes.iter().filter(|success| !**success).count();
        let loss_bps = if self.outcomes.is_empty() {
            0
        } else {
            u64::try_from(misses).unwrap_or(u64::MAX).saturating_mul(10_000)
                / u64::try_from(self.outcomes.len()).unwrap_or(1)
        };
        self.rtt_ewma_millis
            .unwrap_or(500)
            .saturating_add(loss_bps.saturating_mul(10))
            .saturating_add(u64::from(self.queue_pressure_permyriad).saturating_mul(5))
            .saturating_add(u64::from(self.reconnects).saturating_mul(250))
    }
}

/// Cloneable packet/control sender backed by a primary and warm-standby relay slot.
#[derive(Clone)]
pub struct RelayPoolSender {
    state: Arc<Mutex<RelayPoolState>>,
    health: Arc<Mutex<Vec<RelaySlotHealth>>>,
    observability: Option<peerward_service::PeerObservability>,
}

/// Packet receiver shared by both live relay slots.
pub struct RelayPoolReceiver(mpsc::Receiver<(DataPath, Vec<u8>)>);

impl RelayPoolSender {
    /// Bounded datagram enqueue. An offline Relay must never stall WG timers or direct traffic.
    async fn try_wireguard(&self, mesh: MeshId, peer: PeerId, ciphertext: &[u8], guard: WireguardSendGuard) -> Result<(), PacketPumpError> {
        let slots = self.order().await;
        let health = self.health.lock().await;
        for (index, sender) in slots {
            if !health.get(index).is_some_and(|slot| slot.connected) { continue; }
            let message = ControlEnvelope { trace_context: None, message: Some(ControlMessage::Opaque(RelayEnvelopeV2 {
                major: PROTOCOL_MAJOR, mesh_id: mesh.as_bytes().to_vec(), source_peer: Vec::new(),
                destination_peer: peer.as_bytes().to_vec(), kind: OpaqueFrameKind::Session as i32, opaque: ciphertext.to_vec(),
            })) };
            if sender.try_send(RelaySlotCommand::Wireguard(message, guard.clone())).is_ok() { return Ok(()); }
        }
        Err(PacketPumpError::QueueFull)
    }

    async fn health_scores(&self) -> Vec<u64> {
        let slots = self.state.lock().await.slots.clone();
        let mut health = self.health.lock().await;
        let mut maximum_pressure = 0_u16;
        for (slot, sender) in health.iter_mut().zip(&slots) {
            slot.queue_pressure_permyriad = relay_queue_pressure(sender);
            maximum_pressure = maximum_pressure.max(slot.queue_pressure_permyriad);
        }
        if let Some(observability) = &self.observability {
            observability.record_relay_queue_pressure(maximum_pressure);
        }
        health.iter().map(RelaySlotHealth::score).collect()
    }

    async fn order(&self) -> Vec<(usize, mpsc::Sender<RelaySlotCommand>)> {
        self.consider_health_promotion().await;
        let scores = self.health_scores().await;
        let (primary, slots) = {
            let state = self.state.lock().await;
            (state.primary, state.slots.clone())
        };
        let mut order = Vec::with_capacity(slots.len());
        order.push(primary);
        let mut alternates = (0..slots.len())
            .filter(|index| *index != primary)
            .collect::<Vec<_>>();
        alternates.sort_by_key(|index| scores.get(*index).copied().unwrap_or(u64::MAX));
        order.extend(alternates);
        order
            .into_iter()
            .map(|index| (index, slots[index].clone()))
            .collect()
    }

    async fn promote(&self, slot: usize) {
        let mut state = self.state.lock().await;
        if slot < state.slots.len() && slot != state.primary {
            state.primary = slot;
            state.primary_since = monotonic_seconds();
            state.better_streak.fill(0);
            if let Some(observability) = &self.observability {
                observability.promote_relay(slot);
                observability.record_relay_switch();
            }
        }
    }

    async fn consider_health_promotion(&self) {
        let scores = self.health_scores().await;
        let mut state = self.state.lock().await;
        if state.slots.is_empty() || monotonic_seconds().saturating_sub(state.primary_since) < 30 {
            return;
        }
        let primary_score = scores.get(state.primary).copied().unwrap_or(u64::MAX);
        let best = (0..state.slots.len())
            .min_by_key(|index| scores.get(*index).copied().unwrap_or(u64::MAX));
        let Some(best) = best.filter(|best| *best != state.primary) else {
            state.better_streak.fill(0);
            return;
        };
        let best_score = scores.get(best).copied().unwrap_or(u64::MAX);
        if best_score.saturating_mul(100) <= primary_score.saturating_mul(80) {
            state.better_streak[best] = state.better_streak[best].saturating_add(1);
            if state.better_streak[best] >= 3 {
                state.primary = best;
                state.primary_since = monotonic_seconds();
                state.better_streak.fill(0);
                if let Some(observability) = &self.observability {
                    observability.promote_relay(best);
                    observability.record_relay_switch();
                }
            }
        } else {
            state.better_streak[best] = 0;
        }
    }

    async fn dispatch_control(&self, envelope: ControlEnvelope) -> Result<(), PacketPumpError> {
        self.dispatch(envelope, None).await
    }

    async fn flow_order(&self, flow_key: u64) -> Vec<(usize, mpsc::Sender<RelaySlotCommand>)> {
        let health = self.health_scores().await;
        let mut state = self.state.lock().await;
        let slots = state.slots.clone();
        if let Some((slot, touched_at)) = state.flow_assignments.get_mut(&flow_key)
            && health.get(*slot).is_some_and(|score| *score != u64::MAX)
        {
            *touched_at = monotonic_seconds();
            let selected = *slot;
            let mut order = vec![selected];
            order.extend((0..slots.len()).filter(|index| *index != selected));
            return order
                .into_iter()
                .map(|index| (index, slots[index].clone()))
                .collect();
        }
        let mut order = (0..slots.len()).collect::<Vec<_>>();
        order.sort_by_key(|index| {
            let cost = health.get(*index).copied().unwrap_or(u64::MAX);
            if cost == u64::MAX {
                return std::cmp::Reverse(0_u128);
            }
            let mut hash = flow_key
                ^ u64::try_from(*index)
                    .unwrap_or(u64::MAX)
                    .wrapping_mul(0x9e37_79b9_7f4a_7c15);
            hash ^= hash >> 30;
            hash = hash.wrapping_mul(0xbf58_476d_1ce4_e5b9);
            hash ^= hash >> 27;
            hash = hash.wrapping_mul(0x94d0_49bb_1331_11eb);
            hash ^= hash >> 31;
            std::cmp::Reverse(u128::from(hash) / u128::from(cost.max(1)))
        });
        if let Some(selected) = order.first().copied()
            && health.get(selected).is_some_and(|score| *score != u64::MAX)
        {
            if state.flow_assignments.len() >= MAX_FLOW_ASSIGNMENTS
                && let Some(oldest) = state
                    .flow_assignments
                    .iter()
                    .min_by_key(|(_, (_, touched_at))| *touched_at)
                    .map(|(key, _)| *key)
            {
                state.flow_assignments.remove(&oldest);
            }
            state
                .flow_assignments
                .insert(flow_key, (selected, monotonic_seconds()));
        }
        order
            .into_iter()
            .map(|index| (index, slots[index].clone()))
            .collect()
    }

    async fn dispatch(
        &self,
        envelope: ControlEnvelope,
        flow_key: Option<u64>,
    ) -> Result<(), PacketPumpError> {
        loop {
            let slots = match flow_key {
                Some(key) => self.flow_order(key).await,
                None => self.order().await,
            };
            let mut has_live_worker = false;
            for (slot_index, slot) in slots {
                if slot.is_closed() {
                    continue;
                }
                has_live_worker = true;
                let (reply_tx, reply_rx) = oneshot::channel();
                if slot
                    .send(RelaySlotCommand::Control(envelope.clone(), reply_tx))
                    .await
                    .is_ok()
                    && tokio::time::timeout(std::time::Duration::from_secs(2), reply_rx)
                        .await
                        .is_ok_and(|reply| reply == Ok(true))
                {
                    if let Some(flow_key) = flow_key {
                        self.state.lock().await.flow_assignments.insert(
                            flow_key,
                            (slot_index, monotonic_seconds()),
                        );
                    } else {
                        self.promote(slot_index).await;
                    }
                    return Ok(());
                }
            }
            if !has_live_worker {
                return Err(io::Error::from(io::ErrorKind::NotConnected).into());
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
}

fn relay_queue_pressure(sender: &mpsc::Sender<RelaySlotCommand>) -> u16 {
    let maximum = sender.max_capacity();
    if maximum == 0 {
        return 10_000;
    }
    let occupied = maximum.saturating_sub(sender.capacity());
    u16::try_from(occupied.saturating_mul(10_000) / maximum).unwrap_or(10_000)
}

#[async_trait]
impl PacketSender for RelayPoolSender {
    async fn send_packet(&mut self, _: &[u8], _: u64) -> Result<DataPath, PacketPumpError> {
        Err(PacketPumpError::InvalidControl)
    }
}

#[async_trait]
impl OpaqueRelaySender for RelayPoolSender {
    async fn send_opaque(
        &mut self,
        mesh_id: MeshId,
        destination: PeerId,
        ciphertext: &[u8],
    ) -> Result<DataPath, PacketPumpError> {
        self.dispatch_control(ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::Opaque(RelayEnvelopeV2 {
                major: PROTOCOL_MAJOR,
                mesh_id: mesh_id.as_bytes().to_vec(),
                destination_peer: destination.as_bytes().to_vec(),
                source_peer: Vec::new(),
                kind: OpaqueFrameKind::Session as i32,
                opaque: ciphertext.to_vec(),
            })),
        })
        .await?;
        Ok(DataPath::Relay)
    }

    async fn send_opaque_on_flow(
        &mut self,
        mesh_id: MeshId,
        destination: PeerId,
        ciphertext: &[u8],
        flow_key: u64,
    ) -> Result<DataPath, PacketPumpError> {
        self.dispatch(
            ControlEnvelope {
                trace_context: None,
                message: Some(ControlMessage::Opaque(RelayEnvelopeV2 {
                    major: PROTOCOL_MAJOR,
                    mesh_id: mesh_id.as_bytes().to_vec(),
                    destination_peer: destination.as_bytes().to_vec(),
                    source_peer: Vec::new(),
                    kind: OpaqueFrameKind::Session as i32,
                    opaque: ciphertext.to_vec(),
                })),
            },
            Some(flow_key),
        )
        .await?;
        Ok(DataPath::Relay)
    }
}

#[async_trait]
impl ControlSender for RelayPoolSender {
    async fn send_control(&self, control: ControlEnvelope) -> Result<(), PacketPumpError> {
        self.dispatch_control(control).await
    }
}

#[async_trait]
impl PacketReceiver for RelayPoolReceiver {
    async fn receive_packet(&mut self) -> Result<(DataPath, Vec<u8>), PacketPumpError> {
        self.0
            .recv()
            .await
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected).into())
    }
}

include!("relay_pool_worker.rs");
