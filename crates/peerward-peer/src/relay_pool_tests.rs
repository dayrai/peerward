use super::*;

#[tokio::test]
async fn wireguard_enqueue_never_waits_for_an_offline_or_saturated_relay() {
    let (sender, mut receiver) = mpsc::channel(1);
    let pool = RelayPoolSender {
        state: Arc::new(Mutex::new(RelayPoolState { primary: 0, primary_since: monotonic_seconds(), better_streak: vec![0], slots: vec![sender], flow_assignments: BTreeMap::new() })),
        health: Arc::new(Mutex::new(vec![RelaySlotHealth::default()])), observability: None,
    };
    let guard = WireguardSendGuard { core: std::sync::Weak::new(), authorization: 0, expires: Instant::now() + Duration::from_secs(3) };
    let mesh = MeshId::new(); let peer = PeerId::new();
    assert!(tokio::time::timeout(Duration::from_millis(100), pool.try_wireguard(mesh, peer, &[1; 148], guard.clone())).await.unwrap().is_err());
    pool.health.lock().await[0].connected = true;
    pool.try_wireguard(mesh, peer, &[1; 148], guard.clone()).await.unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(100), pool.try_wireguard(mesh, peer, &[1; 148], guard.clone())).await.unwrap().is_err());
    assert!(receiver.try_recv().is_ok());
}

#[tokio::test]
async fn offline_dispatch_retries_preserve_inflight_handshake_and_backoff() {
    let (commands, mut receiver) = mpsc::channel(1);
    let (finish, finished) = oneshot::channel();
    let waiting =
        tokio::spawn(async move { wait_with_rejected_commands(finished, &mut receiver).await });
    for _ in 0..5 {
        let (reply, rejected) = oneshot::channel();
        commands
            .send(RelaySlotCommand::Control(
                ControlEnvelope {
                    trace_context: None,
                    message: Some(ControlMessage::Keepalive(peerward_wire::Keepalive {
                        monotonic_timestamp: 1,
                    })),
                },
                reply,
            ))
            .await
            .unwrap();
        assert!(!rejected.await.unwrap());
        assert!(!waiting.is_finished());
    }
    finish
        .send(42)
        .expect("dispatch must not cancel the in-flight operation");
    assert_eq!(waiting.await.unwrap(), Some(Ok(42)));
}

#[tokio::test]
async fn closing_dispatch_stops_an_offline_worker() {
    let (commands, mut receiver) = mpsc::channel(1);
    drop(commands);
    assert_eq!(
        wait_with_rejected_commands(std::future::pending::<()>(), &mut receiver).await,
        None
    );
}

fn transport_at(epoch: u64) -> StreamTransport {
    let initiator_key = snow::Builder::new(peerward_wire::IK_SUITE.parse().unwrap())
        .generate_keypair()
        .unwrap();
    let responder_key = snow::Builder::new(peerward_wire::IK_SUITE.parse().unwrap())
        .generate_keypair()
        .unwrap();
    let initiator_private: [u8; 32] = initiator_key.private.try_into().unwrap();
    let responder_private: [u8; 32] = responder_key.private.try_into().unwrap();
    let responder_public: [u8; 32] = responder_key.public.try_into().unwrap();
    let mut initiator = peerward_wire::ik_initiator(&initiator_private, &responder_public).unwrap();
    let mut responder = peerward_wire::ik_responder(&responder_private).unwrap();
    let mut message = vec![0_u8; 128];
    let count = initiator.write_message(b"client", &mut message).unwrap();
    let mut plaintext = vec![0_u8; 128];
    responder
        .read_message(&message[..count], &mut plaintext)
        .unwrap();
    let count = responder.write_message(b"server", &mut message).unwrap();
    initiator
        .read_message(&message[..count], &mut plaintext)
        .unwrap();
    StreamTransport::from_handshake(initiator, epoch).unwrap()
}

#[test]
fn relay_link_replacement_obeys_exact_soft_and_hard_time_boundaries() {
    let transport = transport_at(100);
    assert_eq!(
        link_epoch_action(&transport, 2_799),
        LinkEpochAction::Continue
    );
    assert_eq!(
        link_epoch_action(&transport, 2_800),
        LinkEpochAction::Replace
    );
    assert_eq!(
        link_epoch_action(&transport, 3_699),
        LinkEpochAction::Replace
    );
    assert_eq!(
        link_epoch_action(&transport, 3_700),
        LinkEpochAction::FailClosed
    );
}

#[test]
fn relay_queue_pressure_is_bounded_and_capacity_relative() {
    let (sender, mut receiver) = mpsc::channel(4);
    assert_eq!(relay_queue_pressure(&sender), 0);
    let (reply, _) = oneshot::channel();
    sender
        .try_send(RelaySlotCommand::Control(
            ControlEnvelope {
                trace_context: None,
                message: Some(ControlMessage::Keepalive(peerward_wire::Keepalive {
                    monotonic_timestamp: 1,
                })),
            },
            reply,
        ))
        .unwrap();
    assert_eq!(relay_queue_pressure(&sender), 2_500);
    assert!(receiver.try_recv().is_ok());
    assert_eq!(relay_queue_pressure(&sender), 0);
}
