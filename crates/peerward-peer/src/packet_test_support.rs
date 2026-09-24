fn noise_pair() -> ([u8; 32], [u8; 32]) {
    let pair = snow::Builder::new(peerward_wire::IK_SUITE.parse().unwrap())
        .generate_keypair()
        .unwrap();
    (
        pair.private.try_into().unwrap(),
        pair.public.try_into().unwrap(),
    )
}

fn stream_transport_pair() -> (StreamTransport, StreamTransport) {
    let (initiator_private, _) = noise_pair();
    let (responder_private, responder_public) = noise_pair();
    let mut initiator = peerward_wire::ik_initiator(&initiator_private, &responder_public).unwrap();
    let mut responder = peerward_wire::ik_responder(&responder_private).unwrap();
    let mut message = vec![0_u8; 1024];
    let first = initiator.write_message(b"client", &mut message).unwrap();
    let mut plaintext = vec![0_u8; 1024];
    responder
        .read_message(&message[..first], &mut plaintext)
        .unwrap();
    let second = responder.write_message(b"server", &mut message).unwrap();
    initiator
        .read_message(&message[..second], &mut plaintext)
        .unwrap();
    (
        StreamTransport::from_handshake(initiator, 0).unwrap(),
        StreamTransport::from_handshake(responder, 0).unwrap(),
    )
}

struct ClassifyingSender {
    results: std::collections::VecDeque<Result<DataPath, PacketPumpError>>,
    delivered: mpsc::Sender<Vec<u8>>,
}

#[async_trait]
impl PacketSender for ClassifyingSender {
    async fn send_packet(&mut self, packet: &[u8], _: u64) -> Result<DataPath, PacketPumpError> {
        let result = self
            .results
            .pop_front()
            .expect("one result per test packet");
        if result.is_ok() {
            self.delivered
                .send(packet.to_vec())
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        }
        result
    }
}

#[tokio::test]
async fn packet_classification_errors_drop_only_the_current_packet() {
    let packet = udp_packet();
    let firewall = Arc::new(Firewall::new(1, Action::Allow, Vec::new(), 32, 2));
    let (tun_tx, tun_rx) = mpsc::channel(4);
    let (written_tx, _written_rx) = mpsc::channel(1);
    let (delivered_tx, mut delivered_rx) = mpsc::channel(1);
    let (_receive_tx, receive_rx) = mpsc::channel(1);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let pump = tokio::spawn(run_packet_pump(
        ChannelReader(tun_rx),
        ChannelWriter(written_tx),
        ClassifyingSender {
            results: std::collections::VecDeque::from([
                Err(PacketPumpError::InvalidPacket),
                Err(PacketPumpError::QueueFull),
                Err(PacketPumpError::NoRoute),
                Ok(DataPath::Relay),
            ]),
            delivered: delivered_tx,
        },
        ChannelReceiver(receive_rx),
        Arc::clone(&firewall),
        firewall,
        1380,
        shutdown_rx,
    ));
    for _ in 0..4 {
        tun_tx.send(packet.clone()).await.unwrap();
    }
    assert_eq!(delivered_rx.recv().await.unwrap(), packet);
    shutdown_tx.send(true).unwrap();
    let counters = pump.await.unwrap().unwrap();
    assert_eq!(counters.egress_denied, 3);
    assert_eq!(counters.egress_allowed, 1);
    assert_eq!(counters.relay_sent, 1);
}
