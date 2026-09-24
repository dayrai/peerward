use super::*;

struct RelayReadHarness {
    socket: TcpStream,
    transport: StreamTransport,
    receiver: NoiseRelayReceiver,
    controls: mpsc::Receiver<ControlEnvelope>,
}

impl RelayReadHarness {
    async fn new(capacity: usize) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (socket, _) = listener.accept().await.unwrap();
        let (client_transport, transport) = stream_transport_pair();
        let (sender, controls) = mpsc::channel(capacity);
        let (_, receiver) = split_noise_relay(client, client_transport, sender);
        Self {
            socket,
            transport,
            receiver,
            controls,
        }
    }

    fn frame(&mut self, sequence: u64) -> Vec<u8> {
        self.transport
            .encode(&Record::Control(control(sequence)))
            .unwrap()
    }

    async fn receive(&mut self) -> ControlEnvelope {
        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::select! {
                value = self.controls.recv() => value.unwrap(),
                result = self.receiver.receive_packet() => panic!("Relay read failed: {result:?}"),
            }
        })
        .await
        .expect("control delivery must complete")
    }

    async fn cancel_read(&mut self) {
        assert!(
            tokio::time::timeout(Duration::from_millis(20), self.receiver.receive_packet())
                .await
                .is_err()
        );
    }
}

fn control(sequence: u64) -> ControlEnvelope {
    ControlEnvelope {
        trace_context: None,
        message: Some(ControlMessage::Keepalive(peerward_wire::Keepalive {
            monotonic_timestamp: sequence,
        })),
    }
}

#[tokio::test]
async fn cancelled_relay_reads_preserve_partial_headers_and_bodies() {
    let mut harness = RelayReadHarness::new(4).await;
    for (sequence, split) in [(1, 2), (2, 4), (3, 9)] {
        let frame = harness.frame(sequence);
        harness.socket.write_all(&frame[..split]).await.unwrap();
        harness.cancel_read().await;
        harness.socket.write_all(&frame[split..]).await.unwrap();
        assert_eq!(harness.receive().await, control(sequence));
    }
}

#[tokio::test]
async fn cancelled_control_delivery_preserves_order_under_backpressure() {
    let mut harness = RelayReadHarness::new(1).await;
    for sequence in 1..=3 {
        let frame = harness.frame(sequence);
        harness.socket.write_all(&frame).await.unwrap();
    }
    harness.cancel_read().await;
    assert_eq!(harness.controls.recv().await.unwrap(), control(1));
    assert_eq!(harness.receive().await, control(2));
    assert_eq!(harness.receive().await, control(3));
}

#[tokio::test]
async fn cancelled_relay_decode_preserves_a_complete_frame() {
    let mut harness = RelayReadHarness::new(1).await;
    let transport = Arc::clone(&harness.receiver.transport);
    let guard = transport.lock().await;
    let frame = harness.frame(1);
    harness.socket.write_all(&frame).await.unwrap();
    harness.cancel_read().await;
    drop(guard);
    assert_eq!(harness.receive().await, control(1));
    let frame = harness.frame(2);
    harness.socket.write_all(&frame).await.unwrap();
    assert_eq!(harness.receive().await, control(2));
}
