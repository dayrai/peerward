async fn read_local(socket: &mut BoxStream, codec: &mut crate::RecordTransport) -> ControlEnvelope {
    let length = socket.read_u32().await.unwrap() as usize;
    let mut frame = u32::try_from(length).unwrap().to_be_bytes().to_vec();
    frame.resize(length + 4, 0);
    socket.read_exact(&mut frame[4..]).await.unwrap();
    let Record::Control(control) = codec.decode(&frame).unwrap() else {
        panic!("control expected");
    };
    control
}

#[tokio::test]
async fn production_bridge_preserves_control_on_close_and_uses_real_datagrams() {
    let route = preface();
    let (mut left, mut right, _listener) = pending_pair(route).await;
    let (a, b) = authenticate(&mut left, &mut right, route).await;
    let (process, mesh) = budgets();
    let (application, remote) = tokio::join!(
        activate(left.into_stream(), a.into(), Some(route), 100),
        right.admit(b, route, process, mesh, 100)
    );
    let (mut socket, mut codec) = application.unwrap();
    let mut remote = remote.unwrap();
    let message = envelope(route, vec![], 9000);
    let control = ControlEnvelope {
        trace_context: None,
        message: Some(ControlMessage::Opaque(message.clone())),
    };
    socket
        .write_all(&codec.encode(&Record::Control(control)).unwrap())
        .await
        .unwrap();
    socket.flush().await.unwrap();
    assert!(matches!(receive(&mut remote).await, Received::Opaque(value) if value == message));
    assert!(remote.stats().received_fragments > 1);
    assert_eq!(
        remote.received_control(),
        0,
        "WireGuard never enters the reliable stream"
    );

    socket
        .write_all(&codec.encode(&Record::Control(keepalive(9))).unwrap())
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(20), socket.flush())
            .await
            .is_err(),
        "flush must wait for the remote receipt"
    );
    assert!(
        matches!(receive(&mut remote).await, Received::Control(value) if value == keepalive(9))
    );
    tokio::time::timeout(Duration::from_secs(1), socket.flush())
        .await
        .unwrap()
        .unwrap();

    remote.send_control(keepalive(10)).await.unwrap();
    // Receipt proves the full frame reached the runtime's bounded pipe. A
    // subsequent network close cannot discard it, even before the app reads.
    assert!(matches!(
        remote.receive().await.unwrap(),
        Received::Acknowledged(1)
    ));
    remote.close();
    assert_eq!(read_local(&mut socket, &mut codec).await, keepalive(10));
}

#[tokio::test]
async fn backbone_datagrams_keep_source_generation_and_topology_fences() {
    let route = RelayPreface {
        source: Some(RelayId::new()),
        ..preface()
    };
    let (mut left, mut right, _listener) = pair(route).await;
    let message = envelope(route, PeerId::new().as_bytes().to_vec(), 9000);
    let payload = datagram_bytes(message.clone());
    let mut body = vec![3, 1];
    body.extend_from_slice(route.source.unwrap().as_bytes());
    body.extend_from_slice(route.target.as_bytes());
    body.extend_from_slice(&123_u64.to_be_bytes());
    body.extend_from_slice(&[4, 1]);
    body.extend_from_slice(route.source.unwrap().as_bytes());
    body.extend_from_slice(&(44_u32 + u32::try_from(payload.len()).unwrap()).to_be_bytes());
    body.extend_from_slice(&message.source_peer);
    body.extend_from_slice(&message.destination_peer);
    body.extend_from_slice(&456_u64.to_be_bytes());
    body.extend_from_slice(&(u32::try_from(payload.len()).unwrap()).to_be_bytes());
    body.extend_from_slice(&payload);
    let control = ControlEnvelope {
        trace_context: None,
        message: Some(ControlMessage::Forwarded(peerward_wire::ForwardedPacket {
            mesh_id: route.mesh_id.as_bytes().to_vec(),
            body: body.clone(),
        })),
    };
    assert!(left.send_control(control.clone()).await.is_err());
    assert!(left.send_datagram_control(&control).unwrap());
    assert!(matches!(receive(&mut right).await, Received::Datagram(value) if value == control));
    body[64] ^= 1; // Replace the source while leaving the inner envelope intact.
    let forged = ControlEnvelope {
        trace_context: None,
        message: Some(ControlMessage::Forwarded(peerward_wire::ForwardedPacket {
            mesh_id: route.mesh_id.as_bytes().to_vec(),
            body,
        })),
    };
    assert!(left.send_datagram_control(&forged).is_err());
    let (mut peer, _, _listener) = pair(RelayPreface {
        source: None,
        ..route
    })
    .await;
    assert!(peer.send_datagram_control(&control).is_err());
}

#[test]
fn local_codec_never_accepts_a_network_noise_frame() {
    let (mut left, mut right) = noise_states(preface());
    let mut frame = [0; 1024];
    let mut plain = [0; 1024];
    let n = left.write_message(b"", &mut frame).unwrap();
    right.read_message(&frame[..n], &mut plain).unwrap();
    let n = right.write_message(b"", &mut frame).unwrap();
    left.read_message(&frame[..n], &mut plain).unwrap();
    let mut noise = StreamTransport::from_handshake(left, 100).unwrap();
    let mut remote = StreamTransport::from_handshake(right, 100).unwrap();
    let record = Record::Control(keepalive(1));
    let mut local = crate::RecordTransport::local(100);
    assert!(local.decode(&noise.encode(&record).unwrap()).is_err());
    assert!(remote.decode(&local.encode(&record).unwrap()).is_err());
}

#[tokio::test]
async fn active_bridge_requires_application_pongs_and_fails_within_three_seconds() {
    let route = preface();
    let (left, mut right, _listener) = pair(route).await;
    let mut socket = crate::quic_bridge::bridge(left);
    let mut codec = crate::RecordTransport::local(100);
    let packet = ControlEnvelope {
        trace_context: None,
        message: Some(ControlMessage::Opaque(envelope(route, vec![], 1280))),
    };
    socket
        .write_all(&codec.encode(&Record::Control(packet)).unwrap())
        .await
        .unwrap();
    socket.flush().await.unwrap();
    assert!(matches!(receive(&mut right).await, Received::Opaque(_)));
    // Quinn remains alive and acknowledges UDP packets, but the remote runtime
    // stops responding. Transport ACKs alone cannot keep this path healthy.
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), socket.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn datagram_backpressure_does_not_starve_authenticated_heartbeats() {
    let route = preface();
    let (left, mut right, _listener) = pair(route).await;
    let mut socket = crate::quic_bridge::bridge(left);
    let mut codec = crate::RecordTransport::local(100);
    let frame = envelope(route, PeerId::new().as_bytes().to_vec(), 9000);
    let until = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut flood = tokio::time::interval(Duration::from_millis(20));
    let mut pings = 0;
    // Do not read the application pipe: its 64 KiB capacity must fill. The
    // reliable health stream must still be read while DATAGRAMs are throttled.
    while tokio::time::Instant::now() < until {
        tokio::select! {
            _ = flood.tick() => { let _ = right.send_opaque(&frame).unwrap(); }
            record = right.receive() => match record.unwrap() {
                Received::Ping(sequence) => { right.heartbeat(sequence, true).await.unwrap(); pings += 1; },
                _ => panic!("unexpected health record"),
            },
        }
    }
    assert!(right.stats().sent_frames > 20);
    assert!(pings >= 3);
    let message = envelope(route, vec![], 1280);
    let control = ControlEnvelope {
        trace_context: None,
        message: Some(ControlMessage::Opaque(message.clone())),
    };
    socket
        .write_all(&codec.encode(&Record::Control(control)).unwrap())
        .await
        .unwrap();
    socket.flush().await.unwrap();
    assert!(matches!(receive(&mut right).await, Received::Opaque(value) if value == message));
}

#[tokio::test]
async fn full_datagram_queue_drains_and_accepts_new_frames_after_a_burst() {
    let route = preface();
    let (mut left, mut right, _listener) = pair(route).await;
    let frame = envelope(route, vec![], 1280);
    let mut accepted = 0;
    // No await: saturate the real Quinn queue before its driver can drain it.
    // Fragment payload bytes alone do not include Quinn's per-datagram memory.
    for _ in 0..4096 {
        if !left.send_opaque(&frame).unwrap() {
            break;
        }
        accepted += 1;
    }
    assert!(accepted > 1);
    assert!(
        accepted < 4096,
        "bounded queue admitted all {accepted} frames without yielding"
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        while left.owner.connection.datagram_send_buffer_space() < QUEUE_BYTES / 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("DATAGRAM byte accounting stayed full after the driver drained it");

    let mut marker = envelope(route, vec![], 1280);
    marker.opaque.fill(9);
    assert!(left.send_opaque(&marker).unwrap());
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if matches!(right.receive().await.unwrap(), Received::Opaque(value) if value == marker)
            {
                break;
            }
        }
    })
    .await
    .expect("fresh complete frame was not delivered after queue pressure");
}
