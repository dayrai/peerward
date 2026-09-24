use super::*;
fn query(name: &str, kind: u16) -> Vec<u8> {
    let mut bytes = vec![0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    bytes.extend(encode_name(name));
    bytes.extend(kind.to_be_bytes());
    bytes.extend([0, 1]);
    bytes
}
fn answer(query: &[u8], records: &[(&str, u16, Vec<u8>)]) -> Vec<u8> {
    let mut reply = query.to_vec();
    reply[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    reply[6..8].copy_from_slice(&u16::try_from(records.len()).unwrap().to_be_bytes());
    for (owner, kind, data) in records {
        reply.extend(encode_name(owner));
        reply.extend(kind.to_be_bytes());
        reply.extend([0, 1, 0, 0, 0, 1]);
        reply.extend(u16::try_from(data.len()).unwrap().to_be_bytes());
        reply.extend(data);
    }
    reply
}
#[test]
fn bootstrap_only_accepts_addresses_owned_by_the_requested_cname_chain() {
    let query = query("relay.example", 1);
    let question = parse_question(&query).unwrap();
    let reply = answer(
        &query,
        &[
            ("relay.example", 5, encode_name("actual.example")),
            ("actual.example", 1, vec![192, 0, 2, 1]),
            ("unrelated.example", 1, vec![192, 0, 2, 99]),
        ],
    );
    assert_eq!(
        bootstrap_answers(&reply, &question).unwrap(),
        vec!["192.0.2.1".parse::<IpAddr>().unwrap()]
    );
    let mut wrong = reply.clone();
    wrong[0] = 1;
    assert!(bootstrap_answers(&wrong, &question).is_err());
    let cycle = answer(
        &query,
        &[
            ("relay.example", 5, encode_name("actual.example")),
            ("actual.example", 5, encode_name("relay.example")),
        ],
    );
    assert!(bootstrap_answers(&cycle, &question).is_err());
    for length in 0..reply.len() {
        assert!(bootstrap_answers(&reply[..length], &question).is_err());
    }
    let unrelated = answer(&query, &[("unrelated.example", 1, vec![192, 0, 2, 99])]);
    assert!(bootstrap_answers(&unrelated, &question).unwrap().is_empty());
}
#[tokio::test]
async fn bootstrap_queries_use_explicit_upstreams_with_tcp_truncation_and_dual_stack() {
    // TCP and UDP have independent ephemeral-port allocators. Reserve both
    // sockets together; a UDP allocation can already be in use by TCP.
    let mut pair = None;
    for _ in 0..100 {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        match UdpSocket::bind(tcp.local_addr().unwrap()).await {
            Ok(udp) => {
                pair = Some((tcp, udp));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {}
            Err(error) => panic!("cannot reserve DNS test socket: {error}"),
        }
    }
    let (tcp, udp) = pair.expect("could not reserve a loopback TCP/UDP pair");
    let address = udp.local_addr().unwrap();
    let datagrams = tokio::spawn(async move {
        for _ in 0..2 {
            let mut bytes = vec![0; 4096];
            let (length, remote) = udp.recv_from(&mut bytes).await.unwrap();
            bytes.truncate(length);
            let question = parse_question(&bytes).unwrap();
            let response = if question.qtype == 1 {
                let mut reply = bytes.clone();
                reply[2..4].copy_from_slice(&0x8380u16.to_be_bytes());
                reply
            } else {
                answer(
                    &bytes,
                    &[(
                        "relay.example",
                        28,
                        "2001:db8::1"
                            .parse::<std::net::Ipv6Addr>()
                            .unwrap()
                            .octets()
                            .to_vec(),
                    )],
                )
            };
            udp.send_to(&response, remote).await.unwrap();
        }
    });
    let stream = tokio::spawn(async move {
        let (mut stream, _) = tcp.accept().await.unwrap();
        let length = stream.read_u16().await.unwrap();
        let mut query = vec![0; usize::from(length)];
        stream.read_exact(&mut query).await.unwrap();
        let response = answer(&query, &[("relay.example", 1, vec![192, 0, 2, 1])]);
        stream
            .write_u16(u16::try_from(response.len()).unwrap())
            .await
            .unwrap();
        stream.write_all(&response).await.unwrap();
    });
    let result = resolve_bootstrap(
        &peerward_platform::LinuxUnderlayNetwork::default(),
        &[address],
        "relay.example",
        7777,
    )
    .await
    .unwrap();
    assert_eq!(
        result,
        vec![
            "[2001:db8::1]:7777".parse().unwrap(),
            "192.0.2.1:7777".parse().unwrap()
        ]
    );
    datagrams.await.unwrap();
    stream.await.unwrap();
}
