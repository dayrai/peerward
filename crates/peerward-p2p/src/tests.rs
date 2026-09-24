use super::*;
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::net::UdpSocket;

#[test]
fn stun_ipv4_xor_mapping_is_a_golden_vector() {
    let request = StunRequest::from_transaction([0x11; 12]);
    assert_eq!(
        hex::encode(request.bytes),
        "000100002112a442111111111111111111111111"
    );
    let mapped: SocketAddr = "203.0.113.9:54321".parse().unwrap();
    let mut response = vec![0_u8; 32];
    response[..2].copy_from_slice(&STUN_BINDING_SUCCESS.to_be_bytes());
    response[2..4].copy_from_slice(&12_u16.to_be_bytes());
    response[4..8].copy_from_slice(&STUN_MAGIC.to_be_bytes());
    response[8..20].copy_from_slice(&request.transaction);
    response[20..22].copy_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes());
    response[22..24].copy_from_slice(&8_u16.to_be_bytes());
    response[25] = 1;
    response[26..28].copy_from_slice(&(0xd431_u16 ^ (STUN_MAGIC >> 16) as u16).to_be_bytes());
    let mask = STUN_MAGIC.to_be_bytes();
    let octets = match mapped.ip() {
        IpAddr::V4(value) => value.octets(),
        IpAddr::V6(_) => unreachable!(),
    };
    for index in 0..4 {
        response[28 + index] = octets[index] ^ mask[index];
    }
    assert_eq!(request.parse_response(&response).unwrap(), mapped);
}

#[tokio::test]
async fn localhost_stun_discovery_requires_matching_server_and_transaction() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_address = server.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut request = [0_u8; 64];
        let (length, client) = server.recv_from(&mut request).await.unwrap();
        assert_eq!(length, 20);
        let mapped = client;
        let mut response = vec![0_u8; 32];
        response[..2].copy_from_slice(&STUN_BINDING_SUCCESS.to_be_bytes());
        response[2..4].copy_from_slice(&12_u16.to_be_bytes());
        response[4..8].copy_from_slice(&STUN_MAGIC.to_be_bytes());
        response[8..20].copy_from_slice(&request[8..20]);
        response[20..22].copy_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes());
        response[22..24].copy_from_slice(&8_u16.to_be_bytes());
        response[25] = 1;
        response[26..28]
            .copy_from_slice(&(mapped.port() ^ (STUN_MAGIC >> 16) as u16).to_be_bytes());
        let octets = match mapped.ip() {
            IpAddr::V4(value) => value.octets(),
            IpAddr::V6(_) => unreachable!(),
        };
        for index in 0..4 {
            response[28 + index] = octets[index] ^ STUN_MAGIC.to_be_bytes()[index];
        }
        server.send_to(&response, client).await.unwrap();
        mapped
    });
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let discovered = discover_mapping(&client, server_address, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(discovered, task.await.unwrap());
}

#[test]
fn nat_classification_and_immediate_relay_fallback_are_deterministic() {
    let first: SocketAddr = "198.51.100.1:5000".parse().unwrap();
    let second: SocketAddr = "198.51.100.1:5001".parse().unwrap();
    assert_eq!(
        classify_nat(&[first, first]),
        NatBehavior::EndpointIndependent
    );
    assert_eq!(
        classify_nat(&[first, second]),
        NatBehavior::EndpointDependent
    );
}
