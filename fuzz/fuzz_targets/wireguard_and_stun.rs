#![no_main]

use libfuzzer_sys::fuzz_target;
use peerward_p2p::{StunRequest, StunRuntime, stun_binding_response};
use peerward_wireguard::{Engine, Event, Ingress, Limits};
use x25519_dalek::StaticSecret;

fuzz_target!(|bytes: &[u8]| {
    let source = "127.0.0.1:51820".parse().unwrap();
    let request = StunRequest::from_transaction([7; 12]);
    let _ = request.parse_response(bytes);
    let _ = stun_binding_response(bytes, source);
    let mut stun = StunRuntime::new(vec![source]).unwrap();
    let probe = stun.poll(0).probes.remove(0);
    let mut response = stun_binding_response(&probe.request, source).unwrap();
    mutate(&mut response, bytes);
    let _ = stun.accept(source, &response, 1);
    stun.poll(2000);
    let _ = stun.accept(source, &response, 2001);

    let mut a = Engine::new(StaticSecret::from([1; 32]), Limits::default()).unwrap();
    let mut b = Engine::new(StaticSecret::from([2; 32]), Limits::default()).unwrap();
    a.install(b.public_key()).unwrap();
    b.install(a.public_key()).unwrap();
    let _ = b.receive(Ingress::Direct(source), bytes);
    if let Event::Network { mut packet, .. } = a.initiate(&b.public_key()).unwrap().remove(0) {
        mutate(&mut packet, bytes);
        let _ = b.receive(Ingress::Direct(source), &packet);
        b.remove(&a.public_key());
        let _ = b.receive(Ingress::Direct(source), &packet);
    }
});

fn mutate(packet: &mut [u8], bytes: &[u8]) {
    for mutation in bytes.chunks_exact(3).take(64) {
        let index = usize::from(u16::from_be_bytes([mutation[0], mutation[1]])) % packet.len();
        packet[index] ^= mutation[2];
    }
}
