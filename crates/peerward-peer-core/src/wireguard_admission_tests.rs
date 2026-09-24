use super::*;

#[test]
fn admission_deadline_expires_local_and_remote_access_without_a_control_update() {
    for expire_local in [true, false] {
        let f = Fixture::new();
        let local = f.credential(PeerId::new(), 10);
        let remote = f.credential(PeerId::new(), 20);
        let target = if expire_local { &local } else { &remote };
        let short = f
            .authority
            .issue(UnsignedSubject {
                subject: target.subject,
                mesh_id: f.mesh,
                serial: target.serial,
                identity_public_key: target.identity_public_key,
                public_noise_key: target.public_noise_key,
                wireguard_public_key: target.wireguard_public_key,
                not_before: UnixTime(1),
                not_after: UnixTime(20),
            })
            .unwrap();
        let (local, remote) = if expire_local {
            (short, remote)
        } else {
            (local, short)
        };
        let entries = vec![f.entry(&local, "10.0.0.1"), f.entry(&remote, "10.0.0.2")];
        let mut runtime = f.runtime(local, 10);
        runtime
            .install_directory(&f.signed(1, entries.clone()), UnixTime(10))
            .unwrap();
        runtime.install_policy(&f.policy(1, true)).unwrap();
        f.authorize(&mut runtime); // Lease remains valid through 910, Authority through 1000.
        let now = Instant::now();
        let packet = udp(1, 2, 4242, 10);
        assert!(
            !runtime
                .send_tunnel(&packet, UnixTime(19), now)
                .unwrap()
                .is_empty()
        );
        runtime
            .tick(UnixTime(20), now + Duration::from_secs(1))
            .unwrap();
        assert_eq!(runtime.pending_bytes(), 0);
        assert_eq!(runtime.credential_count(), usize::from(!expire_local));
        assert!(runtime.send_tunnel(&packet, UnixTime(20), now).is_err());
        assert!(
            runtime.send_tunnel(&packet, UnixTime(10), now).is_err(),
            "clock rollback cannot restore access"
        );
        let _ = runtime.install_directory(&f.signed(2, entries), UnixTime(10));
        assert!(
            runtime.send_tunnel(&packet, UnixTime(10), now).is_err(),
            "re-signing an expired binding cannot extend it"
        );
    }
}
