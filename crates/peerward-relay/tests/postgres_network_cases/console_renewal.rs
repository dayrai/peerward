/// Uses real Noise/TCP Relay sessions, without substituting a store observer for
/// the authenticated runtime. The third session intentionally lacks the bit.
async fn assert_console_renewal_delivery(
    store: &Store,
    mesh: MeshId,
    credentials: &[peerward_credentials::SubjectCredential],
    signer: &DirectorySigningKey,
    sessions: &mut [RelayTestSession],
    now: u64,
) {
    let mut commands = Vec::new();
    for credential in credentials.iter().take(3) {
        let SubjectId::Peer(peer) = credential.subject else {
            panic!("peer credential required")
        };
        let command = signer
            .sign_credential_renewal(peerward_management::CredentialRenewalCommand {
                request_id: uuid::Uuid::new_v4(),
                mesh_id: mesh,
                peer_id: peer,
                current_serial: credential.serial,
                issued_at: now,
                expires_at: now + 600,
            })
            .unwrap();
        sqlx::query("INSERT INTO console_credential_renewals(mesh_id,peer_id,id,current_serial,actor,reason,request_digest,command,expires_at) VALUES($1,$2,$3,$4,'runtime-test','real relay capability delivery','runtime-test',$5,to_timestamp($6::double precision))")
            .bind(mesh.into_uuid()).bind(peer.into_uuid()).bind(command.command.request_id).bind(credential.serial.into_uuid()).bind(serde_json::to_value(&command).unwrap()).bind((now+600)as i64).execute(store.pool()).await.unwrap();
        commands.push(command);
    }
    for index in 0..2 {
        let message = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            receive_matching_control(&mut sessions[index], |control| match control.message {
                Some(ControlMessage::CredentialRenewal(value)) => Some(value),
                _ => None,
            }),
        )
        .await
        .unwrap();
        let received: peerward_management::SignedCredentialRenewal =
            serde_json::from_slice(&message.body).unwrap();
        assert_eq!(received, commands[index]);
    }
    // Repeated timer ticks must not send an already delivered command in this
    // connection, and no new message family is sent to a legacy connection.
    for index in [0, 2] {
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(1400),
                receive_matching_control(&mut sessions[index], |control| match control.message {
                    Some(ControlMessage::CredentialRenewal(value)) => Some(value),
                    _ => None,
                })
            )
            .await
            .is_err()
        );
    }
    let delivered:bool=sqlx::query_scalar("SELECT delivered_at IS NOT NULL FROM console_credential_renewals WHERE mesh_id=$1 AND id=$2").bind(mesh.into_uuid()).bind(commands[0].command.request_id).fetch_one(store.pool()).await.unwrap();
    assert!(delivered);
    let legacy_delivered:bool=sqlx::query_scalar("SELECT delivered_at IS NOT NULL FROM console_credential_renewals WHERE mesh_id=$1 AND id=$2").bind(mesh.into_uuid()).bind(commands[2].command.request_id).fetch_one(store.pool()).await.unwrap();
    assert!(!legacy_delivered);
}
