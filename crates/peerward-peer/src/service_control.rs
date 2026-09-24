fn encode_service_change(
    mesh_id: MeshId,
    change: ServiceChange,
) -> (ServiceId, oneshot::Sender<bool>, ControlEnvelope) {
    let (service_id, reply, message) = match change {
        ServiceChange::Publish(service, reply) => {
            let protocols = service
                .protocols
                .iter()
                .map(|protocol| match protocol {
                    ServiceProtocol::Tcp => 1,
                    ServiceProtocol::Udp => 2,
                })
                .collect();
            let message = ControlMessage::ServicePublish(peerward_wire::ServicePublish {
                mesh_id: mesh_id.as_bytes().to_vec(),
                service_id: service.id.as_bytes().to_vec(),
                protocols,
                listen_port: u32::from(service.listen_port),
                alias: service.alias.unwrap_or_default(),
            });
            (service.id, reply, message)
        }
        ServiceChange::Remove(service_id, reply) => {
            let message = ControlMessage::ServiceRemove(peerward_wire::ServiceRemove {
                mesh_id: mesh_id.as_bytes().to_vec(),
                service_id: service_id.as_bytes().to_vec(),
            });
            (service_id, reply, message)
        }
    };
    (
        service_id,
        reply,
        ControlEnvelope {
            trace_context: None,
            message: Some(message),
        },
    )
}

fn decode_service_result(
    mesh_id: MeshId,
    result: &peerward_wire::ServiceMutationResult,
) -> Result<(ServiceId, bool), PacketPumpError> {
    if result.mesh_id != mesh_id.as_bytes() {
        return Err(PacketPumpError::InvalidControl);
    }
    let raw = uuid::Uuid::from_slice(&result.service_id)
        .map_err(|_| PacketPumpError::InvalidControl)?;
    let service_id =
        ServiceId::from_uuid(raw).map_err(|_| PacketPumpError::InvalidControl)?;
    Ok((service_id, result.committed))
}
