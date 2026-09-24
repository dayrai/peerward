async fn execute_service(command: ServiceCommand) -> Result<(), CliError> {
    let request = match command {
        ServiceCommand::Publish {
            listen_port,
            target,
            protocol,
            name,
        } => ServiceRequest::Publish {
            listen_port,
            target,
            protocols: match protocol {
                ServiceProtocol::Tcp => vec![PublishedProtocol::Tcp],
                ServiceProtocol::Udp => vec![PublishedProtocol::Udp],
                ServiceProtocol::Both => {
                    vec![PublishedProtocol::Tcp, PublishedProtocol::Udp]
                }
            },
            alias: name,
        },
        ServiceCommand::List => ServiceRequest::List,
        ServiceCommand::Remove { service_id } => ServiceRequest::Remove {
            service_id: peerward_types::ServiceId::from_uuid(service_id)
                .map_err(|_| CliError::invalid("service ID must be a UUIDv4"))?,
        },
    };
    let response = peerward_service::client(&peer_socket_path(), &request)
        .await
        .map_err(|_| CliError::unavailable("peer management socket is unavailable"))?;
    if !response.ok {
        return Err(CliError::failure(
            response
                .error
                .unwrap_or_else(|| "service operation failed".into()),
        ));
    }
    match request {
        ServiceRequest::List => println!(
            "{}",
            serde_json::to_string(&response.services)
                .map_err(|_| CliError::failure("cannot encode service list"))?
        ),
        _ => {
            if let Some(service) = response.service {
                println!("{}", service.id);
            }
        }
    }
    Ok(())
}

async fn execute_local_query(request: ServiceRequest) -> Result<(), CliError> {
    let response = peerward_service::client(&peer_socket_path(), &request)
        .await
        .map_err(|_| CliError::unavailable("peer management socket is unavailable"))?;
    if !response.ok {
        return Err(CliError::failure(
            response
                .error
                .unwrap_or_else(|| "local query failed".into()),
        ));
    }
    println!(
        "{}",
        serde_json::to_string(&response.detail)
            .map_err(|_| CliError::failure("cannot encode local response"))?
    );
    Ok(())
}

fn peer_socket_path() -> PathBuf {
    std::env::var_os("PEERWARD_PEER_SOCKET")
        .map_or_else(|| "/run/peerward/peer.sock".into(), PathBuf::from)
}
