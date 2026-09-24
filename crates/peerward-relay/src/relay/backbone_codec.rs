const MAX_BACKBONE_BODY: usize = 60 * 1024;

fn encode_backbone_payload(payload: &BackbonePayload) -> Result<Vec<u8>, RelayError> {
    match payload {
        BackbonePayload::Control(control) => encode_legacy_forwarded_control(control),
        BackbonePayload::Presence(_) => Err(RelayError::Wire(WireError::KindMismatch)),
        BackbonePayload::RoutedControl(control, route) => {
            encode_routed_payload(1, route, &encode_control_body(control)?)
        }
        BackbonePayload::RoutedPresence(update, route) => {
            encode_routed_payload(2, route, &encode_presence(*update))
        }
    }
}

fn encode_legacy_forwarded_control(control: &RoutedControl) -> Result<Vec<u8>, RelayError> {
    let payload = encode_control_body(control)?;
    let mut body = Vec::with_capacity(1 + payload.len());
    body.push(2);
    body.extend_from_slice(&payload);
    Ok(body)
}

fn encode_control_body(control: &RoutedControl) -> Result<Vec<u8>, RelayError> {
    let envelope = control.envelope.encode_to_vec();
    if envelope.len() > MAX_BACKBONE_BODY {
        return Err(RelayError::QueueFull);
    }
    let mut body = Vec::with_capacity(44 + envelope.len());
    body.extend_from_slice(control.source.as_bytes());
    body.extend_from_slice(control.destination.as_bytes());
    body.extend_from_slice(&control.generation.to_be_bytes());
    body.extend_from_slice(
        &u32::try_from(envelope.len())
            .map_err(|_| RelayError::QueueFull)?
            .to_be_bytes(),
    );
    body.extend_from_slice(&envelope);
    Ok(body)
}

fn encode_routed_payload(
    kind: u8,
    route: &BackboneRoute,
    payload: &[u8],
) -> Result<Vec<u8>, RelayError> {
    if !(1..=4).contains(&route.hop_limit)
        || route.visited.is_empty()
        || route.visited.len() > 4
        || payload.len() > MAX_BACKBONE_BODY
        || (kind == 1) != route.destination.is_some()
    {
        return Err(RelayError::MalformedForwarded);
    }
    let mut unique = BTreeSet::new();
    if !route.visited.iter().all(|relay| unique.insert(*relay)) {
        return Err(RelayError::MalformedForwarded);
    }
    let mut body = Vec::with_capacity(48 + route.visited.len() * 16 + payload.len());
    body.extend_from_slice(&[3, kind]);
    body.extend_from_slice(route.origin.as_bytes());
    let destination = route
        .destination
        .map_or([0_u8; 16], |relay| *relay.as_bytes());
    body.extend_from_slice(&destination);
    body.extend_from_slice(&route.topology_revision.to_be_bytes());
    body.push(route.hop_limit);
    body.push(u8::try_from(route.visited.len()).map_err(|_| RelayError::MalformedForwarded)?);
    for relay in &route.visited {
        body.extend_from_slice(relay.as_bytes());
    }
    body.extend_from_slice(
        &u32::try_from(payload.len())
            .map_err(|_| RelayError::QueueFull)?
            .to_be_bytes(),
    );
    body.extend_from_slice(payload);
    Ok(body)
}

fn decode_backbone_payload(body: &[u8]) -> Result<BackbonePayload, RelayError> {
    match body.first() {
        Some(2) => decode_control_body(&body[1..]).map(BackbonePayload::Control),
        Some(3) => decode_routed_payload(&body[1..]),
        _ => Err(RelayError::MalformedForwarded),
    }
}

fn decode_routed_payload(body: &[u8]) -> Result<BackbonePayload, RelayError> {
    if body.len() < 47 {
        return Err(RelayError::MalformedForwarded);
    }
    let kind = body[0];
    let origin = relay_id(&body[1..17])?;
    let destination_bytes: [u8; 16] = body[17..33]
        .try_into()
        .map_err(|_| RelayError::MalformedForwarded)?;
    let destination = if destination_bytes == [0; 16] {
        None
    } else {
        Some(
            RelayId::from_uuid(uuid::Uuid::from_bytes(destination_bytes))
                .map_err(|_| RelayError::MalformedForwarded)?,
        )
    };
    let topology_revision = u64::from_be_bytes(
        body[33..41]
            .try_into()
            .map_err(|_| RelayError::MalformedForwarded)?,
    );
    let hop_limit = body[41];
    let visited_count = usize::from(body[42]);
    if !(1..=4).contains(&hop_limit) || !(1..=4).contains(&visited_count) {
        return Err(RelayError::MalformedForwarded);
    }
    let route_length = 43 + visited_count * 16 + 4;
    if body.len() < route_length {
        return Err(RelayError::MalformedForwarded);
    }
    let mut visited = Vec::with_capacity(visited_count);
    for chunk in body[43..43 + visited_count * 16].chunks_exact(16) {
        visited.push(relay_id(chunk)?);
    }
    let mut unique = BTreeSet::new();
    if !visited.iter().all(|relay| unique.insert(*relay)) {
        return Err(RelayError::MalformedForwarded);
    }
    let length_offset = 43 + visited_count * 16;
    let payload_length = u32::from_be_bytes(
        body[length_offset..length_offset + 4]
            .try_into()
            .map_err(|_| RelayError::MalformedForwarded)?,
    ) as usize;
    if payload_length > MAX_BACKBONE_BODY || body.len() != route_length + payload_length {
        return Err(RelayError::MalformedForwarded);
    }
    let route = BackboneRoute {
        origin,
        destination,
        topology_revision,
        hop_limit,
        visited,
    };
    let payload = &body[route_length..];
    match (kind, destination) {
        (1, Some(_)) => decode_control_body(payload)
            .map(|control| BackbonePayload::RoutedControl(control, route)),
        (2, None) => decode_presence(payload)
            .map(|presence| BackbonePayload::RoutedPresence(presence, route)),
        _ => Err(RelayError::MalformedForwarded),
    }
}

fn decode_control_body(body: &[u8]) -> Result<RoutedControl, RelayError> {
    if body.len() < 44 {
        return Err(RelayError::MalformedForwarded);
    }
    let source = PeerId::from_uuid(
        uuid::Uuid::from_slice(&body[..16]).map_err(|_| RelayError::MalformedForwarded)?,
    )
    .map_err(|_| RelayError::MalformedForwarded)?;
    let destination = PeerId::from_uuid(
        uuid::Uuid::from_slice(&body[16..32]).map_err(|_| RelayError::MalformedForwarded)?,
    )
    .map_err(|_| RelayError::MalformedForwarded)?;
    let generation = i64::from_be_bytes(
        body[32..40]
            .try_into()
            .map_err(|_| RelayError::MalformedForwarded)?,
    );
    let length = u32::from_be_bytes(
        body[40..44]
            .try_into()
            .map_err(|_| RelayError::MalformedForwarded)?,
    ) as usize;
    if length > MAX_BACKBONE_BODY || body.len() != 44 + length {
        return Err(RelayError::MalformedForwarded);
    }
    let envelope =
        ControlEnvelope::decode(&body[44..]).map_err(WireError::MalformedControl)?;
    Ok(RoutedControl {
        source,
        destination,
        generation,
        envelope,
    })
}

fn relay_id(bytes: &[u8]) -> Result<RelayId, RelayError> {
    RelayId::from_uuid(
        uuid::Uuid::from_slice(bytes).map_err(|_| RelayError::MalformedForwarded)?,
    )
    .map_err(|_| RelayError::MalformedForwarded)
}
