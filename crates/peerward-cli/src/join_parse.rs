#[cfg(test)]
fn parse_join_bundle(value: &str) -> Result<ParsedJoinBundle, CliError> {
    parse_join_bundle_for_resume(value, false)
}
fn parse_join_bundle_for_resume(
    value: &str,
    allow_expired: bool,
) -> Result<ParsedJoinBundle, CliError> {
    let url = Url::parse(value).map_err(|_| CliError::invalid("invalid join URI"))?;
    if url.scheme() != "peerward"
        || url.host_str() != Some("join")
        || !url.path().is_empty()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.fragment().is_some()
    {
        return Err(CliError::invalid("join URI must use peerward://join"));
    }
    let mut values = std::collections::BTreeMap::new();
    for (key, value) in url.query_pairs() {
        if values
            .insert(key.into_owned(), value.into_owned())
            .is_some()
        {
            return Err(CliError::invalid("join URI contains duplicate fields"));
        }
    }
    if values.len() == 1 && values.contains_key("bundle") {
        return parse_encoded_join_bundle(
            values.get("bundle").expect("bundle key was checked above"),
            allow_expired,
        );
    }
    if values.keys().any(|key| {
        !matches!(
            key.as_str(),
            "control" | "token" | "mesh_id" | "root_public_key"
        )
    }) {
        return Err(CliError::invalid("join URI contains unknown fields"));
    }
    let control = Url::parse(
        values
            .get("control")
            .ok_or_else(|| CliError::invalid("join URI lacks control"))?,
    )
    .map_err(|_| CliError::invalid("invalid join control URL"))?;
    validate_join_claim_url(&control)?;
    let token = values
        .get("token")
        .ok_or_else(|| CliError::invalid("join URI lacks token"))?
        .clone();
    let token_bytes = URL_SAFE_NO_PAD
        .decode(&token)
        .map_err(|_| CliError::invalid("join token is invalid"))?;
    if !(16..=128).contains(&token_bytes.len()) {
        return Err(CliError::invalid("join token is invalid"));
    }
    let mesh_id = values
        .get("mesh_id")
        .ok_or_else(|| CliError::invalid("join URI lacks mesh_id"))?
        .parse::<Uuid>()
        .map_err(|_| CliError::invalid("invalid join mesh ID"))
        .and_then(|id| {
            MeshId::from_uuid(id).map_err(|_| CliError::invalid("invalid join mesh ID"))
        })?;
    let root_public_key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(
            values
                .get("root_public_key")
                .ok_or_else(|| CliError::invalid("join URI lacks root_public_key"))?,
        )
        .map_err(|_| CliError::invalid("invalid pinned Root key"))?
        .try_into()
        .map_err(|_| CliError::invalid("pinned Root key must contain 32 bytes"))?;
    let claim_url = control
        .join(&format!("/api/v1/join/{token}/claim"))
        .map_err(|_| CliError::invalid("invalid join control URL"))?;
    Ok(ParsedJoinBundle {
        claim_url,
        token,
        mesh_id,
        root_pin: RootPin::PublicKey(root_public_key),
    })
}

fn parse_encoded_join_bundle(
    value: &str,
    allow_expired: bool,
) -> Result<ParsedJoinBundle, CliError> {
    if value.is_empty()
        || value.contains('=')
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(CliError::invalid("join bundle must be unpadded base64url"));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| CliError::invalid("join bundle is not base64url"))?;
    if decoded.is_empty() || decoded.len() > 8 * 1024 {
        return Err(CliError::invalid("join bundle has an invalid size"));
    }
    let encoded: EncodedJoinBundle = serde_json::from_slice(&decoded)
        .map_err(|_| CliError::invalid("join bundle fields do not match schema"))?;
    if !allow_expired && encoded.expires_at <= current_unix_time()? {
        return Err(CliError::invalid("join bundle has expired"));
    }
    let nonce = URL_SAFE_NO_PAD
        .decode(&encoded.nonce)
        .map_err(|_| CliError::invalid("join bundle nonce is invalid"))?;
    if !(16..=64).contains(&nonce.len()) {
        return Err(CliError::invalid("join bundle nonce is invalid"));
    }
    let root_fingerprint: [u8; 32] = hex::decode(&encoded.root_fingerprint)
        .map_err(|_| CliError::invalid("join Root fingerprint is invalid"))?
        .try_into()
        .map_err(|_| CliError::invalid("join Root fingerprint must contain 32 bytes"))?;
    let mesh_id = encoded
        .mesh_id
        .ok_or_else(|| CliError::invalid("join bundle lacks mesh_id"))?
        .parse::<Uuid>()
        .map_err(|_| CliError::invalid("invalid join mesh ID"))
        .and_then(|id| {
            MeshId::from_uuid(id).map_err(|_| CliError::invalid("invalid join mesh ID"))
        })?;
    let claim_url =
        Url::parse(&encoded.claim_url).map_err(|_| CliError::invalid("invalid join claim URL"))?;
    validate_join_claim_url(&claim_url)?;
    let segments = claim_url
        .path_segments()
        .ok_or_else(|| CliError::invalid("invalid join claim URL"))?
        .collect::<Vec<_>>();
    if segments.len() != 5
        || segments[0] != "api"
        || segments[1] != "v1"
        || segments[2] != "join"
        || segments[4] != "claim"
    {
        return Err(CliError::invalid("join claim URL has an invalid path"));
    }
    let token = segments[3].to_owned();
    let token_bytes = URL_SAFE_NO_PAD
        .decode(&token)
        .map_err(|_| CliError::invalid("join token is invalid"))?;
    if !(16..=128).contains(&token_bytes.len()) {
        return Err(CliError::invalid("join token is invalid"));
    }
    Ok(ParsedJoinBundle {
        claim_url,
        token,
        mesh_id,
        root_pin: RootPin::Fingerprint(root_fingerprint),
    })
}

fn validate_join_claim_url(url: &Url) -> Result<(), CliError> {
    let loopback_http = url.scheme() == "http"
        && match url.host() {
            Some(url::Host::Domain("localhost")) => true,
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            _ => false,
        };
    if (url.scheme() != "https" && !loopback_http)
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(CliError::invalid(
            "join claim URL must use HTTPS outside a loopback development environment",
        ));
    }
    Ok(())
}

struct VerifiedJoinResponse {
    credential: Vec<u8>,
    root_public_key: [u8; 32],
    authority_certificates: Vec<Vec<u8>>,
    distribution_certificate: Vec<u8>,
    directory_public_key: [u8; 32],
    service_public_key: [u8; 32],
    audit_public_key: [u8; 32],
    relays: Vec<(RelayId, Vec<NetworkEndpoint>, [u8; 32])>,
    address: ipnet::IpNet,
    secondary_address: Option<ipnet::IpNet>,
    routes: Vec<ipnet::IpNet>,
    dns_server: std::net::IpAddr,
    mtu: u16,
    stun_servers: Vec<peerward_types::StunEndpoint>,
}

fn verify_join_response(
    bundle: &ParsedJoinBundle,
    response: &JoinResponse,
    local_identity_public: [u8; 32],
    local_session_public: [u8; 32],
    local_wireguard_public: [u8; 32],
) -> Result<VerifiedJoinResponse, CliError> {
    if response.mesh_id != bundle.mesh_id
        || response.profile_id != response.peer_id
        || response.authority_revision == 0
        || response.mesh_name.trim().is_empty()
        || response.dns_suffix.trim().is_empty()
        || response.relays.is_empty()
        || response.relays.len() > 64
        || response
            .relays
            .iter()
            .any(|relay| validate_endpoint_list(&relay.endpoints).is_err())
        || response.routes.is_empty()
        || response.dns_servers.len() != 1
        || !(1_280..=9_000).contains(&response.mtu)
        || response.stun_servers.len() > 8
    {
        return Err(CliError::auth(
            "join response identity or relay set is invalid",
        ));
    }
    let returned_root: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&response.root_public_key)
        .map_err(|_| CliError::auth("join response Root key is malformed"))?
        .try_into()
        .map_err(|_| CliError::auth("join response Root key has the wrong length"))?;
    let root_matches_pin = match bundle.root_pin {
        RootPin::PublicKey(expected) => returned_root == expected,
        RootPin::Fingerprint(expected) => {
            let actual: [u8; 32] = Sha256::digest(returned_root).into();
            actual == expected
        }
    };
    if !root_matches_pin {
        return Err(CliError::auth(
            "join response does not match the pinned Root identity",
        ));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CliError::failure("system clock is before the Unix epoch"))?
        .as_secs();
    let root = RootPublicKey::from_bytes(&returned_root)
        .map_err(|_| CliError::auth("pinned Root key is invalid"))?;
    let mut trust = TrustSet::new(root, bundle.mesh_id);
    let mut authority_certificates = Vec::new();
    for encoded in &response.authority_certificates {
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| CliError::auth("authority certificate is malformed"))?;
        let certificate = AuthorityCertificate::decode(&bytes)
            .map_err(|_| CliError::auth("authority certificate is malformed"))?;
        trust
            .add_authority(certificate, UnixTime(now))
            .map_err(|_| CliError::auth("authority certificate is not Root anchored"))?;
        authority_certificates.push(bytes);
    }
    if authority_certificates.is_empty() {
        return Err(CliError::auth("join response contains no authority"));
    }
    let credential = URL_SAFE_NO_PAD
        .decode(&response.credential)
        .map_err(|_| CliError::auth("peer credential is malformed"))?;
    let decoded = SubjectCredential::decode(&credential)
        .map_err(|_| CliError::auth("peer credential is malformed"))?;
    trust
        .verify_subject(&decoded, UnixTime(now))
        .map_err(|_| CliError::auth("peer credential is not Root anchored"))?;
    if decoded.subject != SubjectId::Peer(response.peer_id)
        || decoded.mesh_id != response.mesh_id
        || decoded.identity_public_key != local_identity_public
        || decoded.public_noise_key != local_session_public
        || decoded.wireguard_public_key != local_wireguard_public
    {
        return Err(CliError::auth("peer credential does not bind this device"));
    }
    let distribution_certificate = URL_SAFE_NO_PAD
        .decode(&response.distribution_certificate)
        .map_err(|_| CliError::auth("distribution certificate is malformed"))?;
    let distribution = DistributionCertificate::decode(&distribution_certificate)
        .map_err(|_| CliError::auth("distribution certificate is malformed"))?;
    trust
        .verify_distribution(&distribution, UnixTime(now))
        .map_err(|_| CliError::auth("distribution certificate is not Root anchored"))?;
    let directory_public_key = decode_join_key(&response.distribution_public_key)?;
    let service_public_key = decode_join_key(&response.service_public_key)?;
    let audit_public_key = decode_join_key(&response.audit_public_key)?;
    if distribution.directory_public_key != directory_public_key
        || distribution.service_public_key != service_public_key
        || distribution.audit_public_key != audit_public_key
    {
        return Err(CliError::auth(
            "distribution verifier binding is inconsistent",
        ));
    }
    let mut relays = Vec::new();
    for relay in &response.relays {
        let public_key = decode_join_key(&relay.public_key)?;
        relays.push((relay.relay_id, relay.endpoints.clone(), public_key));
    }
    let address = response
        .address
        .parse::<ipnet::IpNet>()
        .map_err(|_| CliError::auth("assigned address is invalid"))?;
    let routes = response
        .routes
        .iter()
        .map(|route| {
            route
                .parse::<ipnet::IpNet>()
                .map_err(|_| CliError::auth("mesh route is invalid"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let secondary_address = response
        .secondary_address
        .as_ref()
        .map(|value| {
            value
                .parse::<ipnet::IpNet>()
                .map_err(|_| CliError::auth("secondary address is invalid"))
        })
        .transpose()?;
    peerward_management::validate_assignments(address, secondary_address, &routes)
        .map_err(|_| CliError::auth("assigned addresses do not cover the Mesh route families"))?;
    let dns_server = response.dns_servers[0]
        .parse::<std::net::IpAddr>()
        .map_err(|_| CliError::auth("mesh DNS address is invalid"))?;
    if !routes.iter().any(|route| route.contains(&dns_server)) {
        return Err(CliError::auth(
            "mesh DNS address is outside every mesh route",
        ));
    }
    let stun_servers = response
        .stun_servers
        .iter()
        .map(|server| {
            server
                .parse::<peerward_types::StunEndpoint>()
                .map_err(|_| CliError::auth("STUN server is invalid"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    peerward_types::validate_stun_servers(&stun_servers)
        .map_err(|_| CliError::auth("STUN servers must be bounded and unique"))?;
    Ok(VerifiedJoinResponse {
        credential,
        root_public_key: returned_root,
        authority_certificates,
        distribution_certificate,
        directory_public_key,
        service_public_key,
        audit_public_key,
        relays,
        address,
        secondary_address,
        routes,
        dns_server,
        mtu: response.mtu,
        stun_servers,
    })
}

fn decode_join_key(value: &str) -> Result<[u8; 32], CliError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| CliError::auth("join response public key is malformed"))?
        .try_into()
        .map_err(|_| CliError::auth("join response public key has the wrong length"))
}
