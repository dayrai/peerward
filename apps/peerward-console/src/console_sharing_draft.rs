#[allow(clippy::too_many_arguments)]
fn build_sharing_draft(
    request_id: uuid::Uuid,
    name: String,
    provider: String,
    kind: String,
    protocol: String,
    port: String,
    prefix: String,
    site: String,
    ipv6: bool,
    dns: String,
    dns_address: String,
    source: String,
    reason: String,
) -> Result<peerward_api::ConsoleSharingDraft, String> {
    let invalid =
        || "请检查地址、端口和设备选择 / Check addresses, ports and device selection".to_owned();
    if !matches!(kind.as_str(), "service" | "lan" | "internet")
        || !matches!(protocol.as_str(), "tcp" | "udp" | "http" | "https" | "both" | "all")
        || (kind != "service" && matches!(protocol.as_str(), "http" | "https" | "both"))
        || (kind == "service" && protocol == "all")
        || name.trim().is_empty()
    {
        return Err(invalid());
    }
    let provider = provider.parse().map_err(|_| invalid())?;
    let port = if protocol == "all" {
        None
    } else {
        Some(
            port.parse::<u16>()
                .ok()
                .filter(|p| *p > 0)
                .ok_or_else(invalid)?,
        )
    };
    let target = if kind == "service" {
        let protocols = match protocol.as_str() {
            "udp" => vec![peerward_types::ServiceProtocol::Udp],
            "both" => {
                vec![
                    peerward_types::ServiceProtocol::Tcp,
                    peerward_types::ServiceProtocol::Udp,
                ]
            }
            _ => vec![peerward_types::ServiceProtocol::Tcp],
        };
        let alias = dns.trim();
        if !alias.is_empty() && (alias.len() > 63 || alias.starts_with('-') || alias.ends_with('-') || !alias.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')) {
            return Err("DNS 服务别名只能包含字母、数字和连字符，例如 nas；不要填写完整域名。 / Enter a DNS service label, such as nas, not a full domain.".into());
        }
        peerward_api::ConsoleSharingTarget::Service {
            protocols,
            port: port.ok_or_else(invalid)?,
            alias: (!alias.is_empty()).then(|| alias.to_ascii_lowercase()),
        }
    } else {
        let target = if kind == "lan" {
            peerward_management::ResourceTarget::Subnet {
                prefix: prefix.parse().map_err(|_| invalid())?,
                site_id: site.parse().map_err(|_| invalid())?,
            }
        } else {
            peerward_management::ResourceTarget::Internet { ipv4: true, ipv6 }
        };
        peerward_api::ConsoleSharingTarget::Network {
            definition: peerward_management::ResourceDefinition {
                name: name.trim().to_owned(),
                target,
                labels: BTreeMap::new(),
                health_probe: None,
            },
            dns_name: (!dns.trim().is_empty()).then(|| dns.trim().to_owned()),
            dns_address: if dns.trim().is_empty() {
                None
            } else if dns_address.trim().is_empty() && kind == "lan" {
                let network: ipnet::IpNet = prefix.parse().map_err(|_| invalid())?;
                if network.prefix_len() != if network.addr().is_ipv4() { 32 } else { 128 } {
                    return Err("请为网段内的 DNS 名称指定解析地址。 / Choose a DNS address within the subnet.".into());
                }
                Some(network.addr())
            } else if dns_address.trim().is_empty() {
                return Err(invalid());
            } else {
                Some(dns_address.trim().parse().map_err(|_| invalid())?)
            },
        }
    };
    let source = if let Some(id) = source.strip_prefix("peer:") {
        peerward_api::ConsoleGrantSource::Peer {
            id: id.parse().map_err(|_| invalid())?,
        }
    } else if let Some(id) = source.strip_prefix("group:") {
        peerward_api::ConsoleGrantSource::Collection {
            id: id.parse().map_err(|_| invalid())?,
        }
    } else if source.is_empty() {
        peerward_api::ConsoleGrantSource::None
    } else {
        return Err(invalid());
    };
    Ok(peerward_api::ConsoleSharingDraft {
        request_id,
        name: name.trim().to_owned(),
        provider,
        target,
        source,
        protocol: match protocol.as_str() {
            "all" => 0,
            "udp" => 17,
            _ => 6,
        },
        port,
        reason,
    })
}
