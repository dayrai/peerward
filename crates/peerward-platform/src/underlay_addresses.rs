//! Netlink address snapshots for the current Linux underlay, excluding tunnel/loopback links.
use crate::{MAX_KERNEL_TABLE_BYTES, PlatformError, read_text_bounded};
use futures_util::TryStreamExt;
use rtnetlink::packet_route::{
    address::{AddressAttribute, AddressFlags},
    link::{InfoKind, LinkAttribute, LinkFlags, LinkInfo},
};
use std::{collections::BTreeMap, net::IpAddr};

#[derive(Clone, Debug)]
pub struct UnderlayAddress {
    pub interface: String,
    pub index: u32,
    pub address: IpAddr,
    pub mtu: u32,
}

/// Reads addresses and MTUs from one bounded dump. Failures leave Relay discovery usable.
pub async fn linux_underlay_addresses() -> Result<Vec<UnderlayAddress>, PlatformError> {
    let (connection, handle, _) = rtnetlink::new_connection()?;
    let worker = DumpWorker(tokio::spawn(connection));
    let result = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut links = BTreeMap::new();
        let mut stream = handle.link().get().execute();
        while let Some(link) = stream.try_next().await.map_err(netlink_error)? {
            if !link.header.flags.contains(LinkFlags::Up) || link.header.flags.contains(LinkFlags::Loopback)
                || link.attributes.iter().any(|attribute| matches!(attribute, LinkAttribute::LinkInfo(info) if info.iter().any(|info| matches!(info, LinkInfo::Kind(InfoKind::Tun))))) { continue; }
            let name = link.attributes.iter().find_map(|attribute| match attribute { LinkAttribute::IfName(name) => Some(name.clone()), _ => None });
            let mtu = link.attributes.iter().find_map(|attribute| match attribute { LinkAttribute::Mtu(mtu) => Some(*mtu), _ => None });
            if let (Some(name), Some(mtu)) = (name, mtu) {
                if links.len() >= 4096 { return Err(PlatformError::Command("underlay link budget exceeded".into())); }
                links.insert(link.header.index, (name, mtu));
            }
        }
        let mut addresses = Vec::new();
        let mut stream = handle.address().get().execute();
        while let Some(address) = stream.try_next().await.map_err(netlink_error)? {
            let Some((name, mtu)) = links.get(&address.header.index) else { continue; };
            let flags = address.attributes.iter().find_map(|attribute| match attribute { AddressAttribute::Flags(flags) => Some(*flags), _ => None })
                .unwrap_or_else(|| AddressFlags::from_bits_retain(u32::from(address.header.flags.bits())));
            if flags.intersects(AddressFlags::Tentative | AddressFlags::Dadfailed | AddressFlags::Deprecated) { continue; }
            let ip = address.attributes.iter().find_map(|attribute| match attribute { AddressAttribute::Local(ip) => Some(*ip), _ => None })
                .or_else(|| address.attributes.iter().find_map(|attribute| match attribute { AddressAttribute::Address(ip) => Some(*ip), _ => None }));
            if let Some(ip) = ip {
                if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || matches!(ip, IpAddr::V6(ip) if ip.is_unicast_link_local()) { continue; }
                if addresses.len() >= 4096 { return Err(PlatformError::Command("underlay address budget exceeded".into())); }
                addresses.push(UnderlayAddress { interface: name.clone(), index: address.header.index, address: ip, mtu: *mtu });
            }
        }
        Ok(addresses)
    }).await;
    drop(worker);
    result.map_err(|_| PlatformError::Command("underlay snapshot timed out".into()))?
}

fn netlink_error(error: rtnetlink::Error) -> PlatformError {
    PlatformError::Command(format!("underlay netlink: {error}"))
}
struct DumpWorker(tokio::task::JoinHandle<()>);
impl Drop for DumpWorker {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Enumerates IPv4 default gateways for one interface, in route metric order.
/// Each gateway gets an independent PCP/NAT-PMP lease; no process-global default is assumed.
pub fn linux_ipv4_gateways(interface: &str) -> Result<Vec<IpAddr>, PlatformError> {
    let routes = read_text_bounded(
        std::path::Path::new("/proc/net/route"),
        MAX_KERNEL_TABLE_BYTES,
    )?;
    Ok(ipv4_gateways(&routes, interface))
}

fn ipv4_gateways(routes: &str, interface: &str) -> Vec<IpAddr> {
    let mut gateways = Vec::new();
    for line in routes.lines().skip(1) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 8 || fields[0] != interface || fields[1] != "00000000" {
            continue;
        }
        let (Ok(flags), Ok(gateway), Ok(metric)) = (
            u16::from_str_radix(fields[3], 16),
            u32::from_str_radix(fields[2], 16),
            fields[6].parse::<u32>(),
        ) else {
            continue;
        };
        if flags & 3 == 3 && gateway != 0 {
            gateways.push((
                metric,
                IpAddr::V4(std::net::Ipv4Addr::from(gateway.to_le_bytes())),
            ));
        }
    }
    gateways.sort_unstable();
    let mut ordered = Vec::new();
    for (_, gateway) in gateways {
        if !ordered.contains(&gateway) {
            ordered.push(gateway);
        }
    }
    ordered.truncate(4);
    ordered
}

/// Default gateways of the selected family, scoped by the actual interface.
pub fn linux_gateways(interface: &str, ipv4: bool) -> Result<Vec<IpAddr>, PlatformError> {
    if ipv4 {
        return linux_ipv4_gateways(interface);
    }
    let routes = read_text_bounded(
        std::path::Path::new("/proc/net/ipv6_route"),
        MAX_KERNEL_TABLE_BYTES,
    )?;
    Ok(ipv6_gateways(&routes, interface))
}

fn ipv6_gateways(routes: &str, interface: &str) -> Vec<IpAddr> {
    let mut gateways = Vec::new();
    for line in routes.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 10
            || fields[9] != interface
            || fields[0] != "00000000000000000000000000000000"
            || fields[1] != "00"
        {
            continue;
        }
        let (Ok(flags), Ok(gateway), Ok(metric)) = (
            u32::from_str_radix(fields[8], 16),
            u128::from_str_radix(fields[4], 16),
            u32::from_str_radix(fields[5], 16),
        ) else {
            continue;
        };
        if flags & 3 == 3 && gateway != 0 {
            gateways.push((metric, IpAddr::V6(std::net::Ipv6Addr::from(gateway))));
        }
    }
    gateways.sort_unstable();
    let mut ordered = Vec::new();
    for (_, gateway) in gateways {
        if !ordered.contains(&gateway) {
            ordered.push(gateway);
        }
    }
    ordered.truncate(4);
    ordered
}

#[cfg(test)]
mod gateway_tests {
    #[test]
    fn gateways_are_scoped_to_interface_up_default_routes_and_metric_order() {
        let routes = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\neth0 00000000 010200C0 0003 0 0 200 00000000 0 0 0\neth0 00000000 020200C0 0003 0 0 100 00000000 0 0 0\neth1 00000000 036433C6 0003 0 0 0 00000000 0 0 0\neth0 00000000 030200C0 0002 0 0 0 00000000 0 0 0\neth0 000200C0 040200C0 0003 0 0 0 00FFFFFF 0 0 0\n";
        let actual: Vec<_> = super::ipv4_gateways(routes, "eth0")
            .into_iter()
            .map(|v| v.to_string())
            .collect();
        assert_eq!(actual, ["192.0.2.2", "192.0.2.1"]);
    }
}
