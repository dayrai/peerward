use crate::{HostRoute, PlatformError};
use futures_util::TryStreamExt as _;
use rtnetlink::{
    RouteMessageBuilder,
    packet_route::{
        link::LinkAttribute,
        route::{RouteAddress, RouteAttribute},
    },
};
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

/// Snapshot all IPv4/IPv6 route tables before installing a private route or advertising a gateway.
pub async fn linux_resource_routes() -> Result<Vec<HostRoute>, PlatformError> {
    let (connection, handle, _) = rtnetlink::new_connection()?;
    let worker = tokio::spawn(connection);
    let result = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut interfaces = BTreeMap::new();
        let mut stream = handle.link().get().execute();
        while let Some(link) = stream.try_next().await.map_err(error)? {
            if interfaces.len() >= 4096 {
                return Err(PlatformError::Command(
                    "route interface limit exceeded".into(),
                ));
            }
            if let Some(name) = link
                .attributes
                .iter()
                .find_map(|attribute| match attribute {
                    LinkAttribute::IfName(name) => Some(name.clone()),
                    _ => None,
                })
            {
                interfaces.insert(link.header.index, name);
            }
        }
        let mut result = Vec::new();
        for request in [
            RouteMessageBuilder::<Ipv4Addr>::new().build(),
            RouteMessageBuilder::<Ipv6Addr>::new().build(),
        ] {
            let mut stream = handle.route().get(request).execute();
            while let Some(route) = stream.try_next().await.map_err(error)? {
                if result.len() >= 8192 {
                    return Err(PlatformError::Command(
                        "route observation limit exceeded".into(),
                    ));
                }
                let interface = route
                    .attributes
                    .iter()
                    .find_map(|attribute| match attribute {
                        RouteAttribute::Oif(index) => interfaces.get(index).cloned(),
                        _ => None,
                    });
                let address = route
                    .attributes
                    .iter()
                    .find_map(|attribute| match attribute {
                        RouteAttribute::Destination(RouteAddress::Inet(ip)) => {
                            Some(IpAddr::V4(*ip))
                        }
                        RouteAttribute::Destination(RouteAddress::Inet6(ip)) => {
                            Some(IpAddr::V6(*ip))
                        }
                        _ => None,
                    });
                let address = address.or_else(|| {
                    if route.header.destination_prefix_length != 0 {
                        return None;
                    }
                    match route.header.address_family {
                        rtnetlink::packet_route::AddressFamily::Inet => {
                            Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
                        }
                        rtnetlink::packet_route::AddressFamily::Inet6 => {
                            Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
                        }
                        _ => None,
                    }
                });
                if let (Some(interface), Some(address)) = (interface, address) {
                    let prefix = ipnet::IpNet::new(address, route.header.destination_prefix_length)
                        .map_err(|_| PlatformError::InvalidName)?;
                    result.push(HostRoute {
                        prefix,
                        interface,
                        protocol: route.header.protocol.into(),
                    });
                }
            }
        }
        Ok(result)
    })
    .await;
    worker.abort();
    let _ = worker.await;
    result.map_err(|_| PlatformError::Command("route snapshot timed out".into()))?
}
fn error(error: rtnetlink::Error) -> PlatformError {
    PlatformError::Command(format!("route snapshot: {error}"))
}
