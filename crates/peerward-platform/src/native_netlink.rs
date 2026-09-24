//! Native Linux address, link, and route changes through rtnetlink.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use futures_util::TryStreamExt;
use ipnet::IpNet;
use rtnetlink::{
    AddressMessageBuilder, Handle, LinkUnspec, RouteMessageBuilder, new_connection,
    packet_route::route::RouteProtocol,
};

use crate::PlatformError;

// Keep Peerward-created routes distinguishable from kernel, boot, and operator routes so
// recovery can remove only the entries owned by this transaction.
const PEERWARD_ROUTE_PROTOCOL: u8 = 99;

pub(crate) fn run(arguments: &[String]) -> Result<String, PlatformError> {
    let arguments = arguments.to_vec();
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .map_err(PlatformError::Io)?
            .block_on(run_async(&arguments))
    })
    .join()
    .map_err(|_| PlatformError::Command("rtnetlink worker panicked".into()))?
}

async fn run_async(arguments: &[String]) -> Result<String, PlatformError> {
    let (connection, handle, _) = new_connection().map_err(netlink_error)?;
    tokio::spawn(connection);
    match arguments {
        [address, action, cidr, dev, interface]
            if address == "address" && dev == "dev" && matches!(action.as_str(), "add" | "del") =>
        {
            change_address(&handle, interface, cidr, action == "add").await?;
        }
        [link, set, dev, interface, mtu_keyword, mtu, up]
            if link == "link"
                && set == "set"
                && dev == "dev"
                && mtu_keyword == "mtu"
                && up == "up" =>
        {
            let mtu = mtu.parse::<u32>().map_err(|_| invalid_command(arguments))?;
            let index = interface_index(&handle, interface).await?;
            let message = LinkUnspec::new_with_index(index).mtu(mtu).up().build();
            handle
                .link()
                .set(message)
                .execute()
                .await
                .map_err(|error| link_error(error, interface))?;
        }
        [link, set, dev, interface, down]
            if link == "link" && set == "set" && dev == "dev" && down == "down" =>
        {
            let index = interface_index(&handle, interface).await?;
            let message = LinkUnspec::new_with_index(index).down().build();
            handle
                .link()
                .set(message)
                .execute()
                .await
                .map_err(|error| link_error(error, interface))?;
        }
        [route, action, cidr, dev, interface]
            if route == "route" && dev == "dev" && matches!(action.as_str(), "add" | "del") =>
        {
            change_route(&handle, interface, cidr, action == "add").await?;
        }
        _ => return Err(invalid_command(arguments)),
    }
    Ok(String::new())
}

async fn change_address(
    handle: &Handle,
    interface: &str,
    cidr: &str,
    add: bool,
) -> Result<(), PlatformError> {
    let network = cidr.parse::<IpNet>().map_err(|_| invalid_value(cidr))?;
    let index = interface_index(handle, interface).await?;
    if add {
        handle
            .address()
            .add(index, network.addr(), network.prefix_len())
            .execute()
            .await
            .map_err(|error| link_error(error, interface))?;
        return Ok(());
    }
    let message = match network.addr() {
        IpAddr::V4(address) => AddressMessageBuilder::<Ipv4Addr>::new()
            .index(index)
            .address(address, network.prefix_len())
            .build(),
        IpAddr::V6(address) => AddressMessageBuilder::<Ipv6Addr>::new()
            .index(index)
            .address(address, network.prefix_len())
            .build(),
    };
    handle
        .address()
        .del(message)
        .execute()
        .await
        .map_err(|error| link_error(error, interface))
}

async fn change_route(
    handle: &Handle,
    interface: &str,
    cidr: &str,
    add: bool,
) -> Result<(), PlatformError> {
    let network = cidr.parse::<IpNet>().map_err(|_| invalid_value(cidr))?;
    let index = interface_index(handle, interface).await?;
    let message = match network {
        IpNet::V4(network) => RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(network.network(), network.prefix_len())
            .output_interface(index)
            .protocol(RouteProtocol::Other(PEERWARD_ROUTE_PROTOCOL))
            .build(),
        IpNet::V6(network) => RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix(network.network(), network.prefix_len())
            .output_interface(index)
            .protocol(RouteProtocol::Other(PEERWARD_ROUTE_PROTOCOL))
            .build(),
    };
    if add {
        handle
            .route()
            .add(message)
            .execute()
            .await
            .map_err(|error| link_error(error, interface))
    } else {
        handle
            .route()
            .del(message)
            .execute()
            .await
            .map_err(|error| link_error(error, interface))
    }
}

pub(crate) async fn interface_index(
    handle: &Handle,
    interface: &str,
) -> Result<u32, PlatformError> {
    let mut links = handle
        .link()
        .get()
        .match_name(interface.to_owned())
        .execute();
    links
        .try_next()
        .await
        .map_err(|error| link_error(error, interface))?
        .map(|link| link.header.index)
        .ok_or_else(|| PlatformError::InterfaceMissing(interface.to_owned()))
}

fn invalid_command(arguments: &[String]) -> PlatformError {
    PlatformError::Command(format!(
        "unsupported native network operation: {}",
        arguments.join(" ")
    ))
}

fn invalid_value(value: &str) -> PlatformError {
    PlatformError::Command(format!("invalid network value: {value}"))
}

fn netlink_error(error: impl std::fmt::Display) -> PlatformError {
    PlatformError::Command(format!("rtnetlink: {error}"))
}

fn link_error(error: rtnetlink::Error, interface: &str) -> PlatformError {
    if matches!(&error, rtnetlink::Error::NetlinkError(message)
        if message.to_io().raw_os_error() == Some(libc::ENODEV))
    {
        PlatformError::InterfaceMissing(interface.to_owned())
    } else {
        netlink_error(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_enodev_is_classified_as_a_missing_interface() {
        for code in [libc::ENODEV, libc::EPERM, libc::ENOENT, libc::EIO] {
            let mut message = rtnetlink::packet_core::ErrorMessage::default();
            message.code = std::num::NonZeroI32::new(-code);
            let error = link_error(rtnetlink::Error::NetlinkError(message), "pwd0");
            assert_eq!(
                matches!(error, PlatformError::InterfaceMissing(_)),
                code == libc::ENODEV
            );
        }
    }

    #[tokio::test]
    async fn real_netlink_lookup_reports_missing_interface() {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        // Query only: no network changes or elevated permissions are needed.
        let interface = format!("pw{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
        assert!(matches!(interface_index(&handle, &interface).await,
            Err(PlatformError::InterfaceMissing(name)) if name == interface));
    }
}
