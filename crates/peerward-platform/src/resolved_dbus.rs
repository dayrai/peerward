//! Type-safe systemd-resolved split-DNS updates over the system D-Bus.

use std::net::IpAddr;

use rtnetlink::new_connection;
use zbus::{Connection, Proxy, zvariant::OwnedObjectPath};

use crate::{PlatformError, ResolvedLinkMutation, ResolvedLinkState, native_netlink};

const SERVICE: &str = "org.freedesktop.resolve1";
const PATH: &str = "/org/freedesktop/resolve1";
const INTERFACE: &str = "org.freedesktop.resolve1.Manager";
const LINK_INTERFACE: &str = "org.freedesktop.resolve1.Link";

pub(crate) fn run(arguments: &[String], input: Option<&str>) -> Result<String, PlatformError> {
    let arguments = arguments.to_vec();
    let input = input.map(ToOwned::to_owned);
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .map_err(PlatformError::Io)?
            .block_on(run_async(&arguments, input.as_deref()))
    })
    .join()
    .map_err(|_| PlatformError::Command("D-Bus worker panicked".into()))?
}

async fn run_async(arguments: &[String], input: Option<&str>) -> Result<String, PlatformError> {
    let interface = arguments.get(1).ok_or_else(|| invalid_command(arguments))?;
    let (netlink_connection, handle, _) = new_connection().map_err(dbus_error)?;
    tokio::spawn(netlink_connection);
    let index = i32::try_from(native_netlink::interface_index(&handle, interface).await?)
        .map_err(|_| PlatformError::Command("interface index exceeds D-Bus range".into()))?;
    let connection = Connection::system().await.map_err(dbus_error)?;
    let proxy = Proxy::new(&connection, SERVICE, PATH, INTERFACE)
        .await
        .map_err(dbus_error)?;
    let link_path: OwnedObjectPath = proxy.call("GetLink", &(index,)).await.map_err(dbus_error)?;
    match arguments {
        [operation, _] if operation == "probe" => {}
        [operation, _] if operation == "snapshot" => {
            return serde_json::to_string(&read_link_state(&connection, &link_path).await?)
                .map_err(PlatformError::from);
        }
        [operation, _] if operation == "replace" => {
            let mutation: ResolvedLinkMutation = serde_json::from_str(
                input.ok_or_else(|| PlatformError::Command("missing resolved mutation".into()))?,
            )?;
            let current = read_link_state(&connection, &link_path).await?;
            if current == mutation.replacement {
                return Ok(String::new());
            }
            if current != mutation.expected {
                return Err(PlatformError::OwnershipConflict);
            }
            if let Err(error) = set_link_state(&proxy, index, &mutation.replacement).await {
                let _ = set_link_state(&proxy, index, &mutation.expected).await;
                return Err(error);
            }
        }
        [operation, _, server] if operation == "dns" => {
            let address = server
                .parse::<IpAddr>()
                .map_err(|_| invalid_command(arguments))?;
            let family = if address.is_ipv4() { 2 } else { 10 };
            let bytes = match address {
                IpAddr::V4(value) => value.octets().to_vec(),
                IpAddr::V6(value) => value.octets().to_vec(),
            };
            proxy
                .call::<_, _, ()>("SetLinkDNS", &(index, vec![(family, bytes)]))
                .await
                .map_err(dbus_error)?;
        }
        [operation, _, domain] if operation == "domain" => {
            let domain = domain
                .strip_prefix('~')
                .ok_or_else(|| invalid_command(arguments))?;
            proxy
                .call::<_, _, ()>("SetLinkDomains", &(index, vec![(domain, true)]))
                .await
                .map_err(dbus_error)?;
        }
        [operation, _, value] if operation == "default-route" => {
            let enabled = match value.as_str() {
                "true" => true,
                "false" => false,
                _ => return Err(invalid_command(arguments)),
            };
            proxy
                .call::<_, _, ()>("SetLinkDefaultRoute", &(index, enabled))
                .await
                .map_err(dbus_error)?;
        }
        [operation, _] if operation == "revert" => {
            proxy
                .call::<_, _, ()>("RevertLink", &(index,))
                .await
                .map_err(dbus_error)?;
        }
        _ => return Err(invalid_command(arguments)),
    }
    Ok(String::new())
}

async fn read_link_state(
    connection: &Connection,
    path: &OwnedObjectPath,
) -> Result<ResolvedLinkState, PlatformError> {
    let proxy = Proxy::new(connection, SERVICE, path.as_str(), LINK_INTERFACE)
        .await
        .map_err(dbus_error)?;
    Ok(ResolvedLinkState {
        dns: proxy.get_property("DNS").await.map_err(dbus_error)?,
        domains: proxy.get_property("Domains").await.map_err(dbus_error)?,
        default_route: proxy
            .get_property("DefaultRoute")
            .await
            .map_err(dbus_error)?,
    })
}

async fn set_link_state(
    proxy: &Proxy<'_>,
    index: i32,
    state: &ResolvedLinkState,
) -> Result<(), PlatformError> {
    proxy
        .call::<_, _, ()>("SetLinkDNS", &(index, &state.dns))
        .await
        .map_err(dbus_error)?;
    proxy
        .call::<_, _, ()>("SetLinkDomains", &(index, &state.domains))
        .await
        .map_err(dbus_error)?;
    proxy
        .call::<_, _, ()>("SetLinkDefaultRoute", &(index, state.default_route))
        .await
        .map_err(dbus_error)
}

fn invalid_command(arguments: &[String]) -> PlatformError {
    PlatformError::Command(format!(
        "unsupported resolved D-Bus operation: {}",
        arguments.join(" ")
    ))
}

fn dbus_error(error: impl std::fmt::Display) -> PlatformError {
    PlatformError::Command(format!("system D-Bus: {error}"))
}
