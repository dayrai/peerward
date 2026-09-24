//! `NetworkManager` profile DNS updates without spawning `nmcli`.

use std::collections::HashMap;

use zbus::{
    Connection, Proxy,
    zvariant::{OwnedObjectPath, OwnedValue, Value},
};

use crate::{NetworkManagerDnsMutation, NetworkManagerDnsState, PlatformError};

const SERVICE: &str = "org.freedesktop.NetworkManager";
const MANAGER_PATH: &str = "/org/freedesktop/NetworkManager";
const SETTINGS_PATH: &str = "/org/freedesktop/NetworkManager/Settings";
const SETTINGS_INTERFACE: &str = "org.freedesktop.NetworkManager.Settings";
const CONNECTION_INTERFACE: &str = "org.freedesktop.NetworkManager.Settings.Connection";
const ACTIVE_INTERFACE: &str = "org.freedesktop.NetworkManager.Connection.Active";
const DEVICE_INTERFACE: &str = "org.freedesktop.NetworkManager.Device";

type Settings = HashMap<String, HashMap<String, OwnedValue>>;

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
    .map_err(|_| PlatformError::Command("NetworkManager D-Bus worker panicked".into()))?
}

async fn run_async(arguments: &[String], input: Option<&str>) -> Result<String, PlatformError> {
    let connection = Connection::system().await.map_err(dbus_error)?;
    match arguments {
        [replace, profile] if replace == "replace" => {
            let mutation: NetworkManagerDnsMutation =
                serde_json::from_str(input.ok_or_else(|| {
                    PlatformError::Command("missing NetworkManager DNS mutation".into())
                })?)?;
            if mutation.expected.family != mutation.replacement.family {
                return Err(invalid_command(arguments));
            }
            let current = read_dns_state(&connection, profile, &mutation.expected.family).await?;
            if current == mutation.replacement {
                return Ok(String::new());
            }
            if current != mutation.expected {
                return Err(PlatformError::OwnershipConflict);
            }
            if let Err(error) = apply_dns_state(&connection, profile, &mutation.replacement).await {
                let _ = apply_dns_state(&connection, profile, &mutation.expected).await;
                return Err(error);
            }
            Ok(String::new())
        }
        [get, property, connection_keyword, show, profile]
            if get == "-g" && connection_keyword == "connection" && show == "show" =>
        {
            read_property(&connection, profile, property).await
        }
        [
            connection_keyword,
            modify,
            profile,
            property_a,
            value_a,
            property_b,
            value_b,
        ] if connection_keyword == "connection" && modify == "modify" => {
            let (path, mut settings) = find_profile(&connection, profile).await?;
            set_property(&mut settings, property_a, value_a)?;
            set_property(&mut settings, property_b, value_b)?;
            let proxy = connection_proxy(&connection, &path).await?;
            proxy
                .call::<_, _, ()>("Update", &(settings,))
                .await
                .map_err(dbus_error)?;
            Ok(String::new())
        }
        [connection_keyword, up, profile] if connection_keyword == "connection" && up == "up" => {
            let (path, _) = find_profile(&connection, profile).await?;
            reapply_active_devices(&connection, &path).await?;
            Ok(String::new())
        }
        _ => Err(invalid_command(arguments)),
    }
}

async fn read_dns_state(
    connection: &Connection,
    profile: &str,
    family: &str,
) -> Result<NetworkManagerDnsState, PlatformError> {
    if !matches!(family, "ipv4" | "ipv6") {
        return Err(PlatformError::Command(
            "invalid NetworkManager DNS family".into(),
        ));
    }
    Ok(NetworkManagerDnsState {
        family: family.to_owned(),
        dns: read_property(connection, profile, &format!("{family}.dns")).await?,
        search: read_property(connection, profile, &format!("{family}.dns-search")).await?,
    })
}

async fn apply_dns_state(
    connection: &Connection,
    profile: &str,
    state: &NetworkManagerDnsState,
) -> Result<(), PlatformError> {
    let (path, mut settings) = find_profile(connection, profile).await?;
    set_property(&mut settings, &format!("{}.dns", state.family), &state.dns)?;
    set_property(
        &mut settings,
        &format!("{}.dns-search", state.family),
        &state.search,
    )?;
    let proxy = connection_proxy(connection, &path).await?;
    proxy
        .call::<_, _, ()>("Update", &(settings,))
        .await
        .map_err(dbus_error)?;
    reapply_active_devices(connection, &path).await
}

async fn read_property(
    connection: &Connection,
    profile: &str,
    property: &str,
) -> Result<String, PlatformError> {
    let (_, settings) = find_profile(connection, profile).await?;
    let (family, key) = property_names(property)?;
    let Some(value) = settings.get(family).and_then(|section| section.get(key)) else {
        return Ok(String::new());
    };
    let owned = value.try_clone().map_err(dbus_error)?;
    let values = Vec::<String>::try_from(owned).map_err(dbus_error)?;
    Ok(values.join(","))
}

fn set_property(settings: &mut Settings, property: &str, value: &str) -> Result<(), PlatformError> {
    let (family, key) = property_names(property)?;
    let values = value
        .split(',')
        .filter(|entry| !entry.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    let owned = Value::new(values).try_to_owned().map_err(dbus_error)?;
    settings
        .entry(family.to_owned())
        .or_default()
        .insert(key.to_owned(), owned);
    Ok(())
}

fn property_names(property: &str) -> Result<(&str, &str), PlatformError> {
    match property {
        "ipv4.dns" => Ok(("ipv4", "dns-data")),
        "ipv4.dns-search" => Ok(("ipv4", "dns-search")),
        "ipv6.dns" => Ok(("ipv6", "dns-data")),
        "ipv6.dns-search" => Ok(("ipv6", "dns-search")),
        _ => Err(PlatformError::Command(format!(
            "unsupported NetworkManager property: {property}"
        ))),
    }
}

async fn find_profile(
    connection: &Connection,
    profile: &str,
) -> Result<(OwnedObjectPath, Settings), PlatformError> {
    let proxy = Proxy::new(connection, SERVICE, SETTINGS_PATH, SETTINGS_INTERFACE)
        .await
        .map_err(dbus_error)?;
    let paths: Vec<OwnedObjectPath> = proxy
        .call("ListConnections", &())
        .await
        .map_err(dbus_error)?;
    for path in paths {
        let proxy = connection_proxy(connection, &path).await?;
        let settings: Settings = proxy.call("GetSettings", &()).await.map_err(dbus_error)?;
        let id = settings
            .get("connection")
            .and_then(|section| section.get("id"))
            .and_then(|value| <&str>::try_from(value).ok());
        if id == Some(profile) {
            return Ok((path, settings));
        }
    }
    Err(PlatformError::Command(format!(
        "NetworkManager profile {profile} does not exist"
    )))
}

async fn connection_proxy<'a>(
    connection: &'a Connection,
    path: &'a OwnedObjectPath,
) -> Result<Proxy<'a>, PlatformError> {
    Proxy::new(connection, SERVICE, path.as_str(), CONNECTION_INTERFACE)
        .await
        .map_err(dbus_error)
}

async fn reapply_active_devices(
    connection: &Connection,
    profile: &OwnedObjectPath,
) -> Result<(), PlatformError> {
    let manager = Proxy::new(
        connection,
        SERVICE,
        MANAGER_PATH,
        "org.freedesktop.NetworkManager",
    )
    .await
    .map_err(dbus_error)?;
    let active: Vec<OwnedObjectPath> = manager
        .get_property("ActiveConnections")
        .await
        .map_err(dbus_error)?;
    for path in active {
        let active_proxy = Proxy::new(connection, SERVICE, path.as_str(), ACTIVE_INTERFACE)
            .await
            .map_err(dbus_error)?;
        let configured: OwnedObjectPath = active_proxy
            .get_property("Connection")
            .await
            .map_err(dbus_error)?;
        if configured != *profile {
            continue;
        }
        let devices: Vec<OwnedObjectPath> = active_proxy
            .get_property("Devices")
            .await
            .map_err(dbus_error)?;
        for device in devices {
            let proxy = Proxy::new(connection, SERVICE, device.as_str(), DEVICE_INTERFACE)
                .await
                .map_err(dbus_error)?;
            proxy
                .call::<_, _, ()>("Reapply", &(Settings::new(), 0_u64, 0_u32))
                .await
                .map_err(dbus_error)?;
        }
        return Ok(());
    }
    Err(PlatformError::Command(format!(
        "NetworkManager profile {} is not active",
        profile.as_str()
    )))
}

fn invalid_command(arguments: &[String]) -> PlatformError {
    PlatformError::Command(format!(
        "unsupported NetworkManager D-Bus operation: {}",
        arguments.join(" ")
    ))
}

fn dbus_error(error: impl std::fmt::Display) -> PlatformError {
    PlatformError::Command(format!("NetworkManager D-Bus: {error}"))
}
