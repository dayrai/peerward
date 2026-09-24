use crate::{
    EXIT_UNDERLAY_MARK, ExitRoutingIntent, PlatformError,
    exit_routes::{EXIT_RULE_CAPTURE, EXIT_RULE_START, EXIT_TABLE},
};
use futures_util::TryStreamExt as _;
use rtnetlink::{
    Handle, IpVersion, RouteMessageBuilder,
    packet_route::{
        AddressFamily,
        route::{RouteAttribute, RouteMessage, RouteProtocol},
        rule::{RuleAction, RuleAttribute, RuleMessage},
    },
};
use std::net::{Ipv4Addr, Ipv6Addr};
const PROTOCOL: RouteProtocol = RouteProtocol::Other(99);

pub(crate) async fn change(intent: &ExitRoutingIntent, action: &str) -> Result<(), PlatformError> {
    let (connection, handle, _) = rtnetlink::new_connection()?;
    let worker = tokio::spawn(connection);
    let result = change_connected(&handle, intent, action).await;
    worker.abort();
    let _ = worker.await;
    result
}
async fn change_connected(
    handle: &Handle,
    intent: &ExitRoutingIntent,
    action: &str,
) -> Result<(), PlatformError> {
    let wanted_rules = rules(intent);
    let existing_rules = read_rules(handle).await?;
    let existing_routes = read_routes(handle).await?;
    if action == "check" {
        if !existing_routes.is_empty()
            || existing_rules.iter().any(|rule| {
                let priority = priority(rule);
                (priority > 0 && priority <= EXIT_RULE_CAPTURE) || rule_table(rule) == EXIT_TABLE
            })
        {
            return Err(PlatformError::Command(
                "exit routing conflicts with existing policy rules or reserved route table 20567"
                    .into(),
            ));
        }
        return Ok(());
    }
    let index = match crate::native_netlink::interface_index(handle, &intent.interface).await {
        Ok(index) => Some(index),
        Err(PlatformError::InterfaceMissing(_)) if action == "remove" => None,
        Err(error) => return Err(error),
    };
    let wanted_routes = index.map(|index| routes(intent, index)).unwrap_or_default();
    // Recovery matches the entire known rule/route rather than deleting by priority or table.
    // Kernel-added bookkeeping attributes are normalized, all other attributes must match.
    for rule in existing_rules.iter().filter(|rule| {
        (EXIT_RULE_START..=EXIT_RULE_CAPTURE).contains(&priority(rule))
            || rule_table(rule) == EXIT_TABLE
    }) {
        if !wanted_rules.iter().any(|wanted| same_rule(rule, wanted)) {
            return Err(PlatformError::OwnershipConflict);
        }
    }
    for route in &existing_routes {
        if !wanted_routes.iter().any(|wanted| same_route(route, wanted)) {
            return Err(PlatformError::OwnershipConflict);
        }
    }
    if action == "remove" {
        for rule in existing_rules
            .into_iter()
            .filter(|rule| wanted_rules.iter().any(|wanted| same_rule(rule, wanted)))
            .rev()
        {
            handle.rule().del(rule).execute().await.map_err(error)?;
        }
        for route in existing_routes {
            handle.route().del(route).execute().await.map_err(error)?;
        }
        return Ok(());
    }
    if !existing_routes.is_empty()
        || existing_rules
            .iter()
            .any(|rule| (EXIT_RULE_START..=EXIT_RULE_CAPTURE).contains(&priority(rule)))
    {
        return Err(PlatformError::OwnershipConflict);
    }
    for route in wanted_routes {
        handle.route().add(route).execute().await.map_err(error)?;
    }
    for rule in wanted_rules {
        let mut request = handle.rule().add();
        *request.message_mut() = rule;
        request.execute().await.map_err(error)?;
    }
    Ok(())
}
fn routes(intent: &ExitRoutingIntent, index: u32) -> Vec<RouteMessage> {
    vec![
        RouteMessageBuilder::<Ipv4Addr>::new()
            .table_id(EXIT_TABLE)
            .output_interface(index)
            .protocol(PROTOCOL)
            .pref_source(intent.ipv4)
            .build(),
        RouteMessageBuilder::<Ipv6Addr>::new()
            .table_id(EXIT_TABLE)
            .output_interface(index)
            .protocol(PROTOCOL)
            .pref_source(intent.ipv6)
            .build(),
    ]
}
fn base_rule(family: AddressFamily, priority: u32, table: u32, action: RuleAction) -> RuleMessage {
    let mut message = RuleMessage::default();
    message.header.family = family;
    message.header.action = action;
    if table <= 255 {
        message.header.table = u8::try_from(table).expect("small table identifier");
    } else {
        message.attributes.push(RuleAttribute::Table(table));
    }
    message.attributes.extend([
        RuleAttribute::Priority(priority),
        RuleAttribute::Protocol(PROTOCOL),
        RuleAttribute::Iifname("lo".into()),
    ]);
    message
}
fn rules(intent: &ExitRoutingIntent) -> Vec<RuleMessage> {
    let mut result = Vec::new();
    for family in [AddressFamily::Inet, AddressFamily::Inet6] {
        let mut bypass = base_rule(family, EXIT_RULE_START, 254, RuleAction::ToTable);
        bypass.attributes.extend([
            RuleAttribute::FwMark(EXIT_UNDERLAY_MARK),
            RuleAttribute::FwMask(u32::MAX),
        ]);
        result.push(bypass);
        // If the actual underlay has no route, marked traffic must not recurse into capture.
        let mut unavailable = base_rule(family, EXIT_RULE_START + 1, 0, RuleAction::Prohibit);
        unavailable.attributes.extend([
            RuleAttribute::FwMark(EXIT_UNDERLAY_MARK),
            RuleAttribute::FwMask(u32::MAX),
        ]);
        result.push(unavailable);
        let mut exceptions = intent.local_lan.clone();
        if family == AddressFamily::Inet6 {
            exceptions.extend([
                "fe80::/10".parse::<ipnet::IpNet>().expect("fixed prefix"),
                "ff00::/8".parse().expect("fixed prefix"),
            ]);
        }
        for (index, prefix) in exceptions
            .into_iter()
            .filter(|prefix| prefix.addr().is_ipv4() == (family == AddressFamily::Inet))
            .enumerate()
        {
            let mut rule = base_rule(
                family,
                EXIT_RULE_START + 2 + u32::try_from(index).expect("bounded exceptions"),
                254,
                RuleAction::ToTable,
            );
            rule.header.dst_len = prefix.prefix_len();
            rule.attributes
                .push(RuleAttribute::Destination(prefix.network()));
            result.push(rule);
        }
        result.push(base_rule(
            family,
            EXIT_RULE_CAPTURE,
            EXIT_TABLE,
            RuleAction::ToTable,
        ));
    }
    result
}
async fn read_rules(handle: &Handle) -> Result<Vec<RuleMessage>, PlatformError> {
    let mut result = Vec::new();
    for family in [IpVersion::V4, IpVersion::V6] {
        let mut stream = handle.rule().get(family).execute();
        while let Some(rule) = stream.try_next().await.map_err(error)? {
            if result.len() >= 4096 {
                return Err(PlatformError::OwnershipConflict);
            }
            result.push(rule);
        }
    }
    Ok(result)
}
async fn read_routes(handle: &Handle) -> Result<Vec<RouteMessage>, PlatformError> {
    let mut result = Vec::new();
    let mut observed = 0;
    for request in [
        RouteMessageBuilder::<Ipv4Addr>::new().build(),
        RouteMessageBuilder::<Ipv6Addr>::new().build(),
    ] {
        let mut stream = handle.route().get(request).execute();
        while let Some(route) = stream.try_next().await.map_err(error)? {
            observed += 1;
            if observed > 8192 {
                return Err(PlatformError::OwnershipConflict);
            }
            if route_table(&route) == EXIT_TABLE {
                result.push(route);
            }
        }
    }
    Ok(result)
}
fn priority(rule: &RuleMessage) -> u32 {
    rule.attributes
        .iter()
        .find_map(|attribute| {
            if let RuleAttribute::Priority(value) = attribute {
                Some(*value)
            } else {
                None
            }
        })
        .unwrap_or(0)
}
fn rule_table(rule: &RuleMessage) -> u32 {
    rule.attributes
        .iter()
        .find_map(|attribute| {
            if let RuleAttribute::Table(value) = attribute {
                Some(*value)
            } else {
                None
            }
        })
        .unwrap_or(u32::from(rule.header.table))
}
fn route_table(route: &RouteMessage) -> u32 {
    route
        .attributes
        .iter()
        .find_map(|attribute| {
            if let RouteAttribute::Table(value) = attribute {
                Some(*value)
            } else {
                None
            }
        })
        .unwrap_or(u32::from(route.header.table))
}
fn same_rule(actual: &RuleMessage, wanted: &RuleMessage) -> bool {
    let mut left = actual.clone();
    let mut right = wanted.clone();
    if rule_table(&left) != rule_table(&right) {
        return false;
    }
    for message in [&mut left, &mut right] {
        message.header.table = 0;
        message.attributes.retain(|attribute| {
            !matches!(
                attribute,
                RuleAttribute::Table(_) | RuleAttribute::SuppressPrefixLen(u32::MAX)
            )
        });
    }
    left.header == right.header
        && left.attributes.len() == right.attributes.len()
        && left
            .attributes
            .iter()
            .all(|attribute| right.attributes.contains(attribute))
}
fn same_route(actual: &RouteMessage, wanted: &RouteMessage) -> bool {
    let mut left = actual.clone();
    let mut right = wanted.clone();
    if route_table(&left) != route_table(&right) {
        return false;
    }
    for message in [&mut left, &mut right] {
        message.header.table = 0;
        message.attributes.retain(|attribute| {
            !matches!(
                attribute,
                RouteAttribute::Table(_)
                    | RouteAttribute::CacheInfo(_)
                    | RouteAttribute::Priority(0 | 1024)
                    | RouteAttribute::Preference(_)
            )
        });
    }
    left.header == right.header
        && left.attributes.len() == right.attributes.len()
        && left
            .attributes
            .iter()
            .all(|attribute| right.attributes.contains(attribute))
}
fn error(error: impl std::fmt::Display) -> PlatformError {
    PlatformError::Command(format!("exit policy routing: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recovery_does_not_match_foreign_routes_or_modified_rules() {
        let intent = ExitRoutingIntent {
            interface: "pwtun0".into(),
            ipv4: "10.40.0.1".parse().unwrap(),
            ipv6: "fd42::1".parse().unwrap(),
            local_lan: vec![],
        };
        let wanted = rules(&intent);
        let mut changed = wanted[0].clone();
        assert!(same_rule(&changed, &wanted[0]));
        changed
            .attributes
            .push(RuleAttribute::Source(std::net::IpAddr::V4(
                Ipv4Addr::LOCALHOST,
            )));
        assert!(!same_rule(&changed, &wanted[0]));
        let wanted = routes(&intent, 42);
        let mut changed = wanted[0].clone();
        assert!(same_route(&changed, &wanted[0]));
        changed.header.protocol = RouteProtocol::Static;
        assert!(!same_route(&changed, &wanted[0]));
    }
}
