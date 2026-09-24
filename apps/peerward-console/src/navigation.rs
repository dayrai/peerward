const fn primary_route(route: ConsoleRoute) -> ConsoleRoute {
    match route {
        ConsoleRoute::JoinTickets => ConsoleRoute::Peers,
        route => route,
    }
}

fn primary_route_label(locale: Locale, route: ConsoleRoute) -> &'static str {
    match route {
        ConsoleRoute::Meshes => console_message(locale, "network-settings"),
        ConsoleRoute::Networks => console_text(locale, "所有网络", "All networks"),
        ConsoleRoute::Audit => console_text(locale, "操作记录", "Activity log"),
        ConsoleRoute::Relays => console_text(locale, "系统维护", "System maintenance"),
        ConsoleRoute::Authorities => {
            console_text(locale, "凭据与签发机构", "Credentials and authorities")
        }
        ConsoleRoute::JoinTickets => console_text(locale, "添加设备", "Add device"),
        ConsoleRoute::Services => console_message(locale, "network-sharing"),
        ConsoleRoute::Policy => console_message(locale, "access-rules"),
        ConsoleRoute::Operations => console_message(locale, "operations"),
        _ => localized_route(locale, route),
    }
}

#[component]
fn ConsoleSectionLink(
    item: ConsoleRoute,
    mesh: String,
    selected: bool,
    client_routing: bool,
    label: &'static str,
) -> Element {
    let href =
        ConsoleClientRoute::from_console_route(item, (!mesh.is_empty()).then_some(mesh), None)
            .href();
    rsx! {
        if client_routing {
            Link { to: href, aria_current: if selected { Some("page") } else { None }, {label} }
        } else {
            a { href, aria_current: if selected { Some("page") } else { None }, {label} }
        }
    }
}

#[cfg(test)]
mod navigation_tests {
    use super::*;

    #[test]
    fn enrollment_stays_with_devices_while_system_tools_keep_their_own_scope() {
        assert_eq!(
            primary_route(ConsoleRoute::JoinTickets),
            ConsoleRoute::Peers
        );
        for route in [
            ConsoleRoute::Audit,
            ConsoleRoute::Relays,
            ConsoleRoute::Authorities,
            ConsoleRoute::Webhooks,
        ] {
            assert_eq!(primary_route(route), route);
        }
        assert_eq!(
            ConsoleRoute::from_path("/join-tickets"),
            ConsoleRoute::JoinTickets
        );
    }

    #[test]
    fn client_routes_preserve_mesh_and_relay_filters() {
        let peers = ConsoleClientRoute::from_console_route(
            ConsoleRoute::Peers,
            Some("mesh-1".into()),
            Some("relay-1".into()),
        );
        assert_eq!(peers.href(), "/peers?mesh=mesh-1&relay_id=relay-1");
        assert_eq!(
            peers.parts(),
            (
                ConsoleRoute::Peers,
                Some("mesh-1".into()),
                Some("relay-1".into())
            )
        );
        let unfiltered_peers =
            ConsoleClientRoute::from_console_route(ConsoleRoute::Peers, Some("mesh-1".into()), None);
        assert_eq!(unfiltered_peers.href(), "/peers?mesh=mesh-1");

        let overview = ConsoleClientRoute::from_console_route(ConsoleRoute::Overview, None, None);
        assert_eq!(overview.href(), "/");
        assert_eq!(overview.parts(), (ConsoleRoute::Overview, None, None));

        let access = ConsoleClientRoute::Policy {
            mesh: Some("mesh-1".into()),
            resource: Some("00000000-0000-0000-0000-000000000001".into()),
            source: Some("peer:00000000-0000-0000-0000-000000000002".into()),
        };
        let href = access.href();
        for value in [
            "/policy?",
            "mesh=mesh-1",
            "resource=00000000-0000-0000-0000-000000000001",
            "source=peer",
        ] {
            assert!(href.contains(value));
        }
        assert_eq!(
            access.parts(),
            (ConsoleRoute::Policy, Some("mesh-1".into()), None)
        );
    }
}
