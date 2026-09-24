#[cfg(feature = "ssr")]
const HASHED_STYLESHEET_PATH: &str = concat!(
    "/assets/main-",
    env!("PEERWARD_CONSOLE_ASSET_VERSION"),
    ".css"
);
#[cfg(feature = "ssr")]
const CLIENT_ASSET_VERSION: &str = env!("PEERWARD_CONSOLE_ASSET_VERSION");

fn create_action_disabled(loading: bool, resource_selected: bool) -> bool {
    loading || resource_selected
}

#[derive(Clone)]
struct ConsoleRouterBootstrap {
    snapshot: ConsoleSnapshot,
}

#[derive(Debug, Clone, PartialEq, Routable)]
#[rustfmt::skip]
enum ConsoleClientRoute {
    #[layout(ConsoleRouterLayout)]
        #[route("/?:mesh")]
        Overview { mesh: Option<String> },
        #[route("/meshes?:mesh")]
        Meshes { mesh: Option<String> },
        #[route("/networks?:mesh")]
        Networks { mesh: Option<String> },
        #[route("/authorities?:mesh")]
        Authorities { mesh: Option<String> },
        #[route("/peers?:mesh&:relay_id&:resource")]
        Peers { mesh: Option<String>, relay_id: Option<String>, resource:Option<String> },
        #[route("/relays?:mesh")]
        Relays { mesh: Option<String> },
        #[route("/join-tickets?:mesh&:resource")]
        JoinTickets { mesh: Option<String>, resource: Option<String> },
        #[route("/policy?:mesh&:resource&:source")]
        Policy { mesh: Option<String>, resource: Option<String>, source: Option<String> },
        #[route("/services?:mesh&:resource")]
        Services { mesh: Option<String>, resource:Option<String> },
        #[route("/audit?:mesh")]
        Audit { mesh: Option<String> },
        #[route("/operations?:mesh")]
        Operations { mesh: Option<String> },
        #[route("/webhooks?:mesh")]
        Webhooks { mesh: Option<String> },
}

impl ConsoleClientRoute {
    fn from_console_route(
        route: ConsoleRoute,
        mesh: Option<String>,
        relay_id: Option<String>,
    ) -> Self {
        match route {
            ConsoleRoute::Overview => Self::Overview { mesh },
            ConsoleRoute::Meshes => Self::Meshes { mesh },
            ConsoleRoute::Networks => Self::Networks { mesh },
            ConsoleRoute::Authorities => Self::Authorities { mesh },
            ConsoleRoute::Peers => Self::Peers {
                mesh,
                relay_id,
                resource: None,
            },
            ConsoleRoute::Relays => Self::Relays { mesh },
            ConsoleRoute::JoinTickets => Self::JoinTickets { mesh, resource: None },
            ConsoleRoute::Policy => Self::Policy {
                mesh,
                resource: None,
                source: None,
            },
            ConsoleRoute::Services => Self::Services {
                mesh,
                resource: None,
            },
            ConsoleRoute::Audit => Self::Audit { mesh },
            ConsoleRoute::Operations => Self::Operations { mesh },
            ConsoleRoute::Webhooks => Self::Webhooks { mesh },
        }
    }

    fn parts(&self) -> (ConsoleRoute, Option<String>, Option<String>) {
        match self {
            Self::Overview { mesh } => (ConsoleRoute::Overview, mesh.clone(), None),
            Self::Meshes { mesh } => (ConsoleRoute::Meshes, mesh.clone(), None),
            Self::Networks { mesh } => (ConsoleRoute::Networks, mesh.clone(), None),
            Self::Authorities { mesh } => (ConsoleRoute::Authorities, mesh.clone(), None),
            Self::Peers { mesh, relay_id, .. } => {
                (ConsoleRoute::Peers, mesh.clone(), relay_id.clone())
            }
            Self::Relays { mesh } => (ConsoleRoute::Relays, mesh.clone(), None),
            Self::JoinTickets { mesh, .. } => (ConsoleRoute::JoinTickets, mesh.clone(), None),
            Self::Policy { mesh, .. } => (ConsoleRoute::Policy, mesh.clone(), None),
            Self::Services { mesh, .. } => (ConsoleRoute::Services, mesh.clone(), None),
            Self::Audit { mesh } => (ConsoleRoute::Audit, mesh.clone(), None),
            Self::Operations { mesh } => (ConsoleRoute::Operations, mesh.clone(), None),
            Self::Webhooks { mesh } => (ConsoleRoute::Webhooks, mesh.clone(), None),
        }
    }

    fn href(&self) -> String {
        self.to_string().trim_end_matches(['?', '&']).to_owned()
    }
}

#[derive(Clone, PartialEq, Eq)]
struct ConsoleLocation {
    route: ConsoleRoute,
    mesh: Option<String>,
    relay_id: Option<String>,
}

impl ConsoleLocation {
    fn new(route: ConsoleRoute, mesh: Option<String>, relay_id: Option<String>) -> Self {
        Self {
            route,
            mesh: mesh.filter(|value| !value.is_empty()),
            relay_id: relay_id.filter(|value| !value.is_empty()),
        }
    }
}

#[allow(non_snake_case)]
pub fn WebConsole() -> Element {
    #[cfg(not(target_arch = "wasm32"))]
    let (route, snapshot) = {
        #[cfg(feature = "ssr")]
        {
            SSR_BOOTSTRAP
                .with(|value| value.borrow().clone())
                .unwrap_or_default()
        }
        #[cfg(not(feature = "ssr"))]
        {
            (ConsoleRoute::Overview, ConsoleSnapshot::default())
        }
    };
    #[cfg(target_arch = "wasm32")]
    let snapshot: ConsoleSnapshot = web_sys::window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id("peerward-bootstrap"))
        .and_then(|element| element.text_content())
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default();

    #[cfg(not(target_arch = "wasm32"))]
    let initial_location = ConsoleClientRoute::from_console_route(
        route,
        (!snapshot.mesh_id.is_empty()).then(|| snapshot.mesh_id.clone()),
        snapshot.relay_filter.clone(),
    );
    use_context_provider(|| ConsoleRouterBootstrap { snapshot });

    #[cfg(target_arch = "wasm32")]
    return rsx! { Router::<ConsoleClientRoute> {} };

    #[cfg(not(target_arch = "wasm32"))]
    rsx! {
        dioxus::router::components::HistoryProvider {
            history: move |()| std::rc::Rc::new(
                dioxus_history::MemoryHistory::with_initial_path(initial_location.href())
            ) as std::rc::Rc<dyn dioxus_history::History>,
            Router::<ConsoleClientRoute> {}
        }
    }
}

#[component]
fn ConsoleRouterLayout() -> Element {
    let bootstrap = use_context::<ConsoleRouterBootstrap>();
    let location: ConsoleClientRoute = use_route();
    let (route, _, _) = location.parts();
    rsx! {
        InteractiveConsole {
            route,
            initial: bootstrap.snapshot,
            client_location: location,
        }
        Outlet::<ConsoleClientRoute> {}
    }
}

macro_rules! empty_route_component {
    ($name:ident { $($field:ident : $ty:ty),* $(,)? }) => {
        #[component]
        fn $name($($field: $ty),*) -> Element {
            let _ = ($($field),*);
            VNode::empty()
        }
    };
}

empty_route_component!(Overview { mesh: Option<String> });
empty_route_component!(Meshes { mesh: Option<String> });
empty_route_component!(Networks { mesh: Option<String> });
empty_route_component!(Authorities { mesh: Option<String> });
empty_route_component!(Peers {
    mesh: Option<String>,
    relay_id: Option<String>,
    resource:Option<String>,
});
empty_route_component!(Relays { mesh: Option<String> });
empty_route_component!(JoinTickets { mesh: Option<String>, resource: Option<String> });
empty_route_component!(Policy { mesh: Option<String>, resource: Option<String>, source: Option<String> });
empty_route_component!(Services { mesh: Option<String>, resource:Option<String> });
empty_route_component!(Audit { mesh: Option<String> });
empty_route_component!(Operations { mesh: Option<String> });
empty_route_component!(Webhooks { mesh: Option<String> });

include!("interactive_navigation.rs");
include!("interactive_events.rs");
include!("ui_interactive.rs");
include!("ui_app.rs");
