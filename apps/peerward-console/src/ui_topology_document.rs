#[derive(Clone)]
struct TopologyRegionView {
    name: String,
    y: usize,
    height: usize,
    presence_count: u64,
}

#[derive(Clone)]
struct TopologyRelayView {
    id: String,
    name: String,
    x: usize,
    y: usize,
    online: bool,
    presence_count: u64,
}

#[component]
fn TopologyGraph(resources: Vec<ResourceSummary>, mesh_id: String, locale: Locale) -> Element {
    let mut region_counts = BTreeMap::<String, u64>::new();
    for resource in &resources {
        if resource.details.get("kind").and_then(Value::as_str) == Some("region") {
            let name = resource
                .details
                .get("region")
                .and_then(Value::as_str)
                .unwrap_or("default");
            let count = resource
                .details
                .get("presence_count")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            region_counts.insert(name.to_owned(), count);
        }
    }
    let mut relays_by_region = BTreeMap::<String, Vec<&ResourceSummary>>::new();
    for resource in &resources {
        if resource.details.get("kind").and_then(Value::as_str) == Some("relay") {
            let region = resource
                .details
                .get("region")
                .and_then(Value::as_str)
                .unwrap_or("default");
            relays_by_region
                .entry(region.to_owned())
                .or_default()
                .push(resource);
        }
    }
    for region in relays_by_region.keys() {
        region_counts.entry(region.clone()).or_default();
    }

    let mut regions = Vec::new();
    let mut relays = Vec::new();
    let mut positions = BTreeMap::<String, (usize, usize)>::new();
    let mut next_y = 20_usize;
    for (region, presence_count) in region_counts {
        let region_relays = relays_by_region.remove(&region).unwrap_or_default();
        let rows = region_relays.len().max(1).div_ceil(8);
        let height = 70 + rows * 62;
        regions.push(TopologyRegionView {
            name: region,
            y: next_y,
            height,
            presence_count,
        });
        for (index, relay) in region_relays.into_iter().enumerate() {
            let x = 140 + (index % 8) * 105;
            let y = next_y + 72 + (index / 8) * 62;
            positions.insert(relay.id.clone(), (x, y));
            relays.push(TopologyRelayView {
                id: relay.id.clone(),
                name: relay.name.clone(),
                x,
                y,
                online: relay
                    .details
                    .get("online")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                presence_count: relay
                    .details
                    .get("presence_count")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            });
        }
        next_y += height + 20;
    }
    let edges = resources
        .iter()
        .filter(|resource| resource.details.get("kind").and_then(Value::as_str) == Some("backbone"))
        .filter_map(|resource| {
            let source = resource.details.get("source_id")?.as_str()?;
            let target = resource.details.get("target_id")?.as_str()?;
            Some((*positions.get(source)?, *positions.get(target)?))
        })
        .collect::<Vec<_>>();
    let graph_height = next_y.max(180);

    rsx! {
        section { class: "card topology-card",
            h2 { {console_message(locale, "privacy-safe-topology")} }
            if regions.is_empty() {
                div { class: "empty", role: "status", {console_message(locale, "no-resources")} }
            } else {
                div { class: "topology-scroll",
                    svg {
                        class: "topology-graph",
                        view_box: "0 0 1000 {graph_height}",
                        role: "img",
                        title { {console_message(locale, "privacy-safe-topology")} }
                        for ((source_x, source_y), (target_x, target_y)) in edges {
                            line { class: "topology-edge", x1: "{source_x}", y1: "{source_y}", x2: "{target_x}", y2: "{target_y}" }
                        }
                        for region in &regions {
                            rect { class: "topology-region", x: "20", y: "{region.y}", width: "960", height: "{region.height}", rx: "14" }
                            text { class: "topology-region-label", x: "42", y: "{region.y + 32}", "{region.name}" }
                            text { class: "topology-region-badge", x: "940", y: "{region.y + 32}", text_anchor: "end", "{region.presence_count} peers" }
                        }
                        for relay in &relays {
                            a {
                                href: format!("/peers?mesh={mesh_id}&relay_id={}", relay.id),
                                aria_label: format!("{}: {} peers", relay.name, relay.presence_count),
                                g { class: "topology-relay",
                                    title { "{relay.name} · {relay.presence_count} peers" }
                                    circle { class: if relay.online { "topology-relay-node online" } else { "topology-relay-node" }, cx: "{relay.x}", cy: "{relay.y}", r: "18" }
                                    text { x: "{relay.x}", y: "{relay.y + 34}", text_anchor: "middle", "{relay.name}" }
                                    text { class: "topology-relay-count", x: "{relay.x}", y: "{relay.y + 5}", text_anchor: "middle", "{relay.presence_count}" }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(feature = "ssr")]
pub fn render_route(route: ConsoleRoute, snapshot: ConsoleSnapshot) -> String {
    dioxus::ssr::render_element(rsx! { ConsoleRoot { route, snapshot } })
}

#[component]
fn ConsoleRoot(route: ConsoleRoute, snapshot: ConsoleSnapshot) -> Element {
    let locale = use_signal(Locale::default);
    let theme = use_signal(Theme::default);
    rsx! {
        ConsoleApp {
            route,
            snapshot,
            locale,
            theme,
            show_action_panel: false,
            action_panel: rsx! {},
            resource_extras: rsx! {},
            client_routing: false,
        }
    }
}

#[cfg(feature = "ssr")]
pub fn render_document(route: ConsoleRoute, snapshot: ConsoleSnapshot) -> String {
    render_document_with_nonce(route, snapshot, "peerward-static-render")
}

#[cfg(feature = "ssr")]
pub fn render_document_with_nonce(
    route: ConsoleRoute,
    snapshot: ConsoleSnapshot,
    nonce: &str,
) -> String {
    let bootstrap = serde_json::to_string(&snapshot)
        .expect("console snapshots are serializable")
        .replace('<', "\\u003c");
    SSR_BOOTSTRAP.with(|value| *value.borrow_mut() = Some((route, snapshot)));
    let mut virtual_dom = VirtualDom::new(WebConsole);
    let hydration = dioxus_fullstack_core::HydrationContext::default();
    virtual_dom.insert_any_root_context(Box::new(hydration.clone()));
    virtual_dom.rebuild_in_place();
    let mut renderer = dioxus::ssr::Renderer::new();
    renderer.pre_render = true;
    let shell = renderer.render(&virtual_dom);
    SSR_BOOTSTRAP.with(|value| value.borrow_mut().take());
    let hydration = hydration.serialized().data;
    format!(
        "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"theme-color\" content=\"#3157d5\"><title>{} · Peerward Console</title><link rel=\"manifest\" href=\"/manifest.webmanifest\"><link rel=\"stylesheet\" href=\"{}\"></head><body><div id=\"main\">{}</div><script nonce=\"{}\" id=\"peerward-bootstrap\" type=\"application/json\">{}</script><script nonce=\"{}\">window.initial_dioxus_hydration_data='{}';window.initial_dioxus_hydration_debug_types=[];window.initial_dioxus_hydration_debug_locations=[];window.hydrate_queue=[];</script><script nonce=\"{}\" type=\"module\">import '/console-interactions.js';import init from '/assets/peerward-console-web.js?v={}';await init({{module_or_path:'/assets/peerward-console-web_bg.wasm?v={}'}});if('serviceWorker' in navigator){{await navigator.serviceWorker.register('/service-worker.js');}}</script></body></html>",
        route.label(),
        HASHED_STYLESHEET_PATH,
        shell,
        nonce,
        bootstrap,
        nonce,
        hydration,
        nonce,
        CLIENT_ASSET_VERSION,
        CLIENT_ASSET_VERSION,
    )
}

#[cfg(feature = "ssr")]
pub fn stylesheet() -> &'static str {
    STYLE
}

#[cfg(feature = "ssr")]
pub fn stylesheet_path() -> &'static str {
    HASHED_STYLESHEET_PATH
}
