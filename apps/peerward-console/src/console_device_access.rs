#[component]
fn ConsoleDeviceAccessSummary(mesh: String, peer: peerward_types::PeerId, locale: Locale, can_write: bool) -> Element {
    let mut cursor = use_signal(String::new);
    let mut shares = use_console_query::<Page<peerward_api::ConsoleSharingResource>>(format!(
        "/api/v1/meshes/{mesh}/console/sharing?limit=20&cursor={}", cursor()
    ));
    let page = shares.read().as_ref().and_then(|result| result.as_ref().ok()).cloned();
    let targets = page.as_ref().map(|page| page.items.iter().map(|share| {
        if share.kind == "service" {
            peerward_api::ConsoleMatrixTarget::Service { id: share.id, address: None, protocol: None }
        } else {
            peerward_api::ConsoleMatrixTarget::Network { id: share.id, address: None, provider: None, protocol: None, port: None }
        }
    }).collect::<Vec<_>>()).unwrap_or_default();
    let mut matrix = use_console_post::<peerward_api::ConsoleMatrix>(
        if page.is_some() { format!("/api/v1/meshes/{mesh}/console/matrix") } else { String::new() },
        json!(peerward_api::ConsoleMatrixQuery { source: peerward_api::ConsoleGrantSource::Peer { id: peer }, targets }),
    );
    let results = matrix.read().as_ref().and_then(|result| result.as_ref().ok()).cloned();
    let error = shares.read().as_ref().and_then(|result| result.as_ref().err()).cloned()
        .or_else(|| matrix.read().as_ref().and_then(|result| result.as_ref().err()).cloned())
        .unwrap_or_default();
    rsx! {
        section { class: "device-access-summary",
            div { class: "device-section-head",
                div {
                    h3 { {console_text(locale, "可以访问", "Accessible shares")} }
                    p { {console_text(locale, "按当前访问规则检查这台设备；具体服务还需在线可达。", "Evaluated using current access rules; the service must also be reachable.")} }
                }
                a { class: "text-link", href: format!("/policy?mesh={mesh}&source=peer%3A{peer}"),
                    {if can_write { console_text(locale, "调整访问", "Adjust access") } else { console_text(locale, "查看访问", "View access") }}
                }
            }
            if !error.is_empty() {
                p { role: "alert", "{error}" }
                button { class: "secondary-button", onclick: move |_| { shares.restart(); matrix.restart(); }, {console_text(locale, "重试", "Retry")} }
            } else if let (Some(page), Some(results)) = (&page, &results) {
                if shares.state()() == UseResourceState::Pending || matrix.state()() == UseResourceState::Pending {
                    p { role: "status", {console_text(locale, "正在检查访问…", "Checking access…")} }
                } else if page.items.is_empty() {
                    p { class: "device-empty-mini", {console_text(locale, "这个网络还没有共享", "This network has no shares yet")} }
                } else {
                    for share in &page.items {
                        a { class: "device-resource-chip", href: format!("/policy?mesh={mesh}&source=peer%3A{peer}&resource={}", share.id),
                            span { "{share.name}" }
                            b { {matrix_outcome(locale, results.cells.iter().find(|cell| cell.id == share.id).map_or("unknown", |cell| cell.outcome.as_str()))} }
                        }
                    }
                }
                div { class: "device-access-pagination",
                    if !cursor().is_empty() {
                        button { class: "secondary-button", onclick: move |_| cursor.set(String::new()), {console_text(locale, "第一页", "First page")} }
                    }
                    if let Some(next) = page.next_cursor.clone() {
                        button { class: "secondary-button", onclick: move |_| cursor.set(next.clone()), {console_message(locale, "next-page")} }
                    }
                }
            } else {
                p { role: "status", {console_text(locale, "正在检查访问…", "Checking access…")} }
            }
        }
    }
}
