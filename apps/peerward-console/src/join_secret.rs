use std::fmt::Write as _;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use peerward_api::JoinTicketCreateResponse;
use qrcodegen::{QrCode, QrCodeEcc};

impl ApiClient {
    /// Builds the Android/CLI deep link locally from a one-time ticket response.
    pub fn join_link(
        &self,
        ticket: &JoinTicketCreateResponse,
    ) -> Result<String, ConsoleApiError> {
        if ticket.token.is_empty()
            || !ticket.token.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || ticket.root_fingerprint.len() != 64
            || !ticket
                .root_fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ConsoleApiError::InvalidResponse);
        }
        let fallback = format!(
                "{}/api/v1/join/{}/claim",
                self.base.trim_end_matches('/'),
                ticket.token,
            );
        let claim_url = ticket.claim_url.as_deref().unwrap_or(&fallback);
        let url = url::Url::parse(claim_url).map_err(|_| ConsoleApiError::InvalidResponse)?;
        let loopback = match url.host() {
            Some(url::Host::Domain("localhost")) => true,
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            _ => false,
        };
        if url.host().is_none() || !(url.scheme() == "https" || url.scheme() == "http" && loopback)
            || !url.username().is_empty() || url.password().is_some()
            || url.query().is_some() || url.fragment().is_some()
            || url.path() != format!("/api/v1/join/{}/claim", ticket.token)
        {
            return Err(ConsoleApiError::InvalidResponse);
        }
        let bundle = serde_json::json!({
            "claim_url": claim_url,
            "root_fingerprint": ticket.root_fingerprint,
            "expires_at": ticket.expires_at_unix,
            "nonce": URL_SAFE_NO_PAD.encode(uuid::Uuid::new_v4().as_bytes()),
            "mesh_id": ticket.mesh_id,
        });
        let encoded = serde_json::to_vec(&bundle)
            .map(|body| URL_SAFE_NO_PAD.encode(body))
            .map_err(|_| ConsoleApiError::InvalidResponse)?;
        Ok(format!("peerward://join?bundle={encoded}"))
    }
}

fn join_qr_svg(link: &str, locale: Locale) -> Option<String> {
    let code = QrCode::encode_text(link, QrCodeEcc::Medium).ok()?;
    let border = 4_i32;
    let size = code.size();
    let dimension = size + border * 2;
    let mut path = String::new();
    for y in 0..size {
        for x in 0..size {
            if code.get_module(x, y) {
                let _ = write!(path, "M{} {}h1v1h-1z", x + border, y + border);
            }
        }
    }
    Some(format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {dimension} {dimension}\" role=\"img\" aria-label=\"{}\" shape-rendering=\"crispEdges\"><rect width=\"100%\" height=\"100%\" fill=\"white\"/><path d=\"{path}\" fill=\"black\"/></svg>",
        console_message(locale, "join-qr"),
    ))
}

/// Ephemeral card that deliberately exists only in browser memory after ticket creation.
#[component]
fn JoinSecretCard(link: String, locale: Locale) -> Element {
    let svg = join_qr_svg(&link, locale).unwrap_or_default();
    let copy_link = link.clone();
    rsx! {
        section { class: "card join-secret", aria_label: console_message(locale, "join-secret"),
            h2 { {console_message(locale, "join-title")} }
            p { {console_message(locale, "join-help")} }
            pre { class: "join-link", "{link}" }
            button {
                r#type: "button",
                onclick: move |_| {
                    #[cfg(target_arch = "wasm32")]
                    {
                        let _ = web_sys::window()
                            .map(|window| window.navigator().clipboard().write_text(&copy_link));
                    }
                    #[cfg(not(target_arch = "wasm32"))]
                    let _ = &copy_link;
                },
                {console_message(locale, "copy-join")}
            }
            div { class: "join-qr", dangerous_inner_html: "{svg}" }
        }
    }
}
