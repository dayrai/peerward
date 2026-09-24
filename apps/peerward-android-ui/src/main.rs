use std::cell::Cell;

use dioxus::prelude::*;
use peerward_ui::{DESIGN_CSS, Locale, Message, PreferenceControls, Theme};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const CONTRACT_VERSION: u32 = 1;

fn main() {
    dioxus_web::launch::launch_cfg(App, dioxus_web::Config::new());
}

#[derive(Debug, Clone, Routable, PartialEq)]
enum Route {
    #[layout(MobileShell)]
    #[route("/")]
    Home {},
    #[route("/profile")]
    Profile {},
    #[route("/rotation")]
    Rotation {},
    #[route("/diagnostics")]
    Diagnostics {},
    #[route("/settings")]
    Settings {},
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ConnectionPhase {
    #[default]
    Stopped,
    PermissionRequired,
    Starting,
    Connecting,
    Healthy,
    Degraded,
    Reconnecting,
    Stopping,
    Failed,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
struct ProfileSummary {
    mesh_name: String,
    address: String,
    peer_id: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
struct TaskStatus {
    rust_runtime: bool,
    tun_open: bool,
    packet_pump_running: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
struct RelayStatus {
    primary_authenticated: bool,
    standby_count: usize,
    carrier: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
struct SignedStateStatus {
    revision: u64,
    complete: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
struct RotationStatus {
    state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RuntimeError {
    code: String,
    retryable: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
struct MobileRuntimeSnapshot {
    #[serde(skip)]
    sequence: u64,
    profile: Option<ProfileSummary>,
    connection: ConnectionPhase,
    tasks: TaskStatus,
    relays: RelayStatus,
    direct_peer_count: usize,
    signed_state: SignedStateStatus,
    rotation: RotationStatus,
    last_error: Option<RuntimeError>,
    legacy_profile_present: bool,
    #[serde(default)]
    vpn_protection: VpnProtectionStatus,
    #[serde(default)]
    client_preferences: Option<MobilePreferenceView>,
    #[serde(default)]
    observed_at: Option<u64>,
    #[serde(default)]
    diagnostics: Vec<peerward_ui::RuntimeDiagnostic>,
}

#[derive(Debug, Deserialize)]
struct BridgeEnvelope {
    version: u32,
    #[serde(default)]
    sequence: u64,
    kind: String,
    #[serde(default)]
    payload: Value,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct InvitationPreview {
    control_origin: String,
    mesh_summary: String,
    ticket_summary: String,
}

#[derive(Serialize)]
struct NativeCommand<'a> {
    version: u32,
    request_id: String,
    kind: &'a str,
    payload: Value,
}

#[allow(non_snake_case)]
fn App() -> Element {
    use_context_provider(|| Signal::new(system_locale()));
    use_context_provider(|| Signal::new(Theme::default()));
    let snapshot = use_context_provider(|| Signal::new(MobileRuntimeSnapshot::default()));
    let invitation = use_context_provider(|| Signal::new(String::new()));
    let invitation_preview = use_context_provider(|| Signal::new(None::<InvitationPreview>));
    let enrollment = use_context_provider(|| Signal::new(EnrollmentDisplay::default()));
    let profiles = use_context_provider(|| Signal::new(Vec::<SavedProfile>::new()));
    let command_error = use_context_provider(|| Signal::new(None::<String>));
    use_effect(move || {
        install_native_bridge(
            snapshot,
            invitation,
            invitation_preview,
            command_error,
            enrollment,
            profiles,
        );
    });
    rsx! { Router::<Route> {} }
}

#[component]
fn MobileShell() -> Element {
    let locale = consume_context::<Signal<Locale>>();
    let theme = consume_context::<Signal<Theme>>();
    use_effect(move || set_document_preferences(locale(), theme()));
    rsx! {
        style { "{DESIGN_CSS}{MOBILE_CSS}" }
        div { class: "mobile-app", "data-theme": "{theme().attribute()}",
            a { class: "pw-skip", href: "#mobile-content", "{locale().message(Message::SkipToContent)}" }
            header { class: "mobile-header",
                div { class: "mobile-brand", "Peerward" }
                PreferenceControls { locale, theme }
            }
            main { id: "mobile-content", tabindex: "-1", Outlet::<Route> {} }
            nav { class: "mobile-tabs", aria_label: "{locale().message(Message::PrimaryNavigation)}",
                Link { to: Route::Home {}, "{locale().message(Message::Home)}" }
                Link { to: Route::Profile {}, "{locale().message(Message::Profile)}" }
                Link { to: Route::Diagnostics {}, "{locale().message(Message::Diagnostics)}" }
                Link { to: Route::Settings {}, "{locale().message(Message::Settings)}" }
            }
        }
    }
}

#[cfg(feature = "web")]
fn set_document_preferences(locale: Locale, theme: Theme) {
    if let Some(root) = web_sys::window()
        .and_then(|window| window.document())
        .and_then(|document| document.document_element())
    {
        let _ = root.set_attribute("lang", locale.tag());
        let _ = root.set_attribute("data-theme", theme.attribute());
    }
}

#[cfg(not(feature = "web"))]
fn set_document_preferences(_locale: Locale, _theme: Theme) {}

#[component]
fn Home() -> Element {
    let snapshot = consume_context::<Signal<MobileRuntimeSnapshot>>();
    let mut invitation = consume_context::<Signal<String>>();
    let mut invitation_preview = consume_context::<Signal<Option<InvitationPreview>>>();
    let command_error = consume_context::<Signal<Option<String>>>();
    let locale = consume_context::<Signal<Locale>>();
    let phase = snapshot().connection;
    let status = phase_label(locale(), phase);
    let pending = matches!(
        phase,
        ConnectionPhase::PermissionRequired
            | ConnectionPhase::Starting
            | ConnectionPhase::Connecting
            | ConnectionPhase::Reconnecting
            | ConnectionPhase::Stopping
    );
    let active = matches!(
        phase,
        ConnectionPhase::Starting
            | ConnectionPhase::Connecting
            | ConnectionPhase::Healthy
            | ConnectionPhase::Degraded
            | ConnectionPhase::Reconnecting
            | ConnectionPhase::Stopping
    );
    rsx! {
        section { class: "mobile-stack", aria_label: "{locale().message(Message::VpnStatus)}",
            if snapshot().legacy_profile_present {
                LegacyWarning {}
            }
            if let Some(error) = snapshot().last_error.as_ref().map(|item| item.code.clone()).or(command_error()) {
                p { class: "pw-error", role: "alert", {enrollment_error(locale(),&error).unwrap_or(&error)} }
            }
            MobileDiagnostics { observations: snapshot().diagnostics, locale: locale() }
            p { class: "mobile-eyebrow", "{locale().message(Message::PrivateMesh)}" }
            h1 { "{locale().message(Message::VpnConnection)}" }
            article { class: "mobile-hero",
                div { class: "mobile-orb", "data-state": "{phase_wire_name(phase)}", aria_hidden: "true" }
                strong { class: "mobile-status", "{status}" }
                p { "{locale().message(Message::E2ePathDescription)}" }
                div { class: "mobile-actions",
                    if active {
                        button {
                            id: "connection-toggle",
                            class: "secondary",
                            disabled: phase == ConnectionPhase::Stopping || snapshot().vpn_protection.always_on == Some(true),
                            onclick: move |_| { send_command("disconnect", json!({})); },
                            "{locale().message(Message::Disconnect)}"
                        }
                    } else {
                        button {
                            id: "connection-toggle",
                            disabled: pending || snapshot().profile.is_none(),
                            onclick: move |_| { send_command("connect", json!({})); },
                            "{locale().message(Message::Connect)}"
                        }
                    }
                }
            }
            article { class: "mobile-card",
                h2 { "{locale().message(Message::JoinMesh)}" }
                label { r#for: "join-link", "{locale().message(Message::Invitation)}" }
                input {
                    id: "join-link",
                    r#type: "url",
                    placeholder: "peerward://join?bundle=…",
                    autocomplete: "off",
                    value: "{invitation}",
                    oninput: move |event| {
                        invitation.set(event.value());
                        invitation_preview.set(None);
                    },
                }
                button {
                    id: "join-scan",
                    class: "secondary",
                    onclick: move |_| { send_command("scan_join_qr", json!({})); },
                    if locale() == Locale::ZhCn { "扫描 Join 二维码" } else { "Scan Join QR" }
                }
                if let Some(preview) = invitation_preview() {
                    dl { class: "diagnostic-list invitation-preview",
                        div { dt { if locale() == Locale::ZhCn { "Control 来源" } else { "Control origin" } } dd { "{preview.control_origin}" } }
                        div { dt { if locale() == Locale::ZhCn { "Mesh" } else { "Mesh" } } dd { "{preview.mesh_summary}" } }
                        div { dt { if locale() == Locale::ZhCn { "Ticket 摘要" } else { "Ticket summary" } } dd { "{preview.ticket_summary}" } }
                    }
                    p { class: "mobile-help", role: "status",
                        if locale() == Locale::ZhCn { "请核对以上信息；扫描不会自动加入，点击下方按钮后才会提交。" } else { "Review these details. Scanning never joins automatically; submit explicitly below." }
                    }
                }
                button {
                    id: "join-submit",
                    class: "secondary",
                    disabled: !invitation().starts_with("peerward://join?"),
                    onclick: move |_| {
                        send_command("join", json!({"invitation": invitation()}));
                    },
                    "{locale().message(Message::VerifyInvitation)}"
                }
                EnrollmentStatus {}
                p { class: "mobile-help", "{locale().message(Message::JoinHelp)}" }
            }
        }
    }
}

#[component]
fn Profile() -> Element {
    let locale = consume_context::<Signal<Locale>>();
    let snapshot = consume_context::<Signal<MobileRuntimeSnapshot>>();
    let profile = snapshot().profile.clone();
    rsx! {
        section { class: "mobile-stack",
            h1 { "{locale().message(Message::Profile)}" }
            article { class: "mobile-card",
                if let Some(profile) = profile {
                    h2 { "{locale().message(Message::ActiveProfile)}" }
                    dl { class: "diagnostic-list",
                        div { dt { "{locale().message(Message::MeshName)}" } dd { "{profile.mesh_name}" } }
                        div { dt { "{locale().message(Message::AssignedAddress)}" } dd { "{profile.address}" } }
                        div { dt { "{locale().message(Message::PeerIdentity)}" } dd { "{profile.peer_id}" } }
                    }
                } else {
                    h2 { "{locale().message(Message::NoActiveProfile)}" }
                    p { "{locale().message(Message::ProfileHelp)}" }
                }
            }
            Link { class: "button-link secondary", to: Route::Rotation {}, "{locale().message(Message::CredentialRotation)}" }
        }
    }
}

#[component]
fn Rotation() -> Element {
    let locale = consume_context::<Signal<Locale>>();
    let snapshot = consume_context::<Signal<MobileRuntimeSnapshot>>();
    let pending = snapshot().rotation.state == "pending";
    rsx! { section { class: "mobile-stack", h1 { "{locale().message(Message::CredentialRotation)}" } p { if pending { "{locale().message(Message::PendingRotation)}" } else { "{locale().message(Message::NoPendingRotation)}" } } p { class: "mobile-help", "{locale().message(Message::RotationHelp)}" } } }
}

#[component]
fn Diagnostics() -> Element {
    let locale = consume_context::<Signal<Locale>>();
    let snapshot = consume_context::<Signal<MobileRuntimeSnapshot>>();
    let state = snapshot();
    let rows = [
        (
            locale().message(Message::RustRuntime),
            locale()
                .message(if state.tasks.rust_runtime {
                    Message::Online
                } else {
                    Message::Offline
                })
                .to_owned(),
        ),
        (
            locale().message(Message::WireProtocol),
            "Wire 5 · WireGuard".to_owned(),
        ),
        (
            locale().message(Message::RelaySession),
            format!(
                "{}{}",
                locale()
                    .message(if state.relays.primary_authenticated {
                        Message::Connected
                    } else {
                        Message::Disconnected
                    })
                    .to_owned(),
                if state.relays.primary_authenticated {
                    match state.relays.carrier.as_deref() {
                        Some("quic") => " · QUIC",
                        Some("wss") => " · WSS",
                        Some("tcp") => " · TCP",
                        _ => "",
                    }
                } else {
                    ""
                }
            ),
        ),
        (
            locale().message(Message::DirectPath),
            if state.direct_peer_count == 0 {
                locale().message(Message::Offline).to_owned()
            } else {
                state.direct_peer_count.to_string()
            },
        ),
        (
            locale().message(Message::SignedState),
            if state.signed_state.complete {
                format!(
                    "{} · r{}",
                    locale().message(Message::Online),
                    state.signed_state.revision
                )
            } else {
                locale().message(Message::Waiting).to_owned()
            },
        ),
    ];
    rsx! {
        section { class: "mobile-stack",
            h1 { "{locale().message(Message::Diagnostics)}" }
            MobileDiagnostics { observations: state.diagnostics, locale: locale() }
            p { class: "mobile-help",
                {if locale() == Locale::ZhCn { "最近观测：" } else { "Last observed: " }}
                {diagnostic_time(state.observed_at, locale())}
            }
            dl { class: "mobile-card diagnostic-list",
                for (name, value) in rows { div { dt { "{name}" } dd { "{value}" } } }
            }
            button {
                class: "secondary",
                onclick: move |_| { send_command("export_diagnostics", json!({})); },
                "{locale().message(Message::ExportDiagnostics)}"
            }
        }
    }
}

#[component]
fn Settings() -> Element {
    let locale = consume_context::<Signal<Locale>>();
    let snapshot = consume_context::<Signal<MobileRuntimeSnapshot>>();
    let mut confirming = use_signal(|| false);
    rsx! {
        section { class: "mobile-stack",
            h1 { "{locale().message(Message::Settings)}" }
            SavedProfileSettings {}
            ClientPreferenceSettings {}
            VpnProtectionSettings {}
            article { class: "mobile-card",
                h2 { "{locale().message(Message::Security)}" }
                p { "{locale().message(Message::KeySecurityHelp)}" }
                if confirming() {
                    p { role: "alert",
                        if locale() == Locale::ZhCn {
                            "此操作会先停止 VPN，再删除配置以及当前、上一组和待启用的全部密钥。"
                        } else {
                            "This stops the VPN before removing the profile and every current, previous, or pending key."
                        }
                    }
                    button {
                        class: "danger",
                        disabled: snapshot().connection == ConnectionPhase::Stopping,
                        onclick: move |_| { send_command("remove_profile", json!({})); },
                        "{locale().message(Message::RemoveLocalProfile)}"
                    }
                    button { class: "secondary", onclick: move |_| confirming.set(false),
                        if locale() == Locale::ZhCn { "取消" } else { "Cancel" }
                    }
                } else {
                    button { class: "danger", onclick: move |_| confirming.set(true), "{locale().message(Message::RemoveLocalProfile)}" }
                }
            }
        }
    }
}

#[component]
fn LegacyWarning() -> Element {
    let locale = consume_context::<Signal<Locale>>();
    rsx! {
        article { class: "mobile-card", role: "alert",
            h2 { "{locale().message(Message::LegacyTitle)}" }
            p { "{locale().message(Message::LegacyBody)}" }
            button {
                class: "danger",
                onclick: move |_| { send_command("clear_legacy", json!({})); },
                "{locale().message(Message::ClearLegacy)}"
            }
        }
    }
}

include!("native_bridge.rs");

#[cfg(feature = "web")]
fn system_locale() -> Locale {
    web_sys::window()
        .and_then(|window| window.navigator().language())
        .filter(|language| language.to_ascii_lowercase().starts_with("zh"))
        .map_or(Locale::EnUs, |_| Locale::ZhCn)
}

#[cfg(not(feature = "web"))]
fn system_locale() -> Locale {
    Locale::default()
}

include!("mobile_presentation.rs");
include!("mobile_protection.rs");
#[cfg(test)]
mod tests;

include!("mobile_enrollment.rs");

include!("mobile_preferences.rs");

include!("mobile_profiles.rs");
include!("mobile_diagnostics.rs");
