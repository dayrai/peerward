//! Shared Dioxus design tokens, localization, error state, and accessible primitives.

use std::collections::BTreeMap;

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

mod diagnostics;
pub use diagnostics::{diagnostic_label, diagnostic_next_step};
pub use peerward_types::{DiagnosticCode, RetryHint, RuntimeDiagnostic};

/// Formally maintained interface languages.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Locale {
    /// Simplified Chinese.
    ZhCn,
    /// United States English.
    #[default]
    EnUs,
}

impl Locale {
    /// Stable BCP 47 language tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::ZhCn => "zh-CN",
            Self::EnUs => "en-US",
        }
    }

    /// Resolves one message from the checked-in Fluent-style catalogs.
    pub const fn message(self, key: Message) -> &'static str {
        match (self, key) {
            (Self::ZhCn, Message::SkipToContent) => "跳到主要内容",
            (Self::ZhCn, Message::Language) => "语言",
            (Self::ZhCn, Message::Theme) => "主题",
            (Self::ZhCn, Message::SystemTheme) => "跟随系统",
            (Self::ZhCn, Message::LightTheme) => "亮色",
            (Self::ZhCn, Message::DarkTheme) => "暗色",
            (Self::ZhCn, Message::Loading) => "正在加载…",
            (Self::ZhCn, Message::Empty) => "暂无可显示的数据。",
            (Self::ZhCn, Message::Retry) => "重试",
            (Self::ZhCn, Message::Online) => "正常",
            (Self::ZhCn, Message::Offline) => "不可用",
            (Self::ZhCn, Message::PrimaryNavigation) => "主要导航",
            (Self::ZhCn, Message::Home) => "首页",
            (Self::ZhCn, Message::Profile) => "身份配置",
            (Self::ZhCn, Message::Diagnostics) => "诊断",
            (Self::ZhCn, Message::Settings) => "设置",
            (Self::ZhCn, Message::Disconnected) => "未连接",
            (Self::ZhCn, Message::Connected) => "已连接",
            (Self::ZhCn, Message::VpnStatus) => "VPN 状态",
            (Self::ZhCn, Message::PrivateMesh) => "私有网格",
            (Self::ZhCn, Message::VpnConnection) => "VPN 连接",
            (Self::ZhCn, Message::E2ePathDescription) => {
                "端到端加密的直连和 Relay 路径共用同一个 Peer 会话。"
            }
            (Self::ZhCn, Message::Connect) => "连接",
            (Self::ZhCn, Message::Disconnect) => "断开连接",
            (Self::ZhCn, Message::JoinMesh) => "加入网格",
            (Self::ZhCn, Message::Invitation) => "Peerward 邀请链接",
            (Self::ZhCn, Message::VerifyInvitation) => "验证并加入",
            (Self::ZhCn, Message::JoinHelp) => "申请前将验证根指纹、有效期和 Wire v5 支持。",
            (Self::ZhCn, Message::NoActiveProfile) => "没有活动身份配置",
            (Self::ZhCn, Message::ProfileHelp) => "加入网格以创建不可导出的设备身份。",
            (Self::ZhCn, Message::ActiveProfile) => "活动身份配置",
            (Self::ZhCn, Message::MeshName) => "网格",
            (Self::ZhCn, Message::AssignedAddress) => "分配地址",
            (Self::ZhCn, Message::PeerIdentity) => "Peer 身份",
            (Self::ZhCn, Message::CredentialRotation) => "凭据轮换",
            (Self::ZhCn, Message::PendingRotation) => "轮换正在等待目录确认。",
            (Self::ZhCn, Message::NoPendingRotation) => "当前没有待处理的轮换。",
            (Self::ZhCn, Message::RotationHelp) => {
                "pending、activated、目录发布和本地提交阶段均可从崩溃中恢复。"
            }
            (Self::ZhCn, Message::RustRuntime) => "Rust 运行时",
            (Self::ZhCn, Message::WireProtocol) => "Wire 协议",
            (Self::ZhCn, Message::RelaySession) => "Relay 会话",
            (Self::ZhCn, Message::DirectPath) => "直连路径",
            (Self::ZhCn, Message::SignedState) => "签名状态",
            (Self::ZhCn, Message::Waiting) => "等待中",
            (Self::ZhCn, Message::ExportDiagnostics) => "导出脱敏诊断信息",
            (Self::ZhCn, Message::Security) => "安全",
            (Self::ZhCn, Message::KeySecurityHelp) => {
                "私钥由 Rust 生成，并使用 Android Keystore 中不可导出的密钥加密。"
            }
            (Self::ZhCn, Message::RemoveLocalProfile) => "移除本地身份配置",
            (Self::ZhCn, Message::LegacyTitle) => "旧版身份配置不兼容",
            (Self::ZhCn, Message::LegacyBody) => {
                "当前 Peerward 客户端无法使用旧格式的身份配置、数据库或协议状态；尚未删除任何内容。"
            }
            (Self::ZhCn, Message::ClearLegacy) => "我已了解——清除旧身份配置",
            (Self::ZhCn, Message::EnrollmentFailed) => "加入失败。请检查邀请和网络后重试。",
            (Self::EnUs, Message::SkipToContent) => "Skip to main content",
            (Self::EnUs, Message::Language) => "Language",
            (Self::EnUs, Message::Theme) => "Theme",
            (Self::EnUs, Message::SystemTheme) => "System",
            (Self::EnUs, Message::LightTheme) => "Light",
            (Self::EnUs, Message::DarkTheme) => "Dark",
            (Self::EnUs, Message::Loading) => "Loading…",
            (Self::EnUs, Message::Empty) => "There is no data to display.",
            (Self::EnUs, Message::Retry) => "Retry",
            (Self::EnUs, Message::Online) => "Ready",
            (Self::EnUs, Message::Offline) => "Unavailable",
            (Self::EnUs, Message::PrimaryNavigation) => "Primary navigation",
            (Self::EnUs, Message::Home) => "Home",
            (Self::EnUs, Message::Profile) => "Profile",
            (Self::EnUs, Message::Diagnostics) => "Diagnostics",
            (Self::EnUs, Message::Settings) => "Settings",
            (Self::EnUs, Message::Disconnected) => "Disconnected",
            (Self::EnUs, Message::Connected) => "Connected",
            (Self::EnUs, Message::VpnStatus) => "VPN status",
            (Self::EnUs, Message::PrivateMesh) => "PRIVATE MESH",
            (Self::EnUs, Message::VpnConnection) => "VPN connection",
            (Self::EnUs, Message::E2ePathDescription) => {
                "End-to-end encrypted direct and Relay paths use the same Peer session."
            }
            (Self::EnUs, Message::Connect) => "Connect",
            (Self::EnUs, Message::Disconnect) => "Disconnect",
            (Self::EnUs, Message::JoinMesh) => "Join a mesh",
            (Self::EnUs, Message::Invitation) => "Peerward invitation",
            (Self::EnUs, Message::VerifyInvitation) => "Verify and join",
            (Self::EnUs, Message::JoinHelp) => {
                "Root fingerprint, expiry, and Wire v5 support are checked before claiming."
            }
            (Self::EnUs, Message::NoActiveProfile) => "No active profile",
            (Self::EnUs, Message::ProfileHelp) => {
                "Join a mesh to create a non-exportable device identity."
            }
            (Self::EnUs, Message::ActiveProfile) => "Active profile",
            (Self::EnUs, Message::MeshName) => "Mesh",
            (Self::EnUs, Message::AssignedAddress) => "Assigned address",
            (Self::EnUs, Message::PeerIdentity) => "Peer identity",
            (Self::EnUs, Message::CredentialRotation) => "Credential rotation",
            (Self::EnUs, Message::PendingRotation) => {
                "Rotation is waiting for signed-directory confirmation."
            }
            (Self::EnUs, Message::NoPendingRotation) => "No pending rotation.",
            (Self::EnUs, Message::RotationHelp) => {
                "Pending, activated, directory-published, and local-commit stages are crash recoverable."
            }
            (Self::EnUs, Message::RustRuntime) => "Rust runtime",
            (Self::EnUs, Message::WireProtocol) => "Wire protocol",
            (Self::EnUs, Message::RelaySession) => "Relay session",
            (Self::EnUs, Message::DirectPath) => "Direct path",
            (Self::EnUs, Message::SignedState) => "Signed state",
            (Self::EnUs, Message::Waiting) => "Waiting",
            (Self::EnUs, Message::ExportDiagnostics) => "Export redacted diagnostics",
            (Self::EnUs, Message::Security) => "Security",
            (Self::EnUs, Message::KeySecurityHelp) => {
                "Private keys are generated in Rust and encrypted with an Android Keystore non-exportable key."
            }
            (Self::EnUs, Message::RemoveLocalProfile) => "Remove local profile",
            (Self::EnUs, Message::LegacyTitle) => "Older profile is incompatible",
            (Self::EnUs, Message::LegacyBody) => {
                "This Peerward client cannot use the legacy profile, database, or protocol state. Nothing has been deleted."
            }
            (Self::EnUs, Message::ClearLegacy) => "I understand — clear old profile",
            (Self::EnUs, Message::EnrollmentFailed) => {
                "Join failed. Check the invitation and network, then retry."
            }
        }
    }

    /// Original Fluent-style catalog, exposed for completeness tests and tooling.
    pub const fn catalog(self) -> &'static str {
        match self {
            Self::ZhCn => include_str!("../i18n/zh-CN.ftl"),
            Self::EnUs => include_str!("../i18n/en-US.ftl"),
        }
    }
}

/// Shared message identifiers used by reusable components.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Message {
    SkipToContent,
    Language,
    Theme,
    SystemTheme,
    LightTheme,
    DarkTheme,
    Loading,
    Empty,
    Retry,
    Online,
    Offline,
    PrimaryNavigation,
    Home,
    Profile,
    Diagnostics,
    Settings,
    Disconnected,
    Connected,
    VpnStatus,
    PrivateMesh,
    VpnConnection,
    E2ePathDescription,
    Connect,
    Disconnect,
    JoinMesh,
    Invitation,
    VerifyInvitation,
    JoinHelp,
    NoActiveProfile,
    ProfileHelp,
    ActiveProfile,
    MeshName,
    AssignedAddress,
    PeerIdentity,
    CredentialRotation,
    PendingRotation,
    NoPendingRotation,
    RotationHelp,
    RustRuntime,
    WireProtocol,
    RelaySession,
    DirectPath,
    SignedState,
    Waiting,
    ExportDiagnostics,
    Security,
    KeySecurityHelp,
    RemoveLocalProfile,
    LegacyTitle,
    LegacyBody,
    ClearLegacy,
    EnrollmentFailed,
}

/// Explicit theme override. System mode follows `prefers-color-scheme`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Theme {
    #[default]
    System,
    Light,
    Dark,
}

impl Theme {
    pub const fn attribute(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Light => "light",
            Self::Dark => "dark",
        }
    }
}

/// Stable UI error model shared by web and Android.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiError {
    pub code: String,
    pub message: String,
    pub request_id: Option<String>,
    #[serde(default)]
    pub field_errors: BTreeMap<String, String>,
    pub retryable: bool,
}

/// WCAG-compliant language and theme controls.
#[component]
pub fn PreferenceControls(mut locale: Signal<Locale>, mut theme: Signal<Theme>) -> Element {
    let language_label = locale().message(Message::Language);
    let theme_label = locale().message(Message::Theme);
    rsx! {
        div { class: "pw-preferences", role: "group", aria_label: "{language_label}; {theme_label}",
            label { r#for: "pw-language", class: "pw-sr-only", "{language_label}" }
            select {
                id: "pw-language",
                aria_label: "{language_label}",
                value: "{locale().tag()}",
                onchange: move |event| locale.set(if event.value() == "zh-CN" { Locale::ZhCn } else { Locale::EnUs }),
                option { value: "zh-CN", selected: locale() == Locale::ZhCn, "简体中文" }
                option { value: "en-US", selected: locale() == Locale::EnUs, "English" }
            }
            label { r#for: "pw-theme", class: "pw-sr-only", "{theme_label}" }
            select {
                id: "pw-theme",
                aria_label: "{theme_label}",
                value: "{theme().attribute()}",
                onchange: move |event| theme.set(match event.value().as_str() {
                    "light" => Theme::Light,
                    "dark" => Theme::Dark,
                    _ => Theme::System,
                }),
                option { value: "system", selected: theme() == Theme::System, "{locale().message(Message::SystemTheme)}" }
                option { value: "light", selected: theme() == Theme::Light, "{locale().message(Message::LightTheme)}" }
                option { value: "dark", selected: theme() == Theme::Dark, "{locale().message(Message::DarkTheme)}" }
            }
        }
    }
}

/// Accessible error summary with per-field details.
#[component]
pub fn ErrorNotice(error: UiError) -> Element {
    rsx! {
        section { class: "pw-error", role: "alert", aria_live: "polite",
            strong { "{error.code}" }
            p { "{error.message}" }
            if let Some(request_id) = error.request_id { small { "Request {request_id}" } }
            if !error.field_errors.is_empty() {
                ul { for (field, message) in error.field_errors { li { strong { "{field}: " } "{message}" } } }
            }
        }
    }
}

/// Shared adaptive design tokens and accessibility utilities.
pub const DESIGN_CSS: &str = include_str!("../assets/tokens.css");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maintained_catalogs_cover_shared_messages() {
        for locale in [Locale::ZhCn, Locale::EnUs] {
            let catalog = locale.catalog();
            for key in [
                "skip-to-content",
                "language",
                "theme",
                "loading",
                "empty",
                "primary-navigation",
                "home",
                "profile",
                "diagnostics",
                "settings",
                "disconnected",
                "connected",
                "vpn-status",
                "private-mesh",
                "vpn-connection",
                "e2e-path-description",
                "connect",
                "disconnect",
                "join-mesh",
                "invitation",
                "verify-invitation",
                "join-help",
                "no-active-profile",
                "profile-help",
                "active-profile",
                "mesh-name",
                "assigned-address",
                "peer-identity",
                "credential-rotation",
                "pending-rotation",
                "no-pending-rotation",
                "rotation-help",
                "rust-runtime",
                "wire-protocol",
                "relay-session",
                "direct-path",
                "signed-state",
                "waiting",
                "export-diagnostics",
                "security",
                "key-security-help",
                "remove-local-profile",
                "legacy-title",
                "legacy-body",
                "clear-legacy",
                "enrollment-failed",
            ] {
                assert!(catalog.lines().any(|line| line.starts_with(key)));
            }
        }
    }
}
