const fn phase_wire_name(phase: ConnectionPhase) -> &'static str {
    match phase {
        ConnectionPhase::Stopped => "stopped",
        ConnectionPhase::PermissionRequired => "permission_required",
        ConnectionPhase::Starting => "starting",
        ConnectionPhase::Connecting => "connecting",
        ConnectionPhase::Healthy => "healthy",
        ConnectionPhase::Degraded => "degraded",
        ConnectionPhase::Reconnecting => "reconnecting",
        ConnectionPhase::Stopping => "stopping",
        ConnectionPhase::Failed => "failed",
    }
}

const fn phase_label(locale: Locale, phase: ConnectionPhase) -> &'static str {
    match (locale, phase) {
        (Locale::ZhCn, ConnectionPhase::Stopped) => "未连接",
        (Locale::ZhCn, ConnectionPhase::PermissionRequired) => "等待 VPN 权限",
        (Locale::ZhCn, ConnectionPhase::Starting) => "正在启动",
        (Locale::ZhCn, ConnectionPhase::Connecting) => "正在认证 Relay",
        (Locale::ZhCn, ConnectionPhase::Healthy) => "已连接",
        (Locale::ZhCn, ConnectionPhase::Degraded) => "连接已降级",
        (Locale::ZhCn, ConnectionPhase::Reconnecting) => "正在重连",
        (Locale::ZhCn, ConnectionPhase::Stopping) => "正在停止",
        (Locale::ZhCn, ConnectionPhase::Failed) => "连接失败",
        (Locale::EnUs, ConnectionPhase::Stopped) => "Disconnected",
        (Locale::EnUs, ConnectionPhase::PermissionRequired) => "VPN permission required",
        (Locale::EnUs, ConnectionPhase::Starting) => "Starting",
        (Locale::EnUs, ConnectionPhase::Connecting) => "Authenticating Relay",
        (Locale::EnUs, ConnectionPhase::Healthy) => "Connected",
        (Locale::EnUs, ConnectionPhase::Degraded) => "Degraded",
        (Locale::EnUs, ConnectionPhase::Reconnecting) => "Reconnecting",
        (Locale::EnUs, ConnectionPhase::Stopping) => "Stopping",
        (Locale::EnUs, ConnectionPhase::Failed) => "Connection failed",
    }
}

const MOBILE_CSS: &str = r#"
.mobile-app { min-height: 100vh; max-width: 52rem; margin: 0 auto; padding: env(safe-area-inset-top) 1rem calc(5.75rem + env(safe-area-inset-bottom)); background: var(--pw-bg); color: var(--pw-text); }
.mobile-header { display: flex; justify-content: space-between; align-items: center; gap: .75rem; min-height: 4.5rem; }
.mobile-brand { font-size: 1.2rem; font-weight: 800; letter-spacing: -.02em; }
.mobile-stack { display: grid; gap: 1rem; }
.mobile-stack h1 { margin: .5rem 0 0; font-size: clamp(1.75rem, 8vw, 2.5rem); letter-spacing: -.04em; }
.mobile-eyebrow { color: var(--pw-brand); font-size: .75rem; font-weight: 800; letter-spacing: .14em; margin: 0; }
.mobile-card, .mobile-hero { background: var(--pw-surface); border: 1px solid var(--pw-border); border-radius: 1rem; padding: 1.25rem; box-shadow: var(--pw-shadow); }
.mobile-hero { text-align: center; padding-block: 2rem; }
.mobile-orb { width: 5.5rem; aspect-ratio: 1; margin: 0 auto 1rem; border-radius: 50%; background: radial-gradient(circle at 35% 30%, #7dd3fc, var(--pw-brand) 55%, #082f49); box-shadow: 0 0 0 .65rem color-mix(in srgb, var(--pw-brand) 12%, transparent); }
.mobile-orb[data-state="degraded"], .mobile-orb[data-state="failed"] { background: var(--pw-danger); }
.mobile-status { display: block; font-size: 1.5rem; }
.mobile-actions { display: flex; justify-content: center; gap: .75rem; margin-top: 1.25rem; }
.mobile-card label { display: block; margin-block: .75rem .35rem; font-weight: 650; }
.mobile-card input { width: 100%; padding: .75rem; border: 1px solid var(--pw-border); border-radius: .65rem; background: var(--pw-bg); color: var(--pw-text); }
button, .button-link { display: inline-flex; align-items: center; justify-content: center; border: 0; border-radius: .7rem; padding: .75rem 1rem; background: var(--pw-brand); color: var(--pw-brand-contrast); font: inherit; font-weight: 750; text-decoration: none; cursor: pointer; }
button.secondary, .button-link.secondary { background: var(--pw-surface-subtle); color: var(--pw-text); border: 1px solid var(--pw-border); }
button.danger { background: var(--pw-danger); color: #fff; }
button:disabled { cursor: wait; opacity: .55; }
.mobile-help { color: var(--pw-muted); font-size: .9rem; }
.mobile-tabs { position: fixed; inset: auto 0 0; display: grid; grid-template-columns: repeat(4, 1fr); gap: .25rem; padding: .5rem max(.75rem, env(safe-area-inset-right)) calc(.5rem + env(safe-area-inset-bottom)) max(.75rem, env(safe-area-inset-left)); background: color-mix(in srgb, var(--pw-surface) 92%, transparent); border-top: 1px solid var(--pw-border); backdrop-filter: blur(16px); z-index: 20; }
.mobile-tabs a { display: grid; place-items: center; min-height: 48px; color: var(--pw-muted); text-decoration: none; font-size: .78rem; font-weight: 700; }
.mobile-tabs a[aria-current="page"] { color: var(--pw-brand); }
.diagnostic-list div { display: flex; justify-content: space-between; gap: 1rem; padding: .75rem 0; border-bottom: 1px solid var(--pw-border); }
.diagnostic-list div:last-child { border: 0; }
.diagnostic-list dt { color: var(--pw-muted); } .diagnostic-list dd { margin: 0; font-weight: 700; overflow-wrap: anywhere; }
@media (min-width: 700px) { .mobile-tabs { left: 50%; width: min(52rem, 100%); transform: translateX(-50%); border-inline: 1px solid var(--pw-border); } }
"#;
