use super::*;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Host {
    comment: Option<String>,
    fail: bool,
    mutations: usize,
}
#[derive(Clone, Default)]
struct Backend(Arc<Mutex<Host>>);
impl CommandBackend for Backend {
    fn run(&mut self, command: &CommandSpec) -> Result<String, PlatformError> {
        let mut host = self.0.lock().unwrap();
        if command.arguments.first().is_some_and(|arg| arg == "--json") {
            return Ok(serde_json::json!({"nftables":host.comment.as_ref().map(|comment|vec![serde_json::json!({"table":{"family":"inet","name":"pw_exit_pwtest0","comment":comment}})]).unwrap_or_default()}).to_string());
        }
        if host.fail {
            return Err(PlatformError::Command("injected firewall failure".into()));
        }
        host.mutations += 1;
        let input = command.input.as_deref().unwrap();
        host.comment = input
            .split("peerward-exit:")
            .nth(1)
            .map(|tail| format!("peerward-exit:{}", tail.split('"').next().unwrap()));
        Ok(String::new())
    }
}
fn intent() -> ExitProtectionIntent {
    ExitProtectionIntent {
        interface: "pwtest0".into(),
        exit_resource: Uuid::new_v4(),
        local_lan: vec![],
    }
}

#[test]
fn crash_and_firewall_failure_retain_blocking_intent_until_explicit_disable() {
    let path = std::env::temp_dir().join(format!("peerward-exit-{}.json", Uuid::new_v4()));
    let backend = Backend::default();
    let request = intent();
    {
        let mut guard = ExitProtection::new(backend.clone(), &path);
        guard.arm(request.clone()).unwrap();
    }
    assert!(path.exists());
    assert!(
        backend.0.lock().unwrap().comment.is_some(),
        "Drop must not restore direct Internet"
    );
    let mut restored = ExitProtection::new(backend.clone(), &path);
    assert_eq!(restored.restore().unwrap(), Some(request.clone()));
    backend.0.lock().unwrap().fail = true;
    assert!(restored.disarm().is_err());
    assert!(path.exists());
    let next = intent();
    assert!(restored.arm(next.clone()).is_err());
    assert_eq!(
        restored.load().unwrap().unwrap().intent,
        next,
        "failed apply is retryable after restart"
    );
    backend.0.lock().unwrap().fail = false;
    assert_eq!(restored.restore().unwrap(), Some(next));
    restored.disarm().unwrap();
    assert!(!path.exists());
    assert!(backend.0.lock().unwrap().comment.is_none());
    restored.disarm().unwrap();
}

#[test]
fn foreign_firewall_or_untrusted_journal_is_never_removed() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    let path = std::env::temp_dir().join(format!("peerward-exit-{}.json", Uuid::new_v4()));
    let backend = Backend::default();
    backend.0.lock().unwrap().comment = Some("another owner".into());
    let mut guard = ExitProtection::new(backend.clone(), &path);
    assert!(guard.arm(intent()).is_err());
    assert!(!path.exists());
    assert_eq!(backend.0.lock().unwrap().mutations, 0);
    backend.0.lock().unwrap().comment = None;
    guard.arm(intent()).unwrap();
    let saved = fs::read(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(guard.restore().is_err());
    fs::remove_file(&path).unwrap();
    let target = path.with_extension("original");
    fs::write(&target, &saved).unwrap();
    symlink(&target, &path).unwrap();
    assert!(guard.restore().is_err());
    assert!(guard.disarm().is_err());
    assert_eq!(fs::read(&target).unwrap(), saved);
    fs::remove_file(path).unwrap();
    fs::remove_file(target).unwrap();
}
