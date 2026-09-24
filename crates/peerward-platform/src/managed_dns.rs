use super::*;

/// Search-domain updates while the base network transaction retains root DNS capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxDnsIntent {
    pub search_domains: Vec<String>,
}

impl LinuxDnsIntent {
    fn validate(&self) -> Result<(), PlatformError> {
        if self.search_domains.len() > 6
            || self.search_domains.iter().any(|name| {
                name.is_empty()
                    || name.len() > 253
                    || name != &name.to_ascii_lowercase()
                    || name.split('.').any(|label| {
                        label.is_empty()
                            || label.len() > 63
                            || label.starts_with('-')
                            || label.ends_with('-')
                            || !label.bytes().all(|byte| {
                                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                            })
                    })
            })
        {
            return Err(PlatformError::InvalidName);
        }
        Ok(())
    }
}
impl<B: CommandBackend> StateCoordinator<B> {
    /// Separate journal; recover it before recovering the owning base network journal.
    pub fn apply_dns_profile(
        &mut self,
        base: &LinuxNetworkConfig,
        intent: &LinuxDnsIntent,
    ) -> Result<(), PlatformError> {
        validate_config(base)?;
        intent.validate()?;
        self.shutdown()?;
        self.phase = Some(TransactionPhase::Prepared);
        let mut domains = vec![(".".into(), true), (base.dns_suffix.clone(), true)];
        for name in &intent.search_domains {
            domains.retain(|(existing, _)| existing != name);
            domains.push((name.clone(), false));
        }
        let label = format!("{}.peerward-managed", base.interface);
        let operations = dns_operations_scoped(&mut self.backend, base, &domains, Some(&label))?;
        self.apply_operations_journaled(operations, true)?;
        self.commit()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn search_update_keeps_root_capture_and_an_exact_owned_rollback() {
        let base = crate::tests::config();
        let mut coordinator = StateCoordinator::new(crate::tests::MockBackend::default());
        coordinator
            .apply_dns_profile(
                &base,
                &LinuxDnsIntent {
                    search_domains: vec!["office.example".into()],
                },
            )
            .unwrap();
        let mutation = coordinator
            .backend
            .calls
            .iter()
            .find(|command| command.program == "peerward-resolved")
            .unwrap();
        let body: ResolvedLinkMutation =
            serde_json::from_str(mutation.input.as_ref().unwrap()).unwrap();
        assert!(body.replacement.domains.contains(&(".".into(), true)));
        assert!(
            body.replacement
                .domains
                .contains(&("office.example".into(), false))
        );
        coordinator.shutdown().unwrap();
        let last = coordinator.backend.calls.last().unwrap();
        let rollback: ResolvedLinkMutation =
            serde_json::from_str(last.input.as_ref().unwrap()).unwrap();
        assert_eq!(rollback.replacement, body.expected);
    }
}
