#[derive(Clone, PartialEq)]
struct ResourceRuleForm {
    source: String,
    target: String,
    source_collection: String,
    target_collection: String,
    protocol: u8,
    port: String,
    priority: String,
    allow: bool,
}
impl Default for ResourceRuleForm {
    fn default() -> Self {
        Self {
            source: String::new(),
            target: String::new(),
            source_collection: String::new(),
            target_collection: String::new(),
            protocol: 6,
            port: "443".into(),
            priority: "100".into(),
            allow: true,
        }
    }
}
impl ResourceRuleForm {
    fn rule(&self) -> Result<peerward_management::ResourceRule, &'static str> {
        use peerward_management::{DeviceSelector, ResourceAction, ResourceRule};
        let source = if self.source_collection.is_empty() {
            [self
                .source
                .parse::<peerward_types::PeerId>()
                .map_err(|_| "resource-rule-select-source")?]
            .into()
        } else {
            std::collections::BTreeSet::new()
        };
        let targets = if self.target_collection.is_empty() {
            [self
                .target
                .parse::<uuid::Uuid>()
                .map_err(|_| "resource-rule-select-target")?]
            .into()
        } else {
            std::collections::BTreeSet::new()
        };
        let parse_group =
            |value: &str| -> Result<std::collections::BTreeSet<uuid::Uuid>, &'static str> {
                if value.is_empty() {
                    Ok(std::collections::BTreeSet::new())
                } else {
                    Ok([value.parse().map_err(|_| "resource-rule-invalid")?].into())
                }
            };
        let ports = if [6, 17].contains(&self.protocol) {
            let (first, last) = self
                .port
                .split_once('-')
                .unwrap_or((&self.port, &self.port));
            let first = first
                .trim()
                .parse::<u16>()
                .ok()
                .filter(|port| *port > 0)
                .ok_or("resource-rule-invalid-port")?;
            let last = last
                .trim()
                .parse::<u16>()
                .ok()
                .filter(|port| *port >= first)
                .ok_or("resource-rule-invalid-port")?;
            vec![(first, last)]
        } else {
            vec![]
        };
        let rule = ResourceRule {
            source_collections: parse_group(&self.source_collection)?,
            resource_collections: parse_group(&self.target_collection)?,
            id: uuid::Uuid::new_v4(),
            priority: self
                .priority
                .parse()
                .map_err(|_| "resource-rule-priority")?,
            enabled: true,
            action: if self.allow {
                ResourceAction::Allow
            } else {
                ResourceAction::Deny
            },
            source: DeviceSelector {
                peers: source,
                ..DeviceSelector::default()
            },
            resources: targets,
            providers: std::collections::BTreeSet::default(),
            protocol: self.protocol,
            destination_ports: ports,
            not_after: None,
        };
        rule.validate().map_err(|_| "resource-rule-invalid")?;
        Ok(rule)
    }
}

fn resource_policy_draft(
    document: &str,
) -> Result<peerward_api::ResourcePolicyDocument, &'static str> {
    let document: peerward_api::ResourcePolicyDocument =
        serde_json::from_str(document).map_err(|_| "resource-rule-invalid-document")?;
    if document.rules.len() > 4096 || document.tests.len() > 256 {
        return Err("resource-rule-invalid-document");
    }
    for rule in &document.rules {
        rule.validate().map_err(|_| "resource-rule-invalid")?;
    }
    Ok(document)
}

#[derive(Clone, Copy)]
enum ResourcePolicyOperation {
    Load,
    Preview,
    Publish,
    History(u64),
    Simulate,
}

fn resource_rule_summary(
    rule: &peerward_management::ResourceRule,
    peers: &[PeerResource],
    resources: &[peerward_management::NetworkResource],
    collections: &[peerward_management::Collection],
    locale: Locale,
) -> String {
    let mut sources = rule
        .source
        .peers
        .iter()
        .map(|id| {
            peers.iter().find(|peer| peer.id == *id).map_or_else(
                || console_message(locale, "network-device-unavailable").into(),
                |peer| peer.name.clone(),
            )
        })
        .collect::<Vec<_>>();
    sources.extend(
        rule.source
            .labels
            .iter()
            .map(|(key, value)| format!("{key}={value}")),
    );
    sources.extend(rule.source.cidrs.iter().map(ToString::to_string));
    let group_name = |id: &uuid::Uuid| {
        collections
            .iter()
            .find(|collection| collection.id == *id)
            .map_or_else(
                || console_message(locale, "collections").into(),
                |collection| collection.definition.name.clone(),
            )
    };
    sources.extend(rule.source_collections.iter().map(group_name));
    if sources.is_empty() {
        sources.push(console_message(locale, "dns-all-devices").into());
    }
    let mut targets = rule
        .resources
        .iter()
        .map(|id| {
            resources
                .iter()
                .find(|target| target.id == *id)
                .map_or_else(
                    || console_message(locale, "resource-rule-select-target").into(),
                    |target| target.definition.name.clone(),
                )
        })
        .collect::<Vec<_>>();
    targets.extend(rule.resource_collections.iter().map(group_name));
    let protocol = match rule.protocol {
        6 => "TCP",
        17 => "UDP",
        1 => "ICMPv4",
        58 => "ICMPv6",
        _ => "IP",
    };
    let ports = rule
        .destination_ports
        .iter()
        .map(|(first, last)| {
            if first == last {
                first.to_string()
            } else {
                format!("{first}-{last}")
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{} · {} → {} · {} {} · {}",
        rule.priority,
        sources.join(", "),
        targets.join(", "),
        protocol,
        ports,
        console_message(
            locale,
            if rule.action == peerward_management::ResourceAction::Allow {
                "resource-rule-allow"
            } else {
                "resource-rule-deny"
            }
        )
    )
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
impl ApiClient {
    async fn resource_policy_operation(
        &self,
        mesh: &str,
        operation: ResourcePolicyOperation,
        version: u64,
        document: Value,
    ) -> Result<Value, ConsoleApiError> {
        let base = format!("/api/v1/meshes/{mesh}");
        match operation {
            ResourcePolicyOperation::Load => {
                self.request(Method::GET, &format!("{base}/resource-policy"), None)
                    .await
            }
            ResourcePolicyOperation::History(revision) => {
                self.request(
                    Method::GET,
                    &format!("{base}/resource-policy/history/{revision}"),
                    None,
                )
                .await
            }
            ResourcePolicyOperation::Preview => {
                self.request(
                    Method::POST,
                    &format!("{base}/resource-policy/preview"),
                    Some(document),
                )
                .await
            }
            ResourcePolicyOperation::Publish => {
                self.conditional_request(
                    Method::PUT,
                    &format!("{base}/resource-policy"),
                    Some(document),
                    version,
                )
                .await
            }
            ResourcePolicyOperation::Simulate => {
                self.request(
                    Method::POST,
                    &format!("{base}/policy/simulate"),
                    Some(document),
                )
                .await
            }
        }
    }
}
