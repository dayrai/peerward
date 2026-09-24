#[derive(Clone, Copy, PartialEq, Eq)]
enum BrowserOperation {
    Create,
    Edit,
    Delete,
    DeletePeer,
    DeleteMesh,
    ActivateAuthority,
    Rotate,
    ActivateCredential,
    RevokeCredential,
    ValidatePolicy,
    SimulatePolicy,
    ReplacePolicy,
}

#[cfg(target_arch = "wasm32")]
fn api_error_body(error: ConsoleApiError) -> ApiErrorBody {
    match error {
        ConsoleApiError::Server(body) => body,
        ConsoleApiError::Transport(_) => ApiErrorBody {
            code: "control_unavailable".into(),
            message: "The control service is unavailable.".into(),
            request_id: uuid::Uuid::new_v4().to_string(),
            field_errors: BTreeMap::new(),
            retryable: true,
        },
        ConsoleApiError::InvalidResponse => ApiErrorBody {
            code: "invalid_control_response".into(),
            message: "The control service returned an invalid response.".into(),
            request_id: uuid::Uuid::new_v4().to_string(),
            field_errors: BTreeMap::new(),
            retryable: false,
        },
        ConsoleApiError::InvalidBaseUrl => ApiErrorBody {
            code: "invalid_control_origin".into(),
            message: "The configured control origin is invalid.".into(),
            request_id: uuid::Uuid::new_v4().to_string(),
            field_errors: BTreeMap::new(),
            retryable: false,
        },
        ConsoleApiError::ResponseTooLarge => ApiErrorBody {
            code: "control_response_too_large".into(),
            message: "The control service response exceeded its safety bound.".into(),
            request_id: uuid::Uuid::new_v4().to_string(),
            field_errors: BTreeMap::new(),
            retryable: false,
        },
    }
}

#[cfg(target_arch = "wasm32")]
fn browser_api_client() -> ApiClient {
    let origin = web_sys::window()
        .and_then(|window| window.location().origin().ok())
        .expect("the Console runs in a browser origin");
    ApiClient::new(origin).expect("the browser origin is a valid control proxy URL")
}

#[cfg(any(test, target_arch = "wasm32"))]
fn form_object(document: &str) -> Result<serde_json::Map<String, Value>, ConsoleApiError> {
    serde_json::from_str::<Value>(document)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .ok_or(ConsoleApiError::InvalidResponse)
}

#[cfg(any(test, target_arch = "wasm32"))]
fn form_string(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<String, ConsoleApiError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or(ConsoleApiError::InvalidResponse)
}

#[cfg(any(test, target_arch = "wasm32"))]
fn form_number(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<u64, ConsoleApiError> {
    form_string(object, field)?
        .parse()
        .map_err(|_| ConsoleApiError::InvalidResponse)
}

#[cfg(any(test, target_arch = "wasm32"))]
fn form_labels(
    object: &serde_json::Map<String, Value>,
) -> Result<serde_json::Map<String, Value>, ConsoleApiError> {
    let input = object.get("labels").and_then(Value::as_str).unwrap_or("");
    input
        .split(',')
        .map(str::trim)
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair
                .split_once('=')
                .ok_or(ConsoleApiError::InvalidResponse)?;
            let key = key.trim();
            let value = value.trim();
            if key.is_empty() || value.is_empty() {
                return Err(ConsoleApiError::InvalidResponse);
            }
            Ok((key.to_owned(), Value::String(value.to_owned())))
        })
        .collect()
}

#[cfg(any(test, target_arch = "wasm32"))]
fn optional_form_string(object: &serde_json::Map<String, Value>, field: &str) -> Option<String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

#[cfg(any(test, target_arch = "wasm32"))]
fn form_list(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<Vec<String>, ConsoleApiError> {
    let values = form_string(object, field)?
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    (!values.is_empty())
        .then_some(values)
        .ok_or(ConsoleApiError::InvalidResponse)
}

#[cfg(any(test, target_arch = "wasm32"))]
fn operation_body(
    route: ConsoleRoute,
    operation: BrowserOperation,
    name: &str,
    document: &str,
) -> Result<Value, ConsoleApiError> {
    let form = form_object(document)?;
    let name = if operation == BrowserOperation::DeleteMesh {
        name
    } else {
        name.trim()
    };
    let body = match (route, operation) {
        (ConsoleRoute::Meshes, BrowserOperation::Create) => json!({
            "name": (!name.is_empty()).then_some(name).ok_or(ConsoleApiError::InvalidResponse)?,
            "address_cidr": form_string(&form, "address_cidr")?,
            "gateway": form_string(&form, "gateway")?,
            "dns_suffix": form_string(&form, "dns_suffix")?,
            "mtu": form_number(&form, "mtu")?,
            "reserved": optional_form_string(&form, "reserved").map_or_else(Vec::new, |value| value.split(',').map(str::trim).filter(|part| !part.is_empty()).map(str::to_owned).collect()),
            "default_policy": form_string(&form, "default_policy")?,
            "quarantine_seconds": form_number(&form, "quarantine_seconds")?,
            "rotation_overlap_seconds": form_number(&form, "rotation_overlap_seconds")?
        }),
        (ConsoleRoute::Meshes, BrowserOperation::Edit) => json!({
            "name": (!name.is_empty()).then_some(name),
            "dns_suffix": optional_form_string(&form, "dns_suffix"),
            "lease_seconds": form.contains_key("lease_seconds").then(|| form_number(&form,"lease_seconds")).transpose()?
        }),
        (ConsoleRoute::Peers, BrowserOperation::Create) => json!({
            "display_name": optional_form_string(&form, "display_name").unwrap_or_default(),
            "location": optional_form_string(&form, "location").unwrap_or_default(),
            "name": (!name.is_empty()).then_some(name).ok_or(ConsoleApiError::InvalidResponse)?,
            "labels": form_labels(&form)?
        }),
        (ConsoleRoute::Peers, BrowserOperation::Edit) => json!({
            "display_name": optional_form_string(&form, "display_name").unwrap_or_default(),
            "location": optional_form_string(&form, "location").unwrap_or_default(),
            "name": (!name.is_empty()).then_some(name),
            "labels": form_labels(&form)?,
            "administrative_state": optional_form_string(&form, "administrative_state")
        }),
        (ConsoleRoute::Relays, BrowserOperation::Create) => json!({
            "name": (!name.is_empty()).then_some(name).ok_or(ConsoleApiError::InvalidResponse)?,
            "peer_endpoints": form_list(&form, "peer_endpoints")?,
            "backbone_endpoints": form_list(&form, "backbone_endpoints")?,
            "region": optional_form_string(&form, "region").unwrap_or_else(|| "default".into()),
            "routing_weight": if form.contains_key("routing_weight") { form_number(&form, "routing_weight")? } else { 100 }
        }),
        (ConsoleRoute::Relays, BrowserOperation::Edit) => json!({
            "name": (!name.is_empty()).then_some(name),
            "peer_endpoints": form_list(&form, "peer_endpoints")?,
            "backbone_endpoints": form_list(&form, "backbone_endpoints")?,
            "administrative_state": optional_form_string(&form, "administrative_state"),
            "region": optional_form_string(&form, "region"),
            "routing_weight": form.contains_key("routing_weight").then(|| form_number(&form, "routing_weight")).transpose()?
        }),
        (ConsoleRoute::Authorities, BrowserOperation::Create) => json!({
            "certificate": form_string(&form, "certificate")?,
            "replaces": optional_form_string(&form, "replaces")
        }),
        (ConsoleRoute::JoinTickets, BrowserOperation::Create) => json!({
            "expires_in_seconds": form_number(&form, "expires_in_seconds")?,
            "settings": {
                "name":optional_form_string(&form,"assigned_name"),"labels":form_labels(&form)?,
                "lifecycle": invitation_lifecycle(&form)?,
                "mode":match optional_form_string(&form,"join_mode").as_deref().unwrap_or("bearer") {
                    "bearer"=>json!({"kind":"bearer"}),"approval"=>json!({"kind":"approval"}),
                    "prebound"=>json!({"kind":"prebound","identity_fingerprint":form_string(&form,"identity_fingerprint")?}),
                    _=>return Err(ConsoleApiError::InvalidResponse),
                }
            }
        }),
        (ConsoleRoute::Services, BrowserOperation::Create) => json!({
            "peer_id": form_string(&form, "peer_id")?,
            "protocols": match form_string(&form, "protocol")?.as_str() {
                "tcp" => vec!["tcp"], "udp" => vec!["udp"], "both" => vec!["tcp", "udp"],
                _ => return Err(ConsoleApiError::InvalidResponse),
            },
            "listen_port": form_number(&form, "listen_port")?,
            "alias": optional_form_string(&form, "alias"),
            "labels": form_labels(&form)?
        }),
        (
            ConsoleRoute::Policy,
            BrowserOperation::ValidatePolicy | BrowserOperation::ReplacePolicy,
        ) => json!({
            "revision": form_number(&form, "revision")?,
            "default_action": form_string(&form, "default_action")?,
            "rules": serde_json::from_str::<Vec<Value>>(&form_string(&form, "rules")?).map_err(|_| ConsoleApiError::InvalidResponse)?
        }),
        (ConsoleRoute::Policy, BrowserOperation::SimulatePolicy) => {
            let draft_policy = if form_string(&form, "simulate_draft")? == "true" {
                Some(json!({
                    "revision": form_number(&form, "revision")?,
                    "default_action": form_string(&form, "default_action")?,
                    "rules": serde_json::from_str::<Vec<Value>>(&form_string(&form, "rules")?)
                        .map_err(|_| ConsoleApiError::InvalidResponse)?
                }))
            } else {
                None
            };
            json!({
                "source_peer_id": form_string(&form, "source_peer_id")?,
                "target_service_id": form_string(&form, "target_service_id")?,
                "protocol": form_string(&form, "simulation_protocol")?,
                "draft_policy": draft_policy
            })
        }
        (ConsoleRoute::Relays, BrowserOperation::Rotate) => json!({
            "public_key": form_string(&form, "public_key")?
        }),
        (
            ConsoleRoute::Peers | ConsoleRoute::Relays,
            BrowserOperation::ActivateCredential | BrowserOperation::RevokeCredential,
        ) => json!({"serial": form_string(&form, "serial")?}),
        (ConsoleRoute::Peers, BrowserOperation::DeletePeer) => json!({"name": name}),
        (ConsoleRoute::Meshes, BrowserOperation::DeleteMesh) => json!({"confirmation_name": name}),
        (_, BrowserOperation::Delete | BrowserOperation::ActivateAuthority) => json!({}),
        _ => return Err(ConsoleApiError::InvalidResponse),
    };
    Ok(body)
}

#[cfg(target_arch = "wasm32")]
fn typed_body<T: DeserializeOwned>(body: Value) -> Result<T, ConsoleApiError> {
    serde_json::from_value(body).map_err(|_| ConsoleApiError::InvalidResponse)
}

#[cfg(target_arch = "wasm32")]
async fn apply_browser_operation(
    client: &ApiClient,
    route: ConsoleRoute,
    snapshot: &ConsoleSnapshot,
    operation: BrowserOperation,
    name: &str,
    document: &str,
    selected_resource: &str,
    locale: Locale,
) -> Result<Option<String>, ConsoleApiError> {
    let client = snapshot
        .csrf_token
        .as_ref()
        .map_or_else(|| client.clone(), |csrf| client.clone().with_csrf(csrf));
    let body = operation_body(route, operation, name, document)?;
    let selected = (!selected_resource.is_empty())
        .then_some(selected_resource)
        .ok_or(ConsoleApiError::InvalidResponse);
    let selected_version = || {
        snapshot
            .resources
            .iter()
            .find(|resource| resource.id == selected_resource)
            .and_then(|resource| resource.details.get("version"))
            .and_then(Value::as_u64)
            .ok_or(ConsoleApiError::InvalidResponse)
    };
    let family = match route {
        ConsoleRoute::Authorities => Some(ResourceFamily::Authorities),
        ConsoleRoute::Peers => Some(ResourceFamily::Peers),
        ConsoleRoute::Relays => Some(ResourceFamily::Relays),
        ConsoleRoute::JoinTickets => Some(ResourceFamily::JoinTickets),
        ConsoleRoute::Services => Some(ResourceFamily::Services),
        _ => None,
    };
    let credential_subject = match route {
        ConsoleRoute::Peers => Some(CredentialSubject::Peer),
        ConsoleRoute::Relays => Some(CredentialSubject::Relay),
        _ => None,
    };
    if operation == BrowserOperation::Create && route == ConsoleRoute::JoinTickets {
        let request = typed_body::<JoinTicketCreateRequest>(body)?;
        let ticket = client
            .create_join_ticket(&snapshot.mesh_id, &request)
            .await?;
        return client.join_link(&ticket).map(Some);
    }
    if operation == BrowserOperation::ValidatePolicy && route == ConsoleRoute::Policy {
        let request = typed_body::<PolicyPutRequest>(body)?;
        let validation = client.validate_policy(&snapshot.mesh_id, &request).await?;
        if validation.valid {
            let digest = validation
                .canonical_sha256
                .as_deref()
                .unwrap_or_else(|| console_message(locale, "unavailable"));
            let warnings = if validation.warnings.is_empty() {
                String::new()
            } else {
                format!(
                    "; {}: {}",
                    console_message(locale, "warnings"),
                    validation.warnings.join(", ")
                )
            };
            return Ok(Some(format!(
                "{} {digest}{warnings}",
                console_message(locale, "policy-valid")
            )));
        }
        let fields = validation
            .field_errors
            .iter()
            .map(|(field, message)| format!("{field}: {message}"))
            .collect::<Vec<_>>()
            .join("; ");
        return Ok(Some(format!(
            "{}: {fields}",
            console_message(locale, "policy-invalid")
        )));
    }
    if operation == BrowserOperation::SimulatePolicy && route == ConsoleRoute::Policy {
        let request = typed_body::<PolicySimulationRequest>(body)?;
        let simulation = client.simulate_policy(&snapshot.mesh_id, &request).await?;
        let matched = simulation
            .matched_rule_id
            .map_or_else(|| "default".into(), |rule| rule.to_string());
        return Ok(Some(format!(
            "{} · {} · {}: {matched} · SHA-256 {}",
            if simulation.allowed { "ALLOW" } else { "DENY" },
            simulation.action,
            console_message(locale, "matched-rule"),
            simulation.canonical_sha256,
        )));
    }
    let result = match operation {
        BrowserOperation::Create if route == ConsoleRoute::Meshes => {
            let request = typed_body::<MeshCreateRequest>(body)?;
            client.create_mesh(&request).await.map(|_| ())
        }
        BrowserOperation::Create if route == ConsoleRoute::Authorities => {
            let request = typed_body::<AuthorityStageRequest>(body)?;
            client
                .stage_authority(&snapshot.mesh_id, &request)
                .await
                .map(|_| ())
        }
        BrowserOperation::Create if route == ConsoleRoute::Peers => {
            let request = typed_body::<PeerCreateRequest>(body)?;
            client
                .create_peer(&snapshot.mesh_id, &request)
                .await
                .map(|_| ())
        }
        BrowserOperation::Create if route == ConsoleRoute::Relays => {
            let request = typed_body::<RelayCreateRequest>(body)?;
            client
                .create_relay(&snapshot.mesh_id, &request)
                .await
                .map(|_| ())
        }
        BrowserOperation::Create if route == ConsoleRoute::Services => {
            let request = typed_body::<ServiceCreateRequest>(body)?;
            client
                .create_service(&snapshot.mesh_id, &request)
                .await
                .map(|_| ())
        }
        BrowserOperation::Edit if route == ConsoleRoute::Meshes => {
            let request = typed_body::<MeshPatchRequest>(body)?;
            client
                .update_mesh(selected?, &request, selected_version()?)
                .await
                .map(|_| ())
        }
        BrowserOperation::Edit if route == ConsoleRoute::Peers => {
            let request = typed_body::<PeerPatchRequest>(body)?;
            client
                .update_peer(&snapshot.mesh_id, selected?, &request, selected_version()?)
                .await
                .map(|_| ())
        }
        BrowserOperation::Edit if route == ConsoleRoute::Relays => {
            let request = typed_body::<RelayPatchRequest>(body)?;
            client
                .update_relay(&snapshot.mesh_id, selected?, &request, selected_version()?)
                .await
                .map(|_| ())
        }
        BrowserOperation::Delete if family.is_some() => client
            .delete_resource(
                &snapshot.mesh_id,
                family.ok_or(ConsoleApiError::InvalidResponse)?,
                selected?,
                selected_version()?,
            )
            .await
            .map(|_| ()),
        BrowserOperation::DeleteMesh if route == ConsoleRoute::Meshes => client
            .delete_mesh(
                selected?,
                &typed_body::<MeshDeleteRequest>(body)?,
                selected_version()?,
            )
            .await
            .map(|_| ()),
        BrowserOperation::DeletePeer if route == ConsoleRoute::Peers => {
            let request = typed_body::<PeerDeleteRequest>(body)?;
            client
                .delete_peer(&snapshot.mesh_id, selected?, &request, selected_version()?)
                .await
                .map(|_| ())
        }
        BrowserOperation::ActivateAuthority if route == ConsoleRoute::Authorities => client
            .activate_authority(&snapshot.mesh_id, selected?, selected_version()?)
            .await
            .map(|_| ()),
        BrowserOperation::Rotate if route == ConsoleRoute::Relays => {
            let request = typed_body::<CredentialRotationRequest>(body)?;
            client
                .rotate_credential(
                    &snapshot.mesh_id,
                    credential_subject.ok_or(ConsoleApiError::InvalidResponse)?,
                    selected?,
                    &request,
                    selected_version()?,
                )
                .await
                .map(|_| ())
        }
        BrowserOperation::ActivateCredential
            if matches!(route, ConsoleRoute::Peers | ConsoleRoute::Relays) =>
        {
            let serial = body
                .get("serial")
                .and_then(Value::as_str)
                .ok_or(ConsoleApiError::InvalidResponse)?;
            client
                .activate_credential(
                    &snapshot.mesh_id,
                    credential_subject.ok_or(ConsoleApiError::InvalidResponse)?,
                    selected?,
                    serial,
                    selected_version()?,
                )
                .await
                .map(|_| ())
        }
        BrowserOperation::RevokeCredential
            if matches!(route, ConsoleRoute::Peers | ConsoleRoute::Relays) =>
        {
            let serial = body
                .get("serial")
                .and_then(Value::as_str)
                .ok_or(ConsoleApiError::InvalidResponse)?;
            client
                .revoke_credential(
                    &snapshot.mesh_id,
                    credential_subject.ok_or(ConsoleApiError::InvalidResponse)?,
                    selected?,
                    serial,
                    selected_version()?,
                )
                .await
                .map(|_| ())
        }
        BrowserOperation::ReplacePolicy if route == ConsoleRoute::Policy => {
            let request = typed_body::<PolicyPutRequest>(body)?;
            client
                .replace_policy(&snapshot.mesh_id, &request)
                .await
                .map(|_| ())
        }
        _ => return Err(ConsoleApiError::InvalidResponse),
    };
    result.map(|()| None)
}
#[cfg(target_arch = "wasm32")]
fn sync_document_preferences(locale: Locale, theme: Theme) {
    if let Some(storage) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
        let _ = storage.set_item("peerward.console.locale", locale.tag());
        let _ = storage.set_item("peerward.console.theme", theme.attribute());
    }
    if let Some(root) = web_sys::window()
        .and_then(|window| window.document())
        .and_then(|document| document.document_element())
    {
        let _ = root.set_attribute("lang", locale.tag());
        let _ = root.set_attribute("data-theme", theme.attribute());
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn sync_document_preferences(_locale: Locale, _theme: Theme) {}
