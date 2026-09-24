impl ApiClient {
    async fn mesh_page_with_selection(
        &self,
        selected: Option<&str>,
    ) -> Result<Page<MeshResource>, ConsoleApiError> {
        let mut page = self.meshes(None, 100).await?;
        if let Some(mesh) = selected.filter(|id| !id.is_empty())
            && !page.items.iter().any(|item| item.id.to_string() == mesh)
        {
            match self.mesh(mesh).await {
                Ok(resource) => page.items.push(resource),
                Err(ConsoleApiError::Server(error)) if error.code == "not_found" => {}
                Err(error) => return Err(error),
            }
        }
        page.items.retain(|mesh| mesh.lifecycle != "deleted");
        Ok(page)
    }
    /// Starts or recovers an idempotent bootstrap-host initialization task.
    pub async fn provision_mesh(
        &self,
        body: &MeshProvisioningCreateRequest,
    ) -> Result<MeshProvisioningResource, ConsoleApiError> {
        self.request(
            Method::POST,
            "/api/v1/mesh-provisioning",
            Some(body_value(body)?),
        )
        .await
    }

    /// Lists recent durable initialization tasks, including unfinished work.
    pub async fn mesh_provisioning_jobs(
        &self,
    ) -> Result<Page<MeshProvisioningResource>, ConsoleApiError> {
        self.list("/api/v1/mesh-provisioning", None, 100).await
    }

    /// Retries the same task and its existing identity bundle.
    pub async fn retry_mesh_provisioning(
        &self,
        id: uuid::Uuid,
    ) -> Result<MeshProvisioningResource, ConsoleApiError> {
        self.request(
            Method::POST,
            &format!("/api/v1/mesh-provisioning/{id}/retry"),
            Some(json!({})),
        )
        .await
    }
}

fn provisioning_stage_key(job: &MeshProvisioningResource) -> &'static str {
    if job.operation == "delete" {
        return match (job.status.as_str(), job.stage.as_str()) {
            ("succeeded", _) => "deletion-complete",
            ("failed", _) => "deletion-failed",
            (_, "waiting_for_relay") => "deletion-waiting-relay",
            _ => "deletion-stopping",
        };
    }
    match job.status.as_str() {
        "succeeded" => "initialization-ready",
        "failed" => "initialization-failed",
        _ => match job.stage.as_str() {
            "planning" => "initialization-planning",
            "credentials" => "initialization-credentials",
            "database" => "initialization-database",
            "signer" => "initialization-signer",
            "relay" => "initialization-relay",
            "health" => "initialization-health",
            _ => "initialization-queued",
        },
    }
}

fn visible_lifecycle_job(job: &MeshProvisioningResource) -> bool {
    job.status != "succeeded" && job.error_code.as_deref() != Some("mesh_deleted")
}

#[component]
fn MeshProvisioningPanel(
    snapshot: Signal<ConsoleSnapshot>,
    name: Signal<String>,
    selected: String,
    automatic: bool,
    locale: Locale,
    on_complete: EventHandler<String>,
    #[props(default)] watch_job: Option<uuid::Uuid>,
    #[props(default)] current_network: bool,
) -> Element {
    #[allow(unused_mut)]
    let mut jobs = use_signal(Vec::<MeshProvisioningResource>::new);
    #[allow(unused_mut)]
    let mut busy = use_signal(|| false);
    #[allow(unused_mut)]
    let mut reconnecting = use_signal(|| false);
    #[allow(unused_mut)]
    let mut failure = use_signal(|| false);
    #[allow(unused_mut, unused_variables)]
    let mut watched = use_signal(HashSet::<uuid::Uuid>::new);
    #[allow(unused_mut, unused_variables)]
    let mut captured = use_signal(|| None::<MeshProvisioningCreateRequest>);

    #[allow(unused_mut)]
    let mut active_selection = use_signal(|| selected.clone());
    use_effect(use_reactive(
        (&selected, &watch_job),
        move |(selected, watch_job)| {
            active_selection.set(selected);
            if let Some(id) = watch_job {
                watched.write().insert(id);
            }
        },
    ));
    use_future(move || async move {
        #[cfg(target_arch = "wasm32")]
        {
            let api = browser_api_client();
            loop {
                match api.mesh_provisioning_jobs().await {
                    Ok(page) => {
                        reconnecting.set(false);
                        for job in &page.items {
                            if job.status != "succeeded" {
                                if job.mesh_id.to_string() == *active_selection.peek() {
                                    watched.write().insert(job.id);
                                }
                            } else if watched.peek().contains(&job.id) {
                                let mesh = if job.operation == "delete" {
                                    String::new()
                                } else {
                                    job.mesh_id.to_string()
                                };
                                match api
                                    .route_snapshot_filtered(
                                        ConsoleRoute::Meshes,
                                        Some(&mesh),
                                        None,
                                        None,
                                    )
                                    .await
                                {
                                    Ok(value) => {
                                        snapshot.set(value);
                                        watched.write().remove(&job.id);
                                        on_complete.call(mesh);
                                    }
                                    Err(_) => reconnecting.set(true),
                                }
                            }
                        }
                        jobs.set(page.items);
                    }
                    Err(_) => reconnecting.set(true),
                }
                gloo_timers::future::TimeoutFuture::new(2000).await;
            }
        }
    });

    let submit = use_callback(move |existing: Option<MeshId>| {
        #[cfg(target_arch = "wasm32")]
        {
            let entered = existing
                .and_then(|id| {
                    snapshot
                        .peek()
                        .resources
                        .iter()
                        .find(|resource| resource.id == id.to_string())
                        .map(|resource| resource.name.clone())
                })
                .unwrap_or_else(|| name.peek().trim().to_owned());
            if entered.is_empty() || busy() {
                return;
            }
            let body = captured
                .peek()
                .as_ref()
                .filter(|body| body.name == entered && body.existing_mesh_id == existing)
                .cloned()
                .unwrap_or_else(|| MeshProvisioningCreateRequest {
                    request_id: uuid::Uuid::new_v4(),
                    name: entered,
                    existing_mesh_id: existing,
                    network_identifier: None,
                });
            captured.set(Some(body.clone()));
            busy.set(true);
            failure.set(false);
            let api = browser_api_client();
            let api = snapshot
                .peek()
                .csrf_token
                .as_ref()
                .map_or_else(|| api.clone(), |csrf| api.clone().with_csrf(csrf));
            spawn(async move {
                match api.provision_mesh(&body).await {
                    Ok(job) => {
                        watched.write().insert(job.id);
                        jobs.write().retain(|old| old.id != job.id);
                        jobs.write().insert(0, job);
                        captured.set(None);
                    }
                    Err(_) => failure.set(true),
                }
                busy.set(false);
            });
        }
        #[cfg(not(target_arch = "wasm32"))]
        let _ = existing;
    });
    let retry = use_callback(move |id: uuid::Uuid| {
        #[cfg(target_arch = "wasm32")]
        {
            busy.set(true);
            failure.set(false);
            let api = browser_api_client();
            let api = snapshot
                .peek()
                .csrf_token
                .as_ref()
                .map_or_else(|| api.clone(), |csrf| api.clone().with_csrf(csrf));
            spawn(async move {
                match api.retry_mesh_provisioning(id).await {
                    Ok(job) => {
                        watched.write().insert(id);
                        jobs.write().retain(|old| old.id != id);
                        jobs.write().insert(0, job);
                    }
                    Err(_) => failure.set(true),
                }
                busy.set(false);
            });
        }
        #[cfg(not(target_arch = "wasm32"))]
        let _ = id;
    });

    rsx! {
        section { aria_label: if current_network {console_text(locale,"当前网络任务","Current network tasks")} else {console_message(locale, "initialization-title")},
            p { {console_message(locale, "initialization-help")} }
            if automatic && selected.is_empty() {
                button { r#type: "button", disabled: busy() || name.read().trim().is_empty(),
                    onclick: move |_| submit.call(None),
                    {console_message(locale, "initialize-create")}
                }
            }
            if reconnecting() { p { role: "status", {console_message(locale, "initialization-reconnecting")} } }
            if failure() { p { role: "alert", {console_message(locale, "initialization-request-failed")} } }
            for job in jobs().into_iter().filter(|job|visible_lifecycle_job(job) && (!current_network || job.mesh_id.to_string()==selected)) {
                div { key: "{job.id}", class: "card",
                    strong { "{job.name}" }
                    p { role: "status", aria_live: "polite", {console_message(locale, provisioning_stage_key(&job))} }
                    if job.status == "failed" {
                        p { {console_message(locale, "initialization-failed-help")} }
                        if let Some(code) = job.error_code { p { code { "{code}" } } }
                        button { r#type: "button", disabled: busy(), onclick: move |_| retry.call(job.id),
                            {console_message(locale, "initialization-retry")}
                        }
                    }
                    if let Some(endpoint) = job.relay_endpoint { p { "{endpoint}" } }
                }
            }
        }
    }
}
