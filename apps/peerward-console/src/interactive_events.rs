#[allow(unused_variables, unused_mut)]
fn use_interactive_events(state: &InteractiveNavigation, mut browser_ready: Signal<bool>) {
    #[cfg(target_arch = "wasm32")]
    let route_navigator = use_navigator();
    #[allow(unused_variables, unused_mut)]
    let InteractiveNavigation {
        mut snapshot,
        mut active_route,
        mut loaded_location,
        generation,
        mut selected_mesh,
        mut selected_resource,
        mut name,
        mut document,
        mut confirmation,
        mut join_link,
        mut status,
        mut locale,
        mut loading,
    } = *state;
    use_effect(move || {
        #[cfg(target_arch = "wasm32")]
        {
            browser_ready.set(true);
            let api = browser_api_client();
            // SSR already supplied the form data. Background event reconnects
            // must neither block the form nor release a foreground operation.
            let events_api = api.clone();
            spawn(async move {
                let mut replay = EventReplay::default();
                loop {
                    match events_api.events(replay.cursor()).await {
                        Ok(response) => {
                            use futures_util::StreamExt as _;
                            let mut stream = response.bytes_stream();
                            let mut parser = SseParser::default();
                            while let Some(chunk) = stream.next().await {
                                let Ok(chunk) = chunk else { break };
                                let Ok(events) = parser.push(&chunk) else {
                                    break;
                                };
                                let selected = selected_mesh.peek().clone();
                                let mut refresh = false;
                                let mut ready = false;
                                let mut latest_id = None;
                                for event in events {
                                    if replay.delivered(&event) {
                                        ready |= event.event.as_deref() == Some("peerward.ready");
                                        let route = *active_route.peek();
                                        if event_affects_route(&event, route, &selected) {
                                            refresh = true;
                                            latest_id = event.id;
                                        }
                                    }
                                }
                                if refresh {
                                    gloo_timers::future::TimeoutFuture::new(250).await;
                                    let current = snapshot.peek().clone();
                                    let route = *active_route.peek();
                                    let location = loaded_location.peek().clone();
                                    let request_generation = *generation.peek();
                                    let refreshed = if ready
                                        || matches!(route, ConsoleRoute::Meshes)
                                    {
                                        events_api
                                            .route_snapshot_filtered(
                                                route,
                                                (!selected.is_empty()).then_some(selected.as_str()),
                                                None,
                                                current.relay_filter.as_deref(),
                                            )
                                            .await
                                    } else {
                                        events_api
                                            .route_resource_snapshot(
                                                route,
                                                &current,
                                                (!selected.is_empty()).then_some(selected.as_str()),
                                                None,
                                            )
                                            .await
                                    };
                                    match refreshed {
                                        Ok(value)
                                            if selected_mesh.peek().as_str() == selected
                                                && *loaded_location.peek() == location
                                                && *generation.peek() == request_generation =>
                                        {
                                            if route == ConsoleRoute::Meshes {
                                                if !selected_resource.peek().is_empty()
                                                    && !value.resources.iter().any(|resource| {
                                                        resource.id == *selected_resource.peek()
                                                    })
                                                {
                                                    selected_resource.set(String::new());
                                                    confirmation.set(String::new());
                                                    name.set(String::new());
                                                    document.set(default_editor_document(route));
                                                }
                                                if value.mesh_id != selected {
                                                    selected_mesh.set(value.mesh_id.clone());
                                                    loaded_location.set(ConsoleLocation::new(
                                                        route, None, None,
                                                    ));
                                                    route_navigator.replace(
                                                        ConsoleClientRoute::Meshes { mesh: None }
                                                            .href(),
                                                    );
                                                }
                                            }
                                            snapshot.set(value);
                                            *CONSOLE_QUERY_EPOCH.write() += 1;
                                            status.set(format!(
                                                "{}: {}",
                                                console_message(locale(), "live-update"),
                                                latest_id.unwrap_or_default()
                                            ));
                                        }
                                        Ok(_) => {}
                                        Err(error) => {
                                            if *loaded_location.peek() == location
                                                && *generation.peek() == request_generation
                                            {
                                                snapshot.write().error =
                                                    Some(api_error_body(error));
                                            }
                                            replay.reset();
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        Err(ConsoleApiError::Server(error))
                            if error.code == "event_cursor_expired" =>
                        {
                            replay.reset();
                        }
                        Err(error) => snapshot.write().error = Some(api_error_body(error)),
                    }
                    let delay = u32::try_from(replay.failed()).unwrap_or(u32::MAX);
                    gloo_timers::future::TimeoutFuture::new(delay).await;
                }
            });
        }
    });
}
