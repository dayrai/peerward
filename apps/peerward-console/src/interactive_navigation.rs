#[derive(Clone, Copy)]
struct InteractiveNavigation {
    snapshot: Signal<ConsoleSnapshot>,
    active_route: Signal<ConsoleRoute>,
    loaded_location: Signal<ConsoleLocation>,
    generation: Signal<u64>,
    selected_mesh: Signal<String>,
    selected_resource: Signal<String>,
    name: Signal<String>,
    document: Signal<String>,
    confirmation: Signal<String>,
    join_link: Signal<String>,
    status: Signal<String>,
    locale: Signal<Locale>,
    loading: Signal<bool>,
}

fn use_interactive_navigation(client_location: ConsoleClientRoute, state: &InteractiveNavigation) {
    #[allow(unused_mut, unused_variables)]
    let InteractiveNavigation {
        mut snapshot,
        mut active_route,
        mut loaded_location,
        mut generation,
        mut selected_mesh,
        mut selected_resource,
        mut name,
        mut document,
        mut confirmation,
        mut join_link,
        mut status,
        locale,
        mut loading,
    } = *state;
    use_effect(use_reactive(
        (&client_location,),
        move |(client_location,)| {
            let (route, mesh, relay_id) = client_location.parts();
            let requested = ConsoleLocation::new(route, mesh, relay_id);
            if *loaded_location.peek() == requested {
                return;
            }
            let request_generation = generation.peek().wrapping_add(1);
            generation.set(request_generation);
            active_route.set(route);
            loaded_location.set(requested.clone());
            selected_mesh.set(requested.mesh.clone().unwrap_or_default());
            selected_resource.set(String::new());
            name.set(String::new());
            document.set(default_editor_document(route));
            confirmation.set(String::new());
            join_link.set(String::new());
            status.set(console_message(locale(), "loading").into());

            #[cfg(target_arch = "wasm32")]
            {
                if let Some(document) = web_sys::window().and_then(|window| window.document()) {
                    document.set_title(&format!("{} · Peerward Console", route.label()));
                }
                let api = browser_api_client();
                let mut current = snapshot.peek().clone();
                current.relay_filter.clone_from(&requested.relay_id);
                // Stop presenting or acting on the old network while the new
                // snapshot is in flight. Keyed domain pages drop drafts/secrets.
                let mut pending = current.clone();
                pending.mesh_id = requested.mesh.clone().unwrap_or_default();
                pending.mesh_name = pending
                    .meshes
                    .iter()
                    .find(|m| m.id == pending.mesh_id)
                    .map(|m| m.name.clone())
                    .unwrap_or_default();
                pending.resources.clear();
                pending.lookups.clear();
                pending.next_cursor = None;
                pending.error = None;
                snapshot.set(pending);
                loading.set(true);
                spawn(async move {
                    let result = api
                        .route_resource_snapshot(route, &current, requested.mesh.as_deref(), None)
                        .await;
                    if *loaded_location.peek() != requested
                        || *generation.peek() != request_generation
                    {
                        return;
                    }
                    match result {
                        Ok(value) => {
                            selected_mesh.set(value.mesh_id.clone());
                            snapshot.set(value);
                            status.set(String::new());
                        }
                        Err(error) => snapshot.write().error = Some(api_error_body(error)),
                    }
                    loading.set(false);
                });
            }
        },
    ));
}
