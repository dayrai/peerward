fn use_interactive_mutation(
    route: ConsoleRoute,
    state: &InteractiveNavigation,
) -> Callback<BrowserOperation> {
    #[allow(unused_mut, unused_variables)]
    let InteractiveNavigation {
        mut snapshot,
        mut loaded_location,
        generation,
        mut name,
        mut document,
        mut selected_resource,
        mut confirmation,
        mut join_link,
        mut loading,
        mut status,
        locale,
        mut selected_mesh,
        ..
    } = *state;
    #[cfg(target_arch = "wasm32")]
    let route_navigator = use_navigator();
    use_callback(move |operation: BrowserOperation| {
        #[cfg(target_arch = "wasm32")]
        {
            if *loading.peek() {
                return;
            }
            let mut operation_location = loaded_location.peek().clone();
            let operation_generation = *generation.peek();
            let api = browser_api_client();
            let current = snapshot.read().clone();
            let entered_name = if matches!(
                operation,
                BrowserOperation::DeletePeer | BrowserOperation::DeleteMesh
            ) {
                confirmation.read().clone()
            } else {
                name.read().clone()
            };
            let entered_document = document.read().clone();
            let selected = selected_resource.read().clone();
            if route == ConsoleRoute::JoinTickets && operation == BrowserOperation::Create {
                join_link.set(String::new());
            }
            loading.set(true);
            snapshot.write().error = None;
            status.set(console_message(locale(), "saving").into());
            spawn(async move {
                let result = apply_browser_operation(
                    &api,
                    route,
                    &current,
                    operation,
                    &entered_name,
                    &entered_document,
                    &selected,
                    locale(),
                )
                .await;
                if *loaded_location.peek() != operation_location
                    || *generation.peek() != operation_generation
                {
                    return;
                }
                match result {
                    Ok(created_link) => {
                        if matches!(
                            operation,
                            BrowserOperation::Delete
                                | BrowserOperation::DeletePeer
                                | BrowserOperation::DeleteMesh
                                | BrowserOperation::ActivateCredential
                                | BrowserOperation::RevokeCredential
                                | BrowserOperation::ActivateAuthority
                        ) {
                            confirmation.set(String::new());
                        }
                        if matches!(
                            operation,
                            BrowserOperation::DeletePeer | BrowserOperation::DeleteMesh
                        ) {
                            snapshot
                                .write()
                                .resources
                                .retain(|resource| resource.id != selected);
                            selected_resource.set(String::new());
                            name.set(String::new());
                            document.set(default_editor_document(route));
                        }
                        if operation == BrowserOperation::DeleteMesh {
                            snapshot.write().meshes.retain(|mesh| mesh.id != selected);
                            selected_mesh.set(String::new());
                            snapshot.write().mesh_id.clear();
                            operation_location =
                                ConsoleLocation::new(ConsoleRoute::Meshes, None, None);
                            loaded_location.set(operation_location.clone());
                            route_navigator
                                .replace(ConsoleClientRoute::Meshes { mesh: None }.href());
                        }
                        if let Some(created_link) = created_link {
                            if matches!(
                                operation,
                                BrowserOperation::ValidatePolicy | BrowserOperation::SimulatePolicy
                            ) {
                                status.set(created_link);
                                loading.set(false);
                                return;
                            }
                            join_link.set(created_link);
                            status.set(console_message(locale(), "join-created").into());
                        } else {
                            // The write is committed even when the following read fails.
                            status.set(console_message(locale(), "saved").into());
                        }
                        match api
                            .route_snapshot_filtered(
                                route,
                                (operation != BrowserOperation::DeleteMesh
                                    && !current.mesh_id.is_empty())
                                .then_some(current.mesh_id.as_str()),
                                None,
                                current.relay_filter.as_deref(),
                            )
                            .await
                        {
                            Ok(value)
                                if *loaded_location.peek() == operation_location
                                    && *generation.peek() == operation_generation =>
                            {
                                if let Some(resource) = value
                                    .resources
                                    .iter()
                                    .find(|resource| resource.id == selected)
                                {
                                    name.set(resource.name.clone());
                                    document.set(editor_document_for_resource(route, resource));
                                }
                                snapshot.set(value);
                                if join_link.peek().is_empty() {
                                    status.set(console_message(locale(), "saved").into());
                                }
                            }
                            Err(error)
                                if *loaded_location.peek() == operation_location
                                    && *generation.peek() == operation_generation =>
                            {
                                status.set(console_message(locale(), "saved-refresh-failed").into());
                                snapshot.write().error = Some(api_error_body(error));
                            }
                            Ok(_) | Err(_) => return,
                        }
                    }
                    Err(error)
                        if *loaded_location.peek() == operation_location
                            && *generation.peek() == operation_generation =>
                    {
                        status.set(String::new());
                        snapshot.write().error = Some(api_error_body(error));
                    }
                    Err(_) => {}
                }
                if *loaded_location.peek() == operation_location
                    && *generation.peek() == operation_generation
                {
                    loading.set(false);
                }
            });
        }
        #[cfg(not(target_arch = "wasm32"))]
        let _ = (route, operation);
    })
}
