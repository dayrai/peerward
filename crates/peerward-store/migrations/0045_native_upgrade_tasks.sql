-- Fixed native upgrade intentions share the existing restricted runner channel.
-- Commands, paths, signing keys and database credentials remain on the runner.
ALTER TABLE public.deployment_tasks DROP CONSTRAINT deployment_tasks_operation_check;
ALTER TABLE public.deployment_tasks ADD CONSTRAINT deployment_tasks_operation_check
    CHECK(operation IN ('installation_backup','native_upgrade'));
