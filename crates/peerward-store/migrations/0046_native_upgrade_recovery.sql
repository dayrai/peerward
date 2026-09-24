ALTER TABLE public.deployment_tasks ADD COLUMN recovery_generation bigint NOT NULL DEFAULT 0 CHECK(recovery_generation>=0);
CREATE TABLE public.deployment_task_recoveries (
    request_id uuid PRIMARY KEY CHECK(public.peerward_uuid_v4(request_id)),
    task_id uuid NOT NULL REFERENCES public.deployment_tasks(id),
    expected_version bigint NOT NULL CHECK(expected_version>0),
    actor text NOT NULL,
    recovery_generation bigint NOT NULL CHECK(recovery_generation>0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
