-- Fixed Linux runner operations. The Control process never obtains Docker/shell access.
CREATE TABLE public.deployment_runners (
    id uuid PRIMARY KEY CHECK(public.peerward_uuid_v4(id)),
    name text NOT NULL CHECK(octet_length(name) BETWEEN 1 AND 128),
    profile_digest text NOT NULL CHECK(profile_digest ~ '^[0-9a-f]{64}$'),
    token_digest bytea UNIQUE NOT NULL CHECK(octet_length(token_digest)=32),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    version bigint NOT NULL DEFAULT 1 CHECK(version>0),
    last_seen timestamptz,
    preview jsonb,
    preview_at timestamptz,
    exchange_sequence bigint NOT NULL DEFAULT 0 CHECK(exchange_sequence>=0),
    exchange_digest bytea,
    exchange_response jsonb,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE public.deployment_tasks (
    id uuid PRIMARY KEY CHECK(public.peerward_uuid_v4(id)),
    runner_id uuid NOT NULL REFERENCES public.deployment_runners(id),
    operation text NOT NULL DEFAULT 'installation_backup' CHECK(operation='installation_backup'),
    request jsonb NOT NULL,
    actor text NOT NULL,
    preview jsonb NOT NULL,
    profile_digest text NOT NULL CHECK(profile_digest ~ '^[0-9a-f]{64}$'),
    version bigint NOT NULL DEFAULT 1 CHECK(version>0),
    status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','recovery_required','failed','succeeded','cancelled')),
    stage text NOT NULL DEFAULT 'queued',
    local_version bigint NOT NULL DEFAULT 0 CHECK(local_version>=0),
    report jsonb,
    reported_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE UNIQUE INDEX deployment_one_active_task ON public.deployment_tasks(runner_id)
    WHERE status IN ('queued','running','recovery_required');
CREATE INDEX deployment_task_history ON public.deployment_tasks(created_at DESC,id DESC);
