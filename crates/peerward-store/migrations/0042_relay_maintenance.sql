-- Maintenance suspends a host; it never terminates a Mesh or erases its keys.
ALTER TABLE public.relay_hosts ADD COLUMN maintenance_state text NOT NULL DEFAULT 'active'
    CHECK(maintenance_state IN ('active','draining','suspended'));
ALTER TABLE public.relay_host_assignments DROP CONSTRAINT relay_host_assignments_desired_check;
ALTER TABLE public.relay_host_assignments ADD CONSTRAINT relay_host_assignments_desired_check
    CHECK(desired IN ('active','draining','suspended','removed'));
ALTER TABLE public.relay_host_assignments DROP CONSTRAINT relay_host_assignments_state_check;
ALTER TABLE public.relay_host_assignments ADD CONSTRAINT relay_host_assignments_state_check
    CHECK(state IN ('pending','ready','draining','suspended','failed','removed'));
ALTER TABLE public.relay_host_assignments ADD COLUMN observed_at timestamptz,
    ADD COLUMN active_sessions bigint CHECK(active_sessions>=0);

CREATE TABLE public.maintenance_tasks (
    id uuid PRIMARY KEY CHECK(public.peerward_uuid_v4(id)),
    host_id uuid NOT NULL REFERENCES public.relay_hosts(id),
    operation text NOT NULL CHECK(operation IN ('relay_drain','relay_resume')),
    request jsonb NOT NULL,
    actor text NOT NULL,
    version bigint NOT NULL DEFAULT 1 CHECK(version>0),
    status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','waiting','failed','succeeded')),
    stage text NOT NULL DEFAULT 'queued',
    attempt integer NOT NULL DEFAULT 1 CHECK(attempt>0),
    error_code text,
    grace_until timestamptz,
    deadline timestamptz NOT NULL DEFAULT clock_timestamp()+interval '30 minutes',
    next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE UNIQUE INDEX maintenance_one_host_task ON public.maintenance_tasks(host_id)
    WHERE status IN ('queued','waiting','failed');
CREATE INDEX maintenance_task_queue ON public.maintenance_tasks(next_attempt_at,id)
    WHERE status IN ('queued','waiting');

CREATE FUNCTION public.peerward_relay_host_admission() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE host_state text;
BEGIN
    IF TG_OP='INSERT' AND EXISTS(SELECT 1 FROM public.maintenance_tasks
        WHERE host_id=NEW.host_id AND status IN ('queued','waiting','failed')) THEN
        RAISE EXCEPTION 'Relay host has an unfinished maintenance task' USING ERRCODE='23514';
    END IF;
    IF TG_OP='INSERT' OR (NEW.desired='active' AND OLD.desired<>'active') THEN
        SELECT maintenance_state INTO host_state FROM public.relay_hosts WHERE id=NEW.host_id FOR SHARE;
        IF host_state<>'active' THEN
            RAISE EXCEPTION 'Relay host is under maintenance' USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER relay_host_admission BEFORE INSERT OR UPDATE ON public.relay_host_assignments
    FOR EACH ROW EXECUTE FUNCTION public.peerward_relay_host_admission();
