-- Bounded to one row per host. Observations are telemetry, never authority.
CREATE TABLE public.relay_host_capacity (
    host_id uuid PRIMARY KEY REFERENCES public.relay_hosts(id) ON DELETE CASCADE,
    nonce uuid NOT NULL CHECK(public.peerward_uuid_v4(nonce)),
    nonce_created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_nonce uuid,
    report jsonb,
    previous_report jsonb,
    observed_at timestamptz,
    CHECK (report IS NULL OR jsonb_typeof(report)='object'),
    CHECK ((report IS NULL)=(observed_at IS NULL))
);
