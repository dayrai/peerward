-- Additive migration: the historical installation baseline remains unchanged.
ALTER TABLE public.peerward_installation DROP CONSTRAINT peerward_installation_wire_major_check;
UPDATE public.peerward_installation SET wire_major=3;
ALTER TABLE public.peerward_installation ADD CONSTRAINT peerward_installation_wire_major_check CHECK(wire_major=3);

ALTER TABLE public.meshes
    ADD COLUMN lifecycle text NOT NULL DEFAULT 'active' CHECK(lifecycle IN ('creating','active','deleting','deleted')),
    ADD COLUMN lifecycle_revision bigint NOT NULL DEFAULT 1 CHECK(lifecycle_revision>0);

CREATE TABLE public.relay_hosts (
    id uuid PRIMARY KEY CHECK(public.peerward_uuid_v4(id)),
    name text NOT NULL CHECK(octet_length(name) BETWEEN 1 AND 128),
    certificate_sha256 bytea UNIQUE NOT NULL CHECK(octet_length(certificate_sha256)=32),
    peer_endpoints text[] NOT NULL CHECK(cardinality(peer_endpoints)>0),
    backbone_endpoints text[] NOT NULL CHECK(cardinality(backbone_endpoints)>0),
    enabled boolean NOT NULL DEFAULT true,
    is_default boolean NOT NULL DEFAULT false,
    revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
    last_seen timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE UNIQUE INDEX relay_hosts_one_default ON public.relay_hosts(is_default) WHERE is_default;

-- Deliberately retains assignments until the owning host has removed its keys.
CREATE TABLE public.relay_host_assignments (
    host_id uuid NOT NULL REFERENCES public.relay_hosts(id),
    mesh_id uuid NOT NULL CHECK(public.peerward_uuid_v4(mesh_id)),
    relay_id uuid UNIQUE NOT NULL CHECK(public.peerward_uuid_v4(relay_id)),
    desired text NOT NULL DEFAULT 'active' CHECK(desired IN ('active','removed')),
    revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
    applied_revision bigint NOT NULL DEFAULT 0 CHECK(applied_revision>=0 AND applied_revision<=revision),
    state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','ready','failed','removed')),
    public_key bytea CHECK(octet_length(public_key)=32),
    credential bytea,
    error_code text CHECK(octet_length(error_code)<=128),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(host_id,mesh_id)
);
CREATE INDEX relay_host_assignments_mesh ON public.relay_host_assignments(mesh_id);

CREATE TABLE public.mesh_lifecycle_jobs (
    id uuid PRIMARY KEY CHECK(public.peerward_uuid_v4(id)),
    mesh_id uuid NOT NULL CHECK(public.peerward_uuid_v4(mesh_id)),
    operation text NOT NULL CHECK(operation IN ('create','delete')),
    request jsonb NOT NULL,
    actor text NOT NULL,
    status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','waiting','failed','succeeded')),
    stage text NOT NULL DEFAULT 'queued',
    error_code text CHECK(octet_length(error_code)<=128),
    generation bigint NOT NULL DEFAULT 0 CHECK(generation>=0),
    attempt integer NOT NULL DEFAULT 0 CHECK(attempt>=0),
    lease_owner uuid,
    lease_until timestamptz,
    next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE(mesh_id,operation)
);
CREATE INDEX mesh_lifecycle_jobs_queue ON public.mesh_lifecycle_jobs(next_attempt_at,created_at)
    WHERE status IN ('queued','running','waiting');

-- These public signed records and immutable audit history outlive all secrets.
CREATE TABLE public.mesh_tombstones (
    mesh_id uuid PRIMARY KEY CHECK(public.peerward_uuid_v4(mesh_id)),
    name text NOT NULL,
    revision bigint NOT NULL CHECK(revision>0),
    root_public_key bytea NOT NULL CHECK(octet_length(root_public_key)=32),
    termination bytea NOT NULL CHECK(octet_length(termination)=228),
    terminated_at timestamptz NOT NULL,
    cleaned_at timestamptz
);

-- A deleting Mesh can never be reactivated by a delayed task or publisher.
CREATE FUNCTION public.peerward_mesh_lifecycle_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.lifecycle IN ('deleting','deleted') AND NEW.lifecycle NOT IN ('deleting','deleted') THEN
        RAISE EXCEPTION 'mesh is terminal' USING ERRCODE='23514';
    END IF;
    IF NEW.lifecycle_revision < OLD.lifecycle_revision OR
       (NEW.lifecycle <> OLD.lifecycle AND NEW.lifecycle_revision <= OLD.lifecycle_revision) THEN
        RAISE EXCEPTION 'mesh lifecycle revision must advance' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER mesh_lifecycle_guard BEFORE UPDATE ON public.meshes
    FOR EACH ROW EXECUTE FUNCTION public.peerward_mesh_lifecycle_guard();

-- Serialize ordinary child writes against the parent lifecycle transition.
CREATE FUNCTION public.peerward_live_mesh_write() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE state text;
BEGIN
    SELECT lifecycle INTO state FROM public.meshes WHERE id=NEW.mesh_id FOR SHARE;
    IF state IS NULL OR state IN ('deleting','deleted') OR
       (state='creating' AND TG_TABLE_NAME IN ('peers','join_tickets','peer_credentials','services','peer_credential_rotation_requests')) THEN
        RAISE EXCEPTION 'mesh is not active for this operation' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
DO $$
DECLARE relation text;
BEGIN
    FOREACH relation IN ARRAY ARRAY['mesh_authorities','relays','relay_credentials','signed_state_revisions',
        'peers','join_tickets','peer_credentials','services','peer_credential_rotation_requests','policies','policy_rules'] LOOP
        EXECUTE format('CREATE TRIGGER mesh_live_write BEFORE INSERT OR UPDATE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.peerward_live_mesh_write()',relation);
    END LOOP;
END $$;
