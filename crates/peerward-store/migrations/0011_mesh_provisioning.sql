CREATE TABLE mesh_provisioning_jobs (
    id uuid PRIMARY KEY CHECK (public.peerward_uuid_v4(id)),
    mesh_id uuid UNIQUE NOT NULL CHECK (public.peerward_uuid_v4(mesh_id)),
    name text NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 128),
    existing_mesh boolean NOT NULL DEFAULT false,
    status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','failed','succeeded')),
    stage text NOT NULL DEFAULT 'queued' CHECK (stage IN ('queued','planning','credentials','database','signer','relay','health','complete')),
    error_code text CHECK (octet_length(error_code) <= 128),
    relay_endpoint text CHECK (octet_length(relay_endpoint) <= 512),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    actor text NOT NULL,
    attempt integer NOT NULL DEFAULT 0 CHECK (attempt >= 0)
);
CREATE INDEX mesh_provisioning_jobs_recent ON mesh_provisioning_jobs (created_at DESC, id DESC);
CREATE INDEX mesh_provisioning_jobs_queue ON mesh_provisioning_jobs (created_at, id) WHERE status IN ('queued','running');
