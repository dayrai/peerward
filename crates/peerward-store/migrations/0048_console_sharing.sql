ALTER TABLE services ADD COLUMN display_name text NOT NULL DEFAULT '' CHECK(length(display_name)<=128);
ALTER TABLE services ADD COLUMN console_paused boolean NOT NULL DEFAULT false;
ALTER TABLE network_resources ADD COLUMN console_paused boolean NOT NULL DEFAULT false;

-- Managed service grants retain collection references. Their compiled rules are
-- derived on publication, so an empty group never becomes an unrestricted source.
CREATE TABLE console_service_grants (
    mesh_id uuid NOT NULL,
    id uuid NOT NULL CHECK(peerward_uuid_v4(id)),
    service_id uuid NOT NULL,
    source jsonb NOT NULL,
    source_collections uuid[] NOT NULL DEFAULT '{}',
    priority bigint NOT NULL DEFAULT 1000 CHECK(priority BETWEEN 0 AND 4294967295),
    enabled boolean NOT NULL DEFAULT true,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(mesh_id,id),
    FOREIGN KEY(mesh_id,service_id) REFERENCES services(mesh_id,id) ON DELETE CASCADE
);
CREATE TRIGGER console_service_grants_version BEFORE UPDATE ON console_service_grants
FOR EACH ROW EXECUTE FUNCTION peerward_increment_resource_version();

CREATE TABLE console_sharing_requests (
    mesh_id uuid NOT NULL REFERENCES meshes(id) ON DELETE CASCADE,
    request_id uuid NOT NULL CHECK(peerward_uuid_v4(request_id)),
    actor text NOT NULL,
    digest text NOT NULL,
    response jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(mesh_id,request_id)
);
