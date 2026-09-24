-- Declarative revision changes only for management intent and its identity
-- dependencies, independently of rapidly refreshed leases/route observations.
CREATE TABLE configuration_ownership (
    mesh_id uuid PRIMARY KEY REFERENCES meshes(id) ON DELETE CASCADE,
    version bigint NOT NULL DEFAULT 1 CHECK(version>0),
    owner_machine_id uuid,
    FOREIGN KEY(mesh_id,owner_machine_id) REFERENCES machine_credentials(mesh_id,id),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO configuration_ownership(mesh_id) SELECT id FROM meshes;
CREATE TRIGGER configuration_ownership_version BEFORE UPDATE ON configuration_ownership
    FOR EACH ROW EXECUTE FUNCTION peerward_increment_resource_version();
CREATE FUNCTION peerward_initialize_configuration_ownership() RETURNS trigger
LANGUAGE plpgsql SET search_path=public,pg_temp AS $$
BEGIN
    INSERT INTO configuration_ownership(mesh_id) VALUES(NEW.id);
    RETURN NEW;
END;
$$;
CREATE TRIGGER initialize_configuration_ownership AFTER INSERT ON meshes
    FOR EACH ROW EXECUTE FUNCTION peerward_initialize_configuration_ownership();

-- Response retry is bound to the request digest and original authority; no
-- secrets, signed grants, addresses or live sessions belong in declarations.
CREATE TABLE configuration_applications (
    mesh_id uuid NOT NULL REFERENCES meshes(id) ON DELETE CASCADE,
    request_id uuid NOT NULL CHECK(peerward_uuid_v4(request_id)),
    actor text NOT NULL,
    request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
    response jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(mesh_id,request_id)
);
