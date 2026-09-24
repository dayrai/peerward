-- Software evidence is a signed self-report, not a hardware attestation.
-- Its authorization lifetime is separate from device retirement and credentials.
CREATE TABLE device_conditions (
    mesh_id uuid PRIMARY KEY REFERENCES meshes(id) ON DELETE CASCADE,
    version bigint NOT NULL DEFAULT 1 CHECK(version>0),
    definition jsonb NOT NULL DEFAULT '{"enabled":false,"scope":{},"minimum_version":null,"platforms":[],"required_capabilities":[],"minimum_credential_seconds":0}',
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO device_conditions(mesh_id) SELECT id FROM meshes;
CREATE TRIGGER device_conditions_version BEFORE UPDATE ON device_conditions
    FOR EACH ROW EXECUTE FUNCTION peerward_increment_resource_version();
CREATE FUNCTION peerward_initialize_device_conditions() RETURNS trigger
LANGUAGE plpgsql SET search_path=public,pg_temp AS $$
BEGIN
    INSERT INTO device_conditions(mesh_id) VALUES(NEW.id);
    RETURN NEW;
END;
$$;
CREATE TRIGGER initialize_device_conditions AFTER INSERT ON meshes
    FOR EACH ROW EXECUTE FUNCTION peerward_initialize_device_conditions();

CREATE TABLE device_evidence (
    mesh_id uuid NOT NULL,
    peer_id uuid NOT NULL,
    credential_serial uuid NOT NULL,
    sequence bigint NOT NULL CHECK(sequence>0),
    evidence jsonb NOT NULL,
    observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    valid_until timestamptz NOT NULL,
    PRIMARY KEY(mesh_id,peer_id),
    FOREIGN KEY(mesh_id,peer_id) REFERENCES peers(mesh_id,id) ON DELETE CASCADE,
    CHECK(valid_until>observed_at AND valid_until<=observed_at+interval '900 seconds')
);
