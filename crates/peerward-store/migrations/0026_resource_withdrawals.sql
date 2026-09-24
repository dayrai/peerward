-- Revoked address ownership is signed and survives deletion/restart. A broader
-- target or default route never silently becomes a replacement authorization.
CREATE TABLE resource_withdrawals (
    mesh_id uuid NOT NULL REFERENCES meshes(id) ON DELETE CASCADE,
    target jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (mesh_id, target)
);

CREATE FUNCTION preserve_resource_withdrawal() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (TG_OP = 'DELETE' OR NEW.definition->'target' IS DISTINCT FROM OLD.definition->'target')
        AND EXISTS (SELECT 1 FROM meshes WHERE id=OLD.mesh_id) THEN
        INSERT INTO resource_withdrawals(mesh_id,target)
            VALUES(OLD.mesh_id,OLD.definition->'target') ON CONFLICT DO NOTHING;
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER resource_withdrawal BEFORE UPDATE OR DELETE ON network_resources
    FOR EACH ROW EXECUTE FUNCTION preserve_resource_withdrawal();
