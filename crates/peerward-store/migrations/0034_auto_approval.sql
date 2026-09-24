-- Controlled collections and exact site/prefix bounds are the only automatic authority.
CREATE TABLE auto_approval_rules (
    id uuid PRIMARY KEY CHECK(peerward_uuid_v4(id)),
    mesh_id uuid NOT NULL REFERENCES meshes(id) ON DELETE CASCADE,
    version bigint NOT NULL DEFAULT 1 CHECK(version>0),
    definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX auto_approval_rules_page ON auto_approval_rules(mesh_id,created_at,id);
CREATE TRIGGER auto_approval_rule_version BEFORE UPDATE ON auto_approval_rules
    FOR EACH ROW EXECUTE FUNCTION peerward_increment_resource_version();

-- Explicit manual decisions remove eligibility, so a later rule cannot undo a withdrawal.
CREATE TABLE gateway_auto_eligibility (
    mesh_id uuid NOT NULL,
    binding_id uuid NOT NULL,
    PRIMARY KEY(mesh_id,binding_id),
    FOREIGN KEY(mesh_id,binding_id) REFERENCES gateway_bindings(mesh_id,id) ON DELETE CASCADE
);
CREATE FUNCTION peerward_new_binding_auto_eligible() RETURNS trigger
LANGUAGE plpgsql SET search_path=public,pg_temp AS $$
BEGIN
    INSERT INTO gateway_auto_eligibility(mesh_id,binding_id) VALUES(NEW.mesh_id,NEW.id);
    RETURN NEW;
END;
$$;
CREATE TRIGGER gateway_auto_eligible AFTER INSERT ON gateway_bindings
    FOR EACH ROW EXECUTE FUNCTION peerward_new_binding_auto_eligible();
