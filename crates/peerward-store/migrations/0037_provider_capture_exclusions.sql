-- Route capture history grants no forwarding or packet permission. A removed
-- gateway must not install a tunnel route over its own still-connected LAN.
CREATE TABLE provider_capture_exclusions (
    mesh_id uuid NOT NULL REFERENCES meshes(id) ON DELETE CASCADE,
    target jsonb NOT NULL CHECK(jsonb_typeof(target)='object'),
    providers jsonb NOT NULL CHECK(jsonb_typeof(providers)='array'),
    PRIMARY KEY(mesh_id,target)
);
CREATE FUNCTION preserve_provider_capture_exclusion() RETURNS trigger
LANGUAGE plpgsql SET search_path=public,pg_temp AS $$
DECLARE original_target jsonb;
BEGIN
    SELECT definition->'target' INTO original_target FROM network_resources
        WHERE mesh_id=OLD.mesh_id AND id=OLD.resource_id;
    IF original_target IS NOT NULL AND original_target->>'kind'='subnet' THEN
        INSERT INTO provider_capture_exclusions(mesh_id,target,providers)
            VALUES(OLD.mesh_id,original_target,jsonb_build_array(OLD.peer_id))
            ON CONFLICT(mesh_id,target) DO UPDATE SET providers=(
                SELECT jsonb_agg(value ORDER BY value)
                FROM (SELECT DISTINCT value FROM jsonb_array_elements(provider_capture_exclusions.providers || EXCLUDED.providers)) combined
            );
    END IF;
    RETURN OLD;
END;
$$;
CREATE TRIGGER preserve_provider_capture BEFORE DELETE ON gateway_bindings
    FOR EACH ROW EXECUTE FUNCTION preserve_provider_capture_exclusion();
