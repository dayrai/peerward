-- Original gateways must not capture their former LAN after deletion/retargeting.
-- These exclusions grant no packet authorization. Consumers retain deny shadows.
ALTER TABLE resource_withdrawals ADD COLUMN providers jsonb NOT NULL DEFAULT '[]'::jsonb
    CHECK(jsonb_typeof(providers)='array');
CREATE OR REPLACE FUNCTION preserve_resource_withdrawal() RETURNS trigger
LANGUAGE plpgsql SET search_path=public,pg_temp AS $$
DECLARE original_providers jsonb;
BEGIN
    IF (TG_OP='DELETE' OR NEW.definition->'target' IS DISTINCT FROM OLD.definition->'target')
        AND EXISTS(SELECT 1 FROM meshes WHERE id=OLD.mesh_id) THEN
        SELECT COALESCE(jsonb_agg(peer_id ORDER BY peer_id),'[]'::jsonb) INTO original_providers
            FROM (SELECT DISTINCT peer_id FROM gateway_bindings WHERE mesh_id=OLD.mesh_id AND resource_id=OLD.id) providers;
        INSERT INTO resource_withdrawals(mesh_id,target,providers)
            VALUES(OLD.mesh_id,OLD.definition->'target',original_providers)
            ON CONFLICT(mesh_id,target) DO UPDATE SET providers=(
                SELECT COALESCE(jsonb_agg(value ORDER BY value),'[]'::jsonb)
                FROM (SELECT DISTINCT value FROM jsonb_array_elements(resource_withdrawals.providers || EXCLUDED.providers)) combined
            );
    END IF;
    IF TG_OP='DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$$;
