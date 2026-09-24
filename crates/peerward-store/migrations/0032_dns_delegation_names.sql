-- Explicit child DNS authorities must reserve their first-level Mesh label too.
-- Otherwise a later Peer registration could silently shadow (or be shadowed by)
-- an already approved namespace. Historical migrations remain unchanged.
CREATE OR REPLACE FUNCTION public.peerward_sync_static_dns_names(target_mesh uuid) RETURNS void
LANGUAGE plpgsql SET search_path=public,pg_temp AS $$
DECLARE suffix text;
BEGIN
    SELECT dns_suffix INTO suffix FROM meshes WHERE id=target_mesh FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;
    DELETE FROM mesh_names WHERE mesh_id=target_mesh AND owner_kind='dns';
    INSERT INTO mesh_names(mesh_id,normalized_name,owner_kind,owner_id)
        SELECT DISTINCT target_mesh,left(name,-length(suffix)-1),'dns',target_mesh
        FROM (
            SELECT jsonb_object_keys(p.profile->'records') AS name FROM dns_profiles p WHERE p.mesh_id=target_mesh
            UNION
            SELECT route->>'suffix' AS name FROM dns_profiles p CROSS JOIN LATERAL jsonb_array_elements(p.profile->'routes') AS route WHERE p.mesh_id=target_mesh
        ) AS names
        WHERE right(name,length(suffix)+1)='.'||suffix
          AND left(name,-length(suffix)-1) ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$';
END;
$$;
SELECT public.peerward_sync_static_dns_names(id) FROM public.meshes;
