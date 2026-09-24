CREATE TABLE public.network_collections (
    id uuid PRIMARY KEY CHECK(public.peerward_uuid_v4(id)),
    mesh_id uuid NOT NULL REFERENCES public.meshes(id) ON DELETE CASCADE,
    version bigint NOT NULL DEFAULT 1 CHECK(version>0),
    definition jsonb NOT NULL CHECK(definition->>'kind' IN ('devices','resources')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX network_collections_page ON public.network_collections(mesh_id,created_at,id);
CREATE TRIGGER network_collections_version BEFORE UPDATE ON public.network_collections
    FOR EACH ROW EXECUTE FUNCTION public.peerward_increment_resource_version();
-- Resolved membership is signed alongside resource policy. Its component version
-- must change with labels/admission, even if no resource definition was edited.
CREATE FUNCTION public.peerward_collection_membership_changed() RETURNS trigger
LANGUAGE plpgsql SET search_path=public,pg_temp AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        UPDATE meshes SET management_revision=management_revision+1 WHERE id=OLD.mesh_id;
        RETURN OLD;
    END IF;
    IF TG_OP='INSERT' OR NEW.labels IS DISTINCT FROM OLD.labels
        OR NEW.administrative_state IS DISTINCT FROM OLD.administrative_state THEN
        IF NEW.administrative_state='enabled' AND EXISTS (
            SELECT 1 FROM network_collections g JOIN peers p ON p.mesh_id=g.mesh_id
                AND p.administrative_state='enabled'
                AND (g.definition->'members' @> jsonb_build_array(p.id)
                    OR (COALESCE(g.definition->'labels','{}'::jsonb)<>'{}'::jsonb
                        AND p.labels @> (g.definition->'labels')))
            WHERE g.mesh_id=NEW.mesh_id AND g.definition->>'kind'='devices'
            GROUP BY g.id HAVING count(*)>4096
        ) THEN
            RAISE EXCEPTION 'resolved device collection exceeds 4096 members' USING ERRCODE='23514';
        END IF;
        UPDATE meshes SET management_revision=management_revision+1 WHERE id=NEW.mesh_id;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER peer_collection_membership AFTER INSERT OR UPDATE OR DELETE ON public.peers
    FOR EACH ROW EXECUTE FUNCTION public.peerward_collection_membership_changed();
