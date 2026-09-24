-- Static names and Peer/Service names share one atomic namespace reservation.
-- Multiple scoped DNS profiles may mention a name, but cannot impersonate a Peer.
ALTER TABLE public.mesh_names DROP CONSTRAINT mesh_names_owner_kind_check;
ALTER TABLE public.mesh_names ADD CONSTRAINT mesh_names_owner_kind_check
    CHECK(owner_kind IN ('peer','service','dns'));
ALTER TABLE public.mesh_names DROP CONSTRAINT mesh_names_mesh_id_owner_kind_owner_id_key;
CREATE UNIQUE INDEX mesh_names_device_owner ON public.mesh_names(mesh_id,owner_kind,owner_id)
    WHERE owner_kind<>'dns';

CREATE FUNCTION public.peerward_sync_static_dns_names(target_mesh uuid) RETURNS void
LANGUAGE plpgsql SET search_path=public,pg_temp AS $$
DECLARE suffix text;
BEGIN
    SELECT dns_suffix INTO suffix FROM meshes WHERE id=target_mesh FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;
    DELETE FROM mesh_names WHERE mesh_id=target_mesh AND owner_kind='dns';
    INSERT INTO mesh_names(mesh_id,normalized_name,owner_kind,owner_id)
        SELECT DISTINCT target_mesh,left(name,-length(suffix)-1),'dns',target_mesh
        FROM dns_profiles p CROSS JOIN LATERAL jsonb_object_keys(p.profile->'records') AS names(name)
        WHERE p.mesh_id=target_mesh AND right(name,length(suffix)+1)='.'||suffix
          AND left(name,-length(suffix)-1) ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$';
END;
$$;
CREATE FUNCTION public.peerward_dns_profile_names() RETURNS trigger
LANGUAGE plpgsql SET search_path=public,pg_temp AS $$
BEGIN
    IF TG_OP='DELETE' THEN PERFORM peerward_sync_static_dns_names(OLD.mesh_id); RETURN OLD; END IF;
    PERFORM peerward_sync_static_dns_names(NEW.mesh_id); RETURN NEW;
END;
$$;
CREATE TRIGGER dns_profile_names AFTER INSERT OR UPDATE OR DELETE ON public.dns_profiles
    FOR EACH ROW EXECUTE FUNCTION public.peerward_dns_profile_names();
CREATE FUNCTION public.peerward_dns_suffix_names() RETURNS trigger
LANGUAGE plpgsql SET search_path=public,pg_temp AS $$
BEGIN
    PERFORM peerward_sync_static_dns_names(NEW.id); RETURN NEW;
END;
$$;
CREATE TRIGGER dns_suffix_names AFTER UPDATE OF dns_suffix ON public.meshes
    FOR EACH ROW WHEN (OLD.dns_suffix IS DISTINCT FROM NEW.dns_suffix)
    EXECUTE FUNCTION public.peerward_dns_suffix_names();
SELECT public.peerward_sync_static_dns_names(id) FROM public.meshes;
