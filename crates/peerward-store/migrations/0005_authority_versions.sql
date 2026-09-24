ALTER TABLE public.mesh_authorities
    ADD COLUMN version bigint NOT NULL DEFAULT 1 CHECK (version > 0);

CREATE TRIGGER mesh_authorities_increment_version
    BEFORE UPDATE ON public.mesh_authorities
    FOR EACH ROW EXECUTE FUNCTION public.peerward_increment_resource_version();
