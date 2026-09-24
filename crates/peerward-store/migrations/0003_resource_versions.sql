ALTER TABLE public.meshes ADD COLUMN version bigint NOT NULL DEFAULT 1 CHECK (version > 0);
ALTER TABLE public.peers ADD COLUMN version bigint NOT NULL DEFAULT 1 CHECK (version > 0);
ALTER TABLE public.relays ADD COLUMN version bigint NOT NULL DEFAULT 1 CHECK (version > 0);
ALTER TABLE public.join_tickets ADD COLUMN version bigint NOT NULL DEFAULT 1 CHECK (version > 0);
ALTER TABLE public.services ADD COLUMN version bigint NOT NULL DEFAULT 1 CHECK (version > 0);

CREATE FUNCTION public.peerward_increment_resource_version() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.version := OLD.version + 1;
    RETURN NEW;
END
$$;

CREATE TRIGGER meshes_increment_version BEFORE UPDATE ON public.meshes
    FOR EACH ROW EXECUTE FUNCTION public.peerward_increment_resource_version();
CREATE TRIGGER peers_increment_version BEFORE UPDATE ON public.peers
    FOR EACH ROW EXECUTE FUNCTION public.peerward_increment_resource_version();
CREATE TRIGGER relays_increment_version BEFORE UPDATE ON public.relays
    FOR EACH ROW EXECUTE FUNCTION public.peerward_increment_resource_version();
CREATE TRIGGER join_tickets_increment_version BEFORE UPDATE ON public.join_tickets
    FOR EACH ROW EXECUTE FUNCTION public.peerward_increment_resource_version();
CREATE TRIGGER services_increment_version BEFORE UPDATE ON public.services
    FOR EACH ROW EXECUTE FUNCTION public.peerward_increment_resource_version();
