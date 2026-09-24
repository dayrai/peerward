-- Count failures independently from successful polling while a Relay is offline.
ALTER TABLE public.mesh_lifecycle_jobs ADD COLUMN consecutive_failures integer NOT NULL DEFAULT 0
    CHECK(consecutive_failures>=0);

CREATE FUNCTION public.peerward_terminal_mesh_edit_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.lifecycle IN ('deleting','deleted') AND
       (NEW.name<>OLD.name OR NEW.dns_suffix<>OLD.dns_suffix) THEN
        RAISE EXCEPTION 'mesh is terminal' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER mesh_terminal_edit_guard BEFORE UPDATE ON public.meshes
    FOR EACH ROW EXECUTE FUNCTION public.peerward_terminal_mesh_edit_guard();
