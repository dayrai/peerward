-- Acknowledgement belongs to one continuous condition, not all future failures
-- with the same text. Ordinary refresh samples retain the current generation.
ALTER TABLE public.target_health_observations
    ADD COLUMN evidence_generation uuid NOT NULL DEFAULT gen_random_uuid();
ALTER TABLE public.route_advertisements
    ADD COLUMN evidence_generation uuid NOT NULL DEFAULT gen_random_uuid();

CREATE FUNCTION public.peerward_health_evidence_generation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    IF (NEW.result, NEW.binding_version, NEW.resource_version, NEW.credential_serial)
       IS DISTINCT FROM (OLD.result, OLD.binding_version, OLD.resource_version, OLD.credential_serial)
       OR OLD.valid_until <= NEW.observed_at THEN
        NEW.evidence_generation := gen_random_uuid();
    ELSE
        NEW.evidence_generation := OLD.evidence_generation;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER target_health_evidence_generation BEFORE UPDATE ON public.target_health_observations
    FOR EACH ROW EXECUTE FUNCTION public.peerward_health_evidence_generation();

CREATE FUNCTION public.peerward_route_evidence_generation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    IF (NEW.published, NEW.forwarding_ready, NEW.binding_version, NEW.peer_id)
       IS DISTINCT FROM (OLD.published, OLD.forwarding_ready, OLD.binding_version, OLD.peer_id)
       OR OLD.valid_until <= NEW.updated_at THEN
        NEW.evidence_generation := gen_random_uuid();
    ELSE
        NEW.evidence_generation := OLD.evidence_generation;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER route_evidence_generation BEFORE UPDATE ON public.route_advertisements
    FOR EACH ROW EXECUTE FUNCTION public.peerward_route_evidence_generation();
