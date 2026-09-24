-- Fresh Schema 4 installations allocate one address in each family atomically.
ALTER TABLE public.meshes ADD COLUMN secondary_cidr cidr;
ALTER TABLE public.meshes ADD COLUMN secondary_gateway inet;
ALTER TABLE public.meshes ADD COLUMN secondary_next_address inet;
CREATE FUNCTION public.peerward_mesh_dual_stack() RETURNS trigger
LANGUAGE plpgsql SET search_path=public,pg_temp AS $$
DECLARE
    candidate cidr;
    random_hex text;
    slot integer;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('mesh-prefix-allocation',0));
    IF TG_OP='UPDATE' AND (NEW.address_cidr IS DISTINCT FROM OLD.address_cidr
        OR NEW.secondary_cidr IS DISTINCT FROM OLD.secondary_cidr
        OR NEW.gateway IS DISTINCT FROM OLD.gateway
        OR NEW.secondary_gateway IS DISTINCT FROM OLD.secondary_gateway) THEN
        RAISE EXCEPTION 'address pools cannot change on an existing Mesh' USING ERRCODE='23514';
    END IF;
    IF NEW.secondary_cidr IS NULL THEN
        FOR attempt IN 1..16384 LOOP
            random_hex := replace(gen_random_uuid()::text,'-','');
            IF family(NEW.address_cidr)=4 THEN
                candidate := ('fd'||substr(random_hex,1,2)||':'||substr(random_hex,3,4)||':'||substr(random_hex,7,4)||':'||substr(random_hex,11,4)||'::/64')::cidr;
            ELSE
                slot := (('x'||substr(random_hex,1,4))::bit(16)::integer + attempt) % 16384;
                candidate := ('100.'||(64+slot/256)||'.'||(slot%256)||'.0/24')::cidr;
            END IF;
            EXIT WHEN NOT EXISTS(SELECT 1 FROM meshes WHERE id<>NEW.id
                AND (address_cidr && candidate OR secondary_cidr && candidate));
            candidate := NULL;
        END LOOP;
        IF candidate IS NULL THEN
            RAISE EXCEPTION 'secondary address pool exhausted' USING ERRCODE='23514';
        END IF;
        NEW.secondary_cidr := candidate;
        NEW.secondary_gateway := set_masklen(candidate::inet+1,CASE WHEN family(candidate)=4 THEN 32 ELSE 128 END);
    END IF;
    IF family(NEW.secondary_cidr)=family(NEW.address_cidr)
        OR NOT (NEW.secondary_gateway <<= NEW.secondary_cidr)
        OR family(NEW.secondary_gateway)<>family(NEW.secondary_cidr) THEN
        RAISE EXCEPTION 'invalid secondary address pool' USING ERRCODE='23514';
    END IF;
    IF TG_OP='INSERT' AND EXISTS(SELECT 1 FROM meshes WHERE id<>NEW.id
        AND (secondary_cidr && NEW.address_cidr
            OR address_cidr && NEW.secondary_cidr OR secondary_cidr && NEW.secondary_cidr)) THEN
        RAISE EXCEPTION 'Mesh address pool overlaps an existing Mesh' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER mesh_dual_stack BEFORE INSERT OR UPDATE OF address_cidr,secondary_cidr,gateway,secondary_gateway ON public.meshes
    FOR EACH ROW EXECUTE FUNCTION public.peerward_mesh_dual_stack();
-- The migration chain is run before initial provisioning. No historical rows or
-- installed client profiles are transformed into partially assigned dual stacks.
ALTER TABLE public.meshes ALTER COLUMN secondary_cidr SET NOT NULL;
ALTER TABLE public.meshes ALTER COLUMN secondary_gateway SET NOT NULL;
DROP INDEX public.peer_addresses_one_active_peer_uq;
CREATE UNIQUE INDEX peer_addresses_one_active_family_uq ON public.peer_addresses(mesh_id,peer_id,(family(address))) WHERE state='active';

-- Address reuse must outlive every lease already issued, including a longer
-- lease issued before the administrator shortened the configured duration.
CREATE TABLE public.mesh_authorization_bounds (
    mesh_id uuid PRIMARY KEY REFERENCES public.meshes(id) ON DELETE CASCADE,
    valid_until timestamptz NOT NULL
);
CREATE FUNCTION public.peerward_address_quarantine_bound() RETURNS trigger
LANGUAGE plpgsql SET search_path=public,pg_temp AS $$
DECLARE
    upper_bound timestamptz;
BEGIN
    IF OLD.state='active' AND NEW.state='quarantine' THEN
        SELECT valid_until INTO upper_bound FROM mesh_authorization_bounds WHERE mesh_id=NEW.mesh_id;
        -- Matches the protocol's 30-second clock tolerance plus a 1-second
        -- packet-loop scheduling allowance. This is an address reuse bound.
        NEW.quarantine_until := GREATEST(NEW.quarantine_until,upper_bound+interval '31 seconds');
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER address_quarantine_bound BEFORE UPDATE ON public.peer_addresses
    FOR EACH ROW EXECUTE FUNCTION public.peerward_address_quarantine_bound();
