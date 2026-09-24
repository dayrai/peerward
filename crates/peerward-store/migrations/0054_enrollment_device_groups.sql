-- Remove descriptive purpose without changing identities, labels or permissions.
CREATE OR REPLACE FUNCTION public.peerward_peer_api_json(peer public.peers) RETURNS jsonb
LANGUAGE sql STABLE SET search_path = pg_catalog, public, pg_temp AS $$
    SELECT public.peerward_peer_api_json_before_purpose(peer)
$$;
ALTER TABLE public.peers DROP COLUMN purpose;

-- Outstanding invitations retain every admission constraint. Purpose never
-- represented membership and must not be converted into access-bearing groups.
UPDATE public.join_tickets SET settings = settings - 'purpose'
WHERE settings ? 'purpose';
