-- Device roles are descriptions, never policy selector labels.
ALTER TABLE public.peers ADD COLUMN purpose text
    CHECK (purpose IN ('personal', 'managed', 'service', 'test'));

ALTER FUNCTION public.peerward_peer_api_json(public.peers)
    RENAME TO peerward_peer_api_json_before_purpose;
CREATE FUNCTION public.peerward_peer_api_json(peer public.peers) RETURNS jsonb
LANGUAGE sql STABLE SET search_path = pg_catalog, public, pg_temp AS $$
    SELECT public.peerward_peer_api_json_before_purpose(peer)
        || jsonb_build_object('purpose', peer.purpose)
$$;
