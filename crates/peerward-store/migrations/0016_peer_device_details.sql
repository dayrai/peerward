-- Device descriptions are not policy labels or inferred physical locations.
ALTER TABLE public.peers
    ADD COLUMN display_name text NOT NULL DEFAULT '' CHECK (char_length(display_name) <= 128),
    ADD COLUMN location text NOT NULL DEFAULT '' CHECK (char_length(location) <= 128);

-- Retain assigned addresses for offline Peers, excluding released/quarantined allocations.
CREATE OR REPLACE FUNCTION public.peerward_peer_api_json(peer public.peers) RETURNS jsonb
    LANGUAGE sql STABLE
    SET search_path = pg_catalog, public, pg_temp
    AS $$
    SELECT jsonb_build_object(
      'id',peer.id,'name',peer.name,'labels',peer.labels,
      'display_name',peer.display_name,'location',peer.location,
      'mesh_addresses',COALESCE((SELECT jsonb_agg(host(allocation.address) ORDER BY allocation.address)
        FROM public.peer_addresses allocation
        WHERE allocation.mesh_id=peer.mesh_id AND allocation.peer_id=peer.id
          AND allocation.state='active'),'[]'::jsonb),
      'administrative_state',peer.administrative_state,
      'online',peer.administrative_state='enabled' AND EXISTS(
        SELECT 1 FROM relay_presence_all presence
        JOIN relays relay ON relay.mesh_id=presence.mesh_id
          AND relay.id=presence.relay_id
          AND relay.administrative_state='enabled'
        JOIN relay_runtime_leases runtime ON runtime.mesh_id=presence.mesh_id
          AND runtime.relay_id=presence.relay_id
          AND runtime.lease_deadline>clock_timestamp()
        WHERE presence.mesh_id=peer.mesh_id AND presence.peer_id=peer.id
          AND presence.lease_deadline>clock_timestamp()),
      'presence',COALESCE((SELECT jsonb_agg(jsonb_build_object(
        'relay_id',presence.relay_id,'role',presence.role,
        'generation',presence.fencing_generation,
        'lease_deadline',presence.lease_deadline) ORDER BY presence.role,presence.relay_id)
        FROM relay_presence_all presence
        JOIN relays relay ON relay.mesh_id=presence.mesh_id
          AND relay.id=presence.relay_id
          AND relay.administrative_state='enabled'
        JOIN relay_runtime_leases runtime ON runtime.mesh_id=presence.mesh_id
          AND runtime.relay_id=presence.relay_id
          AND runtime.lease_deadline>clock_timestamp()
        WHERE presence.mesh_id=peer.mesh_id AND presence.peer_id=peer.id
          AND peer.administrative_state='enabled'
          AND presence.lease_deadline>clock_timestamp()),'[]'::jsonb),
      'credentials',jsonb_build_object(
        'active',(SELECT jsonb_build_object('serial',credential.serial,
          'not_after',credential.not_after) FROM peer_credentials credential
          WHERE credential.mesh_id=peer.mesh_id AND credential.peer_id=peer.id
            AND credential.lifecycle='active'),
        'pending',(SELECT jsonb_build_object('serial',credential.serial,
          'not_after',credential.not_after) FROM peer_credentials credential
          WHERE credential.mesh_id=peer.mesh_id AND credential.peer_id=peer.id
            AND credential.lifecycle='staged' ORDER BY credential.created_at DESC LIMIT 1),
        'overlap',COALESCE((SELECT jsonb_agg(jsonb_build_object(
          'serial',credential.serial,'overlap_deadline',credential.overlap_deadline)
          ORDER BY credential.created_at) FROM peer_credentials credential
          WHERE credential.mesh_id=peer.mesh_id AND credential.peer_id=peer.id
            AND credential.lifecycle='overlap'),'[]'::jsonb))
    )
$$;

