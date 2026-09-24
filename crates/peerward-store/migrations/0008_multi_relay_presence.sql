-- Keep relay_presence and its (mesh_id,peer_id,role) conflict target intact so
-- pre-upgrade Relay processes can continue to acquire and renew leases while
-- the fleet rolls. Upgraded Relays write every standby to this per-Relay table.
CREATE TABLE public.relay_standby_presence_v1 (
    mesh_id uuid NOT NULL,
    peer_id uuid NOT NULL,
    relay_id uuid NOT NULL,
    attachment_id uuid NOT NULL,
    fencing_generation bigint NOT NULL,
    lease_deadline timestamp with time zone NOT NULL,
    updated_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT relay_standby_presence_v1_pkey
        PRIMARY KEY (mesh_id, peer_id, relay_id),
    CONSTRAINT relay_standby_presence_v1_attachment_id_check
        CHECK (public.peerward_uuid_v4(attachment_id)),
    CONSTRAINT relay_standby_presence_v1_fencing_generation_check
        CHECK (fencing_generation > 0),
    CONSTRAINT relay_standby_presence_v1_mesh_id_peer_id_fkey
        FOREIGN KEY (mesh_id, peer_id) REFERENCES public.peers(mesh_id, id)
        ON DELETE CASCADE,
    CONSTRAINT relay_standby_presence_v1_mesh_id_relay_id_fkey
        FOREIGN KEY (mesh_id, relay_id) REFERENCES public.relays(mesh_id, id)
        ON DELETE CASCADE
);

CREATE INDEX relay_standby_presence_v1_expiry_idx
    ON public.relay_standby_presence_v1(lease_deadline, mesh_id, peer_id);
CREATE INDEX relay_standby_presence_v1_topology_page_idx
    ON public.relay_standby_presence_v1(mesh_id, peer_id, relay_id);
CREATE INDEX relay_standby_presence_v1_relay_peer_idx
    ON public.relay_standby_presence_v1(mesh_id, relay_id, peer_id);

CREATE VIEW public.relay_presence_all AS
    SELECT mesh_id,peer_id,relay_id,attachment_id,role,fencing_generation,
           lease_deadline,updated_at
      FROM public.relay_presence
     WHERE role='primary' OR NOT EXISTS (
       SELECT 1 FROM public.relay_standby_presence_v1 standby
        WHERE standby.mesh_id=relay_presence.mesh_id
          AND standby.peer_id=relay_presence.peer_id
          AND standby.relay_id=relay_presence.relay_id)
    UNION ALL
    SELECT mesh_id,peer_id,relay_id,attachment_id,'standby'::text AS role,
           fencing_generation,lease_deadline,updated_at
      FROM public.relay_standby_presence_v1;

CREATE OR REPLACE FUNCTION public.peerward_peer_api_json(peer public.peers) RETURNS jsonb
    LANGUAGE sql STABLE
    AS $$
    SELECT jsonb_build_object(
      'id',peer.id,'name',peer.name,'labels',peer.labels,
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

CREATE OR REPLACE FUNCTION public.peerward_relay_api_json(relay public.relays) RETURNS jsonb
    LANGUAGE sql STABLE
    AS $$
    SELECT jsonb_build_object(
      'id',relay.id,'name',relay.name,'peer_endpoints',relay.peer_endpoints,
      'backbone_endpoints',relay.backbone_endpoints,'region',relay.region,
      'routing_weight',relay.routing_weight,
      'administrative_state',relay.administrative_state,
      'online',relay.administrative_state='enabled' AND EXISTS(
        SELECT 1 FROM relay_runtime_leases runtime
        WHERE runtime.mesh_id=relay.mesh_id AND runtime.relay_id=relay.id
          AND runtime.lease_deadline>clock_timestamp()),
      'presence_count',CASE WHEN relay.administrative_state='enabled' AND EXISTS(
        SELECT 1 FROM relay_runtime_leases runtime
        WHERE runtime.mesh_id=relay.mesh_id AND runtime.relay_id=relay.id
          AND runtime.lease_deadline>clock_timestamp()) THEN (
        SELECT count(*) FROM relay_presence_all presence
        JOIN peers peer ON peer.mesh_id=presence.mesh_id
          AND peer.id=presence.peer_id
          AND peer.administrative_state='enabled'
        WHERE presence.mesh_id=relay.mesh_id AND presence.relay_id=relay.id
          AND presence.lease_deadline>clock_timestamp()) ELSE 0 END,
      'credentials',jsonb_build_object(
        'active',(SELECT jsonb_build_object('serial',credential.serial,
          'not_after',credential.not_after) FROM relay_credentials credential
          WHERE credential.mesh_id=relay.mesh_id AND credential.relay_id=relay.id
            AND credential.lifecycle='active'),
        'pending',(SELECT jsonb_build_object('serial',credential.serial,
          'not_after',credential.not_after) FROM relay_credentials credential
          WHERE credential.mesh_id=relay.mesh_id AND credential.relay_id=relay.id
            AND credential.lifecycle='staged' ORDER BY credential.created_at DESC LIMIT 1),
        'overlap',COALESCE((SELECT jsonb_agg(jsonb_build_object(
          'serial',credential.serial,'overlap_deadline',credential.overlap_deadline)
          ORDER BY credential.created_at) FROM relay_credentials credential
          WHERE credential.mesh_id=relay.mesh_id AND credential.relay_id=relay.id
            AND credential.lifecycle='overlap'),'[]'::jsonb))
    )
$$;
