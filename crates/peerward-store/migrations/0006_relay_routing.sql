ALTER TABLE public.relays
    ADD COLUMN region text NOT NULL DEFAULT 'default',
    ADD COLUMN routing_weight integer NOT NULL DEFAULT 100,
    ADD CONSTRAINT relays_region_check CHECK (
        region ~ '^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$'
    ),
    ADD CONSTRAINT relays_routing_weight_check CHECK (routing_weight BETWEEN 1 AND 1000);

CREATE INDEX relays_mesh_region_id_idx ON public.relays(mesh_id, region, id);
CREATE INDEX relay_presence_topology_page_idx
    ON public.relay_presence(mesh_id, peer_id, relay_id, role);
CREATE INDEX relay_presence_relay_peer_idx
    ON public.relay_presence(mesh_id, relay_id, peer_id);

ALTER TABLE public.relay_runtime_leases
    ADD COLUMN wire_capabilities bigint NOT NULL DEFAULT 0 CHECK (wire_capabilities >= 0),
    ADD COLUMN neighbor_health jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (
        jsonb_typeof(neighbor_health) = 'array' AND pg_column_size(neighbor_health) <= 65536
    );

ALTER TABLE public.signed_state_revisions
    DROP CONSTRAINT signed_state_revisions_kind_check,
    ADD CONSTRAINT signed_state_revisions_kind_check CHECK (
        kind = ANY (ARRAY[
            'authorities'::text, 'peers'::text, 'relays'::text, 'policy'::text,
            'services'::text, 'revocations'::text, 'relay_topology'::text
        ])
    );

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
        SELECT count(*) FROM relay_presence presence
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
