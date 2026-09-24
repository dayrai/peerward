-- Peerward 1.0 clean-install baseline. There is intentionally no 0.2 upgrade path.
SET LOCAL check_function_bodies = false;

CREATE FUNCTION public.peerward_check_peer_dns_name() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.administrative_state = 'enabled' AND EXISTS (
        SELECT 1 FROM services WHERE mesh_id = NEW.mesh_id AND state = 'enabled'
          AND lower(alias) = lower(NEW.name)
    ) THEN
        RAISE EXCEPTION 'DNS name collides with service alias' USING ERRCODE = '23505';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION public.peerward_check_service_dns_name() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.state = 'enabled' AND NEW.alias IS NOT NULL AND EXISTS (
        SELECT 1 FROM peers WHERE mesh_id = NEW.mesh_id
          AND administrative_state = 'enabled' AND lower(name) = lower(NEW.alias)
    ) THEN
        RAISE EXCEPTION 'DNS alias collides with peer name' USING ERRCODE = '23505';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION public.peerward_uuid_v4(value uuid) RETURNS boolean
    LANGUAGE sql IMMUTABLE STRICT
    AS $$
    SELECT (get_byte(uuid_send(value), 6) >> 4) = 4
       AND (get_byte(uuid_send(value), 8) & 192) = 128
$$;

CREATE FUNCTION public.peerward_valid_labels(labels jsonb) RETURNS boolean
    LANGUAGE sql IMMUTABLE STRICT
    AS $$
    SELECT jsonb_typeof(labels) = 'object'
       AND (SELECT count(*) FROM jsonb_object_keys(labels)) <= 64
       AND NOT EXISTS (
           SELECT 1 FROM jsonb_each(labels) item
           WHERE octet_length(item.key) NOT BETWEEN 1 AND 64
              OR jsonb_typeof(item.value) <> 'string'
              OR octet_length(item.value #>> '{}') NOT BETWEEN 1 AND 256
       )
$$;

CREATE TABLE public.peers (
    id uuid NOT NULL,
    mesh_id uuid NOT NULL,
    name text NOT NULL,
    labels jsonb DEFAULT '{}'::jsonb NOT NULL,
    administrative_state text DEFAULT 'enabled'::text NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT peers_administrative_state_check CHECK ((administrative_state = ANY (ARRAY['enabled'::text, 'disabled'::text, 'deleted'::text]))),
    CONSTRAINT peers_labels_check CHECK (public.peerward_valid_labels(labels)),
    CONSTRAINT peers_id_check CHECK (public.peerward_uuid_v4(id)),
    CONSTRAINT peers_name_check CHECK ((name ~ '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$'::text))
);

CREATE FUNCTION public.peerward_peer_api_json(peer public.peers) RETURNS jsonb
    LANGUAGE sql STABLE
    AS $$
    SELECT jsonb_build_object(
      'id',peer.id,'name',peer.name,'labels',peer.labels,
      'administrative_state',peer.administrative_state,
      'online',peer.administrative_state='enabled' AND EXISTS(
        SELECT 1 FROM relay_presence presence
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
        FROM relay_presence presence
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

CREATE FUNCTION public.peerward_reject_audit_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'audit records are immutable' USING ERRCODE = '55000';
END
$$;

CREATE FUNCTION public.peerward_valid_endpoint_list(endpoints text[]) RETURNS boolean
    LANGUAGE sql IMMUTABLE STRICT
    AS $$
    SELECT cardinality(endpoints) BETWEEN 1 AND 16
       AND NOT EXISTS (
           SELECT 1 FROM unnest(endpoints) endpoint
           WHERE NOT peerward_valid_network_endpoint(endpoint)
       )
       AND cardinality(endpoints) = (
           SELECT count(DISTINCT endpoint) FROM unnest(endpoints) endpoint
       )
$$;

CREATE TABLE public.relays (
    id uuid NOT NULL,
    mesh_id uuid NOT NULL,
    name text NOT NULL,
    administrative_state text DEFAULT 'enabled'::text NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    peer_endpoints text[] NOT NULL,
    backbone_endpoints text[] NOT NULL,
    CONSTRAINT relays_administrative_state_check CHECK ((administrative_state = ANY (ARRAY['enabled'::text, 'disabled'::text, 'deleted'::text]))),
    CONSTRAINT relays_backbone_endpoints_valid CHECK (public.peerward_valid_endpoint_list(backbone_endpoints)),
    CONSTRAINT relays_id_check CHECK (public.peerward_uuid_v4(id)),
    CONSTRAINT relays_name_check CHECK ((btrim(name) <> ''::text) AND (octet_length(name) <= 128)),
    CONSTRAINT relays_peer_endpoints_valid CHECK (public.peerward_valid_endpoint_list(peer_endpoints))
);

CREATE FUNCTION public.peerward_relay_api_json(relay public.relays) RETURNS jsonb
    LANGUAGE sql STABLE
    AS $$
    SELECT jsonb_build_object(
      'id',relay.id,'name',relay.name,'peer_endpoints',relay.peer_endpoints,
      'backbone_endpoints',relay.backbone_endpoints,
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

CREATE FUNCTION public.peerward_reserve_peer_name() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP IN ('UPDATE', 'DELETE') AND OLD.administrative_state = 'enabled' THEN
        DELETE FROM mesh_names WHERE mesh_id=OLD.mesh_id AND owner_kind='peer' AND owner_id=OLD.id;
    END IF;
    IF TG_OP <> 'DELETE' AND NEW.administrative_state = 'enabled' THEN
        INSERT INTO mesh_names(mesh_id,normalized_name,owner_kind,owner_id)
        VALUES(NEW.mesh_id,lower(NEW.name),'peer',NEW.id);
    END IF;
    IF TG_OP='DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION public.peerward_reserve_service_name() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP IN ('UPDATE', 'DELETE') AND OLD.state = 'enabled' AND OLD.alias IS NOT NULL THEN
        DELETE FROM mesh_names WHERE mesh_id=OLD.mesh_id AND owner_kind='service' AND owner_id=OLD.id;
    END IF;
    IF TG_OP <> 'DELETE' AND NEW.state = 'enabled' AND NEW.alias IS NOT NULL THEN
        INSERT INTO mesh_names(mesh_id,normalized_name,owner_kind,owner_id)
        VALUES(NEW.mesh_id,lower(NEW.alias),'service',NEW.id);
    END IF;
    IF TG_OP='DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION public.peerward_valid_network_endpoint(endpoint text) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE STRICT
    AS $_$
DECLARE
    authority text;
    host text;
    port_text text;
    label text;
    parsed_port integer;
BEGIN
    IF endpoint !~ '^tcp://[^/?#@]+$' THEN
        RETURN false;
    END IF;
    authority := substring(endpoint FROM 7);
    IF left(authority, 1) = '[' THEN
        IF authority !~ '^\[[0-9a-f:.]+\]:[0-9]+$' THEN
            RETURN false;
        END IF;
        host := split_part(authority, ']:', 1);
        host := substring(host FROM 2);
        port_text := split_part(authority, ']:', 2);
        IF family(host::inet) <> 6 THEN
            RETURN false;
        END IF;
    ELSE
        host := regexp_replace(authority, ':[^:]+$', '');
        port_text := substring(authority FROM ':([^:]+)$');
        IF host = authority OR host = '' OR host <> lower(host) THEN
            RETURN false;
        END IF;
        BEGIN
            IF family(host::inet) <> 4 THEN
                RETURN false;
            END IF;
        EXCEPTION WHEN invalid_text_representation THEN
            IF length(host) > 253 THEN
                RETURN false;
            END IF;
            FOREACH label IN ARRAY string_to_array(host, '.') LOOP
                IF label = '' OR length(label) > 63
                   OR label !~ '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$' THEN
                    RETURN false;
                END IF;
            END LOOP;
        END;
    END IF;
    parsed_port := port_text::integer;
    RETURN parsed_port BETWEEN 1 AND 65535 AND port_text = parsed_port::text;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
    RETURN false;
END
$_$;

CREATE FUNCTION public.peerward_valid_port_ranges(protocol_name text, spans int8range[]) RETURNS boolean
    LANGUAGE sql IMMUTABLE STRICT
    AS $$
    SELECT CASE
      WHEN protocol_name IN ('any','icmp') THEN cardinality(spans) = 0
      WHEN protocol_name IN ('tcp','udp') THEN NOT EXISTS (
        SELECT 1 FROM unnest(spans) span
        WHERE lower(span) < 1 OR upper(span) > 65536 OR isempty(span)
      )
      ELSE false
    END
$$;

CREATE FUNCTION public.peerward_check_policy_rule_count() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF (SELECT count(*) FROM policy_rules
        WHERE mesh_id=NEW.mesh_id AND policy_revision=NEW.policy_revision) >= 1024 THEN
        RAISE EXCEPTION 'policy contains too many rules' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION public.peerward_check_policy_peer_count() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF (SELECT count(*) FROM policy_rule_peers
        WHERE mesh_id=NEW.mesh_id AND policy_revision=NEW.policy_revision
          AND rule_id=NEW.rule_id AND direction=NEW.direction) >= 1024 THEN
        RAISE EXCEPTION 'policy selector contains too many peers' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TABLE public.audit_log (
    id uuid NOT NULL,
    mesh_id uuid,
    retained_mesh_id uuid,
    actor text NOT NULL,
    action text NOT NULL,
    target_type text NOT NULL,
    target_id uuid,
    occurred_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    result text NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT audit_log_check CHECK (((retained_mesh_id IS NOT NULL) OR (mesh_id IS NULL))),
    CONSTRAINT audit_log_id_check CHECK (public.peerward_uuid_v4(id)),
    CONSTRAINT audit_log_result_check CHECK ((result = ANY (ARRAY['success'::text, 'denied'::text, 'failure'::text])))
);

CREATE TABLE public.encrypted_audit_inbox (
    id uuid NOT NULL,
    mesh_id uuid NOT NULL,
    source_peer uuid NOT NULL,
    ciphertext_digest bytea NOT NULL,
    envelope bytea NOT NULL,
    received_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    claimed_until timestamp with time zone,
    attempts integer DEFAULT 0 NOT NULL,
    last_error text,
    CONSTRAINT encrypted_audit_inbox_id_check CHECK (public.peerward_uuid_v4(id)),
    CONSTRAINT encrypted_audit_inbox_digest_check CHECK (octet_length(ciphertext_digest) = 32),
    CONSTRAINT encrypted_audit_inbox_envelope_check CHECK (octet_length(envelope) BETWEEN 1 AND 65535),
    CONSTRAINT encrypted_audit_inbox_attempts_check CHECK (attempts >= 0),
    CONSTRAINT encrypted_audit_inbox_error_check CHECK (last_error IS NULL OR char_length(last_error) <= 128)
);

CREATE TABLE public.processed_peer_audit_batches (
    mesh_id uuid NOT NULL,
    source_peer uuid NOT NULL,
    batch_id uuid NOT NULL,
    processed_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT processed_peer_audit_batches_id_check CHECK (public.peerward_uuid_v4(batch_id))
);

CREATE TABLE public.bootstrap_state (
    singleton boolean DEFAULT true NOT NULL,
    completed_at timestamp with time zone NOT NULL,
    actor text NOT NULL,
    oidc_configuration jsonb NOT NULL,
    CONSTRAINT bootstrap_state_singleton_check CHECK (singleton)
);

CREATE TABLE public.event_outbox (
    sequence bigint NOT NULL,
    cursor uuid NOT NULL,
    mesh_id uuid,
    event_type text NOT NULL,
    resource_type text NOT NULL,
    resource_id uuid,
    payload jsonb NOT NULL,
    committed_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT event_outbox_cursor_check CHECK (public.peerward_uuid_v4(cursor)),
    CONSTRAINT event_outbox_payload_check CHECK (pg_column_size(payload) <= 262144)
);

CREATE TABLE public.event_stream_state (
    singleton boolean DEFAULT true NOT NULL PRIMARY KEY,
    high_water_sequence bigint DEFAULT 0 NOT NULL,
    high_water_cursor uuid,
    oldest_retained_sequence bigint DEFAULT 1 NOT NULL,
    CONSTRAINT event_stream_state_singleton_check CHECK (singleton),
    CONSTRAINT event_stream_state_high_water_check CHECK (high_water_sequence >= 0),
    CONSTRAINT event_stream_state_oldest_check CHECK (oldest_retained_sequence >= 1),
    CONSTRAINT event_stream_state_cursor_check CHECK (
        (high_water_sequence = 0 AND high_water_cursor IS NULL)
        OR (high_water_sequence > 0 AND public.peerward_uuid_v4(high_water_cursor))
    )
);

INSERT INTO public.event_stream_state(singleton) VALUES(true);

ALTER TABLE public.event_outbox ALTER COLUMN sequence ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.event_outbox_sequence_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE public.join_tickets (
    id uuid NOT NULL,
    mesh_id uuid NOT NULL,
    token_digest bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    creator text NOT NULL,
    consumed_at timestamp with time zone,
    cancelled_at timestamp with time zone,
    claimed_peer_id uuid,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    claimed_credential_id uuid,
    claim_id uuid,
    claim_request_digest bytea,
    response_document bytea,
    CONSTRAINT join_tickets_claim_id_check CHECK (((claim_id IS NULL) OR public.peerward_uuid_v4(claim_id))),
    CONSTRAINT join_tickets_claim_request_digest_check CHECK (((claim_request_digest IS NULL) OR (octet_length(claim_request_digest) = 32))),
    CONSTRAINT join_tickets_creator_check CHECK ((btrim(creator) <> ''::text)),
    CONSTRAINT join_tickets_id_check CHECK (public.peerward_uuid_v4(id)),
    CONSTRAINT join_tickets_response_document_check CHECK (((response_document IS NULL) OR (octet_length(response_document) BETWEEN 2 AND 1048576))),
    CONSTRAINT join_tickets_consumption_complete_check CHECK (
        ((consumed_at IS NULL) AND (cancelled_at IS NULL) AND (claimed_peer_id IS NULL) AND (claimed_credential_id IS NULL)
            AND (claim_id IS NULL) AND (claim_request_digest IS NULL) AND (response_document IS NULL))
        OR
        ((consumed_at IS NOT NULL) AND (cancelled_at IS NULL) AND (claimed_peer_id IS NOT NULL) AND (claimed_credential_id IS NOT NULL)
            AND (claim_id IS NOT NULL) AND (claim_request_digest IS NOT NULL) AND (response_document IS NOT NULL))
        OR
        ((consumed_at IS NULL) AND (cancelled_at IS NOT NULL) AND (claimed_peer_id IS NULL) AND (claimed_credential_id IS NULL)
            AND (claim_id IS NULL) AND (claim_request_digest IS NULL) AND (response_document IS NULL))
    ),
    CONSTRAINT join_tickets_token_digest_check CHECK ((octet_length(token_digest) = 32))
);

CREATE TABLE public.mesh_authorities (
    id uuid NOT NULL,
    mesh_id uuid NOT NULL,
    serial uuid NOT NULL,
    public_key bytea NOT NULL,
    not_before timestamp with time zone NOT NULL,
    not_after timestamp with time zone NOT NULL,
    lifecycle text NOT NULL,
    replacement_id uuid,
    overlap_deadline timestamp with time zone,
    certificate bytea NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT mesh_authorities_check CHECK ((not_before < not_after)),
    CONSTRAINT mesh_authorities_check1 CHECK (((replacement_id IS NULL) OR (replacement_id <> id))),
    CONSTRAINT mesh_authorities_id_check CHECK (public.peerward_uuid_v4(id)),
    CONSTRAINT mesh_authorities_lifecycle_check CHECK ((lifecycle = ANY (ARRAY['staged'::text, 'overlap'::text, 'active'::text, 'revoked'::text]))),
    CONSTRAINT mesh_authorities_public_key_check CHECK ((octet_length(public_key) = 32)),
    CONSTRAINT mesh_authorities_serial_check CHECK (public.peerward_uuid_v4(serial))
);

CREATE TABLE public.mesh_names (
    mesh_id uuid NOT NULL,
    normalized_name text NOT NULL,
    owner_kind text NOT NULL,
    owner_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT mesh_names_normalized_name_check CHECK (((normalized_name = lower(normalized_name)) AND (normalized_name ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'::text))),
    CONSTRAINT mesh_names_owner_kind_check CHECK ((owner_kind = ANY (ARRAY['peer'::text, 'service'::text])))
);

CREATE TABLE public.meshes (
    id uuid NOT NULL,
    name text NOT NULL,
    address_cidr cidr NOT NULL,
    gateway inet NOT NULL,
    dns_suffix text NOT NULL,
    mtu integer DEFAULT 1380 NOT NULL,
    reserved_addresses inet[] DEFAULT '{}'::inet[] NOT NULL,
    default_policy text DEFAULT 'deny'::text NOT NULL,
    quarantine_seconds bigint DEFAULT 3600 NOT NULL,
    rotation_overlap_seconds bigint DEFAULT 86400 NOT NULL,
    policy_revision bigint DEFAULT 0 NOT NULL,
    directory_revision bigint DEFAULT 0 NOT NULL,
    relay_revision bigint DEFAULT 0 NOT NULL,
    service_revision bigint DEFAULT 0 NOT NULL,
    revocation_revision bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    authority_revision bigint DEFAULT 0 NOT NULL,
    next_address inet,
    CONSTRAINT meshes_authority_revision_check CHECK ((authority_revision >= 0)),
    CONSTRAINT meshes_check CHECK (((family(gateway) = family((address_cidr)::inet)) AND (gateway <<= (address_cidr)::inet))),
    CONSTRAINT meshes_default_policy_check CHECK ((default_policy = ANY (ARRAY['allow'::text, 'deny'::text]))),
    CONSTRAINT meshes_directory_revision_check CHECK ((directory_revision >= 0)),
    CONSTRAINT meshes_dns_suffix_check CHECK (((dns_suffix = lower(dns_suffix)) AND (dns_suffix <> ''::text))),
    CONSTRAINT meshes_id_check CHECK (public.peerward_uuid_v4(id)),
    CONSTRAINT meshes_mtu_check CHECK (((mtu >= 1280) AND (mtu <= 9000))),
    CONSTRAINT meshes_name_check CHECK ((btrim(name) <> ''::text) AND (octet_length(name) <= 128)),
    CONSTRAINT meshes_policy_revision_check CHECK ((policy_revision >= 0)),
    CONSTRAINT meshes_quarantine_seconds_check CHECK ((quarantine_seconds >= 0)),
    CONSTRAINT meshes_relay_revision_check CHECK ((relay_revision >= 0)),
    CONSTRAINT meshes_revocation_revision_check CHECK ((revocation_revision >= 0)),
    CONSTRAINT meshes_reserved_addresses_check CHECK ((cardinality(reserved_addresses) <= 4096)),
    CONSTRAINT meshes_rotation_overlap_seconds_check CHECK ((rotation_overlap_seconds >= 0)),
    CONSTRAINT meshes_service_revision_check CHECK ((service_revision >= 0))
);

CREATE TABLE public.oidc_flows (
    id uuid NOT NULL,
    state_digest bytea NOT NULL,
    nonce_digest bytea NOT NULL,
    pkce_verifier_digest bytea NOT NULL,
    nonce_secret text NOT NULL,
    pkce_verifier_secret text NOT NULL,
    redirect_uri text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT oidc_flows_id_check CHECK (public.peerward_uuid_v4(id)),
    CONSTRAINT oidc_flows_nonce_digest_check CHECK ((octet_length(nonce_digest) = 32)),
    CONSTRAINT oidc_flows_nonce_secret_check CHECK (((length(nonce_secret) >= 16) AND (length(nonce_secret) <= 512))),
    CONSTRAINT oidc_flows_pkce_verifier_digest_check CHECK ((octet_length(pkce_verifier_digest) = 32)),
    CONSTRAINT oidc_flows_pkce_verifier_secret_check CHECK (((length(pkce_verifier_secret) >= 43) AND (length(pkce_verifier_secret) <= 128))),
    CONSTRAINT oidc_flows_state_digest_check CHECK ((octet_length(state_digest) = 32))
);

CREATE TABLE public.peer_addresses (
    id uuid NOT NULL,
    mesh_id uuid NOT NULL,
    peer_id uuid NOT NULL,
    address inet NOT NULL,
    state text NOT NULL,
    released_at timestamp with time zone,
    quarantine_until timestamp with time zone,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT peer_addresses_id_check CHECK (public.peerward_uuid_v4(id)),
    CONSTRAINT peer_addresses_state_check CHECK ((state = ANY (ARRAY['active'::text, 'quarantine'::text, 'released'::text])))
);

CREATE TABLE public.peer_credential_rotation_requests (
    id uuid NOT NULL,
    mesh_id uuid NOT NULL,
    peer_id uuid NOT NULL,
    authenticated_serial uuid NOT NULL,
    requested_identity_public_key bytea NOT NULL,
    requested_session_public_key bytea NOT NULL,
    request_signature bytea NOT NULL,
    activation_challenge bytea NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    issued_serial uuid,
    issued_credential bytea,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    issued_at timestamp with time zone,
    activated_at timestamp with time zone,
    cancelled_at timestamp with time zone,
    activation_signature bytea,
    CONSTRAINT peer_credential_rotation_requests_authenticated_serial_check CHECK (public.peerward_uuid_v4(authenticated_serial)),
    CONSTRAINT peer_credential_rotation_requests_issue_complete_check CHECK (((issued_serial IS NULL) = (issued_credential IS NULL))),
    CONSTRAINT peer_credential_rotation_requests_state_complete_check CHECK (
        (status = 'pending' AND issued_serial IS NULL AND issued_at IS NULL
            AND activated_at IS NULL AND cancelled_at IS NULL AND activation_signature IS NULL)
        OR (status = 'issued' AND issued_serial IS NOT NULL AND issued_at IS NOT NULL
            AND activated_at IS NULL AND cancelled_at IS NULL AND activation_signature IS NULL)
        OR (status = 'activated' AND issued_serial IS NOT NULL AND issued_at IS NOT NULL
            AND activated_at IS NOT NULL AND cancelled_at IS NULL AND activation_signature IS NOT NULL)
        OR (status = 'cancelled' AND activated_at IS NULL AND cancelled_at IS NOT NULL
            AND activation_signature IS NULL
            AND ((issued_serial IS NULL AND issued_at IS NULL)
                OR (issued_serial IS NOT NULL AND issued_at IS NOT NULL)))
    ),
    CONSTRAINT peer_credential_rotation_requests_id_check CHECK (public.peerward_uuid_v4(id)),
    CONSTRAINT peer_credential_rotation_requests_issued_serial_check CHECK (((issued_serial IS NULL) OR public.peerward_uuid_v4(issued_serial))),
    CONSTRAINT peer_credential_rotation_requests_requested_identity_key_check CHECK ((octet_length(requested_identity_public_key) = 32)),
    CONSTRAINT peer_credential_rotation_requests_requested_session_key_check CHECK ((octet_length(requested_session_public_key) = 32)),
    CONSTRAINT peer_credential_rotation_requests_request_signature_check CHECK ((octet_length(request_signature) = 64)),
    CONSTRAINT peer_credential_rotation_requests_activation_challenge_check CHECK ((octet_length(activation_challenge) = 32)),
    CONSTRAINT peer_credential_rotation_requests_activation_signature_check CHECK (((activation_signature IS NULL) OR (octet_length(activation_signature) = 64))),
    CONSTRAINT peer_credential_rotation_requests_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'issued'::text, 'activated'::text, 'cancelled'::text])))
);

CREATE TABLE public.peer_credentials (
    id uuid NOT NULL,
    mesh_id uuid NOT NULL,
    peer_id uuid NOT NULL,
    authority_id uuid NOT NULL,
    serial uuid NOT NULL,
    public_key bytea NOT NULL,
    not_before timestamp with time zone NOT NULL,
    not_after timestamp with time zone NOT NULL,
    lifecycle text NOT NULL,
    replacement_id uuid,
    overlap_deadline timestamp with time zone,
    signature bytea NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    identity_public_key bytea NOT NULL,
    CONSTRAINT peer_credentials_check CHECK ((not_before < not_after)),
    CONSTRAINT peer_credentials_check1 CHECK (((replacement_id IS NULL) OR (replacement_id <> id))),
    CONSTRAINT peer_credentials_id_check CHECK (public.peerward_uuid_v4(id)),
    CONSTRAINT peer_credentials_identity_public_key_check CHECK ((octet_length(identity_public_key) = 32)),
    CONSTRAINT peer_credentials_lifecycle_check CHECK ((lifecycle = ANY (ARRAY['staged'::text, 'overlap'::text, 'active'::text, 'revoked'::text]))),
    CONSTRAINT peer_credentials_public_key_check CHECK ((octet_length(public_key) = 32)),
    CONSTRAINT peer_credentials_serial_check CHECK (public.peerward_uuid_v4(serial)),
    CONSTRAINT peer_credentials_signature_check CHECK ((octet_length(signature) = 64))
);

CREATE TABLE public.peerward_installation (
    singleton boolean DEFAULT true NOT NULL,
    product_major integer NOT NULL,
    wire_major integer NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT peerward_installation_product_major_check CHECK ((product_major = 1)),
    CONSTRAINT peerward_installation_singleton_check CHECK (singleton),
    CONSTRAINT peerward_installation_wire_major_check CHECK ((wire_major = 2))
);

CREATE TABLE public.policies (
    mesh_id uuid NOT NULL,
    revision bigint NOT NULL,
    default_action text NOT NULL,
    document bytea NOT NULL,
    signature bytea,
    current boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT policies_default_action_check CHECK ((default_action = ANY (ARRAY['allow'::text, 'deny'::text]))),
    CONSTRAINT policies_document_check CHECK ((octet_length(document) >= 33)),
    CONSTRAINT policies_revision_check CHECK ((revision >= 0))
);

CREATE TABLE public.policy_rule_peers (
    mesh_id uuid NOT NULL,
    policy_revision bigint NOT NULL,
    rule_id uuid NOT NULL,
    direction text NOT NULL,
    peer_id uuid NOT NULL,
    CONSTRAINT policy_rule_peers_direction_check CHECK ((direction = ANY (ARRAY['source'::text, 'destination'::text])))
);

CREATE TABLE public.policy_rules (
    id uuid NOT NULL,
    mesh_id uuid NOT NULL,
    policy_revision bigint NOT NULL,
    priority integer NOT NULL,
    action text NOT NULL,
    source_labels jsonb DEFAULT '{}'::jsonb NOT NULL,
    destination_labels jsonb DEFAULT '{}'::jsonb NOT NULL,
    protocol text NOT NULL,
    destination_port_ranges int8range[] DEFAULT '{}'::int8range[] NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    audit_log boolean DEFAULT false NOT NULL,
    source_cidrs cidr[] DEFAULT '{}'::cidr[] NOT NULL,
    destination_cidrs cidr[] DEFAULT '{}'::cidr[] NOT NULL,
    CONSTRAINT policy_rules_action_check CHECK ((action = ANY (ARRAY['allow'::text, 'deny'::text]))),
    CONSTRAINT policy_rules_destination_cidrs_check CHECK ((cardinality(destination_cidrs) <= 256)),
    CONSTRAINT policy_rules_destination_labels_check CHECK (public.peerward_valid_labels(destination_labels)),
    CONSTRAINT policy_rules_destination_ports_check CHECK ((cardinality(destination_port_ranges) <= 256)),
    CONSTRAINT policy_rules_id_check CHECK (public.peerward_uuid_v4(id)),
    CONSTRAINT policy_rules_priority_check CHECK ((priority >= 0)),
    CONSTRAINT policy_rules_protocol_check CHECK ((protocol = ANY (ARRAY['any'::text, 'tcp'::text, 'udp'::text, 'icmp'::text]))),
    CONSTRAINT policy_rules_source_cidrs_check CHECK ((cardinality(source_cidrs) <= 256)),
    CONSTRAINT policy_rules_source_labels_check CHECK (public.peerward_valid_labels(source_labels)),
    CONSTRAINT policy_rules_valid_port_ranges CHECK (public.peerward_valid_port_ranges(protocol, destination_port_ranges))
);

CREATE TABLE public.relay_credentials (
    id uuid NOT NULL,
    mesh_id uuid NOT NULL,
    relay_id uuid NOT NULL,
    authority_id uuid NOT NULL,
    serial uuid NOT NULL,
    public_key bytea NOT NULL,
    not_before timestamp with time zone NOT NULL,
    not_after timestamp with time zone NOT NULL,
    lifecycle text NOT NULL,
    replacement_id uuid,
    overlap_deadline timestamp with time zone,
    signature bytea NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT relay_credentials_check CHECK ((not_before < not_after)),
    CONSTRAINT relay_credentials_check1 CHECK (((replacement_id IS NULL) OR (replacement_id <> id))),
    CONSTRAINT relay_credentials_id_check CHECK (public.peerward_uuid_v4(id)),
    CONSTRAINT relay_credentials_lifecycle_check CHECK ((lifecycle = ANY (ARRAY['staged'::text, 'overlap'::text, 'active'::text, 'revoked'::text]))),
    CONSTRAINT relay_credentials_public_key_check CHECK ((octet_length(public_key) = 32)),
    CONSTRAINT relay_credentials_serial_check CHECK (public.peerward_uuid_v4(serial)),
    CONSTRAINT relay_credentials_signature_check CHECK ((octet_length(signature) = 64))
);

CREATE TABLE public.relay_presence (
    mesh_id uuid NOT NULL,
    peer_id uuid NOT NULL,
    relay_id uuid NOT NULL,
    attachment_id uuid NOT NULL,
    role text NOT NULL,
    fencing_generation bigint NOT NULL,
    lease_deadline timestamp with time zone NOT NULL,
    updated_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT relay_presence_attachment_id_check CHECK (public.peerward_uuid_v4(attachment_id)),
    CONSTRAINT relay_presence_fencing_generation_check CHECK ((fencing_generation > 0)),
    CONSTRAINT relay_presence_role_check CHECK ((role = ANY (ARRAY['primary'::text, 'standby'::text])))
);

CREATE TABLE public.relay_runtime_leases (
    mesh_id uuid NOT NULL,
    relay_id uuid NOT NULL,
    instance_id uuid NOT NULL,
    fencing_generation bigint NOT NULL,
    lease_deadline timestamp with time zone NOT NULL,
    updated_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT relay_runtime_leases_fencing_generation_check CHECK ((fencing_generation > 0)),
    CONSTRAINT relay_runtime_leases_instance_id_check CHECK (public.peerward_uuid_v4(instance_id))
);

CREATE TABLE public.services (
    id uuid NOT NULL,
    mesh_id uuid NOT NULL,
    peer_id uuid NOT NULL,
    alias text,
    labels jsonb DEFAULT '{}'::jsonb NOT NULL,
    state text DEFAULT 'enabled'::text NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    protocols text[] NOT NULL,
    listen_port integer NOT NULL,
    CONSTRAINT services_alias_check CHECK ((alias ~ '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$'::text)),
    CONSTRAINT services_id_check CHECK (public.peerward_uuid_v4(id)),
    CONSTRAINT services_labels_check CHECK (public.peerward_valid_labels(labels)),
    CONSTRAINT services_listen_port_valid CHECK (((listen_port >= 1) AND (listen_port <= 65535))),
    CONSTRAINT services_protocols_valid CHECK (((protocols = ARRAY['tcp'::text]) OR (protocols = ARRAY['udp'::text]) OR (protocols = ARRAY['tcp'::text, 'udp'::text]))),
    CONSTRAINT services_state_check CHECK ((state = ANY (ARRAY['enabled'::text, 'disabled'::text, 'deleted'::text])))
);

CREATE TABLE public.signed_state_revisions (
    mesh_id uuid NOT NULL,
    kind text NOT NULL,
    revision bigint NOT NULL,
    body bytea NOT NULL,
    published_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT signed_state_revisions_body_check CHECK (((octet_length(body) > 0) AND (octet_length(body) <= 8388608))),
    CONSTRAINT signed_state_revisions_kind_check CHECK ((kind = ANY (ARRAY['authorities'::text, 'peers'::text, 'relays'::text, 'policy'::text, 'services'::text, 'revocations'::text]))),
    CONSTRAINT signed_state_revisions_revision_check CHECK ((revision >= 0))
);

CREATE TABLE public.web_sessions (
    id uuid NOT NULL,
    session_digest bytea NOT NULL,
    csrf_digest bytea NOT NULL,
    subject text NOT NULL,
    role text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    last_seen_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT web_sessions_csrf_digest_check CHECK ((octet_length(csrf_digest) = 32)),
    CONSTRAINT web_sessions_id_check CHECK (public.peerward_uuid_v4(id)),
    CONSTRAINT web_sessions_role_check CHECK ((role = ANY (ARRAY['viewer'::text, 'operator'::text, 'admin'::text]))),
    CONSTRAINT web_sessions_session_digest_check CHECK ((octet_length(session_digest) = 32))
);

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.encrypted_audit_inbox
    ADD CONSTRAINT encrypted_audit_inbox_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.encrypted_audit_inbox
    ADD CONSTRAINT encrypted_audit_inbox_dedupe_key UNIQUE (mesh_id, source_peer, ciphertext_digest);

ALTER TABLE ONLY public.processed_peer_audit_batches
    ADD CONSTRAINT processed_peer_audit_batches_pkey PRIMARY KEY (mesh_id, source_peer, batch_id);

ALTER TABLE ONLY public.bootstrap_state
    ADD CONSTRAINT bootstrap_state_pkey PRIMARY KEY (singleton);

ALTER TABLE ONLY public.event_outbox
    ADD CONSTRAINT event_outbox_cursor_key UNIQUE (cursor);

ALTER TABLE ONLY public.event_outbox
    ADD CONSTRAINT event_outbox_pkey PRIMARY KEY (sequence);

ALTER TABLE ONLY public.join_tickets
    ADD CONSTRAINT join_tickets_mesh_id_id_key UNIQUE (mesh_id, id);

ALTER TABLE ONLY public.join_tickets
    ADD CONSTRAINT join_tickets_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.join_tickets
    ADD CONSTRAINT join_tickets_token_digest_key UNIQUE (token_digest);

ALTER TABLE ONLY public.mesh_authorities
    ADD CONSTRAINT mesh_authorities_mesh_id_id_key UNIQUE (mesh_id, id);

ALTER TABLE ONLY public.mesh_authorities
    ADD CONSTRAINT mesh_authorities_mesh_id_public_key_key UNIQUE (mesh_id, public_key);

ALTER TABLE ONLY public.mesh_authorities
    ADD CONSTRAINT mesh_authorities_mesh_id_serial_key UNIQUE (mesh_id, serial);

ALTER TABLE ONLY public.mesh_authorities
    ADD CONSTRAINT mesh_authorities_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.mesh_names
    ADD CONSTRAINT mesh_names_mesh_id_owner_kind_owner_id_key UNIQUE (mesh_id, owner_kind, owner_id);

ALTER TABLE ONLY public.mesh_names
    ADD CONSTRAINT mesh_names_pkey PRIMARY KEY (mesh_id, normalized_name);

ALTER TABLE ONLY public.meshes
    ADD CONSTRAINT meshes_id_address_cidr_key UNIQUE (id, address_cidr);

ALTER TABLE ONLY public.meshes
    ADD CONSTRAINT meshes_id_gateway_key UNIQUE (id, gateway);

ALTER TABLE ONLY public.meshes
    ADD CONSTRAINT meshes_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.oidc_flows
    ADD CONSTRAINT oidc_flows_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.oidc_flows
    ADD CONSTRAINT oidc_flows_state_digest_key UNIQUE (state_digest);

ALTER TABLE ONLY public.peer_addresses
    ADD CONSTRAINT peer_addresses_mesh_id_id_key UNIQUE (mesh_id, id);

ALTER TABLE ONLY public.peer_addresses
    ADD CONSTRAINT peer_addresses_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.peer_credential_rotation_requests
    ADD CONSTRAINT peer_credential_rotation_requested_keys_uq UNIQUE
        (mesh_id, peer_id, requested_identity_public_key, requested_session_public_key);

ALTER TABLE ONLY public.peer_credential_rotation_requests
    ADD CONSTRAINT peer_credential_rotation_requests_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.peer_credentials
    ADD CONSTRAINT peer_credentials_mesh_id_id_key UNIQUE (mesh_id, id);

ALTER TABLE ONLY public.peer_credentials
    ADD CONSTRAINT peer_credentials_mesh_id_peer_id_public_key_key UNIQUE (mesh_id, peer_id, public_key);

ALTER TABLE ONLY public.peer_credentials
    ADD CONSTRAINT peer_credentials_mesh_id_serial_key UNIQUE (mesh_id, serial);

ALTER TABLE ONLY public.peer_credentials
    ADD CONSTRAINT peer_credentials_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.peers
    ADD CONSTRAINT peers_mesh_id_id_key UNIQUE (mesh_id, id);

ALTER TABLE ONLY public.peers
    ADD CONSTRAINT peers_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.peerward_installation
    ADD CONSTRAINT peerward_installation_pkey PRIMARY KEY (singleton);

ALTER TABLE ONLY public.policies
    ADD CONSTRAINT policies_pkey PRIMARY KEY (mesh_id, revision);

ALTER TABLE ONLY public.policy_rule_peers
    ADD CONSTRAINT policy_rule_peers_pkey PRIMARY KEY (mesh_id, policy_revision, rule_id, direction, peer_id);

ALTER TABLE ONLY public.policy_rules
    ADD CONSTRAINT policy_rules_pkey PRIMARY KEY (mesh_id, policy_revision, id);

ALTER TABLE ONLY public.relay_credentials
    ADD CONSTRAINT relay_credentials_mesh_id_id_key UNIQUE (mesh_id, id);

ALTER TABLE ONLY public.relay_credentials
    ADD CONSTRAINT relay_credentials_mesh_id_relay_id_public_key_key UNIQUE (mesh_id, relay_id, public_key);

ALTER TABLE ONLY public.relay_credentials
    ADD CONSTRAINT relay_credentials_mesh_id_serial_key UNIQUE (mesh_id, serial);

ALTER TABLE ONLY public.relay_credentials
    ADD CONSTRAINT relay_credentials_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.relay_presence
    ADD CONSTRAINT relay_presence_pkey PRIMARY KEY (mesh_id, peer_id, role);

ALTER TABLE ONLY public.relay_runtime_leases
    ADD CONSTRAINT relay_runtime_leases_pkey PRIMARY KEY (mesh_id, relay_id);

ALTER TABLE ONLY public.relays
    ADD CONSTRAINT relays_mesh_id_id_key UNIQUE (mesh_id, id);

ALTER TABLE ONLY public.relays
    ADD CONSTRAINT relays_mesh_id_name_key UNIQUE (mesh_id, name);

ALTER TABLE ONLY public.relays
    ADD CONSTRAINT relays_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.services
    ADD CONSTRAINT services_mesh_id_id_key UNIQUE (mesh_id, id);

ALTER TABLE ONLY public.services
    ADD CONSTRAINT services_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.signed_state_revisions
    ADD CONSTRAINT signed_state_revisions_pkey PRIMARY KEY (mesh_id, kind, revision);

ALTER TABLE ONLY public.web_sessions
    ADD CONSTRAINT web_sessions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.web_sessions
    ADD CONSTRAINT web_sessions_session_digest_key UNIQUE (session_digest);

CREATE INDEX event_outbox_mesh_sequence_idx ON public.event_outbox USING btree (mesh_id, sequence);

CREATE UNIQUE INDEX event_outbox_cursor_uq ON public.event_outbox USING btree (cursor);

CREATE INDEX event_outbox_committed_sequence_idx ON public.event_outbox USING btree (committed_at, sequence);

CREATE INDEX encrypted_audit_inbox_claim_idx ON public.encrypted_audit_inbox USING btree (received_at) WHERE claimed_until IS NULL;

CREATE INDEX join_tickets_terminal_idx ON public.join_tickets USING btree ((COALESCE(consumed_at, cancelled_at, expires_at)), id);

CREATE INDEX join_tickets_page_idx ON public.join_tickets USING btree (mesh_id, created_at, id);

CREATE INDEX meshes_page_idx ON public.meshes USING btree (created_at, id);

CREATE INDEX mesh_authorities_page_idx ON public.mesh_authorities USING btree (mesh_id, created_at, id);

CREATE INDEX mesh_authorities_retention_idx ON public.mesh_authorities USING btree (not_after, id) WHERE (lifecycle <> 'active'::text);

CREATE INDEX mesh_authorities_expiry_idx ON public.mesh_authorities USING btree
    (LEAST(not_after, COALESCE(overlap_deadline, 'infinity'::timestamp with time zone)), id)
    WHERE (lifecycle = ANY (ARRAY['active'::text, 'overlap'::text]));

CREATE INDEX oidc_flows_terminal_idx ON public.oidc_flows USING btree ((COALESCE(consumed_at, expires_at)), id);

CREATE INDEX processed_audit_expiry_idx ON public.processed_peer_audit_batches USING btree (processed_at, batch_id);

CREATE INDEX relay_presence_expiry_idx ON public.relay_presence USING btree (lease_deadline, mesh_id, peer_id);

CREATE INDEX relay_runtime_expiry_idx ON public.relay_runtime_leases USING btree (lease_deadline, mesh_id, relay_id);

CREATE UNIQUE INDEX peer_addresses_one_active_ip_uq ON public.peer_addresses USING btree (mesh_id, address) WHERE (state = 'active'::text);

CREATE UNIQUE INDEX peer_addresses_one_active_peer_uq ON public.peer_addresses USING btree (mesh_id, peer_id) WHERE (state = 'active'::text);

CREATE INDEX peer_addresses_allocation_idx ON public.peer_addresses USING btree (mesh_id, address, state, quarantine_until);

CREATE INDEX peer_addresses_retention_idx ON public.peer_addresses USING btree (quarantine_until, id)
    WHERE (state = ANY (ARRAY['quarantine'::text, 'released'::text]));

CREATE UNIQUE INDEX peer_credentials_one_active_uq ON public.peer_credentials USING btree (mesh_id, peer_id) WHERE (lifecycle = 'active'::text);

CREATE INDEX peer_credentials_page_idx ON public.peer_credentials USING btree (mesh_id, peer_id, created_at, id);

CREATE INDEX peer_credentials_retention_idx ON public.peer_credentials USING btree (not_after, id) WHERE (lifecycle <> 'active'::text);

CREATE INDEX peer_credentials_expiry_idx ON public.peer_credentials USING btree
    (LEAST(not_after, COALESCE(overlap_deadline, 'infinity'::timestamp with time zone)), id)
    WHERE (lifecycle = ANY (ARRAY['active'::text, 'overlap'::text]));

CREATE INDEX peers_page_idx ON public.peers USING btree (mesh_id, created_at, id);

CREATE UNIQUE INDEX peer_rotation_one_open_uq ON public.peer_credential_rotation_requests USING btree (mesh_id, peer_id) WHERE (status = ANY (ARRAY['pending'::text, 'issued'::text]));

CREATE INDEX peer_rotation_terminal_idx ON public.peer_credential_rotation_requests USING btree
    ((COALESCE(activated_at, cancelled_at, issued_at, created_at)), id)
    WHERE (status = ANY (ARRAY['activated'::text, 'cancelled'::text]));

CREATE UNIQUE INDEX peers_enabled_name_uq ON public.peers USING btree (mesh_id, lower(name)) WHERE (administrative_state = 'enabled'::text);

CREATE UNIQUE INDEX policies_one_current_uq ON public.policies USING btree (mesh_id) WHERE current;

CREATE INDEX policy_rule_peers_lookup_idx ON public.policy_rule_peers USING btree (mesh_id, policy_revision, direction, peer_id, rule_id);

CREATE INDEX policy_rules_order_idx ON public.policy_rules USING btree (mesh_id, policy_revision, priority, id);

CREATE UNIQUE INDEX relay_credentials_one_active_uq ON public.relay_credentials USING btree (mesh_id, relay_id) WHERE (lifecycle = 'active'::text);

CREATE INDEX relay_credentials_page_idx ON public.relay_credentials USING btree (mesh_id, relay_id, created_at, id);

CREATE INDEX relay_credentials_retention_idx ON public.relay_credentials USING btree (not_after, id) WHERE (lifecycle <> 'active'::text);

CREATE INDEX relay_credentials_expiry_idx ON public.relay_credentials USING btree
    (LEAST(not_after, COALESCE(overlap_deadline, 'infinity'::timestamp with time zone)), id)
    WHERE (lifecycle = ANY (ARRAY['active'::text, 'overlap'::text]));

CREATE INDEX relays_page_idx ON public.relays USING btree (mesh_id, created_at, id);

CREATE UNIQUE INDEX services_enabled_alias_uq ON public.services USING btree (mesh_id, lower(alias)) WHERE ((state = 'enabled'::text) AND (alias IS NOT NULL));

CREATE INDEX services_page_idx ON public.services USING btree (mesh_id, created_at, id);

CREATE INDEX audit_log_page_idx ON public.audit_log USING btree (retained_mesh_id, occurred_at DESC, id DESC);

CREATE INDEX signed_state_latest_idx ON public.signed_state_revisions USING btree (mesh_id, kind, revision DESC);

CREATE INDEX web_sessions_terminal_idx ON public.web_sessions USING btree
    (LEAST(expires_at, COALESCE(revoked_at, expires_at)), id);

CREATE TRIGGER audit_log_immutable BEFORE DELETE OR UPDATE ON public.audit_log FOR EACH ROW EXECUTE FUNCTION public.peerward_reject_audit_mutation();

CREATE TRIGGER peers_shared_dns_name BEFORE INSERT OR DELETE OR UPDATE ON public.peers FOR EACH ROW EXECUTE FUNCTION public.peerward_reserve_peer_name();

CREATE TRIGGER policy_rule_count_bound BEFORE INSERT ON public.policy_rules FOR EACH ROW EXECUTE FUNCTION public.peerward_check_policy_rule_count();

CREATE TRIGGER policy_rule_peer_count_bound BEFORE INSERT ON public.policy_rule_peers FOR EACH ROW EXECUTE FUNCTION public.peerward_check_policy_peer_count();

CREATE TRIGGER services_shared_dns_name BEFORE INSERT OR DELETE OR UPDATE ON public.services FOR EACH ROW EXECUTE FUNCTION public.peerward_reserve_service_name();

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_mesh_id_fkey FOREIGN KEY (mesh_id) REFERENCES public.meshes(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.encrypted_audit_inbox
    ADD CONSTRAINT encrypted_audit_inbox_mesh_id_fkey FOREIGN KEY (mesh_id) REFERENCES public.meshes(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.encrypted_audit_inbox
    ADD CONSTRAINT encrypted_audit_inbox_peer_fkey FOREIGN KEY (mesh_id, source_peer) REFERENCES public.peers(mesh_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY public.processed_peer_audit_batches
    ADD CONSTRAINT processed_peer_audit_batches_mesh_id_fkey FOREIGN KEY (mesh_id) REFERENCES public.meshes(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.processed_peer_audit_batches
    ADD CONSTRAINT processed_peer_audit_batches_peer_fkey FOREIGN KEY (mesh_id, source_peer) REFERENCES public.peers(mesh_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY public.event_outbox
    ADD CONSTRAINT event_outbox_mesh_id_fkey FOREIGN KEY (mesh_id) REFERENCES public.meshes(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.join_tickets
    ADD CONSTRAINT join_tickets_claimed_credential_fk FOREIGN KEY (mesh_id, claimed_credential_id) REFERENCES public.peer_credentials(mesh_id, id);

ALTER TABLE ONLY public.join_tickets
    ADD CONSTRAINT join_tickets_mesh_id_claimed_peer_id_fkey FOREIGN KEY (mesh_id, claimed_peer_id) REFERENCES public.peers(mesh_id, id);

ALTER TABLE ONLY public.join_tickets
    ADD CONSTRAINT join_tickets_mesh_id_fkey FOREIGN KEY (mesh_id) REFERENCES public.meshes(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.mesh_authorities
    ADD CONSTRAINT mesh_authorities_mesh_id_fkey FOREIGN KEY (mesh_id) REFERENCES public.meshes(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.mesh_authorities
    ADD CONSTRAINT mesh_authorities_mesh_id_replacement_id_fkey FOREIGN KEY (mesh_id, replacement_id) REFERENCES public.mesh_authorities(mesh_id, id) DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY public.mesh_names
    ADD CONSTRAINT mesh_names_mesh_id_fkey FOREIGN KEY (mesh_id) REFERENCES public.meshes(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.peer_addresses
    ADD CONSTRAINT peer_addresses_mesh_id_peer_id_fkey FOREIGN KEY (mesh_id, peer_id) REFERENCES public.peers(mesh_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY public.peer_credential_rotation_requests
    ADD CONSTRAINT peer_credential_rotation_requ_mesh_id_authenticated_serial_fkey FOREIGN KEY (mesh_id, authenticated_serial) REFERENCES public.peer_credentials(mesh_id, serial);

ALTER TABLE ONLY public.peer_credential_rotation_requests
    ADD CONSTRAINT peer_credential_rotation_requests_mesh_id_issued_serial_fkey FOREIGN KEY (mesh_id, issued_serial) REFERENCES public.peer_credentials(mesh_id, serial);

ALTER TABLE ONLY public.peer_credential_rotation_requests
    ADD CONSTRAINT peer_credential_rotation_requests_mesh_id_peer_id_fkey FOREIGN KEY (mesh_id, peer_id) REFERENCES public.peers(mesh_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY public.peer_credentials
    ADD CONSTRAINT peer_credentials_mesh_id_authority_id_fkey FOREIGN KEY (mesh_id, authority_id) REFERENCES public.mesh_authorities(mesh_id, id);

ALTER TABLE ONLY public.peer_credentials
    ADD CONSTRAINT peer_credentials_mesh_id_peer_id_fkey FOREIGN KEY (mesh_id, peer_id) REFERENCES public.peers(mesh_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY public.peer_credentials
    ADD CONSTRAINT peer_credentials_mesh_id_replacement_id_fkey FOREIGN KEY (mesh_id, replacement_id) REFERENCES public.peer_credentials(mesh_id, id) DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY public.peers
    ADD CONSTRAINT peers_mesh_id_fkey FOREIGN KEY (mesh_id) REFERENCES public.meshes(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.policies
    ADD CONSTRAINT policies_mesh_id_fkey FOREIGN KEY (mesh_id) REFERENCES public.meshes(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.policy_rule_peers
    ADD CONSTRAINT policy_rule_peers_mesh_id_peer_id_fkey FOREIGN KEY (mesh_id, peer_id) REFERENCES public.peers(mesh_id, id);

ALTER TABLE ONLY public.policy_rule_peers
    ADD CONSTRAINT policy_rule_peers_mesh_id_policy_revision_rule_id_fkey FOREIGN KEY (mesh_id, policy_revision, rule_id) REFERENCES public.policy_rules(mesh_id, policy_revision, id) ON DELETE CASCADE;

ALTER TABLE ONLY public.policy_rules
    ADD CONSTRAINT policy_rules_mesh_id_policy_revision_fkey FOREIGN KEY (mesh_id, policy_revision) REFERENCES public.policies(mesh_id, revision) ON DELETE CASCADE;

ALTER TABLE ONLY public.relay_credentials
    ADD CONSTRAINT relay_credentials_mesh_id_authority_id_fkey FOREIGN KEY (mesh_id, authority_id) REFERENCES public.mesh_authorities(mesh_id, id);

ALTER TABLE ONLY public.relay_credentials
    ADD CONSTRAINT relay_credentials_mesh_id_relay_id_fkey FOREIGN KEY (mesh_id, relay_id) REFERENCES public.relays(mesh_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY public.relay_credentials
    ADD CONSTRAINT relay_credentials_mesh_id_replacement_id_fkey FOREIGN KEY (mesh_id, replacement_id) REFERENCES public.relay_credentials(mesh_id, id) DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY public.relay_presence
    ADD CONSTRAINT relay_presence_mesh_id_peer_id_fkey FOREIGN KEY (mesh_id, peer_id) REFERENCES public.peers(mesh_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY public.relay_presence
    ADD CONSTRAINT relay_presence_mesh_id_relay_id_fkey FOREIGN KEY (mesh_id, relay_id) REFERENCES public.relays(mesh_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY public.relay_runtime_leases
    ADD CONSTRAINT relay_runtime_leases_mesh_id_relay_id_fkey FOREIGN KEY (mesh_id, relay_id) REFERENCES public.relays(mesh_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY public.relays
    ADD CONSTRAINT relays_mesh_id_fkey FOREIGN KEY (mesh_id) REFERENCES public.meshes(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.services
    ADD CONSTRAINT services_mesh_id_peer_id_fkey FOREIGN KEY (mesh_id, peer_id) REFERENCES public.peers(mesh_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY public.signed_state_revisions
    ADD CONSTRAINT signed_state_revisions_mesh_id_fkey FOREIGN KEY (mesh_id) REFERENCES public.meshes(id) ON DELETE CASCADE;

INSERT INTO public.peerward_installation(singleton, product_major, wire_major)
VALUES (true, 1, 2);
