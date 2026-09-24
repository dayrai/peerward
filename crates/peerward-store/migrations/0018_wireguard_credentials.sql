-- Legacy rows deliberately have no invented WireGuard key. They cannot be
-- published or admitted by Wire 4 and their devices must enroll again.
ALTER TABLE public.peer_credentials ADD COLUMN wireguard_public_key bytea
    CHECK (wireguard_public_key IS NULL OR (
        octet_length(wireguard_public_key) = 32
        AND wireguard_public_key <> decode(repeat('00', 32), 'hex')
        AND wireguard_public_key <> public_key
        AND wireguard_public_key <> identity_public_key
    ));
CREATE UNIQUE INDEX peer_credentials_wireguard_key
    ON public.peer_credentials(mesh_id, wireguard_public_key)
    WHERE wireguard_public_key IS NOT NULL;

ALTER TABLE public.peer_credential_rotation_requests
    ADD COLUMN requested_wireguard_public_key bytea
    CHECK (requested_wireguard_public_key IS NULL OR (
        octet_length(requested_wireguard_public_key) = 32
        AND requested_wireguard_public_key <> decode(repeat('00', 32), 'hex')
        AND requested_wireguard_public_key <> requested_session_public_key
        AND requested_wireguard_public_key <> requested_identity_public_key
    ));

CREATE UNIQUE INDEX peer_rotation_wireguard_key
    ON public.peer_credential_rotation_requests(mesh_id, requested_wireguard_public_key)
    WHERE requested_wireguard_public_key IS NOT NULL;

-- Two complete signed generations per Peer must fit the 10,000-Peer limit.
ALTER TABLE public.signed_state_revisions DROP CONSTRAINT signed_state_revisions_body_check;
ALTER TABLE public.signed_state_revisions ADD CONSTRAINT signed_state_revisions_body_check
    CHECK (octet_length(body) > 0 AND octet_length(body) <= 33554432);

ALTER TABLE public.peerward_installation DROP CONSTRAINT peerward_installation_wire_major_check;
UPDATE public.peerward_installation SET wire_major=4;
ALTER TABLE public.peerward_installation ADD CONSTRAINT peerward_installation_wire_major_check CHECK(wire_major=4);
