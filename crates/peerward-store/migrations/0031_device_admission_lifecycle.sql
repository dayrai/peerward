ALTER TABLE public.peers
    ADD COLUMN admission_kind text NOT NULL DEFAULT 'long_lived' CHECK(admission_kind IN ('long_lived','ephemeral','expiring')),
    ADD COLUMN admission_until timestamptz,
    ADD COLUMN admission_ended_at timestamptz,
    ADD COLUMN admission_end_reason text CHECK(admission_end_reason IN ('expired','ephemeral_offline')),
    ADD CONSTRAINT peer_admission_deadline CHECK((admission_kind='expiring')=(admission_until IS NOT NULL)),
    ADD CONSTRAINT peer_admission_terminal CHECK(admission_ended_at IS NULL OR administrative_state<>'enabled'),
    ADD CONSTRAINT peer_admission_end CHECK((admission_ended_at IS NULL)=(admission_end_reason IS NULL));
CREATE INDEX peer_admission_expiry ON public.peers(admission_until,mesh_id,id)
    WHERE administrative_state='enabled' AND admission_kind='expiring';

-- This is a credential issuance constraint, not an in-place edit of signed bytes.
CREATE FUNCTION public.peerward_credential_admission_bound() RETURNS trigger
LANGUAGE plpgsql SET search_path=public,pg_temp AS $$
DECLARE deadline timestamptz;
BEGIN
    SELECT admission_until INTO deadline FROM peers WHERE mesh_id=NEW.mesh_id AND id=NEW.peer_id;
    IF deadline IS NOT NULL AND NEW.not_after>deadline THEN
        RAISE EXCEPTION 'credential exceeds device admission deadline' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER credential_admission_bound BEFORE INSERT OR UPDATE OF not_after ON public.peer_credentials
    FOR EACH ROW EXECUTE FUNCTION public.peerward_credential_admission_bound();

CREATE TABLE public.device_admission_observers (
    mesh_id uuid PRIMARY KEY REFERENCES public.meshes(id) ON DELETE CASCADE,
    observer_id uuid NOT NULL CHECK(public.peerward_uuid_v4(observer_id)),
    observed_at timestamptz NOT NULL,
    healthy boolean NOT NULL,
    runtime_fingerprint text NOT NULL
);
CREATE TABLE public.ephemeral_peer_observations (
    mesh_id uuid NOT NULL,
    peer_id uuid NOT NULL,
    offline_seconds double precision NOT NULL DEFAULT 0 CHECK(offline_seconds>=0 AND offline_seconds<=1800),
    PRIMARY KEY(mesh_id,peer_id),
    FOREIGN KEY(mesh_id,peer_id) REFERENCES public.peers(mesh_id,id) ON DELETE CASCADE
);

-- Preserve all previous Peer projections while adding independent admission state.
ALTER FUNCTION public.peerward_peer_api_json(public.peers) RENAME TO peerward_peer_api_json_before_admission;
CREATE FUNCTION public.peerward_peer_api_json(peer public.peers) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=public,pg_temp AS $$
    SELECT peerward_peer_api_json_before_admission(peer) || jsonb_build_object(
        'admission',CASE WHEN peer.admission_kind='expiring' THEN jsonb_build_object('kind','expiring','valid_until',floor(extract(epoch FROM peer.admission_until))::bigint)
            ELSE jsonb_build_object('kind',peer.admission_kind) END,
        'admission_ended_at',peer.admission_ended_at,
        'admission_end_reason',peer.admission_end_reason)
$$;
