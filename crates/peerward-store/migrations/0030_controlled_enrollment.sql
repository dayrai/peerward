ALTER TABLE public.join_tickets ADD COLUMN settings jsonb NOT NULL DEFAULT '{"name":null,"labels":{},"mode":{"kind":"bearer"}}';
CREATE TABLE public.join_applications (
    id uuid PRIMARY KEY CHECK(public.peerward_uuid_v4(id)),
    mesh_id uuid NOT NULL,
    ticket_id uuid NOT NULL UNIQUE,
    version bigint NOT NULL DEFAULT 1 CHECK(version>0),
    claim_id uuid NOT NULL CHECK(public.peerward_uuid_v4(claim_id)),
    request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
    request_document jsonb NOT NULL CHECK(NOT request_document ? 'token'),
    signed_request jsonb NOT NULL CHECK(octet_length(signed_request::text)<=16384),
    identity_fingerprint text NOT NULL CHECK(identity_fingerprint ~ '^[0-9a-f]{64}$'),
    status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected','cancelled')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '30 minutes',
    decided_at timestamptz,
    decision_version bigint,
    decision_actor text,
    peer_id uuid,
    FOREIGN KEY(mesh_id,ticket_id) REFERENCES public.join_tickets(mesh_id,id) ON DELETE CASCADE,
    FOREIGN KEY(mesh_id,peer_id) REFERENCES public.peers(mesh_id,id),
    CHECK ((status='pending' AND decided_at IS NULL AND decision_version IS NULL AND peer_id IS NULL)
        OR (status<>'pending' AND decided_at IS NOT NULL AND decision_version>0)),
    CHECK ((status='approved') = (peer_id IS NOT NULL)),
    UNIQUE(mesh_id,id)
);
CREATE INDEX join_applications_page ON public.join_applications(mesh_id,created_at,id);
CREATE TRIGGER join_applications_version BEFORE UPDATE ON public.join_applications
    FOR EACH ROW EXECUTE FUNCTION public.peerward_increment_resource_version();
CREATE FUNCTION public.peerward_cancel_join_application() RETURNS trigger
LANGUAGE plpgsql SET search_path=public,pg_temp AS $$
BEGIN
    IF NEW.cancelled_at IS NOT NULL AND OLD.cancelled_at IS NULL THEN
        UPDATE join_applications SET status='cancelled',decided_at=clock_timestamp(),
            decision_version=version,decision_actor='ticket-cancellation'
            WHERE ticket_id=NEW.id AND status='pending';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER join_application_cancel AFTER UPDATE ON public.join_tickets
    FOR EACH ROW EXECUTE FUNCTION public.peerward_cancel_join_application();
