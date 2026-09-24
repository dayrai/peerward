ALTER TABLE public.event_outbox
    ADD COLUMN request_id uuid,
    ADD COLUMN trace_id bytea,
    ADD COLUMN span_id bytea,
    ADD COLUMN trace_flags smallint,
    ADD CONSTRAINT event_outbox_trace_context_check CHECK (
        (request_id IS NULL AND trace_id IS NULL AND span_id IS NULL AND trace_flags IS NULL)
        OR (
            request_id IS NOT NULL AND trace_id IS NOT NULL AND span_id IS NOT NULL
            AND trace_flags IS NOT NULL
            AND peerward_uuid_v4(request_id)
            AND octet_length(trace_id) = 16
            AND trace_id <> decode(repeat('00', 16), 'hex')
            AND octet_length(span_id) = 8
            AND span_id <> decode(repeat('00', 8), 'hex')
            AND trace_flags BETWEEN 0 AND 255
        )
    );

ALTER TABLE public.signed_state_revisions
    ADD COLUMN request_id uuid,
    ADD COLUMN trace_id bytea,
    ADD COLUMN span_id bytea,
    ADD COLUMN trace_flags smallint,
    ADD CONSTRAINT signed_state_revisions_trace_context_check CHECK (
        (request_id IS NULL AND trace_id IS NULL AND span_id IS NULL AND trace_flags IS NULL)
        OR (
            request_id IS NOT NULL AND trace_id IS NOT NULL AND span_id IS NOT NULL
            AND trace_flags IS NOT NULL
            AND peerward_uuid_v4(request_id)
            AND octet_length(trace_id) = 16
            AND trace_id <> decode(repeat('00', 16), 'hex')
            AND octet_length(span_id) = 8
            AND span_id <> decode(repeat('00', 8), 'hex')
            AND trace_flags BETWEEN 0 AND 255
        )
    );
