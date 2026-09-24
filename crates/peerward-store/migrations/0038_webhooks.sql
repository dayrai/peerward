-- Optional bounded event notifications. Network grants never depend on delivery.
CREATE TABLE webhooks (
    mesh_id uuid NOT NULL REFERENCES meshes(id) ON DELETE CASCADE,
    id uuid NOT NULL CHECK(peerward_uuid_v4(id)),
    version bigint NOT NULL DEFAULT 1 CHECK(version>0),
    name text NOT NULL CHECK(length(name) BETWEEN 1 AND 128),
    endpoint text NOT NULL CHECK(length(endpoint) BETWEEN 1 AND 2048),
    enabled boolean NOT NULL DEFAULT false,
    event_types text[] NOT NULL CHECK(cardinality(event_types) BETWEEN 1 AND 32),
    dropped_events bigint NOT NULL DEFAULT 0 CHECK(dropped_events>=0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(mesh_id,id)
);
CREATE INDEX webhooks_enabled ON webhooks(mesh_id) WHERE enabled;
CREATE TABLE webhook_deliveries (
    mesh_id uuid NOT NULL,
    webhook_id uuid NOT NULL,
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    webhook_version bigint NOT NULL,
    version bigint NOT NULL DEFAULT 1 CHECK(version>0),
    event jsonb NOT NULL,
    event_sequence bigint NOT NULL,
    status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','sending','succeeded','failed','cancelled')),
    attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 10),
    next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    retry_until timestamptz NOT NULL DEFAULT clock_timestamp()+interval '24 hours',
    lease_owner uuid,
    lease_until timestamptz,
    result_code text,
    http_status integer CHECK(http_status BETWEEN 100 AND 599),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    PRIMARY KEY(mesh_id,id),
    UNIQUE(mesh_id,webhook_id,event_sequence),
    FOREIGN KEY(mesh_id,webhook_id) REFERENCES webhooks(mesh_id,id) ON DELETE CASCADE
);
CREATE INDEX webhook_delivery_due ON webhook_deliveries(next_attempt_at,id) WHERE status IN ('queued','sending');
CREATE INDEX webhook_delivery_list ON webhook_deliveries(mesh_id,webhook_id,created_at,id);
CREATE TRIGGER webhook_delivery_version BEFORE UPDATE ON webhook_deliveries
    FOR EACH ROW EXECUTE FUNCTION peerward_increment_resource_version();

CREATE FUNCTION peerward_enqueue_webhooks() RETURNS trigger
LANGUAGE plpgsql SET search_path=public,pg_temp AS $$
DECLARE hook webhooks%ROWTYPE;
BEGIN
    -- Exact opt-in control event names only. No payload, actor, packet or secret data.
    FOR hook IN SELECT * FROM webhooks WHERE mesh_id=NEW.mesh_id AND enabled
        AND NEW.event_type=ANY(event_types) ORDER BY id FOR UPDATE
    LOOP
        IF (SELECT count(*) FROM webhook_deliveries WHERE mesh_id=hook.mesh_id AND webhook_id=hook.id)>=10000 THEN
            UPDATE webhooks SET dropped_events=LEAST(dropped_events+1,9223372036854775806)
                WHERE mesh_id=hook.mesh_id AND id=hook.id;
        ELSE
            INSERT INTO webhook_deliveries(mesh_id,webhook_id,webhook_version,event_sequence,event)
                VALUES(hook.mesh_id,hook.id,hook.version,NEW.sequence,jsonb_build_object(
                    'id',NEW.cursor,'sequence',NEW.sequence,
                    'occurred_at',floor(extract(epoch from NEW.committed_at))::bigint,
                    'kind',NEW.event_type,'resource_kind',NEW.resource_type,'resource_id',NEW.resource_id));
        END IF;
    END LOOP;
    RETURN NEW;
END;
$$;
CREATE TRIGGER enqueue_webhooks AFTER INSERT ON event_outbox FOR EACH ROW EXECUTE FUNCTION peerward_enqueue_webhooks();
