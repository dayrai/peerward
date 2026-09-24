CREATE TABLE console_device_capabilities (
    mesh_id uuid NOT NULL,
    peer_id uuid NOT NULL,
    credential_serial uuid NOT NULL,
    credential_renewal boolean NOT NULL,
    observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(mesh_id,peer_id),
    FOREIGN KEY(mesh_id,peer_id) REFERENCES peers(mesh_id,id) ON DELETE CASCADE
);
CREATE TABLE console_credential_renewals (
    mesh_id uuid NOT NULL,
    peer_id uuid NOT NULL,
    id uuid NOT NULL CHECK(peerward_uuid_v4(id)),
    current_serial uuid NOT NULL,
    actor text NOT NULL,
    reason text NOT NULL CHECK(length(reason)<=512),
    request_digest text NOT NULL,
    command jsonb NOT NULL,
    expires_at timestamptz NOT NULL,
    delivered_at timestamptz,
    completed_at timestamptz,
    completed_serial uuid,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(mesh_id,id),
    FOREIGN KEY(mesh_id,peer_id) REFERENCES peers(mesh_id,id) ON DELETE CASCADE,
    CHECK((completed_at IS NULL)=(completed_serial IS NULL))
);
CREATE INDEX console_renewal_delivery ON console_credential_renewals(mesh_id,peer_id,current_serial,expires_at) WHERE completed_at IS NULL;
