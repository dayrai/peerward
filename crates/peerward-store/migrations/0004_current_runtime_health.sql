CREATE TABLE current_peer_runtime_health (
    mesh_id uuid NOT NULL,
    peer_id uuid NOT NULL,
    sequence bigint NOT NULL CHECK (sequence > 0),
    observed_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    direct_path_count integer NOT NULL CHECK (direct_path_count BETWEEN 0 AND 65535),
    relay_packets bigint NOT NULL CHECK (relay_packets >= 0),
    direct_packets bigint NOT NULL CHECK (direct_packets >= 0),
    degraded_reasons text[] NOT NULL CHECK (cardinality(degraded_reasons) <= 8),
    signed_revision bigint NOT NULL CHECK (signed_revision >= 0),
    PRIMARY KEY (mesh_id, peer_id),
    FOREIGN KEY (mesh_id, peer_id) REFERENCES peers(mesh_id, id) ON DELETE CASCADE,
    CHECK (expires_at > observed_at)
);

CREATE INDEX current_peer_runtime_health_expiry_idx
    ON current_peer_runtime_health(expires_at);

COMMENT ON TABLE current_peer_runtime_health IS
    'Single privacy-safe current value per Peer; expires after 90 seconds and has no history or remote relationship data.';
