-- Acknowledgements are scoped to an authenticated actor and an exact condition.
-- New fingerprints must be acknowledged again; these rows never suppress faults.
CREATE TABLE console_notice_state (
    mesh_id uuid NOT NULL REFERENCES meshes(id) ON DELETE CASCADE,
    actor text NOT NULL,
    notice_id text NOT NULL CHECK(length(notice_id) BETWEEN 1 AND 160),
    fingerprint text NOT NULL CHECK(length(fingerprint) BETWEEN 1 AND 160),
    known boolean NOT NULL DEFAULT false,
    is_read boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(mesh_id,actor,notice_id)
);
