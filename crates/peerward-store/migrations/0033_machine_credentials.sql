-- Mesh-scoped automation credentials. Only digests persist; no user accounts.
CREATE TABLE machine_credentials (
    id uuid PRIMARY KEY,
    mesh_id uuid NOT NULL REFERENCES meshes(id) ON DELETE CASCADE,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    version bigint NOT NULL DEFAULT 1 CHECK (version>0),
    token_digest bytea NOT NULL UNIQUE CHECK (octet_length(token_digest)=32),
    capabilities text[] NOT NULL CHECK (cardinality(capabilities) BETWEEN 1 AND 3 AND
        capabilities <@ ARRAY['status_audit_read','resource_read','resource_write']::text[]),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    CHECK (expires_at>created_at AND expires_at<=created_at+interval '90 days'),
    UNIQUE(mesh_id,id)
);
CREATE INDEX machine_credentials_page ON machine_credentials(mesh_id,created_at,id);
CREATE TRIGGER machine_credentials_increment_version BEFORE UPDATE ON machine_credentials
    FOR EACH ROW EXECUTE FUNCTION peerward_increment_resource_version();
