ALTER TABLE meshes ADD COLUMN network_identifier text
    CHECK (network_identifier IS NULL OR (length(network_identifier) BETWEEN 1 AND 63
        AND network_identifier ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'));
CREATE UNIQUE INDEX meshes_network_identifier_unique ON meshes (network_identifier);
-- Retain the submitted identifier after network deletion for idempotent retries.
ALTER TABLE mesh_lifecycle_jobs ADD COLUMN network_identifier text;
