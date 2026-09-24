-- Only the currently approved provider may report this observation. It is not
-- an access grant, route advertisement, or automatic failover instruction.
CREATE TABLE target_health_observations (
    mesh_id uuid NOT NULL,
    binding_id uuid NOT NULL,
    binding_version bigint NOT NULL CHECK(binding_version>0),
    resource_version bigint NOT NULL CHECK(resource_version>0),
    credential_serial uuid NOT NULL,
    sequence bigint NOT NULL CHECK(sequence>0),
    result text NOT NULL CHECK(result IN ('reachable','refused','timeout','unavailable')),
    observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    valid_until timestamptz NOT NULL DEFAULT clock_timestamp()+interval '90 seconds',
    PRIMARY KEY(mesh_id,binding_id),
    FOREIGN KEY(mesh_id,binding_id) REFERENCES gateway_bindings(mesh_id,id) ON DELETE CASCADE
);
