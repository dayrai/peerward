CREATE TABLE public.peer_management_floors (
    mesh_id uuid NOT NULL,
    peer_id uuid NOT NULL,
    sequence bigint NOT NULL DEFAULT 0 CHECK(sequence>=0),
    PRIMARY KEY(mesh_id,peer_id),
    FOREIGN KEY(mesh_id,peer_id) REFERENCES public.peers(mesh_id,id) ON DELETE CASCADE
);
CREATE TABLE public.peer_management_requests (
    request_id uuid PRIMARY KEY,
    mesh_id uuid NOT NULL,
    peer_id uuid NOT NULL,
    sequence bigint NOT NULL CHECK(sequence>0),
    digest bytea NOT NULL CHECK(octet_length(digest)=32),
    committed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE(mesh_id,peer_id,sequence),
    FOREIGN KEY(mesh_id,peer_id) REFERENCES public.peers(mesh_id,id) ON DELETE CASCADE
);
CREATE TABLE public.configuration_receipts (
    mesh_id uuid NOT NULL,
    peer_id uuid NOT NULL,
    configuration_version bigint NOT NULL CHECK(configuration_version>0),
    configuration_digest bytea NOT NULL CHECK(octet_length(configuration_digest)=32),
    lease_sequence bigint NOT NULL CHECK(lease_sequence>0),
    result text NOT NULL CHECK(result IN ('applied','rejected')),
    reason text,
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(mesh_id,peer_id),
    FOREIGN KEY(mesh_id,peer_id) REFERENCES public.peers(mesh_id,id) ON DELETE CASCADE
);
