-- Presence rows are ephemeral; their fencing counter must survive release and
-- expiry cleanup. Keep a counter for each durable Peer identity, separate from
-- resource versions so reconnects do not invalidate pending admin edits.
CREATE TABLE public.peer_presence_generations (
    mesh_id uuid NOT NULL,
    peer_id uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    PRIMARY KEY (mesh_id, peer_id),
    FOREIGN KEY (mesh_id, peer_id) REFERENCES public.peers(mesh_id, id) ON DELETE CASCADE
);

INSERT INTO public.peer_presence_generations (mesh_id, peer_id, generation)
    SELECT mesh_id, peer_id, max(fencing_generation) AS maximum
    FROM (
        SELECT mesh_id, peer_id, fencing_generation FROM public.relay_presence
        UNION ALL
        SELECT mesh_id, peer_id, fencing_generation FROM public.relay_standby_presence_v1
    ) presence GROUP BY mesh_id, peer_id;
