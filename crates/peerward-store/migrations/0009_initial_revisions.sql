-- Early technical-preview bootstraps installed initial signed-state families at
-- revision zero. Zero cannot represent a complete runtime state or a rollback
-- boundary. Repair state-backed families conditionally and give the always-present
-- policy plus the canonical empty service/revocation snapshots revision one.
-- Existing Peer directories are also advanced once so the publisher can add the
-- resource name to authenticated directory labels used by Mesh DNS. No schema or
-- protocol shape changes.
UPDATE public.policies AS policy
SET revision = 1
WHERE policy.revision = 0
  AND policy.current
  AND EXISTS (
      SELECT 1 FROM public.meshes AS mesh
      WHERE mesh.id = policy.mesh_id AND mesh.policy_revision = 0
  );

UPDATE public.meshes AS mesh
SET authority_revision = CASE
        WHEN mesh.authority_revision = 0 AND EXISTS (
            SELECT 1 FROM public.mesh_authorities AS authority
            WHERE authority.mesh_id = mesh.id
        ) THEN 1 ELSE mesh.authority_revision END,
    relay_revision = CASE
        WHEN mesh.relay_revision = 0 AND EXISTS (
            SELECT 1 FROM public.relays AS relay
            WHERE relay.mesh_id = mesh.id
        ) THEN 1 ELSE mesh.relay_revision END,
    directory_revision = CASE
        WHEN EXISTS (
            SELECT 1 FROM public.peers AS peer
            WHERE peer.mesh_id = mesh.id
        ) THEN mesh.directory_revision + 1 ELSE mesh.directory_revision END,
    policy_revision = CASE
        WHEN mesh.policy_revision = 0 AND EXISTS (
            SELECT 1 FROM public.policies AS policy
            WHERE policy.mesh_id = mesh.id AND policy.revision = 1 AND policy.current
        ) THEN 1 ELSE mesh.policy_revision END,
    service_revision = GREATEST(mesh.service_revision, 1),
    revocation_revision = GREATEST(mesh.revocation_revision, 1),
    updated_at = clock_timestamp()
WHERE (mesh.authority_revision = 0 AND EXISTS (
        SELECT 1 FROM public.mesh_authorities AS authority
        WHERE authority.mesh_id = mesh.id
      ))
   OR (mesh.relay_revision = 0 AND EXISTS (
        SELECT 1 FROM public.relays AS relay
        WHERE relay.mesh_id = mesh.id
      ))
   OR EXISTS (
        SELECT 1 FROM public.peers AS peer
        WHERE peer.mesh_id = mesh.id
      )
   OR (mesh.policy_revision = 0 AND EXISTS (
        SELECT 1 FROM public.policies AS policy
        WHERE policy.mesh_id = mesh.id AND policy.revision = 1 AND policy.current
      ))
   OR mesh.service_revision = 0
   OR mesh.revocation_revision = 0;
