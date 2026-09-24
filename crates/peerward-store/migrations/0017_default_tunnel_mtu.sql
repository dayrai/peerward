-- Conservative default for new Meshes and the WireGuard migration.
-- Existing explicitly provisioned MTUs remain unchanged.
ALTER TABLE public.meshes ALTER COLUMN mtu SET DEFAULT 1280;
