-- Mesh deletion must not mutate immutable audit rows or erase event history.
-- Historical mesh UUIDs deliberately outlive the resource, just like target_id.
-- Keep retained_mesh_id and the audit immutability trigger unchanged. SET NULL
-- would violate that trigger; an outbox CASCADE would erase the creation event
-- and invalidate retained SSE cursors. Normal outbox retention still applies.
ALTER TABLE public.audit_log DROP CONSTRAINT audit_log_mesh_id_fkey;
ALTER TABLE public.event_outbox DROP CONSTRAINT event_outbox_mesh_id_fkey;
