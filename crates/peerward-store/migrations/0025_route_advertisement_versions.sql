ALTER TABLE route_advertisements ADD COLUMN binding_version bigint NOT NULL DEFAULT 1 CHECK (binding_version > 0);
