-- Schema 4 / Wire 5. Only the clean-install chain may reach this migration.
ALTER TABLE public.meshes
    ADD COLUMN management_revision bigint NOT NULL DEFAULT 1 CHECK (management_revision > 0),
    ADD COLUMN lease_seconds integer NOT NULL DEFAULT 900 CHECK (lease_seconds IN (300,900,3600));

CREATE TABLE public.network_resources (
    id uuid PRIMARY KEY,
    mesh_id uuid NOT NULL REFERENCES public.meshes(id) ON DELETE CASCADE,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    definition jsonb NOT NULL CHECK (jsonb_typeof(definition)='object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (mesh_id,id)
);
CREATE UNIQUE INDEX network_resource_names ON public.network_resources(mesh_id,(definition->>'name'));
CREATE INDEX network_resources_page ON public.network_resources(mesh_id,created_at,id);
CREATE TRIGGER network_resources_increment_version BEFORE UPDATE ON public.network_resources
    FOR EACH ROW EXECUTE FUNCTION public.peerward_increment_resource_version();

CREATE TABLE public.gateway_bindings (
    id uuid PRIMARY KEY,
    mesh_id uuid NOT NULL REFERENCES public.meshes(id) ON DELETE CASCADE,
    resource_id uuid NOT NULL,
    peer_id uuid NOT NULL,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    approved boolean NOT NULL DEFAULT false,
    priority bigint NOT NULL DEFAULT 100 CHECK (priority BETWEEN 0 AND 4294967295),
    forwarding text NOT NULL DEFAULT 'snat' CHECK (forwarding IN ('snat','preserve_source')),
    return_route_confirmed boolean NOT NULL DEFAULT false,
    approval_source jsonb NOT NULL DEFAULT '{"kind":"manual"}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (mesh_id,resource_id) REFERENCES public.network_resources(mesh_id,id) ON DELETE CASCADE,
    FOREIGN KEY (mesh_id,peer_id) REFERENCES public.peers(mesh_id,id),
    UNIQUE (mesh_id,id), UNIQUE(mesh_id,resource_id,peer_id),
    CHECK (NOT approved OR forwarding='snat' OR return_route_confirmed)
);
CREATE TRIGGER gateway_bindings_increment_version BEFORE UPDATE ON public.gateway_bindings
    FOR EACH ROW EXECUTE FUNCTION public.peerward_increment_resource_version();
CREATE INDEX gateway_bindings_page ON public.gateway_bindings(mesh_id,created_at,id);

CREATE TABLE public.route_advertisements (
    mesh_id uuid NOT NULL,
    binding_id uuid NOT NULL,
    peer_id uuid NOT NULL,
    sequence bigint NOT NULL CHECK (sequence > 0),
    published boolean NOT NULL,
    forwarding_ready boolean NOT NULL,
    valid_until timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (mesh_id,binding_id),
    FOREIGN KEY (mesh_id,binding_id) REFERENCES public.gateway_bindings(mesh_id,id) ON DELETE CASCADE,
    FOREIGN KEY (mesh_id,peer_id) REFERENCES public.peers(mesh_id,id)
);

CREATE TABLE public.dns_profiles (
    id uuid PRIMARY KEY,
    mesh_id uuid NOT NULL REFERENCES public.meshes(id) ON DELETE CASCADE,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    profile jsonb NOT NULL CHECK(jsonb_typeof(profile)='object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER dns_profiles_increment_version BEFORE UPDATE ON public.dns_profiles
    FOR EACH ROW EXECUTE FUNCTION public.peerward_increment_resource_version();

ALTER TABLE public.peerward_installation DROP CONSTRAINT peerward_installation_wire_major_check;
UPDATE public.peerward_installation SET wire_major=5;
ALTER TABLE public.peerward_installation ADD CONSTRAINT peerward_installation_wire_major_check CHECK(wire_major=5);

ALTER TABLE public.signed_state_revisions DROP CONSTRAINT signed_state_revisions_kind_check;
ALTER TABLE public.signed_state_revisions ADD CONSTRAINT signed_state_revisions_kind_check
    CHECK(kind IN ('authorities','peers','relays','relay_topology','policy','services','revocations','configuration'));
CREATE TABLE public.resource_rules (
    id uuid PRIMARY KEY,
    mesh_id uuid NOT NULL REFERENCES public.meshes(id) ON DELETE CASCADE,
    version bigint NOT NULL DEFAULT 1 CHECK(version>0),
    rule jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER resource_rules_increment_version BEFORE UPDATE ON public.resource_rules
    FOR EACH ROW EXECUTE FUNCTION public.peerward_increment_resource_version();
