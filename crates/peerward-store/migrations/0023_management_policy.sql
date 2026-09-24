ALTER TABLE meshes ADD COLUMN resource_policy_revision bigint NOT NULL DEFAULT 1 CHECK (resource_policy_revision > 0);
CREATE TABLE resource_policy_history (
    mesh_id uuid NOT NULL REFERENCES meshes(id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision > 0),
    document jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(mesh_id,revision)
);
CREATE FUNCTION initialize_mesh_management() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO dns_profiles(id,mesh_id,profile) VALUES(NEW.id,NEW.id,
        jsonb_build_object('id',NEW.id,'scope',jsonb_build_object('peers','[]'::jsonb,'labels','{}'::jsonb,'cidrs','[]'::jsonb),
            'search_domains','[]'::jsonb,'routes','[]'::jsonb,'records','{}'::jsonb));
    INSERT INTO resource_policy_history(mesh_id,revision,document) VALUES(NEW.id,1,'{"rules":[],"tests":[]}'::jsonb);
    RETURN NEW;
END $$;
CREATE TRIGGER meshes_initialize_management AFTER INSERT ON meshes FOR EACH ROW EXECUTE FUNCTION initialize_mesh_management();
INSERT INTO dns_profiles(id,mesh_id,profile) SELECT id,id,
    jsonb_build_object('id',id,'scope',jsonb_build_object('peers','[]'::jsonb,'labels','{}'::jsonb,'cidrs','[]'::jsonb),
        'search_domains','[]'::jsonb,'routes','[]'::jsonb,'records','{}'::jsonb) FROM meshes;
INSERT INTO resource_policy_history(mesh_id,revision,document) SELECT id,1,'{"rules":[],"tests":[]}'::jsonb FROM meshes;
