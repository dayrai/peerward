-- pg_restore deliberately clears its session search_path. Validators and trigger
-- bodies must resolve their own Peerward dependencies independently of callers.
DO $$
DECLARE routine regprocedure;
BEGIN
    FOR routine IN
        SELECT p.oid::regprocedure FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname='public' AND p.proname LIKE 'peerward\_%' ESCAPE '\'
    LOOP
        EXECUTE format('ALTER FUNCTION %s SET search_path = pg_catalog, public, pg_temp', routine);
    END LOOP;
END $$;
