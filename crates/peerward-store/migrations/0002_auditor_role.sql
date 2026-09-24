ALTER TABLE web_sessions DROP CONSTRAINT web_sessions_role_check;
ALTER TABLE web_sessions ADD CONSTRAINT web_sessions_role_check
    CHECK (role = ANY (ARRAY['auditor'::text, 'viewer'::text, 'operator'::text, 'admin'::text]));
