-- Preserve request identities after response compaction: an old request must
-- never become a new mutation, even if its original apply was a no-op.
ALTER TABLE configuration_applications ALTER COLUMN response DROP NOT NULL;
ALTER TABLE configuration_applications ADD COLUMN archived_at timestamptz;
ALTER TABLE configuration_applications ADD CONSTRAINT configuration_response_archive
    CHECK ((response IS NULL) = (archived_at IS NOT NULL));
CREATE INDEX configuration_responses_retention ON configuration_applications(created_at)
    WHERE response IS NOT NULL;
