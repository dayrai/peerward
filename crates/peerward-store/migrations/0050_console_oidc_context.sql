ALTER TABLE oidc_flows ADD COLUMN return_to text NOT NULL DEFAULT '/' CHECK(length(return_to)<=2048);
ALTER TABLE oidc_flows ADD COLUMN reauthenticate boolean NOT NULL DEFAULT false;
