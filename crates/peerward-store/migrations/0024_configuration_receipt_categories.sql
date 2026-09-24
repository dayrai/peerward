ALTER TABLE configuration_receipts ADD COLUMN category text NOT NULL DEFAULT 'core' CHECK (category IN ('core','routes','dns','firewall'));
ALTER TABLE configuration_receipts DROP CONSTRAINT configuration_receipts_pkey;
ALTER TABLE configuration_receipts ADD PRIMARY KEY(mesh_id,peer_id,category);
