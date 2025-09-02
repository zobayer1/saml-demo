-- Description: Rollback initial data insertions in reverse order due to foreign key constraints

-- Remove SP user access grants first (due to foreign keys)
DELETE FROM sp_users WHERE user_id = 1;

-- Remove admin user
DELETE FROM users WHERE id = 1;

-- Reset auto-increment sequence back to 0 (so next insert starts from 1)
UPDATE sqlite_sequence SET seq = 0 WHERE name = 'users';

-- Remove SP configurations
DELETE FROM sp_configurations WHERE sp_entity_id IN (
    'http://sp1.localhost:8001/saml/metadata',
    'http://sp2.localhost:8002/saml/metadata'
);

-- Remove SP providers
DELETE FROM sp_providers WHERE entity_id IN (
    'http://sp1.localhost:8001/saml/metadata',
    'http://sp2.localhost:8002/saml/metadata'
);
