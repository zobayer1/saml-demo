-- Description: Rollback initial data insertions in reverse order due to foreign key constraints

-- Remove SP user access grants first (due to foreign keys)
DELETE FROM sp_users WHERE user_id = (
    SELECT id FROM users WHERE email = 'admin@idp.localhost'
);

-- Remove admin user
DELETE FROM users WHERE email = 'admin@idp.localhost';

-- Remove SP configurations
DELETE FROM sp_configurations WHERE sp_entity_id IN (
    'urn:samldemo:sp1',
    'urn:samldemo:sp2'
);

-- Remove SP providers
DELETE FROM sp_providers WHERE entity_id IN (
    'urn:samldemo:sp1',
    'urn:samldemo:sp2'
);
