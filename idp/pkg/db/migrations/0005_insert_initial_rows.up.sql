-- Description: Insert initial rows into the sp_providers table
INSERT INTO sp_providers (entity_id, name, metadata_file_path, enabled) VALUES
('http://sp1.localhost:8001/saml/metadata',
 'Demo Service Provider 1',
 'etc/sp-metadata/sp1-metadata.xml',
 true),
('http://sp2.localhost:8002/saml/metadata',
 'Demo Service Provider 2',
 'etc/sp-metadata/sp2-metadata.xml',
 true);

-- Description: Insert initial rows into the sp_configurations table
INSERT INTO sp_configurations (sp_entity_id, required_attributes, attribute_mapping, access_policy) VALUES
('http://sp1.localhost:8001/saml/metadata',
 '["email", "name"]',
 '{"email": "email", "name": "name", "uid": "name"}',
 'allow'),
('http://sp2.localhost:8002/saml/metadata',
 '["email", "roles", "department"]',
 '{"email": "email", "roles": "user_roles", "uid": "name"}',
 'whitelist');

-- Description: Insert IDP admin user (other users will register via registration page)
-- Password hash is for 'admin123' - change this in production
INSERT INTO users (id, username, email, password_hash, user_roles) VALUES
(1, 'admin', 'admin@idp.localhost',
 '$2a$10$example_hash_for_admin123_change_in_production',
 '{"idp": "admin", "sp1": "admin", "sp2": "admin"}');

-- Reset auto-increment sequence to start from 2 for future registered users
UPDATE sqlite_sequence SET seq = 1 WHERE name = 'users';

-- Description: Grant admin user access to both SPs (user_id=1 for the admin we just created)
INSERT INTO sp_users (user_id, sp_entity_id, granted_by) VALUES
(1, 'http://sp1.localhost:8001/saml/metadata', 'system'),
(1, 'http://sp2.localhost:8002/saml/metadata', 'system');
