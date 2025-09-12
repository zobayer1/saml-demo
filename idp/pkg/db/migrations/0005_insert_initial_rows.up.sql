-- Description: Insert initial rows into the sp_providers table
INSERT INTO sp_providers (entity_id, name, metadata_file_path, metadata_url, enabled) VALUES
('urn:samldemo:sp1',
 'Service Provider 1',
 'etc/saml/sp1-metadata.xml',
 NULL,
 true),
('urn:samldemo:sp2',
 'Service Provider 2',
 'etc/saml/sp2-metadata.xml',
 NULL,
 true);

-- Description: Insert initial rows into the sp_configurations table
INSERT INTO sp_configurations (sp_entity_id, required_attributes, attribute_mapping, access_policy) VALUES
('urn:samldemo:sp1',
 '["email", "displayName"]',
 '{"email": "email", "displayName": "username"}',
 'allow'),
('urn:samldemo:sp2',
 '["email", "roles"]',
 '{"email": "email", "roles": "user_roles", "displayName": "username"}',
 'whitelist');

-- Description: Insert IDP admin user. Password plaintext used for demo: ea339aa6b55f
INSERT INTO users (username, email, password_hash, user_roles) VALUES
('admin', 'admin@idp.localhost',
 '$2a$10$cIlZhmnhLKkWE/oZ0wRkY.w60m6JroSMqY9YhfDHmwnRt2XPsPgmO',
 '{"idp": "admin", "sp1": "admin", "sp2": "admin"}');

-- Description: Grant admin user access to both SPs (lookup by email)
INSERT INTO sp_users (user_id, sp_entity_id, granted_by)
SELECT u.id, 'urn:samldemo:sp1', 'system'
FROM users u WHERE u.email = 'admin@idp.localhost';

INSERT INTO sp_users (user_id, sp_entity_id, granted_by)
SELECT u.id, 'urn:samldemo:sp2', 'system'
FROM users u WHERE u.email = 'admin@idp.localhost';
