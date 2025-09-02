-- Description: Create SP configurations table for runtime configuration and attribute mappings
CREATE TABLE IF NOT EXISTS sp_configurations (
    sp_entity_id VARCHAR(255) PRIMARY KEY,      -- Links to sp_providers.entity_id
    required_attributes TEXT,                   -- JSON array: ["email", "name", "roles"]
    attribute_mapping TEXT,                     -- JSON object: {"email": "email", "name": "name"}
    access_policy VARCHAR(50) DEFAULT 'allow',  -- Access policy: 'allow', 'deny', 'whitelist'
    session_timeout INTEGER DEFAULT 1800,       -- Session timeout in seconds (30 minutes)
    FOREIGN KEY (sp_entity_id) REFERENCES sp_providers(entity_id) ON DELETE CASCADE
);
