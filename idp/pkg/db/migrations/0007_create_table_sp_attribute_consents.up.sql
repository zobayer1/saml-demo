-- Description: Create SP attribute consents table for per-attribute release control
CREATE TABLE IF NOT EXISTS sp_attribute_consents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,                   -- Unique consent record identifier
    user_id INTEGER NOT NULL,                               -- References users.id
    sp_entity_id VARCHAR(255) NOT NULL,                     -- References sp_providers.entity_id
    attribute_name VARCHAR(255) NOT NULL,                   -- SAML Attribute Name consent applies to
    consent_status VARCHAR(20) NOT NULL DEFAULT 'granted',  -- 'granted' or 'revoked'
    consented_at DATETIME DEFAULT CURRENT_TIMESTAMP,        -- When consent was first granted
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,          -- Last time status changed
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (sp_entity_id) REFERENCES sp_providers(entity_id) ON DELETE CASCADE,
    UNIQUE(user_id, sp_entity_id, attribute_name)
);

-- Description: Index to quickly resolve all consents for a user/SP pair
CREATE INDEX IF NOT EXISTS idx_attr_consent_user_sp ON sp_attribute_consents (user_id, sp_entity_id);
