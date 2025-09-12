-- Description: Create SAML user, entity and NameID mapping table for persistent NameID format
CREATE TABLE IF NOT EXISTS saml_nameid_maps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,           -- Unique mapping row id
    user_id INTEGER NOT NULL,                       -- References users.id (the principal)
    sp_entity_id VARCHAR(255) NOT NULL,             -- References sp_providers.entity_id (the SP this mapping is for)
    nameid_value TEXT NOT NULL,                     -- The persistent NameID value issued to this SP for this user
    format VARCHAR(255) NOT NULL DEFAULT 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
                                                    -- NameID format (allow future flexibility)
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,  -- When this mapping was created
    last_used_at DATETIME,                          -- Last time this persistent NameID was issued in an assertion
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (sp_entity_id) REFERENCES sp_providers(entity_id) ON DELETE CASCADE,
    UNIQUE (user_id, sp_entity_id),
    UNIQUE (nameid_value)
);

-- Description: Index to quickly resolve all mappings for a given SP or user
CREATE INDEX IF NOT EXISTS idx_saml_nameid_sp ON saml_nameid_maps(sp_entity_id);
CREATE INDEX IF NOT EXISTS idx_saml_nameid_user ON saml_nameid_maps(user_id);
