-- Description: Create SP providers table to register trusted Service Providers
CREATE TABLE IF NOT EXISTS sp_providers (
    entity_id VARCHAR(255) PRIMARY KEY,             -- SP's unique identifier (matches SAML Issuer)
    name VARCHAR(100) NOT NULL,                     -- Human-readable name for the SP
    metadata_file_path VARCHAR(255),                -- Path to SP's SAML metadata XML file
    metadata_url VARCHAR(255),                      -- URL to fetch SP's SAML metadata XML
    enabled BOOLEAN DEFAULT true,                   -- Whether this SP is currently active/allowed
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,  -- When SP was registered
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,  -- Last modification timestamp
    CHECK (metadata_file_path IS NOT NULL OR metadata_url IS NOT NULL)
);
