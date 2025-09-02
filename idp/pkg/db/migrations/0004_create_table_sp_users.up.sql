-- Description: Create SP users table for user-level access control to Service Providers
CREATE TABLE IF NOT EXISTS sp_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,           -- Unique access grant identifier
    user_id INTEGER NOT NULL,                       -- References users.id
    sp_entity_id VARCHAR(255) NOT NULL,             -- References sp_providers.entity_id
    granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,  -- When access was granted
    granted_by VARCHAR(100),                        -- Who granted the access (admin, system, etc.)
    expires_at DATETIME,                            -- Optional: when access expires
    UNIQUE(user_id, sp_entity_id),                  -- One access record per user-SP pair
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (sp_entity_id) REFERENCES sp_providers(entity_id) ON DELETE CASCADE
);
