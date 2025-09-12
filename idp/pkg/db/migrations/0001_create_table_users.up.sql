-- Description: Create users table for IDP authentication and user management
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,           -- Unique user identifier
    username TEXT NOT NULL,                         -- User login name (also used as display name)
    email TEXT UNIQUE NOT NULL,                     -- User email address (must be unique)
    password_hash TEXT NOT NULL,                    -- Hashed password for authentication
    user_roles TEXT NOT NULL,                       -- JSON object: {"idp": "admin", "sp1": "user", "sp2": "none"}
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,  -- When user was created
    status TEXT DEFAULT 'active'                    -- User account status (active, inactive, banned)
);
