-- Migration: Create App Tokens Table
-- Created at: 2024-03-09T00:00:07

-- Write your UP migration SQL here

CREATE TABLE IF NOT EXISTS app_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token VARCHAR(64) NOT NULL UNIQUE,
    name VARCHAR(100) NOT NULL,
    service_id INTEGER NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used TIMESTAMP,
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
);

-- Create index on token for faster lookups
CREATE INDEX IF NOT EXISTS idx_app_tokens_token ON app_tokens(token);

-- Create index on service_id for faster lookups
CREATE INDEX IF NOT EXISTS idx_app_tokens_service_id ON app_tokens(service_id); 