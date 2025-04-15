-- Migration: Create Services Table
-- Created at: 2024-03-09T00:00:02

-- Write your UP migration SQL here

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    public_id VARCHAR(36) NOT NULL UNIQUE,
    name VARCHAR(100) NOT NULL UNIQUE,
    description VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create index on name for faster lookups
CREATE INDEX IF NOT EXISTS idx_services_name ON services(name);

-- Create index on public_id for faster lookups
CREATE INDEX IF NOT EXISTS idx_services_public_id ON services(public_id); 