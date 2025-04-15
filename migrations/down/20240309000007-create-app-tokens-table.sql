-- Migration: Create App Tokens Table
-- Created at: 2024-03-09T00:00:07

-- Write your DOWN migration SQL here

-- Drop indexes first
DROP INDEX IF EXISTS idx_app_tokens_token;
DROP INDEX IF EXISTS idx_app_tokens_service_id;

-- Drop the table
DROP TABLE IF EXISTS app_tokens; 