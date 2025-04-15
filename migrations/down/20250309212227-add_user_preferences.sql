-- Migration: add_user_preferences
-- Created at: 2025-03-09T21:22:27.193713

-- Write your DOWN migration SQL here

-- Drop indexes first
DROP INDEX IF EXISTS idx_user_preferences_user_id;
DROP INDEX IF EXISTS idx_user_preferences_key;

-- Drop the table
DROP TABLE IF EXISTS user_preferences;

