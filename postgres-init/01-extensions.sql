-- Create PostgreSQL extensions if they don't exist
CREATE EXTENSION IF NOT EXISTS pg_trgm;  -- For text search/similarity
CREATE EXTENSION IF NOT EXISTS unaccent; -- For accent-insensitive search